use backoff::Backoff;
use bitcoin::{consensus, Address, Amount, ScriptBuf};
use hex_conservative::FromHex;
use miniscript::bitcoin::{consensus::Decodable, OutPoint, Script, Transaction, TxOut, Txid};
use simple_electrum_client::{
    electrum::{
        request::Request,
        response::{
            ErrorResponse, HistoryResult, Response, SHGetHistoryResponse, SHNotification,
            SHSubscribeResponse, TxBroadcastResponse, TxGetResponse, TxGetResult,
        },
        types::ScriptHash,
    },
    raw_client::{self, Client as RawClient},
};
use simple_nostr_client::nostr::bitcoin::consensus::encode::serialize_hex;
use std::{
    collections::{BTreeMap, HashMap},
    fmt::{Debug, Display},
    sync::mpsc,
    thread::{self},
    time::{Duration, Instant},
};

use crate::coinjoin::BitcoinBackend;

/// How long a batched request waits for every id to be answered before giving
/// up. `recv` has no read timeout of its own, so this is what stops a server
/// that answers only part of a batch from hanging the caller forever.
const BATCH_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Debug, Clone)]
pub enum Error {
    Electrum(String),
    TxParsing,
    WrongResponse,
    WrongOutPoint,
    TxDoesNotExists,
    /// A batched request was not fully answered before [`BATCH_TIMEOUT`].
    BatchTimeout,
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Electrum(e) => write!(f, "{e:?}"),
            Error::TxParsing => write!(f, "Fail to parse the transaction"),
            Error::WrongResponse => write!(f, "Wrong response from electrum server"),
            Error::WrongOutPoint => write!(f, "Requested outpoint did not exists"),
            Error::TxDoesNotExists => write!(f, "Requested transaction did not exists"),
            Error::BatchTimeout => write!(f, "Batched request timed out"),
        }
    }
}

impl From<raw_client::Error> for Error {
    fn from(value: raw_client::Error) -> Self {
        Error::Electrum(format!("{value:?}"))
    }
}

impl Error {
    /// Whether this error is worth reconnecting and retrying once. Transport and
    /// framing failures (dropped/stale tor circuit, `WouldBlock`, a desynced
    /// response) are; logical outcomes (tx absent, unparseable) are not.
    fn is_retryable(&self) -> bool {
        matches!(self, Error::Electrum(_) | Error::WrongResponse)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum CoinStatus {
    Unconfirmed,
    Confirmed,
    Spend,
}

pub fn short_hash(s: &ScriptBuf) -> String {
    let s = ScriptHash::new(s).to_string();
    short_string(s)
}

pub fn short_string(s: String) -> String {
    let head = 4;
    let tail = 4;
    if s.len() <= head + tail + 2 {
        // No need to truncate if string is short
        return s.to_string();
    }
    format!("{}..{}", &s[..head], &s[s.len() - tail..])
}

#[derive(Clone)]
pub enum CoinRequest {
    Subscribe(Vec<ScriptBuf>),
    History(Vec<ScriptBuf>),
    Txs(Vec<Txid>),
    Stop,
}

impl Debug for CoinRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Subscribe(vec) => {
                let hashes: Vec<_> = vec.iter().map(short_hash).collect();
                f.debug_tuple("Subscribe").field(&hashes).finish()
            }
            Self::History(vec) => {
                let hashes: Vec<_> = vec.iter().map(short_hash).collect();
                f.debug_tuple("History").field(&hashes).finish()
            }
            Self::Txs(arg0) => f.debug_tuple("Txs").field(arg0).finish(),
            Self::Stop => write!(f, "Stop"),
        }
    }
}

#[derive(Clone)]
pub enum CoinResponse {
    Status(BTreeMap<ScriptBuf, Option<String>>),
    History(BTreeMap<ScriptBuf, Vec<(Txid, Option<u64> /* height */)>>),
    Txs(Vec<Transaction>),
    Stopped,
    Error(String),
}

impl Debug for CoinResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Txs(vec) => {
                let txids: Vec<_> = vec.iter().map(|tx| tx.compute_txid()).collect();
                f.debug_tuple("Txs").field(&txids).finish()
            }
            Self::Status(map) => {
                let statuses: Vec<_> = map
                    .iter()
                    .map(|(spk, status)| {
                        format!(
                            "{} => {:?}",
                            short_hash(spk),
                            status.as_ref().map(|st| short_string(st.to_string()))
                        )
                    })
                    .collect();
                f.debug_tuple("Status").field(&statuses).finish()
            }
            Self::History(map) => {
                let map: Vec<_> = map
                    .iter()
                    .map(|(spk, v)| {
                        let conf: Vec<_> =
                            v.iter().filter(|(_, height)| height.is_some()).collect();
                        format!(
                            "{} => conf: {}, total: {}",
                            short_hash(spk),
                            conf.len(),
                            v.len()
                        )
                    })
                    .collect();
                f.debug_tuple("History").field(&map).finish()
            }
            Self::Stopped => write!(f, "Stopped"),
            Self::Error(e) => write!(f, "Error({})", e),
        }
    }
}

#[derive(Debug)]
pub struct Client {
    inner: RawClient,
    index: HashMap<usize, Request>,
    last_id: usize,
    url: String,
    port: u16,
    proxy: Option<String>,
    // `url` has the `ssl://` scheme stripped, so remember whether it was there:
    // a reconnect that dropped TLS would talk plaintext to an SSL-only port.
    ssl: bool,
}

impl Clone for Client {
    fn clone(&self) -> Self {
        // Preserve the proxy: the signer clones its electrum client, and a
        // clone that reconnected directly would leak the real IP mid-coinjoin.
        // Preserve ssl too, or the clone would reconnect in plaintext.
        let mut inner =
            RawClient::new_ssl_maybe(&self.url, self.port, self.ssl).proxy(self.proxy.clone());
        inner.try_connect().expect("electrum reconnect on clone");
        Client {
            inner,
            index: HashMap::new(),
            last_id: 0,
            url: self.url.clone(),
            port: self.port,
            proxy: self.proxy.clone(),
            ssl: self.ssl,
        }
    }
}

impl Client {
    /// Create a new electrum client.
    ///
    /// # Arguments
    /// * `address` - url/ip of the electrum server as String
    /// * `port` - port of the electrum server
    pub fn new(address: &str, port: u16) -> Result<Self, Error> {
        Self::new_with_proxy(address, port, None)
    }

    /// Create a new electrum client, optionally reached through a SOCKS5 proxy
    /// (`host:port`), e.g. a local Tor port. The `ssl://` scheme in `address`
    /// is honored the same way regardless of the proxy.
    ///
    /// # Arguments
    /// * `address` - url/ip of the electrum server as String
    /// * `port` - port of the electrum server
    /// * `proxy` - optional SOCKS5 proxy address
    pub fn new_with_proxy(address: &str, port: u16, proxy: Option<String>) -> Result<Self, Error> {
        let ssl = address.starts_with("ssl://");
        let address = address.to_string().replace("ssl://", "");
        let mut inner = RawClient::new_ssl_maybe(&address, port, ssl).proxy(proxy.clone());
        inner.try_connect()?;
        Ok(Client {
            inner,
            index: HashMap::new(),
            last_id: 0,
            url: address,
            port,
            proxy,
            ssl,
        })
    }

    /// Re-establish the connection after it dropped or went stale (common over
    /// tor while a coinjoin waits minutes for peers). Rebuilds the inner client
    /// from the stored url/port/proxy/ssl and clears any in-flight request ids.
    pub fn reconnect(&mut self) -> Result<(), Error> {
        let mut inner =
            RawClient::new_ssl_maybe(&self.url, self.port, self.ssl).proxy(self.proxy.clone());
        inner.try_connect()?;
        self.inner = inner;
        self.index.clear();
        Ok(())
    }

    /// Run an idempotent request, and if it fails on a dropped/stale connection
    /// reconnect once and try again. Read requests routed through here are safe
    /// to repeat, so a single reconnect turns a torn tor circuit into a hiccup
    /// instead of a failed coinjoin.
    fn with_reconnect<T>(
        &mut self,
        mut op: impl FnMut(&mut Self) -> Result<T, Error>,
    ) -> Result<T, Error> {
        match op(self) {
            Err(e) if e.is_retryable() => {
                self.reconnect()?;
                op(self)
            }
            other => other,
        }
    }

    /// Create a new local electrum client: SSL certificate validation id disabled in
    ///   order to be used with self-signed certificates.
    ///
    /// # Arguments
    /// * `address` - url/ip of the electrum server as String
    /// * `port` - port of the electrum server
    pub fn new_local(address: &str, port: u16) -> Result<Self, Error> {
        let ssl = address.starts_with("ssl://");
        let address = address.to_string().replace("ssl://", "");
        let mut inner = RawClient::new_ssl_maybe(&address, port, ssl).verif_certificate(false);
        inner.try_connect()?;
        Ok(Client {
            inner,
            index: HashMap::new(),
            last_id: 0,
            url: address,
            port,
            proxy: None,
            ssl,
        })
    }

    /// Generate a new request id
    fn id(&mut self) -> usize {
        self.last_id = self.last_id.wrapping_add(1);
        self.last_id
    }

    fn register(&mut self, req: &mut Request) -> usize {
        let id = self.id();
        req.id = id;
        self.index.insert(req.id, req.clone());
        id
    }

    /// Fetch the unspent coins of many scripts in a single batched round trip.
    ///
    /// Scanning address by address costs one round trip per address, which is
    /// unusable over tor. Results are returned in the same order as `scripts`.
    /// `listunspent` also reports only unspent outputs, so unlike walking the
    /// history there is no need to fetch and filter whole transactions.
    pub fn list_unspent_batch(
        &mut self,
        scripts: &[ScriptBuf],
    ) -> Result<Vec<Vec<(TxOut, OutPoint)>>, Error> {
        self.with_reconnect(|c| c.list_unspent_batch_inner(scripts))
    }

    fn list_unspent_batch_inner(
        &mut self,
        scripts: &[ScriptBuf],
    ) -> Result<Vec<Vec<(TxOut, OutPoint)>>, Error> {
        if scripts.is_empty() {
            return Ok(Vec::new());
        }

        let mut requests = Vec::with_capacity(scripts.len());
        let mut position = HashMap::new();
        for (i, script) in scripts.iter().enumerate() {
            let request = Request::sh_list_unspent(script).id(self.id());
            position.insert(request.id, i);
            self.index.insert(request.id, request.clone());
            requests.push(request);
        }

        let send = self.inner.try_send_batch(requests.iter().collect());
        if let Err(e) = send {
            for request in &requests {
                self.index.remove(&request.id);
            }
            return Err(e.into());
        }

        let mut out = vec![Vec::new(); scripts.len()];
        let mut pending = requests.len();
        let mut result: Result<(), Error> = Ok(());
        // A batch may come back split over several messages, so keep reading
        // until every request has been answered. Bound the wait: `recv` blocks
        // in `read_line` with no read timeout, so without a deadline a server
        // that answers only some of the ids would hang this thread forever.
        let deadline = Instant::now() + BATCH_TIMEOUT;
        while pending > 0 {
            if Instant::now() >= deadline {
                result = Err(Error::BatchTimeout);
                break;
            }
            let responses = match self.inner.recv(&self.index) {
                Ok(r) => r,
                Err(e) => {
                    result = Err(e.into());
                    break;
                }
            };
            for response in responses {
                // Account for *any* response carrying one of our ids, not just
                // the expected one: an electrum error (or a mismatched reply)
                // otherwise leaves the id pending forever.
                let Some(id) = response.id() else { continue };
                let Some(i) = position.remove(&id) else {
                    continue;
                };
                self.index.remove(&id);
                pending -= 1;

                match response {
                    Response::SHListUnspent(r) => {
                        out[i] = r
                            .unspent
                            .into_iter()
                            .map(|u| {
                                (
                                    TxOut {
                                        value: Amount::from_sat(u.value as u64),
                                        script_pubkey: scripts[i].clone(),
                                    },
                                    OutPoint {
                                        txid: u.txid,
                                        vout: u.vout as u32,
                                    },
                                )
                            })
                            .collect();
                    }
                    Response::Error(ErrorResponse { error, .. }) => {
                        if result.is_ok() {
                            result = Err(Error::Electrum(format!("{error:?}")));
                        }
                    }
                    _ => {
                        if result.is_ok() {
                            result = Err(Error::WrongResponse);
                        }
                    }
                }
            }
        }

        for id in position.keys() {
            self.index.remove(id);
        }
        result?;

        // `listunspent` is server-supplied: it can name outpoints that do not
        // exist or inflate their value. Signing commits to the amount (BIP143),
        // so a lie here produces an invalid signature and kills the coinjoin
        // after this peer has already published its input and output. Confirm
        // every candidate against the transaction itself, exactly as the
        // per-address path did, and keep the chain's value rather than the
        // claimed one. Only found coins are fetched, so the batch win stands.
        for (i, coins) in out.iter_mut().enumerate() {
            let mut verified = Vec::with_capacity(coins.len());
            for (_, outpoint) in coins.iter() {
                let tx = self.get_tx(outpoint.txid)?;
                let txout = tx
                    .output
                    .get(outpoint.vout as usize)
                    .ok_or(Error::WrongOutPoint)?;
                if txout.script_pubkey != scripts[i] {
                    return Err(Error::WrongOutPoint);
                }
                verified.push((txout.clone(), *outpoint));
            }
            *coins = verified;
        }

        Ok(out)
    }

    pub fn listen<RQ, RS>(self) -> (mpsc::Sender<RQ>, mpsc::Receiver<RS>)
    where
        RQ: Into<CoinRequest> + Debug + Send + 'static,
        RS: From<CoinResponse> + Debug + Send + 'static,
    {
        let (sender, request) = mpsc::channel();
        let (response, receiver) = mpsc::channel();
        thread::spawn(move || self.listen_txs(response, request));

        (sender, receiver)
    }

    fn listen_txs<RQ, RS>(mut self, send: mpsc::Sender<RS>, recv: mpsc::Receiver<RQ>)
    where
        RQ: Into<CoinRequest> + Debug + Send + 'static,
        RS: From<CoinResponse> + Debug + Send + 'static,
    {
        log::debug!("Client::listen_txs()");
        let mut reqid_spk_map = BTreeMap::new();
        let mut watched_spks_sh = BTreeMap::<usize /* request_id */, ScriptHash>::new();
        let mut sh_sbf_map = BTreeMap::<ScriptHash, ScriptBuf>::new();

        let mut last_request = None;

        fn responses_matches_requests(req: &[Request], resp: &[Response]) -> bool {
            req.iter()
                .all(|rq| resp.iter().any(|response| response.id() == Some(rq.id)))
        }

        let mut backoff = Backoff::new_ms(50);

        loop {
            let mut received = false;
            // Handle requests from consumer
            // NOTE: some server implementation (electrs for instance) will answer by an empty
            // response if it receive a request while it has not yes sent its previous response
            // so we need to make sure to not send a request before receiving the previous response
            if last_request.is_none() {
                match recv.try_recv() {
                    Ok(rq) => {
                        log::debug!("Client::listen_txs() recv request: {rq:#?}");
                        received = true;
                        let rq: CoinRequest = rq.into();
                        match rq {
                            CoinRequest::Subscribe(spks) => {
                                let mut batch = vec![];
                                for spk in spks {
                                    let mut sub = Request::subscribe_sh(&spk);
                                    let id = self.register(&mut sub);
                                    log::debug!("Client::listen_txs() subscribe request: {sub:?}");
                                    let sh = ScriptHash::new(&spk);
                                    watched_spks_sh.insert(id, sh);
                                    sh_sbf_map.insert(sh, spk);
                                    batch.push(sub);
                                }
                                if !batch.is_empty() {
                                    log::debug!(
                                        "Client::listen_txs() last_request = {:?}",
                                        batch.len()
                                    );
                                    last_request = Some(batch.clone());

                                    let mut retry = 0usize;
                                    while let Err(e) =
                                        self.inner.try_send_batch(batch.iter().collect())
                                    {
                                        retry += 1;
                                        if retry > 10 {
                                            send.send(CoinResponse::Error(format!("electrum::Client::listen_txs() Fail to send bacth request: {:?}", e)).into()).expect("caller dropped");
                                        }
                                        thread::sleep(Duration::from_millis(50));
                                    }
                                }
                            }
                            CoinRequest::History(sbfs) => {
                                let mut batch = vec![];
                                for spk in sbfs {
                                    let mut history = Request::sh_get_history(&spk);
                                    let id = self.register(&mut history);
                                    log::debug!(
                                        "Client::listen_txs() history request: {history:?}"
                                    );
                                    reqid_spk_map.insert(id, spk);
                                    batch.push(history);
                                }
                                if !batch.is_empty() {
                                    log::debug!(
                                        "Client::listen_txs() last_request = {:?}",
                                        batch.len()
                                    );
                                    last_request = Some(batch.clone());

                                    let mut retry = 0usize;
                                    while let Err(e) =
                                        self.inner.try_send_batch(batch.iter().collect())
                                    {
                                        retry += 1;
                                        if retry > 10 {
                                            send.send(CoinResponse::Error(format!("electrum::Client::listen_txs() Fail to send bacth request: {:?}", e)).into()).expect("caller dropped");
                                        }
                                        thread::sleep(Duration::from_millis(50));
                                    }
                                }
                            }
                            CoinRequest::Txs(txids) => {
                                let mut batch = vec![];
                                for txid in txids {
                                    let mut tx = Request::tx_get(txid);
                                    self.register(&mut tx);
                                    log::debug!("Client::listen_txs() txs request: {tx:?}");
                                    batch.push(tx);
                                }
                                if !batch.is_empty() {
                                    log::debug!(
                                        "Client::listen_txs() last_request = {:?}",
                                        batch.len()
                                    );
                                    last_request = Some(batch.clone());

                                    let mut retry = 0usize;
                                    while let Err(e) =
                                        self.inner.try_send_batch(batch.iter().collect())
                                    {
                                        retry += 1;
                                        if retry > 10 && send.send(CoinResponse::Error(format!("electrum::Client::listen_txs() Fail to send bacth request: {:?}", e)).into()).is_err() {
                                        // NOTE: caller has dropped the channel
                                        // == Close request
                                        return;
                                                    }
                                        thread::sleep(Duration::from_millis(50));
                                    }
                                }
                            }
                            CoinRequest::Stop => {
                                send.send(CoinResponse::Stopped.into()).unwrap();
                                return;
                            }
                        };
                    }
                    Err(e) => {
                        match e {
                            mpsc::TryRecvError::Empty => {}
                            mpsc::TryRecvError::Disconnected => {
                                // NOTE: caller has dropped the channel
                                // == Close request
                                return;
                            }
                        }
                    }
                }
            }
            // Handle responses from electrum server
            match self.inner.try_recv(&self.index) {
                Ok(Some(r)) => {
                    log::debug!("Client::listen_txs() from electrum: {r:#?}");
                    let r_match = if let Some(req) = &last_request {
                        responses_matches_requests(req, &r)
                    } else {
                        false
                    };
                    if r_match {
                        last_request = None;
                    } else if let Some(last_req) = &last_request {
                        log::debug!("Client::listen_txs() request not match resend last request");
                        thread::sleep(Duration::from_millis(100));
                        self.inner
                            .try_send_batch(last_req.iter().collect())
                            .unwrap();
                    }

                    received = true;
                    let mut statuses = BTreeMap::new();
                    let mut txs = Vec::new();
                    // let mut txid_to_get = Vec::new();
                    let mut histories = BTreeMap::new();
                    for r in r {
                        match r {
                            Response::SHSubscribe(SHSubscribeResponse { result: status, id }) => {
                                let sh = watched_spks_sh.get(&id).expect("already inserted");
                                let sbf = sh_sbf_map.get(sh).expect("already inserted");
                                statuses.insert(sbf.clone(), status);
                            }
                            Response::SHNotification(SHNotification {
                                status: (sh, status),
                                ..
                            }) => {
                                let sbf = sh_sbf_map.get(&sh).expect("already inserted");
                                statuses.insert(sbf.clone(), status);
                            }
                            Response::SHGetHistory(SHGetHistoryResponse { history, id }) => {
                                let spk = reqid_spk_map.get(&id).expect("already inserted").clone();
                                reqid_spk_map.remove(&id);
                                let mut spk_hist = vec![];
                                for tx in history {
                                    let HistoryResult { txid, height, .. } = tx;
                                    let height = if height < 1 {
                                        None
                                    } else {
                                        Some(height as u64)
                                    };
                                    spk_hist.push((txid, height));
                                }
                                histories.insert(spk, spk_hist);
                            }
                            Response::TxGet(TxGetResponse {
                                result: TxGetResult::Raw(raw_tx),
                                ..
                            }) => {
                                let tx: Transaction =
                            // TODO: do not unwrap
                                    consensus::encode::deserialize_hex(&raw_tx).unwrap();
                                txs.push(tx);
                            }
                            Response::Error(e) => {
                                let rsp = CoinResponse::Error(e.to_string()).into();
                                if send.send(rsp).is_err() {
                                    // NOTE: caller has dropped the channel
                                    // == Close request
                                    return;
                                }
                            }
                            _ => {}
                        }
                    }
                    if !histories.is_empty() {
                        let rsp = CoinResponse::History(histories);
                        log::debug!("Client::listen_txs() send response: {rsp:#?}");
                        send.send(rsp.into()).unwrap();
                    }
                    if !statuses.is_empty() {
                        let rsp = CoinResponse::Status(statuses);
                        log::debug!("Client::listen_txs() send response: {rsp:#?}");
                        send.send(rsp.into()).unwrap();
                    }
                    // let mut txs = Vec::new();
                    if !txs.is_empty() {
                        let rsp = CoinResponse::Txs(txs);
                        log::debug!("Client::listen_txs() send response: {rsp:#?}");
                        send.send(rsp.into()).unwrap();
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    if send
                        .send(CoinResponse::Error(e.to_string()).into())
                        .is_err()
                    {
                        // NOTE: caller has dropped the channel
                        // == Close request
                        return;
                    }
                }
            }
            if received {
                continue;
            }
            backoff.snooze();
        }
    }

    /// Try to get a transaction by its txid
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    ///   - fail to send the request
    ///   - parsing response fails
    ///   - the response is not of expected type
    ///   - the transaction does not exists
    pub fn get_tx(&mut self, txid: Txid) -> Result<Transaction, Error> {
        self.with_reconnect(|c| c.get_tx_inner(txid))
    }

    fn get_tx_inner(&mut self, txid: Txid) -> Result<Transaction, Error> {
        let request = Request::tx_get(txid).id(self.id());
        self.inner.try_send(&request)?;
        let req_id = request.id;
        self.index.insert(request.id, request);
        let resp = match self.inner.recv(&self.index) {
            Ok(r) => r,
            Err(e) => {
                self.index.remove(&req_id);
                return Err(e.into());
            }
        };
        for r in resp {
            if let Response::TxGet(TxGetResponse {
                id,
                result: TxGetResult::Raw(res),
            }) = r
            {
                if req_id == id {
                    self.index.remove(&req_id);
                    let raw_tx = match Vec::<u8>::from_hex(&res) {
                        Ok(raw) => raw,
                        Err(_) => {
                            return Err(Error::TxParsing);
                        }
                    };
                    let tx: Result<Transaction, _> =
                        Decodable::consensus_decode(&mut raw_tx.as_slice());
                    return tx.map_err(|_| Error::TxParsing);
                }
            } else if let Response::Error(ErrorResponse { id, .. }) = r {
                if req_id == id {
                    self.index.remove(&req_id);
                    // NOTE: it's very likely if we receive an error response from the server
                    // it's because the txid does not match any Transaction, but maybe we can
                    // do a better handling of the error case (for this we need check if responses
                    // from all electrum server implementations are consistant).
                    return Err(Error::TxDoesNotExists);
                }
            }
        }
        self.index.remove(&req_id);
        Err(Error::WrongResponse)
    }

    /// Get coins that pay to the given spk and their related transaction.
    /// This method will make several calls to the electrum server:
    ///   - it will first request a list of all transactions txid that have
    ///     an output paying to the spk.
    ///   - it will then fetch all txs, store them and extract all the coins
    ///     that pay to the given spk.
    ///   - it will return a list of (TxOut, OutPoint) and a map of transactions.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    ///   - a call to the electrum server fail
    #[allow(clippy::type_complexity)]
    pub fn get_coins_at(
        &mut self,
        script: &Script,
    ) -> Result<(Vec<(TxOut, OutPoint)>, HashMap<Txid, Transaction>), Error> {
        let mut txouts = Vec::new();
        let mut transactions = HashMap::new();
        let txs = self.get_coins_tx_at(script)?;
        for txid in txs {
            let tx = self.get_tx(txid)?;
            for (i, txout) in tx.output.iter().enumerate() {
                if *txout.script_pubkey == *script {
                    let outpoint = OutPoint {
                        txid,
                        vout: i as u32,
                    };
                    txouts.push((txout.clone(), outpoint));
                }
            }
            transactions.insert(txid, tx);
        }
        Ok((txouts, transactions))
    }

    /// Get a list of txid of all transaction that have an output paying to the
    ///   given spk
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    ///   - fail sending the request
    ///   - receive a wrong response
    pub fn get_coins_tx_at(&mut self, script: &Script) -> Result<Vec<Txid>, Error> {
        self.with_reconnect(|c| c.get_coins_tx_at_inner(script))
    }

    fn get_coins_tx_at_inner(&mut self, script: &Script) -> Result<Vec<Txid>, Error> {
        let request = Request::sh_get_history(script).id(self.id());
        self.inner.try_send(&request)?;
        let req_id = request.id;
        self.index.insert(request.id, request);
        let resp = match self.inner.recv(&self.index) {
            Ok(r) => r,
            Err(e) => {
                self.index.remove(&req_id);
                return Err(e.into());
            }
        };
        for r in resp {
            if let Response::SHGetHistory(SHGetHistoryResponse { id, history }) = r {
                if req_id == id {
                    self.index.remove(&req_id);
                    let history: Vec<_> = history.into_iter().map(|r| r.txid).collect();
                    return Ok(history);
                }
            }
        }
        self.index.remove(&req_id);
        Err(Error::WrongResponse)
    }

    /// Broadcast the given transaction.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    ///   - fail to send the request
    ///   - get a wrong response
    pub fn broadcast(&mut self, tx: &Transaction) -> Result<(), Error> {
        self.with_reconnect(|c| c.broadcast_inner(tx))
    }

    fn broadcast_inner(&mut self, tx: &Transaction) -> Result<(), Error> {
        let raw_tx = serialize_hex(tx);
        log::debug!("electrum::Client().broadcast(): {:?}", raw_tx);
        let request = Request::tx_broadcast(raw_tx);
        self.inner.try_send(&request)?;
        let req_id = request.id;
        self.index.insert(request.id, request);
        let resp = match self.inner.recv(&self.index) {
            Ok(r) => r,
            Err(e) => {
                self.index.remove(&req_id);
                return Err(e.into());
            }
        };
        log::debug!(
            "electrum::Client().broadcast(): receive response: {:?}",
            resp
        );
        for r in resp {
            if let Response::TxBroadcast(TxBroadcastResponse { id, .. }) = r {
                if req_id == id {
                    self.index.remove(&req_id);
                    return Ok(());
                }
            } else if let Response::Error(ErrorResponse { id, error }) = r {
                if req_id == id {
                    self.index.remove(&req_id);
                    // The server rejected the broadcast (bad fee, conflicting
                    // spend, non-final tx, ...). Surface its message rather than
                    // reporting a generic desync, but the text is
                    // server-controlled: strip ASCII control characters (which
                    // could carry newlines or terminal escapes for log
                    // injection) and clamp the length so a hostile server cannot
                    // emit a multi-megabyte log line.
                    const MAX_ERR_LEN: usize = 512;
                    let sanitized: String = error
                        .message
                        .chars()
                        .map(|c| if c.is_control() { ' ' } else { c })
                        .take(MAX_ERR_LEN)
                        .collect();
                    return Err(Error::Electrum(sanitized));
                }
            }
        }
        self.index.remove(&req_id);
        Err(Error::WrongResponse)
    }

    /// Returns the URL of the electrum client.
    ///
    /// # Returns
    /// A `String` containing the URL of the electrum server.
    pub fn url(&self) -> String {
        self.url.clone()
    }

    /// Returns the port of the electrum client.
    ///
    /// # Returns
    /// A `u16` containing the port of the electrum server.
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl BitcoinBackend for Client {
    type Error = Error;
    fn address_already_used(&mut self, addr: &Address) -> Result<bool, Error> {
        let spk = addr.script_pubkey();
        let txs = self.get_coins_tx_at(&spk)?;
        Ok(!txs.is_empty())
    }

    fn get_outpoint_value(&mut self, outpoint: OutPoint) -> Result<Option<Amount>, Error> {
        let tx = match self.get_tx(outpoint.txid) {
            Ok(tx) => tx,
            Err(e) => match e {
                // NOTE: it's very likely if we receive an error response from the server
                // it's because the txid does not match any Transaction, but maybe we can
                // do a better handling of the error case (for this we need check if responses
                // from all electrum server implementations are consistant).
                Error::TxDoesNotExists => return Ok(None),
                e => return Err(e),
            },
        };
        Ok(Some(
            tx.output
                .get(outpoint.vout as usize)
                .ok_or(Error::WrongOutPoint)?
                .value,
        ))
    }
}
