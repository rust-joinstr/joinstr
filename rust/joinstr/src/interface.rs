use std::{
    fmt::Display,
    thread::sleep,
    time::{Duration, Instant},
};

use bip39::Mnemonic;
use bitcoin::{address::NetworkUnchecked, Address, Network, Txid};
use simple_nostr_client::nostr::Keys;
use zeroize::Zeroizing;

use crate::{
    electrum::Client,
    joinstr::{Joinstr, Step},
    nostr::{sync::NostrClient, Pool},
    signer::{Coin, CoinPath, WpkhHotSigner},
    utils::now,
};

#[derive(Debug)]
pub enum Error {
    Unknown,
    NostrClient(crate::nostr::error::Error),
    SerdeJson(serde_json::Error),
    Joinstr(crate::joinstr::Error),
    Signer(crate::signer::Error),
    Electrum(crate::electrum::Error),
    /// The coinjoin ended without a final transaction: the pool timed out
    /// before enough peers registered, or a peer aborted.
    CoinjoinNotFinalized,
    /// The worker thread running the blocking coinjoin panicked.
    CoinjoinThreadPanicked,
    /// `list_coins` was given a range whose end precedes its start.
    InvertedScanRange {
        start: u32,
        end: u32,
    },
    /// `list_coins` was given a range spanning more than [`MAX_SCAN_SPAN`].
    ScanRangeTooLarge {
        span: u32,
        max: u32,
    },
    /// `now() + max_duration` does not fit in a u64 unix timestamp.
    PoolDurationOverflow {
        max_duration: u64,
    },
}

/// Upper bound on the number of derivation indexes a single [`list_coins`] call
/// may scan. Each index issues two synchronous electrum queries, so an
/// unbounded span (e.g. `0..u32::MAX`) would hang the caller indefinitely.
pub const MAX_SCAN_SPAN: u32 = 100_000;

/// How many addresses `list_coins` asks for in a single electrum batch.
/// Kept modest because servers cap how large a batch they accept.
const SCAN_BATCH_SIZE: usize = 50;

impl From<crate::nostr::error::Error> for Error {
    fn from(value: crate::nostr::error::Error) -> Self {
        Self::NostrClient(value)
    }
}

impl From<crate::joinstr::Error> for Error {
    fn from(value: crate::joinstr::Error) -> Self {
        Self::Joinstr(value)
    }
}

impl From<crate::signer::Error> for Error {
    fn from(value: crate::signer::Error) -> Self {
        Self::Signer(value)
    }
}

impl From<crate::electrum::Error> for Error {
    fn from(value: crate::electrum::Error) -> Self {
        Self::Electrum(value)
    }
}

impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Self {
        Self::SerdeJson(value)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Unknown => write!(f, "Unknown error!"),
            Error::NostrClient(e) => write!(f, "NostrClient error: {:?}", e),
            Error::SerdeJson(e) => write!(f, "serde_json error: {:?}", e),
            Error::Joinstr(e) => write!(f, "Joinstr error: {:?}", e),
            Error::Signer(e) => write!(f, "Signer error: {:?}", e),
            Error::Electrum(e) => write!(f, "Electrum error: {:?}", e),
            Error::CoinjoinNotFinalized => {
                write!(f, "Coinjoin did not produce a final transaction")
            }
            Error::CoinjoinThreadPanicked => {
                write!(f, "Coinjoin worker thread panicked")
            }
            Error::InvertedScanRange { start, end } => {
                write!(f, "invalid range: end {end} is before start {start}")
            }
            Error::ScanRangeTooLarge { span, max } => {
                write!(f, "range span {span} exceeds maximum {max}")
            }
            Error::PoolDurationOverflow { max_duration } => {
                write!(f, "max_duration {max_duration} overflows the pool expiry")
            }
        }
    }
}

pub struct PoolConfig {
    pub denomination: f64,
    pub fee: u32,
    pub max_duration: u64,
    pub peers: usize,
    pub network: Network,
}

pub struct PeerConfig {
    pub mnemonics: Mnemonic,
    pub electrum_address: String,
    pub electrum_port: u16,
    pub input: Coin,
    pub output: Address<NetworkUnchecked>,
    pub relay: String,
    pub network: Network,
    /// SOCKS5 proxy (`host:port`) for every relay and electrum connection this
    /// peer opens, e.g. a local Tor port. `None` connects directly.
    pub proxy: Option<String>,
}

/// Reject inverted and oversized scan ranges before they reach electrum.
///
/// An inverted range would otherwise iterate zero times below and return an
/// empty `Vec`, reporting "you have no coins" rather than a bad argument.
pub fn check_scan_range(range: (u32, u32)) -> Result<(), Error> {
    let (start, end) = range;
    if end < start {
        return Err(Error::InvertedScanRange { start, end });
    }
    if end - start > MAX_SCAN_SPAN {
        return Err(Error::ScanRangeTooLarge {
            span: end - start,
            max: MAX_SCAN_SPAN,
        });
    }
    Ok(())
}

/// List available coins
// FIXME: this function is a ugly+ineficient hack, we should use
// the electrum notification mechanism and let consumer poll our
// static/cached state
pub fn list_coins(
    mnemonics: &str,
    electrum_address: String,
    electrum_port: u16,
    range: (u32, u32),
    network: Network,
    proxy: Option<String>,
) -> Result<Vec<Coin>, Error> {
    check_scan_range(range)?;
    let mut signer = WpkhHotSigner::new_from_mnemonics(network, mnemonics)?;
    let client = Client::new_with_proxy(&electrum_address, electrum_port, proxy)?;
    signer.set_client(client);

    // Scan in batches: one round trip per address is unusable over tor, and the
    // whole range is scanned in a handful of requests instead. Chunked rather
    // than sent as one huge batch because servers cap the batch size.
    let paths: Vec<CoinPath> = (range.0..range.1)
        .flat_map(|i| [CoinPath::new(0, i), CoinPath::new(1, i)])
        .collect();

    // Do not let a failing query masquerade as an empty wallet: if the scan
    // finds nothing while a batch errored, surface that error.
    let mut first_error = None;
    for chunk in paths.chunks(SCAN_BATCH_SIZE) {
        if let Err(e) = signer.get_coins_at_batch(chunk) {
            first_error.get_or_insert(e);
        }
    }

    let coins: Vec<Coin> = signer.list_coins().into_iter().map(|c| c.1).collect();

    if coins.is_empty() {
        if let Some(e) = first_error {
            return Err(e.into());
        }
    }

    Ok(coins)
}

/// Initiate and participate to a coinjoin
///
/// # Arguments
/// * `config` - configuration of the pool to initiate
/// * `peer` - information about the peer
///
pub fn initiate_coinjoin(config: PoolConfig, peer: PeerConfig) -> Result<Txid, Error> {
    initiate_coinjoin_with_progress(config, peer, |_| {})
}

/// Like [`initiate_coinjoin`], but reports each coinjoin [`Step`] to `on_step`
/// as it happens, so a caller can render a progress timeline. The blocking
/// coinjoin runs on a worker thread while this polls the current step; polling
/// (rather than the `notif` callback) avoids the deadlock that callback hits
/// when it fires while the inner lock is held.
pub fn initiate_coinjoin_with_progress<F: Fn(Step)>(
    config: PoolConfig,
    peer: PeerConfig,
    on_step: F,
) -> Result<Txid, Error> {
    // `max_duration` arrives unvalidated from the bindings. An unchecked add
    // panics in debug and wraps to a past timestamp in release, creating a pool
    // that is born expired.
    let expiry = now()
        .checked_add(config.max_duration)
        .ok_or(Error::PoolDurationOverflow {
            max_duration: config.max_duration,
        })?;

    let (url, port) = (peer.electrum_address, peer.electrum_port);
    let proxy = peer.proxy;
    let mut initiator = Joinstr::new_initiator(
        Keys::generate(),
        peer.relay.clone(),
        (&url, port),
        config.network,
        proxy.clone(),
        "initiator",
    )?
    .denomination(config.denomination)?
    .fee(config.fee)?
    .simple_timeout(expiry)?
    .min_peers(config.peers)?;

    // `Mnemonic::to_string` renders the seed into a fresh `String`; wipe it
    // rather than leaving it in freed heap.
    let mnemonics = Zeroizing::new(peer.mnemonics.to_string());
    let mut signer = WpkhHotSigner::new_from_mnemonics(config.network, &mnemonics)?;
    let client = Client::new_with_proxy(&url, port, proxy)?;
    signer.set_client(client);

    initiator.set_coin(peer.input)?;
    initiator.set_address(peer.output)?;

    run_coinjoin_with_progress(initiator, signer, None, on_step)
}

/// Runs `start_coinjoin_blocking` on a worker thread, polling the step and
/// forwarding each change to `on_step`, and returns the final txid.
fn run_coinjoin_with_progress<F: Fn(Step)>(
    joinstr: Joinstr<'static>,
    signer: WpkhHotSigner,
    pool: Option<Pool>,
    on_step: F,
) -> Result<Txid, Error> {
    let progress = joinstr.clone();
    let mut runner = joinstr;
    let handle = std::thread::spawn(move || -> Result<Txid, Error> {
        runner.start_coinjoin_blocking(pool, Some(signer), || {})?;
        Ok(runner
            .final_tx()
            .ok_or(Error::CoinjoinNotFinalized)?
            .compute_txid())
    });

    let mut last: Option<Step> = None;
    let mut report = |step: Step| {
        if last != Some(step) {
            on_step(step);
            last = Some(step);
        }
    };

    while !handle.is_finished() {
        report(progress.current_step());
        std::thread::sleep(Duration::from_millis(300));
    }
    // Surface any step reached in the gap between the last poll and the thread
    // finishing (e.g. Broadcast/Mined).
    report(progress.current_step());

    handle.join().map_err(|_| Error::CoinjoinThreadPanicked)?
}

/// List available pools
///
/// # Arguments
/// * `back` - how many second back look in the past
/// * `timeout` - how many microseconds we will wait before fetching relay notifications
/// * `relay` - the relay url, must start w/ `wss://` or `ws://`
///
/// # Returns a [`Vec`]  of [`String`] containing a json serialization of a [`Pool`]
pub fn list_pools(
    back: u64,
    timeout: u64,
    relay: String,
    proxy: Option<String>,
) -> Result<Vec<Pool>, Error> {
    let mut pools = Vec::new();
    let mut pool_listener = NostrClient::new("pool_listener")
        .relay(relay)?
        .proxy(proxy)?
        .keys(Keys::generate())?;
    pool_listener.connect_nostr()?;
    // subscribe to kind:2022 pool events published within the last `back` seconds
    pool_listener.subscribe_pools(back)?;

    // Cap the number of pools we accept in a single window so a hostile relay
    // that streams events for the whole window cannot exhaust memory. Generous
    // enough to never clip a legitimate relay's pool list.
    const MAX_POOLS: usize = 10_000;

    // Poll for the whole window rather than sleeping once and draining at the
    // end. A single trailing drain misses events (the relay delivers them to the
    // live subscription, not on a late replay) and lets the idle connection
    // drop; polling keeps it pumped and collects pools as they arrive.
    let deadline = Instant::now() + Duration::from_micros(timeout);
    'outer: while Instant::now() < deadline {
        // Drain what is queued, but stop at the deadline so a relay that keeps
        // the queue non-empty cannot hold us here past the timeout.
        while Instant::now() < deadline {
            match pool_listener.receive_pool_notification()? {
                Some(pool) => {
                    pools.push(pool);
                    if pools.len() >= MAX_POOLS {
                        break 'outer;
                    }
                }
                None => break,
            }
        }
        // Only sleep if there is time left, and never past the deadline: a
        // trailing sleep on the last iteration would overshoot the timeout and
        // impose a ~200ms floor even for a tiny window.
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        sleep(std::cmp::min(Duration::from_millis(200), deadline - now));
    }

    Ok(pools)
}

/// Try to join an already initiated coinjoin
///
/// # Arguments
/// * `pool` - information about the pool
/// * `peer` - information about the peer
///
pub fn join_coinjoin(pool: Pool, peer: PeerConfig) -> Result<String /* Txid */, Error> {
    join_coinjoin_with_progress(pool, peer, |_| {})
}

/// Like [`join_coinjoin`], but reports each coinjoin [`Step`] to `on_step` as it
/// happens (see [`initiate_coinjoin_with_progress`]).
pub fn join_coinjoin_with_progress<F: Fn(Step)>(
    pool: Pool,
    peer: PeerConfig,
    on_step: F,
) -> Result<String /* Txid */, Error> {
    let (url, port) = (peer.electrum_address, peer.electrum_port);
    let proxy = peer.proxy;
    let joinstr_peer = Joinstr::new_peer_with_electrum(
        peer.relay.clone(),
        &pool,
        (&url, port),
        peer.input,
        peer.output,
        peer.network,
        proxy.clone(),
        "peer",
    )?;

    // As in `initiate_coinjoin`: wipe the rendered copy of the seed.
    let mnemonics = Zeroizing::new(peer.mnemonics.to_string());
    let mut signer = WpkhHotSigner::new_from_mnemonics(peer.network, &mnemonics)?;
    let client = Client::new_with_proxy(&url, port, proxy)?;
    signer.set_client(client);

    // Pass the pool so the peer JOINS it. `start_coinjoin_blocking(None, ..)`
    // takes the initiator branch and broadcasts a fresh pool instead, so the
    // joiner would never connect to the pool it meant to join.
    let txid = run_coinjoin_with_progress(joinstr_peer, signer, Some(pool), on_step)?;
    Ok(txid.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err_string(range: (u32, u32)) -> String {
        check_scan_range(range).unwrap_err().to_string()
    }

    #[test]
    fn scan_range_accepts_empty_and_max_span() {
        assert!(check_scan_range((0, 0)).is_ok());
        assert!(check_scan_range((5, 6)).is_ok());
        assert!(check_scan_range((0, MAX_SCAN_SPAN)).is_ok());
        // The bound is on the span, not on the absolute indexes.
        assert!(check_scan_range((u32::MAX - MAX_SCAN_SPAN, u32::MAX)).is_ok());
    }

    #[test]
    fn scan_range_rejects_span_over_max() {
        assert!(err_string((0, MAX_SCAN_SPAN + 1)).contains("exceeds maximum"));
    }

    /// An inverted range must be rejected before the span subtraction, which
    /// would otherwise underflow (panic in debug, wrap in release), and before
    /// the scan loop, which would iterate zero times and report "no coins".
    #[test]
    fn scan_range_rejects_inverted_range() {
        assert!(err_string((10, 9)).contains("is before start"));
        assert!(err_string((u32::MAX, 0)).contains("is before start"));
    }
}
