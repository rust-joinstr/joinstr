use std::{
    fmt::Debug,
    io::ErrorKind,
    net::{TcpStream, ToSocketAddrs},
    sync::{
        mpsc::{self, Receiver, Sender},
        Arc, LazyLock,
    },
    time::{Duration, Instant, SystemTime},
};

use backoff::Backoff;
use nostr::{
    event::{Event, EventBuilder, EventId, Kind, Tag},
    key::{Keys, PublicKey},
    message::{ClientMessage, RawRelayMessage, RelayMessage, SubscriptionId},
    nips::nip04,
    types::{Filter, Timestamp},
    util::JsonUtil,
};
use tungstenite::{
    client::IntoClientRequest, stream::MaybeTlsStream, Message as WsMessage, WebSocket,
};

pub use nostr;
pub use tungstenite;

const PING_INTERVAL: u64 = 5; // ping interval in seconds

// Bound the TCP connect and the TLS + WebSocket handshake so a pool-supplied
// relay that accepts the connection and then stalls cannot wedge `connect()`
// forever. `set_nonblocking` supersedes these once the handshake completes.
// Shared with the electrum clients so every tor path uses one budget.
use socks5::{CONNECT_TIMEOUT, HANDSHAKE_TIMEOUT};

type Socket = WebSocket<MaybeTlsStream<TcpStream>>;

#[derive(Debug)]
pub enum Error {
    // Boxed: `tungstenite::Error` embeds an `http::Response`, so keeping it
    // inline would make every `Result<_, Error>` large (clippy::result_large_err).
    WebSocket(Box<tungstenite::Error>),
    Listen,
    Send,
    Receive,
    NonBlocking,
    NotConnected,
    KeysMissing,
    ArgMissing,
    Nip04Encrypt,
    Nip04Decrypt,
    NotNip04,
    SignEvent,
    ConnectionClosed,
    RawRelayMessage,
    RelayMessage,
    /// The relay did not acknowledge the event with an `OK` before the deadline.
    OkTimeout,
    /// The relay rejected the event (`OK` with `false`); carries its message.
    EventRejected(String),
}

impl From<tungstenite::Error> for Error {
    fn from(value: tungstenite::Error) -> Self {
        Self::WebSocket(Box::new(value))
    }
}

type Message = String;

/// A rustls client config using the `ring` crypto provider (rustls' default
/// `aws-lc-rs` provider cannot be cross-compiled to Android) and the bundled
/// Mozilla root set (webpki-roots), independent of any system trust store.
/// Built once and shared: joinstr opens one relay connection per pool, so
/// rebuilding the root store on every connect is wasteful.
static TLS_CONFIG: LazyLock<Arc<rustls::ClientConfig>> = LazyLock::new(|| {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    Arc::new(
        rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("ring provider supports the default protocol versions")
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    )
});

fn tls_config() -> Arc<rustls::ClientConfig> {
    TLS_CONFIG.clone()
}

/// The underlying `TcpStream`, whether the connection is plaintext (`ws://`) or
/// TLS (`wss://`).
fn tcp_stream(ws: &Socket) -> Option<&TcpStream> {
    // `MaybeTlsStream` is `#[non_exhaustive]`; only the rustls and plaintext
    // backends are compiled in, but return `None` rather than panicking should
    // a future variant appear.
    match ws.get_ref() {
        MaybeTlsStream::Plain(s) => Some(s),
        MaybeTlsStream::Rustls(s) => Some(&s.sock),
        _ => None,
    }
}

#[derive(Debug)]
pub enum SendMsg {
    Msg(Message),
    Stop,
}

#[derive(Debug)]
pub enum RecvMsg {
    Close,
    Msg(Message),
}

pub struct WsClient {
    client: Option<Socket>,
    sender: Sender<SendMsg>,
    ws_receiver: Option<Receiver<SendMsg>>,
    receiver: Receiver<RecvMsg>,
    ws_sender: Option<Sender<RecvMsg>>,
    connected: bool,
    relay: String,
    keys: Keys,
}

impl Debug for WsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WsClient")
            .field("connected", &self.connected)
            .field("relay", &self.relay)
            .field("keys", &self.keys)
            .finish()
    }
}

#[derive(Debug, Default, Clone)]
pub struct WsClientBuilder {
    relay: Option<String>,
    keys: Option<Keys>,
    /// SOCKS5 proxy (`host:port`) to reach the relay through, e.g. a local Tor
    /// port. `None` connects directly.
    proxy: Option<String>,
}

impl WsClientBuilder {
    pub fn relay<T: Into<String>>(mut self, relay: T) -> Self {
        self.set_relay(relay);
        self
    }

    pub fn set_relay<T: Into<String>>(&mut self, relay: T) {
        self.relay = Some(relay.into());
    }

    pub fn get_relay(&self) -> Option<String> {
        self.relay.clone()
    }

    pub fn proxy<T: Into<String>>(mut self, proxy: Option<T>) -> Self {
        self.proxy = proxy.map(Into::into);
        self
    }

    pub fn set_proxy<T: Into<String>>(&mut self, proxy: Option<T>) {
        self.proxy = proxy.map(Into::into);
    }

    pub fn keys(mut self, keys: Keys) -> Self {
        self.keys = Some(keys);
        self
    }

    pub fn set_keys(&mut self, keys: Keys) {
        self.keys = Some(keys);
    }

    pub fn get_keys(&self) -> Option<&Keys> {
        self.keys.as_ref()
    }

    pub fn connect(self) -> Result<WsClient, Error> {
        let (url, keys) = if let (Some(url), Some(keys)) = (self.relay, self.keys) {
            (url, keys)
        } else {
            return Err(Error::ArgMissing);
        };
        let proxy = self.proxy;

        let request = url.as_str().into_client_request()?;
        let uri = request.uri();
        let host = uri.host().ok_or(Error::ArgMissing)?.to_string();
        let port = uri
            .port_u16()
            .unwrap_or(if uri.scheme_str() == Some("wss") {
                443
            } else {
                80
            });
        // Through a proxy: hand the relay hostname to the proxy (remote DNS, no
        // local lookup) on its own isolated circuit. Directly: try every
        // resolved address with a bounded connect so a dead first record
        // neither hangs nor fails the whole attempt. Either way the handshake
        // below is bounded.
        let mut last_err = None;
        let tcp = 'connect: {
            if let Some(proxy) = proxy.as_deref() {
                break 'connect socks5::connect(
                    proxy,
                    &host,
                    port,
                    &socks5::isolation_token(),
                    CONNECT_TIMEOUT,
                )
                .map_err(|e| Error::WebSocket(Box::new(tungstenite::Error::Io(e))))?;
            }
            let addrs = (host.as_str(), port)
                .to_socket_addrs()
                .map_err(|e| Error::WebSocket(Box::new(tungstenite::Error::Io(e))))?;
            for a in addrs {
                match TcpStream::connect_timeout(&a, CONNECT_TIMEOUT) {
                    Ok(s) => break 'connect s,
                    Err(e) => last_err = Some(e),
                }
            }
            let e = last_err
                .unwrap_or_else(|| std::io::Error::new(ErrorKind::NotFound, "no address resolved"));
            return Err(Error::WebSocket(Box::new(tungstenite::Error::Io(e))));
        };
        // Bound the TLS + WebSocket handshake; set_nonblocking after it returns
        // supersedes these for the read loop.
        let _ = tcp.set_read_timeout(Some(HANDSHAKE_TIMEOUT));
        let _ = tcp.set_write_timeout(Some(HANDSHAKE_TIMEOUT));

        // Force the `ring` provider by supplying our own rustls connector;
        // tungstenite's auto-negotiation would otherwise pick `aws-lc-rs`. For
        // plaintext `ws://` relays the connector is simply unused.
        let connector = tungstenite::Connector::Rustls(tls_config());
        // Bound tungstenite's defaults (64 MiB message / 16 MiB frame /
        // unbounded write buffer): a hostile relay could otherwise push a huge
        // frame at a phone, and the write buffer can grow without limit when a
        // relay stops reading our non-blocking socket.
        let ws_config = tungstenite::protocol::WebSocketConfig {
            max_message_size: Some(512 * 1024),
            max_frame_size: Some(256 * 1024),
            max_write_buffer_size: 1024 * 1024,
            ..Default::default()
        };
        // The socket is still blocking here, so the handshake runs to
        // completion (never `Interrupted`).
        let (client, _resp) =
            tungstenite::client_tls_with_config(request, tcp, Some(ws_config), Some(connector))
                .map_err(|e| match e {
                    tungstenite::HandshakeError::Failure(err) => Error::WebSocket(Box::new(err)),
                    tungstenite::HandshakeError::Interrupted(_) => {
                        Error::WebSocket(Box::new(tungstenite::Error::Io(std::io::Error::new(
                            ErrorKind::WouldBlock,
                            "handshake interrupted",
                        ))))
                    }
                })?;
        tcp_stream(&client)
            .ok_or(Error::NonBlocking)?
            .set_nonblocking(true)
            .map_err(|_| Error::NonBlocking)?;

        let (sender, ws_receiver) = mpsc::channel();
        let (ws_sender, receiver) = mpsc::channel();
        let mut client = WsClient {
            client: Some(client),
            sender,
            ws_receiver: Some(ws_receiver),
            receiver,
            ws_sender: Some(ws_sender),
            connected: false,
            relay: url,
            keys,
        };
        client.listen()?;
        Ok(client)
    }
}

impl WsClient {
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> WsClientBuilder {
        WsClientBuilder::default()
    }

    pub fn pubkey(&self) -> PublicKey {
        self.keys.public_key
    }

    fn listen(&mut self) -> Result<(), Error> {
        if let (Some(client), Some(sender), Some(receiver)) = (
            self.client.take(),
            self.ws_sender.take(),
            self.ws_receiver.take(),
        ) {
            std::thread::spawn(|| listen(client, sender, receiver));
            self.connected = true;
            Ok(())
        } else {
            Err(Error::Listen)
        }
    }

    pub fn encrypt<T>(&mut self, receiver: &PublicKey, content: T) -> Result<String, Error>
    where
        T: AsRef<[u8]>,
    {
        nip04::encrypt(self.get_keys().secret_key(), receiver, content)
            .map_err(|_| Error::Nip04Encrypt)
    }

    pub fn decrypt_dm(&mut self, mut event: Event) -> Result<Event, Error> {
        if event.kind != Kind::EncryptedDirectMessage {
            return Err(Error::NotNip04);
        }
        let content = self.decrypt(&event.pubkey, event.content)?;
        event.content = content;
        Ok(event)
    }

    pub fn decrypt(&mut self, event_pubkey: &PublicKey, content: String) -> Result<String, Error> {
        nip04::decrypt(self.get_keys().secret_key(), event_pubkey, content)
            .map_err(|_| Error::Nip04Decrypt)
    }

    pub fn subscribe_dm(&mut self) -> Result<(), Error> {
        self.is_connected()?;
        let filter = Filter::new()
            .kind(Kind::EncryptedDirectMessage)
            .pubkey(self.get_keys().public_key());
        let msg = nostr::ClientMessage::req(SubscriptionId::generate(), vec![filter]);
        self.send_raw(msg.as_json())?;
        Ok(())
    }

    pub fn subscribe_pool(&mut self, back: u64) -> Result<(), Error> {
        self.is_connected()?;
        let since = Timestamp::now() - Timestamp::from_secs(back);
        let filter = Filter::new().kind(Kind::Custom(2022)).since(since);
        let msg = nostr::ClientMessage::req(SubscriptionId::generate(), vec![filter]);
        self.send_raw(msg.as_json())?;
        Ok(())
    }

    pub fn send_dm<T: Into<String>>(
        &mut self,
        content: T,
        receiver: &PublicKey,
    ) -> Result<(), Error> {
        let content = self.encrypt(receiver, content.into())?;
        let dm = EventBuilder::new(
            Kind::EncryptedDirectMessage,
            content,
            vec![Tag::public_key(*receiver)],
        );
        self.post_event(dm)
    }

    /// Like [`send_dm`], but wait for the relay's `OK` acknowledgement and return
    /// the accepted event id. Reference joinstr clients confirm every send this
    /// way; without it a fire-and-forget event can be silently dropped and a
    /// peer waits forever for a registration that never arrived.
    pub fn send_dm_confirmed<T: Into<String>>(
        &mut self,
        content: T,
        receiver: &PublicKey,
        timeout: Duration,
    ) -> Result<EventId, Error> {
        let content = self.encrypt(receiver, content.into())?;
        let dm = EventBuilder::new(
            Kind::EncryptedDirectMessage,
            content,
            vec![Tag::public_key(*receiver)],
        );
        self.post_event_confirmed(dm, timeout)
    }

    /// Post an event and block until the relay accepts it with `OK`, returning
    /// its id. Errors on rejection or if no `OK` arrives before `timeout`.
    pub fn post_event_confirmed(
        &mut self,
        event: EventBuilder,
        timeout: Duration,
    ) -> Result<EventId, Error> {
        self.is_connected()?;
        let event = event
            .to_event(self.get_keys())
            .map_err(|_| Error::SignEvent)?;
        let event_id = event.id;
        self.send_raw(ClientMessage::event(event).as_json())?;

        let deadline = Instant::now() + timeout;
        loop {
            if Instant::now() >= deadline {
                return Err(Error::OkTimeout);
            }
            match self.try_receive_message()? {
                Some(RelayMessage::Ok {
                    event_id: id,
                    status,
                    message,
                }) if id == event_id => {
                    return if status {
                        Ok(event_id)
                    } else {
                        Err(Error::EventRejected(message))
                    };
                }
                // EOSE, other events, OK for a different id: keep waiting.
                Some(_) => {}
                None => std::thread::sleep(Duration::from_millis(50)),
            }
        }
    }

    /// Receive and parse the next relay message without decrypting DMs, so the
    /// caller can match control frames such as `OK`.
    fn try_receive_message(&mut self) -> Result<Option<RelayMessage>, Error> {
        match self.try_receive_raw()? {
            Some(RecvMsg::Close) => Err(Error::ConnectionClosed),
            Some(RecvMsg::Msg(t)) => {
                let raw = RawRelayMessage::from_json(t).map_err(|_| Error::RawRelayMessage)?;
                let msg = RelayMessage::try_from(raw).map_err(|_| Error::RelayMessage)?;
                Ok(Some(msg))
            }
            None => Ok(None),
        }
    }

    fn send_raw(&mut self, msg: Message) -> Result<(), Error> {
        self.is_connected()?;
        self.sender.send(SendMsg::Msg(msg)).map_err(|_| Error::Send)
    }

    fn try_receive_raw(&mut self) -> Result<Option<RecvMsg>, Error> {
        self.is_connected()?;
        let msg = match self.receiver.try_recv() {
            Ok(m) => Ok(Some(m)),
            Err(e) => match e {
                mpsc::TryRecvError::Empty => Ok(None),
                mpsc::TryRecvError::Disconnected => Err(Error::Receive),
            },
        };
        if let Ok(Some(RecvMsg::Close)) = msg {
            self.connected = false;
        }
        msg
    }

    pub fn try_receive(&mut self) -> Result<Option<Event>, Error> {
        match self.try_receive_raw()? {
            Some(m) => match m {
                RecvMsg::Close => Err(Error::ConnectionClosed),
                RecvMsg::Msg(t) => match RawRelayMessage::from_json(t) {
                    Ok(rrm) => match RelayMessage::try_from(rrm) {
                        Ok(rm) => match rm {
                            RelayMessage::Event { event, .. } => {
                                #[allow(deprecated)]
                                if event.kind() == Kind::EncryptedDirectMessage {
                                    let event = self.decrypt_dm(*event)?;
                                    Ok(Some(event))
                                } else {
                                    Ok(Some(*event))
                                }
                            }
                            RelayMessage::Auth { .. } => {
                                log::error!("unexpected auth message");
                                Ok(None)
                            }
                            _ => Ok(None),
                        },
                        Err(_) => Err(Error::RelayMessage),
                    },
                    Err(_) => Err(Error::RawRelayMessage),
                },
            },
            None => Ok(None),
        }
    }

    pub fn stop(&mut self) {
        if self.connected {
            self.connected = false;
            _ = self.sender.send(SendMsg::Stop);
        }
    }

    pub fn get_relay(&self) -> String {
        self.relay.clone()
    }

    pub fn is_connected(&self) -> Result<(), Error> {
        if self.connected {
            Ok(())
        } else {
            Err(Error::NotConnected)
        }
    }

    pub fn get_keys(&self) -> &Keys {
        &self.keys
    }

    pub fn post_event(&mut self, event: EventBuilder) -> Result<(), Error> {
        self.is_connected()?;
        let event = event
            .to_event(self.get_keys())
            .map_err(|_| Error::SignEvent)?;
        let msg = ClientMessage::event(event);
        log::debug!("_post_event() msg: {:?}", msg);
        self.send_raw(msg.as_json())
    }
}

impl Drop for WsClient {
    fn drop(&mut self) {
        self.stop();
    }
}

pub fn listen(mut client: Socket, sender: Sender<RecvMsg>, receiver: Receiver<SendMsg>) {
    let mut backoff = Backoff::new_us(50);

    let mut last_ping = SystemTime::now();
    let mut last_pong = SystemTime::now();
    let mut ping_nonce = 0u8;
    loop {
        let mut wait = true;
        match receiver.try_recv() {
            Ok(m) => match m {
                SendMsg::Msg(m) => {
                    wait = false;
                    match client.send(WsMessage::text(m)) {
                        Ok(()) => {}
                        // On the non-blocking socket a full write buffers in
                        // tungstenite and flushes on a later call, so this is
                        // not a lost frame, just backpressure.
                        Err(tungstenite::Error::Io(e)) if e.kind() == ErrorKind::WouldBlock => {}
                        Err(e) => log::error!("listen(): fail to send message: {:?}", e),
                    }
                }
                SendMsg::Stop => return,
            },
            Err(mpsc::TryRecvError::Empty) => {}
            _ => return,
        }

        match client.read() {
            Ok(m) => {
                wait = false;
                match m {
                    WsMessage::Text(m) => {
                        log::debug!("recv text: {:?}", m);
                        let _ = sender.send(RecvMsg::Msg(m));
                    }
                    WsMessage::Binary(m) => {
                        log::error!("listen() unexpected binary message {:?}", m);
                    }
                    WsMessage::Close(_) => {
                        log::debug!("recv: Close ");
                        sender.send(RecvMsg::Close).expect("main thread panicked");
                    }
                    WsMessage::Ping(_) => {
                        // tungstenite auto-queues the Pong on read(); a manual
                        // reply here would send a redundant second pong.
                    }
                    WsMessage::Pong(_) => {
                        last_pong = SystemTime::now();
                    }
                    WsMessage::Frame(_) => {}
                }
            }
            // `WouldBlock` means no message is ready and `Interrupted` (EINTR)
            // is transient (std does not retry it for us): keep looping, do not
            // treat either as a disconnect.
            Err(tungstenite::Error::Io(e))
                if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {}
            // Any other read error (ConnectionClosed, AlreadyClosed, a hard Io
            // like ECONNRESET, or a Protocol/Tls/Capacity fault) is fatal: the
            // relay is gone, so signal Close and stop rather than spin forever.
            Err(e) => {
                log::error!("listen(): read error: {:?}", e);
                let _ = sender.send(RecvMsg::Close);
                return;
            }
        }

        if SystemTime::now()
            .duration_since(last_ping)
            .expect("valid duration")
            > Duration::from_secs(PING_INTERVAL)
        {
            last_ping = SystemTime::now();
            ping_nonce = ping_nonce.wrapping_add(1);
            _ = client.send(WsMessage::Ping(vec![ping_nonce]));
        }

        if SystemTime::now()
            .duration_since(last_pong)
            .expect("valid duration")
            > Duration::from_secs(3 * PING_INTERVAL)
        {
            _ = sender.send(RecvMsg::Close);
            return;
        }

        if wait {
            backoff.snooze();
        }
    }
}
