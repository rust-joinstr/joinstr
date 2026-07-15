use super::Error;
use std::{
    io::Write,
    net::{self, ToSocketAddrs},
    sync::{Arc, LazyLock, Mutex},
    time::Duration,
};

type TlsStream = rustls::StreamOwned<rustls::ClientConnection, net::TcpStream>;
type SharedStream = Arc<Mutex<TlsStream>>;

/// Bound the TCP connect and the TLS handshake so a server that accepts the
/// connection and then stalls cannot hang `try_connect` (and thus
/// `Client::new`) forever. Superseded by the caller's own timeouts once the
/// handshake completes.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Verifying rustls config (bundled Mozilla roots, `ring` provider), built once
/// and shared: joinstr opens one connection per pool, so rebuilding the root
/// store and provider on every `try_connect` is wasteful.
static VERIFYING_TLS_CONFIG: LazyLock<Arc<rustls::ClientConfig>> = LazyLock::new(|| {
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

#[derive(Debug)]
pub struct SslClient {
    url: String,
    port: u16,
    pub(crate) proxy: Option<String>,
    pub(crate) stream: Option<SharedStream>,
    pub(crate) read_timeout: Option<Duration>,
    pub(crate) write_timeout: Option<Duration>,
    pub(crate) verif_certificate: bool,
}

impl Clone for SslClient {
    fn clone(&self) -> Self {
        Self {
            url: self.url.clone(),
            port: self.port,
            proxy: self.proxy.clone(),
            stream: self.stream.clone(),
            read_timeout: self.read_timeout,
            write_timeout: self.write_timeout,
            verif_certificate: self.verif_certificate,
        }
    }
}

impl Drop for SslClient {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

impl Default for SslClient {
    fn default() -> Self {
        Self {
            url: Default::default(),
            port: 50002,
            proxy: None,
            stream: None,
            read_timeout: None,
            write_timeout: None,
            verif_certificate: true,
        }
    }
}

impl SslClient {
    pub fn url(mut self, url: &str) -> Self {
        if !self.is_connected() {
            self.url = url.into();
        } else {
            log::error!("Cannot change url of a connected SslClient!")
        }
        self
    }

    pub fn proxy(mut self, proxy: Option<String>) -> Self {
        if !self.is_connected() {
            self.proxy = proxy;
        } else {
            log::error!("Cannot change proxy of a connected SslClient!")
        }
        self
    }

    pub fn port(mut self, port: u16) -> Self {
        if !self.is_connected() {
            self.port = port;
        } else {
            log::error!("Cannot change port of a connected TcpClient!")
        }
        self
    }

    pub fn is_connected(&self) -> bool {
        self.stream.is_some()
    }

    pub fn try_connect(&mut self) -> Result<(), Error> {
        let addr = format!("{}:{}", self.url, self.port);

        let config = if self.verif_certificate {
            // Verify the server certificate against the bundled Mozilla root
            // set (webpki-roots), independent of any system trust store. Reuse
            // the cached config to avoid rebuilding the root store per connect.
            VERIFYING_TLS_CONFIG.clone()
        } else {
            // DANGEROUS: certificate verification disabled. Reached only when
            // `verif_certificate == false`, i.e. for self-signed regtest/dev
            // servers. Always use the `ring` crypto provider: rustls' default
            // `aws-lc-rs` provider cannot be cross-compiled to Android.
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            Arc::new(
                rustls::ClientConfig::builder_with_provider(provider)
                    .with_safe_default_protocol_versions()
                    .expect("ring provider supports the default protocol versions")
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(
                        danger::NoCertificateVerification::new(),
                    ))
                    .with_no_client_auth(),
            )
        };

        let server_name = rustls::pki_types::ServerName::try_from(self.url.clone())
            .map_err(|_| Error::InvalidDnsName)?;
        let conn = rustls::ClientConnection::new(config, server_name).map_err(Error::Tls)?;

        // Through a proxy: hand the electrum hostname to the proxy (remote DNS,
        // no local lookup) on its own isolated circuit. Directly: try every
        // resolved address with a bounded connect so a dead first record
        // neither hangs nor fails the whole attempt. TLS runs over the returned
        // socket either way, so the certificate is still verified end to end.
        let mut last_err = None;
        let sock = 'connect: {
            if let Some(proxy) = self.proxy.as_deref() {
                break 'connect socks5::connect(
                    proxy,
                    &self.url,
                    self.port,
                    &socks5::isolation_token(),
                    CONNECT_TIMEOUT,
                )
                .map_err(Error::TcpStream)?;
            }
            for a in addr.to_socket_addrs().map_err(Error::TcpStream)? {
                match net::TcpStream::connect_timeout(&a, CONNECT_TIMEOUT) {
                    Ok(s) => break 'connect s,
                    Err(e) => last_err = Some(e),
                }
            }
            return Err(Error::TcpStream(last_err.unwrap_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "no address resolved")
            })));
        };
        // Bound the handshake below; restored to the caller's timeouts after.
        sock.set_read_timeout(Some(HANDSHAKE_TIMEOUT))
            .map_err(Error::TcpStream)?;
        sock.set_write_timeout(Some(HANDSHAKE_TIMEOUT))
            .map_err(Error::TcpStream)?;

        // `StreamOwned::new` does no IO, so the handshake would otherwise be
        // deferred to the first read/write and a bad certificate would surface
        // as `Error::TcpStream` on the first send (indistinguishable from the
        // network being down). Drive it to completion here, while the socket is
        // still blocking, so verification happens at connect: a rustls TLS
        // failure (expired/self-signed/wrong-host cert) is wrapped by
        // `complete_io` in an `io::Error` whose inner error is a `rustls::Error`,
        // which we downcast back to `Error::Tls`; any other IO failure stays
        // `Error::TcpStream`.
        let mut stream = rustls::StreamOwned::new(conn, sock);
        while stream.conn.is_handshaking() {
            if let Err(e) = stream.conn.complete_io(&mut stream.sock) {
                let kind = e.kind();
                return Err(match e.into_inner() {
                    Some(inner) => match inner.downcast::<rustls::Error>() {
                        Ok(tls) => Error::Tls(*tls),
                        Err(other) => Error::TcpStream(std::io::Error::new(kind, other)),
                    },
                    None => Error::TcpStream(std::io::Error::from(kind)),
                });
            }
        }
        // Handshake done: hand the socket back to the caller's timeout policy
        // (both default to blocking/None) for normal request/response reads.
        stream
            .sock
            .set_read_timeout(self.read_timeout)
            .map_err(Error::TcpStream)?;
        stream
            .sock
            .set_write_timeout(self.write_timeout)
            .map_err(Error::TcpStream)?;
        let stream = Arc::new(Mutex::new(stream));

        if self.stream.is_none() {
            self.stream = Some(stream);
            Ok(())
        } else {
            Err(Error::AlreadyConnected)
        }
    }

    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) -> Result<(), Error> {
        if let Some(stream) = self.stream.as_mut() {
            let stream = stream.lock().map_err(|_| Error::Mutex)?;
            stream
                .sock
                .set_read_timeout(timeout)
                .map_err(Error::TcpStream)?;
        }
        self.read_timeout = timeout;
        Ok(())
    }

    pub fn set_write_timeout(&mut self, timeout: Option<Duration>) -> Result<(), Error> {
        if let Some(stream) = self.stream.as_mut() {
            let stream = stream.lock().map_err(|_| Error::Mutex)?;
            stream
                .sock
                .set_write_timeout(timeout)
                .map_err(Error::TcpStream)?;
        }
        self.write_timeout = timeout;
        Ok(())
    }

    pub fn send(stream: &mut TlsStream, request: &str) -> Result<(), Error> {
        stream
            .write_all(request.as_bytes())
            .map_err(Error::TcpStream)?;
        // add a \n char for EOL
        stream.write_all(&[10]).map_err(Error::TcpStream)?;
        stream.flush().map_err(Error::TcpStream)?;
        Ok(())
    }

    /// Is there application **plaintext** ready to be read without blocking?
    ///
    /// Only decrypted application data counts. Peeking the raw socket would
    /// report non-application TLS records (most importantly the TLS 1.3
    /// `NewSessionTicket` real electrum servers send right after the handshake,
    /// but also key-updates/alerts or a TCP-fragmented partial record) as
    /// "data ready"; `read_line` would then block forever on a socket with no
    /// plaintext behind it. So we check rustls' decrypted buffer, and if it is
    /// empty pump any pending records non-blocking and re-check, never treating
    /// raw encrypted bytes as a readable line.
    fn data_available(stream: &mut TlsStream) -> Result<bool, Error> {
        if Self::plaintext_ready(stream)? {
            return Ok(true);
        }

        stream
            .sock
            .set_nonblocking(true)
            .map_err(|_| Error::SetNonBlocking)?;
        let pumped = Self::pump_tls(stream);
        stream
            .sock
            .set_nonblocking(false)
            .map_err(|_| Error::SetBlocking)?;
        pumped
    }

    /// Plaintext already decrypted and buffered by rustls (a single TLS record
    /// can carry several coalesced response lines). A TLS-layer error here is
    /// propagated rather than masked as "no data", so a broken connection is
    /// surfaced instead of spinning the subscription loop forever.
    fn plaintext_ready(stream: &mut TlsStream) -> Result<bool, Error> {
        Ok(stream
            .conn
            .process_new_packets()
            .map_err(Error::Tls)?
            .plaintext_bytes_to_read()
            > 0)
    }

    /// Read whatever TLS records are pending on the (non-blocking) socket and
    /// report whether any yielded application plaintext. `WouldBlock` and a
    /// clean EOF both mean "nothing readable yet".
    fn pump_tls(stream: &mut TlsStream) -> Result<bool, Error> {
        while stream.conn.wants_read() {
            match stream.conn.read_tls(&mut stream.sock) {
                Ok(0) => return Ok(false),
                Ok(_) => {
                    if Self::plaintext_ready(stream)? {
                        return Ok(true);
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
                Err(e) => return Err(Error::TcpStream(e)),
            }
        }
        Ok(false)
    }

    fn raw_read(stream: &mut TlsStream, blocking: bool) -> Result<Option<String>, Error> {
        // If blocking or data in the receiving end of the stream
        if blocking || Self::data_available(stream)? {
            Ok(Some(super::read_line(stream)?))
        } else {
            Ok(None)
        }
    }

    pub fn try_read(stream: &mut TlsStream) -> Result<Option<String>, Error> {
        Self::raw_read(stream, false)
    }

    pub fn read(stream: &mut TlsStream) -> Result<String, Error> {
        Ok(Self::raw_read(stream, true)?.expect("blocking"))
    }

    pub fn close(&mut self) -> Result<(), Error> {
        if let Some(stream) = self.stream.take() {
            let mut guard = stream.try_lock().map_err(|_| Error::Mutex)?;
            let stream = &mut *guard;
            // Best-effort TLS close_notify before the TCP shutdown so the peer
            // can distinguish a clean close from a truncation attack.
            stream.conn.send_close_notify();
            let _ = stream.conn.write_tls(&mut stream.sock);
            let _ = stream.flush();
            stream
                .sock
                .shutdown(net::Shutdown::Both)
                .map_err(|_| Error::ShutDown)?;
            Ok(())
        } else {
            Err(Error::NotConnected)
        }
    }
}

/// A rustls `ServerCertVerifier` that accepts any server certificate.
///
/// DANGEROUS: only used by [`SslClient::try_connect`] when
/// `verif_certificate == false` (self-signed regtest/dev servers). Handshake
/// signatures are still checked with the `ring` provider; only the certificate
/// chain/identity is left unverified.
mod danger {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::crypto::{ring, verify_tls12_signature, verify_tls13_signature};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, Error, SignatureScheme};

    #[derive(Debug)]
    pub struct NoCertificateVerification(rustls::crypto::WebPkiSupportedAlgorithms);

    impl NoCertificateVerification {
        pub fn new() -> Self {
            Self(ring::default_provider().signature_verification_algorithms)
        }
    }

    impl ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            verify_tls12_signature(message, cert, dss, &self.0)
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            verify_tls13_signature(message, cert, dss, &self.0)
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.0.supported_schemes()
        }
    }
}
