pub(crate) mod ssl_client;
pub(crate) mod tcp_client;

use std::{collections::HashMap, fmt::Display, net, thread, time::Duration};

use crate::electrum::{
    self,
    request::Request,
    response::{parse_str_response, Response},
};

use self::{ssl_client::SslClient, tcp_client::TcpClient};

// Using a 1 byte seek buffer
pub const PEEK_BUFFER_SIZE: usize = 10;

/// Upper bound on a single `\n`-terminated response line. The read loop caps
/// growth here so a server that never sends a newline cannot exhaust memory.
/// This bounds memory, not time: no read timeout is configured, so a server
/// that dribbles bytes slowly without a newline still blocks the caller (a
/// pre-existing slowloris shape, tracked separately). Comfortably above any
/// real electrum reply.
pub const MAX_LINE_LEN: usize = 16 * 1024 * 1024;

#[derive(Debug)]
pub enum Error {
    TcpStream(std::io::Error),
    SslStream(openssl::ssl::HandshakeError<net::TcpStream>),
    Electrum(electrum::Error),
    SslPeek,
    Mutex,
    SslConnector(std::io::Error),
    AlreadyConnected,
    NotConnected,
    NotConfigured,
    LineTooLong,
    ShutDown,
    SetNonBlocking,
    SetBlocking,
    SerializeRequest,
    Batch,
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<electrum::Error> for Error {
    fn from(value: electrum::Error) -> Self {
        Error::Electrum(value)
    }
}

/// Read exactly one `\n`-terminated line straight from `stream`.
///
/// Both the TCP and TLS clients need this identical framing: a per-call
/// `BufReader` would pull the whole pending buffer in, return the first line,
/// then drop the rest, silently losing electrum responses coalesced into the
/// same segment/TLS record and desyncing every later request. Reading
/// byte-by-byte never over-reads. The [`MAX_LINE_LEN`] cap bounds memory so a
/// server that streams data without ever sending a newline cannot exhaust it.
/// EOF returns whatever was accumulated; the terminating `\n` is kept in the
/// line. A line may carry up to [`MAX_LINE_LEN`] content bytes before its `\n`
/// (so a full-length line ending in `\n` is accepted); the `MAX_LINE_LEN + 1`-th
/// non-newline byte is rejected with [`Error::LineTooLong`].
pub(crate) fn read_line<R: std::io::Read>(stream: &mut R) -> Result<String, Error> {
    read_line_capped(stream, MAX_LINE_LEN)
}

fn read_line_capped<R: std::io::Read>(stream: &mut R, max_len: usize) -> Result<String, Error> {
    let mut response = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if stream.read(&mut byte).map_err(Error::TcpStream)? == 0 {
            break;
        }
        if byte[0] == b'\n' {
            response.push(byte[0]);
            break;
        }
        // Reject before storing the `max_len + 1`-th content byte, so a line of
        // exactly `max_len` content bytes followed by `\n` is still accepted.
        if response.len() >= max_len {
            return Err(Error::LineTooLong);
        }
        response.push(byte[0]);
    }
    Ok(String::from_utf8_lossy(&response).into_owned())
}

#[derive(Debug, Default, Clone)]
pub enum Client {
    #[default]
    None,
    Tcp(TcpClient),
    Ssl(SslClient),
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

impl Client {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn tcp(self, url: &str, port: u16) -> Self {
        Self::new_tcp(url, port)
    }

    pub fn new_tcp(url: &str, port: u16) -> Self {
        Self::Tcp(TcpClient::default().url(url).port(port))
    }

    pub fn ssl(self, url: &str, port: u16) -> Self {
        Self::new_ssl(url, port)
    }

    pub fn new_ssl(url: &str, port: u16) -> Self {
        Self::Ssl(SslClient::default().url(url).port(port))
    }

    pub fn new_ssl_maybe(url: &str, port: u16, ssl: bool) -> Self {
        match ssl {
            true => Self::new_ssl(url, port),
            false => Self::new_tcp(url, port),
        }
    }

    pub fn read_timeout(mut self, timeout: Option<Duration>) -> Self {
        match &mut self {
            Client::None => {}
            Client::Tcp(c) => c.read_timeout = timeout,
            Client::Ssl(c) => c.read_timeout = timeout,
        }
        self
    }

    pub fn set_read_timeout(&mut self, timeout: Option<Duration>) -> Result<(), Error> {
        match self {
            Client::None => Err(Error::NotConfigured),
            Client::Tcp(c) => c.set_read_timeout(timeout),
            Client::Ssl(c) => c.set_read_timeout(timeout),
        }
    }

    pub fn write_timeout(mut self, timeout: Option<Duration>) -> Self {
        match &mut self {
            Client::None => {}
            Client::Tcp(c) => c.write_timeout = timeout,
            Client::Ssl(c) => c.write_timeout = timeout,
        }
        self
    }

    pub fn set_write_timeout(&mut self, timeout: Option<Duration>) -> Result<(), Error> {
        match self {
            Client::None => Err(Error::NotConfigured),
            Client::Tcp(c) => c.set_write_timeout(timeout),
            Client::Ssl(c) => c.set_write_timeout(timeout),
        }
    }

    pub fn verif_certificate(mut self, verif: bool) -> Self {
        let connected = self.is_connected();
        if let (
            Self::Ssl(SslClient {
                verif_certificate, ..
            }),
            false,
        ) = (&mut self, connected)
        {
            *verif_certificate = verif;
        }
        self
    }

    pub fn connect(&mut self) {
        self.try_connect().unwrap()
    }

    pub fn is_connected(&self) -> bool {
        match self {
            Client::None => false,
            Client::Tcp(c) => c.is_connected(),
            Client::Ssl(c) => c.is_connected(),
        }
    }

    pub fn try_connect(&mut self) -> Result<(), Error> {
        match self {
            Client::None => Err(Error::NotConfigured),
            Client::Tcp(c) => c.try_connect(),
            Client::Ssl(c) => c.try_connect(),
        }
    }

    pub fn try_connect_retry(&mut self, retry: usize, delay: Duration) -> Result<(), Error> {
        let mut result = self.try_connect();
        let mut count = 0;
        loop {
            match result {
                e @ Err(Error::NotConfigured) => return e,
                e @ Err(_) => {
                    thread::sleep(delay);
                    count += 1;
                    if count > retry {
                        return e;
                    }
                    result = self.try_connect();
                }
                ok => return ok,
            }
        }
    }

    pub fn send(&mut self, request: &Request) {
        self.try_send(request).unwrap();
    }

    pub fn send_str(&mut self, request: &str) {
        self.try_send_str(request).unwrap();
    }

    pub fn try_send_batch(&mut self, requests: Vec<&Request>) -> Result<(), Error> {
        let batch = serde_json::to_string(&requests).map_err(|_| Error::Batch)?;
        self.try_send_str(&batch)
    }

    pub fn try_send(&mut self, request: &Request) -> Result<(), Error> {
        let s = serde_json::to_string(request).map_err(|_| Error::SerializeRequest)?;
        self.try_send_str(&s)
    }

    pub fn try_send_str(&mut self, request: &str) -> Result<(), Error> {
        match self {
            Client::None => Err(Error::NotConfigured),
            Client::Tcp(c) => {
                if let Some(stream) = c.stream.as_mut() {
                    let mut stream = stream.lock().map_err(|_| Error::Mutex)?;
                    TcpClient::send(&mut stream, request)
                } else {
                    Err(Error::NotConnected)
                }
            }
            Client::Ssl(c) => {
                if let Some(stream) = c.stream.as_mut() {
                    let mut stream = stream.lock().map_err(|_| Error::Mutex)?;
                    SslClient::send(&mut stream, request)
                } else {
                    Err(Error::NotConnected)
                }
            }
        }
    }

    pub fn recv(&mut self, index: &HashMap<usize, Request>) -> Result<Vec<Response>, Error> {
        let raw = self.recv_str()?;
        Ok(parse_str_response(&raw, index)?)
    }

    pub fn recv_str(&mut self) -> Result<String, Error> {
        match self {
            Client::None => Err(Error::NotConfigured),
            Client::Tcp(c) => {
                if let Some(stream) = c.stream.as_mut() {
                    let mut stream = stream.lock().map_err(|_| Error::Mutex)?;
                    TcpClient::read(&mut stream)
                } else {
                    Err(Error::NotConnected)
                }
            }
            Client::Ssl(c) => {
                if let Some(stream) = c.stream.as_mut() {
                    let mut stream = stream.lock().map_err(|_| Error::Mutex)?;
                    SslClient::read(&mut stream)
                } else {
                    Err(Error::NotConnected)
                }
            }
        }
    }

    pub fn try_recv(
        &mut self,
        index: &HashMap<usize, Request>,
    ) -> Result<Option<Vec<Response>>, Error> {
        let raw = self.try_recv_str()?;
        if let Some(rr) = raw {
            Ok(Some(parse_str_response(&rr, index)?))
        } else {
            Ok(None)
        }
    }

    pub fn try_recv_str(&mut self) -> Result<Option<String>, Error> {
        match self {
            Client::None => Err(Error::NotConfigured),
            Client::Tcp(c) => {
                if let Some(stream) = c.stream.as_mut() {
                    let mut stream = stream.lock().map_err(|_| Error::Mutex)?;
                    TcpClient::try_read(&mut stream)
                } else {
                    Err(Error::NotConnected)
                }
            }
            Client::Ssl(c) => {
                if let Some(stream) = c.stream.as_mut() {
                    let mut stream = stream.lock().map_err(|_| Error::Mutex)?;
                    SslClient::try_read(&mut stream)
                } else {
                    Err(Error::NotConnected)
                }
            }
        }
    }

    pub fn close(&mut self) -> Result<(), Error> {
        match self {
            Client::None => Ok(()),
            Client::Tcp(c) => c.close(),
            Client::Ssl(c) => c.close(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{read_line, read_line_capped, Error, MAX_LINE_LEN};

    #[test]
    fn read_line_single() {
        let mut reader: &[u8] = b"hello\n";
        assert_eq!(read_line(&mut reader).unwrap(), "hello\n");
    }

    #[test]
    fn read_line_coalesced() {
        // Two lines in one buffer: the first call must stop at the newline and
        // leave the second line for the next call (the reader is not consumed
        // past the newline). This is the desync the framing fix guards against.
        let mut reader: &[u8] = b"first\nsecond\n";
        assert_eq!(read_line(&mut reader).unwrap(), "first\n");
        assert_eq!(read_line(&mut reader).unwrap(), "second\n");
    }

    #[test]
    fn read_line_eof_without_newline() {
        let mut reader: &[u8] = b"no newline";
        assert_eq!(read_line(&mut reader).unwrap(), "no newline");
    }

    #[test]
    fn read_line_at_cap_with_newline_accepted() {
        // A line of exactly MAX_LINE_LEN bytes ending in '\n' is accepted: the
        // newline break happens before the cap check.
        let mut buf = vec![b'a'; MAX_LINE_LEN - 1];
        buf.push(b'\n');
        let mut reader: &[u8] = &buf;
        assert_eq!(read_line(&mut reader).unwrap().len(), MAX_LINE_LEN);
    }

    #[test]
    fn read_line_over_cap_rejected() {
        // MAX_LINE_LEN non-newline bytes trips the cap.
        let buf = vec![b'a'; MAX_LINE_LEN + 1];
        let mut reader: &[u8] = &buf;
        assert!(matches!(read_line(&mut reader), Err(Error::LineTooLong)));
    }

    #[test]
    fn read_line_capped_exact_cap_content_then_newline_accepted() {
        // Exactly `cap` content bytes followed by '\n' is the accepted boundary.
        let mut buf = vec![b'a'; 8];
        buf.push(b'\n');
        let mut reader: &[u8] = &buf;
        assert_eq!(read_line_capped(&mut reader, 8).unwrap().len(), 9);
    }

    #[test]
    fn read_line_capped_one_over_cap_rejected() {
        // The `cap + 1`-th non-newline byte is rejected.
        let buf = vec![b'a'; 9];
        let mut reader: &[u8] = &buf;
        assert!(matches!(
            read_line_capped(&mut reader, 8),
            Err(Error::LineTooLong)
        ));
    }
}
