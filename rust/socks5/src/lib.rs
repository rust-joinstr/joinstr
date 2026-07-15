//! Minimal synchronous SOCKS5 client, just enough for joinstr to reach a nostr
//! relay or an electrum server through a local Tor SOCKS proxy.
//!
//! Two properties matter for privacy and are the reason this is not pulled from
//! a general SOCKS crate:
//!
//! * Remote DNS. The destination is sent to the proxy as a domain name
//!   (`ATYP=DOMAINNAME`), never resolved locally, so the client's resolver
//!   never sees the relay or electrum hostname. Resolving locally would leak
//!   the very lookups Tor exists to hide.
//! * Stream isolation. Each connection authenticates with a fresh random
//!   username/password. Tor's default `IsolateSOCKSAuth` builds a separate
//!   circuit per distinct credential pair, so every connection made through
//!   here rides its own circuit without touching the control port.

use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// A random per-connection isolation token. Used as the SOCKS username and
/// password so Tor assigns the connection its own circuit.
pub fn isolation_token() -> String {
    use rand::Rng;
    let mut rng = rand::rng();
    // 16 hex chars of entropy is plenty to make each connection's credential
    // pair unique; the value itself is meaningless to Tor beyond isolation.
    (0..16)
        .map(|_| char::from_digit(rng.random_range(0..16), 16).unwrap())
        .collect()
}

fn read_exact(stream: &mut TcpStream, buf: &mut [u8]) -> io::Result<()> {
    stream.read_exact(buf)
}

/// Open a TCP connection to `dest_host:dest_port` through the SOCKS5 proxy at
/// `proxy` (e.g. `127.0.0.1:9050`), isolating the circuit with `token`.
///
/// The destination host is passed to the proxy verbatim; it is never resolved
/// on this side.
pub fn connect(
    proxy: &str,
    dest_host: &str,
    dest_port: u16,
    token: &str,
    timeout: Duration,
) -> io::Result<TcpStream> {
    let proxy_addr = proxy
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "proxy address did not resolve"))?;

    let mut stream = TcpStream::connect_timeout(&proxy_addr, timeout)?;
    // The whole handshake is a few small round trips to a local Tor; bound
    // each so a wedged proxy cannot hang the connect indefinitely.
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    // Greeting: offer username/password auth (0x02). A Tor SocksPort with
    // stream isolation accepts it; the credentials carry the isolation token.
    stream.write_all(&[0x05, 0x01, 0x02])?;

    let mut method = [0u8; 2];
    read_exact(&mut stream, &mut method)?;
    if method[0] != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not a SOCKS5 proxy",
        ));
    }
    match method[1] {
        0x02 => authenticate(&mut stream, token)?,
        0x00 => {} // proxy accepted no-auth; isolation is then best-effort
        0xff => {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "proxy rejected the offered auth methods",
            ))
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("proxy selected unsupported auth method {other:#04x}"),
            ))
        }
    }

    // CONNECT request with a domain-name destination (remote DNS).
    let host = dest_host.as_bytes();
    if host.len() > 255 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "destination host too long for SOCKS5",
        ));
    }
    let mut req = Vec::with_capacity(7 + host.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00, 0x03]);
    req.push(host.len() as u8);
    req.extend_from_slice(host);
    req.extend_from_slice(&dest_port.to_be_bytes());
    stream.write_all(&req)?;

    // Reply: version, reply code, reserved, then a bound address we discard.
    let mut head = [0u8; 4];
    read_exact(&mut stream, &mut head)?;
    if head[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("SOCKS5 connect failed: reply code {:#04x}", head[1]),
        ));
    }
    let bound_len = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut l = [0u8; 1];
            read_exact(&mut stream, &mut l)?;
            l[0] as usize
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected bound address type {other:#04x}"),
            ))
        }
    };
    let mut discard = vec![0u8; bound_len + 2]; // address + port
    read_exact(&mut stream, &mut discard)?;

    Ok(stream)
}

fn authenticate(stream: &mut TcpStream, token: &str) -> io::Result<()> {
    let cred = token.as_bytes();
    if cred.len() > 255 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "isolation token too long",
        ));
    }
    // RFC 1929: version 1, username, password. Same token for both is fine;
    // Tor only uses the pair as an isolation key.
    let mut msg = Vec::with_capacity(3 + cred.len() * 2);
    msg.push(0x01);
    msg.push(cred.len() as u8);
    msg.extend_from_slice(cred);
    msg.push(cred.len() as u8);
    msg.extend_from_slice(cred);
    stream.write_all(&msg)?;

    let mut resp = [0u8; 2];
    read_exact(stream, &mut resp)?;
    if resp[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SOCKS5 username/password auth was rejected",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn isolation_tokens_are_unique_and_hex() {
        let a = isolation_token();
        let b = isolation_token();
        assert_ne!(a, b);
        assert_eq!(a.len(), 16);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// Drives a real handshake against an in-process fake proxy and asserts the
    /// exact bytes: username/password auth is offered and answered, and the
    /// destination is sent as a domain name (remote DNS), never pre-resolved.
    #[test]
    fn handshake_offers_auth_and_sends_domain() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy = listener.local_addr().unwrap().to_string();

        let server = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();

            // Greeting: version 5, one method, username/password (0x02).
            let mut greet = [0u8; 3];
            s.read_exact(&mut greet).unwrap();
            assert_eq!(greet, [0x05, 0x01, 0x02]);
            s.write_all(&[0x05, 0x02]).unwrap(); // select username/password

            // Auth: version 1, then user and pass, both the isolation token.
            let mut ver = [0u8; 1];
            s.read_exact(&mut ver).unwrap();
            assert_eq!(ver[0], 0x01);
            for _ in 0..2 {
                let mut len = [0u8; 1];
                s.read_exact(&mut len).unwrap();
                let mut cred = vec![0u8; len[0] as usize];
                s.read_exact(&mut cred).unwrap();
                assert_eq!(cred, b"tok0");
            }
            s.write_all(&[0x01, 0x00]).unwrap(); // auth success

            // CONNECT: version, cmd, reserved, ATYP=domain, len, host, port.
            let mut req = [0u8; 4];
            s.read_exact(&mut req).unwrap();
            assert_eq!(req, [0x05, 0x01, 0x00, 0x03]);
            let mut len = [0u8; 1];
            s.read_exact(&mut len).unwrap();
            let mut host = vec![0u8; len[0] as usize];
            s.read_exact(&mut host).unwrap();
            assert_eq!(host, b"relay.example");
            let mut port = [0u8; 2];
            s.read_exact(&mut port).unwrap();
            assert_eq!(u16::from_be_bytes(port), 443);

            // Success reply with an IPv4 bound address (discarded by the client).
            s.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .unwrap();
        });

        let stream = connect(
            &proxy,
            "relay.example",
            443,
            "tok0",
            Duration::from_secs(5),
        );
        assert!(stream.is_ok(), "connect failed: {:?}", stream.err());
        server.join().unwrap();
    }

    #[test]
    fn connect_reports_a_proxy_reply_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy = listener.local_addr().unwrap().to_string();

        let server = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut greet = [0u8; 3];
            s.read_exact(&mut greet).unwrap();
            s.write_all(&[0x05, 0x02]).unwrap();
            let mut ver = [0u8; 1];
            s.read_exact(&mut ver).unwrap();
            for _ in 0..2 {
                let mut len = [0u8; 1];
                s.read_exact(&mut len).unwrap();
                let mut cred = vec![0u8; len[0] as usize];
                s.read_exact(&mut cred).unwrap();
            }
            s.write_all(&[0x01, 0x00]).unwrap();
            let mut req = [0u8; 4];
            s.read_exact(&mut req).unwrap();
            let mut len = [0u8; 1];
            s.read_exact(&mut len).unwrap();
            let mut host = vec![0u8; len[0] as usize];
            s.read_exact(&mut host).unwrap();
            let mut port = [0u8; 2];
            s.read_exact(&mut port).unwrap();
            // 0x05 = connection refused by destination host.
            s.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .unwrap();
        });

        let err = connect(&proxy, "relay.example", 443, "tok0", Duration::from_secs(5))
            .unwrap_err();
        assert!(err.to_string().contains("connect failed"), "{err}");
        server.join().unwrap();
    }
}
