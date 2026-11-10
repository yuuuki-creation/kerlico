//! What xtls/reality learns about a target before it serves anyone (`record_detect.go`).
//!
//! Two real TLS 1.3 handshakes with the target, one per question: which records the target sends
//! right after the client's Finished, and how many ChangeCipherSpec records it takes before it
//! alerts. Like Go's TLS client in xtls/reality, a probe stops when the target's certificate does
//! not verify for the server name, and the target then keeps no records.

use super::{
    checked_x25519, finished_verify, handshake_msg, handshake_secret, invalid_record,
    read_plain_handshake, seal_record, server_share, traffic_keys, traffic_secret,
    HandshakeRecords, RealityDecoyVerifier,
};
use std::io::{self, Read, Write};
use std::time::{Duration, Instant};

/// How long xtls/reality reads after the client's Finished.
pub const POST_HANDSHAKE_WINDOW: Duration = Duration::from_secs(5);
/// How long xtls/reality waits for an alert after a burst of ChangeCipherSpec records.
pub const ALERT_WINDOW: Duration = Duration::from_secs(1);
/// What the probe waits for records that were already on their way before it sends its Finished.
const ALREADY_SENT: Duration = Duration::from_millis(20);
/// More records than a target sends after a handshake are not recorded.
const MAX_RECORDS: usize = 64;

/// Which protocols the probe offers: the last part of xtls/reality's detection key.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum RealityAlpn {
    /// No ALPN extension.
    None,
    /// `http/1.1` only.
    Http1,
    /// `h2` and `http/1.1`.
    H2,
}

impl RealityAlpn {
    pub const ALL: [Self; 3] = [Self::None, Self::Http1, Self::H2];

    /// The class a ClientHello falls in: nothing offered, `h2` first, or anything else first.
    pub fn of_first_offer(first: &str) -> Self {
        match first {
            "" => Self::None,
            "h2" => Self::H2,
            _ => Self::Http1,
        }
    }

    fn protocols(self) -> &'static [&'static str] {
        match self {
            Self::None => &[],
            Self::Http1 => &["http/1.1"],
            Self::H2 => &["h2", "http/1.1"],
        }
    }
}

/// A connection to the target on which one read can be bounded.
pub trait RealityProbeStream: Read + Write {
    /// Like `read`, but fails with `WouldBlock` or `TimedOut` once `wait` has passed.
    fn read_within(&mut self, buf: &mut [u8], wait: Duration) -> io::Result<usize>;
}

/// The lengths of the records the target sends in the `window` after the client's Finished.
/// Only application-data records count, as in xtls/reality. With `roots` the target's certificate
/// must verify for `name`; without them nothing is checked.
pub fn probe_post_handshake_lengths<S: RealityProbeStream>(
    stream: &mut S,
    name: &str,
    alpn: RealityAlpn,
    window: Duration,
    roots: Option<&RealityDecoyVerifier>,
) -> io::Result<Vec<usize>> {
    let finished = finish_server_flight(stream, name, alpn, roots)?;
    stream.write_all(&finished.flight)?;
    stream.flush()?;
    let mut data = finished.ahead;
    let end = Instant::now() + window;
    let mut buffer = vec![0; 16 * 1024];
    loop {
        let left = end.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match stream.read_within(&mut buffer, left) {
            Ok(0) | Err(_) => break,
            Ok(count) => data.extend_from_slice(&buffer[..count]),
        }
    }
    let mut lengths = Vec::new();
    let mut rest = data.as_slice();
    while rest.len() >= 5 && rest[..3] == [23, 3, 3] && lengths.len() < MAX_RECORDS {
        let length = 5 + u16::from_be_bytes([rest[3], rest[4]]) as usize;
        if length > rest.len() {
            break;
        }
        lengths.push(length);
        rest = &rest[length..];
    }
    Ok(lengths)
}

/// How many ChangeCipherSpec records in a row the target takes while it waits for the client's
/// Finished: 1, 16 or 32 when it alerts after two, seventeen or thirty-three of them, otherwise
/// `usize::MAX`. `window` is how long an alert is awaited after each burst. With `roots` the
/// target's certificate must verify for `name`; without them nothing is checked.
pub fn probe_useless_record_limit<S: RealityProbeStream>(
    stream: &mut S,
    name: &str,
    alpn: RealityAlpn,
    window: Duration,
    roots: Option<&RealityDecoyVerifier>,
) -> io::Result<usize> {
    finish_server_flight(stream, name, alpn, roots)?;
    for (count, limit) in [(2, 1), (15, 16), (16, 32)] {
        if alerts_after(stream, count, window) {
            return Ok(limit);
        }
    }
    Ok(usize::MAX)
}

/// Sends `count` ChangeCipherSpec records and says whether the target answered with an alert or
/// closed within `window`. Write errors are ignored: a closed target shows up as a closed read.
fn alerts_after<S: RealityProbeStream>(stream: &mut S, count: usize, window: Duration) -> bool {
    let _ = stream.write_all(&[20, 3, 3, 0, 1, 1].repeat(count));
    let _ = stream.flush();
    let end = Instant::now() + window;
    let mut buffer = [0; 512];
    loop {
        let left = end.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return false;
        }
        match stream.read_within(&mut buffer, left) {
            Ok(0) => return true,
            Ok(_) if buffer[0] == 21 => return true,
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return false
            }
            Err(_) => return true,
        }
    }
}

struct ServerFlightRead {
    /// The client's ChangeCipherSpec and Finished.
    flight: Vec<u8>,
    /// Bytes behind the server's Finished that arrived before the client's Finished was sent and
    /// do not form a whole record. Whole records are dropped: a Go client has read them already.
    ahead: Vec<u8>,
}

/// Runs a TLS 1.3 handshake as far as reading the server's Finished and prepares the client's
/// answer without sending it.
fn finish_server_flight<S: RealityProbeStream>(
    stream: &mut S,
    name: &str,
    alpn: RealityAlpn,
    roots: Option<&RealityDecoyVerifier>,
) -> io::Result<ServerFlightRead> {
    let mut random = [0u8; 32];
    let mut session = [0u8; 32];
    getrandom::getrandom(&mut random).map_err(|error| io::Error::other(error.to_string()))?;
    getrandom::getrandom(&mut session).map_err(|error| io::Error::other(error.to_string()))?;
    let secret = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    let public = x25519_dalek::PublicKey::from(&secret).to_bytes();
    let hello = probe_hello(&random, &session, &public, name, alpn);
    let mut record = vec![22, 3, 1];
    record.extend_from_slice(&(hello.len() as u16).to_be_bytes());
    record.extend_from_slice(&hello);
    stream.write_all(&record)?;
    stream.flush()?;

    let (server_hello, _) = read_plain_handshake(stream, 2)?;
    let (suite, group, share) = server_share(&server_hello, &session).ok_or_else(invalid_record)?;
    let share: [u8; 32] = share.try_into().map_err(|_| invalid_record())?;
    if group != 0x001d {
        return Err(invalid_record());
    }
    let shared = checked_x25519(&secret, &x25519_dalek::PublicKey::from(share))
        .ok_or_else(invalid_record)?;
    let mut transcript = suite.transcript();
    transcript.update(&hello);
    transcript.update(&server_hello);
    let handshake = handshake_secret(suite, &shared);
    let hash = transcript.hash();
    let server_keys = traffic_keys(suite, &traffic_secret(suite, &handshake, "s hs traffic", &hash));
    let client_secret = traffic_secret(suite, &handshake, "c hs traffic", &hash);
    {
        let mut records = HandshakeRecords::new(&mut *stream, &server_keys);
        loop {
            // EncryptedExtensions, Certificate, CertificateRequest, CertificateVerify, Finished
            // and a compressed Certificate.
            let message = records.next_any(&[8, 11, 13, 15, 20, 25])?;
            if let (Some(roots), 11) = (roots, message[0]) {
                roots.verify(&message[4..], name)?;
            }
            transcript.update(&message);
            if message[0] == 20 {
                break;
            }
        }
    }
    let finished = handshake_msg(0x14, &finished_verify(suite, &client_secret, &transcript.hash()));
    let mut flight = vec![20, 3, 3, 0, 1, 1];
    flight.extend(seal_record(
        &traffic_keys(suite, &client_secret),
        0,
        22,
        &finished,
    ));

    let mut ahead = Vec::new();
    let mut buffer = vec![0; 16 * 1024];
    match stream.read_within(&mut buffer, ALREADY_SENT) {
        Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
        Ok(count) => ahead.extend_from_slice(&buffer[..count]),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) => {}
        Err(error) => return Err(error),
    }
    while ahead.len() >= 5 {
        let length = 5 + u16::from_be_bytes([ahead[3], ahead[4]]) as usize;
        if ahead.len() < length {
            break;
        }
        ahead.drain(..length);
    }
    Ok(ServerFlightRead { flight, ahead })
}

/// A TLS 1.3 ClientHello that offers only X25519 and the protocols of `alpn`.
fn probe_hello(
    random: &[u8; 32],
    session: &[u8; 32],
    public: &[u8; 32],
    name: &str,
    alpn: RealityAlpn,
) -> Vec<u8> {
    fn extension(out: &mut Vec<u8>, kind: u16, body: &[u8]) {
        out.extend_from_slice(&kind.to_be_bytes());
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
    }
    let mut extensions = Vec::new();
    if !name.is_empty() {
        let host = name.as_bytes();
        let mut body = Vec::new();
        body.extend_from_slice(&((1 + 2 + host.len()) as u16).to_be_bytes());
        body.push(0);
        body.extend_from_slice(&(host.len() as u16).to_be_bytes());
        body.extend_from_slice(host);
        extension(&mut extensions, 0x0000, &body);
    }
    extension(&mut extensions, 0x000a, &[0, 2, 0x00, 0x1d]);
    extension(
        &mut extensions,
        0x000d,
        &[
            0, 18, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03, 0x08, 0x05, 0x05, 0x01, 0x08,
            0x06, 0x06, 0x01, 0x08, 0x07,
        ],
    );
    if !alpn.protocols().is_empty() {
        let mut list = Vec::new();
        for protocol in alpn.protocols() {
            list.push(protocol.len() as u8);
            list.extend_from_slice(protocol.as_bytes());
        }
        let mut body = (list.len() as u16).to_be_bytes().to_vec();
        body.extend(list);
        extension(&mut extensions, 0x0010, &body);
    }
    extension(&mut extensions, 0x002b, &[2, 3, 4]);
    let mut share = vec![0, 36, 0x00, 0x1d, 0, 32];
    share.extend_from_slice(public);
    extension(&mut extensions, 0x0033, &share);
    extension(&mut extensions, 0x002d, &[1, 1]);

    let mut hello = vec![1, 0, 0, 0, 3, 3];
    hello.extend_from_slice(random);
    hello.push(32);
    hello.extend_from_slice(session);
    hello.extend_from_slice(&[0, 6, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 1, 0]);
    hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    hello.extend(extensions);
    let length = (hello.len() - 4) as u32;
    hello[1..4].copy_from_slice(&length.to_be_bytes()[1..]);
    hello
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};

    struct Tcp(TcpStream);

    impl Read for Tcp {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.set_read_timeout(Some(Duration::from_secs(10)))?;
            self.0.read(buf)
        }
    }

    impl Write for Tcp {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.0.flush()
        }
    }

    impl RealityProbeStream for Tcp {
        fn read_within(&mut self, buf: &mut [u8], wait: Duration) -> io::Result<usize> {
            self.0.set_read_timeout(Some(wait.max(Duration::from_millis(1))))?;
            self.0.read(buf)
        }
    }

    /// A TLS 1.3 server that sends `tickets` NewSessionTickets once it has the client's Finished.
    fn target(tickets: usize, alpn: &[&str]) -> std::net::SocketAddr {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let protocols: Vec<String> = alpn.iter().map(|name| name.to_string()).collect();
        let config = crate::server_config(&cert.pem(), &key.serialize_pem(), &protocols).unwrap();
        let mut config = (*config).clone();
        config.send_tls13_tickets = tickets;
        let config = std::sync::Arc::new(config);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            while let Ok((mut socket, _)) = listener.accept() {
                let config = config.clone();
                std::thread::spawn(move || {
                    socket.set_read_timeout(Some(Duration::from_secs(10))).ok();
                    let mut tls = rustls::ServerConnection::new(config).unwrap();
                    while tls.complete_io(&mut socket).is_ok_and(|(read, written)| read + written > 0) {}
                });
            }
        });
        address
    }

    #[test]
    fn records_behind_the_client_finished_are_measured() {
        let address = target(2, &["h2", "http/1.1"]);
        let mut stream = Tcp(TcpStream::connect(address).unwrap());
        let lengths = probe_post_handshake_lengths(
            &mut stream,
            "localhost",
            RealityAlpn::H2,
            Duration::from_millis(500),
            None,
        )
        .unwrap();
        // rustls puts both tickets in one flight record.
        assert_eq!(lengths.len(), 1, "{lengths:?}");
        assert!(lengths.iter().all(|length| *length > 100 && *length < 1024));
    }

    #[test]
    fn a_target_that_sends_nothing_after_the_finished_yields_no_records() {
        let address = target(0, &[]);
        let mut stream = Tcp(TcpStream::connect(address).unwrap());
        let lengths = probe_post_handshake_lengths(
            &mut stream,
            "localhost",
            RealityAlpn::None,
            Duration::from_millis(300),
            None,
        )
        .unwrap();
        assert!(lengths.is_empty(), "{lengths:?}");
    }

    #[test]
    fn a_target_that_alerts_on_change_cipher_spec_floods_gives_a_finite_limit() {
        // rustls drops a couple of compatibility ChangeCipherSpec records and then alerts, so
        // the probe sees an alert within the first or the second burst.
        let address = target(1, &[]);
        let mut stream = Tcp(TcpStream::connect(address).unwrap());
        let limit = probe_useless_record_limit(
            &mut stream,
            "localhost",
            RealityAlpn::None,
            Duration::from_millis(300),
            None,
        )
        .unwrap();
        assert!(limit == 1 || limit == 16, "{limit}");
    }

    #[test]
    fn a_target_certificate_the_roots_do_not_vouch_for_ends_the_probe() {
        let address = target(2, &["h2"]);
        let stranger = rcgen::CertificateParams::new(vec!["stranger.example".into()])
            .unwrap()
            .self_signed(&rcgen::KeyPair::generate().unwrap())
            .unwrap();
        let roots = RealityDecoyVerifier::from_pem_roots(&stranger.pem()).unwrap();
        let mut stream = Tcp(TcpStream::connect(address).unwrap());
        let probe = probe_post_handshake_lengths(
            &mut stream,
            "localhost",
            RealityAlpn::H2,
            Duration::from_millis(300),
            Some(&roots),
        );
        assert!(probe.is_err(), "{probe:?}");
        let mut stream = Tcp(TcpStream::connect(address).unwrap());
        let probe = probe_useless_record_limit(
            &mut stream,
            "localhost",
            RealityAlpn::H2,
            Duration::from_millis(300),
            Some(&roots),
        );
        assert!(probe.is_err(), "{probe:?}");
    }

    #[test]
    fn the_alpn_class_follows_the_first_offered_protocol() {
        assert_eq!(RealityAlpn::of_first_offer(""), RealityAlpn::None);
        assert_eq!(RealityAlpn::of_first_offer("h2"), RealityAlpn::H2);
        assert_eq!(RealityAlpn::of_first_offer("http/1.1"), RealityAlpn::Http1);
        assert_eq!(RealityAlpn::of_first_offer("h3"), RealityAlpn::Http1);
    }
}
