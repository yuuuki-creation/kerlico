//! TLS in front of a VLESS header. The record layer is rustls.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig as RustlsClient, DigitallySignedStruct, Error as TlsError, RootCertStore, ServerConfig as RustlsServer,
    SignatureScheme,
};
use sha2::{Digest, Sha256};

pub use rustls::{ClientConfig, ServerConfig};

pub fn server_config(cert_pem: &str, key_pem: &str, alpn: &[String]) -> Result<Arc<ServerConfig>, ()> {
    server_config_versions(cert_pem, key_pem, alpn, "", "")
}

pub fn server_config_versions(cert_pem: &str, key_pem: &str, alpn: &[String], min: &str, max: &str) -> Result<Arc<ServerConfig>, ()> {
    install();
    let certs = rustls_pemfile::certs(&mut cert_pem.as_bytes())
        .collect::<Result<Vec<CertificateDer>, _>>()
        .map_err(|_| ())?;
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .map_err(|_| ())?
        .ok_or(())?;
    let mut config = RustlsServer::builder_with_protocol_versions(&versions(min, max)?)
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|_| ())?;
    config.alpn_protocols = alpn.iter().map(|name| name.as_bytes().to_vec()).collect();
    Ok(Arc::new(config))
}

pub fn client_config(alpn: &[String], insecure: bool) -> Result<Arc<ClientConfig>, ()> {
    client_config_pinned(alpn, insecure, "")
}

pub fn client_config_pinned(alpn: &[String], insecure: bool, pins: &str) -> Result<Arc<ClientConfig>, ()> {
    client_config_versions(alpn, insecure, pins, "", "")
}

pub fn client_config_versions(alpn: &[String], insecure: bool, pins: &str, min: &str, max: &str) -> Result<Arc<ClientConfig>, ()> {
    install();
    let pins = parse_pins(pins)?;
    let builder = RustlsClient::builder_with_protocol_versions(&versions(min, max)?);
    let mut config = if insecure || !pins.is_empty() {
        let provider = CryptoProvider::get_default().cloned().ok_or(())?;
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(CertificatePolicy { pins, provider }))
            .with_no_client_auth()
    } else {
        let roots = RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    config.alpn_protocols = alpn.iter().map(|name| name.as_bytes().to_vec()).collect();
    Ok(Arc::new(config))
}

fn versions(min: &str, max: &str) -> Result<Vec<&'static rustls::SupportedProtocolVersion>, ()> {
    let min = match min { "" | "1.2" => 12, "1.3" => 13, _ => return Err(()) };
    let max = match max { "" | "1.3" => 13, "1.2" => 12, _ => return Err(()) };
    if min > max { return Err(()); }
    Ok([(13, &rustls::version::TLS13), (12, &rustls::version::TLS12)]
        .into_iter().filter_map(|(version, config)| (min <= version && version <= max).then_some(config)).collect())
}

pub(crate) fn parse_pins(text: &str) -> Result<Vec<[u8; 32]>, ()> {
    text.split(',').map(str::trim).filter(|pin| !pin.is_empty()).map(|pin| {
        let hex: Vec<_> = pin.bytes().filter(|&byte| byte != b':').collect();
        if hex.len() != 64 {
            return Err(());
        }
        let mut digest = [0; 32];
        for (dest, pair) in digest.iter_mut().zip(hex.chunks_exact(2)) {
            let high = (pair[0] as char).to_digit(16).ok_or(())?;
            let low = (pair[1] as char).to_digit(16).ok_or(())?;
            *dest = ((high << 4) | low) as u8;
        }
        Ok(digest)
    }).collect()
}

pub fn accept_tls(tcp: TcpStream, config: Arc<ServerConfig>) -> std::io::Result<TlsLink> {
    let timeout = Arc::new(Mutex::new(Some(Duration::from_secs(10))));
    let tcp = TimedTcp {
        tcp,
        timeout: Arc::clone(&timeout),
    };
    let conn = rustls::ServerConnection::new(config).map_err(std::io::Error::other)?;
    let io = rustls::StreamOwned::new(conn, tcp);
    Ok(TlsLink {
        io: Arc::new(Mutex::new(TlsIo::Server(io))),
        timeout,
    })
}

pub fn connect_tls(tcp: TcpStream, config: Arc<ClientConfig>, name: &str) -> std::io::Result<TlsLink> {
    let timeout = Arc::new(Mutex::new(Some(Duration::from_secs(10))));
    let tcp = TimedTcp {
        tcp,
        timeout: Arc::clone(&timeout),
    };
    let server = ServerName::try_from(name.to_string()).map_err(|_| std::io::Error::other("server name"))?;
    let conn = rustls::ClientConnection::new(config, server).map_err(std::io::Error::other)?;
    let io = rustls::StreamOwned::new(conn, tcp);
    Ok(TlsLink {
        io: Arc::new(Mutex::new(TlsIo::Client(io))),
        timeout,
    })
}

enum TlsIo {
    Server(rustls::StreamOwned<rustls::ServerConnection, TimedTcp>),
    Client(rustls::StreamOwned<rustls::ClientConnection, TimedTcp>),
}

#[derive(Clone)]
pub struct TlsLink {
    io: Arc<Mutex<TlsIo>>,
    timeout: Arc<Mutex<Option<Duration>>>,
}

impl TlsLink {
    pub fn set_timeout(&self, timeout: Option<Duration>) {
        *self.timeout.lock().expect("timeout") = timeout;
    }

    pub fn identity(&self) -> (String, String) {
        let io = self.io.lock().expect("tls");
        let TlsIo::Server(io) = &*io else {
            return (String::new(), String::new());
        };
        let name = io.conn.server_name().unwrap_or("").to_string();
        let alpn = io
            .conn
            .alpn_protocol()
            .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
            .unwrap_or_default();
        (name, alpn)
    }
}

impl Read for TlsLink {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match &mut *self.io.lock().expect("tls") {
            TlsIo::Server(io) => io.read(buf),
            TlsIo::Client(io) => io.read(buf),
        }
    }
}

impl Write for TlsLink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match &mut *self.io.lock().expect("tls") {
            TlsIo::Server(io) => io.write(buf),
            TlsIo::Client(io) => io.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match &mut *self.io.lock().expect("tls") {
            TlsIo::Server(io) => io.flush(),
            TlsIo::Client(io) => io.flush(),
        }
    }
}

struct TlsCore {
    conn: Mutex<rustls::Connection>,
}

/// The read half of a server TLS connection. A blocking socket read does not hold the connection.
pub struct TlsRead<S = TcpStream> {
    core: Arc<TlsCore>,
    sock: S,
    record: Vec<u8>,
    direct: bool,
}

/// The write half of a server TLS connection. It uses a cloned socket, so it can run beside [`TlsRead`].
pub struct TlsWrite<S = TcpStream> {
    core: Arc<TlsCore>,
    sock: S,
    wire: Vec<u8>,
    sent: usize,
    retry: Option<Vec<u8>>,
    direct: bool,
}

pub fn accept_tls_split(tcp: TcpStream, config: Arc<ServerConfig>) -> std::io::Result<(TlsRead, TlsWrite)> {
    let write = tcp.try_clone()?;
    accept_tls_over(tcp, write, config)
}

pub fn accept_tls_over<R: Read, W: Write>(read: R, write: W, config: Arc<ServerConfig>) -> std::io::Result<(TlsRead<R>, TlsWrite<W>)> {
    install();
    let mut io = HandshakeIo::new(read, write);
    let mut conn = rustls::ServerConnection::new(config).map_err(std::io::Error::other)?;
    while conn.is_handshaking() {
        conn.complete_io(&mut io)?;
    }
    Ok(split(io.read, io.write, conn.into()))
}

pub fn connect_tls_split(tcp: TcpStream, config: Arc<ClientConfig>, name: &str) -> std::io::Result<(TlsRead, TlsWrite)> {
    let write = tcp.try_clone()?;
    connect_tls_over(tcp, write, config, name)
}

pub fn connect_tls_over<R: Read, W: Write>(read: R, write: W, config: Arc<ClientConfig>, name: &str) -> std::io::Result<(TlsRead<R>, TlsWrite<W>)> {
    let name = ServerName::try_from(name.to_string()).map_err(std::io::Error::other)?;
    let mut io = HandshakeIo::new(read, write);
    let mut conn = rustls::ClientConnection::new(config, name).map_err(std::io::Error::other)?;
    while conn.is_handshaking() {
        conn.complete_io(&mut io)?;
    }
    Ok(split(io.read, io.write, conn.into()))
}

struct HandshakeIo<R, W> {
    read: R,
    write: W,
    header: [u8; 5],
    header_len: usize,
    payload_left: usize,
}

impl<R, W> HandshakeIo<R, W> {
    fn new(read: R, write: W) -> Self {
        Self {
            read,
            write,
            header: [0; 5],
            header_len: 0,
            payload_left: 0,
        }
    }
}

impl<R: Read, W> Read for HandshakeIo<R, W> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        // Stop at a record boundary so rustls cannot buffer part of the next
        // record before TlsRead takes over the underlying stream.
        if self.payload_left != 0 {
            let limit = self.payload_left.min(buf.len());
            let n = self.read.read(&mut buf[..limit])?;
            self.payload_left -= n;
            return Ok(n);
        }
        let limit = (self.header.len() - self.header_len).min(buf.len());
        let n = self.read.read(&mut buf[..limit])?;
        let end = self.header_len + n;
        self.header[self.header_len..end].copy_from_slice(&buf[..n]);
        self.header_len = end;
        if self.header_len == self.header.len() {
            self.payload_left = u16::from_be_bytes([self.header[3], self.header[4]]) as usize;
            self.header_len = 0;
        }
        Ok(n)
    }
}

impl<R, W: Write> Write for HandshakeIo<R, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> { self.write.write(buf) }
    fn flush(&mut self) -> std::io::Result<()> { self.write.flush() }
}

fn split<R, W>(read: R, write: W, conn: rustls::Connection) -> (TlsRead<R>, TlsWrite<W>) {
    let core = Arc::new(TlsCore { conn: Mutex::new(conn) });
    (
        TlsRead {
            core: Arc::clone(&core),
            sock: read,
            record: Vec::new(),
            direct: false,
        },
        TlsWrite { core, sock: write, wire: Vec::new(), sent: 0, retry: None, direct: false },
    )
}

impl<S> TlsRead<S> {
    pub fn inner_mut(&mut self) -> &mut S { &mut self.sock }

    pub fn map_inner<T>(self, map: impl FnOnce(S) -> T) -> TlsRead<T> {
        TlsRead { core: self.core, sock: map(self.sock), record: self.record, direct: self.direct }
    }

    pub fn start_direct(&mut self) -> std::io::Result<()> {
        if !self.record.is_empty() { return Err(std::io::Error::other("partial TLS record")); }
        self.direct = true;
        Ok(())
    }

    pub fn alpn(&self) -> Option<Vec<u8>> {
        self.core.conn.lock().expect("tls").alpn_protocol().map(<[u8]>::to_vec)
    }

    pub fn is_tls13(&self) -> bool {
        self.core.conn.lock().expect("tls").protocol_version() == Some(rustls::ProtocolVersion::TLSv1_3)
    }

    pub fn identity(&self) -> (String, String) {
        let conn = self.core.conn.lock().expect("tls");
        let name = match &*conn {
            rustls::Connection::Server(server) => server.server_name().unwrap_or(""),
            _ => "",
        };
        (name.to_string(), String::from_utf8_lossy(conn.alpn_protocol().unwrap_or_default()).into_owned())
    }

}

impl TlsRead<TcpStream> {
    pub fn set_timeout(&self, timeout: Option<Duration>) {
        self.sock.set_read_timeout(timeout).ok();
    }
}

impl<S: Read> Read for TlsRead<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() { return Ok(0); }
        loop {
            {
                let mut conn = self.core.conn.lock().expect("tls");
                match conn.reader().read(buf) {
                    Ok(n) if n > 0 => return Ok(n),
                    Ok(_) => return Ok(0),
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(err) => return Err(err),
                }
            }
            if self.direct { return self.sock.read(buf); }
            loop {
                let needed = if self.record.len() < 5 { 5 } else {
                    5 + u16::from_be_bytes([self.record[3], self.record[4]]) as usize
                };
                if needed > 18437 { return Err(std::io::Error::other("TLS record too large")); }
                if self.record.len() == needed && needed > 5 { break; }
                let mut cipher = [0u8; 16384];
                let capacity = (needed - self.record.len()).min(cipher.len());
                if capacity == 0 { break; }
                let n = match self.sock.read(&mut cipher[..capacity]) {
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                    result => result?,
                };
                if n == 0 {
                    let message = if self.record.is_empty() { "TLS peer closed without close_notify" } else { "truncated TLS record" };
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, message));
                }
                self.record.extend_from_slice(&cipher[..n]);
            }
            let mut conn = self.core.conn.lock().expect("tls");
            let mut cursor = self.record.as_slice();
            while !cursor.is_empty() {
                let before = cursor.len();
                let took = conn.read_tls(&mut cursor)?;
                if took == 0 || cursor.len() == before {
                    break;
                }
            }
            conn.process_new_packets()
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
            self.record.clear();
        }
    }
}

impl<S: Write> TlsWrite<S> {
    pub fn inner_mut(&mut self) -> &mut S { &mut self.sock }

    pub fn map_inner<T: Write>(self, map: impl FnOnce(S) -> T) -> TlsWrite<T> {
        TlsWrite {
            core: self.core, sock: map(self.sock), wire: self.wire, sent: self.sent,
            retry: self.retry, direct: self.direct,
        }
    }

    pub fn start_direct(&mut self) -> std::io::Result<()> {
        if self.retry.is_some() {
            return Err(io::Error::other("TLS write must finish before switching to direct"));
        }
        self.flush()?;
        self.direct = true;
        Ok(())
    }

    fn flush_wire(&mut self) -> io::Result<()> {
        while self.sent < self.wire.len() {
            match self.sock.write(&self.wire[self.sent..]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => self.sent += n,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(err),
            }
        }
        self.wire.clear();
        self.sent = 0;
        Ok(())
    }
}

impl<S: Write> Write for TlsWrite<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() { return Ok(0); }
        if self.direct { return self.sock.write(buf); }
        if let Some(retry) = &self.retry {
            if !buf.starts_with(retry) {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "different buffer on TLS write retry"));
            }
            let n = retry.len();
            self.flush_wire()?;
            self.retry = None;
            return Ok(n);
        }
        let n = {
            let mut conn = self.core.conn.lock().expect("tls");
            let n = conn.writer().write(&buf[..buf.len().min(16384)])?;
            collect_wire(&mut conn, &mut self.wire)?;
            n
        };
        if let Err(err) = self.flush_wire() {
            self.retry = Some(buf[..n].to_vec());
            return Err(err);
        }
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if self.direct { return self.sock.flush(); }
        {
            let mut conn = self.core.conn.lock().expect("tls");
            collect_wire(&mut conn, &mut self.wire)?;
        }
        self.flush_wire()?;
        self.sock.flush()
    }
}

fn collect_wire(conn: &mut rustls::Connection, wire: &mut Vec<u8>) -> io::Result<()> {
    while conn.wants_write() {
        if conn.write_tls(wire)? == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
    }
    Ok(())
}

struct TimedTcp {
    tcp: TcpStream,
    timeout: Arc<Mutex<Option<Duration>>>,
}

impl Read for TimedTcp {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let timeout = *self.timeout.lock().expect("timeout");
        self.tcp.set_read_timeout(timeout).ok();
        self.tcp.read(buf)
    }
}

impl Write for TimedTcp {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let timeout = *self.timeout.lock().expect("timeout");
        self.tcp.set_write_timeout(timeout).ok();
        self.tcp.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.tcp.flush()
    }
}

fn install() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[derive(Debug)]
struct CertificatePolicy {
    pins: Vec<[u8; 32]>,
    provider: Arc<CryptoProvider>,
}

impl CertificatePolicy {
    fn matches_pin(&self, cert: &CertificateDer<'_>) -> bool {
        let hash: [u8; 32] = Sha256::digest(cert.as_ref()).into();
        self.pins.contains(&hash)
    }
}

impl ServerCertVerifier for CertificatePolicy {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        if self.pins.is_empty() || self.matches_pin(end_entity) {
            return Ok(ServerCertVerified::assertion());
        }
        let ca = intermediates.iter().find(|cert| self.matches_pin(cert) && certificate_is_ca(cert.as_ref()))
            .ok_or_else(|| TlsError::General("TLS certificate does not match a configured pin".into()))?;
        let mut roots = RootCertStore::empty();
        roots.add(ca.clone())?;
        let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), self.provider.clone())
            .build().map_err(|err| TlsError::General(err.to_string()))?;
        verifier.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

pub(crate) fn certificate_is_ca(der: &[u8]) -> bool {
    fn basic_constraints(mut der: &[u8]) -> Option<bool> {
        let mut certificate = der_field(&mut der, 0x30)?;
        let mut tbs = der_field(&mut certificate, 0x30)?;
        if tbs.first() == Some(&0xa0) {
            der_field(&mut tbs, 0xa0)?;
        }
        for tag in [0x02, 0x30, 0x30, 0x30, 0x30, 0x30] {
            der_field(&mut tbs, tag)?;
        }
        if tbs.first() == Some(&0x81) {
            der_field(&mut tbs, 0x81)?;
        }
        if tbs.first() == Some(&0x82) {
            der_field(&mut tbs, 0x82)?;
        }
        let mut extensions = der_field(&mut tbs, 0xa3)?;
        let mut extensions = der_field(&mut extensions, 0x30)?;
        while !extensions.is_empty() {
            let mut extension = der_field(&mut extensions, 0x30)?;
            if der_field(&mut extension, 0x06)? != [0x55, 0x1d, 0x13] {
                continue;
            }
            if extension.first() == Some(&0x01) {
                der_field(&mut extension, 0x01)?;
            }
            let mut value = der_field(&mut extension, 0x04)?;
            let mut constraints = der_field(&mut value, 0x30)?;
            return Some(der_field(&mut constraints, 0x01)? == [0xff]);
        }
        Some(false)
    }
    basic_constraints(der).unwrap_or(false)
}

fn der_field<'a>(der: &mut &'a [u8], tag: u8) -> Option<&'a [u8]> {
    if der.first() != Some(&tag) {
        return None;
    }
    let len = *der.get(1)? as usize;
    let (len, start) = if len < 128 {
        (len, 2)
    } else {
        let width = len & 127;
        if width == 0 || width > std::mem::size_of::<usize>() || *der.get(2)? == 0 {
            return None;
        }
        let len = der.get(2..2 + width)?.iter().fold(0usize, |len, byte| (len << 8) | *byte as usize);
        if len < 128 {
            return None;
        }
        (len, 2 + width)
    };
    let (value, remaining) = der.get(start..)?.split_at_checked(len)?;
    *der = remaining;
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    fn test_configs() -> (Arc<ServerConfig>, Arc<ClientConfig>) {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let alpn = ["h2".to_string()];
        let server = server_config(&certified.cert.pem(), &certified.key_pair.serialize_pem(), &alpn).unwrap();
        (server, client_config(&alpn, true).unwrap())
    }

    #[test]
    fn split_tls_preserves_application_record_coalesced_with_finished() {
        struct FlightRead {
            input: mpsc::Receiver<Vec<u8>>,
            bytes: io::Cursor<Vec<u8>>,
        }
        impl Read for FlightRead {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if self.bytes.position() as usize == self.bytes.get_ref().len() {
                    let packet = match self.input.recv_timeout(Duration::from_secs(3)) {
                        Ok(packet) => packet,
                        Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(0),
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            return Err(io::ErrorKind::TimedOut.into());
                        }
                    };
                    self.bytes = io::Cursor::new(packet);
                }
                self.bytes.read(buf)
            }
        }
        struct FlightWrite(mpsc::Sender<Vec<u8>>);
        impl Write for FlightWrite {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.0.send(buf.to_vec()).map_err(io::Error::other)?;
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let (server_config, client_config) = test_configs();
        let (up, receive_up) = mpsc::channel();
        let (down, receive_down) = mpsc::channel();
        let (handshake, ready) = mpsc::channel();
        let payload = [b'V'; 512];
        let server = thread::spawn(move || -> io::Result<[u8; 512]> {
            let reader = FlightRead {
                input: receive_up,
                bytes: io::Cursor::default(),
            };
            let (mut read, _) = accept_tls_over(reader, FlightWrite(down), server_config)?;
            handshake.send(()).unwrap();
            let mut received = [0; 512];
            read.read_exact(&mut received)?;
            Ok(received)
        });
        let mut read = FlightRead {
            input: receive_down,
            bytes: io::Cursor::default(),
        };
        let mut write = FlightWrite(up);
        let name = ServerName::try_from("localhost").unwrap();
        let mut client = rustls::ClientConnection::new(client_config, name).unwrap();
        while client.is_handshaking() {
            while client.wants_write() {
                client.write_tls(&mut write).unwrap();
            }
            assert_ne!(client.read_tls(&mut read).unwrap(), 0);
            client.process_new_packets().unwrap();
        }
        client.writer().write_all(&payload).unwrap();
        let mut wire = Vec::new();
        while client.wants_write() {
            client.write_tls(&mut wire).unwrap();
        }
        let suffix = wire.split_off(wire.len() - 32);
        write.0.send(wire).unwrap();
        ready.recv_timeout(Duration::from_secs(3)).unwrap();
        write.0.send(suffix).unwrap();
        drop(write);
        assert_eq!(server.join().unwrap().unwrap(), payload);
    }

    #[test]
    fn backpressured_write_does_not_hold_tls_core() {
        struct Gated {
            sock: TcpStream,
            gate: Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>,
        }
        impl Write for Gated {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if let Some((entered, release)) = self.gate.take() {
                    entered.send(()).unwrap();
                    release.recv_timeout(Duration::from_secs(3)).unwrap();
                }
                self.sock.write(bytes)
            }
            fn flush(&mut self) -> io::Result<()> { self.sock.flush() }
        }

        let (server_config, client_config) = test_configs();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (enter_tx, enter_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (read_tx, read_rx) = mpsc::channel();
        let server = thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
            let writer = Gated { sock: sock.try_clone().unwrap(), gate: None };
            let (mut read, mut write) = accept_tls_over(sock, writer, server_config).unwrap();
            write.inner_mut().gate = Some((enter_tx, release_rx));
            let sending = thread::spawn(move || write.write_all(b"pong").unwrap());
            let mut bytes = [0; 4];
            read.read_exact(&mut bytes).unwrap();
            read_tx.send(bytes).unwrap();
            sending.join().unwrap();
        });
        let socket = TcpStream::connect(address).unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let (mut read, mut write) = connect_tls_split(socket, client_config, "localhost").unwrap();
        enter_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        write.write_all(b"ping").unwrap();
        let received_while_blocked = read_rx.recv_timeout(Duration::from_secs(1));
        release_tx.send(()).unwrap();
        assert_eq!(received_while_blocked.unwrap(), *b"ping");
        let mut response = [0; 4];
        read.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"pong");
        server.join().unwrap();
    }

    #[test]
    fn retry_keeps_partial_record_and_ciphertext_and_accepts_close_notify() {
        struct Choppy<S> {
            inner: S,
            step: u8,
        }
        impl<S> Choppy<S> {
            fn limit(&mut self, len: usize) -> io::Result<usize> {
                match self.step {
                    1 => { self.step = 2; Ok(len.min(2)) }
                    2 => { self.step = 0; Err(io::ErrorKind::WouldBlock.into()) }
                    _ => Ok(len),
                }
            }
        }
        impl<S: Read> Read for Choppy<S> {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                let len = self.limit(buf.len())?;
                self.inner.read(&mut buf[..len])
            }
        }
        impl<S: Write> Write for Choppy<S> {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                let len = self.limit(buf.len())?;
                self.inner.write(&buf[..len])
            }
            fn flush(&mut self) -> io::Result<()> { self.inner.flush() }
        }

        let (server_config, client_config) = test_configs();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let writer = Choppy { inner: sock.try_clone().unwrap(), step: 0 };
            let (_, mut write) = accept_tls_over(sock, writer, server_config).unwrap();
            write.inner_mut().step = 1;
            assert_eq!(write.write(b"hello").unwrap_err().kind(), io::ErrorKind::WouldBlock);
            assert_eq!(write.write(b"other").unwrap_err().kind(), io::ErrorKind::InvalidInput);
            write.write_all(b"hello").unwrap();
            write.core.conn.lock().unwrap().send_close_notify();
            write.flush().unwrap();
        });
        let sock = TcpStream::connect(address).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let reader = Choppy { inner: sock.try_clone().unwrap(), step: 0 };
        let (mut read, _) = connect_tls_over(reader, sock, client_config, "localhost").unwrap();
        read.inner_mut().step = 1;
        let mut bytes = [0; 5];
        assert_eq!(read.read(&mut bytes).unwrap_err().kind(), io::ErrorKind::WouldBlock);
        read.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"hello");
        assert_eq!(read.read(&mut bytes).unwrap(), 0);
        server.join().unwrap();
    }

    #[test]
    fn unclean_tls_eof_reports_truncation() {
        let (server_config, client_config) = test_configs();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            let (_, mut write) = accept_tls_split(socket, server_config).unwrap();
            write.write_all(b"hello").unwrap();
        });
        let socket = TcpStream::connect(address).unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let (mut read, _) = connect_tls_split(socket, client_config, "localhost").unwrap();
        let mut bytes = [0; 5];
        read.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"hello");
        assert_eq!(read.read(&mut bytes).unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
        server.join().unwrap();
    }

    #[test]
    fn leaf_pin_and_ca_pin_follow_different_validation_rules() {
        let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf = rcgen::CertificateParams::new(vec!["example.com".into()]).unwrap()
            .signed_by(&leaf_key, &ca, &ca_key).unwrap();
        let wrong = ServerName::try_from("elsewhere.example").unwrap();
        let name = ServerName::try_from("example.com").unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verify = |pins: Vec<[u8; 32]>, chain: &[CertificateDer<'_>], name| {
            CertificatePolicy { pins, provider: provider.clone() }
                .verify_server_cert(leaf.der(), chain, name, &[], UnixTime::now())
        };
        let digest: [u8; 32] = Sha256::digest(leaf.der()).into();
        let pin = digest.map(|byte| format!("{byte:02X}")).join(":");
        assert!(client_config_pinned(&[], false, &format!(" ,{pin}, ")).is_ok());
        assert!(client_config_pinned(&[], false, &pin[..pin.len() - 1]).is_err());
        assert!(verify(parse_pins(&pin).unwrap(), &[], &wrong).is_ok());
        assert!(verify(vec![[1; 32]], &[], &name).is_err());
        let ca_pin = Sha256::digest(ca.der()).into();
        assert!(verify(vec![ca_pin], &[ca.der().clone()], &name).is_ok());
        assert!(verify(vec![ca_pin], &[ca.der().clone()], &wrong).is_err());
        assert!(verify(vec![ca_pin], &[], &name).is_err());
        assert!(!certificate_is_ca(leaf.der()));
    }

    #[test]
    fn split_read_does_not_block_the_writer() {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        let config = server_config(&certified.cert.pem(), &certified.key_pair.serialize_pem(), &["h2".into()]).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (sock, _) = listener.accept().unwrap();
            let (mut read, mut write) = accept_tls_split(sock, config).unwrap();
            let writer = thread::spawn(move || {
                thread::sleep(Duration::from_millis(50));
                write.write_all(b"pong").unwrap();
                write.flush().unwrap();
            });
            let mut buf = [0u8; 4];
            read.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"ping");
            writer.join().unwrap();
        });
        let sock = TcpStream::connect(addr).unwrap();
        sock.set_read_timeout(Some(Duration::from_secs(2))).ok();
        let mut client = connect_tls(sock, client_config(&["h2".into()], true).unwrap(), "localhost").unwrap();
        client.write_all(b"ping").unwrap();
        client.flush().unwrap();
        let mut buf = [0u8; 4];
        client.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"pong");
        server.join().unwrap();
    }
}
