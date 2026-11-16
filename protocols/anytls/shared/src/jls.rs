//! JLS authenticates the TLS handshake before the ordinary AnyTLS password is sent.

use std::io::{self, Cursor, Read, Write};
use std::net::TcpStream;
use std::sync::{Arc, Mutex};

use kerlico_tls::advanced::{self, AdvancedTlsClientConfig, AdvancedTlsOptions};
use rustls_jls::jls::{JlsClientConfig, JlsServerConfig, JlsState, JlsUser};
use rustls_jls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls_jls::{ClientConfig, ClientConnection, Connection, RootCertStore, ServerConfig, ServerConnection};

use crate::tls::{Established, TransportWrite};
use crate::shadow::{is_tls13, record, server_random};

#[derive(Clone)]
pub enum Client {
    Kernel(Arc<ClientConfig>),
    Fingerprint(Arc<AdvancedTlsClientConfig>, JlsUser),
}

impl Client {
    pub fn new(username: &str, password: &str, alpn: Option<&[String]>, fingerprint: &str) -> io::Result<Self> {
        if username.is_empty() || password.is_empty() {
            return Err(invalid("JLS username and password are required"));
        }
        if !fingerprint.is_empty() && fingerprint != "none" {
            let options = AdvancedTlsOptions {
                min_version: "1.3".into(),
                max_version: "1.3".into(),
                fingerprint: fingerprint.into(),
                alpn: alpn.map(<[String]>::to_vec).unwrap_or_else(|| vec!["h2".into(), "http/1.1".into()]),
                // The ServerHello proof replaces trust in the certificate chain.
                allow_insecure: true,
                ..Default::default()
            };
            return Ok(Self::Fingerprint(advanced::advanced_client_config(&options)?, JlsUser::new(password, username)));
        }
        let mut config = ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls_jls::version::TLS13]).map_err(invalid)?
            .with_root_certificates(RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() })
            .with_no_client_auth();
        config.jls_config = JlsClientConfig::new(password, username);
        config.resumption = rustls_jls::client::Resumption::disabled();
        config.alpn_protocols = protocols(alpn);
        Ok(Self::Kernel(Arc::new(config)))
    }

    pub fn connect(&self, tcp: TcpStream, sni: &str) -> io::Result<Established> {
        let Self::Kernel(config) = self else {
            let Self::Fingerprint(config, user) = self else { unreachable!() };
            return connect_fingerprint(tcp, sni, config.clone(), user.clone());
        };
        let name = ServerName::try_from(sni.to_owned()).map_err(invalid)?;
        let conn = ClientConnection::new(config.clone(), name).map_err(invalid)?;
        match handshake(tcp, Connection::Client(conn), false)? {
            Accepted::Authenticated(link) => Ok(link),
            Accepted::Fallback(_, _) => unreachable!("client does not relay"),
        }
    }
}

fn connect_fingerprint(
    tcp: TcpStream, sni: &str, config: Arc<AdvancedTlsClientConfig>, user: JlsUser,
) -> io::Result<Established> {
    let read = VerifyServerHello { tcp: tcp.try_clone()?, user: Some(user.clone()), pending: Cursor::new(Vec::new()) };
    let rng = provider().secure_random;
    let (read, write) = advanced::connect_advanced_tls_with_hello(read, tcp.try_clone()?, config, sni,
        move |hello, random, _| {
            let Some(authenticated) = hello_auth_data(hello, 1) else { return false };
            let seed: [u8; 16] = random[..16].try_into().expect("JLS seed");
            *random = user.build_server_fake_random(&seed, rng, &authenticated);
            true
        })?;
    Ok(Established::wrapped(tcp, read, write))
}

fn hello_auth_data(hello: &[u8], message: u8) -> Option<Vec<u8>> {
    let size = hello.get(1..4)?;
    if hello.len() < 38 || hello[0] != message
        || u32::from_be_bytes([0, size[0], size[1], size[2]]) as usize + 4 != hello.len()
    {
        return None;
    }
    let mut authenticated = hello.to_vec();
    authenticated[6..38].fill(0);
    Some(authenticated)
}

struct VerifyServerHello {
    tcp: TcpStream,
    user: Option<JlsUser>,
    pending: Cursor<Vec<u8>>,
}

impl Read for VerifyServerHello {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let n = self.pending.read(bytes)?;
        if n != 0 || bytes.is_empty() {
            return Ok(n);
        }
        let Some(user) = self.user.take() else { return self.tcp.read(bytes) };
        let frame = record(&mut self.tcp)?;
        let random = server_random(&frame).filter(|_| is_tls13(&frame)).ok_or_else(|| invalid("JLS ServerHello missing"))?;
        let auth = hello_auth_data(&frame[5..], 2).ok_or_else(|| invalid("invalid JLS ServerHello"))?;
        if !user.check_fake_random(&random, &auth) {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "JLS authentication failed"));
        }
        self.pending = Cursor::new(frame);
        self.pending.read(bytes)
    }
}

#[derive(Clone)]
pub struct Server(Arc<ServerConfig>);

pub enum Accepted {
    Authenticated(Established),
    Fallback(TcpStream, Vec<u8>),
}

impl Server {
    pub fn new(
        sni: &str,
        users: &[(&str, &str)],
        alpn: Option<&[String]>,
        certificate: CertificateDer<'static>,
        private_key: PrivateKeyDer<'static>,
    ) -> io::Result<Self> {
        if users.is_empty() || users.iter().any(|(username, password)| username.is_empty() || password.is_empty()) {
            return Err(invalid("JLS requires a nonempty user list"));
        }
        let mut config = ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls_jls::version::TLS13]).map_err(invalid)?
            .with_no_client_auth()
            .with_single_cert(vec![certificate], private_key).map_err(invalid)?;
        config.jls_config = Arc::new(JlsServerConfig {
            enable: true,
            users: users.iter().map(|(username, password)| JlsUser::new(password, username)).collect(),
            upstream_sni: Some(sni.into()),
            ..Default::default()
        });
        config.alpn_protocols = protocols(alpn);
        config.send_tls13_tickets = 0;
        Ok(Self(Arc::new(config)))
    }

    pub fn accept(&self, tcp: TcpStream) -> io::Result<Accepted> {
        let conn = ServerConnection::new(self.0.clone()).map_err(invalid)?;
        handshake(tcp, Connection::Server(conn), true)
    }
}

fn provider() -> Arc<rustls_jls::crypto::CryptoProvider> {
    Arc::new(rustls_jls::crypto::ring::default_provider())
}

fn protocols(alpn: Option<&[String]>) -> Vec<Vec<u8>> {
    alpn.map(|alpn| alpn.iter().map(|value| value.as_bytes().to_vec()).collect())
        .unwrap_or_else(|| vec![b"h2".to_vec(), b"http/1.1".to_vec()])
}

fn invalid(error: impl ToString) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

struct Record<'a> {
    tcp: &'a mut TcpStream,
    prefix: Option<&'a mut Vec<u8>>,
}

impl Read for Record<'_> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let count = self.tcp.read(bytes)?;
        if let Some(prefix) = self.prefix.as_deref_mut() {
            if prefix.len() + count > 128 * 1024 {
                return Err(invalid("JLS initial handshake too large"));
            }
            prefix.extend_from_slice(&bytes[..count]);
        }
        Ok(count)
    }
}

fn handshake(mut tcp: TcpStream, mut conn: Connection, server: bool) -> io::Result<Accepted> {
    let mut prefix = Vec::new();
    let mut sent = false;
    loop {
        while conn.wants_write() {
            conn.write_tls(&mut tcp)?;
            sent = true;
        }
        if !conn.is_handshaking() {
            break;
        }
        let can_relay = server && !sent;
        let n = conn.read_tls(&mut Record { tcp: &mut tcp, prefix: can_relay.then_some(&mut prefix) })?;
        if n == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        let progress = conn.process_new_packets();
        if can_relay && (progress.is_err() || matches!(conn.jls_authed, JlsState::AuthFailed(_))) {
            return Ok(Accepted::Fallback(tcp, prefix));
        }
        progress.map_err(invalid)?;
    }
    if !matches!(conn.jls_authed, JlsState::AuthSuccess(_)) {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "JLS authentication failed"));
    }
    let read_sock = tcp.try_clone()?;
    let state = Arc::new(State { conn: Mutex::new(conn), send: Mutex::new(tcp.try_clone()?) });
    Ok(Accepted::Authenticated(Established::wrapped(
        tcp,
        Rx { state: state.clone(), tcp: read_sock, wire: vec![0; 32 * 1024], head: 0, tail: 0 },
        Tx { state, wire: Vec::new() },
    )))
}

struct State {
    conn: Mutex<Connection>,
    /// Keeps the TLS encoder and socket writes in the same order. Socket reads never hold it.
    send: Mutex<TcpStream>,
}

impl State {
    fn send(&self, wire: &mut Vec<u8>, queue: impl FnOnce(&mut Connection) -> io::Result<()>) -> io::Result<()> {
        let mut socket = self.send.lock().expect("JLS writer");
        {
            let mut conn = self.conn.lock().expect("JLS");
            queue(&mut conn)?;
            wire.clear();
            while conn.wants_write() {
                conn.write_tls(wire)?;
            }
        }
        socket.write_all(wire)
    }
}

struct Rx {
    state: Arc<State>,
    tcp: TcpStream,
    wire: Vec<u8>,
    head: usize,
    tail: usize,
}

impl Read for Rx {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        loop {
            match self.state.conn.lock().expect("JLS").reader().read(bytes) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                result => return result,
            }
            if self.head == self.tail {
                self.tail = self.tcp.read(&mut self.wire)?;
                self.head = 0;
                if self.tail == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
            }
            let needs_write = {
                let mut conn = self.state.conn.lock().expect("JLS");
                let mut input = Cursor::new(&self.wire[self.head..self.tail]);
                let consumed = conn.read_tls(&mut input)?;
                if consumed == 0 {
                    return Ok(0);
                }
                self.head += consumed;
                conn.process_new_packets().map_err(invalid)?;
                conn.wants_write()
            };
            if needs_write {
                self.state.send(&mut Vec::new(), |_| Ok(()))?;
            }
        }
    }
}

struct Tx {
    state: Arc<State>,
    wire: Vec<u8>,
}

impl Write for Tx {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.state.send(&mut self.wire, |conn| conn.writer().write_all(bytes))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl TransportWrite for Tx {
    fn close(&mut self) -> io::Result<()> {
        self.state.send(&mut self.wire, |conn| {
            conn.send_close_notify();
            Ok(())
        })
    }
}
