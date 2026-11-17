//! TLS for AnyTLS. rustls's unbuffered API runs the handshake; afterwards the record layer is
//! ours, one cipher per direction, so the reading thread and the writing threads never share a
//! lock. rustls keeps the secrets and computes the next ones when a key update happens.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine};
use kerlico_tls::advanced::{self, AdvancedTlsClientConfig, AdvancedTlsOptions,
                            AdvancedTlsServerConfig, AdvancedTlsWrite, TlsCertificate};
pub use kerlico_tls::advanced::{TlsNetwork, TlsNetworkRequest, TlsNetworkResponse};
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{ClientConnectionData, Resumption, UnbufferedClientConnection, WebPkiServerVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::kernel::KernelConnection;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::{NoClientAuth, ServerConnectionData, UnbufferedServerConnection, WebPkiClientVerifier};
use rustls::unbuffered::{ConnectionState, EncodeError, UnbufferedStatus};
use rustls::{ConnectionTrafficSecrets, DigitallySignedStruct, DistinguishedName, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};

pub use rustls::{ClientConfig, ServerConfig};

/// Largest TLS 1.3 plaintext in one record.
pub const MAX_PLAIN: usize = 16384;
/// Header, content type and tag around a record's plaintext.
pub const RECORD_OVERHEAD: usize = 5 + 1 + 16;
/// Largest ciphertext a peer may send (RFC 8446 section 5.2).
pub const MAX_CIPHERTEXT: usize = MAX_PLAIN + 256;
/// The socket read buffer starts here and doubles up to `RX_BUF_MAX` while reads fill it.
pub const RX_BUF_MIN: usize = 64 * 1024;
pub const RX_BUF_MAX: usize = 512 * 1024;
/// Handshake and authentication share this deadline.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Rotate or end the connection before reaching the AES-GCM confidentiality limit.
pub(crate) const RECORD_LIMIT: u64 = 1 << 23;

const CONTENT_ALERT: u8 = 21;
const CONTENT_HANDSHAKE: u8 = 22;
pub(crate) const CONTENT_APPDATA: u8 = 23;

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn server_provider() -> Arc<CryptoProvider> {
    let mut crypto = rustls::crypto::ring::default_provider();
    // Match the reference server's TLS 1.3 AES preference. Preserve every
    // supported suite and the TLS 1.2 order; the client's offer is unchanged.
    if let Some(index) = crypto.cipher_suites.iter().position(|suite|
        suite.suite() == rustls::CipherSuite::TLS13_AES_128_GCM_SHA256)
    {
        crypto.cipher_suites[..=index].rotate_right(1);
    }
    Arc::new(crypto)
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// `certificate` and `private-key` are PEM text or the path of a PEM file, as mihomo's
/// `NewTLSKeyPairLoader` accepts. The server offers no ALPN, like mihomo's listener.
pub fn server_config(certificate: &str, private_key: &str) -> io::Result<Arc<ServerConfig>> {
    server_config_with_client_auth(certificate, private_key, "", None)
}

pub fn server_config_with_client_auth(
    certificate: &str,
    private_key: &str,
    mode: &str,
    client_ca: Option<&str>,
) -> io::Result<Arc<ServerConfig>> {
    let (certs, key) = load_identity(certificate, private_key)?;
    let crypto = server_provider();
    let auth: Arc<dyn ClientCertVerifier> = match (mode, client_ca) {
        ("", None) => Arc::new(NoClientAuth),
        ("request" | "require-any", _) => Arc::new(CertificatePossession {
            required: mode == "require-any",
            provider: Arc::clone(&crypto),
        }),
        ("" | "verify-if-given" | "require-and-verify", Some(ca)) => {
            let mut roots = RootCertStore::empty();
            for cert in load_certs(ca)? {
                roots.add(cert).map_err(io::Error::other)?;
            }
            let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&crypto));
            let verifier = if mode == "verify-if-given" { verifier.allow_unauthenticated() } else { verifier };
            verifier.build().map_err(io::Error::other)?
        }
        ("verify-if-given" | "require-and-verify", None) => return Err(invalid("client-auth-cert is required")),
        _ => return Err(invalid("client-auth-type")),
    };
    let mut config = ServerConfig::builder_with_provider(crypto)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(io::Error::other)?
        .with_client_cert_verifier(auth)
        .with_single_cert(certs, key)
        .map_err(io::Error::other)?;
    config.ignore_client_order = true;
    config.enable_secret_extraction = true;
    config.max_early_data_size = 0;
    // Go's server sends one NewSessionTicket after the handshake.
    config.send_tls13_tickets = 1;
    Ok(Arc::new(config))
}

fn pem_or_file(text: &str) -> io::Result<Vec<u8>> {
    if text.contains("-----BEGIN") {
        Ok(text.as_bytes().to_vec())
    } else {
        std::fs::read(text)
    }
}

fn load_certs(certificate: &str) -> io::Result<Vec<CertificateDer<'static>>> {
    let pem = pem_or_file(certificate)?;
    let certs = rustls_pemfile::certs(&mut pem.as_slice()).collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(invalid("no certificate"));
    }
    Ok(certs)
}

fn load_identity(certificate: &str, private_key: &str) -> io::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let certs = load_certs(certificate)?;
    let key_pem = pem_or_file(private_key)?;
    let key = rustls_pemfile::private_key(&mut key_pem.as_slice())?
        .ok_or_else(|| invalid("no private key"))?;
    Ok((certs, key))
}

/// Request/require-any does not establish CA trust, but does require proof of key possession
/// whenever the peer presents a certificate.
#[derive(Debug)]
struct CertificatePossession {
    required: bool,
    provider: Arc<CryptoProvider>,
}

impl ClientCertVerifier for CertificatePossession {
    fn client_auth_mandatory(&self) -> bool {
        self.required
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(&self, _: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: UnixTime)
        -> Result<ClientCertVerified, rustls::Error>
    {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self, message: &[u8], cert: &CertificateDer<'_>, dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// What the client checks about the server's certificate.
#[derive(Clone, Default)]
pub struct ClientTls {
    pub alpn: Vec<String>,
    /// `skip-cert-verify`.
    pub insecure: bool,
    /// `fingerprint`: SHA-256 of one certificate in the chain, hex with optional colons.
    pub fingerprint: Option<[u8; 32]>,
    /// PEM text or paths for the certificate and private key presented to the server.
    pub identity: Option<(String, String)>,
    pub client_fingerprint: String,
    pub verify_name: String,
    pub ech_config: String,
    pub ech_dns_name: Option<String>,
}

pub enum ClientTransport {
    Kernel(Arc<ClientConfig>),
    Library(Arc<AdvancedTlsClientConfig>),
}

impl ClientTransport {
    pub fn new(options: &ClientTls, network_provider: Option<Arc<dyn TlsNetwork>>) -> io::Result<Self> {
        let ech = !options.ech_config.is_empty() || options.ech_dns_name.is_some();
        if options.client_fingerprint.is_empty() && !ech && options.verify_name.is_empty() {
            return client_config(options).map(Self::Kernel);
        }
        let mut advanced = options.advanced();
        advanced.min_version = if ech { "1.3" } else { "1.2" }.into();
        advanced.ech_config_list.clone_from(&options.ech_config);
        advanced.ech_dns_name.clone_from(&options.ech_dns_name);
        advanced.network_provider = network_provider;
        advanced::advanced_client_config(&advanced).map(Self::Library)
    }

    pub fn connect(&self, tcp: TcpStream, name: &str) -> io::Result<Established> {
        match self {
            Self::Kernel(config) => connect(tcp, Arc::clone(config), name),
            Self::Library(config) => {
                let name = name.strip_prefix('[').and_then(|name| name.strip_suffix(']')).unwrap_or(name);
                let (read, write) = advanced::connect_advanced_tls_over(
                    tcp.try_clone()?, tcp.try_clone()?, Arc::clone(config), name,
                )?;
                Ok(Established::wrapped(tcp, read, write))
            }
        }
    }
}

impl ClientTls {
    pub(crate) fn advanced(&self) -> AdvancedTlsOptions {
        AdvancedTlsOptions {
            alpn: self.alpn.clone(),
            min_version: "1.2".into(),
            fingerprint: self.client_fingerprint.to_ascii_lowercase(),
            allow_insecure: self.insecure,
            pinned_peer_cert_sha256: self.fingerprint.map(|digest| STANDARD.encode(digest)).unwrap_or_default(),
            verify_peer_cert_by_name: (!self.verify_name.is_empty()).then(|| self.verify_name.clone()).into_iter().collect(),
            client_identity: self.identity.as_ref().map(|(cert, key)| tls_certificate(cert, key)),
            ..Default::default()
        }
    }
}

pub enum ServerTransport {
    Plain,
    Kernel(Arc<ServerConfig>),
    Library(Arc<AdvancedTlsServerConfig>),
}

impl ServerTransport {
    pub fn new(certificate: &str, key: &str, mode: &str, ca: Option<&str>, ech: Option<&str>) -> io::Result<Self> {
        let Some(ech) = ech else {
            return server_config_with_client_auth(certificate, key, mode, ca).map(Self::Kernel);
        };
        let pem = pem_or_file(ech)?;
        let pem = std::str::from_utf8(&pem).map_err(io::Error::other)?.trim();
        let ech_keys = pem.strip_prefix("-----BEGIN ECH KEYS-----")
            .and_then(|contents| contents.strip_suffix("-----END ECH KEYS-----"))
            .ok_or_else(|| invalid("ECH keys PEM"))?;
        let ech_keys = ech_keys.split_ascii_whitespace().collect::<String>();
        if ech_keys.is_empty() {
            return Err(invalid("empty ECH keys PEM"));
        }
        let ca = ca.map(pem_or_file).transpose()?.map(String::from_utf8)
            .transpose().map_err(io::Error::other)?.unwrap_or_default();
        advanced::advanced_server_config(&AdvancedTlsOptions {
            min_version: "1.2".into(),
            certificates: vec![tls_certificate(certificate, key)],
            ech_server_keys: ech_keys,
            client_auth_type: mode.into(),
            client_auth_ca: ca,
            ..Default::default()
        }).map(Self::Library)
    }

    pub fn accept(&self, tcp: TcpStream) -> io::Result<Established> {
        match self {
            Self::Plain => Ok(Established::plaintext(tcp)),
            Self::Kernel(config) => accept(tcp, Arc::clone(config)),
            Self::Library(config) => {
                let (read, write) = advanced::accept_advanced_tls_over(
                    tcp.try_clone()?, tcp.try_clone()?, Arc::clone(config),
                )?;
                Ok(Established::wrapped(tcp, read, write))
            }
        }
    }
}

fn tls_certificate(cert: &str, key: &str) -> TlsCertificate {
    let mut identity = TlsCertificate::default();
    if cert.contains("-----BEGIN") {
        identity.certificate = cert.into();
    } else {
        identity.certificate_file = cert.into();
    }
    if key.contains("-----BEGIN") {
        identity.key = key.into();
    } else {
        identity.key_file = key.into();
    }
    identity
}

pub fn client_config(options: &ClientTls) -> io::Result<Arc<ClientConfig>> {
    let provider = provider();
    let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|error| invalid(error.to_string()))?;
    let builder = if options.insecure || options.fingerprint.is_some() {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Policy {
                pin: options.fingerprint,
                provider,
            }))
    } else {
        let roots = RootCertStore { roots: webpki_roots::TLS_SERVER_ROOTS.to_vec() };
        builder.with_root_certificates(roots)
    };
    let mut config = if let Some((cert, key)) = &options.identity {
        let (certs, key) = load_identity(cert, key)?;
        builder.with_client_auth_cert(certs, key).map_err(io::Error::other)?
    } else {
        builder.with_no_client_auth()
    };
    config.alpn_protocols = options.alpn.iter().map(|name| name.as_bytes().to_vec()).collect();
    // A Go client without a session cache does a full handshake every time.
    config.resumption = Resumption::disabled();
    config.enable_secret_extraction = true;
    Ok(Arc::new(config))
}

/// mihomo's `NewFingerprintVerifier`: `chrome` and the other browser names are refused, colons and
/// surrounding spaces are dropped, and the rest must be 32 bytes of hex.
pub fn parse_fingerprint(text: &str) -> io::Result<[u8; 32]> {
    if matches!(
        text,
        "chrome" | "firefox" | "safari" | "ios" | "android" | "edge" | "360" | "qq" | "random" | "randomized"
    ) {
        return Err(invalid("fingerprint is a certificate pin; a browser fingerprint is client-fingerprint"));
    }
    let hex: String = text.replace(':', "");
    let hex = hex.trim();
    if hex.len() != 64 {
        return Err(invalid("fingerprint is a SHA-256 digest"));
    }
    let mut digest = [0u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).map_err(|_| invalid("fingerprint hex"))?;
    }
    Ok(digest)
}

/// `skip-cert-verify` accepts any chain. A pin that matches the leaf accepts the chain as it is; a
/// pin that matches a later certificate makes it the only root and verifies the chain and the name,
/// as mihomo does. The handshake signature is always checked.
#[derive(Debug)]
struct Policy {
    pin: Option<[u8; 32]>,
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for Policy {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let Some(pin) = self.pin else {
            return Ok(ServerCertVerified::assertion());
        };
        let digest = |cert: &CertificateDer<'_>| -> [u8; 32] { Sha256::digest(cert.as_ref()).into() };
        if digest(end_entity) == pin {
            return Ok(ServerCertVerified::assertion());
        }
        let index = intermediates
            .iter()
            .position(|cert| digest(cert) == pin)
            .ok_or_else(|| rustls::Error::General("certificate fingerprint does not match".into()))?;
        let mut roots = RootCertStore::empty();
        roots.add(intermediates[index].clone())?;
        let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), Arc::clone(&self.provider))
            .build()
            .map_err(|error| rustls::Error::General(error.to_string()))?;
        verifier.verify_server_cert(end_entity, &intermediates[..index], server_name, ocsp, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

/// The part of rustls that outlives the handshake: it derives the next traffic secret.
pub(crate) enum Kernel {
    Client(KernelConnection<ClientConnectionData>),
    Server(KernelConnection<ServerConnectionData>),
    Library,
}

impl Kernel {
    fn is_tls13(&self) -> bool {
        let version = match self {
            Self::Client(kernel) => kernel.protocol_version(),
            Self::Server(kernel) => kernel.protocol_version(),
            Self::Library => return false,
        };
        version == rustls::ProtocolVersion::TLSv1_3
    }

    pub(crate) fn next_tx(&mut self) -> io::Result<Cipher> {
        let secrets = match self {
            Self::Client(kernel) => kernel.update_tx_secret(),
            Self::Server(kernel) => kernel.update_tx_secret(),
            Self::Library => return Err(invalid("library TLS owns the send keys")),
        };
        Cipher::new(secrets.map_err(|error| invalid(error.to_string()))?, true)
    }

    pub(crate) fn next_rx(&mut self) -> io::Result<Cipher> {
        let secrets = match self {
            Self::Client(kernel) => kernel.update_rx_secret(),
            Self::Server(kernel) => kernel.update_rx_secret(),
            Self::Library => return Err(invalid("library TLS owns the receive keys")),
        };
        Cipher::new(secrets.map_err(|error| invalid(error.to_string()))?, true)
    }
}

/// A transport ready for the AnyTLS password and session framing.
pub struct Established {
    pub(crate) tcp: TcpStream,
    pub(crate) wire: Wire,
}

pub(crate) enum Wire {
    Plain,
    Records(Box<Records>),
    Library(Box<dyn Read + Send>, Box<dyn TransportWrite>),
}

pub(crate) trait TransportWrite: Write + Send {
    fn close(&mut self) -> io::Result<()>;
}

impl TransportWrite for AdvancedTlsWrite<TcpStream> {
    fn close(&mut self) -> io::Result<()> {
        self.send_close_notify()
    }
}

pub(crate) struct Records {
    /// Ciphertext that arrived after the last handshake record, at the front of a read buffer.
    pub(crate) rx_buf: Vec<u8>,
    pub(crate) rx_len: usize,
    /// Application data rustls already decrypted while finishing the handshake.
    pub(crate) early: Vec<u8>,
    /// The client's last flight, held back so it leaves with the first AnyTLS bytes.
    pub(crate) pending: Vec<u8>,
    pub(crate) tx: Cipher,
    pub(crate) rx: Cipher,
    pub(crate) kernel: Kernel,
}

impl Established {
    /// Use a socket already known to be plaintext. Never infer plaintext from a TLS failure.
    pub fn plaintext(tcp: TcpStream) -> Self {
        Self { tcp, wire: Wire::Plain }
    }

    pub(crate) fn wrapped(tcp: TcpStream, read: impl Read + Send + 'static, write: impl TransportWrite + 'static) -> Self {
        Self { tcp, wire: Wire::Library(Box::new(read), Box::new(write)) }
    }

    pub fn peer_addr(&self) -> io::Result<std::net::SocketAddr> {
        self.tcp.peer_addr()
    }
}

/// Runs the server handshake on `tcp`. The caller sets and clears the socket deadline.
pub fn accept(tcp: TcpStream, config: Arc<ServerConfig>) -> io::Result<Established> {
    let mut conn = UnbufferedServerConnection::new(config).map_err(|error| invalid(error.to_string()))?;
    let mut io = HandshakeIo::new(tcp, false);
    let mut incoming = Incoming::new();
    loop {
        let UnbufferedStatus { discard, state } = conn.process_tls_records(incoming.filled());
        let action = io.step(discard, state)?;
        if incoming.apply(&mut io.tcp, action)? {
            break;
        }
    }
    let (secrets, kernel) = conn.dangerous_into_kernel_connection().map_err(|error| invalid(error.to_string()))?;
    io.finish(incoming, secrets, Kernel::Server(kernel))
}

/// Runs the client handshake. `name` is the SNI and the name the certificate is checked against.
pub fn connect(tcp: TcpStream, config: Arc<ClientConfig>, name: &str) -> io::Result<Established> {
    let host = name.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')).unwrap_or(name);
    let server = ServerName::try_from(host.to_string()).map_err(|_| invalid("server name"))?;
    let mut conn = UnbufferedClientConnection::new(config, server).map_err(|error| invalid(error.to_string()))?;
    let mut io = HandshakeIo::new(tcp, true);
    let mut incoming = Incoming::new();
    loop {
        let UnbufferedStatus { discard, state } = conn.process_tls_records(incoming.filled());
        let action = io.step(discard, state)?;
        if incoming.apply(&mut io.tcp, action)? {
            break;
        }
    }
    let (secrets, kernel) = conn.dangerous_into_kernel_connection().map_err(|error| invalid(error.to_string()))?;
    io.finish(incoming, secrets, Kernel::Client(kernel))
}

struct Incoming {
    buf: Vec<u8>,
    filled: usize,
}

struct Action {
    discard: usize,
    read: bool,
    done: bool,
}

impl Incoming {
    fn new() -> Self {
        Self { buf: vec![0; RX_BUF_MIN], filled: 0 }
    }

    fn filled(&mut self) -> &mut [u8] {
        &mut self.buf[..self.filled]
    }

    /// Drops what rustls consumed and reads more when it is blocked; `Ok(true)` when done.
    fn apply(&mut self, tcp: &mut TcpStream, action: Action) -> io::Result<bool> {
        if action.discard > 0 {
            self.buf.copy_within(action.discard..self.filled, 0);
            self.filled -= action.discard;
        }
        if action.read {
            if self.filled == self.buf.len() {
                return Err(invalid("TLS handshake message too large"));
            }
            let n = tcp.read(&mut self.buf[self.filled..])?;
            if n == 0 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "TLS peer closed during the handshake"));
            }
            self.filled += n;
        }
        Ok(action.done)
    }
}

struct HandshakeIo {
    tcp: TcpStream,
    outgoing: Vec<u8>,
    used: usize,
    early: Vec<u8>,
    defer_last_flight: bool,
}

impl HandshakeIo {
    fn new(tcp: TcpStream, defer_last_flight: bool) -> Self {
        Self {
            tcp,
            outgoing: vec![0; 4096],
            used: 0,
            early: Vec::new(),
            defer_last_flight,
        }
    }

    /// Handles one state. `done` once rustls may send application data and has nothing left to
    /// process.
    fn step<Data>(&mut self, mut discard: usize, state: Result<ConnectionState<'_, '_, Data>, rustls::Error>) -> io::Result<Action> {
        let mut done = false;
        let mut read = false;
        match state.map_err(|error| invalid(error.to_string()))? {
            ConnectionState::ReadTraffic(mut traffic) => {
                while let Some(record) = traffic.next_record() {
                    let record = record.map_err(|error| invalid(error.to_string()))?;
                    discard += record.discard;
                    self.early.extend_from_slice(record.payload);
                }
            }
            ConnectionState::EncodeTlsData(mut encode) => loop {
                match encode.encode(&mut self.outgoing[self.used..]) {
                    Ok(n) => {
                        self.used += n;
                        break;
                    }
                    Err(EncodeError::InsufficientSize(size)) => {
                        let need = self.used + size.required_size;
                        self.outgoing.resize(need, 0);
                    }
                    Err(error) => return Err(invalid(error.to_string())),
                }
            },
            ConnectionState::TransmitTlsData(mut transmit) => {
                let last = transmit.may_encrypt_app_data().is_some();
                if !(last && self.defer_last_flight) {
                    self.tcp.write_all(&self.outgoing[..self.used])?;
                    self.used = 0;
                }
                transmit.done();
            }
            ConnectionState::BlockedHandshake => read = true,
            ConnectionState::WriteTraffic(_) => done = true,
            ConnectionState::PeerClosed | ConnectionState::Closed => {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "TLS peer closed during the handshake"))
            }
            _ => return Err(invalid("unexpected TLS state during the handshake")),
        }
        Ok(Action { discard, read, done })
    }

    fn finish(self, incoming: Incoming, secrets: rustls::ExtractedSecrets, kernel: Kernel) -> io::Result<Established> {
        let mut pending = self.outgoing;
        pending.truncate(self.used);
        let tls13 = kernel.is_tls13();
        let records = Records {
            rx_buf: incoming.buf,
            rx_len: incoming.filled,
            early: self.early,
            pending,
            tx: Cipher::new(secrets.tx, tls13)?,
            rx: Cipher::new(secrets.rx, tls13)?,
            kernel,
        };
        Ok(Established { tcp: self.tcp, wire: Wire::Records(Box::new(records)) })
    }
}

/// One direction of the TLS record layer.
pub(crate) struct Cipher {
    key: LessSafeKey,
    iv: [u8; 12],
    seq: u64,
    tls13: bool,
    explicit: usize,
}

impl Cipher {
    fn new((seq, secrets): (u64, ConnectionTrafficSecrets), tls13: bool) -> io::Result<Self> {
        let (algorithm, key, iv) = match &secrets {
            ConnectionTrafficSecrets::Aes128Gcm { key, iv } => (&aead::AES_128_GCM, key, iv),
            ConnectionTrafficSecrets::Aes256Gcm { key, iv } => (&aead::AES_256_GCM, key, iv),
            ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv } => (&aead::CHACHA20_POLY1305, key, iv),
            _ => return Err(invalid("cipher suite")),
        };
        let key = UnboundKey::new(algorithm, key.as_ref()).map_err(|_| invalid("traffic key"))?;
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(iv.as_ref());
        // TLS 1.2 AES-GCM carries the last eight nonce bytes in the record. ChaCha20
        // and all TLS 1.3 suites derive them from the sequence number on both sides.
        let explicitly_encoded = !tls13 && !matches!(&secrets, ConnectionTrafficSecrets::Chacha20Poly1305 { .. });
        let explicit = if explicitly_encoded { 8 } else { 0 };
        Ok(Self { key: LessSafeKey::new(key), iv: nonce, seq, tls13, explicit })
    }

    pub(crate) fn seq(&self) -> u64 {
        self.seq
    }

    pub(crate) fn is_tls13(&self) -> bool {
        self.tls13
    }

    pub(crate) fn prefix_len(&self) -> usize {
        5 + self.explicit
    }

    fn nonce(&self) -> Nonce {
        let mut nonce = self.iv;
        for (byte, seq) in nonce[4..].iter_mut().zip(self.seq.to_be_bytes()) {
            *byte ^= seq;
        }
        Nonce::assume_unique_for_key(nonce)
    }

    /// Seals the record whose 5 header bytes start at `start`; its plaintext runs to the end of `out`.
    pub(crate) fn seal(&mut self, out: &mut Vec<u8>, start: usize, inner_type: u8) {
        let plain = out.len() - start - self.prefix_len();
        out.resize(out.len() + 16 + usize::from(self.tls13), 0);
        self.seal_in_place(&mut out[start..], plain, inner_type);
    }

    /// The initialized record already contains its plaintext and tag space.
    /// This is the same encoder used by the copying and borrowed-input writers.
    pub(crate) fn seal_in_place(&mut self, record: &mut [u8], plain: usize, inner_type: u8) {
        assert_eq!(record.len(), self.prefix_len() + plain + 16 + usize::from(self.tls13));
        if !self.tls13 {
            let body = self.prefix_len();
            let nonce = self.nonce();
            if self.explicit != 0 {
                record[5..body].copy_from_slice(&nonce.as_ref()[4..]);
            }
            let aad = Aad::from(tls12_aad(self.seq, inner_type, plain as u16));
            let tag = self.key.seal_in_place_separate_tag(nonce, aad, &mut record[body..body + plain]).expect("seal");
            let wire_len = (self.explicit + plain + tag.as_ref().len()) as u16;
            record[..3].copy_from_slice(&[inner_type, 3, 3]);
            record[3..5].copy_from_slice(&wire_len.to_be_bytes());
            record[body + plain..].copy_from_slice(tag.as_ref());
            self.seq += 1;
            return;
        }
        record[5 + plain] = inner_type;
        let len = plain + 1 + 16;
        let header = [CONTENT_APPDATA, 3, 3, (len >> 8) as u8, len as u8];
        record[..5].copy_from_slice(&header);
        let tag = self
            .key
            .seal_in_place_separate_tag(self.nonce(), Aad::from(header), &mut record[5..5 + plain + 1])
            .expect("seal");
        record[5 + plain + 1..].copy_from_slice(tag.as_ref());
        self.seq += 1;
    }

    /// Opens one whole record in place. Returns the inner content type and the plaintext length;
    /// the plaintext starts at `record[5]`.
    pub(crate) fn open(&mut self, record: &mut [u8]) -> io::Result<(u8, usize)> {
        let header: [u8; 5] = record[..5].try_into().expect("header");
        if header[1..3] != [3, 3] {
            return Err(invalid("TLS record version after the handshake"));
        }
        if !self.tls13 {
            if self.seq >= RECORD_LIMIT {
                return Err(invalid("TLS 1.2 receive record limit"));
            }
            let body = &mut record[5..];
            let len = body.len().checked_sub(self.explicit + self.key.algorithm().tag_len())
                .filter(|&len| len <= MAX_PLAIN)
                .ok_or_else(|| invalid("TLS 1.2 record length"))?;
            let nonce = if self.explicit == 0 {
                self.nonce()
            } else {
                let mut nonce = self.iv;
                nonce[4..].copy_from_slice(&body[..self.explicit]);
                Nonce::assume_unique_for_key(nonce)
            };
            let aad = Aad::from(tls12_aad(self.seq, header[0], len as u16));
            self.key.open_within(nonce, aad, body, self.explicit..)
                .map_err(|_| invalid("TLS record authentication"))?;
            self.seq += 1;
            return Ok((header[0], len));
        }
        if header[0] != CONTENT_APPDATA {
            return Err(invalid("TLS record type after the handshake"));
        }
        let plain = self
            .key
            .open_in_place(self.nonce(), Aad::from(header), &mut record[5..])
            .map_err(|_| invalid("TLS record authentication"))?;
        self.seq += 1;
        let end = plain.iter().rposition(|byte| *byte != 0).ok_or_else(|| invalid("TLS record without a type"))?;
        Ok((plain[end], end))
    }
}

fn tls12_aad(seq: u64, kind: u8, len: u16) -> [u8; 13] {
    let mut aad = [0; 13];
    aad[..8].copy_from_slice(&seq.to_be_bytes());
    aad[8..11].copy_from_slice(&[kind, 3, 3]);
    aad[11..].copy_from_slice(&len.to_be_bytes());
    aad
}

/// Builds a KeyUpdate message (RFC 8446 section 4.6.3).
pub(crate) fn key_update(requested: bool) -> [u8; 5] {
    [24, 0, 0, 1, u8::from(requested)]
}

/// What the reading thread found in one record besides application data.
pub(crate) enum Control {
    /// close_notify.
    Closed,
    /// The peer changed its keys; `true` if it asks for ours too.
    KeyUpdate(bool),
    /// A message the session does not act on (NewSessionTicket).
    Ignored,
}

/// Interprets a non-application record. `hs` collects a handshake message split across records.
pub(crate) fn control(inner_type: u8, plain: &[u8], hs: &mut Vec<u8>) -> io::Result<Vec<Control>> {
    match inner_type {
        CONTENT_ALERT => {
            if plain.len() == 2 && plain[1] == 0 {
                Ok(vec![Control::Closed])
            } else {
                Err(io::Error::new(io::ErrorKind::ConnectionAborted, format!("TLS alert {:?}", plain)))
            }
        }
        CONTENT_HANDSHAKE => {
            hs.extend_from_slice(plain);
            let mut found = Vec::new();
            while hs.len() >= 4 {
                let len = u32::from_be_bytes([0, hs[1], hs[2], hs[3]]) as usize;
                if len > 65536 {
                    return Err(invalid("post-handshake message too large"));
                }
                if hs.len() < 4 + len {
                    break;
                }
                match hs[0] {
                    4 => found.push(Control::Ignored),
                    24 if len == 1 && hs[4] <= 1 => found.push(Control::KeyUpdate(hs[4] == 1)),
                    _ => return Err(invalid("unexpected post-handshake message")),
                }
                hs.drain(..4 + len);
            }
            Ok(found)
        }
        _ => Err(invalid("unexpected TLS content type")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn wire_timeout(tcp: &TcpStream) {
        let timeout = Some(Duration::from_secs(3));
        tcp.set_read_timeout(timeout).unwrap();
        tcp.set_write_timeout(timeout).unwrap();
    }

    #[test]
    fn tls13_server_prefers_aes128_and_keeps_aes256_and_chacha_peers() {
        use rustls::crypto::ring::cipher_suite::{TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256};
        let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let server = server_config(&identity.cert.pem(), &identity.key_pair.serialize_pem()).unwrap();
        for (only, expected) in [
            (None, rustls::CipherSuite::TLS13_AES_128_GCM_SHA256),
            (Some(TLS13_AES_256_GCM_SHA384), rustls::CipherSuite::TLS13_AES_256_GCM_SHA384),
            (Some(TLS13_CHACHA20_POLY1305_SHA256), rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256),
        ] {
            let mut crypto = rustls::crypto::ring::default_provider();
            if let Some(suite) = only { crypto.cipher_suites = vec![suite]; }
            let mut roots = RootCertStore::empty();
            roots.add(identity.cert.der().clone()).unwrap();
            let client = ClientConfig::builder_with_provider(Arc::new(crypto))
                .with_protocol_versions(&[&rustls::version::TLS13]).unwrap()
                .with_root_certificates(roots).with_no_client_auth();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let config = server.clone();
            let peer = std::thread::spawn(move || {
                let (tcp, _) = listener.accept().unwrap();
                wire_timeout(&tcp);
                let mut link = accept(tcp, config).unwrap();
                let Wire::Records(wire) = &mut link.wire else { panic!("kernel TLS") };
                assert!(wire.tx.is_tls13());
                let mut out = std::mem::take(&mut wire.pending);
                let start = out.len();
                out.resize(start + wire.tx.prefix_len(), 0);
                out.extend_from_slice(b"ping");
                wire.tx.seal(&mut out, start, CONTENT_APPDATA);
                link.tcp.write_all(&out).unwrap();
                let mut record = vec![0; 5];
                link.tcp.read_exact(&mut record).unwrap();
                record.resize(5 + usize::from(u16::from_be_bytes([record[3], record[4]])), 0);
                link.tcp.read_exact(&mut record[5..]).unwrap();
                assert_eq!(wire.rx.open(&mut record).unwrap(), (CONTENT_APPDATA, 4));
                assert_eq!(&record[5..9], b"pong");
            });
            let tcp = TcpStream::connect(addr).unwrap();
            wire_timeout(&tcp);
            let conn = rustls::ClientConnection::new(Arc::new(client), ServerName::try_from("localhost").unwrap()).unwrap();
            let mut link = rustls::StreamOwned::new(conn, tcp);
            let mut bytes = [0; 4];
            link.read_exact(&mut bytes).unwrap();
            assert_eq!(&bytes, b"ping");
            assert_eq!(link.conn.negotiated_cipher_suite().unwrap().suite(), expected);
            link.write_all(b"pong").unwrap();
            link.flush().unwrap();
            peer.join().unwrap();
        }
    }

    #[test]
    fn tls12_records_interoperate_with_the_standard_rustls_record_layer() {
        use rustls::crypto::ring::cipher_suite::{
            TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        };
        let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate = identity.cert.der().clone();
        let key = PrivateKeyDer::try_from(identity.key_pair.serialize_der()).unwrap();
        for suite in [TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256] {
            let mut peer_provider = rustls::crypto::ring::default_provider();
            peer_provider.cipher_suites = vec![suite];
            let server = ServerConfig::builder_with_provider(Arc::new(peer_provider))
                .with_protocol_versions(&[&rustls::version::TLS12])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![certificate.clone()], key.clone_key())
                .unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let peer = std::thread::spawn(move || {
                let (tcp, _) = listener.accept().unwrap();
                wire_timeout(&tcp);
                let conn = rustls::ServerConnection::new(Arc::new(server)).unwrap();
                let mut tls = rustls::StreamOwned::new(conn, tcp);
                let mut bytes = [0; 4];
                tls.read_exact(&mut bytes).unwrap();
                assert_eq!(&bytes, b"ping");
                tls.write_all(b"pong").unwrap();
                tls.flush().unwrap();
            });
            let tcp = TcpStream::connect(address).unwrap();
            wire_timeout(&tcp);
            let client = client_config(&ClientTls { insecure: true, ..ClientTls::default() }).unwrap();
            let mut link = connect(tcp, client, "localhost").unwrap();
            let Wire::Records(wire) = &mut link.wire else { panic!("kernel TLS") };
            assert!(!wire.tx.is_tls13());
            assert_eq!(wire.rx_len, 0);
            let mut out = std::mem::take(&mut wire.pending);
            let start = out.len();
            out.resize(start + wire.tx.prefix_len(), 0);
            out.extend_from_slice(b"ping");
            wire.tx.seal(&mut out, start, CONTENT_APPDATA);
            link.tcp.write_all(&out).unwrap();
            let mut record = vec![0; 5];
            link.tcp.read_exact(&mut record).unwrap();
            record.resize(5 + usize::from(u16::from_be_bytes([record[3], record[4]])), 0);
            link.tcp.read_exact(&mut record[5..]).unwrap();
            assert_eq!(wire.rx.open(&mut record).unwrap(), (CONTENT_APPDATA, 4));
            assert_eq!(&record[5..9], b"pong");
            peer.join().unwrap();
        }
    }

    #[test]
    fn client_certificate_is_required_and_checked_against_the_configured_ca() {
        use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair};
        let server_pair = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let root_key = KeyPair::generate().unwrap();
        let mut root_params = CertificateParams::default();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let root = root_params.self_signed(&root_key).unwrap();
        let client_key = KeyPair::generate().unwrap();
        let mut client_params = CertificateParams::default();
        client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let client_cert = client_params.signed_by(&client_key, &root, &root_key).unwrap();
        let wrong = rcgen::generate_simple_self_signed(vec!["untrusted".into()]).unwrap();
        let valid = Some((client_cert.pem(), client_key.serialize_pem()));
        let invalid = Some((wrong.cert.pem(), wrong.key_pair.serialize_pem()));
        let server = server_config_with_client_auth(
            &server_pair.cert.pem(), &server_pair.key_pair.serialize_pem(), "require-and-verify", Some(&root.pem()),
        ).unwrap();
        for (client_identity, authorized) in [(None, false), (invalid, false), (valid, true)] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let server = Arc::clone(&server);
            let peer = std::thread::spawn(move || {
                let (tcp, _) = listener.accept().unwrap();
                wire_timeout(&tcp);
                accept(tcp, server).is_ok()
            });
            let tcp = TcpStream::connect(address).unwrap();
            wire_timeout(&tcp);
            let client = client_config(&ClientTls {
                insecure: true, identity: client_identity, ..ClientTls::default()
            }).unwrap();
            if let Ok(link) = connect(tcp, client, "localhost") {
                let Wire::Records(wire) = link.wire else { panic!("kernel TLS") };
                (&link.tcp).write_all(&wire.pending).unwrap();
            }
            assert_eq!(peer.join().unwrap(), authorized);
        }
    }

    #[test]
    fn fingerprint_parses_like_mihomo() {
        let text = "AB:".repeat(31) + "AB";
        assert_eq!(parse_fingerprint(&text).unwrap(), [0xab; 32]);
        assert_eq!(parse_fingerprint(&format!("  {}  ", "0f".repeat(32))).unwrap(), [0x0f; 32]);
        assert!(parse_fingerprint("chrome").is_err());
        assert!(parse_fingerprint(&"ab".repeat(31)).is_err());
        assert!(parse_fingerprint(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn records_round_trip_and_reject_tampering() {
        let secrets = || ConnectionTrafficSecrets::Aes256Gcm { key: [7u8; 32].into(), iv: [9u8; 12].into() };
        let mut seal = Cipher::new((5, secrets()), true).unwrap();
        let mut open = Cipher::new((5, secrets()), true).unwrap();
        let mut out = vec![0u8; 5];
        out.extend_from_slice(b"hello");
        seal.seal(&mut out, 0, CONTENT_APPDATA);
        assert_eq!(out.len(), 5 + RECORD_OVERHEAD);
        assert_eq!(&out[..3], &[23, 3, 3]);
        let mut copy = out.clone();
        assert_eq!(open.open(&mut copy).unwrap(), (CONTENT_APPDATA, 5));
        assert_eq!(&copy[5..10], b"hello");
        let mut tampered = out.clone();
        tampered[7] ^= 1;
        assert!(open.open(&mut tampered).is_err());
    }
}
