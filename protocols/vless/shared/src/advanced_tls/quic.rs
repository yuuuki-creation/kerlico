use super::{
    advanced_client_config, advanced_server_config, AdvancedTlsClientConfig, AdvancedTlsOptions,
    AdvancedTlsServerConfig,
};
use boring2::{
    error::ErrorStack,
    ssl::{
        quic::{EncryptionLevel, HandshakeStatus, QuicConnection, QuicMethod},
        NameType, SslCipherRef, SslVersion,
    },
};
use bytes::BytesMut;
use quinn::crypto::{
    self, CryptoError, ExportKeyingMaterialError, HeaderKey, KeyPair, Keys, PacketKey,
    UnsupportedVersion,
};
use quinn::{ConnectError, ConnectionId, Side};
use quinn_proto::{transport_parameters::TransportParameters, TransportError, TransportErrorCode};
use ring::aead;
use std::{
    any::Any,
    collections::VecDeque,
    io,
    sync::{Arc, Mutex},
};

pub fn advanced_quic_client_config(
    options: &AdvancedTlsOptions,
    chrome_parrot: bool,
) -> io::Result<Arc<dyn crypto::ClientConfig>> {
    let options = quic_options(options)?;
    let config = if chrome_parrot {
        let mut options = options;
        options.enable_session_resumption = false;
        super::config::advanced_client_config_with_profile(
            &options,
            Some(super::fingerprint::chrome_quic(&options.alpn)),
        )?
    } else {
        advanced_client_config(&options)?
    };
    Ok(Arc::new(Client(config)))
}

impl super::AdvancedTlsClientCache {
    pub fn quic(
        &self,
        options: &AdvancedTlsOptions,
        chrome_parrot: bool,
    ) -> io::Result<Arc<dyn crypto::ClientConfig>> {
        let mut options = quic_options(options)?;
        let config = if chrome_parrot {
            options.enable_session_resumption = false;
            self.get_profile(
                &options,
                Some(super::fingerprint::chrome_quic(&options.alpn)),
            )?
        } else {
            self.get(&options)?
        };
        Ok(Arc::new(Client(config)))
    }
}
pub fn advanced_quic_server_config(
    options: &AdvancedTlsOptions,
) -> io::Result<Arc<dyn crypto::ServerConfig>> {
    let options = quic_options(options)?;
    Ok(Arc::new(Server(advanced_server_config(&options)?)))
}

fn quic_options(options: &AdvancedTlsOptions) -> io::Result<AdvancedTlsOptions> {
    if !matches!(options.max_version.as_str(), "" | "1.3") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "QUIC requires TLS 1.3",
        ));
    }
    if let Some(profile) = super::fingerprint::resolve(&options.fingerprint)? {
        if !profile
            .ciphers
            .iter()
            .any(|id| (0x1301..=0x1303).contains(id))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "QUIC fingerprint requires TLS 1.3",
            ));
        }
    }
    let mut options = options.clone();
    options.min_version = "1.3".into();
    options.max_version = "1.3".into();
    if options.alpn.is_empty() {
        options.alpn = vec!["h3".into()];
    }
    Ok(options)
}

struct Client(Arc<AdvancedTlsClientConfig>);
struct Server(Arc<AdvancedTlsServerConfig>);

impl crypto::ClientConfig for Client {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, ConnectError> {
        check_version(version)?;
        let mut ssl = self
            .0
            .ssl(name)
            .map_err(|e| ConnectError::InvalidServerName(e.to_string()))?;
        ssl.set_min_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|e| ConnectError::InvalidServerName(e.to_string()))?;
        ssl.set_max_proto_version(Some(SslVersion::TLS1_3))
            .map_err(|e| ConnectError::InvalidServerName(e.to_string()))?;
        ssl.set_raw_supported_versions(&[0x0304])
            .map_err(|e| ConnectError::InvalidServerName(e.to_string()))?;
        let callbacks = Arc::new(Callbacks::default());
        let mut conn = QuicConnection::new(ssl, callbacks.clone())
            .map_err(|e| ConnectError::InvalidServerName(e.to_string()))?;
        conn.set_connect_state();
        let mut encoded = Vec::new();
        params.write(&mut encoded);
        conn.set_transport_parameters(&encoded)
            .map_err(|e| ConnectError::InvalidServerName(e.to_string()))?;
        let mut session = Session::new(
            conn,
            callbacks,
            Side::Client,
            Some((self.0.clone(), name.to_string())),
        );
        session
            .advance()
            .map_err(|e| ConnectError::InvalidServerName(e.to_string()))?;
        Ok(Box::new(session))
    }
}
impl crypto::ServerConfig for Server {
    fn initial_keys(&self, version: u32, cid: &ConnectionId) -> Result<Keys, UnsupportedVersion> {
        check_version(version)?;
        Ok(initial(cid, Side::Server))
    }
    fn retry_tag(&self, _version: u32, cid: &ConnectionId, packet: &[u8]) -> [u8; 16] {
        retry_tag(cid, packet)
    }
    fn start_session(
        self: Arc<Self>,
        _version: u32,
        params: &TransportParameters,
    ) -> Box<dyn crypto::Session> {
        let mut ssl = self
            .0
            .ssl()
            .expect("validated QUIC TLS server configuration");
        ssl.set_min_proto_version(Some(SslVersion::TLS1_3))
            .expect("TLS 1.3");
        ssl.set_max_proto_version(Some(SslVersion::TLS1_3))
            .expect("TLS 1.3");
        let callbacks = Arc::new(Callbacks::default());
        let mut conn = QuicConnection::new(ssl, callbacks.clone()).expect("QUIC TLS method");
        conn.set_accept_state();
        let mut encoded = Vec::new();
        params.write(&mut encoded);
        conn.set_transport_parameters(&encoded)
            .expect("QUIC transport parameters");
        Box::new(Session::new(conn, callbacks, Side::Server, None))
    }
}

fn check_version(version: u32) -> Result<(), UnsupportedVersion> {
    if version == 1 {
        Ok(())
    } else {
        Err(UnsupportedVersion)
    }
}

enum Event {
    Secret {
        level: EncryptionLevel,
        read: bool,
        secret: Secret,
    },
    Data(EncryptionLevel, Vec<u8>),
}
#[derive(Default)]
struct Callbacks {
    events: Mutex<VecDeque<Event>>,
    alert: Mutex<Option<u8>>,
}
impl QuicMethod for Callbacks {
    fn set_read_secret(
        &self,
        level: EncryptionLevel,
        cipher: &SslCipherRef,
        secret: &[u8],
    ) -> Result<(), ErrorStack> {
        self.secret(level, true, cipher, secret)
    }
    fn set_write_secret(
        &self,
        level: EncryptionLevel,
        cipher: &SslCipherRef,
        secret: &[u8],
    ) -> Result<(), ErrorStack> {
        self.secret(level, false, cipher, secret)
    }
    fn add_handshake_data(&self, level: EncryptionLevel, data: &[u8]) -> Result<(), ErrorStack> {
        self.events
            .lock()
            .expect("QUIC TLS events")
            .push_back(Event::Data(level, data.to_vec()));
        Ok(())
    }
    fn flush_flight(&self) -> Result<(), ErrorStack> {
        Ok(())
    }
    fn send_alert(&self, _level: EncryptionLevel, alert: u8) -> Result<(), ErrorStack> {
        *self.alert.lock().expect("QUIC alert") = Some(alert);
        Ok(())
    }
}
impl Callbacks {
    fn secret(
        &self,
        level: EncryptionLevel,
        read: bool,
        cipher: &SslCipherRef,
        bytes: &[u8],
    ) -> Result<(), ErrorStack> {
        let id = cipher.protocol_id();
        if !matches!(id, 0x1301..=0x1303) {
            return Err(ErrorStack::get());
        }
        self.events
            .lock()
            .expect("QUIC TLS events")
            .push_back(Event::Secret {
                level,
                read,
                secret: Secret {
                    suite: id,
                    bytes: bytes.to_vec(),
                },
            });
        Ok(())
    }
}

#[derive(Default)]
struct Pair {
    read: Option<Secret>,
    write: Option<Secret>,
}
impl Pair {
    fn ready(&self) -> bool {
        self.read.is_some() && self.write.is_some()
    }
    fn keys(&self) -> Keys {
        keys(self.write.as_ref().unwrap(), self.read.as_ref().unwrap())
    }
}

struct Session {
    conn: QuicConnection,
    callbacks: Arc<Callbacks>,
    side: Side,
    verify: Option<(Arc<AdvancedTlsClientConfig>, String)>,
    verified: bool,
    got_handshake_data: bool,
    emitted: EncryptionLevel,
    handshake: Pair,
    application: Pair,
}
impl Session {
    fn new(
        conn: QuicConnection,
        callbacks: Arc<Callbacks>,
        side: Side,
        verify: Option<(Arc<AdvancedTlsClientConfig>, String)>,
    ) -> Self {
        Self {
            conn,
            callbacks,
            side,
            verify,
            verified: false,
            got_handshake_data: false,
            emitted: EncryptionLevel::Initial,
            handshake: Pair::default(),
            application: Pair::default(),
        }
    }
    fn error(&self, error: impl ToString) -> TransportError {
        TransportError {
            code: TransportErrorCode::crypto(
                self.callbacks
                    .alert
                    .lock()
                    .expect("QUIC alert")
                    .unwrap_or(80),
            ),
            frame: None,
            reason: error.to_string(),
        }
    }
    fn advance(&mut self) -> Result<(), TransportError> {
        let status = self.conn.handshake().map_err(|e| self.error(e))?;
        if status == HandshakeStatus::Complete && !self.verified {
            if let Some((config, name)) = &self.verify {
                config
                    .verify(self.conn.ssl(), name)
                    .map_err(|e| self.error(e))?;
            }
            self.verified = true;
        }
        Ok(())
    }
}
impl crypto::Session for Session {
    fn initial_keys(&self, cid: &ConnectionId, side: Side) -> Keys {
        initial(cid, side)
    }
    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        self.got_handshake_data.then(|| {
            Box::new(crypto::rustls::HandshakeData {
                protocol: self.conn.ssl().selected_alpn_protocol().map(<[u8]>::to_vec),
                server_name: if self.side == Side::Server {
                    self.conn
                        .ssl()
                        .servername(NameType::HOST_NAME)
                        .map(str::to_string)
                } else {
                    None
                },
            }) as Box<dyn Any>
        })
    }
    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        self.conn.ssl().peer_cert_chain().map(|certs| {
            Box::new(
                certs
                    .iter()
                    .filter_map(|c| c.to_der().ok().map(rustls::pki_types::CertificateDer::from))
                    .collect::<Vec<_>>(),
            ) as Box<dyn Any>
        })
    }
    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)> {
        None
    }
    fn early_data_accepted(&self) -> Option<bool> {
        (self.side == Side::Client).then_some(false)
    }
    fn is_handshaking(&self) -> bool {
        !self.verified
    }
    fn read_handshake(&mut self, bytes: &[u8]) -> Result<bool, TransportError> {
        let level = self.conn.read_level();
        self.conn
            .provide_data(level, bytes)
            .map_err(|e| self.error(e))?;
        if self.verified {
            self.conn
                .process_post_handshake()
                .map_err(|e| self.error(e))?;
        } else {
            self.advance()?;
        }
        if !self.got_handshake_data
            && (self.conn.ssl().selected_alpn_protocol().is_some() || self.verified)
        {
            self.got_handshake_data = true;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        let bytes = self.conn.peer_transport_parameters();
        if bytes.is_empty() {
            return Ok(None);
        }
        TransportParameters::read(self.side, &mut std::io::Cursor::new(bytes))
            .map(Some)
            .map_err(Into::into)
    }
    fn write_handshake(&mut self, bytes: &mut Vec<u8>) -> Option<Keys> {
        let mut events = self.callbacks.events.lock().expect("QUIC TLS events");
        // Read and write secrets may be published on opposite sides of a flight.
        // Collect both directions before deciding which packet space can be emitted.
        for _ in 0..events.len() {
            match events.pop_front().expect("QUIC TLS event") {
                Event::Secret {
                    level,
                    read,
                    secret,
                } => {
                    let pair = match level {
                        EncryptionLevel::Handshake => &mut self.handshake,
                        EncryptionLevel::Application => &mut self.application,
                        _ => continue,
                    };
                    if read {
                        pair.read = Some(secret);
                    } else {
                        pair.write = Some(secret);
                    }
                }
                data => events.push_back(data),
            }
        }
        loop {
            let change = match self.emitted {
                EncryptionLevel::Initial if self.handshake.ready() => {
                    Some((EncryptionLevel::Handshake, self.handshake.keys()))
                }
                EncryptionLevel::Handshake if self.application.ready() => {
                    Some((EncryptionLevel::Application, self.application.keys()))
                }
                _ => None,
            };
            if let Some((level, keys)) = change {
                if !events.front().is_some_and(
                    |event| matches!(event,Event::Data(current,_)if *current==self.emitted),
                ) {
                    self.emitted = level;
                    return Some(keys);
                }
            }
            match events.pop_front()? {
                Event::Secret {
                    level,
                    read,
                    secret,
                } => {
                    let pair = match level {
                        EncryptionLevel::Handshake => &mut self.handshake,
                        EncryptionLevel::Application => &mut self.application,
                        _ => continue,
                    };
                    if read {
                        pair.read = Some(secret);
                    } else {
                        pair.write = Some(secret);
                    }
                }
                Event::Data(level, data) => {
                    if level != self.emitted {
                        events.push_front(Event::Data(level, data));
                        return None;
                    }
                    bytes.extend(data);
                }
            }
        }
    }
    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        let read = self.application.read.as_mut()?;
        read.update();
        let write = self.application.write.as_mut()?;
        write.update();
        Some(KeyPair {
            local: Box::new(write.packet()),
            remote: Box::new(read.packet()),
        })
    }
    fn is_valid_retry(&self, cid: &ConnectionId, header: &[u8], payload: &[u8]) -> bool {
        let Some(length) = payload.len().checked_sub(16) else {
            return false;
        };
        let mut packet = header.to_vec();
        packet.extend_from_slice(&payload[..length]);
        let expected = retry_tag(cid, &packet);
        boring2::memcmp::eq(&expected, &payload[length..])
    }
    fn export_keying_material(
        &self,
        out: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        self.conn
            .ssl()
            .export_keying_material_bytes(out, label, Some(context))
            .map_err(|_| ExportKeyingMaterialError)
    }
}

struct Secret {
    suite: u16,
    bytes: Vec<u8>,
}
impl Secret {
    fn expand(&self, label: &[u8], length: usize) -> Vec<u8> {
        let mut info = (length as u16).to_be_bytes().to_vec();
        info.push((6 + label.len()) as u8);
        info.extend_from_slice(b"tls13 ");
        info.extend_from_slice(label);
        info.push(0);
        let mut out = vec![0; length];
        if self.suite == 0x1302 {
            hkdf::Hkdf::<sha2::Sha384>::from_prk(&self.bytes)
                .expect("TLS secret")
                .expand(&info, &mut out)
                .expect("QUIC HKDF");
        } else {
            hkdf::Hkdf::<sha2::Sha256>::from_prk(&self.bytes)
                .expect("TLS secret")
                .expand(&info, &mut out)
                .expect("QUIC HKDF");
        }
        out
    }
    fn update(&mut self) {
        self.bytes = self.expand(b"quic ku", self.bytes.len());
    }
    fn packet(&self) -> Packet {
        let algorithm = match self.suite {
            0x1301 => &aead::AES_128_GCM,
            0x1302 => &aead::AES_256_GCM,
            _ => &aead::CHACHA20_POLY1305,
        };
        Packet {
            key: aead::LessSafeKey::new(
                aead::UnboundKey::new(algorithm, &self.expand(b"quic key", algorithm.key_len()))
                    .expect("QUIC key"),
            ),
            iv: self.expand(b"quic iv", 12).try_into().unwrap(),
            chacha: self.suite == 0x1303,
        }
    }
    fn header(&self) -> Header {
        let algorithm = match self.suite {
            0x1301 => &aead::quic::AES_128,
            0x1302 => &aead::quic::AES_256,
            _ => &aead::quic::CHACHA20,
        };
        Header(
            aead::quic::HeaderProtectionKey::new(
                algorithm,
                &self.expand(b"quic hp", if self.suite == 0x1301 { 16 } else { 32 }),
            )
            .expect("QUIC header key"),
        )
    }
}
fn keys(write: &Secret, read: &Secret) -> Keys {
    Keys {
        header: KeyPair {
            local: Box::new(write.header()),
            remote: Box::new(read.header()),
        },
        packet: KeyPair {
            local: Box::new(write.packet()),
            remote: Box::new(read.packet()),
        },
    }
}
fn initial(cid: &ConnectionId, side: Side) -> Keys {
    const SALT: [u8; 20] = [
        0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c,
        0xad, 0xcc, 0xbb, 0x7f, 0x0a,
    ];
    let (root, _) = hkdf::Hkdf::<sha2::Sha256>::extract(Some(&SALT), cid);
    let root = Secret {
        suite: 0x1301,
        bytes: root.to_vec(),
    };
    let client = Secret {
        suite: 0x1301,
        bytes: root.expand(b"client in", 32),
    };
    let server = Secret {
        suite: 0x1301,
        bytes: root.expand(b"server in", 32),
    };
    if side == Side::Client {
        keys(&client, &server)
    } else {
        keys(&server, &client)
    }
}
struct Header(aead::quic::HeaderProtectionKey);
impl Header {
    fn apply(&self, pn_offset: usize, packet: &mut [u8], decrypt: bool) {
        let mask = self
            .0
            .new_mask(&packet[pn_offset + 4..pn_offset + 20])
            .expect("QUIC sample");
        let length = if decrypt {
            packet[0] ^= mask[0] & if packet[0] & 0x80 != 0 { 0x0f } else { 0x1f };
            (packet[0] & 3) as usize + 1
        } else {
            let length = (packet[0] & 3) as usize + 1;
            packet[0] ^= mask[0] & if packet[0] & 0x80 != 0 { 0x0f } else { 0x1f };
            length
        };
        for i in 0..length {
            packet[pn_offset + i] ^= mask[i + 1];
        }
    }
}
impl HeaderKey for Header {
    fn decrypt(&self, offset: usize, packet: &mut [u8]) {
        self.apply(offset, packet, true)
    }
    fn encrypt(&self, offset: usize, packet: &mut [u8]) {
        self.apply(offset, packet, false)
    }
    fn sample_size(&self) -> usize {
        16
    }
}
struct Packet {
    key: aead::LessSafeKey,
    iv: [u8; 12],
    chacha: bool,
}
impl Packet {
    fn nonce(&self, number: u64) -> aead::Nonce {
        let mut nonce = self.iv;
        for (a, b) in nonce[4..].iter_mut().zip(number.to_be_bytes()) {
            *a ^= b;
        }
        aead::Nonce::assume_unique_for_key(nonce)
    }
}
impl PacketKey for Packet {
    fn encrypt(&self, number: u64, bytes: &mut [u8], header_length: usize) {
        let (header, payload) = bytes.split_at_mut(header_length);
        let len = payload.len() - 16;
        let (plain, tag) = payload.split_at_mut(len);
        let generated = self
            .key
            .seal_in_place_separate_tag(self.nonce(number), aead::Aad::from(header), plain)
            .expect("QUIC packet length");
        tag.copy_from_slice(generated.as_ref());
    }
    fn decrypt(
        &self,
        number: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        let len = self
            .key
            .open_in_place(self.nonce(number), aead::Aad::from(header), payload)
            .map_err(|_| CryptoError)?
            .len();
        payload.truncate(len);
        Ok(())
    }
    fn tag_len(&self) -> usize {
        16
    }
    fn confidentiality_limit(&self) -> u64 {
        if self.chacha {
            u64::MAX
        } else {
            1 << 23
        }
    }
    fn integrity_limit(&self) -> u64 {
        if self.chacha {
            1 << 36
        } else {
            1 << 52
        }
    }
}
fn retry_tag(cid: &ConnectionId, packet: &[u8]) -> [u8; 16] {
    const KEY: [u8; 16] = [
        0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8,
        0x4e,
    ];
    const NONCE: [u8; 12] = [
        0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
    ];
    let mut pseudo = vec![cid.len() as u8];
    pseudo.extend_from_slice(cid);
    pseudo.extend_from_slice(packet);
    let key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, &KEY).unwrap());
    key.seal_in_place_separate_tag(
        aead::Nonce::assume_unique_for_key(NONCE),
        aead::Aad::from(pseudo),
        &mut [],
    )
    .unwrap()
    .as_ref()
    .try_into()
    .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn chrome_parrot_emits_quic_hello_fields() {
        let options = super::super::tests::options();
        let mut options = options;
        options.alpn = vec!["h3".into()];
        let config = advanced_quic_client_config(&options, true).unwrap();
        let params = TransportParameters::read(
            Side::Server,
            &mut std::io::Cursor::new(&[15, 4, 1, 2, 3, 4]),
        )
        .unwrap();
        let mut session = config.start_session(1, "localhost", &params).unwrap();
        let mut hello = Vec::new();
        assert!(session.write_handshake(&mut hello).is_none());
        if let Ok(path) = std::env::var("KERLICO_QUIC_HELLO_CAPTURE") {
            std::fs::write(path, &hello).unwrap();
        }
        assert_eq!(hello[0], 1);
        assert_eq!(hello[38], 0, "QUIC has no compatibility session ID");
        let word = |position| u16::from_be_bytes([hello[position], hello[position + 1]]) as usize;
        assert_eq!(&hello[39..47], &[0, 6, 0x13, 1, 0x13, 2, 0x13, 3]);
        let mut position = 51;
        let mut extensions = std::collections::HashMap::new();
        while position < hello.len() {
            let id = word(position) as u16;
            let length = word(position + 2);
            assert!(extensions
                .insert(id, hello[position + 4..position + 4 + length].to_vec())
                .is_none());
            position += 4 + length;
        }
        let mut ids: Vec<_> = extensions.keys().copied().collect();
        ids.sort_unstable();
        assert_eq!(ids, [0, 10, 13, 16, 27, 43, 45, 51, 57, 17613, 65037]);
        assert_eq!(extensions[&10], [0, 8, 0x11, 0xec, 0, 29, 0, 23, 0, 24]);
        assert_eq!(
            extensions[&13],
            [0, 18, 4, 3, 8, 4, 4, 1, 5, 3, 8, 5, 5, 1, 8, 6, 6, 1, 2, 1]
        );
        assert_eq!(extensions[&16], [0, 3, 2, b'h', b'3']);
        assert_eq!(extensions[&17613], [0, 3, 2, b'h', b'3']);
        assert_eq!(extensions[&27], [2, 0, 2]);
        assert_eq!(extensions[&43], [2, 3, 4]);
        assert_eq!(extensions[&45], [1, 1]);
        let mut encoded_params = Vec::new();
        params.write(&mut encoded_params);
        assert_eq!(extensions[&57], encoded_params);
        let share = &extensions[&51];
        assert_eq!(&share[2..6], &[0x11, 0xec, 4, 0xc0]);
        assert_eq!(&share[1222..1226], &[0, 29, 0, 32]);
        assert_eq!(share.len(), 1258);
        let ech = &extensions[&65037];
        assert_eq!(&ech[..5], &[0, 0, 1, 0, 1]);
        assert_eq!(&ech[6..8], &[0, 32]);
        assert!([144, 176, 208, 240].contains(&u16::from_be_bytes([ech[40], ech[41]])));
    }

    #[test]
    fn quic_resumption_crosses_factory_calls_without_enabling_early_data() {
        for chrome_parrot in [false, true] {
            let mut options = super::super::tests::options();
            options.alpn = vec!["h3".into()];
            options.enable_session_resumption = true;
            let factory = super::super::AdvancedTlsClientCache::new();
            let server_config = advanced_quic_server_config(&options).unwrap();
            let params = TransportParameters::read(
                Side::Server,
                &mut std::io::Cursor::new(&[15, 4, 1, 2, 3, 4]),
            )
            .unwrap();
            for repeat in [false, true] {
                let mut client = factory
                    .quic(&options, chrome_parrot)
                    .unwrap()
                    .start_session(1, "localhost", &params)
                    .unwrap();
                let mut server = server_config.clone().start_session(1, &params);
                let mut server_flight = Vec::new();
                for _ in 0..20 {
                    let mut bytes = Vec::new();
                    client.write_handshake(&mut bytes);
                    if !bytes.is_empty() {
                        server.read_handshake(&bytes).unwrap();
                    }
                    let mut bytes = Vec::new();
                    server.write_handshake(&mut bytes);
                    if !bytes.is_empty() {
                        server_flight.extend_from_slice(&bytes);
                        client.read_handshake(&bytes).unwrap();
                    }
                }
                assert!(!client.is_handshaking() && !server.is_handshaking());
                assert!(client.early_crypto().is_none());
                assert_eq!(client.early_data_accepted(), Some(false));
                let mut position = 39 + server_flight[38] as usize + 3;
                let word =
                    |p| u16::from_be_bytes([server_flight[p], server_flight[p + 1]]) as usize;
                let end = position + 2 + word(position);
                position += 2;
                let mut resumed = false;
                while position < end {
                    resumed |= word(position) == 41;
                    position += 4 + word(position + 2);
                }
                assert_eq!(
                    resumed,
                    repeat && !chrome_parrot,
                    "ChromeParrot={chrome_parrot}"
                );
            }
        }
    }

    #[test]
    fn quinn_rustls_and_rama_interoperate_and_update_packet_keys() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        for (native_client, native_server, ech) in [
            (true, true, false),
            (true, false, false),
            (false, true, false),
            (true, true, true),
        ] {
            eprintln!("QUIC client native={native_client} server native={native_server} ECH={ech}");
            let mut options = if ech {
                super::super::tests::ech_options()
            } else {
                super::super::tests::options()
            };
            options.alpn = vec!["h3".into()];
            options.fingerprint = "chrome".into();
            let server_crypto: Arc<dyn crypto::ServerConfig> = if native_server {
                advanced_quic_server_config(&options).unwrap()
            } else {
                let config = crate::server_config(
                    &options.certificates[0].certificate,
                    &options.certificates[0].key,
                    &options.alpn,
                )
                .unwrap();
                Arc::new(crypto::rustls::QuicServerConfig::try_from(config).unwrap())
            };
            let client_crypto: Arc<dyn crypto::ClientConfig> = if native_client {
                advanced_quic_client_config(&options, true).unwrap()
            } else {
                Arc::new(
                    crypto::rustls::QuicClientConfig::try_from(
                        crate::client_config(&options.alpn, true).unwrap(),
                    )
                    .unwrap(),
                )
            };
            runtime.block_on(async move {
                tokio::time::timeout(Duration::from_secs(10), async move {
                    let server = quinn::Endpoint::server(
                        quinn::ServerConfig::with_crypto(server_crypto),
                        "127.0.0.1:0".parse().unwrap(),
                    )
                    .unwrap();
                    let address = server.local_addr().unwrap();
                    let server_task = tokio::spawn(async move {
                        server.accept().await.unwrap().retry().unwrap();
                        let connection = server.accept().await.unwrap().await.unwrap();
                        eprintln!("QUIC server accepted");
                        for expected in [b"before".as_slice(), b"after".as_slice()] {
                            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
                            let payload = recv.read_to_end(1024).await.unwrap();
                            assert_eq!(&payload, expected);
                            send.write_all(expected).await.unwrap();
                            send.finish().unwrap();
                            send.stopped().await.unwrap();
                        }
                        connection.closed().await;
                    });
                    let mut client =
                        quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
                    client.set_default_client_config(quinn::ClientConfig::new(client_crypto));
                    let connection = client.connect(address, "localhost").unwrap().await.unwrap();
                    eprintln!("QUIC client connected");
                    for payload in [b"before".as_slice(), b"after".as_slice()] {
                        let (mut send, mut recv) = connection.open_bi().await.unwrap();
                        send.write_all(payload).await.unwrap();
                        send.finish().unwrap();
                        assert_eq!(&recv.read_to_end(1024).await.unwrap(), payload);
                        connection.force_key_update();
                    }
                    connection.close(0u32.into(), b"done");
                    server_task.await.unwrap();
                    client.wait_idle().await;
                })
                .await
                .unwrap();
            });
        }
    }
}
