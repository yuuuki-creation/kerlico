//! TLS 1.3 handshake and records for REALITY.

use std::io::{self, Read, Write};
use std::sync::Arc;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, KeyInit, Nonce};
use chacha20poly1305::ChaCha20Poly1305;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use ml_dsa::{EncodedVerifyingKey, MlDsa65, Seed as DsaSeed, Signature as DsaSignature};
use ml_dsa::{
    Signer as _, SigningKey as DsaSigningKey, Verifier as _, VerifyingKey as DsaVerifyingKey,
};
use rcgen::{CertificateParams, CustomExtension, KeyPair, RemoteKeyPair};
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::encrypt::checked_x25519;
use crate::reality::{
    alpn_protocols, auth_key, authenticate_hello, b64, client_alpn, client_kem, client_share,
    client_suites, read_plain_handshake, u24, ClientKem, RealityPolicy,
};

#[path = "reality_target.rs"]
mod target;
pub use target::RealityTargetShape;
#[path = "reality_decoy.rs"]
mod decoy;
pub use decoy::RealityDecoyVerifier;

pub struct RealityClientFlight {
    pub read: Traffic,
    pub write: Traffic,
    pub finished: Vec<u8>,
    pub alpn: Option<Vec<u8>>,
}

pub type ServerFlight = (Traffic, Traffic, Vec<u8>, Option<Vec<u8>>);

pub enum RealityClientResult {
    Verified(RealityClientFlight),
    Decoy(RealityClientFlight),
}

impl RealityClientResult {
    fn verified(self) -> io::Result<ServerFlight> {
        match self {
            Self::Verified(flight) => Ok((flight.read, flight.write, flight.finished, flight.alpn)),
            Self::Decoy(_) => Err(invalid_record()),
        }
    }
}

#[derive(Clone)]
pub struct RealityMldsa65Signer(Arc<DsaSigningKey<MlDsa65>>);

impl RealityMldsa65Signer {
    pub fn verification_key(&self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.0.as_ref().as_ref().encode())
    }

    pub fn from_base64(text: &str) -> Option<Self> {
        let bytes = b64(text)?;
        let seed = DsaSeed::try_from(bytes.as_slice()).ok()?;
        Some(Self(Arc::new(DsaSigningKey::from_seed(&seed))))
    }

    fn sign(&self, message: &[u8]) -> io::Result<DsaSignature<MlDsa65>> {
        self.0.try_sign(message).map_err(|_| invalid_record())
    }
}

#[derive(Clone)]
pub struct RealityMldsa65Verifier(Arc<DsaVerifyingKey<MlDsa65>>);

impl RealityMldsa65Verifier {
    pub fn from_base64(text: &str) -> Option<Self> {
        let bytes = b64(text)?;
        let public = EncodedVerifyingKey::<MlDsa65>::try_from(bytes.as_slice()).ok()?;
        Some(Self(Arc::new(DsaVerifyingKey::decode(&public))))
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> Option<()> {
        self.0
            .verify(message, &DsaSignature::try_from(signature).ok()?)
            .ok()
    }
}

#[derive(Clone, Copy)]
#[repr(u16)]
enum Suite {
    Aes128 = 0x1301,
    Aes256 = 0x1302,
    ChaCha = 0x1303,
}

impl Suite {
    const PREFERENCE: [Self; 3] = [Self::Aes128, Self::Aes256, Self::ChaCha];

    fn id(self) -> [u8; 2] {
        (self as u16).to_be_bytes()
    }

    fn hash_len(self) -> usize {
        if matches!(self, Self::Aes256) {
            48
        } else {
            32
        }
    }

    fn transcript(self) -> Transcript {
        match self {
            Self::Aes256 => Transcript::Sha384(Sha384::new()),
            _ => Transcript::Sha256(Sha256::new()),
        }
    }
}

enum Transcript {
    Sha256(Sha256),
    Sha384(Sha384),
}

impl Transcript {
    fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Sha256(hash) => hash.update(bytes),
            Self::Sha384(hash) => hash.update(bytes),
        }
    }

    fn hash(&self) -> Vec<u8> {
        match self {
            Self::Sha256(hash) => hash.clone().finalize().to_vec(),
            Self::Sha384(hash) => hash.clone().finalize().to_vec(),
        }
    }
}

enum RecordCipher {
    Aes128(Box<Aes128Gcm>),
    Aes256(Box<Aes256Gcm>),
    ChaCha(ChaCha20Poly1305),
}

pub struct Traffic {
    cipher: RecordCipher,
    iv: [u8; 12],
}

pub struct ServerHello {
    pub flight: Vec<u8>,
    pub handshake: Traffic,
    pub expect: Vec<u8>,
    secret: Vec<u8>,
    transcript: Transcript,
    suite: Suite,
    alpn: Option<Vec<u8>>,
}

impl ServerHello {
    pub fn application_keys(&self) -> (Traffic, Traffic) {
        let hash = self.transcript.hash();
        let master = master_secret(self.suite, &self.secret);
        (
            traffic_keys(
                self.suite,
                &traffic_secret(self.suite, &master, "c ap traffic", &hash),
            ),
            traffic_keys(
                self.suite,
                &traffic_secret(self.suite, &master, "s ap traffic", &hash),
            ),
        )
    }

    pub fn alpn(&self) -> Option<&[u8]> {
        self.alpn.as_deref()
    }
}

pub struct AppReader<S> {
    inner: S,
    traffic: Traffic,
    seq: u64,
    pending: Vec<u8>,
    wire: Vec<u8>,
    direct: bool,
    closed: bool,
}

pub struct AppWriter<S> {
    inner: S,
    traffic: Traffic,
    seq: u64,
    wire: Vec<u8>,
    sent: usize,
    accepted: usize,
    direct: bool,
}

struct EdRemote {
    signing: SigningKey,
    public: [u8; 32],
}

impl RemoteKeyPair for EdRemote {
    fn public_key(&self) -> &[u8] {
        &self.public
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        Ok(self.signing.sign(msg).to_bytes().to_vec())
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ED25519
    }
}

pub fn server_flight(
    record: &[u8],
    private: &[u8; 32],
    short_id: &[u8; 8],
) -> std::io::Result<ServerHello> {
    server_flight_with_alpn(record, private, short_id, &[] as &[&str])
}

pub fn server_flight_with_alpn<P: AsRef<str>>(
    record: &[u8],
    private: &[u8; 32],
    short_id: &[u8; 8],
    protocols: &[P],
) -> io::Result<ServerHello> {
    server_flight_with_auth(
        record,
        private,
        &RealityPolicy::single_id(*short_id),
        protocols,
        None,
    )
}

pub fn server_flight_with_auth<P: AsRef<str>>(
    record: &[u8],
    private: &[u8; 32],
    policy: &RealityPolicy,
    protocols: &[P],
    proof: Option<&RealityMldsa65Signer>,
) -> io::Result<ServerHello> {
    server_flight_impl(record, private, policy, protocols, proof, None)
}

pub fn server_flight_with_target<P: AsRef<str>>(
    record: &[u8],
    private: &[u8; 32],
    policy: &RealityPolicy,
    protocols: &[P],
    proof: Option<&RealityMldsa65Signer>,
    target: &RealityTargetShape,
) -> io::Result<ServerHello> {
    server_flight_impl(record, private, policy, protocols, proof, Some(target))
}

fn server_flight_impl<P: AsRef<str>>(
    record: &[u8],
    private: &[u8; 32],
    policy: &RealityPolicy,
    protocols: &[P],
    proof: Option<&RealityMldsa65Signer>,
    target: Option<&RealityTargetShape>,
) -> io::Result<ServerHello> {
    let (hello, auth) = authenticate_hello(record, private, policy).ok_or_else(invalid_record)?;
    let offered_suites = client_suites(hello).ok_or_else(invalid_record)?;
    let suite = target
        .map(|target| target.suite)
        .or_else(|| {
            Suite::PREFERENCE
                .into_iter()
                .find(|suite| offered_suites.as_chunks::<2>().0.contains(&suite.id()))
        })
        .ok_or_else(invalid_record)?;
    if !offered_suites.as_chunks::<2>().0.contains(&suite.id()) {
        return Err(invalid_record());
    }
    let offered_alpn = client_alpn(hello).ok_or_else(invalid_record)?;
    let alpn = protocols
        .iter()
        .map(|p| p.as_ref().as_bytes())
        .find(|p| offered_alpn.contains(p));
    if !protocols.is_empty() && !offered_alpn.is_empty() && alpn.is_none() {
        return Err(invalid_record());
    }
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|error| std::io::Error::other(error.to_string()))?;
    let signing = SigningKey::from_bytes(&seed);
    let kem = match target {
        Some(target) => crate::reality::client_kem_for_group(hello, target.group),
        None => client_kem(hello),
    }
    .ok_or_else(|| std::io::Error::other("reality"))?;
    let (group, server_share, shared) = match kem {
        ClientKem::X25519(public) => {
            let eph = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
            let eph_public = x25519_dalek::PublicKey::from(&eph);
            let shared = checked_x25519(&eph, &x25519_dalek::PublicKey::from(public))
                .ok_or_else(invalid_record)?
                .to_vec();
            (0x001du16, eph_public.to_bytes().to_vec(), shared)
        }
        ClientKem::Hybrid { kem, x25519 } => {
            let (mlkem, cipher) = encapsulate(&kem)?;
            let eph = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
            let eph_public = x25519_dalek::PublicKey::from(&eph);
            let x25519 = checked_x25519(&eph, &x25519_dalek::PublicKey::from(x25519))
                .ok_or_else(invalid_record)?;
            let mut share = cipher;
            share.extend_from_slice(&eph_public.to_bytes());
            let mut shared = mlkem;
            shared.extend_from_slice(&x25519);
            (0x11ec, share, shared)
        }
    };
    let server_hello = match target {
        Some(target) => target.replace_share(&hello[39..71], &server_share)?,
        None => server_hello(&hello[39..71], group, &server_share, suite)?,
    };
    let mut transcript = suite.transcript();
    transcript.update(hello);
    transcript.update(&server_hello);
    let handshake_secret = handshake_secret(suite, &shared);
    let hs_hash = transcript.hash();
    let server_hs = traffic_secret(suite, &handshake_secret, "s hs traffic", &hs_hash);
    let client_hs = traffic_secret(suite, &handshake_secret, "c hs traffic", &hs_hash);
    let cert = hmac_cert(&signing, &auth, hello, &server_hello, proof)?;
    let extensions = encrypted_extensions(alpn);
    let certificate = handshake_msg(0x0b, &cert_message(&cert));
    transcript.update(&extensions);
    transcript.update(&certificate);
    let certificate_verify = handshake_msg(0x0f, &verify_message(&signing, &transcript.hash()));
    transcript.update(&certificate_verify);
    let finished = handshake_msg(
        0x14,
        &finished_verify(suite, &server_hs, &transcript.hash()),
    );
    transcript.update(&finished);
    let expect = finished_verify(suite, &client_hs, &transcript.hash());
    let mut body = Vec::new();
    body.extend_from_slice(&extensions);
    body.extend_from_slice(&certificate);
    body.extend_from_slice(&certificate_verify);
    body.extend_from_slice(&finished);
    let mut flight = wrap_handshake(&server_hello);
    flight.extend_from_slice(&[20, 3, 3, 0, 1, 1]);
    let traffic = traffic_keys(suite, &server_hs);
    if let Some(target) = target {
        flight.extend(target.seal_messages(
            &traffic,
            &[extensions, certificate, certificate_verify, finished],
        )?);
    } else {
        flight.extend(seal_record(&traffic, 0, 22, &body));
    }
    Ok(ServerHello {
        flight,
        handshake: traffic_keys(suite, &client_hs),
        expect,
        secret: handshake_secret,
        transcript,
        suite,
        alpn: alpn.map(<[u8]>::to_vec),
    })
}

pub fn read_client_finished<R: Read>(
    reader: &mut R,
    handshake: &Traffic,
    expect: &[u8],
) -> std::io::Result<Vec<u8>> {
    let mut records = HandshakeRecords::new(reader, handshake);
    let finished = records.next(0x14)?;
    if !equal_finished(expect, &finished[4..]) || !records.pending.is_empty() {
        return Err(invalid_record());
    }
    Ok(finished)
}

pub fn client_keys(
    record: &[u8],
    flight: &[u8],
    client_secret: &[u8; 32],
    kem_secret: Option<&[u8]>,
    server_public: &[u8; 32],
) -> std::io::Result<(Traffic, Traffic, Vec<u8>)> {
    read_server_flight(
        &mut &flight[..],
        record,
        client_secret,
        kem_secret,
        server_public,
    )
}

pub fn read_server_flight<R: Read>(
    reader: &mut R,
    record: &[u8],
    client_secret: &[u8; 32],
    kem_secret: Option<&[u8]>,
    server_public: &[u8; 32],
) -> io::Result<(Traffic, Traffic, Vec<u8>)> {
    read_server_flight_with_alpn(reader, record, client_secret, kem_secret, server_public)
        .map(|(read, write, finished, _)| (read, write, finished))
}

pub fn read_server_flight_with_alpn<R: Read>(
    reader: &mut R,
    record: &[u8],
    client_secret: &[u8; 32],
    kem_secret: Option<&[u8]>,
    server_public: &[u8; 32],
) -> io::Result<ServerFlight> {
    read_server_flight_with_auth(
        reader,
        record,
        client_secret,
        kem_secret,
        server_public,
        None,
    )
}

pub fn read_server_flight_with_auth<R: Read>(
    reader: &mut R,
    record: &[u8],
    client_secret: &[u8; 32],
    kem_secret: Option<&[u8]>,
    server_public: &[u8; 32],
    proof: Option<&RealityMldsa65Verifier>,
) -> io::Result<ServerFlight> {
    read_server_flight_impl(
        reader,
        record,
        client_secret,
        server_public,
        proof,
        None,
        |group, share| traffic_shared(client_secret, kem_secret, group, share),
    )
    .and_then(RealityClientResult::verified)
}

pub fn read_server_flight_for_offer<R: Read>(
    reader: &mut R,
    offer: &crate::reality::RealityOffer,
    server_public: &[u8; 32],
    proof: Option<&RealityMldsa65Verifier>,
) -> io::Result<ServerFlight> {
    read_server_flight_impl(
        reader,
        &offer.record,
        &offer.x25519,
        server_public,
        proof,
        None,
        |group, share| offer.shared(group, share),
    )
    .and_then(RealityClientResult::verified)
}

pub fn read_server_flight_or_decoy<R: Read>(
    reader: &mut R,
    offer: &crate::reality::RealityOffer,
    server_public: &[u8; 32],
    proof: Option<&RealityMldsa65Verifier>,
    verifier: &RealityDecoyVerifier,
    name: &str,
) -> io::Result<RealityClientResult> {
    read_server_flight_impl(
        reader,
        &offer.record,
        &offer.x25519,
        server_public,
        proof,
        Some((verifier, name)),
        |group, share| offer.shared(group, share),
    )
}

fn read_server_flight_impl<R: Read>(
    reader: &mut R,
    record: &[u8],
    client_secret: &[u8; 32],
    server_public: &[u8; 32],
    proof: Option<&RealityMldsa65Verifier>,
    decoy: Option<(&RealityDecoyVerifier, &str)>,
    shared: impl FnOnce(u16, &[u8]) -> io::Result<Vec<u8>>,
) -> io::Result<RealityClientResult> {
    let hello = record
        .get(5..)
        .filter(|hello| client_share(hello).is_some())
        .ok_or_else(invalid_record)?;
    let (server_hello, _) = read_plain_handshake(reader, 2)
        .map_err(|error| io::Error::new(error.kind(), format!("REALITY ServerHello: {error}")))?;
    let (suite, group, share) =
        server_share(&server_hello, &hello[39..71]).ok_or_else(invalid_record)?;
    if !client_suites(hello)
        .ok_or_else(invalid_record)?
        .as_chunks::<2>()
        .0
        .contains(&suite.id())
    {
        return Err(invalid_record());
    }
    let shared = shared(group, share)?;
    let mut transcript = suite.transcript();
    transcript.update(hello);
    transcript.update(&server_hello);
    let handshake_secret = handshake_secret(suite, &shared);
    let hs_hash = transcript.hash();
    let server_hs = traffic_secret(suite, &handshake_secret, "s hs traffic", &hs_hash);
    let client_hs = traffic_secret(suite, &handshake_secret, "c hs traffic", &hs_hash);
    let traffic = traffic_keys(suite, &server_hs);
    let mut records = HandshakeRecords::new(reader, &traffic);
    let extensions = records.next(8).map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("REALITY EncryptedExtensions: {error}"),
        )
    })?;
    let alpn = selected_alpn(
        &extensions[4..],
        &client_alpn(hello).ok_or_else(invalid_record)?,
    )?;
    transcript.update(&extensions);
    let cert = records
        .next_any(&[0x0b, 0x19])
        .map_err(|error| io::Error::new(error.kind(), format!("REALITY Certificate: {error}")))?;
    let certificate = if cert[0] == 0x19 {
        decompress_certificate(&cert[4..])?
    } else {
        cert[4..].to_vec()
    };
    let der = cert_der(&certificate).ok_or_else(invalid_record)?;
    let auth = reality_auth_client(client_secret, server_public, &hello[6..38])?;
    let public = cert_hmac(der, &auth, hello, &server_hello, proof);
    let decoy_key = if public.is_none() {
        let (verifier, name) = decoy.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "REALITY certificate authentication failed",
            )
        })?;
        Some(verifier.verify(&certificate, name)?)
    } else {
        None
    };
    transcript.update(&cert);
    let verify = records.next(0x0f)?;
    match (&public, &decoy_key) {
        (Some(public), _) => verify_certificate(public, &transcript.hash(), &verify[4..]),
        (_, Some(public)) => {
            decoy::verify_signature(public, &transcript.hash(), &verify[4..], hello)
        }
        _ => unreachable!(),
    }
    .map_err(|error| io::Error::new(error.kind(), format!("REALITY CertificateVerify: {error}")))?;
    transcript.update(&verify);
    let finished = records.next(0x14)?;
    let expect = finished_verify(suite, &server_hs, &transcript.hash());
    if !equal_finished(&expect, &finished[4..]) || !records.pending.is_empty() {
        return Err(invalid_record());
    }
    transcript.update(&finished);
    let app_hash = transcript.hash();
    let finished = handshake_msg(0x14, &finished_verify(suite, &client_hs, &app_hash));
    let master = master_secret(suite, &handshake_secret);
    let sealed = seal_record(&traffic_keys(suite, &client_hs), 0, 22, &finished);
    let flight = RealityClientFlight {
        read: traffic_keys(
            suite,
            &traffic_secret(suite, &master, "s ap traffic", &app_hash),
        ),
        write: traffic_keys(
            suite,
            &traffic_secret(suite, &master, "c ap traffic", &app_hash),
        ),
        finished: sealed,
        alpn: alpn.map(<[u8]>::to_vec),
    };
    Ok(if public.is_some() {
        RealityClientResult::Verified(flight)
    } else {
        RealityClientResult::Decoy(flight)
    })
}

fn encrypted_extensions(alpn: Option<&[u8]>) -> Vec<u8> {
    let mut body = vec![0, 0];
    if let Some(protocol) = alpn {
        body[..2].copy_from_slice(&((7 + protocol.len()) as u16).to_be_bytes());
        body.extend_from_slice(&0x0010u16.to_be_bytes());
        body.extend_from_slice(&((3 + protocol.len()) as u16).to_be_bytes());
        body.extend_from_slice(&((1 + protocol.len()) as u16).to_be_bytes());
        body.push(protocol.len() as u8);
        body.extend_from_slice(protocol);
    }
    handshake_msg(8, &body)
}

fn decompress_certificate(body: &[u8]) -> io::Result<Vec<u8>> {
    if body.len() < 8 {
        return Err(invalid_record());
    }
    let algorithm = u16::from_be_bytes([body[0], body[1]]);
    let length = u24(&body[2..5]);
    let compressed = u24(&body[5..8]);
    if length > 1_048_576 || compressed != body.len() - 8 {
        return Err(invalid_record());
    }
    let mut output = Vec::with_capacity(length);
    let reader: Box<dyn Read + '_> = match algorithm {
        1 => Box::new(flate2::read::ZlibDecoder::new(&body[8..])),
        2 => Box::new(brotli::Decompressor::new(&body[8..], 4096)),
        3 => Box::new(zstd::stream::read::Decoder::new(&body[8..])?),
        _ => return Err(invalid_record()),
    };
    reader.take(length as u64 + 1).read_to_end(&mut output)?;
    if output.len() != length {
        return Err(invalid_record());
    }
    Ok(output)
}

fn selected_alpn<'a>(extensions: &'a [u8], offered: &[&[u8]]) -> io::Result<Option<&'a [u8]>> {
    let len = u16::from_be_bytes(
        extensions
            .get(..2)
            .ok_or_else(invalid_record)?
            .try_into()
            .unwrap(),
    ) as usize;
    let mut extensions = &extensions[2..];
    if extensions.len() != len {
        return Err(invalid_record());
    }
    let mut selected = None;
    while !extensions.is_empty() {
        let head = extensions.get(..4).ok_or_else(invalid_record)?;
        let kind = u16::from_be_bytes([head[0], head[1]]);
        let len = u16::from_be_bytes([head[2], head[3]]) as usize;
        let (body, rest) = extensions[4..]
            .split_at_checked(len)
            .ok_or_else(invalid_record)?;
        if kind == 0x0010 {
            let protocols = alpn_protocols(body).ok_or_else(invalid_record)?;
            if selected.is_some() || protocols.len() != 1 || !offered.contains(&protocols[0]) {
                return Err(invalid_record());
            }
            selected = Some(protocols[0]);
        }
        extensions = rest;
    }
    Ok(selected)
}

struct HandshakeRecords<'a, R> {
    reader: &'a mut R,
    traffic: &'a Traffic,
    seq: u64,
    pending: Vec<u8>,
    saw_ccs: bool,
}

impl<'a, R: Read> HandshakeRecords<'a, R> {
    fn new(reader: &'a mut R, traffic: &'a Traffic) -> Self {
        Self {
            reader,
            traffic,
            seq: 0,
            pending: Vec::new(),
            saw_ccs: false,
        }
    }

    fn next(&mut self, kind: u8) -> io::Result<Vec<u8>> {
        self.next_any(&[kind])
    }

    fn next_any(&mut self, kinds: &[u8]) -> io::Result<Vec<u8>> {
        loop {
            if self.pending.first().is_some_and(|got| !kinds.contains(got)) {
                return Err(invalid_record());
            }
            if self.pending.len() >= 4 {
                let len = u24(&self.pending[1..4]) + 4;
                if len > 1_048_576 {
                    return Err(invalid_record());
                }
                if self.pending.len() >= len {
                    return Ok(self.pending.drain(..len).collect());
                }
            }
            let record = read_outer(self.reader)?;
            if record == [20, 3, 3, 0, 1, 1] && !self.saw_ccs {
                self.saw_ccs = true;
                continue;
            }
            let plain = open_record(self.traffic, self.seq, &record).ok_or_else(invalid_record)?;
            self.seq += 1;
            let (inner, messages) = split_inner(&plain).ok_or_else(invalid_record)?;
            if inner != 22 || messages.is_empty() {
                return Err(invalid_record());
            }
            self.pending.extend_from_slice(messages);
        }
    }
}

impl<S: Read> Read for AppReader<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        while self.pending.is_empty() {
            if self.closed {
                return Ok(0);
            }
            if self.direct {
                return self.inner.read(buf);
            }
            if !read_outer_into(&mut self.inner, &mut self.wire)? {
                return Ok(0);
            }
            let plain =
                open_record(&self.traffic, self.seq, &self.wire).ok_or_else(invalid_record)?;
            self.wire.clear();
            self.seq += 1;
            let (kind, body) = split_inner(&plain).ok_or_else(invalid_record)?;
            match (kind, body) {
                (23, _) => self.pending.extend_from_slice(body),
                (21, [_, 0]) => self.closed = true,
                (22, [4, ..]) if body.len() >= 4 && u24(&body[1..4]) + 4 == body.len() => {}
                _ => return Err(invalid_record()),
            }
        }
        let n = self.pending.len().min(buf.len());
        buf[..n].copy_from_slice(&self.pending[..n]);
        self.pending.drain(..n);
        Ok(n)
    }
}

impl<S: Write> Write for AppWriter<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.direct {
            return self.inner.write(buf);
        }
        if self.wire.is_empty() {
            self.accepted = buf.len().min(16384);
            self.wire = seal_record(&self.traffic, self.seq, 23, &buf[..self.accepted]);
            self.seq += 1;
            self.sent = 0;
        }
        self.flush_record()?;
        self.wire.clear();
        Ok(self.accepted)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.flush_record()?;
        self.inner.flush()
    }
}

impl<S> AppReader<S> {
    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    pub fn start_direct(&mut self) -> io::Result<()> {
        if !self.wire.is_empty() || self.closed {
            return Err(invalid_record());
        }
        self.direct = true;
        Ok(())
    }
}

impl<S> AppWriter<S> {
    pub fn inner_mut(&mut self) -> &mut S {
        &mut self.inner
    }
}

impl<S: Write> AppWriter<S> {
    pub fn start_direct(&mut self) -> io::Result<()> {
        self.flush()?;
        self.direct = true;
        Ok(())
    }

    fn flush_record(&mut self) -> io::Result<()> {
        while self.sent < self.wire.len() {
            match self.inner.write(&self.wire[self.sent..]) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => self.sent += n,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(err),
            }
        }
        Ok(())
    }
}

pub fn reader<S>(inner: S, traffic: Traffic) -> AppReader<S> {
    AppReader {
        inner,
        traffic,
        seq: 0,
        pending: Vec::new(),
        wire: Vec::new(),
        direct: false,
        closed: false,
    }
}

pub fn writer<S>(inner: S, traffic: Traffic) -> AppWriter<S> {
    AppWriter {
        inner,
        traffic,
        seq: 0,
        wire: Vec::new(),
        sent: 0,
        accepted: 0,
        direct: false,
    }
}

pub struct RealityDuplex<R, W> {
    reader: R,
    writer: W,
}

impl<R, W> RealityDuplex<R, W> {
    pub fn new(reader: R, writer: W) -> Self {
        Self { reader, writer }
    }

    pub fn into_halves(self) -> (R, W) {
        (self.reader, self.writer)
    }
}

impl<R: Read, W> Read for RealityDuplex<R, W> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.reader.read(buf)
    }
}

impl<R, W: Write> Write for RealityDuplex<R, W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.writer.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.writer.flush()
    }
}

impl RealityDuplex<AppReader<std::net::TcpStream>, AppWriter<std::net::TcpStream>> {
    pub fn set_timeout(&mut self, timeout: std::time::Duration) {
        self.reader.set_timeout(timeout);
        self.writer.set_timeout(timeout);
    }
}

impl AppReader<std::net::TcpStream> {
    pub fn set_timeout(&mut self, timeout: std::time::Duration) {
        self.inner.set_read_timeout(Some(timeout)).ok();
        self.inner.set_write_timeout(Some(timeout)).ok();
    }
}

impl AppWriter<std::net::TcpStream> {
    pub fn set_timeout(&mut self, timeout: std::time::Duration) {
        self.inner.set_read_timeout(Some(timeout)).ok();
        self.inner.set_write_timeout(Some(timeout)).ok();
    }
}

pub fn take_flight<R: Read>(reader: &mut R) -> std::io::Result<Vec<u8>> {
    let (_, mut flight) = read_plain_handshake(reader, 2)?;
    let record = read_outer(reader)?;
    flight.extend_from_slice(&record);
    if record[0] == 20 {
        flight.extend_from_slice(&read_outer(reader)?);
    }
    Ok(flight)
}

fn reality_auth_client(
    secret: &[u8; 32],
    server_public: &[u8; 32],
    random: &[u8],
) -> std::io::Result<[u8; 32]> {
    let secret = x25519_dalek::StaticSecret::from(*secret);
    let shared = checked_x25519(&secret, &x25519_dalek::PublicKey::from(*server_public))
        .ok_or_else(invalid_record)?;
    let mut random_bytes = [0u8; 32];
    random_bytes.copy_from_slice(random);
    Ok(auth_key(&shared, &random_bytes))
}

fn hmac_cert(
    signing: &SigningKey,
    auth: &[u8; 32],
    client_hello: &[u8],
    server_hello: &[u8],
    proof: Option<&RealityMldsa65Signer>,
) -> io::Result<Vec<u8>> {
    let public = signing.verifying_key().to_bytes();
    let remote = EdRemote {
        signing: signing.clone(),
        public,
    };
    let key = KeyPair::from_remote(Box::new(remote))
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(auth).expect("hmac key");
    mac.update(&public);
    let signature = mac.clone().finalize().into_bytes();
    let mut params =
        CertificateParams::new(vec!["reality".to_string()]).map_err(io::Error::other)?;
    if let Some(proof) = proof {
        let message = mldsa_message(mac, client_hello, server_hello);
        let proof = proof.sign(&message)?.encode();
        // Xray reads the first extension's value. Its verifier does not inspect the OID.
        const ML_DSA_65_OID: &[u64] = &[2, 16, 840, 1, 101, 3, 4, 3, 18];
        params.subject_alt_names.clear();
        params
            .custom_extensions
            .push(CustomExtension::from_oid_content(
                ML_DSA_65_OID,
                proof.to_vec(),
            ));
    }
    let cert = params
        .self_signed(&key)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let mut der = cert.der().to_vec();
    let start = der.len() - 64;
    der[start..].copy_from_slice(&signature);
    Ok(der)
}

fn cert_hmac(
    der: &[u8],
    auth: &[u8; 32],
    client_hello: &[u8],
    server_hello: &[u8],
    proof: Option<&RealityMldsa65Verifier>,
) -> Option<VerifyingKey> {
    const ED25519_SPKI_PREFIX: &[u8] = &[
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    let cert = rustls::pki_types::CertificateDer::from(der);
    let cert = rustls::server::ParsedCertificate::try_from(&cert).ok()?;
    let spki = cert.subject_public_key_info();
    let public: [u8; 32] = spki
        .as_ref()
        .strip_prefix(ED25519_SPKI_PREFIX)?
        .try_into()
        .ok()?;
    let (tbs, signature) = certificate_fields(der)?;
    let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(auth).expect("hmac");
    mac.update(&public);
    mac.clone().verify_slice(signature).ok()?;
    if let Some(proof) = proof {
        let message = mldsa_message(mac, client_hello, server_hello);
        proof.verify(&message, first_certificate_extension(tbs)?)?;
    }
    VerifyingKey::from_bytes(&public).ok()
}

fn mldsa_message(mut mac: Hmac<Sha512>, client_hello: &[u8], server_hello: &[u8]) -> [u8; 64] {
    mac.update(client_hello);
    mac.update(server_hello);
    mac.finalize().into_bytes().into()
}

fn certificate_fields(mut der: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut cert = der_field(&mut der, 0x30)?;
    if !der.is_empty() {
        return None;
    }
    let tbs = der_field(&mut cert, 0x30)?;
    if der_field(&mut cert, 0x30)? != [0x06, 0x03, 0x2b, 0x65, 0x70] {
        return None;
    }
    let signature = der_field(&mut cert, 0x03)?.strip_prefix(&[0])?;
    (cert.is_empty() && signature.len() == 64).then_some((tbs, signature))
}

fn first_certificate_extension(mut tbs: &[u8]) -> Option<&[u8]> {
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
    let mut tagged_extensions = der_field(&mut tbs, 0xa3)?;
    let mut extensions = der_field(&mut tagged_extensions, 0x30)?;
    let mut first = der_field(&mut extensions, 0x30)?;
    der_field(&mut first, 0x06)?;
    if first.first() == Some(&0x01) {
        der_field(&mut first, 0x01)?;
    }
    let value = der_field(&mut first, 0x04)?;
    first.is_empty().then_some(value)
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
        let mut length = 0usize;
        for byte in der.get(2..2 + width)? {
            length = (length << 8) | *byte as usize;
        }
        if length < 128 {
            return None;
        }
        (length, 2 + width)
    };
    let (field, rest) = der.get(start..)?.split_at_checked(len)?;
    *der = rest;
    Some(field)
}

fn server_hello(session: &[u8], group: u16, share: &[u8], suite: Suite) -> io::Result<Vec<u8>> {
    let mut random = [0u8; 32];
    getrandom::getrandom(&mut random).map_err(|e| io::Error::other(e.to_string()))?;
    let mut body = Vec::new();
    body.extend_from_slice(&[3, 3]);
    body.extend_from_slice(&random);
    body.push(32);
    body.extend_from_slice(session);
    body.extend_from_slice(&suite.id());
    body.push(0);
    let mut ext = Vec::new();
    ext.extend_from_slice(&0x002bu16.to_be_bytes());
    ext.extend_from_slice(&2u16.to_be_bytes());
    ext.extend_from_slice(&[3, 4]);
    ext.extend_from_slice(&0x0033u16.to_be_bytes());
    ext.extend_from_slice(&((4 + share.len()) as u16).to_be_bytes());
    ext.extend_from_slice(&group.to_be_bytes());
    ext.extend_from_slice(&(share.len() as u16).to_be_bytes());
    ext.extend_from_slice(share);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);
    Ok(handshake_msg(2, &body))
}

fn handshake_msg(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(kind);
    let len = body.len() as u32;
    out.push((len >> 16) as u8);
    out.push((len >> 8) as u8);
    out.push(len as u8);
    out.extend_from_slice(body);
    out
}

fn wrap_handshake(handshake: &[u8]) -> Vec<u8> {
    let mut out = vec![22, 3, 3];
    out.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    out.extend_from_slice(handshake);
    out
}

fn cert_message(der: &[u8]) -> Vec<u8> {
    let mut body = vec![0];
    let list_len = (3 + der.len() + 2) as u32;
    body.push((list_len >> 16) as u8);
    body.push((list_len >> 8) as u8);
    body.push(list_len as u8);
    let cert_len = der.len() as u32;
    body.push((cert_len >> 16) as u8);
    body.push((cert_len >> 8) as u8);
    body.push(cert_len as u8);
    body.extend_from_slice(der);
    body.extend_from_slice(&[0, 0]);
    body
}

fn verify_message(signing: &SigningKey, transcript: &[u8]) -> Vec<u8> {
    let mut body = vec![8, 7, 0, 64];
    body.extend_from_slice(
        &signing
            .sign(&certificate_verify_input(transcript))
            .to_bytes(),
    );
    body
}

fn certificate_verify_input(transcript: &[u8]) -> Vec<u8> {
    let mut content = vec![0x20; 64];
    content.extend_from_slice(b"TLS 1.3, server CertificateVerify\0");
    content.extend_from_slice(transcript);
    content
}

fn verify_certificate(public: &VerifyingKey, transcript: &[u8], body: &[u8]) -> io::Result<()> {
    let signature = body
        .strip_prefix(&[8, 7, 0, 64])
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(invalid_record)?;
    public
        .verify_strict(
            &certificate_verify_input(transcript),
            &Signature::from_bytes(signature),
        )
        .map_err(|_| invalid_record())
}

fn finished_verify(suite: Suite, secret: &[u8], transcript: &[u8]) -> Vec<u8> {
    let key = expand_label(suite, secret, "finished", &[], suite.hash_len());
    match suite {
        Suite::Aes256 => {
            let mut mac = <Hmac<Sha384> as Mac>::new_from_slice(&key).expect("hmac");
            mac.update(transcript);
            mac.finalize().into_bytes().to_vec()
        }
        _ => {
            let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key).expect("hmac");
            mac.update(transcript);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

fn equal_finished(expected: &[u8], received: &[u8]) -> bool {
    expected.len() == received.len()
        && expected
            .iter()
            .zip(received)
            .fold(0, |diff, (a, b)| diff | (a ^ b))
            == 0
}

fn server_share<'a>(handshake: &'a [u8], session: &[u8]) -> Option<(Suite, u16, &'a [u8])> {
    if handshake.len() < 76
        || handshake[4..6] != [3, 3]
        || handshake[38] != 32
        || &handshake[39..71] != session
        || handshake[73] != 0
    {
        return None;
    }
    let suite = Suite::PREFERENCE
        .into_iter()
        .find(|suite| handshake[71..73] == suite.id())?;
    let ext_len = u16::from_be_bytes([handshake[74], handshake[75]]) as usize;
    let mut index = 76;
    let end = index + ext_len;
    if end != handshake.len() {
        return None;
    }
    let mut share = None;
    let mut version = false;
    while index + 4 <= end {
        let kind = u16::from_be_bytes([handshake[index], handshake[index + 1]]);
        let len = u16::from_be_bytes([handshake[index + 2], handshake[index + 3]]) as usize;
        index += 4;
        let ext = handshake.get(index..index + len)?;
        match kind {
            0x0033 if share.is_none() && ext.len() >= 4 => {
                let group = u16::from_be_bytes([ext[0], ext[1]]);
                let key_len = u16::from_be_bytes([ext[2], ext[3]]) as usize;
                if 4 + key_len != ext.len() {
                    return None;
                }
                share = Some((suite, group, &ext[4..]));
            }
            0x002b if !version && ext == [3, 4] => version = true,
            _ => return None,
        }
        index += len;
    }
    if version && index == end {
        share
    } else {
        None
    }
}

pub(crate) fn traffic_shared(
    client_secret: &[u8; 32],
    kem_secret: Option<&[u8]>,
    group: u16,
    key: &[u8],
) -> std::io::Result<Vec<u8>> {
    let secret = x25519_dalek::StaticSecret::from(*client_secret);
    if group == 0x001d && key.len() == 32 {
        let mut raw = [0u8; 32];
        raw.copy_from_slice(key);
        return checked_x25519(&secret, &x25519_dalek::PublicKey::from(raw))
            .map(|shared| shared.to_vec())
            .ok_or_else(invalid_record);
    }
    if group == 0x11ec && key.len() == 1120 {
        let kem = kem_secret.ok_or_else(|| std::io::Error::other("reality"))?;
        let mlkem = decapsulate(kem, &key[..1088])?;
        let mut raw = [0u8; 32];
        raw.copy_from_slice(&key[1088..]);
        let x25519 = checked_x25519(&secret, &x25519_dalek::PublicKey::from(raw))
            .ok_or_else(invalid_record)?;
        let mut shared = mlkem;
        shared.extend_from_slice(&x25519);
        return Ok(shared);
    }
    Err(std::io::Error::other("share"))
}

fn encapsulate(public: &[u8]) -> std::io::Result<(Vec<u8>, Vec<u8>)> {
    use ml_kem::kem::Encapsulate;
    use ml_kem::{EncodedSizeUser, KemCore};
    type Public = <ml_kem::MlKem768 as KemCore>::EncapsulationKey;
    let encoded = ml_kem::Encoded::<Public>::try_from(public)
        .map_err(|_| std::io::Error::other("reality"))?;
    let key = Public::from_bytes(&encoded);
    let (cipher, shared) = key
        .encapsulate(&mut rand_core::OsRng)
        .map_err(|_| std::io::Error::other("reality"))?;
    Ok((shared.to_vec(), cipher.to_vec()))
}

fn decapsulate(secret: &[u8], cipher: &[u8]) -> std::io::Result<Vec<u8>> {
    use ml_kem::kem::Decapsulate;
    use ml_kem::{EncodedSizeUser, KemCore};
    type Secret = <ml_kem::MlKem768 as KemCore>::DecapsulationKey;
    type Cipher = ml_kem::Ciphertext<ml_kem::MlKem768>;
    let encoded = ml_kem::Encoded::<Secret>::try_from(secret)
        .map_err(|_| std::io::Error::other("reality"))?;
    let secret = Secret::from_bytes(&encoded);
    let encoded_cipher = Cipher::try_from(cipher).map_err(|_| std::io::Error::other("reality"))?;
    let shared = secret
        .decapsulate(&encoded_cipher)
        .map_err(|_| std::io::Error::other("reality"))?;
    Ok(shared.to_vec())
}

fn cert_der(body: &[u8]) -> Option<&[u8]> {
    if body.len() < 7 || body[0] != 0 || u24(&body[1..4]) + 4 != body.len() {
        return None;
    }
    let first = body.get(7..7 + u24(&body[4..7]))?;
    let mut entries = &body[4..];
    while !entries.is_empty() {
        let cert_end = 3 + u24(entries.get(..3)?);
        let ext = entries.get(cert_end..)?;
        let len = u16::from_be_bytes(ext.get(..2)?.try_into().ok()?) as usize;
        entries = ext.get(2 + len..)?;
    }
    Some(first)
}

fn handshake_secret(suite: Suite, shared: &[u8]) -> Vec<u8> {
    let zeros = vec![0; suite.hash_len()];
    let early = extract(suite, &zeros, &zeros);
    let derived = traffic_secret(suite, &early, "derived", &suite.transcript().hash());
    extract(suite, &derived, shared)
}

fn master_secret(suite: Suite, handshake_secret: &[u8]) -> Vec<u8> {
    let derived = traffic_secret(
        suite,
        handshake_secret,
        "derived",
        &suite.transcript().hash(),
    );
    extract(suite, &derived, &vec![0; suite.hash_len()])
}

fn extract(suite: Suite, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    match suite {
        Suite::Aes256 => Hkdf::<Sha384>::extract(Some(salt), ikm).0.to_vec(),
        _ => Hkdf::<Sha256>::extract(Some(salt), ikm).0.to_vec(),
    }
}

fn traffic_secret(suite: Suite, secret: &[u8], label: &str, transcript: &[u8]) -> Vec<u8> {
    expand_label(suite, secret, label, transcript, suite.hash_len())
}

fn expand_label(suite: Suite, secret: &[u8], label: &str, context: &[u8], len: usize) -> Vec<u8> {
    let mut info = Vec::new();
    info.extend_from_slice(&(len as u16).to_be_bytes());
    let full = format!("tls13 {label}");
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    let mut out = vec![0u8; len];
    match suite {
        Suite::Aes256 => Hkdf::<Sha384>::from_prk(secret)
            .expect("prk")
            .expand(&info, &mut out),
        _ => Hkdf::<Sha256>::from_prk(secret)
            .expect("prk")
            .expand(&info, &mut out),
    }
    .expect("expand");
    out
}

fn traffic_keys(suite: Suite, secret: &[u8]) -> Traffic {
    let key_len = if matches!(suite, Suite::Aes128) {
        16
    } else {
        32
    };
    let key = expand_label(suite, secret, "key", &[], key_len);
    let iv = expand_label(suite, secret, "iv", &[], 12);
    let cipher = match suite {
        Suite::Aes128 => RecordCipher::Aes128(Box::new(Aes128Gcm::new_from_slice(&key).expect("key"))),
        Suite::Aes256 => RecordCipher::Aes256(Box::new(Aes256Gcm::new_from_slice(&key).expect("key"))),
        Suite::ChaCha => RecordCipher::ChaCha(ChaCha20Poly1305::new_from_slice(&key).expect("key")),
    };
    Traffic {
        cipher,
        iv: iv.try_into().unwrap(),
    }
}

fn seal_record(traffic: &Traffic, seq: u64, inner: u8, plain: &[u8]) -> Vec<u8> {
    seal_record_padded(traffic, seq, inner, plain, 0)
}

fn seal_record_padded(
    traffic: &Traffic,
    seq: u64,
    inner: u8,
    plain: &[u8],
    padding: usize,
) -> Vec<u8> {
    let mut body = plain.to_vec();
    body.push(inner);
    body.resize(body.len() + padding, 0);
    let aad = header(body.len() + 16);
    let nonce = nonce(&traffic.iv, seq);
    let payload = Payload {
        msg: &body,
        aad: &aad,
    };
    let sealed = match &traffic.cipher {
        RecordCipher::Aes128(cipher) => cipher.encrypt(Nonce::from_slice(&nonce), payload),
        RecordCipher::Aes256(cipher) => cipher.encrypt(Nonce::from_slice(&nonce), payload),
        RecordCipher::ChaCha(cipher) => cipher.encrypt(Nonce::from_slice(&nonce), payload),
    }
    .expect("seal");
    let mut out = aad;
    out.extend(sealed);
    out
}

fn header(len: usize) -> Vec<u8> {
    let mut out = vec![23, 3, 3];
    out.extend_from_slice(&(len as u16).to_be_bytes());
    out
}

fn split_inner(plain: &[u8]) -> Option<(u8, &[u8])> {
    let end = plain.iter().rposition(|byte| *byte != 0)?;
    Some((plain[end], &plain[..end]))
}

fn open_record(traffic: &Traffic, seq: u64, record: &[u8]) -> Option<Vec<u8>> {
    if record.len() < 22
        || !record.starts_with(&[23, 3, 3])
        || u16::from_be_bytes([record[3], record[4]]) as usize != record.len() - 5
    {
        return None;
    }
    let nonce = nonce(&traffic.iv, seq);
    let payload = Payload {
        msg: &record[5..],
        aad: &record[..5],
    };
    match &traffic.cipher {
        RecordCipher::Aes128(cipher) => cipher.decrypt(Nonce::from_slice(&nonce), payload),
        RecordCipher::Aes256(cipher) => cipher.decrypt(Nonce::from_slice(&nonce), payload),
        RecordCipher::ChaCha(cipher) => cipher.decrypt(Nonce::from_slice(&nonce), payload),
    }
    .ok()
}

fn nonce(iv: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut nonce = *iv;
    let bytes = seq.to_be_bytes();
    for index in 0..8 {
        nonce[4 + index] ^= bytes[index];
    }
    nonce
}

fn read_outer<R: Read>(reader: &mut R) -> std::io::Result<Vec<u8>> {
    let mut record = Vec::new();
    if read_outer_into(reader, &mut record)? {
        Ok(record)
    } else {
        Err(io::ErrorKind::UnexpectedEof.into())
    }
}

fn read_outer_into(reader: &mut impl Read, record: &mut Vec<u8>) -> io::Result<bool> {
    if !fill_record(reader, record, 5)? {
        return Ok(false);
    }
    let len = u16::from_be_bytes([record[3], record[4]]) as usize;
    if record[1..3] != [3, 3] || !(1..=16640).contains(&len) {
        return Err(invalid_record());
    }
    fill_record(reader, record, 5 + len)
}

fn fill_record(reader: &mut impl Read, record: &mut Vec<u8>, end: usize) -> io::Result<bool> {
    let mut filled = record.len();
    if filled >= end {
        return Ok(true);
    }
    record.resize(end, 0);
    while filled < end {
        match reader.read(&mut record[filled..]) {
            Ok(0) => {
                record.truncate(filled);
                return if filled == 0 {
                    Ok(false)
                } else {
                    Err(io::ErrorKind::UnexpectedEof.into())
                };
            }
            Ok(n) => filled += n,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => {
                record.truncate(filled);
                return Err(err);
            }
        }
    }
    Ok(true)
}

fn invalid_record() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "reality TLS record or handshake",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reality::{encode_base64, open_session, reality_offer, reality_pair, seal_session};
    use std::io::{Read, Write};

    #[test]
    fn mldsa_matches_source_transcript_and_openssl_fips204_vector() {
        let mut mac = <Hmac<Sha512> as Mac>::new_from_slice(&[7; 32]).unwrap();
        mac.update(&[1; 32]);
        let message = mldsa_message(mac, &[1, 0, 0, 2, 3, 3], &[2, 0, 0, 2, 3, 3]);
        assert_eq!(message.map(|byte| format!("{byte:02x}")).concat(),
            "99b857753d6ba2ad5360d55fffedbb8194d5beae066f66831d23f9ee238653218445ce4926d0ae9195e75a6ab24bae5b46ba78ff38aac16b917da0cf7b861600");
        let signer = RealityMldsa65Signer::from_base64(&encode_base64(&[0x1b; 32])).unwrap();
        let public = signer.0.as_ref().as_ref().encode();
        let signature = signer.sign(&message).unwrap().encode();
        let hash = |bytes: &[u8]| {
            Sha256::digest(bytes)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<Vec<_>>()
                .concat()
        };
        // OpenSSL 3.5.7 genpkey with hexseed, then pkeyutl -rawin -pkeyopt deterministic:1.
        assert_eq!(
            hash(public.as_slice()),
            "bd2a1360606be71c3c812ba90cc062d0fecf1d1d53640d9c06bfd8436ef84dfc"
        );
        assert_eq!(
            hash(signature.as_slice()),
            "2d32b5645464fd972c58252ba2cb8a852b7fa6d9512c912192d6cd78384bcbc6"
        );
        assert_eq!(signature.len(), 3309);
    }

    #[test]
    fn reality_mldsa_flight_requires_the_configured_proof() {
        let (private, public) = reality_pair();
        let short_id = [7; 8];
        let (hello, secret) = reality_offer(&public, &short_id, "example.com").unwrap();
        let signer = RealityMldsa65Signer::from_base64(&encode_base64(&[5; 32])).unwrap();
        let verify = |signer: &RealityMldsa65Signer| {
            let key = signer.0.as_ref().as_ref().encode();
            RealityMldsa65Verifier::from_base64(&encode_base64(key.as_slice())).unwrap()
        };
        let verifier = verify(&signer);
        let other = verify(&RealityMldsa65Signer::from_base64(&encode_base64(&[6; 32])).unwrap());
        assert!(RealityMldsa65Signer::from_base64(&encode_base64(&[5; 31])).is_none());
        assert!(RealityMldsa65Verifier::from_base64(&encode_base64(&[5; 1951])).is_none());

        let signed = server_flight_with_auth(
            &hello,
            &private,
            &RealityPolicy::single_id(short_id),
            &["h2"],
            Some(&signer),
        )
        .unwrap();
        let (_, _, finished, alpn) = read_server_flight_with_auth(
            &mut signed.flight.as_slice(),
            &hello,
            &secret,
            None,
            &public,
            Some(&verifier),
        )
        .unwrap();
        assert_eq!(alpn.as_deref(), Some(b"h2".as_slice()));
        read_client_finished(&mut finished.as_slice(), &signed.handshake, &signed.expect).unwrap();
        assert!(read_server_flight_with_auth(
            &mut signed.flight.as_slice(),
            &hello,
            &secret,
            None,
            &public,
            Some(&other)
        )
        .is_err());
        assert!(read_server_flight(
            &mut signed.flight.as_slice(),
            &hello,
            &secret,
            None,
            &public
        )
        .is_ok());

        let unsigned = server_flight(&hello, &private, &short_id).unwrap();
        assert!(read_server_flight_with_auth(
            &mut unsigned.flight.as_slice(),
            &hello,
            &secret,
            None,
            &public,
            Some(&verifier)
        )
        .is_err());
    }

    #[test]
    fn mldsa_rejects_a_modified_first_extension_or_transcript() {
        let signer = RealityMldsa65Signer::from_base64(&encode_base64(&[5; 32])).unwrap();
        let key = signer.0.as_ref().as_ref().encode();
        let verifier = RealityMldsa65Verifier::from_base64(&encode_base64(key.as_slice())).unwrap();
        let signing = SigningKey::from_bytes(&[7; 32]);
        let auth = [1; 32];
        let mut der = hmac_cert(&signing, &auth, b"hello", b"server", Some(&signer)).unwrap();
        assert!(cert_hmac(&der, &auth, b"hello", b"server", Some(&verifier)).is_some());
        assert!(cert_hmac(&der, &auth, b"hello", b"other", Some(&verifier)).is_none());
        let (tbs, _) = certificate_fields(&der).unwrap();
        let extension = first_certificate_extension(tbs).unwrap();
        assert_eq!(extension.len(), 3309);
        let offset = extension.as_ptr() as usize - der.as_ptr() as usize;
        der[offset] ^= 1;
        assert!(cert_hmac(&der, &auth, b"hello", b"server", None).is_some());
        assert!(cert_hmac(&der, &auth, b"hello", b"server", Some(&verifier)).is_none());
    }

    #[test]
    fn every_offered_tls13_suite_negotiates_with_alpn() {
        for suite in Suite::PREFERENCE {
            let (private, public) = reality_pair();
            let short_id = [7; 8];
            let (mut hello, secret) = reality_offer(&public, &short_id, "example.com").unwrap();
            let random: [u8; 32] = hello[11..43].try_into().unwrap();
            let auth = reality_auth_client(&secret, &public, &random).unwrap();
            let sealed: [u8; 32] = hello[44..76].try_into().unwrap();
            hello[44..76].fill(0);
            let plain = open_session(&auth, &hello[5..], &random, &sealed).unwrap();
            let len = client_suites(&hello[5..]).unwrap().len();
            for id in hello[78..78 + len].as_chunks_mut::<2>().0 {
                if id[0] == 0x13 && *id != suite.id() {
                    id[0] = 0x2a;
                    id[1] = 0x2a;
                }
            }
            let sealed = seal_session(&auth, &hello[5..], &random, &plain).unwrap();
            hello[44..76].copy_from_slice(&sealed);
            let accepted = server_flight_with_alpn(&hello, &private, &short_id, &["h2"]).unwrap();
            assert_eq!(accepted.suite.id(), suite.id());
            assert_eq!(accepted.alpn(), Some(b"h2".as_slice()));
            let (traffic, _, finished, alpn) = read_server_flight_with_alpn(
                &mut accepted.flight.as_slice(),
                &hello,
                &secret,
                None,
                &public,
            )
            .unwrap();
            assert_eq!(alpn.as_deref(), Some(b"h2".as_slice()));
            read_client_finished(
                &mut finished.as_slice(),
                &accepted.handshake,
                &accepted.expect,
            )
            .unwrap();
            let mut encoded = Vec::new();
            let data = vec![17; 70000];
            writer(&mut encoded, accepted.application_keys().1)
                .write_all(&data)
                .unwrap();
            let mut decoded = Vec::new();
            reader(encoded.as_slice(), traffic)
                .read_to_end(&mut decoded)
                .unwrap();
            assert_eq!(decoded, data);
        }
        assert!(selected_alpn(&encrypted_extensions(Some(b"foo"))[4..], &[b"h2"]).is_err());
    }

    #[test]
    fn server_flight_and_client_finished_can_span_records() {
        let (private, public) = reality_pair();
        let short_id = [7; 8];
        let (hello, secret) = reality_offer(&public, &short_id, "example.com").unwrap();
        let accepted = server_flight(&hello, &private, &short_id).unwrap();
        let (server_hello, traffic, _, messages) = server_messages(&hello, &secret, &accepted);
        let mut flight = Vec::new();
        for fragment in server_hello.chunks(13) {
            flight.extend(wrap_handshake(fragment));
        }
        flight.extend_from_slice(&[20, 3, 3, 0, 1, 1]);
        for (seq, fragment) in messages.chunks(19).enumerate() {
            flight.extend(seal_record(&traffic, seq as u64, 22, fragment));
        }
        flight.extend_from_slice(b"next");
        let mut incoming = flight.as_slice();
        let (_, _, finished) =
            read_server_flight(&mut incoming, &hello, &secret, None, &public).unwrap();
        assert_eq!(incoming, b"next");
        let plain = open_record(&accepted.handshake, 0, &finished).unwrap();
        let (_, finished) = split_inner(&plain).unwrap();
        let first = seal_record(&accepted.handshake, 0, 22, &finished[..3]);
        let second = seal_record(&accepted.handshake, 1, 22, &finished[3..]);
        let records = [first, second].concat();
        assert_eq!(
            read_client_finished(
                &mut records.as_slice(),
                &accepted.handshake,
                &accepted.expect
            )
            .unwrap(),
            finished
        );
    }

    #[test]
    fn forged_certificate_verify_fails_even_with_valid_finished() {
        let (private, public) = reality_pair();
        let short_id = [7; 8];
        let (hello, secret) = reality_offer(&public, &short_id, "example.com").unwrap();
        let accepted = server_flight(&hello, &private, &short_id).unwrap();
        let (server_hello, traffic, server_hs, mut messages) =
            server_messages(&hello, &secret, &accepted);
        let before_finished = messages.len() - 4 - accepted.suite.hash_len();
        messages[before_finished - 1] ^= 1;
        let mut transcript = accepted.suite.transcript();
        transcript.update(&hello[5..]);
        transcript.update(&server_hello);
        transcript.update(&messages[..before_finished]);
        let new_finished = finished_verify(accepted.suite, &server_hs, &transcript.hash());
        messages[before_finished + 4..].copy_from_slice(&new_finished);
        let forged = [
            wrap_handshake(&server_hello),
            seal_record(&traffic, 0, 22, &messages),
        ]
        .concat();
        assert!(client_keys(&hello, &forged, &secret, None, &public).is_err());
        assert!(cert_der(&[0]).is_none());
    }

    fn server_messages(
        hello: &[u8],
        secret: &[u8; 32],
        accepted: &ServerHello,
    ) -> (Vec<u8>, Traffic, Vec<u8>, Vec<u8>) {
        let mut wire = accepted.flight.as_slice();
        let (server_hello, _) = read_plain_handshake(&mut wire, 2).unwrap();
        let (suite, group, share) = server_share(&server_hello, &hello[44..76]).unwrap();
        let shared = traffic_shared(secret, None, group, share).unwrap();
        let mut transcript = suite.transcript();
        transcript.update(&hello[5..]);
        transcript.update(&server_hello);
        let handshake = handshake_secret(suite, &shared);
        let server_hs = traffic_secret(suite, &handshake, "s hs traffic", &transcript.hash());
        let traffic = traffic_keys(suite, &server_hs);
        let mut records = HandshakeRecords::new(&mut wire, &traffic);
        let messages = [8, 0x0b, 0x0f, 0x14]
            .into_iter()
            .flat_map(|kind| records.next(kind).unwrap())
            .collect();
        (server_hello, traffic, server_hs, messages)
    }

    #[test]
    fn flight_then_application_data() {
        let (private, public) = reality_pair();
        let short_id = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let (hello, secret) = reality_offer(&public, &short_id, "www.example.com").unwrap();
        let accepted = server_flight(&hello, &private, &short_id).unwrap();
        let (read_key, write_key, finished_record) =
            client_keys(&hello, &accepted.flight, &secret, None, &public).unwrap();
        let _messages = read_client_finished(
            &mut std::io::Cursor::new(&finished_record),
            &accepted.handshake,
            &accepted.expect,
        )
        .unwrap();
        let (_client_app, server_app) = accepted.application_keys();
        let mut encoded = Vec::new();
        writer(&mut encoded, server_app).write_all(b"ping").unwrap();
        let mut decoded = reader(std::io::Cursor::new(encoded), read_key);
        let mut buf = [0u8; 4];
        decoded.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
        let _ = write_key;
    }

    #[test]
    fn hybrid_flight_then_application_data() {
        let (private, public) = reality_pair();
        let short_id = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let (hello, secret, kem) =
            crate::reality::reality_offer_hybrid(&public, &short_id, "www.example.com").unwrap();
        let accepted = server_flight(&hello, &private, &short_id).unwrap();
        let (read_key, write_key, finished_record) =
            client_keys(&hello, &accepted.flight, &secret, Some(&kem), &public).unwrap();
        let _messages = read_client_finished(
            &mut std::io::Cursor::new(&finished_record),
            &accepted.handshake,
            &accepted.expect,
        )
        .unwrap();
        let (_client_app, server_app) = accepted.application_keys();
        let mut encoded = Vec::new();
        writer(&mut encoded, server_app).write_all(b"ping").unwrap();
        let mut decoded = reader(std::io::Cursor::new(encoded), read_key);
        let mut buf = [0u8; 4];
        decoded.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ping");
        let _ = write_key;
    }
}
