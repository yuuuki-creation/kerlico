//! ClientHello construction carrying a REALITY authenticator.
//!
//! Assembles the message twice: first with a zeroed session ID (the server's
//! AEAD AAD form), then patches the sealed 32-byte ciphertext into that slot.

use std::fmt;

use ml_kem::{
    DecapsulationKey768, Seed,
    kem::{Decapsulate, KeyExport},
    ml_kem_768::Ciphertext,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::{
    AuthKey, AuthPlaintext, MAX_CLIENT_HELLO_BYTES, RealityAuthError, SESSION_ID_LEN,
    SESSION_ID_OFFSET, X25519_GROUP, X25519_MLKEM768_GROUP,
};
use crate::crypto::{SharedSecret, StaticX25519Key, entropy};

const X25519_PUBLIC_LEN: usize = 32;
const MLKEM768_CIPHERTEXT_LEN: usize = 1_088;
const MLKEM768_ENCAP_KEY_LEN: usize = 1_184;

const LEGACY_VERSION: [u8; 2] = [3, 3];
const HANDSHAKE_CLIENT_HELLO: u8 = 1;
const CONTENT_TYPE_HANDSHAKE: u8 = 22;
const RECORD_HEADER_LEN: usize = 5;
const SUPPORTED_VERSIONS_BODY: [u8; 3] = [2, 3, 4];

const CIPHER_SUITES: [u16; 6] = [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc030];
const KEY_SHARE_GROUPS: [u16; 2] = [X25519_MLKEM768_GROUP, X25519_GROUP];
const SUPPORTED_GROUPS: [u16; 5] = [X25519_MLKEM768_GROUP, X25519_GROUP, 0x0017, 0x0018, 0x0019];
const SIGNATURE_ALGORITHMS: [u16; 9] = [
    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0601, 0x0806, 0x0807,
];

/// A ClientHello could not be constructed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HelloError {
    /// Empty, over-long, or non-ASCII presentation name.
    InvalidServerName,
    /// Empty or over-long ALPN protocol.
    InvalidAlpn,
    /// Message would exceed the server ClientHello or TLS record bound.
    TooLarge,
    /// Operating-system entropy was unavailable.
    Entropy,
    /// Key agreement produced a non-contributory result.
    NonContributory,
    /// Authenticator derivation or sealing failed.
    Auth(RealityAuthError),
}

impl fmt::Display for HelloError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidServerName => formatter.write_str("invalid REALITY server name"),
            Self::InvalidAlpn => formatter.write_str("invalid ALPN protocol"),
            Self::TooLarge => formatter.write_str("ClientHello exceeds the wire size limit"),
            Self::Entropy => formatter.write_str("entropy unavailable for ClientHello"),
            Self::NonContributory => formatter.write_str("non-contributory REALITY key agreement"),
            Self::Auth(error) => write!(formatter, "REALITY authenticator: {error}"),
        }
    }
}

impl std::error::Error for HelloError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Auth(error) => Some(error),
            _ => None,
        }
    }
}

impl From<RealityAuthError> for HelloError {
    fn from(error: RealityAuthError) -> Self {
        Self::Auth(error)
    }
}

/// TLS shared secret after the peer selects a key-share group.
#[derive(Zeroize, ZeroizeOnDrop)]
pub enum TlsSharedSecret {
    /// Plain X25519 (32 bytes).
    X25519([u8; 32]),
    /// X25519MLKEM768 (ML-KEM shared || X25519 shared).
    Hybrid([u8; 64]),
}

impl TlsSharedSecret {
    /// Borrowed secret bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::X25519(bytes) => bytes,
            Self::Hybrid(bytes) => bytes,
        }
    }
}

impl fmt::Debug for TlsSharedSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TlsSharedSecret([REDACTED])")
    }
}

/// Ephemeral shares one ClientHello offers.
///
/// The standalone X25519 key is dual-use: REALITY authentication against the
/// configured server public key, and the TLS share when the peer selects plain
/// X25519. It is stored as [`StaticX25519Key`] so both agreements can use `&self`
/// without violating the single-consume ephemeral API.
pub struct ClientKeyAgreement {
    x25519: StaticX25519Key,
    x25519_public: [u8; X25519_PUBLIC_LEN],
    // Hybrid private state is read by `tls_shared_secret` during the TLS handshake.
    hybrid_x25519: StaticX25519Key,
    hybrid_x25519_public: [u8; X25519_PUBLIC_LEN],
    hybrid_mlkem: DecapsulationKey768,
    hybrid_encap: [u8; MLKEM768_ENCAP_KEY_LEN],
}

impl ClientKeyAgreement {
    /// Generates every share from operating-system entropy.
    ///
    /// # Errors
    ///
    /// Returns [`HelloError::Entropy`] when entropy is unavailable.
    pub fn generate() -> Result<Self, HelloError> {
        let x25519_secret = entropy::bytes::<32>().map_err(|_| HelloError::Entropy)?;
        let hybrid_secret = entropy::bytes::<32>().map_err(|_| HelloError::Entropy)?;
        let x25519 = StaticX25519Key::new(&x25519_secret);
        let hybrid_x25519 = StaticX25519Key::new(&hybrid_secret);
        let x25519_public = x25519.public_key();
        let hybrid_x25519_public = hybrid_x25519.public_key();
        let (hybrid_mlkem, hybrid_encap) = generate_mlkem()?;
        Ok(Self {
            x25519,
            x25519_public,
            hybrid_x25519,
            hybrid_x25519_public,
            hybrid_mlkem,
            hybrid_encap,
        })
    }

    /// Derives the REALITY authenticator key against the configured server.
    pub(crate) fn auth_key(
        &self,
        server_public_key: &[u8; X25519_PUBLIC_LEN],
        client_random: &[u8; 32],
    ) -> Result<AuthKey, HelloError> {
        let shared = self
            .x25519
            .agree(server_public_key)
            .ok_or(HelloError::NonContributory)?;
        Ok(AuthKey::derive(shared_as_array(&shared), client_random)?)
    }

    /// Agrees the TLS 1.3 ECDHE secret for the group the server selected.
    pub(crate) fn tls_shared_secret(
        &self,
        group: u16,
        server_share: &[u8],
    ) -> Option<TlsSharedSecret> {
        match group {
            X25519_GROUP => {
                let peer = <[u8; X25519_PUBLIC_LEN]>::try_from(server_share).ok()?;
                let secret = self.x25519.agree(&peer)?;
                Some(TlsSharedSecret::X25519(*shared_as_array(&secret)))
            }
            X25519_MLKEM768_GROUP => {
                let (ciphertext, peer_bytes) =
                    server_share.split_at_checked(MLKEM768_CIPHERTEXT_LEN)?;
                let peer = <[u8; X25519_PUBLIC_LEN]>::try_from(peer_bytes).ok()?;
                let mlkem = mlkem_decapsulate(&self.hybrid_mlkem, ciphertext)?;
                let x25519 = self.hybrid_x25519.agree(&peer)?;
                let mut bytes = [0_u8; 64];
                bytes[..32].copy_from_slice(mlkem.as_ref());
                bytes[32..].copy_from_slice(shared_as_array(&x25519));
                Some(TlsSharedSecret::Hybrid(bytes))
            }
            _ => None,
        }
    }

    /// The standalone X25519 public share used for REALITY authentication.
    #[must_use]
    pub const fn authentication_public_key(&self) -> &[u8; X25519_PUBLIC_LEN] {
        &self.x25519_public
    }

    fn key_shares(&self) -> Result<(Vec<u8>, [u16; KEY_SHARE_GROUPS.len()]), HelloError> {
        let mut output = Vec::with_capacity(
            8 + self.hybrid_encap.len()
                + self.hybrid_x25519_public.len()
                + self.x25519_public.len(),
        );
        output.extend_from_slice(&KEY_SHARE_GROUPS[0].to_be_bytes());
        push_u16(
            &mut output,
            self.hybrid_encap.len() + self.hybrid_x25519_public.len(),
        )?;
        output.extend_from_slice(&self.hybrid_encap);
        output.extend_from_slice(&self.hybrid_x25519_public);
        output.extend_from_slice(&KEY_SHARE_GROUPS[1].to_be_bytes());
        push_u16(&mut output, self.x25519_public.len())?;
        output.extend_from_slice(&self.x25519_public);
        Ok((output, KEY_SHARE_GROUPS))
    }
}

impl fmt::Debug for ClientKeyAgreement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ClientKeyAgreement([REDACTED])")
    }
}

/// One constructed ClientHello, ready to write.
pub struct HelloRecord {
    message: Vec<u8>,
    record_length: u16,
    random: [u8; 32],
    session_id: [u8; SESSION_ID_LEN],
    key_share_groups: [u16; KEY_SHARE_GROUPS.len()],
}

impl HelloRecord {
    /// Handshake message bytes (no record header).
    #[must_use]
    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// TLS record that carries the handshake message.
    #[must_use]
    pub fn record(&self) -> Vec<u8> {
        let mut record = Vec::with_capacity(RECORD_HEADER_LEN + self.message.len());
        record.push(CONTENT_TYPE_HANDSHAKE);
        record.extend_from_slice(&[3, 1]);
        record.extend_from_slice(&self.record_length.to_be_bytes());
        record.extend_from_slice(&self.message);
        record
    }

    /// ClientHello random.
    #[must_use]
    pub const fn random(&self) -> &[u8; 32] {
        &self.random
    }

    /// Sealed session ID ciphertext.
    #[must_use]
    pub const fn session_id(&self) -> &[u8; SESSION_ID_LEN] {
        &self.session_id
    }

    /// Whether the peer echoed this session ID byte-for-byte.
    #[must_use]
    pub fn matches_session_id(&self, observed: &[u8]) -> bool {
        observed == self.session_id
    }

    /// Whether this hello offered the named cipher suite.
    #[must_use]
    pub fn cipher_offered(&self, suite: u16) -> bool {
        CIPHER_SUITES.contains(&suite)
    }

    /// Whether this hello offered the named key-share group.
    #[must_use]
    pub fn key_share_group_offered(&self, group: u16) -> bool {
        self.key_share_groups.contains(&group)
    }
}

impl fmt::Debug for HelloRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HelloRecord")
            .field("message_len", &self.message.len())
            .field("key_share_groups", &self.key_share_groups)
            .finish_non_exhaustive()
    }
}

/// Builds a ClientHello carrying a valid REALITY authenticator.
///
/// # Errors
///
/// Returns [`HelloError`] for invalid names, oversized messages, entropy
/// failure, or a non-contributory server key.
pub fn build_client_hello(
    server_name: &str,
    alpn: &[&[u8]],
    keys: &ClientKeyAgreement,
    server_public_key: &[u8; X25519_PUBLIC_LEN],
    auth: AuthPlaintext,
) -> Result<(HelloRecord, AuthKey), HelloError> {
    if server_name.is_empty() || server_name.len() > 253 || !server_name.is_ascii() {
        return Err(HelloError::InvalidServerName);
    }
    for protocol in alpn {
        if protocol.is_empty() || protocol.len() > 253 {
            return Err(HelloError::InvalidAlpn);
        }
    }

    let random = entropy::bytes::<32>().map_err(|_| HelloError::Entropy)?;
    let auth_key = keys.auth_key(server_public_key, &random)?;
    let (mut message, key_share_groups) = assemble(server_name, alpn, keys, &random)?;
    let session_id = auth_key.seal_session_id(&random, &message, auth)?;
    message
        .get_mut(SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN)
        .ok_or(HelloError::TooLarge)?
        .copy_from_slice(&session_id);
    let record_length = u16::try_from(message.len()).map_err(|_| HelloError::TooLarge)?;
    Ok((
        HelloRecord {
            message,
            record_length,
            random,
            session_id,
            key_share_groups,
        },
        auth_key,
    ))
}

fn assemble(
    server_name: &str,
    alpn: &[&[u8]],
    keys: &ClientKeyAgreement,
    random: &[u8; 32],
) -> Result<(Vec<u8>, [u16; KEY_SHARE_GROUPS.len()]), HelloError> {
    let mut extensions = Vec::new();
    let host = server_name.as_bytes();
    push_extension(&mut extensions, 0x0000, |body| {
        push_u16(body, 3 + host.len())?;
        body.push(0);
        push_u16(body, host.len())?;
        body.extend_from_slice(host);
        Ok(())
    })?;
    push_extension(&mut extensions, 0x000a, |body| {
        push_u16(body, SUPPORTED_GROUPS.len() * 2)?;
        for group in SUPPORTED_GROUPS {
            push_u16(body, usize::from(group))?;
        }
        Ok(())
    })?;
    push_extension(&mut extensions, 0x000d, |body| {
        push_u16(body, SIGNATURE_ALGORITHMS.len() * 2)?;
        for scheme in SIGNATURE_ALGORITHMS {
            push_u16(body, usize::from(scheme))?;
        }
        Ok(())
    })?;
    // RFC 6066 / Go crypto/tls: status_type=ocsp, empty responder list, empty extensions.
    // A 2-byte body is rejected by stock Xray (Go) with "error decoding message".
    push_extension(&mut extensions, 0x0005, |body| {
        body.extend_from_slice(&[1, 0, 0, 0, 0]);
        Ok(())
    })?;
    push_extension(&mut extensions, 0x0010, |body| {
        let list_len: usize = alpn.iter().map(|protocol| 1 + protocol.len()).sum();
        push_u16(body, list_len)?;
        for protocol in alpn {
            let length = u8::try_from(protocol.len()).map_err(|_| HelloError::TooLarge)?;
            body.push(length);
            body.extend_from_slice(protocol);
        }
        Ok(())
    })?;
    // psk_key_exchange_modes (0x002d), not the typo 0x2d00. Stock Xray requires a
    // parseable ClientHello; the wrong type was skipped as unknown but paired with
    // the broken status_request above made Go abort the handshake.
    push_extension(&mut extensions, 0x002d, |body| {
        body.extend_from_slice(&[1, 1]); // modes_len=1, psk_dhe_ke
        Ok(())
    })?;
    push_extension(&mut extensions, 0x002b, |body| {
        body.extend_from_slice(&SUPPORTED_VERSIONS_BODY);
        Ok(())
    })?;
    let (entries, groups) = keys.key_shares()?;
    push_extension(&mut extensions, 0x0033, |body| {
        push_u16(body, entries.len())?;
        body.extend_from_slice(&entries);
        Ok(())
    })?;

    let suites_len = CIPHER_SUITES.len() * 2;
    let body_len = 2 + 32 + 1 + SESSION_ID_LEN + 2 + suites_len + 1 + 1 + 2 + extensions.len();
    let message_len = body_len + 4;
    if message_len > MAX_CLIENT_HELLO_BYTES || message_len > usize::from(u16::MAX) {
        return Err(HelloError::TooLarge);
    }

    let mut message = Vec::with_capacity(message_len);
    message.push(HANDSHAKE_CLIENT_HELLO);
    let length = u32::try_from(body_len).map_err(|_| HelloError::TooLarge)?;
    message.extend_from_slice(&length.to_be_bytes()[1..]);
    message.extend_from_slice(&LEGACY_VERSION);
    message.extend_from_slice(random);
    message.push(u8::try_from(SESSION_ID_LEN).map_err(|_| HelloError::TooLarge)?);
    message.resize(message.len() + SESSION_ID_LEN, 0);
    push_u16(&mut message, suites_len)?;
    for suite in CIPHER_SUITES {
        push_u16(&mut message, usize::from(suite))?;
    }
    message.push(1);
    message.push(0);
    push_u16(&mut message, extensions.len())?;
    message.extend_from_slice(&extensions);
    if message.len() != message_len {
        return Err(HelloError::TooLarge);
    }
    Ok((message, groups))
}

fn push_extension(
    output: &mut Vec<u8>,
    extension_type: u16,
    write: impl FnOnce(&mut Vec<u8>) -> Result<(), HelloError>,
) -> Result<(), HelloError> {
    let mut body = Vec::new();
    write(&mut body)?;
    output.extend_from_slice(&extension_type.to_be_bytes());
    push_u16(output, body.len())?;
    output.extend_from_slice(&body);
    Ok(())
}

fn push_u16(output: &mut Vec<u8>, length: usize) -> Result<(), HelloError> {
    output.extend_from_slice(
        &u16::try_from(length)
            .map_err(|_| HelloError::TooLarge)?
            .to_be_bytes(),
    );
    Ok(())
}

fn shared_as_array(secret: &SharedSecret) -> &[u8; 32] {
    secret
}

fn generate_mlkem() -> Result<(DecapsulationKey768, [u8; MLKEM768_ENCAP_KEY_LEN]), HelloError> {
    let mut seed = Seed::default();
    entropy::fill(seed.as_mut()).map_err(|_| HelloError::Entropy)?;
    let decapsulation = DecapsulationKey768::from_seed(seed);
    let encapsulation = decapsulation.encapsulation_key().to_bytes();
    let mut hybrid_encap = [0_u8; MLKEM768_ENCAP_KEY_LEN];
    hybrid_encap.copy_from_slice(encapsulation.as_slice());
    Ok((decapsulation, hybrid_encap))
}

fn mlkem_decapsulate(
    decapsulation: &DecapsulationKey768,
    ciphertext: &[u8],
) -> Option<Zeroizing<[u8; 32]>> {
    use ml_kem::array::Array as MlKemArray;
    let ct: Ciphertext = MlKemArray::try_from(ciphertext).ok()?;
    let shared = decapsulation.decapsulate(&ct);
    let mut out = Zeroizing::new([0_u8; 32]);
    out.copy_from_slice(shared.as_ref());
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::load_bytes,
        protocol::reality::{CLIENT_VERSION, ClientHello, RealityAuthenticator},
        protocol::vless::UserId,
    };
    use base64::prelude::{BASE64_URL_SAFE_NO_PAD, Engine as _};
    use std::path::Path;
    use x25519_dalek::{PublicKey, StaticSecret};

    const NAME: &str = "www.example.com";
    const ALPN: &[&[u8]] = &[b"h2", b"http/1.1"];
    const SHORT_ID_HEX: &str = "0102030405060708";
    const SHORT_ID: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    const USER: &str = "11111111-1111-4111-8111-111111111111";

    fn plaintext(now: u32) -> AuthPlaintext {
        AuthPlaintext {
            version: CLIENT_VERSION,
            time: now,
            short_id: SHORT_ID,
        }
    }

    fn authenticator(private: [u8; 32]) -> (RealityAuthenticator, [u8; 32]) {
        let public = PublicKey::from(&StaticSecret::from(private)).to_bytes();
        let json = format!(
            r#"{{
  "role": "entry",
  "listeners": [{{ "port": 443 }}],
  "reality": {{
    "cover": "{name}:443",
    "privateKey": "{private_key}",
    "serverNames": ["{name}"],
    "maxTimeDiffMs": 60000
  }},
  "users": [{{
    "id": "{user}",
    "shortIds": ["{short_id}"],
    "label": "alice"
  }}],
  "routing": {{ "default": "direct" }}
}}"#,
            name = NAME,
            private_key = BASE64_URL_SAFE_NO_PAD.encode(private),
            user = USER,
            short_id = SHORT_ID_HEX,
        );
        let validated = load_bytes(Path::new("client-offer-entry.json"), json.as_bytes())
            .expect("entry config must load");
        let node = validated.into_node();
        let entry = node.as_entry().expect("role is entry");
        (
            RealityAuthenticator::from_entry(entry).expect("authenticator"),
            public,
        )
    }

    #[test]
    fn built_hello_authenticates_against_the_shared_server_authenticator() {
        let (authenticator, server_public) = authenticator([0x42; 32]);
        let keys = ClientKeyAgreement::generate().expect("keys");
        let now = 1_700_000_000_u32;
        let (record, client_auth_key) =
            build_client_hello(NAME, ALPN, &keys, &server_public, plaintext(now))
                .expect("client hello");

        let hello = ClientHello::parse_message(record.message()).expect("parse");
        assert_eq!(hello.session_ciphertext(), Some(record.session_id()));
        assert_eq!(*hello.random(), *record.random());

        let result = authenticator
            .authenticate(&hello, u64::from(now))
            .expect("server must accept the client authenticator");
        assert_eq!(result.client_version(), CLIENT_VERSION);
        assert_eq!(result.client_time(), now);
        assert_eq!(result.auth_key().as_bytes(), client_auth_key.as_bytes());
        assert_eq!(
            result.user_id(),
            UserId::new(*uuid::Uuid::parse_str(USER).unwrap().as_bytes())
        );
    }

    #[test]
    fn session_id_slot_starts_zeroed_in_aad_form() {
        let keys = ClientKeyAgreement::generate().expect("keys");
        let server_public = [0x11; 32];
        let (record, _) =
            build_client_hello(NAME, ALPN, &keys, &server_public, plaintext(1)).expect("hello");
        let hello = ClientHello::parse_message(record.message()).expect("parse");
        let aad = hello.reality_aad().expect("aad");
        assert!(
            aad[SESSION_ID_OFFSET..SESSION_ID_OFFSET + SESSION_ID_LEN]
                .iter()
                .all(|&b| b == 0)
        );
        assert_ne!(record.session_id(), &[0; SESSION_ID_LEN]);
    }

    #[test]
    fn tls_shared_secret_agrees_for_plain_x25519() {
        let keys = ClientKeyAgreement::generate().expect("keys");
        let peer = ClientKeyAgreement::generate().expect("peer");
        let secret = keys
            .tls_shared_secret(X25519_GROUP, peer.authentication_public_key())
            .expect("x25519 agreement");
        let mirrored = peer
            .tls_shared_secret(X25519_GROUP, keys.authentication_public_key())
            .expect("mirrored");
        assert_eq!(secret.as_bytes(), mirrored.as_bytes());
        assert_eq!(secret.as_bytes().len(), 32);
    }

    #[test]
    fn offers_hybrid_and_x25519_key_shares() {
        let keys = ClientKeyAgreement::generate().expect("keys");
        let (record, _) =
            build_client_hello(NAME, ALPN, &keys, &[0x22; 32], plaintext(1)).expect("hello");
        assert!(record.key_share_group_offered(X25519_MLKEM768_GROUP));
        assert!(record.key_share_group_offered(X25519_GROUP));
        assert!(record.cipher_offered(0x1301));
    }

    #[test]
    fn client_hello_extensions_match_stock_xray_go_parser() {
        let keys = ClientKeyAgreement::generate().expect("keys");
        let (record, _) =
            build_client_hello(NAME, ALPN, &keys, &[0x22; 32], plaintext(1)).expect("hello");
        let message = record.message();
        // Skip handshake header (4) + legacy_ver(2)+random(32)+session_id
        let sid_len = message[4 + 2 + 32] as usize;
        let mut off = 4 + 2 + 32 + 1 + sid_len;
        let cs_len = u16::from_be_bytes([message[off], message[off + 1]]) as usize;
        off += 2 + cs_len;
        let comp_len = message[off] as usize;
        off += 1 + comp_len;
        let ext_len = u16::from_be_bytes([message[off], message[off + 1]]) as usize;
        off += 2;
        let end = off + ext_len;
        let mut saw_status = false;
        let mut saw_psk_modes = false;
        while off + 4 <= end {
            let et = u16::from_be_bytes([message[off], message[off + 1]]);
            let el = u16::from_be_bytes([message[off + 2], message[off + 3]]) as usize;
            off += 4;
            let body = &message[off..off + el];
            off += el;
            match et {
                0x0005 => {
                    saw_status = true;
                    assert_eq!(
                        body,
                        &[1, 0, 0, 0, 0],
                        "status_request must be OCSP empty lists"
                    );
                }
                0x002d => {
                    saw_psk_modes = true;
                    assert_eq!(body, &[1, 1], "psk_key_exchange_modes");
                }
                0x2d00 => panic!("legacy typo extension 0x2d00 must not be present"),
                _ => {}
            }
        }
        assert!(saw_status, "status_request required for Go crypto/tls");
        assert!(saw_psk_modes, "psk_key_exchange_modes 0x002d required");
    }
}
