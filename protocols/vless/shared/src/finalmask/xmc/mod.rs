mod padding;
mod stream;
mod wire;

use std::io::{self, BufReader, Read};
use std::net::SocketAddr;
use std::sync::Arc;

use num_bigint_dig::{prime::probably_prime, BigUint, ModInverse};
use rand_core::{OsRng, RngCore};
use rsa::{pkcs8::EncodePublicKey, BoxedUint, PrivateKey, PublicKey};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::{invalid, malformed, random_below, settings, Side, TcpPair};
use stream::{packet_pair, CipherReader, CipherWriter};
use wire::{
    encode_packet, put_field, put_varint, read_packet, read_varint, send_packet, take_field,
};

const PROTOCOL_VERSION: u32 = 775;
const STATUS_RESPONSE: &[u8] = br#"{"description":"A Minecraft Server","players":{"max":20,"online":0},"version":{"name":"26.1.2","protocol":775},"enforcesSecureChat":true}"#;
const AUTH_DOWN: &[u8] =
    br#"{"type":"translatable","translate":"multiplayer.disconnect.authservers_down"}"#;
const NOT_WHITE_LISTED: &[u8] = br#"{"text":"You are not white-listed on this server!"}"#;
const STRING_LIMIT: usize = 4096;
const BYTES_LIMIT: usize = 1023;
const PASSWORD_LIMIT: usize = 128 - 11 - 4;

#[derive(Clone)]
pub(super) struct Xmc(Arc<Config>);

struct Config {
    password: String,
    hostname: String,
    profiles: Vec<Profile>,
    private_key: PrivateKey,
    public_key: PublicKey,
    public_der: Vec<u8>,
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawConfig {
    password: String,
    hostname: String,
    profiles: Vec<RawProfile>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawProfile {
    username: String,
    uuid: String,
    textures_value: String,
    textures_signature: String,
}

struct Profile {
    username: String,
    uuid: [u8; 16],
    textures_value: String,
    textures_signature: String,
}

impl TryFrom<RawProfile> for Profile {
    type Error = io::Error;

    fn try_from(profile: RawProfile) -> io::Result<Self> {
        if !(3..=16).contains(&profile.username.len())
            || !profile
                .username
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(invalid("invalid XMC profile username"));
        }
        if !(1..=STRING_LIMIT).contains(&profile.textures_value.len())
            || !(1..=STRING_LIMIT).contains(&profile.textures_signature.len())
        {
            return Err(invalid("invalid XMC profile textures or signature length"));
        }
        Ok(Self {
            username: profile.username,
            uuid: profile_uuid(&profile.uuid)?,
            textures_value: profile.textures_value,
            textures_signature: profile.textures_signature,
        })
    }
}

fn profile_uuid(value: &str) -> io::Result<[u8; 16]> {
    let value = if let Some(body) = value
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .filter(|s| s.len() == 36)
    {
        body
    } else if value.len() == 45
        && value
            .get(..9)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("urn:uuid:"))
    {
        &value[9..]
    } else {
        value
    };
    let valid_shape = match value.len() {
        32 => value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        36 => [8, 13, 18, 23].iter().all(|&i| value.as_bytes()[i] == b'-'),
        _ => false,
    };
    if !valid_shape {
        return Err(invalid("invalid XMC profile UUID"));
    }
    crate::parse_id(value).map_err(|_| invalid("invalid XMC profile UUID"))
}

fn derive_prime(password: &[u8], label: &[u8], different_from: Option<&BigUint>) -> BigUint {
    let mut bytes = [0; 64];
    for (chunk, suffix) in bytes.chunks_exact_mut(32).zip([b"-0", b"-1"]) {
        let mut hash = Sha256::new();
        hash.update(password);
        hash.update(label);
        hash.update(suffix);
        chunk.copy_from_slice(&hash.finalize());
    }
    bytes[0] |= 0xc0;
    bytes[63] |= 1;
    let mut candidate = BigUint::from_bytes_be(&bytes);
    loop {
        if different_from != Some(&candidate)
            && &candidate % 65537u32 != BigUint::from(1u32)
            && probably_prime(&candidate, 20)
        {
            return candidate;
        }
        candidate += 2u32;
    }
}

fn derive_key(password: &[u8]) -> io::Result<PrivateKey> {
    let p = derive_prime(password, b"-p-prime", None);
    let q = derive_prime(password, b"-q-prime", Some(&p));
    let totient = (&p - 1u32) * (&q - 1u32);
    let exponent = BigUint::from(65537u32);
    let private = exponent
        .mod_inverse(totient)
        .and_then(|value| value.to_biguint())
        .ok_or_else(|| invalid("XMC RSA exponent has no modular inverse"))?;
    let integer = |value: BigUint| {
        let bytes = value.to_bytes_be();
        BoxedUint::from_be_slice(&bytes, (bytes.len() * 8) as u32).map_err(invalid)
    };
    PrivateKey::from_components(
        integer(&p * &q)?,
        65537u64.into(),
        integer(private)?,
        vec![integer(p)?, integer(q)?],
    )
    .map_err(invalid)
}

fn denied(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

impl Xmc {
    pub(super) fn parse(value: Value) -> io::Result<Self> {
        let config: RawConfig = settings(value)?;
        if config.profiles.is_empty() {
            return Err(invalid("XMC profiles are required"));
        }
        if !(1..=PASSWORD_LIMIT).contains(&config.password.len()) {
            return Err(invalid("XMC password must contain 1 to 113 bytes"));
        }
        if config.hostname.len() > STRING_LIMIT {
            return Err(invalid("XMC hostname exceeds 4096 bytes"));
        }
        let profiles = config
            .profiles
            .into_iter()
            .map(Profile::try_from)
            .collect::<io::Result<_>>()?;
        let private_key = derive_key(config.password.as_bytes())?;
        let public_key = private_key.to_public_key();
        let public_der = public_key.to_public_key_der().map_err(invalid)?;
        Ok(Self(Arc::new(Config {
            password: config.password,
            hostname: config.hostname,
            profiles,
            private_key,
            public_key,
            public_der: public_der.as_bytes().to_vec(),
        })))
    }

    pub(super) fn wrap(
        &self,
        halves: TcpPair,
        peer: SocketAddr,
        side: Side,
    ) -> io::Result<TcpPair> {
        self.0
            .handshake(halves, peer, side)
            .map_err(|error| io::Error::new(error.kind(), format!("XMC handshake: {error}")))
    }
}

impl Config {
    fn handshake(
        &self,
        (reader, writer): TcpPair,
        peer: SocketAddr,
        side: Side,
    ) -> io::Result<TcpPair> {
        let halves: TcpPair = (Box::new(BufReader::new(reader)), writer);
        let (mut reader, mut writer, ack_length) = match side {
            Side::Client => self.client_login(halves, peer)?,
            Side::Server => self.server_login(halves)?,
        };
        padding::exchange(&mut reader, &mut writer, side, ack_length)?;
        packet_pair(reader, writer, side)
    }

    fn client_login(
        &self,
        (mut reader, mut writer): TcpPair,
        peer: SocketAddr,
    ) -> io::Result<(CipherReader, CipherWriter, usize)> {
        let peer_ip;
        let hostname = if self.hostname.is_empty() {
            peer_ip = peer.ip().to_string();
            &peer_ip
        } else {
            &self.hostname
        };
        let mut fields = Vec::new();
        put_varint(&mut fields, PROTOCOL_VERSION);
        put_field(&mut fields, hostname.as_bytes());
        fields.extend_from_slice(&peer.port().to_be_bytes());
        put_varint(&mut fields, 2);
        send_packet(&mut writer, 0, &fields)?;

        let index = random_below(self.profiles.len() as u32) as usize;
        let profile = &self.profiles[index];
        fields.clear();
        put_field(&mut fields, profile.username.as_bytes());
        fields.extend_from_slice(&profile.uuid);
        send_packet(&mut writer, 0, &fields)?;

        let request = read_packet(&mut reader)?;
        if request.id != 1 {
            return Err(malformed("expected XMC encryption request"));
        }
        let mut data = request.data();
        take_field(&mut data, STRING_LIMIT)?;
        let key = take_field(&mut data, BYTES_LIMIT)?;
        let token = take_field(&mut data, BYTES_LIMIT)?;
        if key != self.public_der {
            return Err(denied("XMC server public key mismatch"));
        }
        let mut secret = [0; 16];
        OsRng
            .try_fill_bytes(&mut secret)
            .map_err(|error| io::Error::other(error.to_string()))?;
        let mut proof = token.to_vec();
        proof.extend_from_slice(self.password.as_bytes());
        fields.clear();
        for value in [&secret[..], &proof[..]] {
            let ciphertext = self
                .public_key
                .pkcs1v15_encrypt(value)
                .map_err(io::Error::other)?;
            put_field(&mut fields, &ciphertext);
        }
        send_packet(&mut writer, 1, &fields)?;

        let mut reader = CipherReader::new(reader, secret);
        let mut writer = CipherWriter::new(writer, secret);
        let success = read_packet(&mut reader)?;
        if success.id == 0 {
            return Err(denied("XMC server rejected login"));
        }
        if success.id != 2 {
            return Err(malformed("expected XMC login success"));
        }
        profile.verify_success(success.data())?;
        let ack = encode_packet(3, &[])?;
        let ack_length = ack.len();
        writer.send(ack)?;
        Ok((reader, writer, ack_length))
    }

    fn server_login(
        &self,
        (mut reader, mut writer): TcpPair,
    ) -> io::Result<(CipherReader, CipherWriter, usize)> {
        let handshake = read_packet(&mut reader)?;
        if handshake.id != 0 {
            return Err(malformed("expected XMC handshake packet"));
        }
        let mut data = handshake.data();
        read_varint(&mut data)?;
        take_field(&mut data, STRING_LIMIT)?;
        data.read_exact(&mut [0; 2])?;
        match read_varint(&mut data)?.0 {
            1 => return status_query((reader, writer)),
            2 => {}
            _ => return Err(malformed("invalid XMC handshake state")),
        }

        let start = read_packet(&mut reader)?;
        if start.id != 0 {
            return Err(malformed("expected XMC login start"));
        }
        let mut data = start.data();
        let username = take_field(&mut data, STRING_LIMIT)?;
        let mut uuid = [0; 16];
        data.read_exact(&mut uuid)?;
        let profile = self
            .profiles
            .iter()
            .find(|p| p.username.as_bytes() == username && p.uuid == uuid);

        let mut challenge = [0; 20];
        OsRng
            .try_fill_bytes(&mut challenge)
            .map_err(|error| io::Error::other(error.to_string()))?;
        let (token, fallback_secret) = challenge.split_at(4);
        let mut fields = vec![0];
        put_field(&mut fields, &self.public_der);
        put_field(&mut fields, token);
        fields.push(1);
        send_packet(&mut writer, 1, &fields)?;

        let response = read_packet(&mut reader)?;
        if response.id != 1 {
            return Err(malformed("expected XMC encryption response"));
        }
        let mut data = response.data();
        let ciphertext = take_field(&mut data, BYTES_LIMIT)?;
        let proof_ciphertext = take_field(&mut data, BYTES_LIMIT)?;
        let secret = self
            .private_key
            .pkcs1v15_decrypt(ciphertext)
            .ok()
            .and_then(|plaintext| <[u8; 16]>::try_from(plaintext).ok());
        let proof = self
            .private_key
            .pkcs1v15_decrypt(proof_ciphertext)
            .map_err(|_| denied("invalid XMC verification proof"))?;
        let Some((received_token, received_password)) = proof.split_at_checked(token.len()) else {
            return Err(denied("invalid XMC verification proof"));
        };
        if !bool::from(received_token.ct_eq(token)) {
            return Err(denied("XMC verification token mismatch"));
        }
        let password_matches = bool::from(received_password.ct_eq(self.password.as_bytes()));
        // A wrong password receives the same disconnect even when the RSA
        // decryption did not yield a usable 16-byte secret.
        let secret = match (secret, password_matches) {
            (Some(secret), _) => secret,
            (None, false) => fallback_secret.try_into().expect("16-byte fallback"),
            (None, true) => return Err(denied("invalid XMC shared secret")),
        };
        let mut reader = CipherReader::new(reader, secret);
        let mut writer = CipherWriter::new(writer, secret);
        if !password_matches {
            let _ = send_disconnect(&mut writer, AUTH_DOWN);
            return Err(denied("invalid XMC password"));
        }
        let Some(profile) = profile else {
            send_disconnect(&mut writer, NOT_WHITE_LISTED)?;
            return Err(denied("unknown XMC login profile"));
        };

        fields.clear();
        profile.login_success(&mut fields);
        writer.send(encode_packet(2, &fields)?)?;
        let ack = read_packet(&mut reader)?;
        if ack.id != 3 || !ack.data().is_empty() {
            return Err(malformed("invalid XMC login acknowledgement"));
        }
        Ok((reader, writer, ack.wire_len))
    }
}

impl Profile {
    fn login_success(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.uuid);
        put_field(out, self.username.as_bytes());
        put_varint(out, 1);
        put_field(out, b"textures");
        put_field(out, self.textures_value.as_bytes());
        out.push(1);
        put_field(out, self.textures_signature.as_bytes());
    }

    fn verify_success(&self, mut data: &[u8]) -> io::Result<()> {
        let mut uuid = [0; 16];
        data.read_exact(&mut uuid)?;
        let username = take_field(&mut data, STRING_LIMIT)?;
        let (property_count, _) = read_varint(&mut data)?;
        let property = take_field(&mut data, STRING_LIMIT)?;
        let textures = take_field(&mut data, STRING_LIMIT)?;
        let mut signed = [0];
        data.read_exact(&mut signed)?;
        let signature = take_field(&mut data, STRING_LIMIT)?;
        if property_count != 1 || property != b"textures" || signed != [1] {
            return Err(malformed("invalid XMC login profile properties"));
        }
        if uuid != self.uuid
            || username != self.username.as_bytes()
            || textures != self.textures_value.as_bytes()
            || signature != self.textures_signature.as_bytes()
        {
            return Err(denied("XMC login profile mismatch"));
        }
        Ok(())
    }
}

fn send_disconnect(writer: &mut CipherWriter, reason: &[u8]) -> io::Result<()> {
    let mut fields = Vec::new();
    put_field(&mut fields, reason);
    writer.send(encode_packet(0, &fields)?)
}

fn status_query<T>((mut reader, mut writer): TcpPair) -> io::Result<T> {
    for _ in 0..2 {
        let packet = read_packet(&mut reader)?;
        match packet.id {
            0 => {
                let mut fields = Vec::new();
                put_field(&mut fields, STATUS_RESPONSE);
                send_packet(&mut writer, 0, &fields)?;
            }
            1 => {
                let payload = packet
                    .data()
                    .first_chunk::<8>()
                    .ok_or(io::ErrorKind::UnexpectedEof)?;
                send_packet(&mut writer, 1, payload)?;
            }
            _ => {}
        }
    }
    Err(io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "XMC status exchange finished",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1::EncodeRsaPrivateKey;

    #[test]
    fn password_derives_the_xray_golden_key() {
        let private = derive_key(b"deterministic-rsa-key-golden").unwrap();
        let der = private.to_pkcs1_der().unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(der.as_bytes())),
            "3a8c4ad56a6fb42dab73c4d5fc3af754460a2db1441edc0970cbc7f4e0798d2f",
        );
    }

    #[test]
    fn accepts_google_uuid_forms_and_rejects_vless_custom_ids() {
        let uuid = "db275cb4-f058-4073-897b-a45f265120ba";
        let expected = profile_uuid(uuid).unwrap();
        assert_eq!(profile_uuid(&uuid.replace('-', "")).unwrap(), expected);
        assert_eq!(profile_uuid(&format!("{{{uuid}}}")).unwrap(), expected);
        assert_eq!(profile_uuid(&format!("URN:UUID:{uuid}")).unwrap(), expected);
        assert!(profile_uuid("a-custom-vless-id").is_err());
    }
}
