//! WireGuard Noise_IKpsk2. The server is the initiator. Reserved bytes stay outside this module.

use std::collections::VecDeque;

use blake2::digest::consts::U16;
use blake2::digest::{Digest, FixedOutput, KeyInit, Mac, Update};
use blake2::{Blake2s256, Blake2sMac};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};
use hmac::SimpleHmac;
use rand_core::OsRng;
use x25519_dalek::{PublicKey, ReusableSecret, StaticSecret};

const CHAIN: [u8; 32] = [
    96, 226, 109, 174, 243, 39, 239, 192, 46, 195, 53, 226, 160, 37, 210, 208, 22, 235, 66, 6, 248,
    114, 119, 245, 45, 56, 209, 152, 139, 120, 205, 54,
];
const HASH0: [u8; 32] = [
    34, 17, 179, 97, 8, 26, 197, 102, 105, 18, 67, 219, 69, 138, 213, 50, 45, 156, 108, 102, 34,
    147, 232, 183, 14, 225, 156, 101, 186, 7, 158, 243,
];

type HmacB = SimpleHmac<Blake2s256>;
type Mac16 = Blake2sMac<U16>;

struct Pending {
    local: u32,
    chain: [u8; 32],
    hash: [u8; 32],
    ephemeral: ReusableSecret,
}

struct Keys {
    send: [u8; 32],
    recv: [u8; 32],
    remote: u32,
}

pub struct Link {
    private: StaticSecret,
    public: PublicKey,
    peer: PublicKey,
    mac1_key: [u8; 32],
    cookie: Option<[u8; 16]>,
    last_mac1: [u8; 16],
    pending: Option<Pending>,
    keys: Option<Keys>,
    send_n: u64,
    recv_n: u64,
    index: u32,
    queued: VecDeque<Vec<u8>>,
}

impl Link {
    pub fn new(private_key: [u8; 32], peer_public: [u8; 32]) -> Self {
        let private = StaticSecret::from(private_key);
        let public = PublicKey::from(&private);
        let peer = PublicKey::from(peer_public);
        Self {
            mac1_key: mix(b"mac1----", peer.as_bytes()),
            private,
            public,
            peer,
            cookie: None,
            last_mac1: [0; 16],
            pending: None,
            keys: None,
            send_n: 0,
            recv_n: 0,
            index: 1,
            queued: VecDeque::new(),
        }
    }

    pub fn ready(&self) -> bool {
        self.keys.is_some()
    }

    pub fn initiation(&mut self) -> Vec<u8> {
        let ephemeral = ReusableSecret::random_from_rng(OsRng);
        let ephemeral_public = PublicKey::from(&ephemeral);
        let local = self.index;
        self.index = self.index.wrapping_add(1).max(1);
        let mut hash = mix(&HASH0, self.peer.as_bytes());
        hash = mix(&hash, ephemeral_public.as_bytes());
        let mut chain = kdf1(&CHAIN, ephemeral_public.as_bytes());
        let shared = ephemeral.diffie_hellman(&self.peer);
        let (chain2, key) = kdf2(&chain, shared.as_bytes());
        chain = chain2;
        let mut msg = vec![0u8; 148];
        msg[0] = 1;
        msg[4..8].copy_from_slice(&local.to_le_bytes());
        msg[8..40].copy_from_slice(ephemeral_public.as_bytes());
        seal(&mut msg[40..88], &key, self.public.as_bytes(), &hash);
        hash = mix(&hash, &msg[40..88]);
        let ss = self.private.diffie_hellman(&self.peer);
        let (chain3, key) = kdf2(&chain, ss.as_bytes());
        seal(&mut msg[88..116], &key, &tai64n(), &hash);
        hash = mix(&hash, &msg[88..116]);
        mac(&mut msg, &self.mac1_key, &self.cookie);
        self.last_mac1.copy_from_slice(&msg[116..132]);
        self.pending = Some(Pending {
            local,
            chain: chain3,
            hash,
            ephemeral,
        });
        msg
    }

    pub fn queue(&mut self, packet: Vec<u8>) {
        if self.queued.len() < 32 {
            self.queued.push_back(packet);
        }
    }

    pub fn drain(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while let Some(packet) = self.queued.pop_front() {
            if let Some(sealed) = self.seal(&packet) {
                out.push(sealed);
            } else {
                self.queued.push_front(packet);
                break;
            }
        }
        out
    }

    pub fn seal(&mut self, packet: &[u8]) -> Option<Vec<u8>> {
        let keys = self.keys.as_ref()?;
        let counter = self.send_n;
        self.send_n = self.send_n.wrapping_add(1);
        let mut msg = vec![0u8; 16 + packet.len() + 16];
        msg[0] = 4;
        msg[4..8].copy_from_slice(&keys.remote.to_le_bytes());
        msg[8..16].copy_from_slice(&counter.to_le_bytes());
        seal_at(&mut msg[16..], &keys.send, counter, packet, &[]);
        Some(msg)
    }

    pub fn input(&mut self, msg: &[u8]) -> Option<Vec<u8>> {
        if msg.len() < 4 {
            return None;
        }
        match u32::from_le_bytes(msg[0..4].try_into().ok()?) {
            2 => {
                self.consume_response(msg);
                None
            }
            3 => {
                self.consume_cookie(msg);
                None
            }
            4 => self.open_transport(msg),
            _ => None,
        }
    }

    fn consume_response(&mut self, msg: &[u8]) -> bool {
        if msg.len() < 92 {
            return false;
        }
        let pending = match self.pending.take() {
            Some(pending) => pending,
            None => return false,
        };
        let receiver = u32::from_le_bytes(msg[8..12].try_into().unwrap());
        if receiver != pending.local {
            self.pending = Some(pending);
            return false;
        }
        let mut hash = mix(&pending.hash, &msg[12..44]);
        let mut chain = kdf1(&pending.chain, &msg[12..44]);
        let peer_eph = PublicKey::from(<[u8; 32]>::try_from(&msg[12..44]).unwrap());
        chain = kdf1(&chain, pending.ephemeral.diffie_hellman(&peer_eph).as_bytes());
        chain = kdf1(&chain, self.private.diffie_hellman(&peer_eph).as_bytes());
        let (chain2, mixed, key) = kdf3(&chain, &[0u8; 32]);
        hash = mix(&hash, &mixed);
        if open(&key, &msg[44..60], &hash).is_none() {
            return false;
        }
        let (send, recv) = transport_keys(&chain2);
        self.keys = Some(Keys {
            send,
            recv,
            remote: u32::from_le_bytes(msg[4..8].try_into().unwrap()),
        });
        self.send_n = 0;
        self.recv_n = 0;
        true
    }

    fn consume_cookie(&mut self, msg: &[u8]) {
        if msg.len() < 64 {
            return;
        }
        let key = mix(b"cookie--", self.peer.as_bytes());
        let cipher = XChaCha20Poly1305::new((&key).into());
        let Ok(nonce) = <[u8; 24]>::try_from(&msg[8..32]) else {
            return;
        };
        let Ok(body) = cipher.decrypt(
            nonce.as_slice().into(),
            Payload { msg: &msg[32..64], aad: &self.last_mac1 },
        ) else {
            return;
        };
        if body.len() == 16 {
            let mut cookie = [0u8; 16];
            cookie.copy_from_slice(&body);
            self.cookie = Some(cookie);
        }
    }

    fn open_transport(&mut self, msg: &[u8]) -> Option<Vec<u8>> {
        if msg.len() < 32 {
            return None;
        }
        let keys = self.keys.as_ref()?;
        let counter = u64::from_le_bytes(msg[8..16].try_into().ok()?);
        if counter < self.recv_n {
            return None;
        }
        let plain = open_at(&keys.recv, counter, &msg[16..], &[])?;
        self.recv_n = counter.wrapping_add(1);
        Some(plain)
    }
}

fn transport_keys(chain: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let temp = hmac(chain, &[]);
    let send = hmac(&temp, &[1]);
    let recv = hmac2(&temp, &send, &[2]);
    (send, recv)
}

fn mac(msg: &mut [u8], mac1_key: &[u8; 32], cookie: &Option<[u8; 16]>) {
    let mac1_at = msg.len() - 32;
    let mac2_at = msg.len() - 16;
    let mac1 = mac16(mac1_key, &msg[..mac1_at]);
    msg[mac1_at..mac2_at].copy_from_slice(&mac1);
    let mac2 = if let Some(cookie) = cookie {
        mac16(cookie, &msg[..mac2_at])
    } else {
        [0u8; 16]
    };
    msg[mac2_at..].copy_from_slice(&mac2);
}

fn mix(left: &[u8], right: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2s256::new();
    Update::update(&mut hasher, left);
    Update::update(&mut hasher, right);
    hasher.finalize_fixed().into()
}

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <HmacB as KeyInit>::new_from_slice(key).expect("hmac");
    Mac::update(&mut mac, data);
    mac.finalize_fixed().into()
}

fn hmac2(key: &[u8], left: &[u8], right: &[u8]) -> [u8; 32] {
    let mut mac = <HmacB as KeyInit>::new_from_slice(key).expect("hmac");
    Mac::update(&mut mac, left);
    Mac::update(&mut mac, right);
    mac.finalize_fixed().into()
}

fn kdf1(key: &[u8], data: &[u8]) -> [u8; 32] {
    hmac(&hmac(key, data), &[1])
}

fn kdf2(key: &[u8], data: &[u8]) -> ([u8; 32], [u8; 32]) {
    let temp = hmac(key, data);
    let first = hmac(&temp, &[1]);
    let second = hmac2(&temp, &first, &[2]);
    (first, second)
}

fn kdf3(key: &[u8], data: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let temp = hmac(key, data);
    let first = hmac(&temp, &[1]);
    let second = hmac2(&temp, &first, &[2]);
    let third = hmac2(&temp, &second, &[3]);
    (first, second, third)
}

fn mac16(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac = <Mac16 as KeyInit>::new_from_slice(key).expect("mac");
    Mac::update(&mut mac, data);
    let out = mac.finalize_fixed();
    let mut result = [0u8; 16];
    result.copy_from_slice(out.as_slice());
    result
}

fn seal(dst: &mut [u8], key: &[u8; 32], plain: &[u8], aad: &[u8]) {
    seal_at(dst, key, 0, plain, aad);
}

fn open(key: &[u8; 32], body: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    open_at(key, 0, body, aad)
}

fn seal_at(dst: &mut [u8], key: &[u8; 32], counter: u64, plain: &[u8], aad: &[u8]) {
    let cipher = ChaCha20Poly1305::new(key.into());
    let sealed = cipher
        .encrypt(nonce(counter).as_slice().into(), Payload { msg: plain, aad })
        .expect("seal");
    dst[..sealed.len()].copy_from_slice(&sealed);
}

fn open_at(key: &[u8; 32], counter: u64, body: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(nonce(counter).as_slice().into(), Payload { msg: body, aad })
        .ok()
}

fn nonce(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&counter.to_le_bytes());
    nonce
}

fn tai64n() -> [u8; 12] {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let seconds = now.as_secs().saturating_add(1 << 62);
    let mut out = [0u8; 12];
    out[..8].copy_from_slice(&seconds.to_be_bytes());
    out[8..].copy_from_slice(&now.subsec_nanos().to_be_bytes());
    out
}

#[cfg(test)]
pub fn answer(private_key: [u8; 32], peer_public: [u8; 32], init: &[u8]) -> Option<(Vec<u8>, [u8; 32], [u8; 32])> {
    if init.len() < 148 || init[0] != 1 {
        return None;
    }
    let private = StaticSecret::from(private_key);
    let public = PublicKey::from(&private);
    let peer = PublicKey::from(peer_public);
    let mut hash = mix(&HASH0, public.as_bytes());
    let peer_eph = PublicKey::from(<[u8; 32]>::try_from(&init[8..40]).ok()?);
    hash = mix(&hash, peer_eph.as_bytes());
    let mut chain = kdf1(&CHAIN, peer_eph.as_bytes());
    let (chain2, key) = kdf2(&chain, private.diffie_hellman(&peer_eph).as_bytes());
    chain = chain2;
    let static_bytes = open(&key, &init[40..88], &hash)?;
    if static_bytes.as_slice() != peer.as_bytes() {
        return None;
    }
    hash = mix(&hash, &init[40..88]);
    let (chain3, key) = kdf2(&chain, private.diffie_hellman(&peer).as_bytes());
    open(&key, &init[88..116], &hash)?;
    hash = mix(&hash, &init[88..116]);
    let ephemeral = ReusableSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral);
    let mut msg = vec![0u8; 92];
    msg[0] = 2;
    msg[4..8].copy_from_slice(&7u32.to_le_bytes());
    msg[8..12].copy_from_slice(&u32::from_le_bytes(init[4..8].try_into().ok()?).to_le_bytes());
    msg[12..44].copy_from_slice(ephemeral_public.as_bytes());
    hash = mix(&hash, ephemeral_public.as_bytes());
    chain = kdf1(&chain3, ephemeral_public.as_bytes());
    chain = kdf1(&chain, ephemeral.diffie_hellman(&peer_eph).as_bytes());
    chain = kdf1(&chain, ephemeral.diffie_hellman(&peer).as_bytes());
    let (chain4, mixed, key) = kdf3(&chain, &[0u8; 32]);
    hash = mix(&hash, &mixed);
    seal(&mut msg[44..60], &key, &[], &hash);
    let mac1_key = mix(b"mac1----", peer.as_bytes());
    mac(&mut msg, &mac1_key, &None);
    let (recv, send) = transport_keys(&chain4);
    Some((msg, send, recv))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_peers_open_each_others_transport() {
        use rand_core::RngCore;
        let mut left_bytes = [0u8; 32];
        let mut right_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut left_bytes);
        OsRng.fill_bytes(&mut right_bytes);
        let left = StaticSecret::from(left_bytes);
        let right = StaticSecret::from(right_bytes);
        let mut initiator = Link::new(left.to_bytes(), *PublicKey::from(&right).as_bytes());
        let init = initiator.initiation();
        let (response, responder_send, responder_recv) =
            answer(right.to_bytes(), *PublicKey::from(&left).as_bytes(), &init).unwrap();
        assert!(initiator.input(&response).is_none());
        assert!(initiator.ready());
        let sealed = initiator.seal(b"ping").unwrap();
        let keys = initiator.keys.as_ref().unwrap();
        assert_eq!(keys.send, responder_recv);
        assert_eq!(keys.recv, responder_send);
        let plain = open(&responder_recv, &sealed[16..], &[]).unwrap();
        assert_eq!(plain, b"ping");
    }
}
