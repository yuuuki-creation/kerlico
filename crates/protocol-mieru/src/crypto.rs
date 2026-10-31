//! TCP nonce 每次运算递增；旧 UDP 同段复用仅由明确的本地兼容入口调用。
use crate::config::User;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use kerlico_core::{Error, Result};
use pbkdf2::pbkdf2_hmac;
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;
pub(crate) fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|_| Error::Rejected)
}
pub(crate) fn epoch(seconds: u64) -> u64 {
    seconds.saturating_add(60) / 120 * 120
}
pub(crate) fn key_bytes(user: &User, bucket: u64) -> Zeroizing<[u8; 32]> {
    let salt = Sha256::digest(bucket.to_be_bytes());
    let mut key = Zeroizing::new([0; 32]);
    pbkdf2_hmac::<Sha256>(&user.secret[..], &salt, 64, &mut key[..]);
    key
}
pub(crate) fn hint(user: &User, nonce: &[u8; 24]) -> [u8; 4] {
    let mut hash = Sha256::new();
    hash.update(user.name.as_bytes());
    hash.update(&nonce[..16]);
    hash.finalize()[..4].try_into().expect("固定 hint 长度")
}
pub(crate) struct Key {
    pub user: Arc<User>,
    cipher: XChaCha20Poly1305,
}
impl Key {
    pub fn new(user: Arc<User>, bucket: u64) -> Arc<Self> {
        let key = key_bytes(&user, bucket);
        Arc::new(Self {
            user,
            cipher: XChaCha20Poly1305::new_from_slice(&key[..]).expect("固定密钥长度"),
        })
    }
    pub fn seal(&self, nonce: &[u8; 24], plain: &[u8]) -> Result<Vec<u8>> {
        self.cipher
            .encrypt(XNonce::from_slice(nonce), plain)
            .map_err(|_| Error::Rejected)
    }
    pub fn open(&self, nonce: &[u8; 24], encrypted: &[u8]) -> Result<Vec<u8>> {
        self.cipher
            .decrypt(XNonce::from_slice(nonce), encrypted)
            .map_err(|_| Error::Rejected)
    }
    pub fn nonce(&self) -> Result<[u8; 24]> {
        let mut nonce = [0; 24];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| Error::Rejected)?;
        let stamp = hint(&self.user, &nonce);
        nonce[20..].copy_from_slice(&stamp);
        Ok(nonce)
    }
}
struct KeyCache {
    epoch: u64,
    keys: HashMap<(usize, u64), Arc<Key>>,
}
pub(crate) struct Users {
    pub entries: Vec<Arc<User>>,
    required: bool,
    cache: Mutex<KeyCache>,
}
impl Users {
    pub fn new(entries: Vec<Arc<User>>, required: bool) -> Self {
        Self {
            entries,
            required,
            cache: Mutex::new(KeyCache {
                epoch: u64::MAX,
                keys: HashMap::new(),
            }),
        }
    }
    pub fn select(
        &self,
        nonce: &[u8; 24],
        encrypted: &[u8],
        known: &[Arc<Key>],
    ) -> Result<(Arc<Key>, [u8; 32])> {
        for key in known {
            if let Ok(plain) = key.open(nonce, encrypted)
                && let Ok(meta) = <[u8; 32]>::try_from(plain)
            {
                return Ok((key.clone(), meta));
            }
        }
        let current = epoch(now()?);
        let mut cache = self.cache.lock().map_err(|_| Error::Rejected)?;
        if cache.epoch != current {
            cache.keys.clear();
            cache.epoch = current;
        }
        for (index, user) in self.entries.iter().enumerate() {
            if self.required && hint(user, nonce) != nonce[20..] {
                continue;
            }
            for bucket in [
                current.saturating_sub(120),
                current,
                current.saturating_add(120),
            ] {
                let key = cache
                    .keys
                    .entry((index, bucket))
                    .or_insert_with(|| Key::new(user.clone(), bucket));
                if let Ok(plain) = key.open(nonce, encrypted)
                    && let Ok(meta) = <[u8; 32]>::try_from(plain)
                {
                    return Ok((key.clone(), meta));
                }
            }
        }
        Err(Error::Rejected)
    }
}
pub(crate) struct StreamCipher {
    pub key: Arc<Key>,
    nonce: Option<[u8; 24]>,
    poisoned: bool,
}
impl StreamCipher {
    pub fn new(key: Arc<Key>) -> Self {
        Self {
            key,
            nonce: None,
            poisoned: false,
        }
    }
    pub fn first_len(&self) -> usize {
        if self.nonce.is_none() { 72 } else { 48 }
    }
    pub fn from_metadata(key: Arc<Key>, nonce: [u8; 24]) -> Self {
        Self {
            key,
            nonce: Some(nonce),
            poisoned: false,
        }
    }
    fn advance(&mut self) -> Result<[u8; 24]> {
        if self.poisoned {
            return Err(Error::Rejected);
        }
        if let Some(nonce) = &mut self.nonce {
            for byte in nonce.iter_mut().rev() {
                *byte = byte.wrapping_add(1);
                if *byte != 0 {
                    return Ok(*nonce);
                }
            }
            self.poisoned = true;
            return Err(Error::Rejected);
        }
        let nonce = self.key.nonce()?;
        self.nonce = Some(nonce);
        Ok(nonce)
    }
    pub fn seal(&mut self, plain: &[u8]) -> Result<Vec<u8>> {
        let first = self.nonce.is_none();
        let nonce = self.advance()?;
        let result = self.key.seal(&nonce, plain);
        match result {
            Ok(encrypted) => {
                let mut out = Vec::with_capacity(encrypted.len() + usize::from(first) * 24);
                if first {
                    out.extend(nonce);
                }
                out.extend(encrypted);
                Ok(out)
            }
            Err(error) => {
                self.poisoned = true;
                Err(error)
            }
        }
    }
    pub fn open(&mut self, encrypted: &[u8]) -> Result<Vec<u8>> {
        if self.poisoned {
            return Err(Error::Rejected);
        }
        let (nonce, encrypted) = if self.nonce.is_none() {
            if encrypted.len() < 40 {
                self.poisoned = true;
                return Err(Error::Rejected);
            }
            let nonce = encrypted[..24].try_into().expect("已检查 nonce 长度");
            self.nonce = Some(nonce);
            (nonce, &encrypted[24..])
        } else {
            (self.advance()?, encrypted)
        };
        match self.key.open(&nonce, encrypted) {
            Ok(plain) => Ok(plain),
            Err(error) => {
                self.poisoned = true;
                Err(error)
            }
        }
    }
}
/// 仅记录已完整校验的首次打开；未到期条目达到上限时拒绝新增，不能驱逐后放行重放。
type ReplayState = (HashSet<[u8; 32]>, VecDeque<(Instant, [u8; 32])>);
pub(crate) struct Replay {
    state: Mutex<ReplayState>,
}
impl Replay {
    pub fn new() -> Self {
        Self {
            state: Mutex::new((HashSet::new(), VecDeque::new())),
        }
    }
    pub fn accept(&self, key: &Key, nonce: &[u8; 24]) -> Result<()> {
        let mut hash = Sha256::new();
        hash.update(key.user.fingerprint());
        hash.update(nonce);
        let id: [u8; 32] = hash.finalize().into();
        let mut state = self.state.lock().map_err(|_| Error::Rejected)?;
        let now = Instant::now();
        while state
            .1
            .front()
            .is_some_and(|(time, _)| now.duration_since(*time) >= Duration::from_secs(360))
        {
            if let Some((_, old)) = state.1.pop_front() {
                state.0.remove(&old);
            }
        }
        if state.0.contains(&id) {
            return Err(Error::Rejected);
        }
        if state.0.len() >= 16384 {
            return Err(Error::ResourceLimit);
        }
        state.0.insert(id);
        state.1.push_back((now, id));
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stream_counter_is_big_endian_and_poisoned_on_wrap_or_authentication_error() {
        let user = User::new("node-user".into(), "synthetic-password".into()).unwrap();
        let key = Key::new(user, 1_700_000_040);
        let mut nonce = [0; 24];
        nonce[23] = 255;
        let mut cipher = StreamCipher::from_metadata(key.clone(), nonce);
        let next = cipher.advance().unwrap();
        assert_eq!(next[22], 1);
        assert_eq!(next[23], 0);
        let mut wrapped = StreamCipher::from_metadata(key.clone(), [255; 24]);
        assert!(wrapped.advance().is_err());
        assert!(wrapped.advance().is_err());
        let mut bad = StreamCipher::new(key);
        assert!(bad.open(&[0; 72]).is_err());
        assert!(bad.open(&[0; 72]).is_err());
        assert_eq!(epoch(119), 120);
        assert_eq!(epoch(60), 120);
        assert_eq!(epoch(59), 0);
    }
}
