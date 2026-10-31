use crate::{invalid, now};
use kerlico_core::{Error, Result};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeSet, HashSet},
    sync::Mutex,
    time::{Duration, Instant},
};
struct Entries {
    keys: HashSet<[u8; 32]>,
    expiry: BTreeSet<(Instant, [u8; 32])>,
}
pub(crate) struct Replay {
    entries: Mutex<Entries>,
    maximum: usize,
}
impl Replay {
    pub(crate) fn new(maximum: usize) -> Self {
        Self {
            entries: Mutex::new(Entries {
                keys: HashSet::new(),
                expiry: BTreeSet::new(),
            }),
            maximum,
        }
    }
    pub(crate) fn insert(&self, tag: &[u8], data: &[u8], ttl: Duration) -> Result<()> {
        let mut digest = Sha256::new();
        digest.update(tag);
        digest.update(data);
        let key: [u8; 32] = digest.finalize().into();
        let mut entries = self.entries.lock().map_err(|_| invalid())?;
        let moment = Instant::now();
        while entries
            .expiry
            .first()
            .is_some_and(|(expiry, _)| *expiry <= moment)
        {
            let (_, key) = entries.expiry.pop_first().expect("到期项存在");
            entries.keys.remove(&key);
        }
        if entries.keys.contains(&key) {
            return Err(invalid());
        }
        if entries.keys.len() >= self.maximum {
            return Err(Error::ResourceLimit);
        }
        entries.keys.insert(key);
        entries.expiry.insert((moment + ttl, key));
        Ok(())
    }
    pub(crate) fn nonce(&self, iv: &[u8]) -> Result<()> {
        if iv.is_empty() {
            return Ok(());
        }
        self.insert(b"cipher-iv", iv, Duration::from_secs(120))
    }
    pub(crate) fn auth(
        &self,
        protocol: &[u8],
        user: u32,
        header: &[u8],
        window: u32,
        time: u32,
    ) -> Result<()> {
        if header.len() < 12 {
            return Err(invalid());
        }
        let stamp = u32::from_le_bytes(header[..4].try_into().map_err(|_| invalid())?);
        let delta = stamp.wrapping_sub(time) as i32;
        if i64::from(delta).abs() > i64::from(window) {
            return Err(invalid());
        }
        let mut data = protocol.to_vec();
        data.extend_from_slice(&user.to_le_bytes());
        data.extend_from_slice(&header[4..12]);
        let remaining = (i64::from(window) + i64::from(delta) + 1) as u64;
        self.insert(b"protocol-auth", &data, Duration::from_secs(remaining))
    }
    pub(crate) fn tls(&self, verify: &[u8], window: u32) -> Result<()> {
        if verify.len() != 22 {
            return Err(invalid());
        }
        let stamp = u32::from_be_bytes(verify[..4].try_into().map_err(|_| invalid())?);
        let delta = stamp.wrapping_sub(now()) as i32;
        if i64::from(delta).abs() > i64::from(window) {
            return Err(invalid());
        }
        self.insert(
            b"tls-auth",
            verify,
            Duration::from_secs((i64::from(window) + i64::from(delta) + 1) as u64),
        )
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn duplicate_expiry_and_capacity_are_bounded() {
        let expired = Replay::new(1);
        assert!(expired.insert(b"x", b"a", Duration::ZERO).is_ok());
        assert!(expired.insert(b"x", b"b", Duration::from_secs(60)).is_ok());
        let cache = Replay::new(2);
        assert!(cache.insert(b"x", b"a", Duration::from_secs(60)).is_ok());
        assert!(cache.insert(b"x", b"a", Duration::from_secs(60)).is_err());
        assert!(cache.insert(b"x", b"b", Duration::from_secs(60)).is_ok());
        assert!(matches!(
            cache.insert(b"x", b"c", Duration::from_secs(60)),
            Err(Error::ResourceLimit)
        ));
    }
}
