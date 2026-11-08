use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kerlico_outbound::Exit;
use kerlico_shared::{Destination, Transport};

const IDLE: Duration = Duration::from_secs(300);

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub struct Key {
    source: SocketAddr,
    host: String,
    port: u16,
}

pub fn key_from(source: Option<SocketAddr>, destination: &Destination) -> Option<Key> {
    if destination.transport() != Transport::Udp {
        return None;
    }
    Some(Key {
        source: source?,
        host: destination.host().to_ascii_lowercase(),
        port: destination.port(),
    })
}

#[derive(Clone)]
pub struct Table {
    inner: Arc<Mutex<BTreeMap<Key, Slot>>>,
}

struct Slot {
    exit: Exit,
    seen: Instant,
}

impl Table {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    fn lookup(&self, key: &Key, now: Instant) -> Option<Exit> {
        let mut map = self.inner.lock().expect("udp");
        sweep(&mut map, now);
        let slot = map.get_mut(key)?;
        slot.seen = now;
        Some(slot.exit)
    }

    fn store(&self, key: Key, exit: Exit, now: Instant) {
        let mut map = self.inner.lock().expect("udp");
        sweep(&mut map, now);
        map.insert(key, Slot { exit, seen: now });
    }

    pub fn end(&self, key: &Key) {
        self.inner.lock().expect("udp").remove(key);
    }
}

pub fn adopt(
    table: &Table,
    key: Option<&Key>,
    now: Instant,
    choose: impl FnOnce() -> Result<Exit, ()>,
) -> Result<Exit, ()> {
    if let Some(key) = key {
        if let Some(exit) = table.lookup(key, now) {
            return Ok(exit);
        }
    }
    let exit = choose()?;
    if let Some(key) = key {
        table.store(key.clone(), exit, now);
    }
    Ok(exit)
}

fn sweep(map: &mut BTreeMap<Key, Slot>, now: Instant) {
    map.retain(|_, slot| now.saturating_duration_since(slot.seen) < IDLE);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn key(port: u16) -> Key {
        Key {
            source: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 8), 40000)),
            host: "1.1.1.1".to_string(),
            port,
        }
    }

    #[test]
    fn later_packet_keeps_the_first_exit_until_idle() {
        let table = Table::new();
        let saved = key(53);
        let start = Instant::now();
        let first = adopt(&table, Some(&saved), start, || Ok(Exit::NativeV4)).unwrap();
        let second = adopt(&table, Some(&saved), start + Duration::from_secs(200), || {
            Ok(Exit::WarpV4)
        })
        .unwrap();
        let after_idle = adopt(&table, Some(&saved), start + Duration::from_secs(501), || {
            Ok(Exit::WarpV4)
        })
        .unwrap();
        assert_eq!(first, Exit::NativeV4);
        assert_eq!(second, Exit::NativeV4);
        assert_eq!(after_idle, Exit::WarpV4);
        table.end(&saved);
        let fresh = adopt(&table, Some(&saved), start + Duration::from_secs(502), || {
            Ok(Exit::NativeV6)
        })
        .unwrap();
        assert_eq!(fresh, Exit::NativeV6);
        let other = adopt(&table, Some(&key(54)), start + Duration::from_secs(502), || {
            Ok(Exit::WarpV6)
        })
        .unwrap();
        assert_eq!(other, Exit::WarpV6);
    }
}
