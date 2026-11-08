use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};

/// Maps the process's fake answers back to the names that produced them.
#[derive(Clone)]
pub struct Pool {
    inner: Arc<Mutex<State>>,
}

struct State {
    by_ip: BTreeMap<IpAddr, String>,
    by_v4: BTreeMap<String, Ipv4Addr>,
    by_v6: BTreeMap<String, Ipv6Addr>,
    v4: u32,
    v6: u128,
}

impl Pool {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(State {
                by_ip: BTreeMap::new(),
                by_v4: BTreeMap::new(),
                by_v6: BTreeMap::new(),
                v4: u32::from(Ipv4Addr::new(198, 18, 0, 1)),
                v6: u128::from(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1)),
            })),
        }
    }

    pub fn rewrite(&self, ip: IpAddr) -> Option<String> {
        self.inner.lock().expect("fakedns").by_ip.get(&ip).cloned()
    }

    pub fn assign_v4(&self, host: &str) -> Ipv4Addr {
        let host = normalize(host);
        let mut state = self.inner.lock().expect("fakedns");
        if let Some(ip) = state.by_v4.get(&host) {
            return *ip;
        }
        let ip = Ipv4Addr::from(state.v4);
        state.v4 = next_v4(state.v4);
        if let Some(old) = state.by_ip.insert(IpAddr::V4(ip), host.clone()) {
            state.by_v4.remove(&old);
        }
        state.by_v4.insert(host, ip);
        ip
    }

    pub fn assign_v6(&self, host: &str) -> Ipv6Addr {
        let host = normalize(host);
        let mut state = self.inner.lock().expect("fakedns");
        if let Some(ip) = state.by_v6.get(&host) {
            return *ip;
        }
        let ip = Ipv6Addr::from(state.v6);
        state.v6 = state.v6.saturating_add(1);
        if let Some(old) = state.by_ip.insert(IpAddr::V6(ip), host.clone()) {
            state.by_v6.remove(&old);
        }
        state.by_v6.insert(host, ip);
        ip
    }
}

fn normalize(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

fn next_v4(current: u32) -> u32 {
    let [a, b, c, d] = Ipv4Addr::from(current).octets();
    if a == 198 && b == 19 && c == 255 && d == 255 {
        u32::from(Ipv4Addr::new(198, 18, 0, 1))
    } else {
        current.saturating_add(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assigned_address_rewrites_to_the_same_name() {
        let pool = Pool::new();
        let ip = pool.assign_v4("example.com");
        assert_eq!(pool.rewrite(IpAddr::V4(ip)).as_deref(), Some("example.com"));
        assert!(ip.octets()[0] == 198 && (ip.octets()[1] == 18 || ip.octets()[1] == 19));
    }
}
