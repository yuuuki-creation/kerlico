//! 节点级客户端登记：`max-clients` 名额、地址池租约、`duplicate-cn` 与 peer-id 分配。
//!
//! 每个会话持有一张 [`Ticket`]；票据析构时归还名额、地址与身份，会话以任何方式结束都会释放。

use kerlico_core::{CancellationToken, Error, Result};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    net::{Ipv4Addr, Ipv6Addr},
    sync::{Arc, Mutex, MutexGuard},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Topology {
    Subnet,
    Net30,
    P2p,
}
impl Topology {
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "subnet" => Some(Self::Subnet),
            "net30" => Some(Self::Net30),
            "p2p" => Some(Self::P2p),
            _ => None,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Subnet => "subnet",
            Self::Net30 => "net30",
            Self::P2p => "p2p",
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct V4Net {
    server: u32,
    network: u32,
    prefix: u8,
}
#[derive(Clone, Copy, Debug)]
struct V6Net {
    server: u128,
    network: u128,
    prefix: u8,
}

/// 上游 `server-ipv6` 从 `::1000` 起分配客户端地址。
const V6_FIRST_HOST: u128 = 0x1000;

/// 客户端隧道参数。`peer` 在 subnet 下是 `route-gateway`，在 net30/p2p 下是 `ifconfig` 的对端地址。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct V4Assignment {
    pub client: Ipv4Addr,
    pub peer: Ipv4Addr,
    pub netmask: Ipv4Addr,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct V6Assignment {
    pub client: Ipv6Addr,
    pub server: Ipv6Addr,
    pub prefix: u8,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Assignment {
    pub topology: Topology,
    pub server_v4: Option<Ipv4Addr>,
    pub v4: Option<V4Assignment>,
    pub v6: Option<V6Assignment>,
}
impl Assignment {
    fn contains(&self, address: std::net::IpAddr) -> bool {
        match address {
            std::net::IpAddr::V4(address) => self.v4.is_some_and(|v4| v4.client == address),
            std::net::IpAddr::V6(address) => self.v6.is_some_and(|v6| v6.client == address),
        }
    }
}

/// 地址池只做下标与地址的换算；占用状态由 [`Registry`] 维护。
#[derive(Clone, Debug)]
pub(crate) struct AddressPool {
    topology: Topology,
    v4: Option<V4Net>,
    v6: Option<V6Net>,
    capacity: u32,
}
impl AddressPool {
    /// `prefixes` 为服务端自身地址加前缀长度，如 `10.8.0.1/24`、`fd00:8::1/64`，每个地址族最多一个。
    pub fn new(topology: Topology, prefixes: &[String]) -> Result<Self> {
        let invalid = |text: &str| Error::Config(format!("OpenVPN 地址前缀不合法：{text}"));
        let mut v4 = None;
        let mut v6 = None;
        for text in prefixes {
            let (address, prefix) = text.split_once('/').ok_or_else(|| invalid(text))?;
            let prefix: u8 = prefix.trim().parse().map_err(|_| invalid(text))?;
            match address
                .trim()
                .parse::<std::net::IpAddr>()
                .map_err(|_| invalid(text))?
            {
                std::net::IpAddr::V4(address) if prefix <= 30 && v4.is_none() => {
                    let server = u32::from(address);
                    let network = server & (u32::MAX << (32 - prefix));
                    let broadcast = network | !(u32::MAX << (32 - prefix));
                    if server == network || server == broadcast {
                        return Err(invalid(text));
                    }
                    v4 = Some(V4Net {
                        server,
                        network,
                        prefix,
                    });
                }
                std::net::IpAddr::V6(address) if (64..=124).contains(&prefix) && v6.is_none() => {
                    let server = u128::from(address);
                    let network = server & (u128::MAX << (128 - prefix));
                    v6 = Some(V6Net {
                        server,
                        network,
                        prefix,
                    });
                }
                _ => return Err(invalid(text)),
            }
        }
        if v4.is_none() && v6.is_none() {
            return Err(Error::Config("OpenVPN 至少需要一个地址前缀".into()));
        }
        let v4_capacity = v4.map(|net| match topology {
            Topology::Net30 => (1u64 << (32 - net.prefix)) / 4 - 1,
            Topology::Subnet | Topology::P2p => (1u64 << (32 - net.prefix)) - 3,
        });
        let v6_capacity = v6.map(|net| {
            let hosts = 1u128 << (128 - net.prefix);
            (hosts.saturating_sub(V6_FIRST_HOST + 2)).min(u128::from(u32::MAX)) as u64
        });
        let capacity = [v4_capacity, v6_capacity]
            .into_iter()
            .flatten()
            .min()
            .unwrap_or(0);
        if capacity == 0 {
            return Err(Error::Config("OpenVPN 地址前缀容纳不下任何客户端".into()));
        }
        Ok(Self {
            topology,
            v4,
            v6,
            capacity: capacity.min(u64::from(u32::MAX)) as u32,
        })
    }

    pub fn capacity(&self) -> u32 {
        self.capacity
    }

    pub fn assignment(&self, slot: u32) -> Assignment {
        let v4 = self.v4.map(|net| {
            let mask = u32::MAX << (32 - net.prefix);
            match self.topology {
                Topology::Net30 => {
                    let server_block = (net.server - net.network) / 4;
                    let block = if slot >= server_block { slot + 1 } else { slot };
                    let base = net.network + block * 4;
                    V4Assignment {
                        client: Ipv4Addr::from(base + 2),
                        peer: Ipv4Addr::from(base + 1),
                        netmask: Ipv4Addr::from(u32::MAX << 2),
                    }
                }
                Topology::Subnet | Topology::P2p => {
                    let mut host = net.network + 1 + slot;
                    if host >= net.server {
                        host += 1;
                    }
                    V4Assignment {
                        client: Ipv4Addr::from(host),
                        peer: Ipv4Addr::from(net.server),
                        netmask: Ipv4Addr::from(mask),
                    }
                }
            }
        });
        let v6 = self.v6.map(|net| {
            let mut host = net.network + V6_FIRST_HOST + u128::from(slot);
            if host >= net.server && net.server >= net.network + V6_FIRST_HOST {
                host += 1;
            }
            V6Assignment {
                client: Ipv6Addr::from(host),
                server: Ipv6Addr::from(net.server),
                prefix: net.prefix,
            }
        });
        Assignment {
            topology: self.topology,
            server_v4: self.v4.map(|net| Ipv4Addr::from(net.server)),
            v4,
            v6,
        }
    }

    /// 固定地址换回下标；不在池内或与服务端地址冲突时返回 `None`。
    pub fn slot_of(&self, address: std::net::IpAddr) -> Option<u32> {
        let slot = match address {
            std::net::IpAddr::V4(address) => {
                let net = self.v4?;
                let address = u32::from(address);
                let offset = address.checked_sub(net.network)?;
                match self.topology {
                    Topology::Net30 => {
                        let block = offset / 4;
                        let server_block = (net.server - net.network) / 4;
                        if offset % 4 != 2 || block == server_block {
                            return None;
                        }
                        block - u32::from(block > server_block)
                    }
                    Topology::Subnet | Topology::P2p => {
                        if offset == 0 || address == net.server {
                            return None;
                        }
                        offset - 1 - u32::from(address > net.server)
                    }
                }
            }
            std::net::IpAddr::V6(address) => {
                let net = self.v6?;
                let address = u128::from(address);
                let skip = net.server >= net.network + V6_FIRST_HOST && address > net.server;
                if address == net.server {
                    return None;
                }
                let offset = address.checked_sub(net.network + V6_FIRST_HOST)?;
                u32::try_from(offset - u128::from(skip)).ok()?
            }
        };
        (slot < self.capacity && self.assignment(slot).contains(address)).then_some(slot)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Refusal {
    Full,
    PoolExhausted,
}

struct Holder {
    ticket: u64,
    kick: CancellationToken,
}

struct State {
    active: usize,
    next_ticket: u64,
    /// 下标到持有票据。
    slots: BTreeMap<u32, u64>,
    identities: HashMap<String, Vec<Holder>>,
    peer_ids: BTreeSet<u32>,
}

pub(crate) struct Registry {
    pool: AddressPool,
    /// 用户固定地址占用的下标，不参与动态分配。
    reserved: BTreeSet<u32>,
    max_clients: usize,
    duplicate_cn: bool,
    state: Mutex<State>,
}
impl Registry {
    pub fn new(
        pool: AddressPool,
        reserved: BTreeSet<u32>,
        max_clients: usize,
        duplicate_cn: bool,
    ) -> Arc<Self> {
        Arc::new(Self {
            pool,
            reserved,
            max_clients,
            duplicate_cn,
            state: Mutex::new(State {
                active: 0,
                next_ticket: 1,
                slots: BTreeMap::new(),
                identities: HashMap::new(),
                peer_ids: BTreeSet::new(),
            }),
        })
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// 已建立与握手中的会话都占名额。
    pub fn admit(self: &Arc<Self>) -> std::result::Result<Ticket, Refusal> {
        let mut state = self.lock();
        if state.active >= self.max_clients {
            return Err(Refusal::Full);
        }
        state.active += 1;
        let id = state.next_ticket;
        state.next_ticket += 1;
        Ok(Ticket {
            registry: self.clone(),
            id,
            kick: CancellationToken::new(),
            lease: None,
        })
    }

    #[cfg(test)]
    pub fn active(&self) -> usize {
        self.lock().active
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Lease {
    #[cfg(test)]
    pub slot: u32,
    pub peer_id: u32,
    pub identity: String,
    pub assignment: Assignment,
}

pub(crate) struct Ticket {
    registry: Arc<Registry>,
    id: u64,
    kick: CancellationToken,
    lease: Option<Lease>,
}
impl Ticket {
    /// 被同名新会话顶替（未启用 `duplicate-cn`）时取消。
    pub fn kicked(&self) -> &CancellationToken {
        &self.kick
    }

    pub fn lease(&self) -> Option<&Lease> {
        self.lease.as_ref()
    }

    /// 认证通过后登记身份并分配地址；未启用 `duplicate-cn` 时先顶掉同名的旧会话。
    pub fn assign(
        &mut self,
        identity: &str,
        fixed: Option<u32>,
    ) -> std::result::Result<&Lease, Refusal> {
        let registry = self.registry.clone();
        let mut state = registry.lock();
        if !registry.duplicate_cn
            && let Some(holders) = state.identities.remove(identity)
        {
            for holder in holders {
                holder.kick.cancel();
                state.slots.retain(|_, owner| *owner != holder.ticket);
            }
        }
        let slot = fixed
            .filter(|slot| !state.slots.contains_key(slot))
            .or_else(|| {
                (0..registry.pool.capacity()).find(|slot| {
                    !registry.reserved.contains(slot) && !state.slots.contains_key(slot)
                })
            })
            .ok_or(Refusal::PoolExhausted)?;
        state.slots.insert(slot, self.id);
        let peer_id = (0..0x00ff_ffff)
            .find(|id| !state.peer_ids.contains(id))
            .ok_or(Refusal::PoolExhausted)?;
        state.peer_ids.insert(peer_id);
        state
            .identities
            .entry(identity.to_owned())
            .or_default()
            .push(Holder {
                ticket: self.id,
                kick: self.kick.clone(),
            });
        drop(state);
        Ok(self.lease.insert(Lease {
            #[cfg(test)]
            slot,
            peer_id,
            identity: identity.to_owned(),
            assignment: registry.pool.assignment(slot),
        }))
    }
}
impl Drop for Ticket {
    fn drop(&mut self) {
        let mut state = self.registry.lock();
        state.active -= 1;
        state.slots.retain(|_, owner| *owner != self.id);
        if let Some(lease) = &self.lease {
            state.peer_ids.remove(&lease.peer_id);
            if let Some(holders) = state.identities.get_mut(&lease.identity) {
                holders.retain(|holder| holder.ticket != self.id);
                if holders.is_empty() {
                    state.identities.remove(&lease.identity);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(topology: Topology, prefixes: &[&str]) -> AddressPool {
        let prefixes: Vec<String> = prefixes.iter().map(|text| (*text).to_owned()).collect();
        AddressPool::new(topology, &prefixes).unwrap()
    }

    #[test]
    fn subnet_pool_skips_the_server_address_and_pairs_ipv6_by_slot() {
        let pool = pool(Topology::Subnet, &["10.8.0.1/24", "fd00:8::1/64"]);
        assert_eq!(pool.capacity(), 253);
        let first = pool.assignment(0);
        assert_eq!(
            first.v4,
            Some(V4Assignment {
                client: Ipv4Addr::new(10, 8, 0, 2),
                peer: Ipv4Addr::new(10, 8, 0, 1),
                netmask: Ipv4Addr::new(255, 255, 255, 0),
            })
        );
        assert_eq!(
            first.v6.unwrap().client,
            "fd00:8::1000".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(
            pool.assignment(252).v4.unwrap().client,
            Ipv4Addr::new(10, 8, 0, 254)
        );
        let middle =
            super::AddressPool::new(Topology::Subnet, &["10.9.0.100/24".to_owned()]).unwrap();
        assert_eq!(
            middle.assignment(98).v4.unwrap().client,
            Ipv4Addr::new(10, 9, 0, 99)
        );
        assert_eq!(
            middle.assignment(99).v4.unwrap().client,
            Ipv4Addr::new(10, 9, 0, 101)
        );
    }

    #[test]
    fn net30_pool_hands_out_slash_30_blocks_after_the_server_block() {
        let pool = pool(Topology::Net30, &["10.8.0.1/24"]);
        assert_eq!(pool.capacity(), 63);
        assert_eq!(
            pool.assignment(0).v4,
            Some(V4Assignment {
                client: Ipv4Addr::new(10, 8, 0, 6),
                peer: Ipv4Addr::new(10, 8, 0, 5),
                netmask: Ipv4Addr::new(255, 255, 255, 252),
            })
        );
        assert_eq!(
            pool.slot_of("10.8.0.10".parse().unwrap()),
            Some(1),
            "fixed client address maps back to its block"
        );
        assert_eq!(pool.slot_of("10.8.0.1".parse().unwrap()), None);
    }

    #[test]
    fn pool_rejects_prefixes_without_room_for_clients() {
        assert!(AddressPool::new(Topology::Subnet, &["10.8.0.1/31".to_owned()]).is_err());
        assert!(AddressPool::new(Topology::Net30, &["10.8.0.1/30".to_owned()]).is_err());
        assert!(AddressPool::new(Topology::Subnet, &[]).is_err());
        assert!(AddressPool::new(Topology::Subnet, &["10.8.0.1".to_owned()]).is_err());
    }

    #[test]
    fn tickets_count_against_max_clients_and_release_on_drop() {
        let registry = Registry::new(
            pool(Topology::Subnet, &["10.8.0.1/24"]),
            BTreeSet::new(),
            2,
            true,
        );
        let mut first = registry.admit().unwrap();
        let second = registry.admit().unwrap();
        assert_eq!(registry.admit().err(), Some(Refusal::Full));
        let address = first
            .assign("alice", None)
            .unwrap()
            .assignment
            .v4
            .unwrap()
            .client;
        assert_eq!(address, Ipv4Addr::new(10, 8, 0, 2));
        drop(first);
        drop(second);
        assert_eq!(registry.active(), 0);
        let mut again = registry.admit().unwrap();
        assert_eq!(
            again
                .assign("bob", None)
                .unwrap()
                .assignment
                .v4
                .unwrap()
                .client,
            Ipv4Addr::new(10, 8, 0, 2),
            "released address is handed out again"
        );
    }

    #[test]
    fn concurrent_clients_get_distinct_addresses_and_peer_ids() {
        let registry = Registry::new(
            pool(Topology::Subnet, &["10.8.0.1/24"]),
            BTreeSet::from([0]),
            8,
            true,
        );
        let mut tickets: Vec<Ticket> = (0..3).map(|_| registry.admit().unwrap()).collect();
        let leases: Vec<Lease> = tickets
            .iter_mut()
            .map(|ticket| ticket.assign("same", None).unwrap().clone())
            .collect();
        let addresses: BTreeSet<_> = leases
            .iter()
            .map(|lease| lease.assignment.v4.unwrap().client)
            .collect();
        let peer_ids: BTreeSet<_> = leases.iter().map(|lease| lease.peer_id).collect();
        assert_eq!(addresses.len(), 3);
        assert_eq!(peer_ids.len(), 3);
        assert!(
            !addresses.contains(&Ipv4Addr::new(10, 8, 0, 2)),
            "reserved fixed slot is not handed out dynamically"
        );
        assert!(tickets.iter().all(|ticket| !ticket.kicked().is_cancelled()));
    }

    #[test]
    fn without_duplicate_cn_a_new_login_kicks_the_old_one_and_takes_its_fixed_address() {
        let registry = Registry::new(
            pool(Topology::Subnet, &["10.8.0.1/24"]),
            BTreeSet::from([5]),
            8,
            false,
        );
        let mut old = registry.admit().unwrap();
        old.assign("alice", Some(5)).unwrap();
        let mut new = registry.admit().unwrap();
        let lease = new.assign("alice", Some(5)).unwrap().clone();
        assert!(old.kicked().is_cancelled());
        assert_eq!(lease.slot, 5);
        drop(old);
        let mut other = registry.admit().unwrap();
        assert_ne!(
            other.assign("bob", None).unwrap().slot,
            5,
            "kicked session drop keeps the new owner"
        );
    }
}
