//! Configuration changes prepared before touching the running peer table.

use super::*;
use std::collections::{BTreeMap, HashSet};
use std::fmt::Write;
use std::time::UNIX_EPOCH;

type Key = [u8; 32];

#[derive(Default)]
pub(crate) struct Change {
    pub private: Option<Key>,
    pub port: Option<u16>,
    pub mark: Option<u32>,
    replace: bool,
    peers: Vec<PeerChange>,
}

struct PeerChange {
    key: Key,
    remove: bool,
    update_only: bool,
    replace: bool,
    preshared: Option<Key>,
    keepalive: Option<u16>,
    endpoint: Option<SocketAddr>,
    routes: Vec<(bool, IpNet)>,
}

fn hex_key(text: &str) -> io::Result<Key> {
    if text.len() != 64 {
        return Err(invalid("invalid UAPI key length"));
    }
    crate::parse_key(text)
}

impl Change {
    pub(crate) fn parse(lines: &[String]) -> io::Result<Self> {
        let mut change = Self::default();
        for line in lines {
            let (name, value) = line
                .split_once('=')
                .ok_or_else(|| invalid("invalid UAPI field"))?;
            if name == "public_key" {
                let key = hex_key(value)?;
                change.peers.push(PeerChange {
                    key,
                    remove: false,
                    update_only: false,
                    replace: false,
                    preshared: None,
                    keepalive: None,
                    endpoint: None,
                    routes: Vec::new(),
                });
                continue;
            }
            if let Some(peer) = change.peers.last_mut() {
                match name {
                    "remove" if value == "true" => peer.remove = true,
                    "update_only" if value == "true" => peer.update_only = true,
                    "replace_allowed_ips" if value == "true" => peer.replace = true,
                    "preshared_key" => peer.preshared = Some(hex_key(value)?),
                    "endpoint" => {
                        peer.endpoint = Some(
                            crate::parse_endpoint(value)
                                .map_err(|_| invalid("invalid UAPI endpoint"))?,
                        )
                    }
                    "persistent_keepalive_interval" => {
                        peer.keepalive = Some(
                            value
                                .parse()
                                .map_err(|_| invalid("invalid UAPI keepalive"))?,
                        )
                    }
                    "protocol_version" if value == "1" => {}
                    "allowed_ip" => {
                        let (add, net) = value
                            .strip_prefix('-')
                            .map_or((true, value), |net| (false, net));
                        let net: IpNet = net
                            .parse()
                            .map_err(|_| invalid("invalid UAPI allowed IP"))?;
                        peer.routes.push((add, net.trunc()));
                    }
                    _ => return Err(invalid("unknown or invalid UAPI peer field")),
                }
            } else {
                match name {
                    "private_key" => change.private = Some(hex_key(value)?),
                    "listen_port" => {
                        change.port = Some(
                            value
                                .parse()
                                .map_err(|_| invalid("invalid UAPI listen port"))?,
                        )
                    }
                    "fwmark" => {
                        change.mark =
                            Some(value.parse().map_err(|_| invalid("invalid UAPI fwmark"))?)
                    }
                    "replace_peers" if value == "true" => change.replace = true,
                    _ => return Err(invalid("unknown or invalid UAPI interface field")),
                }
            }
        }
        Ok(change)
    }
}

struct Config {
    id: Option<PeerId>,
    allowed: Vec<IpNet>,
    endpoint: Option<SocketAddr>,
    preshared: Option<Key>,
    keepalive: u16,
}

pub(crate) struct Plan {
    peers: Vec<(PeerId, Key, Config, bool, Option<Wire>)>,
    secret: StaticSecret,
    public: PublicKey,
    limiter: Arc<RateLimiter>,
    next: u32,
}

impl Hub {
    pub(crate) fn without_key(mtu: usize) -> io::Result<Self> {
        let mut hub = Self::with_mtu([1; 32], mtu)?;
        hub.secret = StaticSecret::from([0; 32]);
        Ok(hub)
    }

    pub(crate) fn plan(&self, change: &Change, bind: IpAddr, dual: bool) -> io::Result<Plan> {
        let new_private = change
            .private
            .map_or_else(|| self.secret.to_bytes(), canonical_private_key);
        let changed = self.secret.to_bytes() != new_private;
        let secret = StaticSecret::from(new_private);
        let public = PublicKey::from(&secret);
        let limiter = if changed {
            Arc::new(RateLimiter::new(&public, 100))
        } else {
            self.limiter.clone()
        };
        let mut configured = BTreeMap::new();
        if !change.replace {
            for (id, peer) in &self.peers {
                configured.insert(
                    peer.key,
                    Config {
                        id: Some(*id),
                        allowed: peer.allowed.clone(),
                        endpoint: peer.endpoint,
                        preshared: peer.preshared,
                        keepalive: peer.keepalive,
                    },
                );
            }
        }
        if new_private != [0; 32] {
            configured.remove(public.as_bytes());
        }
        for edit in &change.peers {
            if new_private != [0; 32] && edit.key == *public.as_bytes() {
                continue;
            }
            if edit.remove {
                configured.remove(&edit.key);
                continue;
            }
            if edit.update_only && !configured.contains_key(&edit.key) {
                continue;
            }
            if edit
                .endpoint
                .is_some_and(|ep| ep.port() == 0 || (!dual && ep.is_ipv4() != bind.is_ipv4()))
            {
                return Err(invalid("UAPI endpoint does not match the carrier"));
            }
            for (add, net) in &edit.routes {
                if *add {
                    if !cfg!(target_os = "linux") && self.mtu < 1280 && matches!(net, IpNet::V6(_))
                    {
                        return Err(invalid("MTU is too small for IPv6"));
                    }
                    for (key, peer) in &mut configured {
                        if *key != edit.key {
                            peer.allowed.retain(|route| route != net);
                        }
                    }
                }
            }
            let peer = configured.entry(edit.key).or_insert_with(|| Config {
                id: None,
                allowed: Vec::new(),
                endpoint: None,
                preshared: None,
                keepalive: 0,
            });
            if let Some(key) = edit.preshared {
                peer.preshared = (key != [0; 32]).then_some(key);
            }
            if let Some(keepalive) = edit.keepalive {
                peer.keepalive = keepalive;
            }
            if let Some(endpoint) = edit.endpoint {
                peer.endpoint = Some(endpoint);
            }
            if edit.replace {
                peer.allowed.clear();
            }
            for (add, route) in &edit.routes {
                if *add {
                    if !peer.allowed.contains(route) {
                        peer.allowed.push(*route);
                    }
                } else {
                    peer.allowed.retain(|net| net != route);
                }
            }
        }
        if configured.len() > 1024 {
            return Err(invalid("too many WireGuard peers"));
        }
        let mut next = self.next;
        let mut allocated = HashSet::new();
        let mut peers = Vec::with_capacity(configured.len());
        for (key, config) in configured {
            let rebuild = changed || config.id.is_none();
            let (id, wire) = if rebuild {
                let id = loop {
                    let id = PeerId(next);
                    next = if next == 0xff_ffff { 1 } else { next + 1 };
                    if !self.peers.contains_key(&id) && allocated.insert(id) {
                        break id;
                    }
                };
                (id, make_wire(&secret, &limiter, id, key, config.preshared)?)
            } else {
                (config.id.expect("existing peer"), None)
            };
            peers.push((id, key, config, rebuild, wire));
        }
        Ok(Plan {
            peers,
            secret,
            public,
            limiter,
            next,
        })
    }

    pub(crate) fn commit(&mut self, plan: Plan) {
        let mut old = std::mem::take(&mut self.peers);
        self.by_key.clear();
        self.secret = plan.secret;
        self.public = plan.public;
        self.limiter = plan.limiter;
        self.next = plan.next;
        for (id, key, config, rebuild, wire) in plan.peers {
            let mut peer = config
                .id
                .and_then(|id| old.remove(&id))
                .unwrap_or_else(|| Peer {
                    key,
                    allowed: Vec::new(),
                    endpoint: None,
                    wire: None,
                    preshared: None,
                    keepalive: 0,
                    last_traffic: None,
                    last_handshake: None,
                    received: 0,
                    sent: 0,
                });
            if rebuild {
                peer.wire = wire;
            } else if config.preshared != peer.preshared {
                if let Some(wire) = &mut peer.wire {
                    wire.set_preshared_key(config.preshared);
                }
            }
            if (peer.keepalive == 0 || rebuild || peer.endpoint != config.endpoint)
                && config.keepalive > 0
            {
                peer.last_traffic = None;
            }
            peer.endpoint = config.endpoint;
            peer.keepalive = config.keepalive;
            peer.preshared = config.preshared;
            peer.allowed = config.allowed;
            self.by_key.insert(key, id);
            self.peers.insert(id, peer);
        }
    }

    pub(crate) fn snapshot(&self, port: u16, mark: u32) -> String {
        let mut result = String::new();
        let key = self.secret.to_bytes();
        if key != [0; 32] {
            write_key(&mut result, "private_key", &key);
        }
        let _ = writeln!(result, "listen_port={port}");
        if mark != 0 {
            let _ = writeln!(result, "fwmark={mark}");
        }
        for peer in self.peers.values() {
            write_key(&mut result, "public_key", &peer.key);
            write_key(
                &mut result,
                "preshared_key",
                &peer.preshared.unwrap_or([0; 32]),
            );
            let _ = writeln!(result, "protocol_version=1");
            if let Some(endpoint) = peer.endpoint {
                let _ = writeln!(result, "endpoint={endpoint}");
            }
            let _ = writeln!(result, "persistent_keepalive_interval={}", peer.keepalive);
            for net in &peer.allowed {
                let _ = writeln!(result, "allowed_ip={net}");
            }
            let stamp = peer
                .last_handshake
                .and_then(|last| last.duration_since(UNIX_EPOCH).ok())
                .unwrap_or_default();
            let _ = writeln!(result, "last_handshake_time_sec={}", stamp.as_secs());
            let _ = writeln!(result, "last_handshake_time_nsec={}", stamp.subsec_nanos());
            let _ = writeln!(result, "rx_bytes={}", peer.received);
            let _ = writeln!(result, "tx_bytes={}", peer.sent);
        }
        result
    }
}

fn write_key(output: &mut String, field: &str, key: &Key) {
    let _ = write!(output, "{field}=");
    for byte in key {
        let _ = write!(output, "{byte:02x}");
    }
    output.push('\n');
}
