// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// (c) ZeroTier, Inc.
// https://www.zerotier.com/
//
// Translated to Rust from ZeroTierOne tag 1.16.2: node/Switch.cpp, node/IncomingPacket.cpp,
// node/Peer.cpp, node/Peer.hpp, node/Network.cpp, node/Membership.cpp, node/Multicaster.cpp,
// node/Topology.cpp, node/Constants.hpp. Reduced to a single-network client with no relaying,
// no flow rule engine, no bridging and no multipath.

use crate::address::{Address, Mac, MulticastGroup};
use crate::certificate::CertificateOfMembership;
use crate::dictionary;
use crate::identity::{Identity, IdentityError};
use crate::inet;
use crate::network::{ConfigAssembler, NetworkConfig};
use crate::packet::{self, error_code, verb};
use crate::reader::Reader;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use zeroize::Zeroizing;

// Protocol 11 predates AES-GMAC-SIV, so peers keep to Salsa20/12 with Poly1305 for this node.
const PROTOCOL_VERSION: u8 = 11;
const MIN_PROTOCOL_VERSION: u8 = 4;
const SOFTWARE_MAJOR: u8 = 1;
const SOFTWARE_MINOR: u8 = 4;
const SOFTWARE_REVISION: u16 = 8;

const NETWORK_CONFIG_VERSION: u64 = 7;
const VENDOR_ZEROTIER: u64 = 1;
const RULES_ENGINE_REVISION: u64 = 1;
const MAX_NETWORK_RULES: u64 = 1024;
const MAX_NETWORK_CAPABILITIES: u64 = 128;
const MAX_CAPABILITY_RULES: u64 = 64;
const MAX_NETWORK_TAGS: u64 = 128;

const PEER_PING_PERIOD: i64 = 60_000;
const PATH_HEARTBEAT_PERIOD: i64 = 14_000;
const PATH_ALIVE_TIMEOUT: i64 = PATH_HEARTBEAT_PERIOD * 2 + 5_000;
const PEER_PATH_EXPIRATION: i64 = PEER_PING_PERIOD * 4 + 3_000;
const PEER_ACTIVITY_TIMEOUT: i64 = 500_000;
const SEED_CONTACT_PERIOD: i64 = 5_000;
const NETWORK_AUTOCONF_DELAY: i64 = 60_000;
const UNCONFIGURED_REQUEST_PERIOD: i64 = 5_000;
const MULTICAST_ANNOUNCE_PERIOD: i64 = 60_000;
const MULTICAST_LIKE_EXPIRE: i64 = 600_000;
const MULTICAST_EXPLICIT_GATHER_DELAY: i64 = MULTICAST_LIKE_EXPIRE / 10;
const EMPTY_GROUP_GATHER_DELAY: i64 = 1_000;
const CREDENTIAL_PUSH_PERIOD: i64 = 60_000;
const CREDENTIAL_REQUEST_RATE_LIMIT: i64 = 1_000;
const WHOIS_RETRY_DELAY: i64 = 500;
const QUEUE_TIMEOUT: i64 = 5_000;
const FRAGMENT_TIMEOUT: i64 = 5_000;
const IDENTITY_VALIDATION_RATE_LIMIT: i64 = 2_000;
const ECHO_RATE_LIMIT: i64 = 1_000;
const CONTACT_RATE_LIMIT: i64 = 1_000;

const MAX_PEERS: usize = 1024;
const MAX_PATHS: usize = 8;
const MAX_PARTIAL_PACKETS: usize = 128;
const MAX_STASHED: usize = 64;
const MAX_PENDING_PEERS: usize = 64;
const MAX_PENDING_PER_PEER: usize = 16;
const MAX_EXPECTED_REPLIES: usize = 1024;
const MAX_UNKNOWN_SOURCES: usize = 64;
const MAX_UNKNOWN_SOURCE_LOOKUPS: usize = 64;
const EXPECTED_REPLY_TIMEOUT: i64 = 60_000;
const WHOIS_PER_SECOND: u32 = 64;
const UNKNOWN_SOURCE_WHOIS_PER_SECOND: u32 = 8;
const STRANGER_HELLO_AGREEMENTS_PER_SECOND: u32 = 256;
// One slot stays free for an identity this node itself asked for.
const MAX_IDENTITY_CHECKS: usize = 3;
const MAX_UNSOLICITED_IDENTITY_CHECKS: usize = MAX_IDENTITY_CHECKS - 1;
const IDENTITY_CHECK_TIMEOUT: i64 = 10_000;
const REPLAY_SLOTS: usize = 2048;
const MAX_GROUPS: usize = 1024;
const MAX_GROUP_MEMBERS: usize = 1024;
const IDENTITY_GATE_BUCKETS: usize = 16384;

/// A node known from configuration rather than learned from the network.
#[derive(Clone, Debug)]
pub struct Seed {
    pub identity: Identity,
    pub endpoints: Vec<SocketAddr>,
}

#[derive(Clone, Debug)]
pub struct NodeOptions {
    /// Must hold a secret key.
    pub identity: Identity,
    pub network_id: u64,
    /// Upstream nodes: they answer WHOIS, relay and introduce peers.
    pub roots: Vec<Seed>,
    /// Peers reached directly, such as a controller or member with a known address.
    pub peers: Vec<Seed>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JoinStatus {
    Requesting,
    Joined,
    AccessDenied,
    NotFound,
    AuthenticationRequired,
    IdentityCollision,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    pub from: Mac,
    pub to: Mac,
    pub ethertype: u16,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug)]
pub enum Event {
    Datagram {
        to: SocketAddr,
        data: Vec<u8>,
    },
    Frame(Frame),
    Config(Arc<NetworkConfig>),
    Status(JoinStatus),
    /// Run [`IdentityCheck::run`] away from the packet path and pass the result to
    /// [`Node::on_identity_verdict`]. The node limits how many are outstanding.
    IdentityCheck(IdentityCheck),
}

/// One proof of work check, which blocks for a memory-hard hash.
#[derive(Clone, Debug)]
pub struct IdentityCheck {
    id: u64,
    identity: Identity,
}

impl IdentityCheck {
    pub fn run(&self) -> IdentityVerdict {
        IdentityVerdict {
            id: self.id,
            valid: self.identity.locally_validate(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct IdentityVerdict {
    id: u64,
    valid: bool,
}

enum AfterCheck {
    Hello {
        from: SocketAddr,
        wire: Vec<u8>,
        timestamp: [u8; 8],
    },
    Whois,
}

struct PendingCheck {
    started: i64,
    identity: Identity,
    key: Zeroizing<[u8; 32]>,
    then: AfterCheck,
}

/// Packet IDs are random (`Packet.hpp`), so a sequence window is impossible. Each authenticated
/// ID overwrites one slot, which remembers roughly the last `REPLAY_SLOTS` packets of a peer.
struct RecentPacketIds(Box<[u64]>);

impl RecentPacketIds {
    fn new() -> Self {
        Self(vec![0; REPLAY_SLOTS].into_boxed_slice())
    }

    fn first_sight(&mut self, id: u64) -> bool {
        let slot = &mut self.0[id as usize % REPLAY_SLOTS];
        if *slot == id && id != 0 {
            return false;
        }
        *slot = id;
        true
    }
}

#[derive(Default)]
struct RateWindow {
    started: i64,
    used: u32,
}

impl RateWindow {
    fn allow(&mut self, now: i64, limit: u32) -> bool {
        if now - self.started >= 1_000 {
            self.started = now;
            self.used = 0;
        }
        if self.used >= limit {
            return false;
        }
        self.used += 1;
        true
    }
}

struct Path {
    address: SocketAddr,
    last_receive: i64,
    last_send: i64,
}

struct Peer {
    identity: Identity,
    key: Zeroizing<[u8; 32]>,
    pinned: bool,
    endpoints: Vec<SocketAddr>,
    paths: Vec<Path>,
    last_hello: i64,
    last_seed_contact: i64,
    last_contact_attempt: i64,
    last_traffic: i64,
    last_credential_push: i64,
    last_credential_request: i64,
    last_echo: i64,
    last_receive: i64,
    com: Option<CertificateOfMembership>,
    recent_packets: RecentPacketIds,
}

impl Peer {
    fn new(
        identity: Identity,
        key: Zeroizing<[u8; 32]>,
        pinned: bool,
        endpoints: Vec<SocketAddr>,
    ) -> Self {
        Self {
            identity,
            key,
            pinned,
            endpoints,
            paths: Vec::new(),
            last_hello: i64::MIN / 2,
            last_seed_contact: i64::MIN / 2,
            last_contact_attempt: i64::MIN / 2,
            last_traffic: i64::MIN / 2,
            last_credential_push: i64::MIN / 2,
            last_credential_request: i64::MIN / 2,
            last_echo: i64::MIN / 2,
            last_receive: i64::MIN / 2,
            com: None,
            recent_packets: RecentPacketIds::new(),
        }
    }

    fn best_alive_path(&self, now: i64) -> Option<SocketAddr> {
        self.paths
            .iter()
            .filter(|path| now - path.last_receive < PATH_ALIVE_TIMEOUT)
            .max_by_key(|path| path.last_receive)
            .map(|path| path.address)
    }

    fn any_address(&self) -> Option<SocketAddr> {
        self.paths
            .iter()
            .max_by_key(|path| path.last_receive)
            .map(|path| path.address)
            .or_else(|| self.endpoints.first().copied())
    }
}

#[derive(Default)]
struct PartialPacket {
    started: i64,
    from: Option<SocketAddr>,
    head: Option<Vec<u8>>,
    fragments: [Option<Vec<u8>>; packet::MAX_FRAGMENTS],
    total: usize,
}

struct Stashed {
    received: i64,
    from: SocketAddr,
    packet: Vec<u8>,
}

/// A destination this node wants to reach.
struct PendingPeer {
    first_queued: i64,
    last_whois: i64,
    packets: VecDeque<(u8, Vec<u8>)>,
}

/// The claimed sender of an unauthenticated packet. Anyone can create these, so they are kept
/// apart from `PendingPeer`, whose table must stay usable for joining the network.
struct UnknownSource {
    first_seen: i64,
    last_whois: i64,
}

#[derive(Default)]
struct Group {
    members: HashMap<Address, i64>,
    last_gather: Option<i64>,
}

struct ExpectedReply {
    peer: Address,
    verb: u8,
    sent: i64,
}

/// Requests awaiting an OK. Oldest entries give way once `capacity` requests have been sent.
struct ExpectedReplies {
    capacity: usize,
    order: VecDeque<u64>,
    entries: HashMap<u64, ExpectedReply>,
}

impl ExpectedReplies {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            order: VecDeque::new(),
            entries: HashMap::new(),
        }
    }

    fn insert(&mut self, id: u64, peer: Address, verb: u8, sent: i64) {
        let reply = ExpectedReply { peer, verb, sent };
        if self.entries.insert(id, reply).is_none() {
            self.order.push_back(id);
            if self.order.len() > self.capacity
                && let Some(old) = self.order.pop_front()
            {
                self.entries.remove(&old);
            }
        }
    }

    /// An ID answers once, with one exception: `Node::ncSendConfig` repeats the request ID on
    /// every chunk of a network config, so that entry stays until it expires.
    fn answer(&mut self, id: u64, peer: Address, verb: u8) -> bool {
        let matches = self
            .entries
            .get(&id)
            .is_some_and(|reply| reply.peer == peer && reply.verb == verb);
        if matches && verb != verb::NETWORK_CONFIG_REQUEST {
            self.entries.remove(&id);
        }
        matches
    }

    fn expire(&mut self, now: i64) {
        while let Some(id) = self.order.front() {
            if self
                .entries
                .get(id)
                .is_some_and(|reply| now - reply.sent < EXPECTED_REPLY_TIMEOUT)
            {
                return;
            }
            self.entries.remove(id);
            self.order.pop_front();
        }
    }
}

pub struct Node {
    identity: Identity,
    address: Address,
    network_id: u64,
    mac: Mac,
    controller: Address,
    roots: Vec<Address>,
    peers: HashMap<Address, Peer>,
    config: Option<Arc<NetworkConfig>>,
    assembler: ConfigAssembler,
    status: JoinStatus,
    last_config_request: i64,
    last_announce: i64,
    subscriptions: Vec<MulticastGroup>,
    groups: HashMap<MulticastGroup, Group>,
    partial: HashMap<u64, PartialPacket>,
    stashed: VecDeque<Stashed>,
    pending: HashMap<Address, PendingPeer>,
    unknown_sources: HashMap<Address, UnknownSource>,
    expected: ExpectedReplies,
    // Lookups for unknown sources stay out of `expected` so forged traffic cannot evict its IDs.
    unknown_source_lookups: ExpectedReplies,
    whois_rate: RateWindow,
    unknown_source_whois_rate: RateWindow,
    stranger_hello_rate: RateWindow,
    identity_checks: HashMap<u64, PendingCheck>,
    next_identity_check: u64,
    identity_gate: Vec<i64>,
    events: VecDeque<Event>,
}

impl Node {
    pub fn new(options: NodeOptions) -> Result<Self, IdentityError> {
        let NodeOptions {
            identity,
            network_id,
            roots,
            peers: direct,
        } = options;
        if !identity.has_secret() {
            return Err(IdentityError::SecretRequired);
        }
        let address = identity.address();
        let mut peers = HashMap::new();
        let mut root_addresses = Vec::new();
        for (seed, is_root) in roots
            .into_iter()
            .map(|seed| (seed, true))
            .chain(direct.into_iter().map(|seed| (seed, false)))
        {
            let seed_address = seed.identity.address();
            if seed_address == address {
                continue;
            }
            if is_root {
                root_addresses.push(seed_address);
            }
            let key = identity.agree(&seed.identity)?;
            peers.insert(
                seed_address,
                Peer::new(seed.identity, key, true, seed.endpoints),
            );
        }
        Ok(Self {
            address,
            network_id,
            mac: Mac::from_address(address, network_id),
            controller: Address::controller_of(network_id),
            identity,
            roots: root_addresses,
            peers,
            config: None,
            assembler: ConfigAssembler::default(),
            status: JoinStatus::Requesting,
            last_config_request: i64::MIN / 2,
            last_announce: i64::MIN / 2,
            subscriptions: Vec::new(),
            groups: HashMap::new(),
            partial: HashMap::new(),
            stashed: VecDeque::new(),
            pending: HashMap::new(),
            unknown_sources: HashMap::new(),
            expected: ExpectedReplies::new(MAX_EXPECTED_REPLIES),
            unknown_source_lookups: ExpectedReplies::new(MAX_UNKNOWN_SOURCE_LOOKUPS),
            whois_rate: RateWindow::default(),
            unknown_source_whois_rate: RateWindow::default(),
            stranger_hello_rate: RateWindow::default(),
            identity_checks: HashMap::new(),
            next_identity_check: 0,
            identity_gate: vec![i64::MIN / 2; IDENTITY_GATE_BUCKETS],
            events: VecDeque::new(),
        })
    }

    pub fn address(&self) -> Address {
        self.address
    }
    pub fn mac(&self) -> Mac {
        self.mac
    }
    pub fn network_id(&self) -> u64 {
        self.network_id
    }
    pub fn config(&self) -> Option<&Arc<NetworkConfig>> {
        self.config.as_ref()
    }
    pub fn status(&self) -> JoinStatus {
        self.status
    }

    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// Runs timers. Call at least a few times per second.
    pub fn tick(&mut self, now: i64) {
        self.expire(now);
        self.ping_peers(now);
        self.retry_whois(now);
        let period = if self.config.is_some() {
            NETWORK_AUTOCONF_DELAY
        } else {
            UNCONFIGURED_REQUEST_PERIOD
        };
        if now - self.last_config_request >= period {
            self.request_config(now);
        }
        if self.config.is_some() && now - self.last_announce >= MULTICAST_ANNOUNCE_PERIOD {
            self.announce(now);
        }
    }

    /// Handles one UDP payload. Anything malformed or unauthenticated is dropped without reply.
    pub fn on_datagram(&mut self, now: i64, from: SocketAddr, data: &[u8]) {
        if data.len() > packet::MAX_PACKET_LENGTH {
            return;
        }
        if data.len() > packet::FRAGMENT_IDX_PAYLOAD
            && data[packet::FRAGMENT_IDX_INDICATOR] == packet::FRAGMENT_INDICATOR
        {
            self.on_fragment(now, from, data);
        } else if data.len() >= packet::MIN_PACKET_LENGTH {
            self.on_head(now, from, data);
        }
    }

    /// Sends an Ethernet frame to a unicast MAC on the network.
    pub fn send_frame(&mut self, now: i64, to: Mac, ethertype: u16, payload: &[u8]) {
        if self.config.is_none() || to.is_multicast() {
            return;
        }
        let destination = to.to_address(self.network_id);
        if destination == self.address || destination.is_reserved() {
            return;
        }
        self.push_credentials_if_stale(now, destination);
        let mut body = Vec::with_capacity(10 + payload.len());
        body.extend_from_slice(&self.network_id.to_be_bytes());
        body.extend_from_slice(&ethertype.to_be_bytes());
        body.extend_from_slice(payload);
        self.send_verb(now, destination, verb::FRAME, body);
        if let Some(peer) = self.peers.get_mut(&destination) {
            peer.last_traffic = now;
        }
    }

    /// Sends to every known member of a group and asks for more members when the list is stale.
    pub fn send_multicast(
        &mut self,
        now: i64,
        group: MulticastGroup,
        ethertype: u16,
        payload: &[u8],
    ) {
        let Some(config) = self.config.clone() else {
            return;
        };
        if config.multicast_limit == 0 {
            return;
        }
        self.expire_group_members(now, group);
        let state = self.groups.entry(group).or_default();
        let member_count = state.members.len();
        let delay = if member_count == 0 {
            EMPTY_GROUP_GATHER_DELAY
        } else {
            MULTICAST_EXPLICIT_GATHER_DELAY
        };
        if state.last_gather.is_none_or(|last| now - last >= delay) {
            state.last_gather = Some(now);
            let limit = config
                .multicast_limit
                .saturating_sub(member_count as u32)
                .saturating_add(1);
            self.gather(now, group, limit, &config);
        }

        let mut targets: Vec<Address> = config.active_bridges().collect();
        if let Some(state) = self.groups.get(&group) {
            let mut members: Vec<Address> = state.members.keys().copied().collect();
            members.sort();
            members.retain(|member| !targets.contains(member));
            members.truncate(config.multicast_limit as usize);
            targets.extend(members);
        }
        let mut body = Vec::with_capacity(21 + payload.len());
        body.extend_from_slice(&self.network_id.to_be_bytes());
        body.push(0);
        body.extend_from_slice(&group.mac.to_bytes());
        body.extend_from_slice(&group.adi.to_be_bytes());
        body.extend_from_slice(&ethertype.to_be_bytes());
        body.extend_from_slice(payload);
        for target in targets {
            if target != self.address {
                self.push_credentials_if_stale(now, target);
                self.send_verb(now, target, verb::MULTICAST_FRAME, body.clone());
            }
        }
    }

    fn gather(&mut self, now: i64, group: MulticastGroup, limit: u32, config: &NetworkConfig) {
        let mut body = Vec::with_capacity(23);
        body.extend_from_slice(&self.network_id.to_be_bytes());
        body.push(u8::from(config.com.is_some()));
        body.extend_from_slice(&group.mac.to_bytes());
        body.extend_from_slice(&group.adi.to_be_bytes());
        body.extend_from_slice(&limit.to_be_bytes());
        if let Some(com) = &config.com {
            com.serialize(&mut body);
        }
        let mut targets: Vec<Address> = self.best_root(now).into_iter().collect();
        if !targets.contains(&self.controller) {
            targets.push(self.controller);
        }
        for target in config.active_bridges() {
            if !targets.contains(&target) {
                targets.push(target);
            }
        }
        for target in targets {
            if target != self.address {
                self.send_verb(now, target, verb::MULTICAST_GATHER, body.clone());
            }
        }
    }

    fn expire(&mut self, now: i64) {
        self.partial
            .retain(|_, entry| now - entry.started < FRAGMENT_TIMEOUT);
        while self
            .stashed
            .front()
            .is_some_and(|item| now - item.received >= QUEUE_TIMEOUT)
        {
            self.stashed.pop_front();
        }
        self.pending
            .retain(|_, entry| now - entry.first_queued < QUEUE_TIMEOUT);
        self.unknown_sources
            .retain(|_, entry| now - entry.first_seen < QUEUE_TIMEOUT);
        self.expected.expire(now);
        self.unknown_source_lookups.expire(now);
        // A check whose task never reports must not hold its slot.
        self.identity_checks
            .retain(|_, check| now - check.started < IDENTITY_CHECK_TIMEOUT);
    }

    fn expire_group_members(&mut self, now: i64, group: MulticastGroup) {
        if let Some(state) = self.groups.get_mut(&group) {
            state
                .members
                .retain(|_, seen| now - *seen < MULTICAST_LIKE_EXPIRE);
        }
    }

    fn ping_peers(&mut self, now: i64) {
        let mut hellos = Vec::new();
        let mut echoes = Vec::new();
        for (address, peer) in &mut self.peers {
            peer.paths
                .retain(|path| now - path.last_receive < PEER_PATH_EXPIRATION);
            if !peer.pinned && now - peer.last_traffic >= PEER_ACTIVITY_TIMEOUT {
                continue;
            }
            let full_hello = now - peer.last_hello >= PEER_PING_PERIOD;
            if full_hello && !peer.paths.is_empty() {
                peer.last_hello = now;
            }
            for path in &mut peer.paths {
                if full_hello {
                    hellos.push((*address, path.address));
                } else if now - path.last_send >= PATH_HEARTBEAT_PERIOD {
                    echoes.push((*address, path.address));
                }
            }
            if peer.pinned
                && peer.best_alive_path(now).is_none()
                && now - peer.last_seed_contact >= SEED_CONTACT_PERIOD
            {
                peer.last_seed_contact = now;
                for endpoint in &peer.endpoints {
                    hellos.push((*address, *endpoint));
                }
            }
        }
        for (address, at) in hellos {
            self.send_hello(now, address, at);
        }
        for (address, at) in echoes {
            self.send_direct(now, address, at, verb::ECHO, Vec::new());
        }
    }

    fn retry_whois(&mut self, now: i64) {
        let mut due: Vec<(i64, Address)> = self
            .pending
            .iter()
            .filter(|(_, entry)| now - entry.last_whois >= WHOIS_RETRY_DELAY)
            .map(|(address, entry)| (entry.last_whois, *address))
            .collect();
        due.sort_unstable();
        for (_, address) in due {
            self.request_whois(now, address);
        }
        let mut due: Vec<(i64, Address)> = self
            .unknown_sources
            .iter()
            .filter(|(_, entry)| now - entry.last_whois >= WHOIS_RETRY_DELAY)
            .map(|(address, entry)| (entry.last_whois, *address))
            .collect();
        due.sort_unstable();
        for (_, address) in due {
            self.request_whois_for_unknown_source(now, address);
        }
    }

    fn best_root(&self, now: i64) -> Option<Address> {
        self.roots
            .iter()
            .find(|root| {
                self.peers
                    .get(root)
                    .is_some_and(|peer| peer.best_alive_path(now).is_some())
            })
            .or_else(|| self.roots.first())
            .copied()
    }

    fn send_whois(&mut self, now: i64, address: Address) -> Option<(u64, Address)> {
        let root = self.best_root(now)?;
        let id = self.send_verb(now, root, verb::WHOIS, address.to_bytes().to_vec())?;
        Some((id, root))
    }

    fn request_whois(&mut self, now: i64, address: Address) {
        if !self.pending.contains_key(&address) || !self.whois_rate.allow(now, WHOIS_PER_SECOND) {
            return;
        }
        if let Some(entry) = self.pending.get_mut(&address) {
            entry.last_whois = now;
        }
        if let Some((id, root)) = self.send_whois(now, address) {
            self.expected.insert(id, root, verb::WHOIS, now);
        }
    }

    /// Spends the smaller budget first, so forged sources leave most of the global one to
    /// destinations this node wants.
    fn request_whois_for_unknown_source(&mut self, now: i64, address: Address) {
        if !self.unknown_sources.contains_key(&address)
            || !self
                .unknown_source_whois_rate
                .allow(now, UNKNOWN_SOURCE_WHOIS_PER_SECOND)
            || !self.whois_rate.allow(now, WHOIS_PER_SECOND)
        {
            return;
        }
        if let Some(entry) = self.unknown_sources.get_mut(&address) {
            entry.last_whois = now;
        }
        if let Some((id, root)) = self.send_whois(now, address) {
            self.unknown_source_lookups
                .insert(id, root, verb::WHOIS, now);
        }
    }

    fn pending_entry(&mut self, now: i64, destination: Address) -> Option<&mut PendingPeer> {
        if destination != self.controller
            && !self.pending.contains_key(&destination)
            && self.pending.len() >= MAX_PENDING_PEERS
        {
            return None;
        }
        Some(self.pending.entry(destination).or_insert(PendingPeer {
            first_queued: now,
            last_whois: i64::MIN / 2,
            packets: VecDeque::new(),
        }))
    }

    /// Queues while the peer's identity is unknown, then asks a root for it.
    fn queue_for_peer(&mut self, now: i64, destination: Address, code: u8, body: Vec<u8>) {
        let Some(entry) = self.pending_entry(now, destination) else {
            return;
        };
        if entry.packets.len() < MAX_PENDING_PER_PEER {
            entry.packets.push_back((code, body));
        }
        if now - entry.last_whois >= WHOIS_RETRY_DELAY {
            self.request_whois(now, destination);
        }
    }

    /// Returns the packet ID when the packet was sent rather than queued or dropped.
    fn send_verb(
        &mut self,
        now: i64,
        destination: Address,
        code: u8,
        body: Vec<u8>,
    ) -> Option<u64> {
        let Some(peer) = self.peers.get(&destination) else {
            self.queue_for_peer(now, destination, code, body);
            return None;
        };
        let via = peer.best_alive_path(now).or_else(|| {
            self.best_root(now)
                .and_then(|root| self.peers.get(&root))
                .and_then(|root| root.best_alive_path(now).or_else(|| root.any_address()))
                .or_else(|| peer.any_address())
        });
        self.send_direct(now, destination, via?, code, body)
    }

    fn send_direct(
        &mut self,
        now: i64,
        destination: Address,
        via: SocketAddr,
        code: u8,
        body: Vec<u8>,
    ) -> Option<u64> {
        let peer = self.peers.get_mut(&destination)?;
        let wire = packet::new_packet(destination, self.address, code, &body);
        let id = packet::packet_id(&wire);
        let datagrams = packet::seal(wire, &peer.key, true)?;
        if let Some(path) = peer.paths.iter_mut().find(|path| path.address == via) {
            path.last_send = now;
        }
        if matches!(
            code,
            verb::ECHO | verb::NETWORK_CONFIG_REQUEST | verb::MULTICAST_GATHER
        ) {
            self.expected.insert(id, destination, code, now);
        }
        for data in datagrams {
            self.events.push_back(Event::Datagram { to: via, data });
        }
        Some(id)
    }

    fn send_hello(&mut self, now: i64, destination: Address, at: SocketAddr) {
        let Some(peer) = self.peers.get_mut(&destination) else {
            return;
        };
        let mut body = Vec::with_capacity(128);
        body.push(PROTOCOL_VERSION);
        body.push(SOFTWARE_MAJOR);
        body.push(SOFTWARE_MINOR);
        body.extend_from_slice(&SOFTWARE_REVISION.to_be_bytes());
        body.extend_from_slice(&now.to_be_bytes());
        self.identity.serialize(&mut body);
        inet::serialize(at, &mut body);
        // World ID and timestamp of zero decline planet updates; this node keeps configured roots.
        body.extend_from_slice(&[0; 16]);
        let crypted_at = packet::IDX_PAYLOAD + body.len();
        body.extend_from_slice(&[0, 0]);

        let mut wire = packet::new_packet(destination, self.address, verb::HELLO, &body);
        packet::crypt_field(&mut wire, &peer.key, crypted_at);
        packet::armor(&mut wire, &peer.key, false);
        let id = packet::packet_id(&wire);
        if let Some(path) = peer.paths.iter_mut().find(|path| path.address == at) {
            path.last_send = now;
        }
        self.expected.insert(id, destination, verb::HELLO, now);
        self.events
            .push_back(Event::Datagram { to: at, data: wire });
    }

    fn request_config(&mut self, now: i64) {
        self.last_config_request = now;
        let mut metadata = Vec::with_capacity(160);
        for (key, value) in [
            ("v", NETWORK_CONFIG_VERSION),
            ("vend", VENDOR_ZEROTIER),
            ("pv", u64::from(PROTOCOL_VERSION)),
            ("majv", u64::from(SOFTWARE_MAJOR)),
            ("minv", u64::from(SOFTWARE_MINOR)),
            ("revv", u64::from(SOFTWARE_REVISION)),
            ("mr", MAX_NETWORK_RULES),
            ("mc", MAX_NETWORK_CAPABILITIES),
            ("mcr", MAX_CAPABILITY_RULES),
            ("mt", MAX_NETWORK_TAGS),
            ("f", 0),
            ("revr", RULES_ENGINE_REVISION),
        ] {
            dictionary::add_u64(&mut metadata, key, value);
        }
        dictionary::add_text(&mut metadata, "o", std::env::consts::OS);

        let mut body = Vec::with_capacity(metadata.len() + 26);
        body.extend_from_slice(&self.network_id.to_be_bytes());
        body.extend_from_slice(&(metadata.len() as u16).to_be_bytes());
        body.extend_from_slice(&metadata);
        let (revision, timestamp) = self
            .config
            .as_ref()
            .map_or((0, 0), |config| (config.revision, config.timestamp));
        body.extend_from_slice(&revision.to_be_bytes());
        body.extend_from_slice(&timestamp.to_be_bytes());
        self.send_verb(now, self.controller, verb::NETWORK_CONFIG_REQUEST, body);
    }

    fn announce(&mut self, now: i64) {
        self.last_announce = now;
        let Some(config) = self.config.clone() else {
            return;
        };
        let mut body = Vec::with_capacity(self.subscriptions.len() * 18);
        for group in &self.subscriptions {
            body.extend_from_slice(&self.network_id.to_be_bytes());
            body.extend_from_slice(&group.mac.to_bytes());
            body.extend_from_slice(&group.adi.to_be_bytes());
        }
        if body.is_empty() {
            return;
        }
        let mut targets: Vec<Address> = self.roots.clone();
        targets.push(self.controller);
        targets.extend(config.active_bridges());
        targets.extend(
            self.peers
                .iter()
                .filter(|(address, peer)| {
                    peer.com.is_some()
                        && now - peer.last_traffic < PEER_ACTIVITY_TIMEOUT
                        && self.gate(**address)
                })
                .map(|(address, _)| *address),
        );
        targets.sort();
        targets.dedup();
        for target in targets {
            if target != self.address {
                self.push_credentials_if_stale(now, target);
                self.send_verb(now, target, verb::MULTICAST_LIKE, body.clone());
            }
        }
    }

    fn credentials_body(&self) -> Option<Vec<u8>> {
        let com = self.config.as_ref()?.com.as_ref()?;
        let mut body = Vec::with_capacity(300);
        com.serialize(&mut body);
        body.push(0);
        // No capabilities, tags, revocations or certificates of ownership.
        body.extend_from_slice(&[0; 8]);
        Some(body)
    }

    fn push_credentials(&mut self, now: i64, destination: Address) {
        let Some(body) = self.credentials_body() else {
            return;
        };
        if let Some(peer) = self.peers.get_mut(&destination) {
            peer.last_credential_push = now;
        } else if self.pending.contains_key(&destination) {
            return;
        }
        self.send_verb(now, destination, verb::NETWORK_CREDENTIALS, body);
    }

    fn push_credentials_if_stale(&mut self, now: i64, destination: Address) {
        let stale = self
            .peers
            .get(&destination)
            .is_none_or(|peer| now - peer.last_credential_push >= CREDENTIAL_PUSH_PERIOD);
        if stale {
            self.push_credentials(now, destination);
        }
    }

    fn gate(&self, address: Address) -> bool {
        let Some(config) = &self.config else {
            return false;
        };
        if config.is_public() {
            return true;
        }
        let (Some(ours), Some(peer)) = (&config.com, self.peers.get(&address)) else {
            return false;
        };
        peer.com
            .as_ref()
            .is_some_and(|theirs| ours.agrees_with(theirs, &peer.identity))
    }

    fn on_fragment(&mut self, now: i64, from: SocketAddr, data: &[u8]) {
        if packet::destination(data) != self.address {
            return;
        }
        let number = usize::from(data[packet::FRAGMENT_IDX_NUMBER] & 0x0f);
        let total = usize::from(data[packet::FRAGMENT_IDX_NUMBER] >> 4);
        if total > packet::MAX_FRAGMENTS
            || number >= packet::MAX_FRAGMENTS
            || number == 0
            || total <= 1
        {
            return;
        }
        let id = packet::packet_id(data);
        let entry = self.partial_entry(now, id);
        entry.total = total;
        if entry.fragments[number].is_none() {
            entry.fragments[number] = Some(data[packet::FRAGMENT_IDX_PAYLOAD..].to_vec());
        }
        if entry.from.is_none() {
            entry.from = Some(from);
        }
        self.try_assemble(now, id);
    }

    fn on_head(&mut self, now: i64, from: SocketAddr, data: &[u8]) {
        let source = packet::source(data);
        if source == self.address || packet::destination(data) != self.address {
            return;
        }
        if data[packet::IDX_FLAGS] & packet::FLAG_FRAGMENTED != 0 {
            let id = packet::packet_id(data);
            let entry = self.partial_entry(now, id);
            if entry.head.is_none() {
                entry.head = Some(data.to_vec());
                entry.from = Some(from);
            }
            self.try_assemble(now, id);
        } else {
            self.decode(now, from, data.to_vec());
        }
    }

    fn partial_entry(&mut self, now: i64, id: u64) -> &mut PartialPacket {
        if !self.partial.contains_key(&id)
            && self.partial.len() >= MAX_PARTIAL_PACKETS
            && let Some(oldest) = self
                .partial
                .iter()
                .min_by_key(|(_, entry)| entry.started)
                .map(|(key, _)| *key)
        {
            self.partial.remove(&oldest);
        }
        self.partial.entry(id).or_insert_with(|| PartialPacket {
            started: now,
            ..PartialPacket::default()
        })
    }

    fn try_assemble(&mut self, now: i64, id: u64) {
        let Some(entry) = self.partial.get(&id) else {
            return;
        };
        let complete = entry.head.is_some()
            && entry.total > 1
            && (1..entry.total).all(|number| entry.fragments[number].is_some());
        if !complete {
            return;
        }
        let Some(entry) = self.partial.remove(&id) else {
            return;
        };
        let (Some(mut assembled), Some(from)) = (entry.head, entry.from) else {
            return;
        };
        for fragment in entry.fragments[1..entry.total].iter().flatten() {
            assembled.extend_from_slice(fragment);
        }
        if assembled.len() <= packet::MAX_PACKET_LENGTH {
            self.decode(now, from, assembled);
        }
    }

    fn decode(&mut self, now: i64, from: SocketAddr, mut wire: Vec<u8>) {
        let source = packet::source(&wire);
        let suite = packet::cipher(&wire);
        if packet::is_extended_armor(&wire) {
            return;
        }
        if suite == packet::CIPHER_POLY1305_NONE && packet::verb_of(&wire) == verb::HELLO {
            self.on_hello(now, from, wire, false);
            return;
        }
        let Some(peer) = self.peers.get_mut(&source) else {
            if self.stashed.len() >= MAX_STASHED {
                self.stashed.pop_front();
            }
            self.stashed.push_back(Stashed {
                received: now,
                from,
                packet: wire,
            });
            self.note_unknown_source(now, source);
            return;
        };
        if !packet::dearmor(&mut wire, &peer.key)
            || !peer.recent_packets.first_sight(packet::packet_id(&wire))
            || !packet::uncompress(&mut wire)
        {
            return;
        }
        let code = packet::verb_of(&wire);
        let mut confirms_path = false;
        match code {
            verb::HELLO => {
                self.on_hello(now, from, wire, true);
                return;
            }
            verb::ERROR => self.on_error(now, source, &wire),
            verb::OK => {
                if !self.on_ok(now, source, &wire) {
                    return;
                }
                confirms_path = true;
            }
            verb::RENDEZVOUS => self.on_rendezvous(now, source, &wire),
            verb::FRAME => {
                if !self.on_frame(now, from, source, &wire) {
                    return;
                }
            }
            verb::EXT_FRAME => {
                if !self.on_ext_frame(now, from, source, &wire) {
                    return;
                }
            }
            verb::ECHO => self.on_echo(now, from, source, &wire),
            verb::MULTICAST_LIKE => self.on_multicast_like(now, source, &wire),
            verb::NETWORK_CREDENTIALS => self.on_credentials(now, source, &wire),
            verb::NETWORK_CONFIG => self.on_network_config(now, from, source, &wire),
            verb::MULTICAST_FRAME => {
                if !self.on_multicast_frame(now, from, source, &wire) {
                    return;
                }
            }
            _ => {}
        }
        self.received(now, from, source, packet::hops(&wire), confirms_path);
    }

    fn note_unknown_source(&mut self, now: i64, source: Address) {
        if self.pending.contains_key(&source) {
            return;
        }
        if !self.unknown_sources.contains_key(&source)
            && self.unknown_sources.len() >= MAX_UNKNOWN_SOURCES
            && let Some(oldest) = self
                .unknown_sources
                .iter()
                .min_by_key(|(_, entry)| entry.first_seen)
                .map(|(address, _)| *address)
        {
            self.unknown_sources.remove(&oldest);
        }
        let entry = self.unknown_sources.entry(source).or_insert(UnknownSource {
            first_seen: now,
            last_whois: i64::MIN / 2,
        });
        if now - entry.last_whois >= WHOIS_RETRY_DELAY {
            self.request_whois_for_unknown_source(now, source);
        }
    }

    /// Learns paths only from answers to our own requests, as `Peer::received` does: anything
    /// else arriving on a new path triggers a HELLO, whose OK then confirms that path.
    fn received(
        &mut self,
        now: i64,
        from: SocketAddr,
        source: Address,
        hops: u8,
        confirms_path: bool,
    ) {
        let Some(peer) = self.peers.get_mut(&source) else {
            return;
        };
        peer.last_receive = now;
        if hops != 0 {
            return;
        }
        if let Some(path) = peer.paths.iter_mut().find(|path| path.address == from) {
            path.last_receive = now;
            return;
        }
        if confirms_path {
            if peer.paths.len() >= MAX_PATHS
                && let Some(oldest) = peer
                    .paths
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, path)| path.last_receive)
                    .map(|(index, _)| index)
            {
                peer.paths.swap_remove(oldest);
            }
            peer.paths.push(Path {
                address: from,
                last_receive: now,
                last_send: now,
            });
        } else if now - peer.last_contact_attempt >= CONTACT_RATE_LIMIT {
            peer.last_contact_attempt = now;
            self.send_hello(now, source, from);
        }
    }

    fn identity_gate_passes(&mut self, now: i64, from: SocketAddr) -> bool {
        let hash = match from.ip().to_canonical() {
            IpAddr::V4(ip) => {
                let octets = ip.octets();
                (usize::from(octets[0]) << 16
                    | usize::from(octets[1]) << 8
                    | usize::from(octets[2]))
                .wrapping_mul(2_654_435_761)
            }
            IpAddr::V6(ip) => {
                let octets = ip.octets();
                let mut value = 0usize;
                for octet in &octets[..6] {
                    value = (value << 8 | usize::from(*octet)).wrapping_mul(2_654_435_761);
                }
                value
            }
        };
        let last = &mut self.identity_gate[hash % IDENTITY_GATE_BUCKETS];
        if now - *last >= IDENTITY_VALIDATION_RATE_LIMIT {
            *last = now;
            true
        } else {
            false
        }
    }

    fn add_peer(&mut self, identity: Identity, key: Zeroizing<[u8; 32]>) {
        if self.peers.len() >= MAX_PEERS
            && let Some(oldest) = self
                .peers
                .iter()
                .filter(|(_, peer)| !peer.pinned)
                .min_by_key(|(_, peer)| peer.last_receive)
                .map(|(address, _)| *address)
        {
            self.peers.remove(&oldest);
        }
        let address = identity.address();
        let pinned = address == self.controller;
        self.peers
            .insert(address, Peer::new(identity, key, pinned, Vec::new()));
    }

    fn peer_learned(&mut self, now: i64, address: Address) {
        self.unknown_sources.remove(&address);
        if let Some(entry) = self.pending.remove(&address) {
            for (code, body) in entry.packets {
                self.send_verb(now, address, code, body);
            }
        }
        let mut retained = VecDeque::with_capacity(self.stashed.len());
        let mut ready = Vec::new();
        while let Some(item) = self.stashed.pop_front() {
            if packet::source(&item.packet) == address {
                ready.push(item);
            } else {
                retained.push_back(item);
            }
        }
        self.stashed = retained;
        for item in ready {
            self.decode(now, item.from, item.packet);
        }
    }

    fn on_hello(&mut self, now: i64, from: SocketAddr, mut wire: Vec<u8>, authenticated: bool) {
        let parsed = (|| {
            let mut reader = Reader::new(&wire[packet::IDX_PAYLOAD..]);
            let version = reader.u8()?;
            reader.skip(1 + 1 + 2)?;
            let timestamp = reader.array::<8>()?;
            let identity = Identity::deserialize(&mut reader)?;
            Some((version, timestamp, identity))
        })();
        let Some((version, timestamp, identity)) = parsed else {
            return;
        };
        let source = packet::source(&wire);
        if version < MIN_PROTOCOL_VERSION || source != identity.address() || identity.has_secret() {
            return;
        }
        let packet_id = packet::packet_id(&wire);
        match self.peers.get_mut(&source) {
            Some(peer) => {
                if !authenticated
                    && (peer.identity != identity
                        || !packet::dearmor(&mut wire, &peer.key)
                        || !peer.recent_packets.first_sight(packet_id))
                {
                    return;
                }
            }
            None => {
                // The MAC needs the key agreement, so that comes first under its own budget.
                // The per-network gate is spent only on packets that really carry this identity.
                if authenticated
                    || self.identity_checks.len() >= MAX_UNSOLICITED_IDENTITY_CHECKS
                    || !self
                        .stranger_hello_rate
                        .allow(now, STRANGER_HELLO_AGREEMENTS_PER_SECOND)
                {
                    return;
                }
                let Ok(key) = self.identity.agree(&identity) else {
                    return;
                };
                if !packet::dearmor(&mut wire, &key) || !self.identity_gate_passes(now, from) {
                    return;
                }
                self.start_identity_check(
                    now,
                    identity,
                    key,
                    AfterCheck::Hello {
                        from,
                        wire,
                        timestamp,
                    },
                    MAX_UNSOLICITED_IDENTITY_CHECKS,
                );
                return;
            }
        }
        self.answer_hello(now, from, &wire, timestamp);
    }

    fn answer_hello(&mut self, now: i64, from: SocketAddr, wire: &[u8], timestamp: [u8; 8]) {
        let mut body = Vec::with_capacity(48);
        body.push(verb::HELLO);
        body.extend_from_slice(&wire[..8]);
        body.extend_from_slice(&timestamp);
        body.push(PROTOCOL_VERSION);
        body.push(SOFTWARE_MAJOR);
        body.push(SOFTWARE_MINOR);
        body.extend_from_slice(&SOFTWARE_REVISION.to_be_bytes());
        inet::serialize(from, &mut body);
        body.extend_from_slice(&[0, 0]);
        let source = packet::source(wire);
        self.send_direct(now, source, from, verb::OK, body);
        self.received(now, from, source, packet::hops(wire), false);
    }

    fn start_identity_check(
        &mut self,
        now: i64,
        identity: Identity,
        key: Zeroizing<[u8; 32]>,
        then: AfterCheck,
        limit: usize,
    ) {
        // Dedup on the whole identity: the address is only a claim until the check passes, so
        // a forged claim must not displace the real identity behind the same address.
        if self.identity_checks.len() >= limit
            || self
                .identity_checks
                .values()
                .any(|check| check.identity == identity)
        {
            return;
        }
        self.next_identity_check += 1;
        let id = self.next_identity_check;
        self.events.push_back(Event::IdentityCheck(IdentityCheck {
            id,
            identity: identity.clone(),
        }));
        self.identity_checks.insert(
            id,
            PendingCheck {
                started: now,
                identity,
                key,
                then,
            },
        );
    }

    /// Learns the peer behind a passed check and resumes what was waiting for it. A verdict
    /// for a check that already timed out is ignored.
    pub fn on_identity_verdict(&mut self, now: i64, verdict: IdentityVerdict) {
        let Some(check) = self.identity_checks.remove(&verdict.id) else {
            return;
        };
        let address = check.identity.address();
        if !verdict.valid || self.peers.contains_key(&address) {
            return;
        }
        self.add_peer(check.identity, check.key);
        if let AfterCheck::Hello {
            from,
            wire,
            timestamp,
        } = check.then
        {
            if let Some(peer) = self.peers.get_mut(&address) {
                peer.recent_packets.first_sight(packet::packet_id(&wire));
            }
            self.answer_hello(now, from, &wire, timestamp);
        }
        self.peer_learned(now, address);
    }

    fn on_error(&mut self, now: i64, source: Address, wire: &[u8]) {
        let mut reader = Reader::new(&wire[packet::IDX_PAYLOAD..]);
        let (Some(in_re), Some(_), Some(code)) = (reader.u8(), reader.u64(), reader.u8()) else {
            return;
        };
        let network = reader.u64();
        let from_controller = source == self.controller;
        let for_config = in_re == verb::NETWORK_CONFIG_REQUEST;
        match code {
            error_code::OBJ_NOT_FOUND | error_code::UNSUPPORTED_OPERATION
                if for_config && from_controller && network == Some(self.network_id) =>
            {
                self.set_status(JoinStatus::NotFound);
            }
            error_code::NETWORK_ACCESS_DENIED
                if from_controller && network == Some(self.network_id) =>
            {
                self.set_status(JoinStatus::AccessDenied);
            }
            error_code::NETWORK_AUTHENTICATION_REQUIRED
                if from_controller && network == Some(self.network_id) =>
            {
                self.set_status(JoinStatus::AuthenticationRequired);
            }
            error_code::IDENTITY_COLLISION if self.roots.contains(&source) => {
                self.set_status(JoinStatus::IdentityCollision);
            }
            error_code::NEED_MEMBERSHIP_CERTIFICATE if network == Some(self.network_id) => {
                let due = self.peers.get(&source).is_some_and(|peer| {
                    now - peer.last_credential_push >= CREDENTIAL_REQUEST_RATE_LIMIT
                });
                if due {
                    self.push_credentials(now, source);
                }
            }
            error_code::UNWANTED_MULTICAST if network == Some(self.network_id) => {
                if let (Some(mac), Some(adi)) = (reader.array::<6>(), reader.u32())
                    && self.gate(source)
                {
                    let group = MulticastGroup {
                        mac: Mac::from_bytes(&mac),
                        adi,
                    };
                    if let Some(state) = self.groups.get_mut(&group) {
                        state.members.remove(&source);
                    }
                }
            }
            _ => {}
        }
    }

    fn set_status(&mut self, status: JoinStatus) {
        if self.status != status {
            self.status = status;
            self.events.push_back(Event::Status(status));
        }
    }

    /// Returns whether this OK answers an outstanding request of ours to its sender.
    fn on_ok(&mut self, now: i64, source: Address, wire: &[u8]) -> bool {
        let mut reader = Reader::new(&wire[packet::IDX_PAYLOAD..]);
        let (Some(in_re), Some(id)) = (reader.u8(), reader.u64()) else {
            return false;
        };
        if !self.expected.answer(id, source, in_re)
            && !self.unknown_source_lookups.answer(id, source, in_re)
        {
            return false;
        }
        match in_re {
            verb::WHOIS if self.roots.contains(&source) => {
                while reader.remaining() > 0 {
                    let Some(identity) = Identity::deserialize(&mut reader) else {
                        return true;
                    };
                    self.on_whois_identity(now, identity);
                }
            }
            verb::NETWORK_CONFIG_REQUEST
                if reader.rest().get(..8) == Some(&self.network_id.to_be_bytes()[..]) =>
            {
                let payload = reader.rest();
                self.accept_config(now, packet::packet_id(wire), source, payload);
            }
            verb::MULTICAST_GATHER => self.on_gather_result(now, &mut reader),
            _ => {}
        }
        true
    }

    fn on_whois_identity(&mut self, now: i64, identity: Identity) {
        let address = identity.address();
        let limit = if self.pending.contains_key(&address) {
            MAX_IDENTITY_CHECKS
        } else if self.unknown_sources.contains_key(&address) {
            MAX_UNSOLICITED_IDENTITY_CHECKS
        } else {
            return;
        };
        if self.peers.contains_key(&address) || address == self.address || identity.has_secret() {
            return;
        }
        if let Ok(key) = self.identity.agree(&identity) {
            self.start_identity_check(now, identity, key, AfterCheck::Whois, limit);
        }
    }

    fn on_gather_result(&mut self, now: i64, reader: &mut Reader<'_>) {
        let (Some(network), Some(mac), Some(adi)) =
            (reader.u64(), reader.array::<6>(), reader.u32())
        else {
            return;
        };
        if network != self.network_id || reader.skip(4).is_none() {
            return;
        }
        let Some(count) = reader.u16() else {
            return;
        };
        let group = MulticastGroup {
            mac: Mac::from_bytes(&mac),
            adi,
        };
        for _ in 0..count {
            let Some(bytes) = reader.array::<5>() else {
                return;
            };
            self.add_group_member(now, group, Address::from_bytes(&bytes));
        }
    }

    fn add_group_member(&mut self, now: i64, group: MulticastGroup, member: Address) {
        if member == self.address || member.is_reserved() {
            return;
        }
        if !self.groups.contains_key(&group) && self.groups.len() >= MAX_GROUPS {
            return;
        }
        let state = self.groups.entry(group).or_default();
        if state.members.contains_key(&member) || state.members.len() < MAX_GROUP_MEMBERS {
            state.members.insert(member, now);
        }
    }

    fn accept_config(
        &mut self,
        now: i64,
        packet_id: u64,
        source: Address,
        payload: &[u8],
    ) -> Option<u64> {
        let controller = self.peers.get(&self.controller)?.identity.clone();
        let assembled = self
            .assembler
            .accept(packet_id, source, &controller, payload)?;
        let config = assembled.config;
        if config.issued_to != self.address || config.network_id != self.network_id {
            return None;
        }
        let update_id = assembled.update_id;
        // 已签名的旧配置可被重放，修订号和时间戳都更旧时不回退。
        if self.config.as_deref().is_some_and(|current| {
            config.timestamp < current.timestamp && config.revision <= current.revision
        }) {
            return None;
        }
        if self.config.as_deref() != Some(&config) {
            let config = Arc::new(config);
            self.config = Some(config.clone());
            self.subscribe(&config);
            self.events.push_back(Event::Config(config));
            self.announce(now);
        }
        self.set_status(JoinStatus::Joined);
        Some(update_id)
    }

    fn subscribe(&mut self, config: &NetworkConfig) {
        let mut groups: Vec<MulticastGroup> = config
            .static_ips
            .iter()
            .map(|(ip, _)| MulticastGroup::for_address_resolution(*ip))
            .collect();
        if config.enable_broadcast() {
            groups.push(MulticastGroup::BROADCAST);
        }
        groups.dedup();
        self.subscriptions = groups;
    }

    fn on_network_config(&mut self, now: i64, from: SocketAddr, source: Address, wire: &[u8]) {
        let payload = &wire[packet::IDX_PAYLOAD..];
        if payload.get(..8) != Some(&self.network_id.to_be_bytes()[..]) {
            return;
        }
        let id = packet::packet_id(wire);
        if let Some(update_id) = self.accept_config(now, id, source, payload) {
            let mut body = Vec::with_capacity(25);
            body.push(verb::ECHO);
            body.extend_from_slice(&id.to_be_bytes());
            body.extend_from_slice(&self.network_id.to_be_bytes());
            body.extend_from_slice(&update_id.to_be_bytes());
            self.send_direct(now, source, from, verb::OK, body);
        }
    }

    fn on_rendezvous(&mut self, now: i64, source: Address, wire: &[u8]) {
        if !self.roots.contains(&source) {
            return;
        }
        let parsed = (|| {
            let mut reader = Reader::new(&wire[packet::IDX_PAYLOAD..]);
            reader.skip(1)?;
            let with = Address::from_bytes(&reader.array()?);
            let port = reader.u16()?;
            let ip = match reader.u8()? {
                4 => IpAddr::from(reader.array::<4>()?),
                16 => IpAddr::from(reader.array::<16>()?),
                _ => return None,
            };
            (port != 0).then_some((with, SocketAddr::new(ip, port)))
        })();
        if let Some((with, at)) = parsed
            && self.peers.contains_key(&with)
        {
            self.send_hello(now, with, at);
        }
    }

    fn on_echo(&mut self, now: i64, from: SocketAddr, source: Address, wire: &[u8]) {
        let Some(peer) = self.peers.get_mut(&source) else {
            return;
        };
        if now - peer.last_echo < ECHO_RATE_LIMIT {
            return;
        }
        peer.last_echo = now;
        let mut body = Vec::with_capacity(9 + wire.len() - packet::IDX_PAYLOAD);
        body.push(verb::ECHO);
        body.extend_from_slice(&wire[..8]);
        body.extend_from_slice(&wire[packet::IDX_PAYLOAD..]);
        self.send_direct(now, source, from, verb::OK, body);
    }

    fn on_multicast_like(&mut self, now: i64, source: Address, wire: &[u8]) {
        if !self.gate(source) {
            return;
        }
        for tuple in wire[packet::IDX_PAYLOAD..].chunks_exact(18) {
            let mut reader = Reader::new(tuple);
            if let (Some(network), Some(mac), Some(adi)) =
                (reader.u64(), reader.array::<6>(), reader.u32())
                && network == self.network_id
            {
                let group = MulticastGroup {
                    mac: Mac::from_bytes(&mac),
                    adi,
                };
                self.add_group_member(now, group, source);
            }
        }
    }

    /// Takes the certificates at the head of the packet. Capabilities, tags, revocations and
    /// certificates of ownership that follow are ignored because no rule engine consumes them.
    fn on_credentials(&mut self, now: i64, source: Address, wire: &[u8]) {
        let mut reader = Reader::new(&wire[packet::IDX_PAYLOAD..]);
        while reader.rest().first().is_some_and(|byte| *byte != 0) {
            let Some(com) = CertificateOfMembership::deserialize(&mut reader) else {
                return;
            };
            self.add_certificate(now, source, com);
        }
    }

    fn add_certificate(&mut self, now: i64, source: Address, com: CertificateOfMembership) {
        if com.network_id() != Some(self.network_id) || com.issued_to() != Some(source) {
            return;
        }
        let Some(controller) = self
            .peers
            .get(&self.controller)
            .map(|peer| peer.identity.clone())
        else {
            if let Some(entry) = self.pending_entry(now, self.controller)
                && now - entry.last_whois >= WHOIS_RETRY_DELAY
            {
                self.request_whois(now, self.controller);
            }
            return;
        };
        let Some(peer) = self.peers.get_mut(&source) else {
            return;
        };
        if peer.com.as_ref() == Some(&com) {
            return;
        }
        let newer = match (&peer.com, com.timestamp()) {
            (Some(old), Some(timestamp)) => old.timestamp().is_none_or(|old| timestamp >= old),
            (None, Some(_)) => true,
            (_, None) => false,
        };
        if newer && com.verify(&controller) {
            peer.com = Some(com);
        }
    }

    /// Asks the sender for credentials and reports the frame as not admitted.
    fn refuse(&mut self, now: i64, from: SocketAddr, source: Address, wire: &[u8]) -> bool {
        let Some(peer) = self.peers.get_mut(&source) else {
            return false;
        };
        if now - peer.last_credential_request >= CREDENTIAL_REQUEST_RATE_LIMIT {
            peer.last_credential_request = now;
            let mut body = Vec::with_capacity(18);
            body.push(packet::verb_of(wire));
            body.extend_from_slice(&wire[..8]);
            body.push(error_code::NEED_MEMBERSHIP_CERTIFICATE);
            body.extend_from_slice(&self.network_id.to_be_bytes());
            self.send_direct(now, source, from, verb::ERROR, body);
        }
        false
    }

    fn deliver(&mut self, now: i64, source: Address, frame: Frame) {
        if let Some(peer) = self.peers.get_mut(&source) {
            peer.last_traffic = now;
        }
        self.events.push_back(Event::Frame(frame));
    }

    fn on_frame(&mut self, now: i64, from: SocketAddr, source: Address, wire: &[u8]) -> bool {
        let mut reader = Reader::new(&wire[packet::IDX_PAYLOAD..]);
        let Some(network) = reader.u64() else {
            return true;
        };
        if network != self.network_id {
            return true;
        }
        if !self.gate(source) {
            return self.refuse(now, from, source, wire);
        }
        if let Some(ethertype) = reader.u16()
            && reader.remaining() > 0
        {
            let frame = Frame {
                from: Mac::from_address(source, network),
                to: self.mac,
                ethertype,
                payload: reader.rest().to_vec(),
            };
            self.deliver(now, source, frame);
        }
        true
    }

    fn on_ext_frame(&mut self, now: i64, from: SocketAddr, source: Address, wire: &[u8]) -> bool {
        let mut reader = Reader::new(&wire[packet::IDX_PAYLOAD..]);
        let (Some(network), Some(flags)) = (reader.u64(), reader.u8()) else {
            return true;
        };
        if network != self.network_id {
            return true;
        }
        if flags & 0x01 != 0 {
            let Some(com) = CertificateOfMembership::deserialize(&mut reader) else {
                return true;
            };
            self.add_certificate(now, source, com);
        }
        if !self.gate(source) {
            return self.refuse(now, from, source, wire);
        }
        if let (Some(to), Some(sender), Some(ethertype)) =
            (reader.array::<6>(), reader.array::<6>(), reader.u16())
            && reader.remaining() > 0
        {
            let to = Mac::from_bytes(&to);
            let sender = Mac::from_bytes(&sender);
            // A sender MAC other than the peer's own would be bridged traffic.
            if sender == Mac::from_address(source, network) && (to == self.mac || to.is_multicast())
            {
                let frame = Frame {
                    from: sender,
                    to,
                    ethertype,
                    payload: reader.rest().to_vec(),
                };
                self.deliver(now, source, frame);
            }
        }
        if flags & 0x10 != 0 {
            let mut body = Vec::with_capacity(17);
            body.push(verb::EXT_FRAME);
            body.extend_from_slice(&wire[..8]);
            body.extend_from_slice(&network.to_be_bytes());
            self.send_direct(now, source, from, verb::OK, body);
        }
        true
    }

    fn on_multicast_frame(
        &mut self,
        now: i64,
        from: SocketAddr,
        source: Address,
        wire: &[u8],
    ) -> bool {
        let mut reader = Reader::new(&wire[packet::IDX_PAYLOAD..]);
        let (Some(network), Some(flags)) = (reader.u64(), reader.u8()) else {
            return true;
        };
        if network != self.network_id {
            return true;
        }
        if flags & 0x01 != 0 {
            let Some(com) = CertificateOfMembership::deserialize(&mut reader) else {
                return true;
            };
            self.add_certificate(now, source, com);
        }
        if !self.gate(source) {
            return self.refuse(now, from, source, wire);
        }
        if flags & 0x02 != 0 && reader.skip(4).is_none() {
            return true;
        }
        let peer_mac = Mac::from_address(source, network);
        let sender = if flags & 0x04 != 0 {
            let Some(sender) = reader.array::<6>() else {
                return true;
            };
            Mac::from_bytes(&sender)
        } else {
            peer_mac
        };
        let (Some(to), Some(_adi), Some(ethertype)) =
            (reader.array::<6>(), reader.u32(), reader.u16())
        else {
            return true;
        };
        let to = Mac::from_bytes(&to);
        let limit = self
            .config
            .as_ref()
            .map_or(0, |config| config.multicast_limit);
        if limit != 0
            && reader.remaining() > 0
            && to.is_multicast()
            && sender == peer_mac
            && sender != self.mac
            && !sender.is_zero()
        {
            let frame = Frame {
                from: sender,
                to,
                ethertype,
                payload: reader.rest().to_vec(),
            };
            self.deliver(now, source, frame);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::tests::{dictionary_for, signed_chunk};

    const CONTROLLER: &str = crate::network::tests::CONTROLLER;
    const ALICE: &str = "26fdbcd524:0:ade8db815db56cb544adea61ef3023deacbf7194352d2d353477505b179a0248cbf8091d5f179fe4ea1db72bcea0162c4775f47088aa688f7fc7d70ccb7b74c6:a0ed2afd4e7a3bbaef3887e362496efa83b1c0e32596c09f427afecd6fa60a97bac7c41e0931fb6c64d498d60d0b2f9df24d39283db2eb734693864b7c4399ca";
    const BOB: &str = "8a013571a2:0:0f711554a5aa81e383f19dd332cb4d7d28d0a159cc1d4ba02023266babe6860bb675010ab16792c22ec4393eec776ee678a16d713f3d686b0d6c9e2edda20a51:628375b56c13313b6225909d7fea6cbd8bc2e0787d320c06fc704ff4d405364be46fc9f440b3f42c862e1ccf631b6d5a54b1d63cb321c143ed223eceaceba4a3";
    const NETWORK: u64 = 0x6c38_6dc8_6900_0001;

    fn endpoint(port: u16) -> SocketAddr {
        SocketAddr::from(([192, 0, 2, 1], port))
    }

    fn public(identity: &Identity) -> Identity {
        Identity::parse(&identity.to_public_string()).unwrap()
    }

    fn node(me: &str, others: &[(&Identity, u16)]) -> Node {
        Node::new(NodeOptions {
            identity: Identity::parse(me).unwrap(),
            network_id: NETWORK,
            roots: Vec::new(),
            peers: others
                .iter()
                .map(|(identity, port)| Seed {
                    identity: public(identity),
                    endpoints: vec![endpoint(*port)],
                })
                .collect(),
        })
        .unwrap()
    }

    fn drain(node: &mut Node) -> Vec<Event> {
        std::iter::from_fn(|| node.poll_event()).collect()
    }

    /// Delivers datagrams between two nodes on ports 1 and 2 until both go quiet.
    fn exchange(now: i64, a: &mut Node, b: &mut Node, seen: &mut Vec<Event>) {
        for _ in 0..16 {
            let mut idle = true;
            for event in drain(a) {
                match event {
                    Event::Datagram { to, data } if to == endpoint(2) => {
                        idle = false;
                        b.on_datagram(now, endpoint(1), &data);
                    }
                    Event::Datagram { .. } => {}
                    other => seen.push(other),
                }
            }
            for event in drain(b) {
                match event {
                    Event::Datagram { to, data } if to == endpoint(1) => {
                        idle = false;
                        a.on_datagram(now, endpoint(2), &data);
                    }
                    Event::Datagram { .. } => {}
                    other => seen.push(other),
                }
            }
            if idle {
                return;
            }
        }
    }

    fn give_config(node: &mut Node, controller: &Identity, ip: &str, timestamp: u64) {
        let dictionary = dictionary_for(controller, &public(&node.identity), ip, timestamp);
        let chunk = signed_chunk(controller, &dictionary, timestamp, 0..dictionary.len());
        node.accept_config(0, 9, controller.address(), &chunk)
            .unwrap();
        drain(node);
    }

    fn joined_pair() -> (Node, Node, Identity) {
        let controller = Identity::parse(CONTROLLER).unwrap();
        let alice = Identity::parse(ALICE).unwrap();
        let bob = Identity::parse(BOB).unwrap();
        let mut a = node(ALICE, &[(&bob, 2), (&controller, 3)]);
        let mut b = node(BOB, &[(&alice, 1), (&controller, 3)]);
        give_config(&mut a, &controller, "10.9.0.1", 100_000);
        give_config(&mut b, &controller, "10.9.0.2", 100_000);
        (a, b, controller)
    }

    #[test]
    fn hello_exchange_confirms_a_direct_path_on_both_sides() {
        let bob = Identity::parse(BOB).unwrap();
        let alice = Identity::parse(ALICE).unwrap();
        let mut a = node(ALICE, &[(&bob, 2)]);
        let mut b = node(BOB, &[(&alice, 1)]);
        a.tick(1000);
        exchange(1000, &mut a, &mut b, &mut Vec::new());
        assert_eq!(
            a.peers[&bob.address()].best_alive_path(1000),
            Some(endpoint(2))
        );
        // Bob's side confirms through the HELLO it sends back on the new path.
        assert_eq!(
            b.peers[&alice.address()].best_alive_path(1000),
            Some(endpoint(1))
        );
    }

    #[test]
    fn stranger_with_forged_address_is_not_learned() {
        let bob = Identity::parse(BOB).unwrap();
        let mut a = node(ALICE, &[]);
        let mut sender = node(BOB, &[(&public(&a.identity), 1)]);
        sender.tick(1000);
        let Some(Event::Datagram { mut data, .. }) = sender
            .poll_event()
            .filter(|event| matches!(event, Event::Datagram { .. }))
        else {
            panic!("expected a HELLO");
        };
        let mut forged = data.clone();
        forged[packet::IDX_SOURCE] ^= 1;
        a.on_datagram(1000, endpoint(2), &forged);
        assert!(a.peers.is_empty());
        // A flipped payload byte fails the MAC before any proof of work is requested.
        *data.last_mut().unwrap() ^= 1;
        a.on_datagram(5000, endpoint(2), &data);
        assert!(!a.peers.contains_key(&bob.address()));
        assert!(drain(&mut a).is_empty());
    }

    #[test]
    fn valid_stranger_is_learned_after_proof_of_work_and_answered() {
        let bob = Identity::parse(BOB).unwrap();
        let mut a = node(ALICE, &[]);
        let mut sender = node(BOB, &[(&public(&a.identity), 1)]);
        sender.tick(1000);
        let Some(Event::Datagram { data, .. }) = sender.poll_event() else {
            panic!("expected a HELLO");
        };
        a.on_datagram(1000, endpoint(2), &data);
        assert!(
            !a.peers.contains_key(&bob.address()),
            "not before the check"
        );
        let checks = identity_checks(&mut a);
        assert_eq!(checks.len(), 1);
        a.on_identity_verdict(1000, checks[0].run());
        assert!(a.peers.contains_key(&bob.address()));
        let replies = drain(&mut a);
        assert!(replies.iter().all(|event| matches!(
            event,
            Event::Datagram { to, .. } if *to == endpoint(2)
        )));
        assert_eq!(replies.len(), 2, "OK plus a HELLO to confirm the new path");
    }

    fn identity_checks(node: &mut Node) -> Vec<IdentityCheck> {
        drain(node)
            .into_iter()
            .filter_map(|event| match event {
                Event::IdentityCheck(check) => Some(check),
                _ => None,
            })
            .collect()
    }

    fn frames(events: &[Event]) -> Vec<Frame> {
        events
            .iter()
            .filter_map(|event| match event {
                Event::Frame(frame) => Some(frame.clone()),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn unicast_frame_is_refused_until_credentials_arrive_then_delivered() {
        let (mut a, mut b, _) = joined_pair();
        let bob_address = b.address;
        let alice_address = a.address;
        let (alice_mac, bob_mac) = (a.mac, b.mac);
        let mut seen = Vec::new();
        let now = 200_000;
        a.tick(now);
        exchange(now, &mut a, &mut b, &mut seen);
        b.peers.get_mut(&alice_address).unwrap().com = None;

        // Recently pushed from Alice's view, so this frame travels without a certificate.
        a.peers.get_mut(&bob_address).unwrap().last_credential_push = now - 2000;
        seen.clear();
        a.send_frame(now, bob_mac, 0x0800, b"early");
        exchange(now, &mut a, &mut b, &mut seen);
        assert!(frames(&seen).is_empty());
        assert!(
            b.peers[&alice_address].com.is_some(),
            "ERROR prompted a push"
        );

        seen.clear();
        let payload = vec![0x5a; 2800];
        a.send_frame(now, bob_mac, 0x0800, &payload);
        exchange(now, &mut a, &mut b, &mut seen);
        assert_eq!(
            frames(&seen),
            [Frame {
                from: alice_mac,
                to: bob_mac,
                ethertype: 0x0800,
                payload,
            }]
        );
    }

    #[test]
    fn certificates_for_other_members_or_from_stale_signers_do_not_open_the_gate() {
        let (mut a, b, controller) = joined_pair();
        let bob_address = b.address;
        let alice = public(&a.identity);
        let wrong_member =
            crate::certificate::tests::issue(&controller, NETWORK, &alice, 100_000, 7_200_000);
        a.add_certificate(0, bob_address, wrong_member);
        assert!(!a.gate(bob_address));

        let not_controller = Identity::parse(BOB).unwrap();
        let bob = public(&not_controller);
        let forged = crate::certificate::tests::issue(&not_controller, NETWORK, &bob, 100_000, 1);
        a.add_certificate(0, bob_address, forged);
        assert!(!a.gate(bob_address));

        let genuine =
            crate::certificate::tests::issue(&controller, NETWORK, &bob, 100_000, 7_200_000);
        a.add_certificate(0, bob_address, genuine);
        assert!(a.gate(bob_address));
    }

    #[test]
    fn multicast_reaches_known_members_and_empty_groups_gather_from_controller() {
        let (mut a, mut b, controller) = joined_pair();
        let group = MulticastGroup::for_address_resolution("10.9.0.2".parse().unwrap());
        let now = 200_000;
        let mut seen = Vec::new();
        a.tick(now);
        exchange(now, &mut a, &mut b, &mut seen);
        seen.clear();

        a.send_multicast(now, group, 0x0806, b"who-has");
        let gather = drain(&mut a)
            .into_iter()
            .find_map(|event| match event {
                Event::Datagram { to, data } if to == endpoint(3) => Some(data),
                _ => None,
            })
            .expect("controller receives a gather");
        let mut plain = gather;
        let key = Identity::parse(CONTROLLER)
            .unwrap()
            .agree(&public(&a.identity))
            .unwrap();
        assert!(packet::dearmor(&mut plain, &key));
        assert_eq!(packet::verb_of(&plain), verb::MULTICAST_GATHER);
        assert_eq!(&plain[28..36], &NETWORK.to_be_bytes());
        assert_eq!(plain[36], 1, "certificate attached");
        assert_eq!(&plain[37..43], &group.mac.to_bytes());
        assert_eq!(&plain[43..47], &group.adi.to_be_bytes());

        let mut reply = Vec::new();
        reply.push(verb::MULTICAST_GATHER);
        reply.extend_from_slice(&plain[..8]);
        reply.extend_from_slice(&NETWORK.to_be_bytes());
        reply.extend_from_slice(&group.mac.to_bytes());
        reply.extend_from_slice(&group.adi.to_be_bytes());
        reply.extend_from_slice(&1u32.to_be_bytes());
        reply.extend_from_slice(&1u16.to_be_bytes());
        reply.extend_from_slice(&b.address.to_bytes());
        let wire = packet::new_packet(a.address, controller.address(), verb::OK, &reply);
        let datagrams = packet::seal(wire, &key, true).unwrap();
        a.on_datagram(now, endpoint(3), &datagrams[0]);
        drain(&mut a);

        a.send_multicast(now + 1, group, 0x0806, b"who-has");
        exchange(now + 1, &mut a, &mut b, &mut seen);
        let delivered = frames(&seen);
        assert_eq!(delivered.len(), 1);
        assert_eq!(delivered[0].to, group.mac);
        assert_eq!(delivered[0].from, a.mac);
        assert_eq!(delivered[0].payload, b"who-has");
    }

    #[test]
    fn replayed_older_config_does_not_roll_the_network_back() {
        let controller = Identity::parse(CONTROLLER).unwrap();
        let mut a = node(ALICE, &[(&controller, 3)]);
        give_config(&mut a, &controller, "10.9.0.1", 2000);
        let older = dictionary_for(&controller, &public(&a.identity), "10.9.0.9", 1000);
        let chunk = signed_chunk(&controller, &older, 11, 0..older.len());
        assert!(
            a.accept_config(10, 2, controller.address(), &chunk)
                .is_none()
        );
        assert_eq!(a.config().unwrap().timestamp, 2000);
        give_config(&mut a, &controller, "10.9.0.2", 3000);
        assert_eq!(a.config().unwrap().timestamp, 3000);
    }

    #[test]
    fn unsolicited_ok_is_ignored_and_config_for_another_member_is_refused() {
        let controller = Identity::parse(CONTROLLER).unwrap();
        let mut a = node(ALICE, &[(&controller, 3)]);
        let key = controller.agree(&public(&a.identity)).unwrap();
        let dictionary = dictionary_for(&controller, &public(&a.identity), "10.9.0.1", 1000);
        let chunk = signed_chunk(&controller, &dictionary, 7, 0..dictionary.len());
        let mut reply = vec![verb::NETWORK_CONFIG_REQUEST];
        reply.extend_from_slice(&5u64.to_be_bytes());
        reply.extend_from_slice(&chunk);
        let wire = packet::new_packet(a.address, controller.address(), verb::OK, &reply);
        a.on_datagram(10, endpoint(3), &packet::seal(wire, &key, true).unwrap()[0]);
        assert!(a.config().is_none());

        let other = Identity::parse(BOB).unwrap();
        let foreign = dictionary_for(&controller, &public(&other), "10.9.0.2", 1000);
        let chunk = signed_chunk(&controller, &foreign, 8, 0..foreign.len());
        assert!(
            a.accept_config(10, 1, controller.address(), &chunk)
                .is_none()
        );
        assert!(a.config().is_none());

        a.expected
            .insert(5, controller.address(), verb::NETWORK_CONFIG_REQUEST, 10);
        let wire = packet::new_packet(a.address, controller.address(), verb::OK, &reply);
        a.on_datagram(10, endpoint(3), &packet::seal(wire, &key, true).unwrap()[0]);
        let config = a.config().expect("solicited config is accepted");
        assert_eq!(
            config.static_ips[0].0,
            "10.9.0.1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(a.status(), JoinStatus::Joined);
        assert_eq!(a.subscriptions.len(), 2);
    }

    #[test]
    fn controller_denial_is_reported_only_from_the_controller() {
        let controller = Identity::parse(CONTROLLER).unwrap();
        let bob = Identity::parse(BOB).unwrap();
        let mut a = node(ALICE, &[(&controller, 3), (&bob, 2)]);
        let mut body = vec![verb::NETWORK_CONFIG_REQUEST];
        body.extend_from_slice(&1u64.to_be_bytes());
        body.push(error_code::NETWORK_ACCESS_DENIED);
        body.extend_from_slice(&NETWORK.to_be_bytes());

        let key = bob.agree(&public(&a.identity)).unwrap();
        let wire = packet::new_packet(a.address, bob.address(), verb::ERROR, &body);
        a.on_datagram(1, endpoint(2), &packet::seal(wire, &key, true).unwrap()[0]);
        assert_eq!(a.status(), JoinStatus::Requesting);

        let key = controller.agree(&public(&a.identity)).unwrap();
        let wire = packet::new_packet(a.address, controller.address(), verb::ERROR, &body);
        a.on_datagram(1, endpoint(3), &packet::seal(wire, &key, true).unwrap()[0]);
        assert_eq!(a.status(), JoinStatus::AccessDenied);
    }

    fn whois_requests(node: &mut Node, root_key: &[u8; 32]) -> Vec<Address> {
        let mut asked = Vec::new();
        for event in drain(node) {
            if let Event::Datagram { mut data, .. } = event
                && packet::dearmor(&mut data, root_key)
                && packet::verb_of(&data) == verb::WHOIS
            {
                let bytes = data[packet::IDX_PAYLOAD..][..5].try_into().unwrap();
                asked.push(Address::from_bytes(&bytes));
            }
        }
        asked
    }

    fn sent_to(node: &mut Node, destination: SocketAddr) -> Vec<Vec<u8>> {
        drain(node)
            .into_iter()
            .filter_map(|event| match event {
                Event::Datagram { to, data } if to == destination => Some(data),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn forged_sources_do_not_block_joining_or_flood_the_root() {
        let root = Identity::parse(BOB).unwrap();
        let mut a = Node::new(NodeOptions {
            identity: Identity::parse(ALICE).unwrap(),
            network_id: NETWORK,
            roots: vec![Seed {
                identity: public(&root),
                endpoints: vec![endpoint(2)],
            }],
            peers: Vec::new(),
        })
        .unwrap();
        let key = root.agree(&public(&a.identity)).unwrap();
        let controller = a.controller;
        let mut whois_sent = 0;
        let mut controller_lookups_after_expiry = 0;
        for now in (0..10_000).step_by(10) {
            let forged = packet::new_packet(
                a.address,
                Address::new(0x10_0000_0000 + now as u64),
                verb::FRAME,
                &[],
            );
            a.on_datagram(now, endpoint(9), &forged);
            if now % 250 == 0 {
                a.tick(now);
            }
            for asked in whois_requests(&mut a, &key) {
                whois_sent += 1;
                if asked == controller && now > 6_000 {
                    controller_lookups_after_expiry += 1;
                }
            }
        }
        assert!(
            controller_lookups_after_expiry >= 5,
            "controller lookups: {controller_lookups_after_expiry}"
        );
        assert!(whois_sent <= 120, "WHOIS sent in 10 s: {whois_sent}");
    }

    #[test]
    fn replayed_frame_is_delivered_once() {
        let (mut a, mut b, _) = joined_pair();
        let now = 200_000;
        a.tick(now);
        exchange(now, &mut a, &mut b, &mut Vec::new());
        a.send_frame(now, b.mac, 0x0800, b"once");
        let captured = sent_to(&mut a, endpoint(2));
        for data in captured.iter().chain(&captured) {
            b.on_datagram(now, endpoint(1), data);
        }
        assert_eq!(frames(&drain(&mut b)).len(), 1);
    }

    #[test]
    fn only_a_fresh_answer_to_our_own_request_teaches_a_path() {
        let bob = Identity::parse(BOB).unwrap();
        let alice = Identity::parse(ALICE).unwrap();
        let mut a = node(ALICE, &[(&bob, 2)]);
        let mut b = node(BOB, &[(&alice, 1)]);
        let key = bob.agree(&public(&alice)).unwrap();
        let attacker = endpoint(7);
        let knows = |a: &Node, address| {
            a.peers[&bob.address()]
                .paths
                .iter()
                .any(|path| path.address == address)
        };

        let mut unsolicited = vec![verb::HELLO];
        unsolicited.extend_from_slice(&7u64.to_be_bytes());
        let wire = packet::new_packet(alice.address(), bob.address(), verb::OK, &unsolicited);
        a.on_datagram(1000, attacker, &packet::seal(wire, &key, true).unwrap()[0]);
        assert!(!knows(&a, attacker), "OK that answers nothing");

        a.tick(1000);
        for data in sent_to(&mut a, endpoint(2)) {
            b.on_datagram(1000, endpoint(1), &data);
        }
        for data in sent_to(&mut b, endpoint(1)) {
            a.on_datagram(1000, endpoint(2), &data);
            a.on_datagram(1000, attacker, &data);
        }
        assert!(knows(&a, endpoint(2)), "the genuine answer is learned");
        assert!(!knows(&a, attacker), "a replay of it is not");
    }

    /// An identity with a working key pair that never went through the proof of work.
    fn unproven(address: u64, seed: u8) -> String {
        let exchange = [seed; 32];
        let public = x25519_dalek::x25519(exchange, x25519_dalek::X25519_BASEPOINT_BYTES);
        let hex = |bytes: &[u8]| {
            bytes
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        let signing = hex(&[seed; 32]);
        format!(
            "{address:010x}:0:{}{signing}:{}{signing}",
            hex(&public),
            hex(&exchange)
        )
    }

    fn hello_from(seed: &str, to: &Identity, now: i64) -> Vec<u8> {
        let mut sender = node(seed, &[(&public(to), 1)]);
        sender.tick(now);
        sent_to(&mut sender, endpoint(1)).remove(0)
    }

    fn other_network(octet: u8) -> SocketAddr {
        SocketAddr::from(([198, 51, octet, 1], 9000))
    }

    #[test]
    fn hello_with_a_bad_mac_does_not_spend_the_identity_gate() {
        let alice = Identity::parse(ALICE).unwrap();
        let mut a = node(ALICE, &[]);
        let genuine = hello_from(BOB, &alice, 1000);
        let mut junk = genuine.clone();
        *junk.last_mut().unwrap() ^= 1;
        a.on_datagram(1000, endpoint(2), &junk);
        assert!(identity_checks(&mut a).is_empty());
        a.on_datagram(1000, endpoint(2), &genuine);
        assert_eq!(identity_checks(&mut a).len(), 1);
    }

    #[test]
    fn stranger_key_agreements_are_rate_limited_per_second() {
        let alice = Identity::parse(ALICE).unwrap();
        let mut a = node(ALICE, &[]);
        let genuine = hello_from(BOB, &alice, 1000);
        let mut junk = genuine.clone();
        *junk.last_mut().unwrap() ^= 1;
        for _ in 0..STRANGER_HELLO_AGREEMENTS_PER_SECOND {
            a.on_datagram(5000, endpoint(2), &junk);
        }
        a.on_datagram(5000, endpoint(2), &genuine);
        assert!(identity_checks(&mut a).is_empty(), "budget spent");
        a.on_datagram(6000, endpoint(2), &genuine);
        assert_eq!(identity_checks(&mut a).len(), 1);
    }

    #[test]
    fn identity_without_proof_of_work_is_refused_and_frees_its_slot() {
        let alice = Identity::parse(ALICE).unwrap();
        let mut a = node(ALICE, &[]);
        let stranger = unproven(0x11_1111_1111, 1);
        a.on_datagram(1000, endpoint(2), &hello_from(&stranger, &alice, 1000));
        let checks = identity_checks(&mut a);
        a.on_identity_verdict(1000, checks[0].run());
        assert!(a.peers.is_empty());
        assert!(a.identity_checks.is_empty());
        assert!(drain(&mut a).is_empty(), "no reply to a failed identity");
    }

    #[test]
    fn verdict_after_the_timeout_learns_nothing() {
        let alice = Identity::parse(ALICE).unwrap();
        let mut a = node(ALICE, &[]);
        a.on_datagram(1000, endpoint(2), &hello_from(BOB, &alice, 1000));
        let checks = identity_checks(&mut a);
        let late = 1000 + IDENTITY_CHECK_TIMEOUT;
        a.tick(late);
        assert!(a.identity_checks.is_empty());
        a.on_identity_verdict(late, checks[0].run());
        assert!(a.peers.is_empty());
    }

    #[test]
    fn stranger_claiming_a_wanted_address_does_not_discard_the_whois_answer() {
        let alice = Identity::parse(ALICE).unwrap();
        let wanted = public(&Identity::parse(BOB).unwrap());
        let mut a = node(ALICE, &[]);
        a.pending_entry(1000, wanted.address());

        let stranger = unproven(wanted.address().value(), 1);
        a.on_datagram(1000, other_network(1), &hello_from(&stranger, &alice, 1000));
        a.on_whois_identity(1000, wanted.clone());

        let checks = identity_checks(&mut a);
        assert_eq!(checks.len(), 2, "the forged claim must not take the check");
        for check in &checks {
            a.on_identity_verdict(1000, check.run());
        }
        assert!(a.peers[&wanted.address()].identity == wanted);
    }

    #[test]
    fn repeated_whois_answer_with_the_same_identity_runs_one_check() {
        let wanted = public(&Identity::parse(BOB).unwrap());
        let mut a = node(ALICE, &[]);
        a.pending_entry(1000, wanted.address());
        a.on_whois_identity(1000, wanted.clone());
        a.on_whois_identity(1000, wanted);
        assert_eq!(identity_checks(&mut a).len(), 1);
    }

    #[test]
    fn saturated_checks_drop_strangers_but_keep_a_slot_for_our_own_lookups() {
        let alice = Identity::parse(ALICE).unwrap();
        let mut a = node(ALICE, &[]);
        for seed in 1..=4 {
            let stranger = unproven(0x11_1111_1100 + u64::from(seed), seed);
            let hello = hello_from(&stranger, &alice, 1000);
            a.on_datagram(1000, other_network(seed), &hello);
        }
        assert_eq!(a.identity_checks.len(), MAX_UNSOLICITED_IDENTITY_CHECKS);

        let wanted = public(&Identity::parse(BOB).unwrap());
        a.pending_entry(1000, wanted.address());
        a.on_whois_identity(1000, wanted);
        assert_eq!(a.identity_checks.len(), MAX_IDENTITY_CHECKS);
    }

    #[test]
    fn answers_must_come_from_the_asked_peer_and_are_consumed_once() {
        let mut expected = ExpectedReplies::new(4);
        let (asked, other) = (Address::new(1), Address::new(2));
        expected.insert(10, asked, verb::ECHO, 0);
        assert!(!expected.answer(10, other, verb::ECHO), "wrong peer");
        assert!(!expected.answer(10, asked, verb::HELLO), "wrong verb");
        assert!(expected.answer(10, asked, verb::ECHO));
        assert!(!expected.answer(10, asked, verb::ECHO), "already used");

        expected.insert(11, asked, verb::NETWORK_CONFIG_REQUEST, 0);
        assert!(expected.answer(11, asked, verb::NETWORK_CONFIG_REQUEST));
        assert!(
            expected.answer(11, asked, verb::NETWORK_CONFIG_REQUEST),
            "each config chunk repeats the request ID"
        );
        expected.expire(EXPECTED_REPLY_TIMEOUT);
        assert!(!expected.answer(11, asked, verb::NETWORK_CONFIG_REQUEST));
    }

    #[test]
    fn forged_flood_stays_bounded_and_cannot_evict_our_expected_replies() {
        let root = Identity::parse(BOB).unwrap();
        let mut a = Node::new(NodeOptions {
            identity: Identity::parse(ALICE).unwrap(),
            network_id: NETWORK,
            roots: vec![Seed {
                identity: public(&root),
                endpoints: vec![endpoint(2)],
            }],
            peers: Vec::new(),
        })
        .unwrap();
        a.expected.insert(77, root.address(), verb::ECHO, 0);
        for now in 0..5_000 {
            for index in 0..4 {
                let source = 0x10_0000_0000 + now as u64 * 4 + index;
                let forged = packet::new_packet(a.address, Address::new(source), verb::FRAME, &[]);
                a.on_datagram(now, endpoint(9), &forged);
            }
            if now % 250 == 0 {
                a.tick(now);
            }
            drain(&mut a);
            assert!(a.unknown_sources.len() <= MAX_UNKNOWN_SOURCES);
            assert!(a.pending.len() <= 1, "only the controller is wanted");
        }
        assert!(a.expected.answer(77, root.address(), verb::ECHO));
    }

    #[test]
    fn whois_answer_for_a_wanted_peer_is_checked_then_flushes_its_queue() {
        let root = Identity::parse(BOB).unwrap();
        let wanted = Identity::parse(CONTROLLER).unwrap();
        let mut a = Node::new(NodeOptions {
            identity: Identity::parse(ALICE).unwrap(),
            network_id: NETWORK,
            roots: vec![Seed {
                identity: public(&root),
                endpoints: vec![endpoint(2)],
            }],
            peers: Vec::new(),
        })
        .unwrap();
        let key = root.agree(&public(&a.identity)).unwrap();
        a.tick(1000);
        let mut request = sent_to(&mut a, endpoint(2))
            .into_iter()
            .find(|data| {
                let mut plain = data.clone();
                packet::dearmor(&mut plain, &key) && packet::verb_of(&plain) == verb::WHOIS
            })
            .expect("the controller is looked up");
        assert!(packet::dearmor(&mut request, &key));

        let mut answer = vec![verb::WHOIS];
        answer.extend_from_slice(&request[..8]);
        public(&wanted).serialize(&mut answer);
        let wire = packet::new_packet(a.address, root.address(), verb::OK, &answer);
        a.on_datagram(
            1000,
            endpoint(2),
            &packet::seal(wire, &key, true).unwrap()[0],
        );
        assert!(
            !a.peers.contains_key(&wanted.address()),
            "not before the check"
        );

        let checks = identity_checks(&mut a);
        a.on_identity_verdict(1000, checks[0].run());
        assert!(a.peers.contains_key(&wanted.address()));
        assert!(!a.pending.contains_key(&wanted.address()));
        assert!(
            !drain(&mut a).is_empty(),
            "the queued config request goes out"
        );
    }
}
