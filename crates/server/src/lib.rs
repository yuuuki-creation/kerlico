//! Server leaf. Many inbound nodes, one outbound module.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use kerlico_outbound::{DialTarget, Exit, Native, Outbound, OutboundChoice};
use kerlico_shared::{
    Accept, AddrError, DocError, Handoff, IdError, ListenAddr, NodeTag, OpenError, PacketError,
    PlaneFault, ProtocolId, Settings, Traffic, UserEmail,
};

mod api;
mod config;
mod dns;
mod fakedns;
mod geodata;
mod udp;
mod gen {
    include!(concat!(env!("OUT_DIR"), "/registry.rs"));
}
mod route;
mod sniff;
mod warp;

pub use warp::attach as attach_warp;

/// Server leaf failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    Config,
    Connect,
    Packet,
    Plane,
    DuplicateNode,
    UnknownNode,
    UnknownUser,
}

impl From<DocError> for Error {
    fn from(_: DocError) -> Self {
        Self::Config
    }
}

impl From<IdError> for Error {
    fn from(_: IdError) -> Self {
        Self::Config
    }
}

impl From<AddrError> for Error {
    fn from(_: AddrError) -> Self {
        Self::Config
    }
}

impl From<PacketError> for Error {
    fn from(_: PacketError) -> Self {
        Self::Packet
    }
}

impl From<OpenError> for Error {
    fn from(_: OpenError) -> Self {
        Self::Connect
    }
}

impl From<PlaneFault> for Error {
    fn from(_: PlaneFault) -> Self {
        Self::Plane
    }
}

/// Process-wide counters. Names follow the Xray `>>>` pattern.
#[derive(Debug)]
#[derive(Clone)]
pub struct Stats {
    counts: Arc<Mutex<BTreeMap<String, u64>>>,
}

impl Stats {
    pub fn new() -> Self {
        Self {
            counts: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    pub fn user_uplink_name(email: &UserEmail) -> String {
        format!("user>>>{}>>>traffic>>>uplink", email.as_str())
    }

    pub fn user_downlink_name(email: &UserEmail) -> String {
        format!("user>>>{}>>>traffic>>>downlink", email.as_str())
    }

    pub fn inbound_uplink_name(node: &NodeTag) -> String {
        format!("inbound>>>{}>>>traffic>>>uplink", node.as_str())
    }

    pub fn inbound_downlink_name(node: &NodeTag) -> String {
        format!("inbound>>>{}>>>traffic>>>downlink", node.as_str())
    }

    pub fn get(&self, name: &str) -> u64 {
        self.counts.lock().expect("stats").get(name).copied().unwrap_or(0)
    }

    fn add(&self, name: String, bytes: u64) {
        let mut counts = self.counts.lock().expect("stats");
        *counts.entry(name).or_insert(0) += bytes;
    }
}

impl Default for Stats {
    fn default() -> Self {
        Self::new()
    }
}

impl Traffic for Stats {
    fn add_uplink(&self, user: &UserEmail, node: &NodeTag, bytes: u64) {
        self.add(Self::user_uplink_name(user), bytes);
        self.add(Self::inbound_uplink_name(node), bytes);
    }

    fn add_downlink(&self, user: &UserEmail, node: &NodeTag, bytes: u64) {
        self.add(Self::user_downlink_name(user), bytes);
        self.add(Self::inbound_downlink_name(node), bytes);
    }

    fn add_exit_uplink(&self, exit: &str, bytes: u64) {
        self.add(format!("outbound>>>{exit}>>>traffic>>>uplink"), bytes);
    }

    fn add_exit_downlink(&self, exit: &str, bytes: u64) {
        self.add(format!("outbound>>>{exit}>>>traffic>>>downlink"), bytes);
    }
}

struct Node {
    tag: NodeTag,
    protocol: ProtocolId,
    listen: ListenAddr,
    outbound: OutboundChoice,
    inbound: Box<dyn Accept>,
    users: BTreeSet<UserEmail>,
    rules: Vec<route::Rule>,
    sniff: Vec<String>,
}

/// One process. Every node hands flows to the same `Outbound`.
pub struct Server {
    nodes: Vec<Node>,
    outbound: Outbound,
    stats: Stats,
    fakedns: fakedns::Pool,
    fake_on: bool,
    geodata: geodata::Catalog,
    udp: udp::Table,
    api: Option<std::net::SocketAddr>,
    api_tx: mpsc::Sender<api::Cmd>,
    api_rx: mpsc::Receiver<api::Cmd>,
}

impl Server {
    pub fn new() -> Self {
        let (api_tx, api_rx) = mpsc::channel();
        Self {
            nodes: Vec::new(),
            outbound: Outbound::new(),
            stats: Stats::new(),
            fakedns: fakedns::Pool::new(),
            fake_on: false,
            geodata: geodata::Catalog::empty(),
            udp: udp::Table::new(),
            api: None,
            api_tx,
            api_rx,
        }
    }

    pub fn set_api(&mut self, addr: std::net::SocketAddr) {
        self.api = Some(addr);
    }

    pub fn load_geodata(&mut self, dir: &std::path::Path) {
        self.geodata = geodata::Catalog::load(dir);
    }

    pub fn enable_fakedns(&mut self) {
        self.fake_on = true;
    }

    pub fn set_sniff(&mut self, tag: &NodeTag, kinds: Vec<String>) {
        if let Some(node) = self.nodes.iter_mut().find(|node| &node.tag == tag) {
            node.sniff = kinds;
        }
    }

    /// Enabled protocol ids for this server build.
    pub fn compiled() -> &'static [ProtocolId] {
        gen::COMPILED
    }

    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    pub fn node(&self, tag: &NodeTag) -> Option<(ProtocolId, ListenAddr, OutboundChoice)> {
        self.nodes.iter().find(|node| &node.tag == tag).map(|node| {
            (node.protocol, node.listen, node.outbound)
        })
    }

    /// Opens one inbound from the compiled registry and keeps it on this server.
    /// `listen` is v4 or v6. `outbound` is a fixed exit, or `Default` when the field was left empty.
    pub fn listen_node(
        &mut self,
        tag: NodeTag,
        protocol: ProtocolId,
        listen: ListenAddr,
        outbound: OutboundChoice,
        settings: &Settings,
    ) -> Result<(), Error> {
        if self.nodes.iter().any(|node| node.tag == tag) {
            return Err(Error::DuplicateNode);
        }
        let open = gen::REGISTRY
            .iter()
            .find(|row| row.id == protocol)
            .map(|row| row.listen)
            .ok_or(Error::Config)?;
        let inbound = open(&tag, &listen, settings)?;
        self.nodes.push(Node {
            tag,
            protocol,
            listen,
            outbound,
            inbound,
            users: BTreeSet::new(),
            rules: Vec::new(),
            sniff: Vec::new(),
        });
        Ok(())
    }

    pub fn add_user(
        &mut self,
        tag: &NodeTag,
        email: UserEmail,
        account: &Settings,
    ) -> Result<(), Error> {
        let node = self.nodes.iter_mut().find(|node| &node.tag == tag).ok_or(Error::UnknownNode)?;
        node.inbound.add_user(&email, account)?;
        node.users.insert(email);
        Ok(())
    }

    pub fn remove_user(&mut self, tag: &NodeTag, email: &UserEmail) -> Result<(), Error> {
        let node = self.nodes.iter_mut().find(|node| &node.tag == tag).ok_or(Error::UnknownNode)?;
        if !node.users.contains(email) {
            return Err(Error::UnknownUser);
        }
        node.inbound.remove_user(email)?;
        node.users.remove(email);
        Ok(())
    }

    pub fn set_rules(&mut self, tag: &NodeTag, rules: Vec<route::Rule>) {
        if let Some(node) = self.nodes.iter_mut().find(|node| &node.tag == tag) {
            node.rules = rules;
        }
    }

    pub fn from_config(text: &str) -> Result<config::Loaded, Error> {
        config::load(text).map_err(|_| Error::Config)
    }

    pub fn install_warp_device(&self, device: std::sync::Arc<dyn kerlico_outbound::PacketDevice>) {
        self.outbound.install_warp(device);
    }

    pub fn install_landing(
        &self,
        protocol: &str,
        host: String,
        port: u16,
        settings: Settings,
    ) -> Result<(), Error> {
        let land = gen::LANDINGS
            .iter()
            .find(|row| row.id.as_str() == protocol)
            .map(|row| row.land)
            .ok_or(Error::Config)?;
        self.outbound.install_landing(land, host, port, settings);
        Ok(())
    }

    /// Accepts flows and dials the chosen exit. This call does not return.
    pub fn run(&mut self, dns: dns::Config) -> Result<(), Error> {
        let native = Native::detect();
        let local = route::remember_locals();
        if let Some(addr) = dns.listen {
            dns::serve(
                addr,
                dns.clone(),
                self.fakedns.clone(),
                self.fake_on,
                native,
                self.outbound.clone(),
            );
        }
        if let Some(addr) = self.api {
            let tx = self.api_tx.clone();
            let stats = self.stats.clone();
            thread::spawn(move || {
                if api::serve(addr, tx, stats).is_none() {
                    eprintln!("api");
                }
            });
        }
        loop {
            self.drain_api();
            self.dispatch_next_with(native, &local, &dns);
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn drain_api(&mut self) {
        while let Ok(cmd) = self.api_rx.try_recv() {
            self.apply_api(cmd);
        }
    }

    fn apply_api(&mut self, cmd: api::Cmd) {
        match cmd {
            api::Cmd::Add(tag, email, settings, reply) => {
                let ok = (|| {
                    let tag = NodeTag::parse(&tag).map_err(|_| Error::Config)?;
                    let email = UserEmail::parse(&email).map_err(|_| Error::Config)?;
                    self.add_user(&tag, email, &settings)
                })();
                let _ = reply.send(ok.is_ok());
            }
            api::Cmd::Remove(tag, email, reply) => {
                let ok = (|| {
                    let tag = NodeTag::parse(&tag).map_err(|_| Error::Config)?;
                    let email = UserEmail::parse(&email).map_err(|_| Error::Config)?;
                    self.remove_user(&tag, &email)
                })();
                let _ = reply.send(ok.is_ok());
            }
        }
    }

    /// Accepts one ready flow and dials it. No ready flow leaves the process idle.
    pub fn dispatch_next(&mut self) -> Result<(), Error> {
        let native = Native::detect();
        let local = route::remember_locals();
        let dns = dns::Config {
            hosts: BTreeMap::new(),
            upstreams: Vec::new(),
            strategy: dns::Strategy::UseIp,
            listen: None,
        };
        self.dispatch_next_with(native, &local, &dns);
        Ok(())
    }

    fn dispatch_next_with(&mut self, native: Native, local: &[IpAddr], dns: &dns::Config) {
        for index in 0..self.nodes.len() {
            let accepted = self.nodes[index].inbound.accept();
            let rules = self.nodes[index].rules.clone();
            let choice = self.nodes[index].outbound;
            let sniff = self.nodes[index].sniff.clone();
            match accepted {
                Ok(handoff) => {
                    let outbound = self.outbound.clone();
                    let stats = self.stats.clone();
                    let local = local.to_vec();
                    let dns = dns.clone();
                    let fakes = self.fakedns.clone();
                    let fake_on = self.fake_on;
                    let geodata = self.geodata.clone();
                    let udp = self.udp.clone();
                    thread::spawn(move || {
                        if let Err(error) = Self::drive(
                            handoff, &rules, choice, native, &local, &dns, &sniff, &fakes,
                            fake_on, &geodata, &udp, &outbound, &stats,
                        ) {
                            eprintln!("flow {error:?}");
                        }
                    });
                    return;
                }
                Err(OpenError::Again) => {}
                Err(_) => {}
            }
        }
    }

    fn drive(
        mut handoff: Handoff,
        rules: &[route::Rule],
        choice: OutboundChoice,
        native: Native,
        local: &[IpAddr],
        dns: &dns::Config,
        sniff: &[String],
        fakes: &fakedns::Pool,
        fake_on: bool,
        geodata: &geodata::Catalog,
        sessions: &udp::Table,
        outbound: &Outbound,
        traffic: &Stats,
    ) -> Result<(), Error> {
        if fake_on {
            if let Some(ip) = route::literal(handoff.destination()) {
                if let Some(name) = fakes.rewrite(ip) {
                    handoff.retarget(name);
                }
            }
        }
        let sniffed = sniff_name(&mut handoff, sniff);
        let destination = handoff.destination().clone();
        let mut resolved = if let Some(ip) = route::literal(&destination) {
            route::resolved_from(destination.host(), destination.port(), &[ip])
        } else {
            route::resolved_from(destination.host(), destination.port(), &[])
        };
        let rule_host = sniffed.or_else(|| {
            if route::literal(&destination).is_none() {
                Some(destination.host().to_string())
            } else {
                None
            }
        });
        let session = udp::key_from(handoff.peer(), &destination);
        let fail = |key: Option<&udp::Key>| {
            if let Some(key) = key {
                sessions.end(key);
            }
            Error::Connect
        };
        let exit = udp::adopt(sessions, session.as_ref(), std::time::Instant::now(), || {
            route::choose(
                rule_host.as_deref(),
                rules,
                choice,
                native,
                &mut resolved,
                local,
                &mut |host| dns.lookup(host, native, outbound),
                geodata,
            )
        })
        .map_err(|_| fail(session.as_ref()))?;
        let mut addresses = family_addresses(&resolved.addresses, exit);
        if addresses.is_empty() && !matches!(exit, Exit::Landing) {
            if route::literal(&destination).is_some() {
                return Err(fail(session.as_ref()));
            }
            let looked = dns.lookup(destination.host(), native, outbound);
            addresses = family_addresses(
                &route::sockets(&looked, destination.port(), destination.transport()),
                exit,
            );
            if addresses.is_empty() {
                return Err(fail(session.as_ref()));
            }
        }
        let target = DialTarget {
            host: destination.host().to_string(),
            port: destination.port(),
            transport: destination.transport(),
            addresses,
        };
        outbound
            .dispatch(handoff, exit, target, traffic)
            .map_err(|_| fail(session.as_ref()))
    }
}

fn sniff_name(handoff: &mut Handoff, kinds: &[String]) -> Option<String> {
    if kinds.is_empty() || route::literal(handoff.destination()).is_none() {
        return None;
    }
    let mut buf = [0u8; 2048];
    let n = match handoff.read_into_prefix(&mut buf) {
        Ok(n) if n > 0 => n,
        _ => return None,
    };
    sniff::host_from(&buf[..n], kinds)
}

fn family_addresses(addresses: &[std::net::SocketAddr], exit: Exit) -> Vec<std::net::SocketAddr> {
    match exit {
        Exit::NativeV4 | Exit::WarpV4 => addresses.iter().copied().filter(|addr| addr.is_ipv4()).collect(),
        Exit::NativeV6 | Exit::WarpV6 => addresses.iter().copied().filter(|addr| addr.is_ipv6()).collect(),
        Exit::Landing => Vec::new(),
    }
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kerlico_shared::ProtocolId;

    struct MemoryInbound {
        users: BTreeSet<UserEmail>,
    }

    impl Accept for MemoryInbound {
        fn add_user(&mut self, email: &UserEmail, _account: &Settings) -> Result<(), OpenError> {
            self.users.insert(email.clone());
            Ok(())
        }

        fn remove_user(&mut self, email: &UserEmail) -> Result<(), OpenError> {
            self.users.remove(email);
            Ok(())
        }

        fn accept(&mut self) -> Result<Handoff, OpenError> {
            unimplemented!("test inbound")
        }
    }

    #[test]
    fn user_bytes_use_the_xray_counter_name() {
        let stats = Stats::new();
        let email = UserEmail::parse("alice@example").unwrap();
        let node = NodeTag::parse("node-a").unwrap();
        stats.add_uplink(&email, &node, 12);
        stats.add_downlink(&email, &node, 7);
        assert_eq!(stats.get("user>>>alice@example>>>traffic>>>uplink"), 12);
        assert_eq!(stats.get("user>>>alice@example>>>traffic>>>downlink"), 7);
        assert_eq!(stats.get("inbound>>>node-a>>>traffic>>>uplink"), 12);
        assert_eq!(stats.get(&Stats::user_uplink_name(&email)), 12);
    }

    #[cfg(not(feature = "landing-mieru"))]
    #[test]
    fn landing_without_the_compiled_client_is_rejected() {
        let text = r#"{"inbounds":[],"landing":{"protocol":"mieru","address":"127.0.0.1","port":1,"settings":{"username":"a","password":"b"}}}"#;
        assert!(Server::from_config(text).is_err());
    }

    #[test]
    fn add_user_reaches_only_the_named_node() {
        let mut server = Server::new();
        let tag = NodeTag::parse("node-a").unwrap();
        server.nodes.push(Node {
            tag: tag.clone(),
            protocol: ProtocolId::must("wireguard"),
            listen: ListenAddr::v4(std::net::Ipv4Addr::LOCALHOST, 443).unwrap(),
            outbound: OutboundChoice::Default,
            inbound: Box::new(MemoryInbound {
                users: BTreeSet::new(),
            }),
            users: BTreeSet::new(),
            rules: Vec::new(),
            sniff: Vec::new(),
        });
        let email = UserEmail::parse("alice@example").unwrap();
        server.add_user(&tag, email.clone(), &Settings::default()).unwrap();
        assert!(server.nodes[0].users.contains(&email));
        server.remove_user(&tag, &email).unwrap();
        assert!(server.nodes[0].users.is_empty());
        assert_eq!(server.remove_user(&tag, &email), Err(Error::UnknownUser));
    }
}
