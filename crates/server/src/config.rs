use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};

use kerlico_outbound::OutboundChoice;
use kerlico_shared::{ListenAddr, NodeTag, Settings};
use serde::Deserialize;

use crate::dns::{Strategy, Upstream};
use crate::route::Rule;
use crate::Server;

#[derive(Deserialize)]
struct File {
    inbounds: Vec<InboundFile>,
    #[serde(default)]
    dns: Option<DnsFile>,
    #[serde(default)]
    fakedns: Option<ToggleFile>,
    #[serde(default)]
    warp: Option<serde_json::Value>,
    #[serde(default)]
    landing: Option<LandingFile>,
    #[serde(default)]
    bridges: Vec<BridgeFile>,
    #[serde(default)]
    api: Option<ApiFile>,
}

#[derive(Deserialize)]
struct InboundFile {
    tag: String,
    protocol: String,
    listen: String,
    port: u16,
    #[serde(default = "default_outbound")]
    outbound: String,
    #[serde(default)]
    rules: Vec<RuleFile>,
    #[serde(default)]
    sniffing: Option<SniffFile>,
    #[serde(default)]
    settings: SettingsFile,
}

#[derive(Deserialize)]
struct BridgeFile {
    tag: String,
    address: String,
    port: u16,
    #[serde(default = "default_outbound")]
    outbound: String,
    #[serde(default)]
    rules: Vec<RuleFile>,
    #[serde(default)]
    sniffing: Option<SniffFile>,
    #[serde(default)]
    settings: serde_json::Map<String, serde_json::Value>,
}

#[derive(Deserialize)]
struct SniffFile {
    #[serde(default)]
    enabled: bool,
    #[serde(default, rename = "destOverride")]
    dest_override: Vec<String>,
}

#[derive(Deserialize)]
struct ToggleFile {
    #[serde(default)]
    enabled: bool,
}

#[derive(Deserialize, Default)]
struct SettingsFile {
    #[serde(default)]
    users: Vec<UserFile>,
    #[serde(flatten)]
    fields: BTreeMap<String, serde_json::Value>,
}

#[derive(Deserialize)]
struct UserFile {
    email: String,
    #[serde(flatten)]
    fields: BTreeMap<String, serde_json::Value>,
}

#[derive(Deserialize)]
struct RuleFile {
    #[serde(default)]
    domain: Vec<String>,
    #[serde(default)]
    geosite: Vec<String>,
    #[serde(default)]
    geoip: Vec<String>,
    outbound: String,
}

#[derive(Deserialize)]
struct ApiFile {
    listen: String,
    port: u16,
}

#[derive(Deserialize)]
struct LandingFile {
    #[serde(default)]
    protocol: String,
    #[serde(default)]
    address: String,
    #[serde(default)]
    port: u16,
    #[serde(default)]
    settings: serde_json::Map<String, serde_json::Value>,
    #[serde(default)]
    node: Option<String>,
    #[serde(default)]
    reverse: Option<String>,
}

#[derive(Deserialize)]
struct DnsFile {
    #[serde(default)]
    listen: Option<String>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default = "default_strategy")]
    #[serde(rename = "queryStrategy")]
    query_strategy: String,
    #[serde(default)]
    hosts: BTreeMap<String, HostList>,
    #[serde(default)]
    servers: Vec<DnsServerFile>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum HostList {
    One(String),
    Many(Vec<String>),
}

#[derive(Deserialize)]
struct DnsServerFile {
    address: String,
    #[serde(default = "default_dns_port")]
    port: u16,
    #[serde(default = "default_network")]
    network: String,
    #[serde(default = "default_outbound")]
    outbound: String,
}

fn default_outbound() -> String {
    "default".to_string()
}

fn default_strategy() -> String {
    "UseIP".to_string()
}

fn default_dns_port() -> u16 {
    53
}

fn default_network() -> String {
    "udp".to_string()
}

pub struct Loaded {
    pub server: Server,
    pub dns: crate::dns::Config,
    pub warp: Option<String>,
}

pub fn load(text: &str) -> Result<Loaded, String> { load_prepared(text, None) }

pub fn load_in(text: &str, dir: &std::path::Path) -> Result<Loaded, String> { load_prepared(text, Some(dir)) }

fn load_prepared(text: &str, dir: Option<&std::path::Path>) -> Result<Loaded, String> {
    let file: File = serde_json::from_str(text).map_err(|error| error.to_string())?;
    let mut server = Server::new();
    let dns = parse_dns(file.dns.as_ref())?;
    server.set_dns(dns.clone());
    if let Some(dir) = dir {
        server.load_geodata(dir);
        crate::attach_warp(&server, file.warp.as_ref().map(serde_json::Value::to_string).as_deref(), dir);
    }
    if let Some(landing) = file.landing.as_ref().filter(|landing| landing.node.is_none() && landing.reverse.is_none()) {
        if landing.port == 0 || landing.address.is_empty() { return Err("bad landing".into()); }
        server.install_landing(&landing.protocol, landing.address.clone(), landing.port, landing_settings(&landing.settings)?)
            .map_err(|_| format!("bad landing {}", landing.protocol))?;
    }
    for inbound in file.inbounds {
        let tag = NodeTag::parse(&inbound.tag).map_err(|_| format!("bad tag {}", inbound.tag))?;
        let protocol = Server::compiled()
            .iter()
            .copied()
            .find(|id| id.as_str() == inbound.protocol)
            .ok_or_else(|| format!("bad protocol {}", inbound.protocol))?;
        let listen = parse_listen(&inbound.listen, inbound.port)?;
        let choice = parse_choice(&inbound.outbound)?;
        let rules = parse_rules(inbound.rules)?;
        let mut node_settings = Settings::default();
        for (key, value) in &inbound.settings.fields {
            node_settings.insert_json(key, value).map_err(|_| format!("bad settings {key}"))?;
        }
        server
            .listen_node(tag.clone(), protocol, listen, choice, &node_settings)
            .map_err(|_| format!("listen {}", inbound.tag))?;
        server.set_rules(&tag, rules);
        if let Some(kinds) = sniff_kinds(inbound.sniffing) {
            server.set_sniff(&tag, kinds);
        }
        for user in inbound.settings.users {
            let email = kerlico_shared::UserEmail::parse(&user.email)
                .map_err(|_| format!("bad email {}", user.email))?;
            let mut account = Settings::default();
            for (key, value) in &user.fields {
                account.insert_json(key, value).map_err(|_| format!("bad user field {key}"))?;
            }
            server
                .add_user(&tag, email, &account)
                .map_err(|_| format!("user {}", inbound.tag))?;
        }
    }
    for bridge in file.bridges {
        let tag = NodeTag::parse(&bridge.tag).map_err(|_| format!("bad tag {}", bridge.tag))?;
        if bridge.port == 0 || bridge.address.is_empty() {
            return Err(format!("bad bridge {}", bridge.tag));
        }
        let choice = parse_choice(&bridge.outbound)?;
        let rules = parse_rules(bridge.rules)?;
        server
            .bridge_node(tag.clone(), bridge.address, bridge.port, choice, &landing_settings(&bridge.settings)?)
            .map_err(|_| format!("bridge {}", bridge.tag))?;
        server.set_rules(&tag, rules);
        if let Some(kinds) = sniff_kinds(bridge.sniffing) {
            server.set_sniff(&tag, kinds);
        }
    }
    if file.fakedns.as_ref().is_some_and(|item| item.enabled) {
        server.enable_fakedns();
    }
    if let Some(api) = file.api.as_ref() {
        if api.port == 0 {
            return Err("bad api port".to_string());
        }
        let ip: IpAddr = api.listen.parse().map_err(|_| format!("bad api listen {}", api.listen))?;
        server.set_api(SocketAddr::new(ip, api.port));
    }
    if let Some(landing) = file.landing.as_ref() {
        if let (Some(node), Some(reverse)) = (&landing.node, &landing.reverse) {
            if !landing.protocol.is_empty() || !landing.address.is_empty() || landing.port != 0 || !landing.settings.is_empty() { return Err("reverse landing cannot also configure a remote peer".into()); }
            server.install_reverse_landing(&NodeTag::parse(node).map_err(|_| "bad reverse landing node")?, reverse).map_err(|_| "bad reverse landing")?;
        } else {
        if landing.node.is_some() || landing.reverse.is_some() { return Err("reverse landing requires node and reverse".into()); }
        }
    }
    Ok(Loaded {
        server,
        dns,
        warp: file.warp.map(|value| value.to_string()),
    })
}

fn parse_dns(file: Option<&DnsFile>) -> Result<crate::dns::Config, String> {
    let strategy = match file.map(|dns| dns.query_strategy.as_str()).unwrap_or("UseIP") {
        "UseIPv4" => Strategy::UseV4,
        "UseIPv6" => Strategy::UseV6,
        _ => Strategy::UseIp,
    };
    let mut hosts = BTreeMap::new();
    let mut upstreams = Vec::new();
    if let Some(file) = file {
        for (name, value) in &file.hosts {
            let texts = match value {
                HostList::One(text) => vec![text.clone()],
                HostList::Many(texts) => texts.clone(),
            };
            let mut ips = Vec::new();
            for text in texts {
                ips.push(text.parse::<IpAddr>().map_err(|_| format!("bad host {name}"))?);
            }
            hosts.insert(name.trim_end_matches('.').to_ascii_lowercase(), ips);
        }
        for server in &file.servers {
            if server.port == 0 {
                return Err("bad dns port".to_string());
            }
            let tcp = match server.network.as_str() {
                "udp" => false,
                "tcp" => true,
                _ => return Err(format!("bad dns network {}", server.network)),
            };
            let choice = OutboundChoice::parse(&server.outbound)
                .ok_or_else(|| format!("bad outbound {}", server.outbound))?;
            upstreams.push(Upstream {
                address: server.address.parse().map_err(|_| format!("bad dns {}", server.address))?,
                port: server.port,
                tcp,
                choice,
            });
        }
    }
    let listen = match file.and_then(|item| item.listen.clone()) {
        Some(host) => {
            let port = file.and_then(|item| item.port).unwrap_or(53);
            if port == 0 {
                return Err("bad dns port".to_string());
            }
            let ip: IpAddr = host.parse().map_err(|_| format!("bad dns listen {host}"))?;
            Some(SocketAddr::new(ip, port))
        }
        None => None,
    };
    Ok(crate::dns::Config {
        hosts,
        upstreams,
        strategy,
        listen,
    })
}

fn parse_choice(text: &str) -> Result<OutboundChoice, String> {
    OutboundChoice::parse(text).ok_or_else(|| format!("bad outbound {text}"))
}

fn parse_rules(rules: Vec<RuleFile>) -> Result<Vec<Rule>, String> {
    rules
        .into_iter()
        .map(|rule| -> Result<Rule, String> {
            let mut lines = rule.domain;
            lines.extend(rule.geosite.into_iter().map(|item| format!("geosite:{item}")));
            lines.extend(rule.geoip.into_iter().map(|item| format!("geoip:{item}")));
            Ok(Rule { lines, choice: parse_choice(&rule.outbound)? })
        })
        .collect()
}

fn sniff_kinds(sniff: Option<SniffFile>) -> Option<Vec<String>> {
    let sniff = sniff.filter(|sniff| sniff.enabled)?;
    Some(if sniff.dest_override.is_empty() {
        vec!["http".to_string(), "tls".to_string(), "quic".to_string()]
    } else {
        sniff.dest_override
    })
}

fn landing_settings(settings: &serde_json::Map<String, serde_json::Value>) -> Result<Settings, String> {
    let mut out = Settings::default();
    for (key, value) in settings {
        out.insert_json(key, value).map_err(|_| format!("bad landing settings {key}"))?;
    }
    Ok(out)
}

fn parse_listen(host: &str, port: u16) -> Result<ListenAddr, String> {
    let ip: IpAddr = host.parse().map_err(|_| format!("bad listen {host}"))?;
    match ip {
        IpAddr::V4(addr) => ListenAddr::v4(addr, port).map_err(|_| "bad port".to_string()),
        IpAddr::V6(addr) => ListenAddr::v6(addr, port).map_err(|_| "bad port".to_string()),
    }
}
