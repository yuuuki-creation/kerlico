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
    #[serde(default)]
    transport: Option<String>,
    #[serde(default, rename = "portRange")]
    port_range: Option<String>,
    #[serde(default)]
    mtu: Option<u16>,
}

#[derive(Deserialize)]
struct UserFile {
    email: String,
    #[serde(default)]
    username: String,
    password: String,
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
    protocol: String,
    address: String,
    port: u16,
    #[serde(default)]
    settings: serde_json::Map<String, serde_json::Value>,
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

pub fn load(text: &str) -> Result<Loaded, String> {
    let file: File = serde_json::from_str(text).map_err(|error| error.to_string())?;
    let mut server = Server::new();
    for inbound in file.inbounds {
        let tag = NodeTag::parse(&inbound.tag).map_err(|_| format!("bad tag {}", inbound.tag))?;
        let protocol = Server::compiled()
            .iter()
            .copied()
            .find(|id| id.as_str() == inbound.protocol)
            .ok_or_else(|| format!("bad protocol {}", inbound.protocol))?;
        let listen = parse_listen(&inbound.listen, inbound.port)?;
        let choice = OutboundChoice::parse(&inbound.outbound)
            .ok_or_else(|| format!("bad outbound {}", inbound.outbound))?;
        let rules = inbound
            .rules
            .into_iter()
            .map(|rule| {
                let mut lines = rule.domain;
                lines.extend(rule.geosite.into_iter().map(|item| format!("geosite:{item}")));
                lines.extend(rule.geoip.into_iter().map(|item| format!("geoip:{item}")));
                let choice = OutboundChoice::parse(&rule.outbound)
                    .ok_or_else(|| format!("bad outbound {}", rule.outbound))?;
                Ok(Rule { lines, choice })
            })
            .collect::<Result<Vec<_>, String>>()?;
        let mut node_settings = Settings::default();
        if let Some(transport) = inbound.settings.transport.clone() {
            node_settings.insert_text("transport", transport);
        }
        if let Some(range) = inbound.settings.port_range.clone() {
            node_settings.insert_text("portRange", range);
        }
        if let Some(mtu) = inbound.settings.mtu {
            node_settings.insert_text("mtu", mtu.to_string());
        }
        server
            .listen_node(tag.clone(), protocol, listen, choice, &node_settings)
            .map_err(|_| format!("listen {}", inbound.tag))?;
        server.set_rules(&tag, rules);
        if let Some(sniff) = inbound.sniffing.filter(|sniff| sniff.enabled) {
            let kinds = if sniff.dest_override.is_empty() {
                vec!["http".to_string(), "tls".to_string(), "quic".to_string()]
            } else {
                sniff.dest_override
            };
            server.set_sniff(&tag, kinds);
        }
        for user in inbound.settings.users {
            let email = kerlico_shared::UserEmail::parse(&user.email)
                .map_err(|_| format!("bad email {}", user.email))?;
            let mut account = Settings::default();
            let username = if user.username.is_empty() { user.email.clone() } else { user.username };
            account.insert_text("username", username);
            account.insert_text("password", user.password);
            server
                .add_user(&tag, email, &account)
                .map_err(|_| format!("user {}", inbound.tag))?;
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
        if landing.port == 0 || landing.address.is_empty() {
            return Err("bad landing".to_string());
        }
        server
            .install_landing(
                &landing.protocol,
                landing.address.clone(),
                landing.port,
                landing_settings(&landing.settings)?,
            )
            .map_err(|_| format!("bad landing {}", landing.protocol))?;
    }
    let dns = parse_dns(file.dns.as_ref())?;
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

fn landing_settings(settings: &serde_json::Map<String, serde_json::Value>) -> Result<Settings, String> {
    let mut out = Settings::default();
    for (key, value) in settings {
        let text = match value {
            serde_json::Value::String(text) => text.clone(),
            serde_json::Value::Number(number) => number.to_string(),
            serde_json::Value::Bool(flag) => flag.to_string(),
            _ => return Err(format!("bad landing settings {key}")),
        };
        out.insert_text(key, text);
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
