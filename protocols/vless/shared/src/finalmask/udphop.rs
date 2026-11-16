use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use serde_json::Value;

use super::{
    filter::IpNetwork, invalid, random_below, settings, PacketIo, Range, UdpDial,
};

#[derive(Clone)]
pub(super) struct Hop {
    local: bool,
    remote: bool,
    remote_once: bool,
    interval: Range,
    ips: Vec<IpNetwork>,
    ports: Vec<u16>,
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct Config {
    mode: String,
    interval: Range,
    #[serde(rename = "remoteIPs")]
    ips: Vec<String>,
    #[serde(rename = "remotePorts")]
    ports: Option<Ports>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Ports {
    Number(u16),
    List(String),
}

impl Hop {
    pub(super) fn parse(value: Value) -> io::Result<Self> {
        let config: Config = settings(value)?;
        let interval = if config.interval.max == 0 {
            Range::fixed(30)
        } else {
            config.interval
        };
        if interval.min < 5 {
            return Err(invalid("udphop interval must be at least five seconds"));
        }
        let mut hop = Self {
            local: false,
            remote: false,
            remote_once: false,
            interval,
            ips: config
                .ips
                .iter()
                .map(|ip| IpNetwork::parse(ip))
                .collect::<io::Result<_>>()?,
            ports: parse_ports(config.ports)?,
        };
        for mode in config.mode.to_ascii_lowercase().split(',') {
            match mode {
                "intervallocal" => hop.local = true,
                "intervalremote" => hop.remote = true,
                "perconnremote" => hop.remote_once = true,
                _ => return Err(invalid("invalid udphop mode")),
            }
        }
        Ok(hop)
    }

    fn interval(&self) -> Duration {
        Duration::from_secs(u64::from(self.interval.pick_inclusive()))
    }

    fn select(&self, peer: SocketAddr) -> SocketAddr {
        let mut selected = peer;
        if !self.ips.is_empty() {
            let ip = self.ips[random_below(self.ips.len() as u32) as usize];
            let entropy = u128::from(OsRng.next_u64()) << 64 | u128::from(OsRng.next_u64());
            selected.set_ip(ip.sample(entropy));
        }
        if !self.ports.is_empty() {
            selected.set_port(self.ports[random_below(self.ports.len() as u32) as usize]);
        }
        selected
    }

    pub(super) fn open(&self, peer: SocketAddr, dial: UdpDial) -> io::Result<Arc<dyn PacketIo>> {
        let timer = self.clone();
        let target = self.clone();
        let config = kerlico_hy2::quic::hop::Hops::new(
            self.local, self.remote, move || timer.interval(), move |peer| target.select(peer),
        );
        config.open(peer, self.remote || self.remote_once, dial)
    }
}

fn parse_ports(config: Option<Ports>) -> io::Result<Vec<u16>> {
    let mut out = Vec::new();
    match config {
        None | Some(Ports::Number(0)) => {}
        Some(Ports::Number(port)) => out.push(port),
        Some(Ports::List(list)) => {
            for value in list
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
            {
                let env;
                let value = if let Some(name) = value.strip_prefix("env:") {
                    env = std::env::var(name).map_err(invalid)?;
                    env.as_str()
                } else {
                    value
                };
                let (start, end) = value.split_once('-').unwrap_or((value, value));
                let start: u16 = start.parse().map_err(invalid)?;
                let end: u16 = end.parse().map_err(invalid)?;
                if start > end || out.len() + usize::from(end - start) + 1 > 65536 {
                    return Err(invalid("invalid udphop port range"));
                }
                out.extend(start..=end);
            }
        }
    }
    Ok(out)
}
