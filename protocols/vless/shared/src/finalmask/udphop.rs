use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use serde_json::Value;

use super::{
    filter::IpNetwork, invalid, random_below, retryable, settings, PacketIo, Range, UdpDial,
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
        let selected = if self.remote || self.remote_once {
            self.select(peer)
        } else {
            peer
        };
        let current = Socket {
            io: dial(selected)?,
            remote: selected,
        };
        Ok(Arc::new(HopPackets {
            config: self.clone(),
            dial,
            peer,
            state: Mutex::new(State {
                current,
                previous: None,
                next_hop: Instant::now() + self.interval(),
            }),
        }))
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

#[derive(Clone)]
struct Socket {
    io: Arc<dyn PacketIo>,
    remote: SocketAddr,
}

struct State {
    current: Socket,
    previous: Option<Socket>,
    next_hop: Instant,
}

struct HopPackets {
    config: Hop,
    dial: UdpDial,
    peer: SocketAddr,
    state: Mutex<State>,
}

impl HopPackets {
    fn sockets(&self) -> (Socket, Option<Socket>) {
        let mut state = self.state.lock().expect("UDP hop");
        let now = Instant::now();
        if now >= state.next_hop {
            state.next_hop = now + self.config.interval();
            if self.config.local || self.config.remote {
                let current = &state.current;
                let remote = if self.config.remote {
                    self.config.select(current.remote)
                } else {
                    current.remote
                };
                let socket = if self.config.local || remote.is_ipv6() != current.remote.is_ipv6() {
                    (self.dial)(remote).ok()
                } else {
                    Some(current.io.clone())
                };
                if let Some(io) = socket {
                    state.previous =
                        Some(std::mem::replace(&mut state.current, Socket { io, remote }));
                }
            }
        }
        (state.current.clone(), state.previous.clone())
    }
}

impl PacketIo for HopPackets {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.state.lock().expect("UDP hop").current.io.local_addr()
    }

    fn recv_from(&self, out: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (current, previous) = self.sockets();
        let accepts = |source| {
            source == current.remote || previous.as_ref().is_some_and(|prev| source == prev.remote)
        };
        match current.io.recv_from(out) {
            Ok((len, source)) if accepts(source) => return Ok((len, self.peer)),
            Err(error) if !retryable(&error) => return Err(error),
            _ => {}
        }
        if let Some(previous) = previous
            .as_ref()
            .filter(|prev| !Arc::ptr_eq(&prev.io, &current.io))
        {
            if let Ok((len, source)) = previous.io.recv_from(out) {
                if accepts(source) {
                    return Ok((len, self.peer));
                }
            }
        }
        Err(io::ErrorKind::WouldBlock.into())
    }

    fn send_to(&self, packet: &[u8], _: SocketAddr) -> io::Result<usize> {
        let (current, _) = self.sockets();
        current.io.send_to(packet, current.remote)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;

    #[test]
    fn remote_override_and_local_hop_keep_the_logical_peer() {
        let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
        let selected = remote.local_addr().unwrap();
        remote
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let logical: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let config = Hop::parse(serde_json::json!({
            "mode": "intervalLocal,perConnRemote",
            "interval": 5,
            "remotePorts": selected.port()
        }))
        .unwrap();
        let dial: UdpDial = Arc::new(move |peer| {
            assert_eq!(peer, selected);
            let socket = UdpSocket::bind("127.0.0.1:0")?;
            socket.set_read_timeout(Some(Duration::from_millis(20)))?;
            Ok(Arc::new(socket))
        });
        let first_remote = config.select(logical);
        let current = Socket {
            io: dial(first_remote).unwrap(),
            remote: first_remote,
        };
        let hop = HopPackets {
            peer: logical,
            config,
            dial,
            state: Mutex::new(State {
                current,
                previous: None,
                next_hop: Instant::now() + Duration::from_secs(5),
            }),
        };
        let mut out = [0; 20];
        hop.send_to(b"first", logical).unwrap();
        let (n, first) = remote.recv_from(&mut out).unwrap();
        assert_eq!(&out[..n], b"first");
        hop.state.lock().unwrap().next_hop = Instant::now();
        hop.send_to(b"second", logical).unwrap();
        let (n, second) = remote.recv_from(&mut out).unwrap();
        assert_eq!(&out[..n], b"second");
        assert_ne!(first, second);
        remote.send_to(b"old reply", first).unwrap();
        let (n, peer) = hop.recv_from(&mut out).unwrap();
        assert_eq!((&out[..n], peer), (&b"old reply"[..], logical));
        remote.send_to(b"new reply", second).unwrap();
        let (n, peer) = hop.recv_from(&mut out).unwrap();
        assert_eq!((&out[..n], peer), (&b"new reply"[..], logical));
    }
}
