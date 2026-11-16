use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use kerlico_shared::runtime::PacketIo;
use rand_core::{OsRng, RngCore};

pub type Dial = Arc<dyn Fn(SocketAddr) -> io::Result<Arc<dyn PacketIo>> + Send + Sync>;

#[derive(Clone)]
pub struct Hops {
    local: bool,
    remote: bool,
    interval: Arc<dyn Fn() -> Duration + Send + Sync>,
    select: Arc<dyn Fn(SocketAddr) -> SocketAddr + Send + Sync>,
}

impl Hops {
    pub fn new(
        local: bool,
        remote: bool,
        interval: impl Fn() -> Duration + Send + Sync + 'static,
        select: impl Fn(SocketAddr) -> SocketAddr + Send + Sync + 'static,
    ) -> Self {
        Self {
            local,
            remote,
            interval: Arc::new(interval),
            select: Arc::new(select),
        }
    }

    pub fn parse(ports: &str, seconds: Option<&str>) -> io::Result<Self> {
        let ports = parse_ports(ports)?;
        let (min, max) = pair(seconds.unwrap_or("30"), 5, 86_400)?;
        Ok(Self::new(
            true,
            true,
            move || Duration::from_secs(u64::from(min + OsRng.next_u32() % (max - min + 1))),
            move |mut peer| {
                if ports.len() > 1 {
                    let index = OsRng.next_u32() as usize % ports.len();
                    let port = if ports[index] == peer.port() {
                        ports[(index + 1) % ports.len()]
                    } else {
                        ports[index]
                    };
                    peer.set_port(port);
                } else {
                    peer.set_port(ports[0]);
                }
                peer
            },
        ))
    }

    pub fn open(
        self,
        peer: SocketAddr,
        select_initial: bool,
        dial: Dial,
    ) -> io::Result<Arc<dyn PacketIo>> {
        let remote = if select_initial {
            (self.select)(peer)
        } else {
            peer
        };
        let current = Socket {
            io: dial(remote)?,
            remote,
        };
        let next_hop = Instant::now() + (self.interval)();
        Ok(Arc::new(Hopping {
            config: self,
            dial,
            peer,
            state: Mutex::new(State {
                current,
                previous: None,
                next_hop,
            }),
        }))
    }
}

pub fn parse_ports(text: &str) -> io::Result<Vec<u16>> {
    let mut present = [false; 65_536];
    for segment in text.split(',') {
        let (min, max) = pair(segment.trim(), 1, 65_535)?;
        present[min as usize..=max as usize].fill(true);
    }
    Ok(present
        .iter()
        .enumerate()
        .filter(|(_, enabled)| **enabled)
        .map(|(port, _)| port as u16)
        .collect())
}

fn pair(text: &str, min: u32, max: u32) -> io::Result<(u32, u32)> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidInput, "invalid UDP hopping range");
    let (start, end) = text.split_once('-').unwrap_or((text, text));
    let start = if start.is_empty() {
        min
    } else {
        start.parse().map_err(|_| invalid())?
    };
    let end = if end.is_empty() {
        max
    } else {
        end.parse().map_err(|_| invalid())?
    };
    if text.is_empty() || start < min || end > max || start > end {
        return Err(invalid());
    }
    Ok((start, end))
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

struct Hopping {
    config: Hops,
    dial: Dial,
    peer: SocketAddr,
    state: Mutex<State>,
}

impl Hopping {
    fn sockets(&self) -> (Socket, Option<Socket>) {
        let mut state = self.state.lock().expect("UDP hop");
        let now = Instant::now();
        if now >= state.next_hop {
            state.next_hop = now + (self.config.interval)();
            if self.config.local || self.config.remote {
                let current = &state.current;
                let remote = if self.config.remote {
                    (self.config.select)(current.remote)
                } else {
                    current.remote
                };
                let io = if self.config.local || remote.is_ipv6() != current.remote.is_ipv6() {
                    (self.dial)(remote).ok()
                } else {
                    Some(current.io.clone())
                };
                if let Some(io) = io {
                    state.previous =
                        Some(std::mem::replace(&mut state.current, Socket { io, remote }));
                }
            }
        }
        (state.current.clone(), state.previous.clone())
    }
}

impl PacketIo for Hopping {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.state.lock().expect("UDP hop").current.io.local_addr()
    }

    fn recv_from(&self, out: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let (current, previous) = self.sockets();
        let accepts = |source| {
            source == current.remote || previous.as_ref().is_some_and(|peer| source == peer.remote)
        };
        match current.io.recv_from(out) {
            Ok((len, source)) if accepts(source) => return Ok((len, self.peer)),
            Err(error)
                if !matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                return Err(error)
            }
            _ => (),
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
    fn local_hop_preserves_the_logical_peer_and_accepts_old_replies() {
        let remote = UdpSocket::bind("127.0.0.1:0").unwrap();
        remote
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let selected = remote.local_addr().unwrap();
        let logical: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let config = Hops::new(true, false, || Duration::from_secs(5), move |_| selected);
        let dial: Dial = Arc::new(move |peer| {
            assert_eq!(peer, selected);
            let socket = UdpSocket::bind("127.0.0.1:0")?;
            socket.set_read_timeout(Some(Duration::from_millis(20)))?;
            Ok(Arc::new(socket))
        });
        let current = Socket {
            io: dial(selected).unwrap(),
            remote: selected,
        };
        let hop = Hopping {
            config,
            dial,
            peer: logical,
            state: Mutex::new(State {
                current,
                previous: None,
                next_hop: Instant::now() + Duration::from_secs(5),
            }),
        };
        let mut out = [0; 20];
        hop.send_to(b"first", logical).unwrap();
        let (_, first) = remote.recv_from(&mut out).unwrap();
        hop.state.lock().unwrap().next_hop = Instant::now();
        hop.send_to(b"second", logical).unwrap();
        let (_, second) = remote.recv_from(&mut out).unwrap();
        assert_ne!(first, second);
        for (origin, payload) in [(first, b"old reply"), (second, b"new reply")] {
            remote.send_to(payload, origin).unwrap();
            let (n, source) = hop.recv_from(&mut out).unwrap();
            assert_eq!((&out[..n], source), (&payload[..], logical));
        }
    }
}
