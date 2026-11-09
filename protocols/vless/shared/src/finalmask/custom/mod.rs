mod expr;

use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rand_core::{OsRng, RngCore};
use serde::Deserialize;
use serde_json::Value;

use super::{
    check_udp_size, copy_packet, decode_bytes, invalid, malformed, retryable, send_packet, settings,
    PacketIo, Range, Side, TcpPair, UDP_POLL, UDP_SIZE,
};
use expr::{Context, Expr, RawExpr, Sizes, Vars};

const MAX_HEADER: usize = 1024 * 1024;
const STATE_TTL: Duration = Duration::from_secs(5);

#[derive(Clone)]
struct Item {
    delay: Range,
    capture: String,
    data: Data,
}

#[derive(Clone)]
enum Data {
    Bytes(Vec<u8>),
    Random { length: usize, min: u8, max: u8 },
    Var(String),
    Transform(Expr),
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
struct RawItem {
    delay: Option<Range>,
    rand: u32,
    rand_range: Option<Range>,
    capture: String,
    #[serde(rename = "type")]
    kind: String,
    reuse: String,
    transform: Option<RawExpr>,
    packet: Option<Value>,
}

impl RawItem {
    fn build(self, tcp: bool) -> io::Result<Item> {
        validate_name(&self.capture)?;
        validate_name(&self.reuse)?;
        if !tcp && self.delay.is_some() {
            return Err(invalid("UDP header-custom items do not have a delay"));
        }
        let kinds = [self.rand > 0, !self.reuse.is_empty(), self.transform.is_some(), self.packet.is_some()]
            .into_iter().filter(|kind| *kind).count();
        if kinds > 1 || (kinds == 0 && !self.capture.is_empty()) {
            return Err(invalid("header-custom item requires exactly one value"));
        }
        let range = self.rand_range.unwrap_or(Range { min: 0, max: 255 });
        if range.max > 255 {
            return Err(invalid("header-custom randRange exceeds a byte"));
        }
        let data = if self.rand != 0 {
            Data::Random { length: self.rand as usize, min: range.min as u8, max: range.max as u8 }
        } else if let Some(transform) = self.transform {
            Data::Transform(transform.build()?)
        } else if !self.reuse.is_empty() {
            Data::Var(self.reuse)
        } else {
            Data::Bytes(decode_bytes(self.packet.unwrap_or_default(), &self.kind)?)
        };
        Ok(Item { delay: self.delay.unwrap_or_default(), capture: self.capture, data })
    }
}

impl Item {
    fn measure(&self, sizes: &Sizes) -> io::Result<usize> {
        let len = match &self.data {
            Data::Bytes(bytes) => bytes.len(),
            Data::Random { length, .. } => *length,
            Data::Var(name) => *sizes.get(name).ok_or_else(|| malformed("unknown header-custom variable"))?,
            Data::Transform(expr) => expr.measure(sizes)?,
        };
        if len > MAX_HEADER {
            return Err(invalid("header-custom item exceeds one MiB"));
        }
        Ok(len)
    }

    fn bytes(&self, context: &Context) -> io::Result<Vec<u8>> {
        match &self.data {
            Data::Bytes(bytes) => Ok(bytes.clone()),
            Data::Var(name) => context.vars.get(name).cloned().ok_or_else(|| malformed("unknown header-custom variable")),
            Data::Transform(expr) => expr.bytes(context),
            Data::Random { length, min, max } => {
                let mut bytes = vec![0; *length];
                OsRng.try_fill_bytes(&mut bytes).map_err(|err| io::Error::other(err.to_string()))?;
                let span = u16::from(*max) - u16::from(*min) + 1;
                if span < 256 {
                    for byte in &mut bytes {
                        *byte = *min + (u16::from(*byte) % span) as u8;
                    }
                }
                Ok(bytes)
            }
        }
    }

    fn capture(&self, bytes: &[u8], context: &mut Context) {
        if !self.capture.is_empty() {
            context.vars.insert(self.capture.clone(), bytes.to_vec());
        }
    }
}

fn validate_name(name: &str) -> io::Result<()> {
    let mut bytes = name.bytes();
    if bytes.next().is_some_and(|byte| !byte.is_ascii_alphabetic() && byte != b'_')
        || bytes.any(|byte| !byte.is_ascii_alphanumeric() && byte != b'_')
    {
        return Err(invalid(format!("invalid header-custom variable {name:?}")));
    }
    Ok(())
}

fn measure(items: &[Item], sizes: &mut Sizes) -> io::Result<usize> {
    let mut total = 0;
    for item in items {
        let len = item.measure(sizes)?;
        if !item.capture.is_empty() {
            sizes.insert(item.capture.clone(), len);
        }
        total += len;
        if total > MAX_HEADER {
            return Err(invalid("header-custom sequence exceeds one MiB"));
        }
    }
    Ok(total)
}

fn read_items(items: &[Item], mut input: impl Read, context: &mut Context) -> io::Result<()> {
    let mut sizes = context.vars.iter().map(|(name, bytes)| (name.clone(), bytes.len())).collect();
    for item in items {
        let len = item.measure(&sizes)?;
        let mut buf = vec![0; len];
        input.read_exact(&mut buf)?;
        if !matches!(item.data, Data::Random { .. }) && item.bytes(context)? != buf {
            return Err(malformed("header-custom bytes do not match"));
        }
        item.capture(&buf, context);
        if !item.capture.is_empty() {
            sizes.insert(item.capture.clone(), len);
        }
    }
    Ok(())
}

fn write_items(items: &[Item], mut output: impl Write, context: &mut Context) -> io::Result<()> {
    let mut bytes = Vec::new();
    for item in items {
        if item.delay.max != 0 {
            output.write_all(&bytes)?;
            bytes.clear();
            std::thread::sleep(Duration::from_millis(u64::from(item.delay.pick())));
        }
        let part = item.bytes(context)?;
        if bytes.len() + part.len() > MAX_HEADER {
            return Err(invalid("header-custom sequence exceeds one MiB"));
        }
        item.capture(&part, context);
        bytes.extend(part);
    }
    output.write_all(&bytes)
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawTcp {
    clients: Vec<Vec<RawItem>>,
    servers: Vec<Vec<RawItem>>,
    errors: Vec<Vec<RawItem>>,
}

#[derive(Clone)]
pub(super) struct TcpHeader {
    clients: Arc<[Vec<Item>]>,
    servers: Arc<[Vec<Item>]>,
    errors: Arc<[Vec<Item>]>,
}

impl TcpHeader {
    pub(super) fn parse(value: Value) -> io::Result<Self> {
        let config: RawTcp = settings(value)?;
        let build = |sequences: Vec<Vec<RawItem>>| sequences.into_iter()
            .map(|items| items.into_iter().map(|item| item.build(true)).collect::<io::Result<Vec<_>>>())
            .collect::<io::Result<Arc<[_]>>>();
        let header = Self { clients: build(config.clients)?, servers: build(config.servers)?, errors: build(config.errors)? };
        let mut sizes = Sizes::new();
        for index in 0..header.clients.len().max(header.servers.len()) {
            if let Some(items) = header.clients.get(index) {
                // An error reply can use captures established earlier in the same sequence.
                measure(items, &mut sizes)?;
                if let Some(errors) = header.errors.get(index) {
                    measure(errors, &mut sizes.clone())?;
                }
            }
            if let Some(items) = header.servers.get(index) {
                measure(items, &mut sizes)?;
            }
        }
        Ok(header)
    }

    pub(super) fn exchange(&self, halves: &mut TcpPair, local: SocketAddr, peer: SocketAddr, side: Side) -> io::Result<()> {
        let mut context = Context { addrs: Some((local, peer)), vars: Vars::new() };
        let (read, write) = halves;
        for index in 0..self.clients.len().max(self.servers.len()) {
            if let Some(items) = self.clients.get(index) {
                if side == Side::Client {
                    write_items(items, &mut *write, &mut context)?;
                } else if let Err(err) = read_items(items, &mut *read, &mut context) {
                    if let Some(items) = self.errors.get(index) {
                        write_items(items, &mut *write, &mut context)?;
                    }
                    return Err(err);
                }
            }
            if let Some(items) = self.servers.get(index) {
                if side == Side::Server {
                    write_items(items, &mut *write, &mut context)?;
                } else {
                    read_items(items, &mut *read, &mut context)?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawUdp {
    mode: String,
    client: Vec<RawItem>,
    server: Vec<RawItem>,
}

#[derive(Clone)]
pub(super) struct UdpHeader {
    standalone: bool,
    client: Arc<[Item]>,
    server: Arc<[Item]>,
    client_size: usize,
    server_size: usize,
}

impl UdpHeader {
    pub(super) fn parse(value: Value) -> io::Result<Self> {
        let config: RawUdp = settings(value)?;
        let standalone = match config.mode.as_str() {
            "" | "prefix" => false,
            "standalone" => true,
            _ => return Err(invalid("invalid UDP header-custom mode")),
        };
        let build = |items: Vec<RawItem>| items.into_iter().map(|item| item.build(false)).collect::<io::Result<Arc<[_]>>>();
        let client = build(config.client)?;
        let server = build(config.server)?;
        let mut sizes = Sizes::new();
        let client_size = measure(&client, &mut sizes)?;
        let server_size = measure(&server, &mut sizes)?;
        check_udp_size(client_size)?;
        check_udp_size(server_size)?;
        Ok(Self { standalone, client, server, client_size, server_size })
    }

    pub(super) fn wrap(&self, inner: Arc<dyn PacketIo>, side: Side) -> Arc<dyn PacketIo> {
        let (incoming, outgoing, read_size, write_size) = match side {
            Side::Client => (self.server.clone(), self.client.clone(), self.server_size, self.client_size),
            Side::Server => (self.client.clone(), self.server.clone(), self.client_size, self.server_size),
        };
        Arc::new(Packets {
            inner, side, standalone: self.standalone, incoming, outgoing, read_size, write_size,
            states: Mutex::new(States::default()),
            receiver: Mutex::new(VecDeque::new()),
        })
    }
}

#[derive(Default)]
struct States {
    peers: HashMap<SocketAddr, (Instant, Vars)>,
}

impl States {
    fn vars(&self, peer: SocketAddr) -> Option<Vars> {
        self.peers.get(&peer).filter(|(expires, _)| *expires > Instant::now()).map(|(_, vars)| vars.clone())
    }

    fn remember(&mut self, peer: SocketAddr, vars: Vars) {
        if self.peers.len() >= 4096 && !self.peers.contains_key(&peer) {
            let now = Instant::now();
            self.peers.retain(|_, (expires, _)| *expires > now);
            if self.peers.len() >= 4096 {
                return;
            }
        }
        self.peers.insert(peer, (Instant::now() + STATE_TTL, vars));
    }
}

struct Packets {
    inner: Arc<dyn PacketIo>,
    side: Side,
    standalone: bool,
    incoming: Arc<[Item]>,
    outgoing: Arc<[Item]>,
    read_size: usize,
    write_size: usize,
    states: Mutex<States>,
    receiver: Mutex<VecDeque<(Vec<u8>, SocketAddr)>>,
}

impl Packets {
    fn header(&self, peer: SocketAddr, vars: Vars) -> io::Result<(Vec<u8>, Vars)> {
        let mut context = Context { vars, addrs: Some((self.inner.local_addr()?, peer)) };
        let mut wire = Vec::with_capacity(self.write_size);
        write_items(&self.outgoing, &mut wire, &mut context)?;
        if wire.len() != self.write_size {
            return Err(malformed("header-custom length changed"));
        }
        Ok((wire, context.vars))
    }

    fn match_header(&self, data: &[u8], vars: Vars) -> Option<Vars> {
        let mut context = Context { vars, addrs: None };
        let mut input = data.get(..self.read_size)?;
        read_items(&self.incoming, &mut input, &mut context).ok()?;
        input.is_empty().then_some(context.vars)
    }

    fn handshake(&self, peer: SocketAddr) -> io::Result<()> {
        let mut queue = self.receiver.lock().expect("header-custom UDP receiver");
        if self.states.lock().expect("header-custom UDP state").vars(peer).is_some() {
            return Ok(());
        }
        let (request, vars) = self.header(peer, Vars::new())?;
        send_packet(&*self.inner, request.len(), &request, peer)?;
        let deadline = Instant::now() + STATE_TTL;
        let mut buf = [0; UDP_SIZE];
        while Instant::now() < deadline {
            match self.inner.recv_from(&mut buf) {
                Ok((len, source)) => {
                    if source == peer && len == self.read_size {
                        if let Some(captured) = self.match_header(&buf[..len], vars.clone()) {
                            self.states.lock().expect("header-custom UDP state").remember(peer, captured);
                            return Ok(());
                        }
                    }
                    if queue.len() < 16 {
                        queue.push_back((buf[..len].to_vec(), source));
                    }
                }
                Err(error) if retryable(&error) => {}
                Err(error) => return Err(error),
            }
        }
        Err(io::ErrorKind::TimedOut.into())
    }
}

impl PacketIo for Packets {
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn recv_from(&self, out: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut queue = self.receiver.lock().expect("header-custom UDP receiver");
        if let Some((packet, peer)) = queue.pop_front() {
            return Ok((copy_packet(out, &packet), peer));
        }
        let mut wire = [0; UDP_SIZE];
        let deadline = Instant::now() + UDP_POLL;
        while Instant::now() < deadline {
            let (len, peer) = self.inner.recv_from(&mut wire)?;
            let packet = &wire[..len];
            if self.standalone {
                if self.side == Side::Server && len == self.read_size {
                    if let Some(vars) = self.match_header(packet, Vars::new()) {
                        let (reply, _) = self.header(peer, vars)?;
                        send_packet(&*self.inner, reply.len(), &reply, peer)?;
                        continue;
                    }
                }
                return Ok((copy_packet(out, packet), peer));
            }
            let mut states = self.states.lock().expect("header-custom UDP state");
            let vars = states.vars(peer).unwrap_or_default();
            if let Some(captured) = self.match_header(packet, vars) {
                states.remember(peer, captured);
                return Ok((copy_packet(out, &packet[self.read_size..]), peer));
            }
        }
        Err(io::ErrorKind::WouldBlock.into())
    }

    fn send_to(&self, packet: &[u8], peer: SocketAddr) -> io::Result<usize> {
        if self.standalone {
            if self.side == Side::Client {
                self.handshake(peer)?;
            }
            return self.inner.send_to(packet, peer);
        }
        check_udp_size(self.write_size + packet.len())?;
        let mut states = self.states.lock().expect("header-custom UDP state");
        let vars = states.vars(peer).unwrap_or_default();
        let (mut wire, vars) = self.header(peer, vars)?;
        wire.extend_from_slice(packet);
        let sent = send_packet(&*self.inner, packet.len(), &wire, peer)?;
        states.remember(peer, vars);
        Ok(sent)
    }
}
