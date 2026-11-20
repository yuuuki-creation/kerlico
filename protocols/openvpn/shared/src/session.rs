use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::{ClientConfig, ClientConnection, Connection, ServerConfig, ServerConnection};
use zeroize::Zeroizing;

use crate::data::{Data, CIPHER, PING};
use crate::invalid;
use crate::wire::{
    control, Carrier, Control, SessionId, ACK, CLIENT_RESET, CONTROL, DATA, FRAME_BATCH,
    SERVER_RESET,
};

const HELLO_TIMEOUT: Duration = Duration::from_secs(25);
const KEEPALIVE: Duration = Duration::from_secs(10);
const IDLE: Duration = Duration::from_secs(60);
const SESSION_LIMIT: Duration = Duration::from_secs(3600);
const CONTROL_FRAGMENT: usize = 1000;
const CONTROL_WINDOW: u32 = 64;
const CONTROL_LIMIT: usize = 32 * 1024;

#[derive(Clone, Copy)]
pub struct Tunnel {
    pub address: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub gateway: Option<Ipv4Addr>,
    pub mtu: u16,
    pub peer_id: u32,
}

pub struct Session {
    link: Link,
    data: Data,
    tunnel: Tunnel,
    last_read: Instant,
    last_write: Instant,
    opened: Instant,
    frame: Vec<u8>,
    batch: Vec<Vec<u8>>,
}

impl Session {
    fn new(link: Link, data: Data, tunnel: Tunnel) -> Self {
        let now = Instant::now();
        Self {
            link,
            data,
            tunnel,
            last_read: now,
            last_write: now,
            opened: now,
            frame: Vec::new(),
            batch: Vec::new(),
        }
    }

    pub fn tunnel(&self) -> Tunnel {
        self.tunnel
    }

    pub fn send(&mut self, packet: &[u8]) -> io::Result<()> {
        if self.opened.elapsed() >= SESSION_LIMIT {
            return Err(io::ErrorKind::TimedOut.into());
        }
        self.validate_packet(packet)?;
        self.send_data(packet)
    }

    fn validate_packet(&self, packet: &[u8]) -> io::Result<()> {
        if packet.len() > usize::from(self.tunnel.mtu) || packet.is_empty() {
            return Err(invalid("packet exceeds tunnel MTU"));
        }
        Ok(())
    }

    pub fn send_batch(&mut self, packets: &[Vec<u8>]) -> io::Result<()> {
        for packets in packets.chunks(FRAME_BATCH) {
            if let [packet] = packets {
                self.send(packet)?;
                continue;
            }
            if self.opened.elapsed() >= SESSION_LIMIT {
                return Err(io::ErrorKind::TimedOut.into());
            }
            for packet in packets {
                self.validate_packet(packet)?;
            }
            if self.batch.len() < packets.len() {
                self.batch.resize_with(packets.len(), Vec::new);
            }
            for (packet, frame) in packets.iter().zip(&mut self.batch) {
                self.data.seal(packet, frame)?;
            }
            self.link.carrier.send_batch(&self.batch[..packets.len()])?;
            self.last_write = Instant::now();
        }
        Ok(())
    }

    fn send_data(&mut self, packet: &[u8]) -> io::Result<()> {
        self.data.seal(packet, &mut self.frame)?;
        self.link.carrier.send(&self.frame)?;
        self.last_write = Instant::now();
        Ok(())
    }

    pub fn receive(&mut self) -> io::Result<Option<Vec<u8>>> {
        let mut packet = None;
        self.receive_batch(1, |received| packet = Some(received))?;
        Ok(packet)
    }

    /// Wait for the first frame and then drain at most `limit` frames in total.
    pub fn receive_batch(&mut self, limit: usize, deliver: impl FnMut(Vec<u8>)) -> io::Result<()> {
        let mut indexes = 0..limit;
        self.receive_from(
            |carrier| match indexes.next() {
                Some(0) => carrier.receive(),
                Some(_) => carrier.receive_ready(),
                None => Ok(None),
            },
            deliver,
        )
    }

    /// Process datagrams already read by the listener. The first drive can
    /// also drain traffic that arrived at the handshake worker.
    pub fn receive_datagrams<'a>(
        &mut self,
        datagrams: impl IntoIterator<Item = &'a [u8]>,
        mut drain_handshake: bool,
        deliver: impl FnMut(Vec<u8>),
    ) -> io::Result<()> {
        let mut datagrams = datagrams.into_iter();
        self.receive_from(
            |carrier| {
                if drain_handshake {
                    if let Some(frame) = carrier.receive_ready()? {
                        return Ok(Some(frame));
                    }
                    drain_handshake = false;
                }
                Ok(datagrams.next().map(<[u8]>::to_vec))
            },
            deliver,
        )
    }

    fn receive_from(
        &mut self,
        mut next: impl FnMut(&mut dyn Carrier) -> io::Result<Option<Vec<u8>>>,
        mut deliver: impl FnMut(Vec<u8>),
    ) -> io::Result<()> {
        let now = Instant::now();
        if now - self.last_read >= IDLE || now - self.opened >= SESSION_LIMIT {
            return Err(io::ErrorKind::TimedOut.into());
        }
        if now - self.last_write >= KEEPALIVE {
            self.send_data(&PING)?;
        }
        self.link.retransmit()?;
        let mut authenticated = false;
        while let Some(frame) = next(&mut *self.link.carrier)? {
            if let Some(frame) = self.link.on_frame(frame)? {
                if let Some(packet) = self.data.open(frame) {
                    authenticated = true;
                    if packet != PING && packet.len() <= usize::from(self.tunnel.mtu) {
                        deliver(packet);
                    }
                }
            }
        }
        if authenticated {
            self.last_read = Instant::now();
        }
        while let Some(message) = self.link.message() {
            if message == b"EXIT" || message.starts_with(b"AUTH_FAILED") {
                return Err(io::ErrorKind::ConnectionAborted.into());
            }
        }
        Ok(())
    }
}

pub fn client(
    carrier: Box<dyn Carrier>,
    tls: Arc<ClientConfig>,
    name: &str,
) -> io::Result<Session> {
    let name = name
        .to_owned()
        .try_into()
        .map_err(|_| invalid("invalid TLS server name"))?;
    let tls = ClientConnection::new(tls, name).map_err(io::Error::other)?;
    let mut link = Link::new(carrier, tls.into(), false)?;
    link.send_control(CLIENT_RESET, None, &[])?;
    link.until(|link| Ok((!link.tls.is_handshaking()).then_some(())))?;
    link.send_keys()?;
    link.until(|link| link.keys())?;
    link.send_message(b"PUSH_REQUEST")?;
    let tunnel = link.until(|link| {
        while let Some(message) = link.message() {
            if message.starts_with(b"AUTH_FAILED") {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
            if message.starts_with(b"PUSH_REPLY,") {
                return Ok(Some(parse_push(&message)?));
            }
        }
        Ok(None)
    })?;
    let data = Data::new(&link.tls, false, tunnel.peer_id)?;
    Ok(Session::new(link, data, tunnel))
}

pub fn server(
    carrier: Box<dyn Carrier>,
    tls: Arc<ServerConfig>,
    authenticate: impl FnOnce(&[u8]) -> io::Result<Tunnel>,
) -> io::Result<Session> {
    let tls = ServerConnection::new(tls).map_err(io::Error::other)?;
    let mut link = Link::new(carrier, tls.into(), true)?;
    link.until(|link| Ok((!link.tls.is_handshaking()).then_some(())))?;
    let certificate = link
        .tls
        .peer_certificates()
        .and_then(|chain| chain.first())
        .ok_or(io::ErrorKind::PermissionDenied)?;
    let tunnel = authenticate(certificate.as_ref())?;
    let peer_info = link.until(|link| link.keys())?;
    if !peer_info.uses_exporter() {
        return Err(invalid("peer needs OpenVPN TLS exporter and AES-256-GCM"));
    }
    link.send_keys()?;
    link.until(|link| {
        while let Some(message) = link.message() {
            if message == b"PUSH_REQUEST" {
                return Ok(Some(()));
            }
        }
        Ok(None)
    })?;
    let gateway = tunnel
        .gateway
        .ok_or_else(|| invalid("missing tunnel gateway"))?;
    let socket_flags = if link.carrier.datagrams() {
        ""
    } else {
        ",socket-flags TCP_NODELAY"
    };
    link.send_message(format!(
        "PUSH_REPLY,topology subnet,route-gateway {gateway},ifconfig {} {},peer-id {},cipher {CIPHER},key-derivation tls-ekm,ping 10,ping-restart 60,tun-mtu {}{socket_flags}",
        tunnel.address, tunnel.netmask, tunnel.peer_id, tunnel.mtu
    ).as_bytes())?;
    let data = Data::new(&link.tls, true, tunnel.peer_id)?;
    Ok(Session::new(link, data, tunnel))
}

struct Pending {
    frame: Vec<u8>,
    sent: Instant,
    retries: u8,
}

struct Link {
    carrier: Box<dyn Carrier>,
    tls: Connection,
    server: bool,
    deadline: Instant,
    local: SessionId,
    remote: Option<SessionId>,
    reset_acknowledged: bool,
    tx: u32,
    rx: u32,
    pending: BTreeMap<u32, Pending>,
    reordered: BTreeMap<u32, Vec<u8>>,
    plaintext: Zeroizing<Vec<u8>>,
}

impl Link {
    fn new(carrier: Box<dyn Carrier>, tls: Connection, server: bool) -> io::Result<Self> {
        let mut local = [0; 8];
        getrandom::getrandom(&mut local)
            .map_err(|_| io::Error::other("OpenVPN random session ID"))?;
        let reset_acknowledged = !server || !carrier.datagrams();
        Ok(Self {
            carrier,
            tls,
            server,
            local,
            remote: None,
            reset_acknowledged,
            deadline: Instant::now() + HELLO_TIMEOUT,
            tx: 0,
            rx: 0,
            pending: BTreeMap::new(),
            reordered: BTreeMap::new(),
            plaintext: Zeroizing::new(Vec::new()),
        })
    }

    fn until<T>(&mut self, parse: impl Fn(&mut Self) -> io::Result<Option<T>>) -> io::Result<T> {
        while Instant::now() < self.deadline {
            if let Some(value) = parse(self)? {
                return Ok(value);
            }
            self.advance()?;
        }
        Err(io::ErrorKind::TimedOut.into())
    }

    fn send_control(
        &mut self,
        opcode: u8,
        ack: Option<(u32, SessionId)>,
        payload: &[u8],
    ) -> io::Result<()> {
        if self.pending.len() >= CONTROL_WINDOW as usize {
            return Err(invalid("control send window full"));
        }
        let id = self.tx;
        self.tx = self
            .tx
            .checked_add(1)
            .ok_or_else(|| invalid("control packet ID exhausted"))?;
        let frame = control(opcode, self.local, ack, Some(id), payload);
        self.carrier.send(&frame)?;
        if self.carrier.datagrams() {
            self.pending.insert(
                id,
                Pending {
                    frame,
                    sent: Instant::now(),
                    retries: 0,
                },
            );
        }
        Ok(())
    }

    fn retransmit(&mut self) -> io::Result<()> {
        for queued in self.pending.values_mut() {
            let interval = Duration::from_millis(500) * 2u32.pow(u32::from(queued.retries.min(3)));
            if queued.sent.elapsed() < interval {
                continue;
            }
            if queued.retries == 8 {
                return Err(io::ErrorKind::TimedOut.into());
            }
            self.carrier.send(&queued.frame)?;
            queued.sent = Instant::now();
            queued.retries += 1;
        }
        Ok(())
    }

    fn advance(&mut self) -> io::Result<Option<Vec<u8>>> {
        self.retransmit()?;
        let Some(frame) = self.carrier.receive()? else {
            return Ok(None);
        };
        self.on_frame(frame)
    }

    fn on_frame(&mut self, frame: Vec<u8>) -> io::Result<Option<Vec<u8>>> {
        if frame.first().is_some_and(|opcode| opcode >> 3 == DATA) {
            return Ok(Some(frame));
        }
        if let Some(record) = Control::parse(&frame) {
            self.handle_control(record)?;
        }
        Ok(None)
    }

    fn handle_control(&mut self, record: Control<'_>) -> io::Result<()> {
        let reset = if self.server {
            CLIENT_RESET
        } else {
            SERVER_RESET
        };
        if let Some(remote) = self.remote {
            if record.session != remote {
                return Ok(());
            }
        } else if record.opcode == reset && record.sequence == Some(0) {
            self.remote = Some(record.session);
            if self.server {
                self.send_control(SERVER_RESET, Some((0, record.session)), &[])?;
            }
        } else {
            return Ok(());
        }
        if let Some(remote) = record.remote {
            if remote != self.local {
                return Ok(());
            }
            for ack in record.acknowledgements.chunks_exact(4) {
                let id = u32::from_be_bytes(ack.try_into().unwrap());
                self.pending.remove(&id);
                if id == 0 {
                    self.reset_acknowledged = true;
                }
            }
        }
        let Some(sequence) = record.sequence else {
            return Ok(());
        };
        // Require receipt of the random server session ID before sending a
        // certificate flight on an unauthenticated UDP carrier.
        if record.opcode == CONTROL && !self.reset_acknowledged {
            return Ok(());
        }
        if sequence >= self.rx.saturating_add(CONTROL_WINDOW)
            || (record.opcode != CONTROL && (record.opcode != reset || sequence != 0))
            || (record.opcode == CONTROL && (sequence == 0 || record.payload.len() > 2048))
        {
            return Ok(());
        }
        self.carrier.send(&control(
            ACK,
            self.local,
            Some((sequence, record.session)),
            None,
            &[],
        ))?;
        if sequence >= self.rx {
            self.reordered
                .entry(sequence)
                .or_insert_with(|| record.payload.to_vec());
        }
        while let Some(bytes) = self.reordered.remove(&self.rx) {
            self.rx = self
                .rx
                .checked_add(1)
                .ok_or_else(|| invalid("control packet ID exhausted"))?;
            let mut input = &bytes[..];
            while !input.is_empty() {
                self.tls.read_tls(&mut input)?;
                self.tls.process_new_packets().map_err(io::Error::other)?;
            }
            self.take_plaintext()?;
        }
        self.flush_tls()
    }

    fn take_plaintext(&mut self) -> io::Result<()> {
        let mut buffer = [0; 4096];
        loop {
            match self.tls.reader().read(&mut buffer) {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(n) => {
                    if self.plaintext.len() + n > CONTROL_LIMIT {
                        return Err(invalid("control plaintext too long"));
                    }
                    self.plaintext.extend_from_slice(&buffer[..n]);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) => return Err(error),
            }
        }
    }

    fn flush_tls(&mut self) -> io::Result<()> {
        let mut bytes = Vec::new();
        while self.tls.wants_write() {
            self.tls.write_tls(&mut bytes)?;
        }
        for fragment in bytes.chunks(CONTROL_FRAGMENT) {
            self.send_control(CONTROL, None, fragment)?;
        }
        Ok(())
    }

    fn send_message(&mut self, message: &[u8]) -> io::Result<()> {
        let mut terminated = Vec::with_capacity(message.len() + 1);
        terminated.extend_from_slice(message);
        terminated.push(0);
        self.tls.writer().write_all(&terminated)?;
        self.flush_tls()
    }

    fn message(&mut self) -> Option<Vec<u8>> {
        let end = self.plaintext.iter().position(|byte| *byte == 0)?;
        let message = self.plaintext[..end].to_vec();
        self.plaintext.drain(..=end);
        Some(message)
    }

    fn send_keys(&mut self) -> io::Result<()> {
        let mut block = Zeroizing::new(vec![0; 5 + if self.server { 64 } else { 112 }]);
        block[4] = 2;
        getrandom::getrandom(&mut block[5..])
            .map_err(|_| io::Error::other("OpenVPN key material"))?;
        let family = if self.carrier.ipv6() { 6 } else { 4 };
        let proto = if self.carrier.datagrams() {
            format!("UDPv{family}")
        } else if self.server {
            format!("TCPv{family}_SERVER")
        } else {
            format!("TCPv{family}_CLIENT")
        };
        let direction = if self.server {
            "tls-server"
        } else {
            "tls-client"
        };
        write_string(&mut block, &format!("V4,dev-type tun,link-mtu 1549,tun-mtu 1500,proto {proto},cipher {CIPHER},auth SHA1,keysize 256,key-method 2,{direction}"));
        block.extend_from_slice(&[0; 4]); // no username or password fields
        write_string(&mut block, "IV_PROTO=10\nIV_CIPHERS=AES-256-GCM\n");
        self.tls.writer().write_all(&block)?;
        self.flush_tls()
    }

    fn keys(&mut self) -> io::Result<Option<PeerInfo>> {
        let skipped = 5 + if self.server { 112 } else { 64 };
        let Some(mut input) = self.plaintext.get(skipped..) else {
            return Ok(None);
        };
        if self.plaintext[..5] != [0, 0, 0, 0, 2] {
            return Err(invalid("unsupported key method"));
        }
        let mut strings = [""; 4];
        for out in &mut strings {
            let Some((length, rest)) = input.split_first_chunk::<2>() else {
                return Ok(None);
            };
            let Some((text, rest)) = rest.split_at_checked(u16::from_be_bytes(*length).into())
            else {
                return Ok(None);
            };
            if !text.is_empty() {
                let text = text
                    .strip_suffix(&[0])
                    .ok_or_else(|| invalid("invalid key method string"))?;
                *out = std::str::from_utf8(text).unwrap_or("");
            }
            input = rest;
        }
        let peer = PeerInfo::parse(strings[3]);
        let consumed = self.plaintext.len() - input.len();
        self.plaintext.drain(..consumed);
        Ok(Some(peer))
    }
}

struct PeerInfo {
    protocol: u32,
    cipher: bool,
}

impl PeerInfo {
    fn parse(text: &str) -> Self {
        let mut info = Self {
            protocol: 0,
            cipher: false,
        };
        for line in text.lines() {
            if let Some(value) = line.strip_prefix("IV_PROTO=") {
                info.protocol = value.parse().unwrap_or(0);
            } else if let Some(ciphers) = line.strip_prefix("IV_CIPHERS=") {
                info.cipher = ciphers.split(':').any(|cipher| cipher == CIPHER);
            }
        }
        info
    }

    fn uses_exporter(&self) -> bool {
        self.cipher && self.protocol & 10 == 10
    }
}

fn write_string(block: &mut Vec<u8>, text: &str) {
    block.extend_from_slice(&((text.len() + 1) as u16).to_be_bytes());
    block.extend_from_slice(text.as_bytes());
    block.push(0);
}

fn parse_push(message: &[u8]) -> io::Result<Tunnel> {
    let text = std::str::from_utf8(message).map_err(io::Error::other)?;
    let mut ifconfig = None;
    let mut gateway = None;
    let mut peer_id = None;
    let mut subnet = false;
    let mut cipher = false;
    let mut exporter = false;
    let mut mtu = 1500u16;
    for option in text.split(',').skip(1) {
        let Some((key, value)) = option.split_once(' ') else {
            continue;
        };
        match key {
            "topology" => subnet = value == "subnet",
            "cipher" => cipher = value == CIPHER,
            "key-derivation" => exporter |= value == "tls-ekm",
            "protocol-flags" => exporter |= value.split_whitespace().any(|item| item == "tls-ekm"),
            "ifconfig" => ifconfig = value.split_once(' '),
            "route-gateway" => gateway = value.parse().ok(),
            "peer-id" => peer_id = value.parse::<u32>().ok(),
            "tun-mtu" => mtu = value.parse().map_err(|_| invalid("invalid tunnel MTU"))?,
            "compress" | "comp-lzo" | "push-continuation" => {
                return Err(invalid("unsupported pushed option"))
            }
            _ => {}
        }
    }
    if !subnet || !cipher || !exporter || !(576..=1500).contains(&mtu) {
        return Err(invalid("peer needs subnet, TLS exporter, and AES-256-GCM"));
    }
    let (address, mask) = ifconfig.ok_or_else(|| invalid("missing pushed tunnel address"))?;
    let address: Ipv4Addr = address
        .parse()
        .map_err(|_| invalid("invalid tunnel address"))?;
    let netmask: Ipv4Addr = mask.parse().map_err(|_| invalid("invalid tunnel mask"))?;
    let bits = u32::from(netmask);
    let network = u32::from(address) & bits;
    let broadcast = network | !bits;
    if address.is_unspecified()
        || address.is_multicast()
        || !(1..=30).contains(&bits.leading_ones())
        || bits.leading_ones() != bits.count_ones()
        || [network, broadcast].contains(&u32::from(address))
        || gateway.is_some_and(|ip: Ipv4Addr| {
            let ip = u32::from(ip);
            ip & bits != network || [network, broadcast, u32::from(address)].contains(&ip)
        })
    {
        return Err(invalid("invalid pushed tunnel subnet"));
    }
    Ok(Tunnel {
        address,
        netmask,
        gateway,
        mtu,
        peer_id: peer_id.ok_or_else(|| invalid("missing data peer ID"))?,
    })
}
