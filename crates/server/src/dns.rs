use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::thread;
use std::time::Duration;

use kerlico_outbound::{Native, Outbound, OutboundChoice, Reachability, select_exit};
use socket2::{Domain, Protocol, Socket, Type};

use crate::fakedns::Pool;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Strategy {
    UseIp,
    UseV4,
    UseV6,
}

#[derive(Clone, Debug)]
pub struct Upstream {
    pub address: IpAddr,
    pub port: u16,
    pub tcp: bool,
    pub choice: OutboundChoice,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub hosts: BTreeMap<String, Vec<IpAddr>>,
    pub upstreams: Vec<Upstream>,
    pub strategy: Strategy,
    pub listen: Option<SocketAddr>,
}

impl Config {
    pub fn lookup_srv(&self, name: &str, native: Native, outbound: &Outbound) -> std::io::Result<Vec<kerlico_shared::runtime::SrvRecord>> {
        let response = self.record_query(name, 33, native, outbound)?;
        let mut result = Vec::new();
        for (kind, offset, length) in record_locations(&response)? {
            if kind != 33 { continue; }
            if length < 7 { return Err(bad_dns("short SRV record")); }
            let u16_at = |at| u16::from_be_bytes([response[at], response[at + 1]]);
            let (target, end) = read_name(&response, offset + 6).ok_or_else(|| bad_dns("bad SRV target"))?;
            if end > offset + length { return Err(bad_dns("SRV target exceeds record")); }
            result.push(kerlico_shared::runtime::SrvRecord { target, port: u16_at(offset + 4), priority: u16_at(offset), weight: u16_at(offset + 2) });
        }
        Ok(result)
    }

    pub fn lookup_txt(&self, name: &str, native: Native, outbound: &Outbound) -> std::io::Result<Vec<String>> {
        let response = self.record_query(name, 16, native, outbound)?;
        let mut result = Vec::new();
        for (kind, offset, length) in record_locations(&response)? {
            if kind != 16 { continue; }
            let mut at = offset;
            let mut text = Vec::new();
            while at < offset + length {
                let size = response[at] as usize;
                at += 1;
                if at + size > offset + length { return Err(bad_dns("short TXT segment")); }
                text.extend_from_slice(&response[at..at + size]);
                at += size;
            }
            result.push(String::from_utf8(text).map_err(|_| bad_dns("non-UTF8 TXT endpoint"))?);
        }
        Ok(result)
    }

    fn record_query(&self, name: &str, kind: u16, native: Native, outbound: &Outbound) -> std::io::Result<Vec<u8>> {
        let message = message(name, kind);
        let fallback = Upstream { address: "1.1.1.1".parse().expect("literal DNS"), port: 53, tcp: false, choice: OutboundChoice::Default };
        let upstreams = if self.upstreams.is_empty() { std::slice::from_ref(&fallback) } else { self.upstreams.as_slice() };
        let mut error = bad_dns("no DNS upstream answered");
        for upstream in upstreams {
            let reach = if upstream.address.is_ipv4() { Reachability::HasV4 } else { Reachability::V6Only };
            let exit = select_exit(upstream.choice, reach, native).map_err(|_| bad_dns("DNS upstream has no address"))?;
            match outbound.exchange(exit, SocketAddr::new(upstream.address, upstream.port), upstream.tcp, &message) {
                Ok(response) if response.len() >= 12 && response[..2] == message[..2] && response[2] & 0x80 != 0 && response[3] & 0xf == 0 => return Ok(response),
                Ok(_) => error = bad_dns("invalid DNS response"),
                Err(_) => error = std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "DNS upstream exchange failed"),
            }
        }
        Err(error)
    }

    pub fn lookup(&self, host: &str, native: Native, outbound: &Outbound) -> Vec<IpAddr> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return vec![ip];
        }
        let key = host.trim_end_matches('.').to_ascii_lowercase();
        if let Some(ips) = self.hosts.get(&key) {
            return filter_family(ips, self.strategy);
        }
        let fallback = Upstream {
            address: IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            port: 53,
            tcp: false,
            choice: OutboundChoice::Default,
        };
        let upstreams = if self.upstreams.is_empty() {
            std::slice::from_ref(&fallback)
        } else {
            self.upstreams.as_slice()
        };
        let mut found = Vec::new();
        for upstream in upstreams {
            if self.strategy != Strategy::UseV6 {
                found.extend(query(host, upstream, 1, native, outbound));
            }
            if self.strategy != Strategy::UseV4 {
                found.extend(query(host, upstream, 28, native, outbound));
            }
            if !found.is_empty() {
                break;
            }
        }
        found
    }
}

impl Default for Config {
    fn default() -> Self { Self { hosts: BTreeMap::new(), upstreams: Vec::new(), strategy: Strategy::UseIp, listen: None } }
}

fn bad_dns(message: &str) -> std::io::Error { std::io::Error::new(std::io::ErrorKind::InvalidData, message) }

fn record_locations(message: &[u8]) -> std::io::Result<Vec<(u16, usize, usize)>> {
    if message.len() < 12 { return Err(bad_dns("short DNS header")); }
    let questions = u16::from_be_bytes([message[4], message[5]]);
    let answers = u16::from_be_bytes([message[6], message[7]]);
    let mut at = 12;
    for _ in 0..questions {
        at = read_name(message, at).ok_or_else(|| bad_dns("bad DNS question"))?.1 + 4;
        if at > message.len() { return Err(bad_dns("short DNS question")); }
    }
    let mut records = Vec::new();
    for _ in 0..answers {
        at = read_name(message, at).ok_or_else(|| bad_dns("bad DNS record name"))?.1;
        if at + 10 > message.len() { return Err(bad_dns("short DNS record")); }
        let kind = u16::from_be_bytes([message[at], message[at + 1]]);
        let class = u16::from_be_bytes([message[at + 2], message[at + 3]]);
        let length = u16::from_be_bytes([message[at + 8], message[at + 9]]) as usize;
        at += 10;
        if at + length > message.len() { return Err(bad_dns("short DNS record data")); }
        if class == 1 { records.push((kind, at, length)); }
        at += length;
    }
    Ok(records)
}

pub fn reply(
    query: &[u8],
    config: &Config,
    pool: &Pool,
    fake: bool,
    native: Native,
    outbound: &Outbound,
) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let (name, after_name) = read_name(query, 12)?;
    if after_name + 4 > query.len() || name.is_empty() {
        return None;
    }
    let qtype = u16::from_be_bytes([query[after_name], query[after_name + 1]]);
    let qclass = u16::from_be_bytes([query[after_name + 2], query[after_name + 3]]);
    let question_end = after_name + 4;
    if qclass != 1 {
        return Some(encode(query, question_end, &[]));
    }
    let ips = addresses(config, pool, fake, native, outbound, &name, qtype);
    Some(encode(query, question_end, &ips))
}

pub fn serve(
    addr: SocketAddr,
    config: Config,
    pool: Pool,
    fake: bool,
    native: Native,
    outbound: Outbound,
) -> Option<SocketAddr> {
    let udp = bind_udp(addr).ok()?;
    let bound = udp.local_addr().ok()?;
    let tcp = bind_tcp(bound).ok()?;
    let udp_config = config.clone();
    let udp_pool = pool.clone();
    let udp_outbound = outbound.clone();
    thread::spawn(move || udp_loop(udp, udp_config, udp_pool, fake, native, udp_outbound));
    thread::spawn(move || tcp_loop(tcp, config, pool, fake, native, outbound));
    Some(bound)
}

fn addresses(
    config: &Config,
    pool: &Pool,
    fake: bool,
    native: Native,
    outbound: &Outbound,
    name: &str,
    qtype: u16,
) -> Vec<IpAddr> {
    let want_v4 = qtype == 1 && config.strategy != Strategy::UseV6;
    let want_v6 = qtype == 28 && config.strategy != Strategy::UseV4;
    if !want_v4 && !want_v6 {
        return Vec::new();
    }
    if fake {
        return if want_v4 {
            vec![IpAddr::V4(pool.assign_v4(name))]
        } else {
            vec![IpAddr::V6(pool.assign_v6(name))]
        };
    }
    config
        .lookup(name, native, outbound)
        .into_iter()
        .filter(|ip| (want_v4 && ip.is_ipv4()) || (want_v6 && ip.is_ipv6()))
        .collect()
}

fn encode(query: &[u8], question_end: usize, ips: &[IpAddr]) -> Vec<u8> {
    let mut out = query[..question_end].to_vec();
    out[2] = 0x81;
    out[3] = 0x80;
    out[4] = 0;
    out[5] = 1;
    let count = ips.len() as u16;
    out[6] = (count >> 8) as u8;
    out[7] = count as u8;
    out[8] = 0;
    out[9] = 0;
    out[10] = 0;
    out[11] = 0;
    for ip in ips {
        out.extend_from_slice(&[0xc0, 0x0c]);
        let (kind, rdata): (u16, Vec<u8>) = match ip {
            IpAddr::V4(addr) => (1, addr.octets().to_vec()),
            IpAddr::V6(addr) => (28, addr.octets().to_vec()),
        };
        out.extend_from_slice(&kind.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&60u32.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&rdata);
    }
    out
}

fn udp_loop(socket: UdpSocket, config: Config, pool: Pool, fake: bool, native: Native, outbound: Outbound) {
    let mut buf = [0u8; 2048];
    loop {
        let Ok((n, peer)) = socket.recv_from(&mut buf) else {
            continue;
        };
        if let Some(response) = reply(&buf[..n], &config, &pool, fake, native, &outbound) {
            let _ = socket.send_to(&response, peer);
        }
    }
}

fn tcp_loop(listener: TcpListener, config: Config, pool: Pool, fake: bool, native: Native, outbound: Outbound) {
    for stream in listener.incoming().flatten() {
        let config = config.clone();
        let pool = pool.clone();
        let outbound = outbound.clone();
        thread::spawn(move || {
            let _ = tcp_one(stream, &config, &pool, fake, native, &outbound);
        });
    }
}

fn tcp_one(
    mut stream: TcpStream,
    config: &Config,
    pool: &Pool,
    fake: bool,
    native: Native,
    outbound: &Outbound,
) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf)?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len == 0 || len > 2048 {
        return Ok(());
    }
    let mut query = vec![0u8; len];
    stream.read_exact(&mut query)?;
    if let Some(response) = reply(&query, config, pool, fake, native, outbound) {
        let n = (response.len() as u16).to_be_bytes();
        stream.write_all(&n)?;
        stream.write_all(&response)?;
    }
    Ok(())
}

fn bind_udp(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let socket = open_socket(addr, Type::DGRAM, Protocol::UDP)?;
    socket.bind(&addr.into())?;
    Ok(UdpSocket::from(socket))
}

fn bind_tcp(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let socket = open_socket(addr, Type::STREAM, Protocol::TCP)?;
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(128)?;
    Ok(TcpListener::from(socket))
}

fn open_socket(addr: SocketAddr, kind: Type, protocol: Protocol) -> std::io::Result<Socket> {
    let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let socket = Socket::new(domain, kind, Some(protocol))?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    Ok(socket)
}

fn read_name(buf: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut jumps = 0;
    let mut end = None;
    while offset < buf.len() && jumps < 8 {
        let len = buf[offset] as usize;
        if len == 0 {
            if end.is_none() {
                end = Some(offset + 1);
            }
            break;
        }
        if len & 0xc0 == 0xc0 {
            if offset + 1 >= buf.len() {
                return None;
            }
            if end.is_none() {
                end = Some(offset + 2);
            }
            offset = ((len & 0x3f) << 8) | buf[offset + 1] as usize;
            jumps += 1;
            continue;
        }
        if offset + 1 + len > buf.len() {
            return None;
        }
        labels.push(String::from_utf8(buf[offset + 1..offset + 1 + len].to_vec()).ok()?);
        offset += 1 + len;
    }
    Some((labels.join("."), end?))
}

fn filter_family(ips: &[IpAddr], strategy: Strategy) -> Vec<IpAddr> {
    ips.iter()
        .copied()
        .filter(|ip| match strategy {
            Strategy::UseV4 => ip.is_ipv4(),
            Strategy::UseV6 => ip.is_ipv6(),
            Strategy::UseIp => true,
        })
        .collect()
}

fn query(
    host: &str,
    upstream: &Upstream,
    kind: u16,
    native: Native,
    outbound: &Outbound,
) -> Vec<IpAddr> {
    let message = message(host, kind);
    let reach = if upstream.address.is_ipv4() {
        Reachability::HasV4
    } else {
        Reachability::V6Only
    };
    let Ok(exit) = select_exit(upstream.choice, reach, native) else {
        return Vec::new();
    };
    let peer = SocketAddr::new(upstream.address, upstream.port);
    let Ok(buf) = outbound.exchange(exit, peer, upstream.tcp, &message) else {
        return Vec::new();
    };
    answers(&buf, kind)
}

fn message(host: &str, kind: u16) -> Vec<u8> {
    static NEXT_ID: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(1);
    let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed).to_be_bytes();
    let mut out = vec![id[0], id[1], 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in host.trim_end_matches('.').split('.') {
        out.push(label.len() as u8);
        out.extend(label.as_bytes());
    }
    out.extend([0, (kind >> 8) as u8, kind as u8, 0, 1]);
    out
}

fn answers(buf: &[u8], kind: u16) -> Vec<IpAddr> {
    if buf.len() < 12 {
        return Vec::new();
    }
    let questions = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let records = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    let mut offset = 12;
    for _ in 0..questions {
        offset = skip_name(buf, offset);
        offset = offset.saturating_add(4);
    }
    let mut found = Vec::new();
    for _ in 0..records {
        offset = skip_name(buf, offset);
        if offset + 10 > buf.len() {
            break;
        }
        let record_kind = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
        let len = u16::from_be_bytes([buf[offset + 8], buf[offset + 9]]) as usize;
        offset += 10;
        if offset + len > buf.len() {
            break;
        }
        if record_kind == kind && kind == 1 && len == 4 {
            found.push(IpAddr::V4(Ipv4Addr::new(buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3])));
        }
        if record_kind == kind && kind == 28 && len == 16 {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[offset..offset + 16]);
            found.push(IpAddr::V6(Ipv6Addr::from(octets)));
        }
        offset += len;
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_match_is_exact_and_obeys_strategy() {
        let mut hosts = BTreeMap::new();
        hosts.insert(
            "example.com".to_string(),
            vec![
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
            ],
        );
        let config = Config {
            hosts,
            upstreams: Vec::new(),
            strategy: Strategy::UseV4,
            listen: None,
        };
        assert_eq!(
            config.lookup(
                "Example.com.",
                Native { v4: true, v6: true },
                &Outbound::new(),
            ),
            vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))]
        );
    }

    #[test]
    fn fakedns_listener_repeats_the_same_address() {
        let config = Config {
            hosts: BTreeMap::new(),
            upstreams: Vec::new(),
            strategy: Strategy::UseIp,
            listen: None,
        };
        let pool = Pool::new();
        let native = Native { v4: true, v6: true };
        let outbound = Outbound::new();
        let query = message("Example.COM", 1);
        let bound = serve(
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            config.clone(),
            pool.clone(),
            true,
            native,
            outbound.clone(),
        )
        .unwrap();
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        socket.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        socket.send_to(&query, bound).unwrap();
        let mut buf = [0u8; 512];
        let n = socket.recv(&mut buf).unwrap();
        let first = answers(&buf[..n], 1);
        assert_eq!(first.len(), 1);
        assert_eq!(pool.rewrite(first[0]).as_deref(), Some("example.com"));
        socket.send_to(&query, bound).unwrap();
        let n = socket.recv(&mut buf).unwrap();
        assert_eq!(answers(&buf[..n], 1), first);
    }
}

fn skip_name(buf: &[u8], mut offset: usize) -> usize {
    while offset < buf.len() {
        let len = buf[offset] as usize;
        if len == 0 {
            return offset + 1;
        }
        if len & 0xc0 == 0xc0 {
            return offset + 2;
        }
        offset += 1 + len;
    }
    offset
}
