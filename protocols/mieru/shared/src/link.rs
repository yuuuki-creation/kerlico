use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::crypto::{self, Direction};

const OPEN_REQUEST: u8 = 2;
const OPEN_RESPONSE: u8 = 3;
const CLOSE_REQUEST: u8 = 4;
const CLOSE_RESPONSE: u8 = 5;
const DATA_C2S: u8 = 6;
const DATA_S2C: u8 = 7;
const ACK_C2S: u8 = 8;
const ACK_S2C: u8 = 9;
const MAX_PAYLOAD: usize = 32 * 1024;

pub struct Account {
    pub username: String,
    pub password: String,
}

pub struct Target {
    pub host: String,
    pub port: u16,
}

struct Meta {
    kind: u8,
    session: u32,
    seq: u32,
    payload_len: u16,
    suffix: u8,
    prefix: u8,
}

pub struct Conn {
    read: Mutex<Half>,
    write: Mutex<Half>,
    server: bool,
    username: String,
    session: u32,
    send_seq: Mutex<u32>,
    recv_seq: Mutex<u32>,
}

struct Half {
    tcp: TcpStream,
    direction: Direction,
    pending: VecDeque<u8>,
    stash: Vec<u8>,
}

pub fn accept(tcp: TcpStream, accounts: &[Account]) -> io::Result<(Conn, Target, String)> {
    tcp.set_nodelay(true).ok();
    let mut tcp = tcp;
    tcp.set_read_timeout(Some(Duration::from_secs(20))).ok();
    let now = unix_now();
    let mut stash = Vec::new();
    let header = read_chunk_stash(&mut tcp, &mut stash, 24 + 32 + 16)?;
    let mut opened = None;
    for account in accounts {
        if let Some(found) = crypto::open_first(&account.username, &account.password, &header, now) {
            opened = Some(found);
            break;
        }
    }
    let opened = opened.ok_or_else(|| io::Error::new(io::ErrorKind::PermissionDenied, "mieru user"))?;
    let meta = parse_meta(&opened.plain)?;
    if meta.kind != OPEN_REQUEST || meta.session == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "open"));
    }
    let mut recv = opened.direction;
    let payload = read_payload(&mut tcp, &mut recv, &mut stash, meta.payload_len, meta.suffix, 0)?;
    let mut send = recv.fork_send();
    let read_tcp = tcp.try_clone()?;
    write_session(&mut tcp, &mut send, &opened.username, OPEN_RESPONSE, meta.session, 0, &[])?;
    let conn = Conn {
        read: Mutex::new(Half {
            tcp: read_tcp,
            direction: recv,
            pending: VecDeque::from(payload),
            stash,
        }),
        write: Mutex::new(Half {
            tcp,
            direction: send,
            pending: VecDeque::new(),
            stash: Vec::new(),
        }),
        server: true,
        username: opened.username.clone(),
        session: meta.session,
        send_seq: Mutex::new(1),
        recv_seq: Mutex::new(meta.seq.wrapping_add(1)),
    };
    let target = socks_server(&conn)?;
    Ok((conn, target, opened.username))
}

pub fn connect(peer: SocketAddr, account: &Account, target: &Target) -> io::Result<Conn> {
    let tcp = TcpStream::connect_timeout(&peer, Duration::from_secs(10))?;
    tcp.set_nodelay(true).ok();
    let mut tcp = tcp;
    tcp.set_read_timeout(Some(Duration::from_secs(20))).ok();
    let now = unix_now();
    let mut send = crypto::client_direction(&account.username, &account.password, now);
    let session = random_u32().max(1);
    write_session(&mut tcp, &mut send, &account.username, OPEN_REQUEST, session, 0, &[])?;
    let mut stash = Vec::new();
    let header = read_chunk_stash(&mut tcp, &mut stash, 24 + 32 + 16)?;
    let opened = crypto::open_first(&account.username, &account.password, &header, now)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "server nonce"))?;
    let meta = parse_meta(&opened.plain)?;
    let mut recv = opened.direction;
    if meta.kind != OPEN_RESPONSE || meta.session != session {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "response"));
    }
    let _ = read_payload(&mut tcp, &mut recv, &mut stash, meta.payload_len, meta.suffix, 0)?;
    let read_tcp = tcp.try_clone()?;
    let conn = Conn {
        read: Mutex::new(Half {
            tcp: read_tcp,
            direction: recv,
            pending: VecDeque::new(),
            stash,
        }),
        write: Mutex::new(Half {
            tcp,
            direction: send,
            pending: VecDeque::new(),
            stash: Vec::new(),
        }),
        server: false,
        username: account.username.clone(),
        session,
        send_seq: Mutex::new(1),
        recv_seq: Mutex::new(1),
    };
    socks_client(&conn, target)?;
    Ok(conn)
}

pub fn resolve_peer(host: &str, port: u16) -> io::Result<SocketAddr> {
    let text = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    text.to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "peer"))
}

impl Conn {
    fn buffered(&self) -> usize {
        self.read.lock().expect("read").pending.len()
    }

    pub fn read_user(&self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut half = self.read.lock().expect("read");
        if half.pending.is_empty() {
            match self.pull(&mut half) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    return Err(error);
                }
                Err(error) => return Err(error),
            }
        }
        let n = half.pending.len().min(buf.len());
        for (slot, byte) in buf.iter_mut().zip(half.pending.drain(..n)) {
            *slot = byte;
        }
        Ok(n)
    }

    pub fn write_user(&self, buf: &[u8]) -> io::Result<()> {
        let mut offset = 0;
        while offset < buf.len() {
            let end = (offset + MAX_PAYLOAD).min(buf.len());
            self.write_data(&buf[offset..end])?;
            offset = end;
        }
        Ok(())
    }

    fn pull(&self, half: &mut Half) -> io::Result<()> {
        loop {
            let encrypted_len = if half.direction_has_nonce() { 32 + 16 } else { 24 + 32 + 16 };
            let header = take(&mut half.tcp, &mut half.stash, encrypted_len, true)?;
            let plain = if half.direction_has_nonce() {
                half.open_next(&header)?
            } else {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "nonce"));
            };
            let meta = parse_meta(&plain)?;
            if meta.kind == CLOSE_REQUEST || meta.kind == CLOSE_RESPONSE {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "close"));
            }
            if meta.kind == ACK_C2S || meta.kind == ACK_S2C {
                continue;
            }
            let payload = read_payload(
                &mut half.tcp,
                &mut half.direction,
                &mut half.stash,
                meta.payload_len,
                meta.suffix,
                meta.prefix,
            )?;
            let expect = *self.recv_seq.lock().expect("seq");
            if meta.seq != expect {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "seq"));
            }
            *self.recv_seq.lock().expect("seq") = expect.wrapping_add(1);
            if !payload.is_empty()
                && (meta.kind == DATA_C2S || meta.kind == DATA_S2C || meta.kind == OPEN_REQUEST)
            {
                half.pending.extend(payload);
                return Ok(());
            }
        }
    }

    fn write_data(&self, payload: &[u8]) -> io::Result<()> {
        let mut half = self.write.lock().expect("write");
        let seq = {
            let mut seq = self.send_seq.lock().expect("seq");
            let current = *seq;
            *seq = current.wrapping_add(1);
            current
        };
        let unack = *self.recv_seq.lock().expect("seq");
        let kind = if self.server { DATA_S2C } else { DATA_C2S };
        let meta = data_meta(kind, self.session, seq, unack, payload.len() as u16);
        let wire_meta = half.direction.seal(&self.username, &meta);
        let wire_body = if payload.is_empty() {
            Vec::new()
        } else {
            half.direction.seal(&self.username, payload)
        };
        write_retry(&mut half.tcp, &wire_meta)?;
        write_retry(&mut half.tcp, &wire_body)?;
        Ok(())
    }
}

impl Half {
    fn direction_has_nonce(&self) -> bool {
        self.direction.has_nonce()
    }

    fn open_next(&mut self, packet: &[u8]) -> io::Result<Vec<u8>> {
        self.direction
            .open_next(packet)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "decrypt"))
    }
}

fn write_session(
    tcp: &mut TcpStream,
    direction: &mut Direction,
    username: &str,
    kind: u8,
    session: u32,
    seq: u32,
    payload: &[u8],
) -> io::Result<()> {
    let meta = session_meta(kind, session, seq, payload.len() as u16);
    let wire = direction.seal(username, &meta);
    write_retry(tcp, &wire)?;
    if !payload.is_empty() {
        let body = direction.seal(username, payload);
        write_retry(tcp, &body)?;
    }
    Ok(())
}

fn read_payload(
    tcp: &mut TcpStream,
    direction: &mut Direction,
    stash: &mut Vec<u8>,
    payload_len: u16,
    suffix: u8,
    prefix: u8,
) -> io::Result<Vec<u8>> {
    if prefix > 0 {
        let _ = read_chunk_stash(tcp, stash, prefix as usize)?;
    }
    let payload = if payload_len == 0 {
        Vec::new()
    } else {
        let wire = read_chunk_stash(tcp, stash, payload_len as usize + 16)?;
        direction
            .open_next(&wire)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "payload"))?
    };
    if suffix > 0 {
        let _ = read_chunk_stash(tcp, stash, suffix as usize)?;
    }
    Ok(payload)
}

fn session_meta(kind: u8, session: u32, seq: u32, payload_len: u16) -> [u8; 32] {
    let mut meta = [0u8; 32];
    meta[0] = kind;
    let minutes = (unix_now() / 60) as u32;
    meta[2..6].copy_from_slice(&minutes.to_be_bytes());
    meta[6..10].copy_from_slice(&session.to_be_bytes());
    meta[10..14].copy_from_slice(&seq.to_be_bytes());
    meta[15..17].copy_from_slice(&payload_len.to_be_bytes());
    meta
}

fn data_meta(kind: u8, session: u32, seq: u32, unack: u32, payload_len: u16) -> [u8; 32] {
    let mut meta = [0u8; 32];
    meta[0] = kind;
    let minutes = (unix_now() / 60) as u32;
    meta[2..6].copy_from_slice(&minutes.to_be_bytes());
    meta[6..10].copy_from_slice(&session.to_be_bytes());
    meta[10..14].copy_from_slice(&seq.to_be_bytes());
    meta[14..18].copy_from_slice(&unack.to_be_bytes());
    meta[18..20].copy_from_slice(&4096u16.to_be_bytes());
    meta[22..24].copy_from_slice(&payload_len.to_be_bytes());
    meta
}

fn parse_meta(plain: &[u8]) -> io::Result<Meta> {
    if plain.len() != 32 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "meta"));
    }
    let minutes = u32::from_be_bytes(plain[2..6].try_into().unwrap());
    let now = (unix_now() / 60) as u32;
    if minutes.abs_diff(now) > 1 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "time"));
    }
    let kind = plain[0];
    let session = u32::from_be_bytes(plain[6..10].try_into().unwrap());
    let seq = u32::from_be_bytes(plain[10..14].try_into().unwrap());
    let (payload_len, suffix, prefix) = if matches!(kind, OPEN_REQUEST | OPEN_RESPONSE | CLOSE_REQUEST | CLOSE_RESPONSE)
    {
        (
            u16::from_be_bytes(plain[15..17].try_into().unwrap()),
            plain[17],
            0,
        )
    } else {
        (
            u16::from_be_bytes(plain[22..24].try_into().unwrap()),
            plain[24],
            plain[21],
        )
    };
    Ok(Meta {
        kind,
        session,
        seq,
        payload_len,
        suffix,
        prefix,
    })
}

fn socks_server(conn: &Conn) -> io::Result<Target> {
    let greeting = read_n(conn, 2)?;
    if greeting[0] != 5 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "socks"));
    }
    if greeting[1] == 1 && conn.buffered() >= 2 {
        let mark = read_n(conn, 2)?;
        if mark[0] == 0 && matches!(mark[1], 1 | 3 | 4) {
            let target = socks_addr(conn, mark[1])?;
            conn.write_user(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])?;
            return Ok(target);
        }
        return Err(io::Error::new(io::ErrorKind::InvalidData, "socks"));
    }
    let methods = read_n(conn, greeting[1] as usize)?;
    if !methods.contains(&0) {
        conn.write_user(&[5, 0xff])?;
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "socks auth"));
    }
    conn.write_user(&[5, 0])?;
    let head = read_n(conn, 4)?;
    if head[0] != 5 || head[1] != 1 {
        conn.write_user(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0])?;
        return Err(io::Error::new(io::ErrorKind::InvalidData, "socks cmd"));
    }
    let target = socks_addr(conn, head[3])?;
    conn.write_user(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])?;
    Ok(target)
}

fn socks_addr(conn: &Conn, atyp: u8) -> io::Result<Target> {
    let host = match atyp {
        1 => {
            let addr = read_n(conn, 4)?;
            format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
        }
        3 => {
            let len = read_n(conn, 1)?[0] as usize;
            String::from_utf8(read_n(conn, len)?)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "host"))?
        }
        4 => {
            let addr = read_n(conn, 16)?;
            let mut parts = [0u8; 16];
            parts.copy_from_slice(&addr);
            std::net::Ipv6Addr::from(parts).to_string()
        }
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "atyp")),
    };
    let port_bytes = read_n(conn, 2)?;
    let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
    Ok(Target { host, port })
}

fn socks_client(conn: &Conn, target: &Target) -> io::Result<()> {
    conn.write_user(&[5, 1, 0])?;
    let reply = read_n(conn, 2)?;
    if reply != [5, 0] {
        return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "socks"));
    }
    let mut request = vec![5, 1, 0, 3, target.host.len() as u8];
    request.extend(target.host.as_bytes());
    request.extend(target.port.to_be_bytes());
    conn.write_user(&request)?;
    let head = read_n(conn, 4)?;
    if head[1] != 0 {
        return Err(io::Error::new(io::ErrorKind::ConnectionRefused, "socks reply"));
    }
    let rest = match head[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => read_n(conn, 1)?[0] as usize + 2,
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "reply atyp")),
    };
    let _ = read_n(conn, rest)?;
    Ok(())
}

fn read_n(conn: &Conn, n: usize) -> io::Result<Vec<u8>> {
    let mut out = vec![0u8; n];
    let mut filled = 0;
    let start = Instant::now();
    while filled < n {
        match conn.read_user(&mut out[filled..]) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "socks")),
            Ok(got) => filled += got,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if start.elapsed() > Duration::from_secs(20) {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "socks"));
                }
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(error),
        }
    }
    Ok(out)
}

fn read_chunk_stash(tcp: &mut TcpStream, stash: &mut Vec<u8>, n: usize) -> io::Result<Vec<u8>> {
    take(tcp, stash, n, false)
}

fn take(tcp: &mut TcpStream, stash: &mut Vec<u8>, n: usize, nonblock_idle: bool) -> io::Result<Vec<u8>> {
    let start = Instant::now();
    while stash.len() < n {
        let mut buf = [0u8; 4096];
        match tcp.read(&mut buf) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "tcp")),
            Ok(read) => stash.extend_from_slice(&buf[..read]),
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::TimedOut =>
            {
                if nonblock_idle && stash.is_empty() {
                    return Err(io::Error::new(io::ErrorKind::WouldBlock, "idle"));
                }
                if start.elapsed() > Duration::from_secs(20) {
                    return Err(error);
                }
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => return Err(error),
        }
    }
    Ok(stash.drain(..n).collect())
}

fn write_retry(tcp: &mut TcpStream, bytes: &[u8]) -> io::Result<()> {
    let mut rest = bytes;
    let start = Instant::now();
    while !rest.is_empty() {
        match tcp.write(rest) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "tcp")),
            Ok(n) => rest = &rest[n..],
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::TimedOut =>
            {
                if start.elapsed() > Duration::from_secs(20) {
                    return Err(error);
                }
                thread::sleep(Duration::from_millis(2));
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

fn random_u32() -> u32 {
    let mut bytes = [0u8; 4];
    getrandom::getrandom(&mut bytes).expect("random");
    u32::from_be_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn localhost_carries_bytes_after_socks() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (tcp, _) = listener.accept().unwrap();
            let account = Account {
                username: "alice".to_string(),
                password: "secret".to_string(),
            };
            let (conn, target, user) = accept(tcp, &[account]).unwrap();
            assert_eq!(user, "alice");
            assert_eq!(target.host, "example.com");
            assert_eq!(target.port, 443);
            let mut buf = [0u8; 4];
            let n = read_n(&conn, 4).unwrap();
            assert_eq!(n, b"ping");
            conn.write_user(b"pong").unwrap();
            let _ = buf;
        });
        let account = Account {
            username: "alice".to_string(),
            password: "secret".to_string(),
        };
        let conn = connect(
            format!("127.0.0.1:{port}").parse().unwrap(),
            &account,
            &Target {
                host: "example.com".to_string(),
                port: 443,
            },
        )
        .unwrap();
        conn.write_user(b"ping").unwrap();
        assert_eq!(read_n(&conn, 4).unwrap(), b"pong");
        server.join().unwrap();
    }
}
