use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::{self, Sender};
use std::thread;
use std::time::Duration;

use kerlico_shared::Settings;
use socket2::{Domain, Protocol, Socket, Type};

use crate::Stats;

pub enum Cmd {
    Add(String, String, Settings, Sender<bool>),
    Remove(String, String, Sender<bool>),
}

pub fn serve(addr: SocketAddr, tx: Sender<Cmd>, stats: Stats) -> Option<SocketAddr> {
    let listener = bind(addr).ok()?;
    let bound = listener.local_addr().ok()?;
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let tx = tx.clone();
            let stats = stats.clone();
            thread::spawn(move || connection(stream, tx, stats));
        }
    });
    Some(bound)
}

fn bind(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(128)?;
    Ok(TcpListener::from(socket))
}

fn connection(mut tcp: TcpStream, tx: Sender<Cmd>, stats: Stats) {
    tcp.set_nodelay(true).ok();
    tcp.set_read_timeout(Some(Duration::from_secs(30))).ok();
    let mut preface = [0u8; 24];
    if tcp.read_exact(&mut preface).is_err() || &preface != b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
        return;
    }
    let _ = tcp.write_all(&frame(4, 0, 0, &[]));
    let mut decoder = hpack::Decoder::new();
    let mut block = Vec::new();
    let mut data = Vec::new();
    let mut stream = 0u32;
    let mut headers_done = false;
    loop {
        let Some((kind, flags, id, payload)) = read_frame(&mut tcp) else {
            return;
        };
        match kind {
            4 if flags & 1 == 0 => {
                let _ = tcp.write_all(&frame(4, 1, 0, &[]));
            }
            6 if flags & 1 == 0 => {
                let _ = tcp.write_all(&frame(6, 1, 0, &payload));
            }
            1 => {
                let rest = header_bytes(&payload, flags);
                block.extend_from_slice(rest);
                stream = id;
                if flags & 0x4 != 0 {
                    headers_done = true;
                }
                if flags & 1 != 0 && headers_done {
                    answer(&mut tcp, &mut decoder, stream, &block, &data, &tx, &stats);
                    block.clear();
                    data.clear();
                    headers_done = false;
                }
            }
            9 => {
                block.extend_from_slice(&payload);
                if flags & 0x4 != 0 {
                    headers_done = true;
                }
            }
            0 => {
                data.extend_from_slice(data_bytes(&payload, flags));
                if flags & 1 != 0 && headers_done {
                    answer(&mut tcp, &mut decoder, stream, &block, &data, &tx, &stats);
                    block.clear();
                    data.clear();
                    headers_done = false;
                }
            }
            _ => {}
        }
    }
}

fn answer(
    tcp: &mut TcpStream,
    decoder: &mut hpack::Decoder,
    stream: u32,
    block: &[u8],
    data: &[u8],
    tx: &Sender<Cmd>,
    stats: &Stats,
) {
    let headers = decoder.decode(block).unwrap_or_default();
    let path = headers
        .iter()
        .find(|(name, _)| name.as_slice() == b":path")
        .map(|(_, value)| String::from_utf8_lossy(value).into_owned())
        .unwrap_or_default();
    let message = grpc_message(data);
    let (status, body) = route(&path, message, tx, stats);
    let mut encoder = hpack::Encoder::new();
    let head = encoder.encode([
        (&b":status"[..], &b"200"[..]),
        (&b"content-type"[..], &b"application/grpc"[..]),
    ]);
    let _ = tcp.write_all(&frame(1, 0x4, stream, &head));
    let _ = tcp.write_all(&frame(0, 0, stream, &grpc_prefix(&body)));
    let trail = encoder.encode([(&b"grpc-status"[..], status.as_bytes())]);
    let _ = tcp.write_all(&frame(1, 0x5, stream, &trail));
}

fn route(path: &str, message: &[u8], tx: &Sender<Cmd>, stats: &Stats) -> (String, Vec<u8>) {
    match path {
        "/kerlico.Stats/Get" => {
            let name = text_field(message, 1);
            let value = stats.get(&name);
            ("0".to_string(), stat_message(&name, value))
        }
        "/kerlico.Users/Add" => {
            let tag = text_field(message, 1);
            let email = text_field(message, 2);
            let settings = settings_field(message);
            (user_status(tx, true, tag, email, settings), Vec::new())
        }
        "/kerlico.Users/Remove" => {
            let tag = text_field(message, 1);
            let email = text_field(message, 2);
            (
                user_status(tx, false, tag, email, Settings::default()),
                Vec::new(),
            )
        }
        _ => ("12".to_string(), Vec::new()),
    }
}

fn user_status(
    tx: &Sender<Cmd>,
    add: bool,
    tag: String,
    email: String,
    settings: Settings,
) -> String {
    if tag.is_empty() || email.is_empty() {
        return "3".to_string();
    }
    let (reply_tx, reply_rx) = mpsc::channel();
    let cmd = if add {
        Cmd::Add(tag, email, settings, reply_tx)
    } else {
        Cmd::Remove(tag, email, reply_tx)
    };
    if tx.send(cmd).is_err() {
        return "2".to_string();
    }
    match reply_rx.recv_timeout(Duration::from_secs(3)) {
        Ok(true) => "0".to_string(),
        _ => "5".to_string(),
    }
}

fn grpc_message(data: &[u8]) -> &[u8] {
    if data.len() < 5 || data[0] != 0 {
        return &[];
    }
    let len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
    let end = (5 + len).min(data.len());
    &data[5..end]
}

fn grpc_prefix(message: &[u8]) -> Vec<u8> {
    let mut out = vec![0, 0, 0, 0, 0];
    let len = message.len() as u32;
    out[1..5].copy_from_slice(&len.to_be_bytes());
    out.extend_from_slice(message);
    out
}

fn stat_message(name: &str, value: u64) -> Vec<u8> {
    let mut out = proto_bytes(1, name.as_bytes());
    out.extend(proto_varint(2, value));
    out
}

fn text_field(buf: &[u8], want: u32) -> String {
    for (field, value) in proto_fields(buf) {
        if field == want {
            if let Value::Bytes(bytes) = value {
                return String::from_utf8(bytes).unwrap_or_default();
            }
        }
    }
    String::new()
}

fn settings_field(buf: &[u8]) -> Settings {
    let mut settings = Settings::default();
    for (field, value) in proto_fields(buf) {
        if field != 3 {
            continue;
        }
        let Value::Bytes(body) = value else {
            continue;
        };
        let mut key = String::new();
        let mut text = String::new();
        for (inner, item) in proto_fields(&body) {
            if let Value::Bytes(bytes) = item {
                let owned = String::from_utf8(bytes).unwrap_or_default();
                if inner == 1 {
                    key = owned;
                } else if inner == 2 {
                    text = owned;
                }
            }
        }
        if !key.is_empty() {
            settings.insert_text(key, text);
        }
    }
    settings
}

#[derive(Debug)]
enum Value {
    #[allow(dead_code)]
    Varint(u64),
    Bytes(Vec<u8>),
}

fn proto_fields(buf: &[u8]) -> Vec<(u32, Value)> {
    let mut out = Vec::new();
    let mut offset = 0;
    while offset < buf.len() {
        let Some((key, next)) = varint_at(buf, offset) else {
            break;
        };
        offset = next;
        let field = (key >> 3) as u32;
        match (key & 7) as u8 {
            0 => {
                let Some((value, next)) = varint_at(buf, offset) else {
                    break;
                };
                offset = next;
                out.push((field, Value::Varint(value)));
            }
            2 => {
                let Some((len, next)) = varint_at(buf, offset) else {
                    break;
                };
                offset = next;
                let end = offset + len as usize;
                if end > buf.len() {
                    break;
                }
                out.push((field, Value::Bytes(buf[offset..end].to_vec())));
                offset = end;
            }
            1 => offset += 8,
            5 => offset += 4,
            _ => break,
        }
    }
    out
}

fn proto_bytes(field: u32, bytes: &[u8]) -> Vec<u8> {
    let mut out = varint_bytes(((field as u64) << 3) | 2);
    out.extend(varint_bytes(bytes.len() as u64));
    out.extend_from_slice(bytes);
    out
}

fn proto_varint(field: u32, value: u64) -> Vec<u8> {
    let mut out = varint_bytes((field as u64) << 3);
    out.extend(varint_bytes(value));
    out
}

fn varint_bytes(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
    out
}

fn varint_at(buf: &[u8], mut offset: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    let mut shift = 0;
    while offset < buf.len() && shift <= 63 {
        let byte = buf[offset];
        offset += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some((value, offset));
        }
        shift += 7;
    }
    None
}

fn read_frame(tcp: &mut TcpStream) -> Option<(u8, u8, u32, Vec<u8>)> {
    let mut head = [0u8; 9];
    tcp.read_exact(&mut head).ok()?;
    let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
    if len > 1024 * 1024 {
        return None;
    }
    let mut payload = vec![0u8; len];
    if len > 0 {
        tcp.read_exact(&mut payload).ok()?;
    }
    let id = u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff;
    Some((head[3], head[4], id, payload))
}

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut out = len.to_be_bytes()[1..].to_vec();
    out.push(kind);
    out.push(flags);
    out.extend_from_slice(&stream.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn header_bytes(payload: &[u8], flags: u8) -> &[u8] {
    let mut rest = payload;
    if flags & 0x8 != 0 {
        if rest.is_empty() {
            return rest;
        }
        let pad = rest[0] as usize;
        rest = &rest[1..rest.len().saturating_sub(pad)];
    }
    if flags & 0x20 != 0 && rest.len() >= 5 {
        rest = &rest[5..];
    }
    rest
}

fn data_bytes(payload: &[u8], flags: u8) -> &[u8] {
    if flags & 0x8 == 0 || payload.is_empty() {
        return payload;
    }
    let pad = payload[0] as usize;
    let end = payload.len().saturating_sub(pad);
    if end <= 1 {
        return &[];
    }
    &payload[1..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::sync::mpsc::Receiver;

    fn call(addr: SocketAddr, path: &str, message: &[u8]) -> (String, Vec<u8>) {
        let mut tcp = TcpStream::connect(addr).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        tcp.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n").unwrap();
        tcp.write_all(&frame(4, 0, 0, &[])).unwrap();
        let mut encoder = hpack::Encoder::new();
        let headers = encoder.encode([
            (&b":method"[..], &b"POST"[..]),
            (&b":path"[..], path.as_bytes()),
            (&b":scheme"[..], &b"http"[..]),
            (&b"content-type"[..], &b"application/grpc"[..]),
        ]);
        tcp.write_all(&frame(1, 0x4, 1, &headers)).unwrap();
        tcp.write_all(&frame(0, 1, 1, &grpc_prefix(message)))
            .unwrap();
        let mut decoder = hpack::Decoder::new();
        let mut status = String::new();
        let mut body = Vec::new();
        for _ in 0..8 {
            let Some((kind, _flags, _id, payload)) = read_frame(&mut tcp) else {
                break;
            };
            if kind == 1 {
                if let Ok(headers) = decoder.decode(&payload) {
                    for (name, value) in headers {
                        if name.as_slice() == b"grpc-status" {
                            status = String::from_utf8_lossy(&value).into_owned();
                        }
                    }
                }
            } else if kind == 0 && payload.len() >= 5 {
                body = grpc_message(&payload).to_vec();
            }
            if !status.is_empty() {
                break;
            }
        }
        (status, body)
    }

    #[test]
    fn stats_and_users_round_trip() {
        let (tx, rx): (Sender<Cmd>, Receiver<Cmd>) = mpsc::channel();
        thread::spawn(move || {
            while let Ok(cmd) = rx.recv() {
                match cmd {
                    Cmd::Add(_, _, settings, reply) => {
                        let _ = reply.send(settings.text("password").is_ok());
                    }
                    Cmd::Remove(_, _, reply) => {
                        let _ = reply.send(false);
                    }
                }
            }
        });
        let stats = Stats::new();
        let email = kerlico_shared::UserEmail::parse("a@b.c").unwrap();
        let node = kerlico_shared::NodeTag::parse("node-a").unwrap();
        stats.add_uplink(&email, &node, 12);
        let addr = serve(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), tx, stats).unwrap();
        thread::sleep(Duration::from_millis(50));
        let name = "user>>>a@b.c>>>traffic>>>uplink";
        let (status, body) = call(addr, "/kerlico.Stats/Get", &proto_bytes(1, name.as_bytes()));
        assert_eq!(status, "0");
        assert_eq!(text_field(&body, 1), name);
        assert!(proto_fields(&body)
            .iter()
            .any(|(field, value)| { *field == 2 && matches!(value, Value::Varint(12)) }));
        let mut add = proto_bytes(1, b"node-a");
        add.extend(proto_bytes(2, b"a@b.c"));
        let mut setting = proto_bytes(1, b"password");
        setting.extend(proto_bytes(2, b"secret"));
        add.extend(proto_bytes(3, &setting));
        let (status, _) = call(addr, "/kerlico.Users/Add", &add);
        assert_eq!(status, "0");
        let mut remove = proto_bytes(1, b"node-a");
        remove.extend(proto_bytes(2, b"a@b.c"));
        let (status, _) = call(addr, "/kerlico.Users/Remove", &remove);
        assert_eq!(status, "5");
    }
}
