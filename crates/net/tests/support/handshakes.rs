//! 入站嗅探测试共用：合成握手、录制夹具与 SOCKS5/HTTP 客户端动作。各 crate 以 `#[path]` 引入。
#![allow(dead_code)]

use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::timeout,
};

pub const ALL_PORTS_SNIFFER: &str = r#"{"enable":true,"override_destination":false,"sniff":{"TLS":{"ports":["1-65535"]},"HTTP":{"ports":["1-65535"]},"QUIC":{"ports":["1-65535"]}}}"#;

pub fn sniffer(extra: serde_json::Value) -> serde_json::Value {
    let mut value: serde_json::Value = serde_json::from_str(ALL_PORTS_SNIFFER).unwrap();
    if let (Some(base), Some(extra)) = (value.as_object_mut(), extra.as_object()) {
        for (key, item) in extra {
            base.insert(key.clone(), item.clone());
        }
    }
    value
}

/// TLS 1.3 风格 ClientHello 记录，只带 SNI 扩展。
pub fn tls_client_hello(sni: &str) -> Vec<u8> {
    let host = sni.as_bytes();
    let mut sni_ext = Vec::new();
    sni_ext.extend_from_slice(&((3 + host.len()) as u16).to_be_bytes());
    sni_ext.push(0);
    sni_ext.extend_from_slice(&(host.len() as u16).to_be_bytes());
    sni_ext.extend_from_slice(host);
    let mut exts = Vec::new();
    exts.extend_from_slice(&0u16.to_be_bytes());
    exts.extend_from_slice(&(sni_ext.len() as u16).to_be_bytes());
    exts.extend_from_slice(&sni_ext);
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&[0x11; 32]);
    body.push(0);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&[0x13, 0x01]);
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);
    let len = body.len() as u32;
    let mut hs = vec![1, (len >> 16) as u8, (len >> 8) as u8, len as u8];
    hs.extend_from_slice(&body);
    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    record.extend_from_slice(&hs);
    record
}

pub fn http_request(host: &str) -> Vec<u8> {
    format!("GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: sniff-test\r\n\r\n").into_bytes()
}

fn parse_hex(text: &str) -> Vec<Vec<u8>> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            (0..line.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&line[i..i + 2], 16).unwrap())
                .collect()
        })
        .collect()
}

/// curl HTTP/3 首个 Initial，SNI 为 `quic.example.com`。
pub fn quic_curl_initial() -> Vec<Vec<u8>> {
    parse_hex(include_str!("../fixtures/sniff/curl-http3-initial.hex"))
}

/// 新版 Chrome 把 ClientHello 拆进三个 Initial。
pub fn quic_chrome_initials() -> Vec<Vec<u8>> {
    parse_hex(include_str!("../fixtures/sniff/singbox-quic-chrome-new.hex"))
}

pub fn openssh_banner() -> Vec<u8> {
    parse_hex(include_str!("../fixtures/sniff/openssh-client-banner.hex")).remove(0)
}

/// 回显首个连接收到的字节，直到对端关闭。
pub async fn tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                while let Ok(n) = stream.read(&mut buf).await {
                    if n == 0 || stream.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    address
}

pub async fn udp_echo() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
            let _ = socket.send_to(&buf[..n], peer).await;
        }
    });
    address
}

/// 写入负载，返回是否在期限内收到同样的回显。
pub async fn echoes(stream: &mut TcpStream, payload: &[u8]) -> bool {
    if stream.write_all(payload).await.is_err() {
        return false;
    }
    let mut got = vec![0u8; payload.len()];
    matches!(
        timeout(Duration::from_secs(3), stream.read_exact(&mut got)).await,
        Ok(Ok(_))
    ) && got == payload
}

fn socks_address(target: SocketAddr) -> Vec<u8> {
    let mut out = Vec::new();
    match target {
        SocketAddr::V4(v4) => {
            out.push(1);
            out.extend_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            out.push(4);
            out.extend_from_slice(&v6.ip().octets());
        }
    }
    out.extend_from_slice(&target.port().to_be_bytes());
    out
}

fn socks_domain(host: &str, port: u16) -> Vec<u8> {
    let mut out = vec![3, host.len() as u8];
    out.extend_from_slice(host.as_bytes());
    out.extend_from_slice(&port.to_be_bytes());
    out
}

async fn socks_request(proxy: SocketAddr, command: u8, address: Vec<u8>) -> (TcpStream, Vec<u8>) {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut reply = [0u8; 2];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply, [5, 0]);
    let mut request = vec![5, command, 0];
    request.extend_from_slice(&address);
    stream.write_all(&request).await.unwrap();
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await.unwrap();
    let len = match head[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut n = [0u8; 1];
            stream.read_exact(&mut n).await.unwrap();
            n[0] as usize
        }
        other => panic!("未知地址类型 {other}"),
    };
    let mut bound = vec![0u8; len + 2];
    stream.read_exact(&mut bound).await.unwrap();
    let mut addr = vec![head[3]];
    addr.extend_from_slice(&bound);
    (stream, addr)
}

pub async fn socks5_connect(proxy: SocketAddr, target: SocketAddr) -> TcpStream {
    socks_request(proxy, 1, socks_address(target)).await.0
}

pub async fn socks5_connect_domain(proxy: SocketAddr, host: &str, port: u16) -> TcpStream {
    socks_request(proxy, 1, socks_domain(host, port)).await.0
}

pub async fn http_connect(proxy: SocketAddr, target: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream
        .write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await.unwrap();
        head.push(byte[0]);
    }
    assert!(head.starts_with(b"HTTP/1.1 200"), "{}", String::from_utf8_lossy(&head));
    stream
}

/// SOCKS5 UDP ASSOCIATE：依次发送数据报，返回是否收到最后一个的回显。
pub async fn socks5_udp_echoes(proxy: SocketAddr, target: SocketAddr, packets: &[Vec<u8>]) -> bool {
    let (control, bound) = socks_request(proxy, 3, socks_address("0.0.0.0:0".parse().unwrap())).await;
    let relay: SocketAddr = match bound[0] {
        1 => SocketAddr::from((
            [bound[1], bound[2], bound[3], bound[4]],
            u16::from_be_bytes([bound[5], bound[6]]),
        )),
        4 => {
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&bound[1..17]);
            SocketAddr::from((ip, u16::from_be_bytes([bound[17], bound[18]])))
        }
        other => panic!("中继地址类型 {other}"),
    };
    let relay = if relay.ip().is_unspecified() {
        SocketAddr::new(proxy.ip(), relay.port())
    } else {
        relay
    };
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for packet in packets {
        let mut datagram = vec![0, 0, 0];
        datagram.extend_from_slice(&socks_address(target));
        datagram.extend_from_slice(packet);
        socket.send_to(&datagram, relay).await.unwrap();
    }
    let header = 3 + socks_address(target).len();
    let mut buf = vec![0u8; 65536];
    let expected = packets.last().unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        match tokio::time::timeout_at(deadline, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, _))) if n >= header && &buf[header..n] == expected.as_slice() => {
                drop(control);
                return true;
            }
            Ok(Ok(_)) => continue,
            _ => {
                drop(control);
                return false;
            }
        }
    }
}
