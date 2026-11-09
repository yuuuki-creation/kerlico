//! Transport peer addresses from PROXY headers and trusted HTTP metadata.

use std::io::{self, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

const V1: &[u8] = b"PROXY ";
const V2: &[u8] = b"\r\n\r\n\0\r\nQUIT\n";

#[derive(Clone, Debug, Default, serde::Deserialize)]
#[serde(try_from = "Vec<String>")]
pub struct TrustedForwardedFor {
    headers: Vec<String>,
}

impl TrustedForwardedFor {
    pub fn from_sockopt(sockopt: Option<&str>) -> io::Result<Self> {
        crate::socket::SocketOptions::parse(sockopt).map(|options| options.trusted_forwarded_for)
    }

    pub fn peer<T: AsRef<str>>(&self, peer: SocketAddr, header: impl Fn(&str) -> Option<T>) -> SocketAddr {
        let Some(forwarded) = header("x-forwarded-for") else { return peer };
        if !self.headers.iter().any(|name| header(name).is_some()) {
            return peer;
        }
        let first = forwarded.as_ref().split(',').next().unwrap_or_default().trim();
        let first = first.strip_prefix('[').and_then(|address| address.strip_suffix(']')).unwrap_or(first);
        let Ok(ip) = first.parse::<IpAddr>() else { return peer };
        SocketAddr::new(ip.to_canonical(), 0)
    }
}

impl TryFrom<Vec<String>> for TrustedForwardedFor {
    type Error = ::http::header::InvalidHeaderName;

    fn try_from(headers: Vec<String>) -> Result<Self, Self::Error> {
        let headers = headers
            .into_iter()
            .map(|header| {
                ::http::HeaderName::from_bytes(header.as_bytes()).map(|name| name.as_str().to_owned())
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { headers })
    }
}

pub fn accept_proxy(socket: &mut TcpStream, peer: SocketAddr, local: Option<SocketAddr>) -> io::Result<(SocketAddr, Option<SocketAddr>)> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut prefix = [0; 12];
    let version = loop {
        let n = socket.peek(&mut prefix)?;
        if n == 0 { return Err(io::ErrorKind::UnexpectedEof.into()); }
        if n >= V1.len() && prefix[..V1.len()] == *V1 { break 1; }
        if n == V2.len() && prefix == V2 { break 2; }
        if !V1.starts_with(&prefix[..n]) && !V2.starts_with(&prefix[..n]) { return Ok((peer, local)); }
        if Instant::now() >= deadline { return Err(io::ErrorKind::TimedOut.into()); }
        std::thread::sleep(Duration::from_millis(1));
    };
    if version == 1 {
        let mut line = Vec::new();
        while line.len() < 108 {
            let mut byte = [0];
            socket.read_exact(&mut byte)?;
            line.push(byte[0]);
            if line.ends_with(b"\r\n") { break; }
        }
        if !line.ends_with(b"\r\n") { return Err(invalid()); }
        let fields: Vec<_> = std::str::from_utf8(&line).map_err(|_| invalid())?.split_whitespace().collect();
        if fields.get(1) == Some(&"UNKNOWN") { return Ok((peer, local)); }
        if fields.len() != 6 { return Err(invalid()); }
        let source: IpAddr = fields[2].parse().map_err(|_| invalid())?;
        let destination: IpAddr = fields[3].parse().map_err(|_| invalid())?;
        if !matches!((fields[1], source, destination), ("TCP4", IpAddr::V4(_), IpAddr::V4(_)) | ("TCP6", IpAddr::V6(_), IpAddr::V6(_))) { return Err(invalid()); }
        return Ok((SocketAddr::new(source, fields[4].parse().map_err(|_| invalid())?), Some(SocketAddr::new(destination, fields[5].parse().map_err(|_| invalid())?))));
    }
    let mut head = [0; 16];
    socket.read_exact(&mut head)?;
    let mut address = vec![0; u16::from_be_bytes([head[14], head[15]]) as usize];
    socket.read_exact(&mut address)?;
    if head[12] == 0x20 { return Ok((peer, local)); }
    if head[12] != 0x21 { return Err(invalid()); }
    match head[13] {
        0 => Ok((peer, local)),
        0x11 if address.len() >= 12 => {
            let source = Ipv4Addr::new(address[0], address[1], address[2], address[3]);
            let destination = Ipv4Addr::new(address[4], address[5], address[6], address[7]);
            Ok((SocketAddr::new(source.into(), u16::from_be_bytes([address[8], address[9]])), Some(SocketAddr::new(destination.into(), u16::from_be_bytes([address[10], address[11]])))))
        }
        0x21 if address.len() >= 36 => {
            let source = Ipv6Addr::from(<[u8;16]>::try_from(&address[..16]).unwrap());
            let destination = Ipv6Addr::from(<[u8;16]>::try_from(&address[16..32]).unwrap());
            Ok((SocketAddr::new(source.into(), u16::from_be_bytes([address[32], address[33]])), Some(SocketAddr::new(destination.into(), u16::from_be_bytes([address[34], address[35]])))))
        }
        _ => Err(invalid()),
    }
}

fn invalid() -> io::Error { io::Error::new(io::ErrorKind::InvalidData, "PROXY protocol header") }

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::TcpListener;

    #[test]
    fn forwarded_address_requires_a_marker_and_an_ip() {
        let peer = "127.0.0.1:32123".parse().unwrap();
        let policy = TrustedForwardedFor::from_sockopt(Some(r#"{"trustedXForwardedFor":["X-Trusted-CDN"]}"#)).unwrap();
        let forwarded = |value, marker| policy.peer(peer, |name| match name {
            "x-forwarded-for" => Some(value),
            "x-trusted-cdn" => marker,
            _ => None,
        });
        assert_eq!(forwarded("203.0.113.8", None), peer);
        assert_eq!(forwarded("hostname, 203.0.113.8", Some("1")), peer);
        assert_eq!(forwarded(" [2001:db8::1], 203.0.113.8", Some("")), "[2001:db8::1]:0".parse().unwrap());
        assert_eq!(forwarded("::ffff:203.0.113.8", Some("1")), "203.0.113.8:0".parse().unwrap());
    }

    #[test]
    fn consumes_only_the_proxy_header() {
        let mut v2 = V2.to_vec();
        v2.extend_from_slice(&[0x21, 0x11, 0, 15, 203,0,113,1, 192,0,2,1, 0x04,0xd2, 0x01,0xbb, 1,0,0]);
        for header in [b"PROXY TCP4 203.0.113.1 192.0.2.1 1234 443\r\n".to_vec(), v2] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (mut server, peer) = listener.accept().unwrap();
            client.write_all(&header).unwrap();
            client.write_all(b"payload").unwrap();
            let (source, destination) = accept_proxy(&mut server, peer, None).unwrap();
            assert_eq!(source, "203.0.113.1:1234".parse().unwrap());
            assert_eq!(destination, Some("192.0.2.1:443".parse().unwrap()));
            let mut payload = [0; 7];
            server.read_exact(&mut payload).unwrap();
            assert_eq!(&payload, b"payload");
        }
    }
}
