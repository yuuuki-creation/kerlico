//! sing-mux 线格式：会话请求、流请求与响应、SOCKS 地址和 Brutal 带宽交换。

use super::SingMuxProtocol;
use kerlico_core::{Address, Destination, Error, Result};
use rand::{Rng, RngCore};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncRead, AsyncReadExt};

pub(super) const BRUTAL_EXCHANGE_DOMAIN: &str = "_BrutalBwExchange";
pub(super) const BRUTAL_DISABLED_MESSAGE: &str = "brutal is not enabled by the server";
pub(super) const STATUS_SUCCESS: u8 = 0;
const STATUS_ERROR: u8 = 1;
const FLAG_UDP: u16 = 1;
const FLAG_ADDR: u16 = 2;

fn malformed() -> Error {
    Error::Protocol("sing-mux 帧或地址格式不合法")
}

/// 载体上的首个会话请求；`padding` 为真时使用版本 1 并附带随机填充。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct SessionRequest {
    pub protocol: SingMuxProtocol,
    pub padding: bool,
}

impl SessionRequest {
    pub fn encode(&self) -> Vec<u8> {
        if !self.padding {
            return vec![0, self.protocol.code()];
        }
        let pad_len = rand::thread_rng().gen_range(256usize..768);
        let mut out = Vec::with_capacity(5 + pad_len);
        out.extend_from_slice(&[1, self.protocol.code(), 1]);
        out.extend_from_slice(&(pad_len as u16).to_be_bytes());
        let start = out.len();
        out.resize(start + pad_len, 0);
        rand::thread_rng().fill_bytes(&mut out[start..]);
        out
    }

    pub async fn read(reader: &mut (impl AsyncRead + Unpin)) -> Result<Self> {
        let version = reader.read_u8().await?;
        if version > 1 {
            return Err(Error::Protocol("不支持的 sing-mux 会话版本"));
        }
        let protocol = SingMuxProtocol::from_code(reader.read_u8().await?)?;
        let mut padding = false;
        if version == 1 {
            padding = reader.read_u8().await? != 0;
            if padding {
                let len = u64::from(reader.read_u16().await?);
                let skipped =
                    tokio::io::copy(&mut (&mut *reader).take(len), &mut tokio::io::sink()).await?;
                if skipped != len {
                    return Err(malformed());
                }
            }
        }
        Ok(Self { protocol, padding })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Host {
    Ip(IpAddr),
    Domain(String),
}

/// SOCKS5 地址加端口；端口可为 0，Brutal 交换与占位目标依赖这一点。
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SocksAddr {
    pub host: Host,
    pub port: u16,
}

impl SocksAddr {
    pub fn from_destination(target: &Destination) -> Self {
        let host = match target.address() {
            Address::Ip(ip) => Host::Ip(*ip),
            Address::Domain(name) => Host::Domain(name.clone()),
        };
        Self {
            host,
            port: target.port(),
        }
    }

    pub fn domain(name: &str, port: u16) -> Self {
        Self {
            host: Host::Domain(name.to_owned()),
            port,
        }
    }

    pub fn to_destination(&self) -> Result<Destination> {
        let host = match &self.host {
            Host::Ip(ip) => ip.to_string(),
            Host::Domain(name) => name.clone(),
        };
        Destination::new(&host, self.port).map_err(|_| malformed())
    }

    pub fn is_domain(&self, name: &str) -> bool {
        matches!(&self.host, Host::Domain(d) if d.eq_ignore_ascii_case(name))
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<()> {
        match &self.host {
            Host::Ip(IpAddr::V4(ip)) => {
                out.push(1);
                out.extend_from_slice(&ip.octets());
            }
            Host::Ip(IpAddr::V6(ip)) => {
                out.push(4);
                out.extend_from_slice(&ip.octets());
            }
            Host::Domain(name) => {
                out.push(3);
                out.push(u8::try_from(name.len()).map_err(|_| malformed())?);
                out.extend_from_slice(name.as_bytes());
            }
        }
        out.extend_from_slice(&self.port.to_be_bytes());
        Ok(())
    }

    pub async fn read(reader: &mut (impl AsyncRead + Unpin)) -> Result<Self> {
        let family = reader.read_u8().await?;
        Self::read_with_family(family, reader).await
    }

    pub async fn read_with_family(
        family: u8,
        reader: &mut (impl AsyncRead + Unpin),
    ) -> Result<Self> {
        let host = match family {
            1 => {
                let mut b = [0; 4];
                reader.read_exact(&mut b).await?;
                Host::Ip(IpAddr::V4(Ipv4Addr::from(b)))
            }
            4 => {
                let mut b = [0; 16];
                reader.read_exact(&mut b).await?;
                Host::Ip(IpAddr::V6(Ipv6Addr::from(b)).to_canonical())
            }
            3 => {
                let len = usize::from(reader.read_u8().await?);
                let mut b = vec![0; len];
                reader.read_exact(&mut b).await?;
                Host::Domain(String::from_utf8(b).map_err(|_| malformed())?)
            }
            _ => return Err(malformed()),
        };
        let port = reader.read_u16().await?;
        Ok(Self { host, port })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum StreamKind {
    Tcp,
    /// 固定目标 UDP：每包 `u16` 长度加负载。
    Udp,
    /// 每包携带地址的 UDP：SOCKS 地址、`u16` 长度加负载。
    UdpPacketAddr,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct StreamRequest {
    pub kind: StreamKind,
    pub addr: SocksAddr,
}

impl StreamRequest {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let flags = match self.kind {
            StreamKind::Tcp => 0,
            StreamKind::Udp => FLAG_UDP,
            StreamKind::UdpPacketAddr => FLAG_UDP | FLAG_ADDR,
        };
        let mut out = Vec::with_capacity(264);
        out.extend_from_slice(&flags.to_be_bytes());
        self.addr.encode_into(&mut out)?;
        Ok(out)
    }

    pub async fn read(reader: &mut (impl AsyncRead + Unpin)) -> Result<Self> {
        let flags = reader.read_u16().await?;
        let addr = SocksAddr::read(reader).await?;
        let kind = match (flags & FLAG_UDP != 0, flags & FLAG_ADDR != 0) {
            (false, _) => StreamKind::Tcp,
            (true, false) => StreamKind::Udp,
            (true, true) => StreamKind::UdpPacketAddr,
        };
        Ok(Self { kind, addr })
    }
}

fn put_uvarint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn put_vstring(out: &mut Vec<u8>, text: &str) {
    put_uvarint(out, text.len() as u64);
    out.extend_from_slice(text.as_bytes());
}

pub(super) async fn read_uvarint(reader: &mut (impl AsyncRead + Unpin)) -> Result<u64> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let byte = reader.read_u8().await?;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(malformed())
}

async fn read_vstring(reader: &mut (impl AsyncRead + Unpin)) -> Result<String> {
    let len = read_uvarint(reader).await?;
    if len > 4096 {
        return Err(malformed());
    }
    let mut b = vec![0; len as usize];
    reader.read_exact(&mut b).await?;
    Ok(String::from_utf8_lossy(&b).into_owned())
}

/// 流失败响应：状态 1 加 uvarint 长度的错误文本。
pub(super) fn encode_error_status(message: &str) -> Vec<u8> {
    let mut out = vec![STATUS_ERROR];
    put_vstring(&mut out, message);
    out
}

pub(super) fn encode_brutal_response(receive_bps: Option<u64>, message: &str) -> Vec<u8> {
    match receive_bps {
        Some(bps) => {
            let mut out = vec![1];
            out.extend_from_slice(&bps.to_be_bytes());
            out
        }
        None => {
            let mut out = vec![0];
            put_vstring(&mut out, message);
            out
        }
    }
}

pub(super) async fn read_brutal_response(reader: &mut (impl AsyncRead + Unpin)) -> Result<u64> {
    if reader.read_u8().await? != 0 {
        return Ok(reader.read_u64().await?);
    }
    let message = read_vstring(reader).await?;
    Err(Error::Config(format!(
        "sing-mux Brutal 交换被远端拒绝：{message}"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn session_request_round_trips_with_and_without_padding() {
        for padding in [false, true] {
            let request = SessionRequest {
                protocol: SingMuxProtocol::Yamux,
                padding,
            };
            let bytes = request.encode();
            assert_eq!(bytes[0], u8::from(padding));
            assert_eq!(bytes[1], 1);
            if padding {
                let len = usize::from(u16::from_be_bytes([bytes[3], bytes[4]]));
                assert!((256..768).contains(&len));
                assert_eq!(bytes.len(), 5 + len);
            } else {
                assert_eq!(bytes.len(), 2);
            }
            let mut reader = &bytes[..];
            assert_eq!(SessionRequest::read(&mut reader).await.unwrap(), request);
            assert!(reader.is_empty());
        }
    }

    #[tokio::test]
    async fn stream_request_uses_socks_address_and_flags() {
        let request = StreamRequest {
            kind: StreamKind::UdpPacketAddr,
            addr: SocksAddr::domain("sp.mux.sing-box.arpa", 444),
        };
        let bytes = request.encode().unwrap();
        assert_eq!(&bytes[..4], &[0, 3, 3, 20]);
        assert_eq!(&bytes[bytes.len() - 2..], &444u16.to_be_bytes());
        assert_eq!(StreamRequest::read(&mut &bytes[..]).await.unwrap(), request);

        let brutal = StreamRequest {
            kind: StreamKind::Tcp,
            addr: SocksAddr::domain(BRUTAL_EXCHANGE_DOMAIN, 0),
        };
        let parsed = StreamRequest::read(&mut &brutal.encode().unwrap()[..])
            .await
            .unwrap();
        assert!(parsed.addr.is_domain(BRUTAL_EXCHANGE_DOMAIN));
    }

    #[tokio::test]
    async fn error_status_and_brutal_response_use_uvarint_strings() {
        let message = "x".repeat(200);
        let bytes = encode_error_status(&message);
        assert_eq!(&bytes[..3], &[1, 0xc8, 0x01]);
        let mut reader = &bytes[1..];
        assert_eq!(read_vstring(&mut reader).await.unwrap(), message);

        let ok = encode_brutal_response(Some(125_000), "");
        assert_eq!(read_brutal_response(&mut &ok[..]).await.unwrap(), 125_000);
        let refused = encode_brutal_response(None, BRUTAL_DISABLED_MESSAGE);
        assert!(read_brutal_response(&mut &refused[..]).await.is_err());
    }
}
