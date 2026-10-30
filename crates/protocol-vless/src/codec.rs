//! 头部和数据报编解码；长度均来自单字节或 u16 字段，不吞掉后续负载。

use crate::UserId;
use kerlico_core::{Address, Destination, Error, Result};
use prost::Message;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const VERSION: u8 = 0;
pub const MAX_DATAGRAM_SIZE: usize = u16::MAX as usize;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Tcp,
    Udp,
}

#[derive(Clone, Debug)]
pub struct RequestHeader {
    pub user: UserId,
    pub command: Command,
    pub target: Destination,
}

#[derive(Clone, PartialEq, Message)]
struct WireAddons {
    #[prost(string, tag = "1")]
    flow: String,
    #[prost(bytes = "vec", tag = "2")]
    seed: Vec<u8>,
}

pub(crate) fn validate_addons(bytes: &[u8]) -> Result<()> {
    let addons =
        WireAddons::decode(bytes).map_err(|_| Error::Protocol("VLESS 附加信息格式不合法"))?;
    if !addons.flow.is_empty() {
        return Err(Error::Unsupported("VLESS flow"));
    }
    Ok(())
}

pub async fn write_request<W: AsyncWrite + Unpin + ?Sized>(
    writer: &mut W,
    request: &RequestHeader,
) -> Result<()> {
    let mut bytes = Vec::with_capacity(64);
    bytes.push(VERSION);
    bytes.extend_from_slice(request.user.as_bytes());
    bytes.push(0);
    bytes.push(match request.command {
        Command::Tcp => 1,
        Command::Udp => 2,
    });
    bytes.extend_from_slice(&request.target.port().to_be_bytes());
    match request.target.address() {
        Address::Ip(IpAddr::V4(ip)) => {
            bytes.push(1);
            bytes.extend_from_slice(&ip.octets());
        }
        Address::Domain(name) => {
            let length = u8::try_from(name.len()).map_err(|_| Error::InvalidAddress)?;
            bytes.push(2);
            bytes.push(length);
            bytes.extend_from_slice(name.as_bytes());
        }
        Address::Ip(IpAddr::V6(ip)) => {
            bytes.push(3);
            bytes.extend_from_slice(&ip.octets());
        }
    }
    writer.write_all(&bytes).await?;
    Ok(())
}

/// 只解析请求，不做用户认证；调用方必须用 UserId::matches 验证。
pub async fn read_request<R: AsyncRead + Unpin + ?Sized>(reader: &mut R) -> Result<RequestHeader> {
    if reader.read_u8().await? != VERSION {
        return Err(Error::Protocol("VLESS 版本不支持"));
    }
    let mut user = [0; 16];
    reader.read_exact(&mut user).await?;
    let length = reader.read_u8().await? as usize;
    let mut addons = vec![0; length];
    reader.read_exact(&mut addons).await?;
    validate_addons(&addons)?;
    let command = match reader.read_u8().await? {
        1 => Command::Tcp,
        2 => Command::Udp,
        _ => return Err(Error::Unsupported("VLESS 指令")),
    };
    let port = reader.read_u16().await?;
    let host = match reader.read_u8().await? {
        1 => {
            let mut bytes = [0; 4];
            reader.read_exact(&mut bytes).await?;
            Ipv4Addr::from(bytes).to_string()
        }
        2 => {
            let length = reader.read_u8().await? as usize;
            let mut bytes = vec![0; length];
            reader.read_exact(&mut bytes).await?;
            String::from_utf8(bytes).map_err(|_| Error::InvalidAddress)?
        }
        3 => {
            let mut bytes = [0; 16];
            reader.read_exact(&mut bytes).await?;
            Ipv6Addr::from(bytes).to_string()
        }
        _ => return Err(Error::Protocol("VLESS 地址类型不支持")),
    };
    Ok(RequestHeader {
        user: UserId::from_bytes(user),
        command,
        target: Destination::new(&host, port)?,
    })
}

pub async fn write_response<W: AsyncWrite + Unpin + ?Sized>(writer: &mut W) -> Result<()> {
    writer.write_all(&[VERSION, 0]).await?;
    Ok(())
}

pub async fn read_response<R: AsyncRead + Unpin + ?Sized>(reader: &mut R) -> Result<()> {
    if reader.read_u8().await? != VERSION {
        return Err(Error::Protocol("VLESS 响应版本不匹配"));
    }
    let length = reader.read_u8().await? as usize;
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes).await?;
    validate_addons(&bytes)
}

pub async fn write_datagram<W: AsyncWrite + Unpin + ?Sized>(
    writer: &mut W,
    packet: &[u8],
) -> Result<()> {
    let length = u16::try_from(packet.len()).map_err(|_| Error::ResourceLimit)?;
    writer.write_all(&length.to_be_bytes()).await?;
    writer.write_all(packet).await?;
    writer.flush().await?;
    Ok(())
}

/// 前缀开始前的 EOF 返回 None，截断前缀/负载返回错误；保留零长度包。
pub async fn read_datagram<R: AsyncRead + Unpin + ?Sized>(
    reader: &mut R,
    maximum: usize,
) -> Result<Option<Vec<u8>>> {
    let mut prefix = [0; 1];
    if reader.read(&mut prefix).await? == 0 {
        return Ok(None);
    }
    let first = prefix[0];
    let second = reader.read_u8().await?;
    let length = u16::from_be_bytes([first, second]) as usize;
    if length > maximum {
        return Err(Error::ResourceLimit);
    }
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes).await?;
    Ok(Some(bytes))
}
