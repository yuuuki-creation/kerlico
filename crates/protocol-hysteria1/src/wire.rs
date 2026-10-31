//! v1 家族专用的大端协议字段，不复用 Hysteria2 的 HTTP/3 或变长整数请求。
use crate::protocol;
use kerlico_core::{Destination, Error, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
pub(crate) const MAX_PACKET: usize = 65507;
const MAX_TEXT: usize = 4096;
#[derive(Clone)]
pub(crate) struct Hello {
    pub up: u64,
    pub down: u64,
    pub auth: Vec<u8>,
}
pub(crate) async fn write_hello<W: AsyncWrite + Unpin>(
    writer: &mut W,
    up: u64,
    down: u64,
    auth: &[u8],
) -> Result<()> {
    if auth.is_empty() || auth.len() > MAX_TEXT || up == 0 || down == 0 {
        return Err(protocol());
    }
    let mut bytes = vec![3];
    bytes.extend_from_slice(&up.to_be_bytes());
    bytes.extend_from_slice(&down.to_be_bytes());
    bytes.extend_from_slice(&(auth.len() as u16).to_be_bytes());
    bytes.extend_from_slice(auth);
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}
pub(crate) async fn read_hello<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Hello> {
    if reader.read_u8().await? != 3 {
        return Err(protocol());
    }
    let up = reader.read_u64().await?;
    let down = reader.read_u64().await?;
    if up == 0 || down == 0 || up > 1_000_000_000_000 || down > 1_000_000_000_000 {
        return Err(protocol());
    }
    let len = reader.read_u16().await? as usize;
    if len == 0 || len > MAX_TEXT {
        return Err(protocol());
    }
    let mut auth = vec![0; len];
    reader.read_exact(&mut auth).await?;
    Ok(Hello { up, down, auth })
}
async fn text<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Vec<u8>> {
    let len = reader.read_u16().await? as usize;
    if len > MAX_TEXT {
        return Err(protocol());
    }
    let mut out = vec![0; len];
    reader.read_exact(&mut out).await?;
    Ok(out)
}
async fn boolean<R: AsyncRead + Unpin>(reader: &mut R) -> Result<bool> {
    match reader.read_u8().await? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(protocol()),
    }
}
pub(crate) async fn write_server_hello<W: AsyncWrite + Unpin>(
    writer: &mut W,
    ok: bool,
    send: u64,
    receive: u64,
) -> Result<()> {
    let mut bytes = vec![u8::from(ok)];
    bytes.extend_from_slice(&send.to_be_bytes());
    bytes.extend_from_slice(&receive.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}
pub(crate) async fn read_server_hello<R: AsyncRead + Unpin>(reader: &mut R) -> Result<(u64, u64)> {
    let ok = boolean(reader).await?;
    let send = reader.read_u64().await?;
    let receive = reader.read_u64().await?;
    let _message = text(reader).await?;
    if !ok {
        return Err(Error::Rejected);
    }
    if send == 0 || receive == 0 {
        return Err(protocol());
    }
    Ok((send, receive))
}
pub(crate) fn rates(up: u64, down: u64, peer: &Hello) -> (u64, u64) {
    (
        if up == 0 {
            peer.down
        } else {
            up.min(peer.down)
        },
        if down == 0 {
            peer.up
        } else {
            down.min(peer.up)
        },
    )
}
pub(crate) async fn write_request<W: AsyncWrite + Unpin>(
    writer: &mut W,
    udp: bool,
    target: Option<&Destination>,
) -> Result<()> {
    if !udp && target.is_none() {
        return Err(protocol());
    }
    let host = target.map_or_else(String::new, Destination::host);
    let port = target.map_or(0, Destination::port);
    let mut bytes = vec![u8::from(udp)];
    bytes.extend_from_slice(&(host.len() as u16).to_be_bytes());
    bytes.extend_from_slice(host.as_bytes());
    bytes.extend_from_slice(&port.to_be_bytes());
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}
pub(crate) async fn read_request<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<(bool, Option<Destination>)> {
    let udp = boolean(reader).await?;
    let len = reader.read_u16().await? as usize;
    if len > 255 {
        return Err(protocol());
    }
    let mut host = vec![0; len];
    reader.read_exact(&mut host).await?;
    let port = reader.read_u16().await?;
    if udp && len == 0 && port == 0 {
        return Ok((true, None));
    }
    let host = std::str::from_utf8(&host).map_err(|_| protocol())?;
    Ok((
        udp,
        Some(Destination::new(host, port).map_err(|_| protocol())?),
    ))
}
pub(crate) async fn write_response<W: AsyncWrite + Unpin>(
    writer: &mut W,
    ok: bool,
    id: u32,
) -> Result<()> {
    let mut bytes = vec![u8::from(ok)];
    bytes.extend_from_slice(&id.to_be_bytes());
    bytes.extend_from_slice(&0u16.to_be_bytes());
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}
pub(crate) async fn read_response<R: AsyncRead + Unpin>(reader: &mut R) -> Result<u32> {
    let ok = boolean(reader).await?;
    let id = reader.read_u32().await?;
    let _message = text(reader).await?;
    if ok { Ok(id) } else { Err(Error::Rejected) }
}
#[derive(Clone)]
pub(crate) struct Packet {
    pub session: u32,
    pub target: Destination,
    pub message: u16,
    pub index: u8,
    pub count: u8,
    pub data: Vec<u8>,
}
impl Packet {
    pub fn header_len(&self) -> usize {
        14 + self.target.host().len()
    }
    pub fn encode(&self) -> Vec<u8> {
        let host = self.target.host();
        let mut out = Vec::with_capacity(self.header_len() + self.data.len());
        out.extend_from_slice(&self.session.to_be_bytes());
        out.extend_from_slice(&(host.len() as u16).to_be_bytes());
        out.extend_from_slice(host.as_bytes());
        out.extend_from_slice(&self.target.port().to_be_bytes());
        out.extend_from_slice(&self.message.to_be_bytes());
        out.push(self.index);
        out.push(self.count);
        out.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.data);
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 14 {
            return Err(protocol());
        }
        let session = u32::from_be_bytes(bytes[..4].try_into().map_err(|_| protocol())?);
        let hostlen = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
        if hostlen == 0 || hostlen > 255 || bytes.len() < 14 + hostlen {
            return Err(protocol());
        }
        let host = std::str::from_utf8(&bytes[6..6 + hostlen]).map_err(|_| protocol())?;
        let at = 6 + hostlen;
        let port = u16::from_be_bytes([bytes[at], bytes[at + 1]]);
        let target = Destination::new(host, port).map_err(|_| protocol())?;
        let message = u16::from_be_bytes([bytes[at + 2], bytes[at + 3]]);
        let index = bytes[at + 4];
        let count = bytes[at + 5];
        let length = u16::from_be_bytes([bytes[at + 6], bytes[at + 7]]) as usize;
        if length > MAX_PACKET
            || bytes.len() != at + 8 + length
            || count == 0
            || (count > 1 && (index >= count || message == 0))
        {
            return Err(protocol());
        }
        Ok(Self {
            session,
            target,
            message,
            index,
            count,
            data: bytes[at + 8..].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn v1_control_and_requests_have_exact_big_endian_fields() {
        let mut bytes = Vec::new();
        write_hello(&mut bytes, 1, 2, &[0, 255]).await.unwrap();
        assert_eq!(&bytes[..3], &[3, 0, 0]);
        assert_eq!(&bytes[1..9], &1u64.to_be_bytes());
        assert_eq!(&bytes[9..17], &2u64.to_be_bytes());
        assert_eq!(&bytes[17..], &[0, 2, 0, 255]);
        let hello = read_hello(&mut bytes.as_slice()).await.unwrap();
        assert_eq!((hello.up, hello.down, hello.auth), (1, 2, vec![0, 255]));
        for host in ["127.0.0.1", "::1", "example.invalid"] {
            let target = Destination::new(host, 443).unwrap();
            let mut bytes = Vec::new();
            write_request(&mut bytes, false, Some(&target))
                .await
                .unwrap();
            bytes.extend_from_slice(b"tail");
            let mut input = bytes.as_slice();
            assert_eq!(
                read_request(&mut input).await.unwrap(),
                (false, Some(target))
            );
            assert_eq!(input, b"tail");
        }
        let mut bytes = Vec::new();
        write_request(&mut bytes, true, None).await.unwrap();
        assert_eq!(bytes, vec![1, 0, 0, 0, 0]);
        assert_eq!(
            read_request(&mut bytes.as_slice()).await.unwrap(),
            (true, None)
        );
        let mut bytes = Vec::new();
        write_response(&mut bytes, true, 0x01020304).await.unwrap();
        assert_eq!(bytes, vec![1, 1, 2, 3, 4, 0, 0]);
        assert_eq!(
            read_response(&mut bytes.as_slice()).await.unwrap(),
            0x01020304
        );
    }
    #[test]
    fn datagram_header_and_zero_payload_are_preserved() {
        let packet = Packet {
            session: 0x01020304,
            target: Destination::new("127.0.0.1", 53).unwrap(),
            message: 0x1112,
            index: 1,
            count: 2,
            data: vec![0, 255],
        };
        let bytes = packet.encode();
        assert_eq!(&bytes[..6], &[1, 2, 3, 4, 0, 9]);
        assert_eq!(&bytes[15..], &[0, 53, 0x11, 0x12, 1, 2, 0, 2, 0, 255]);
        let parsed = Packet::decode(&bytes).unwrap();
        assert_eq!(parsed.data, packet.data);
        assert_eq!(parsed.target, packet.target);
        let empty = Packet {
            count: 1,
            index: 255,
            message: 0,
            data: Vec::new(),
            ..packet
        };
        assert!(Packet::decode(&empty.encode()).unwrap().data.is_empty());
        for len in 0..bytes.len() {
            assert!(Packet::decode(&bytes[..len]).is_err());
        }
    }
    #[tokio::test]
    async fn invalid_control_response_and_bandwidth_are_rejected() {
        let mut bytes = Vec::new();
        write_hello(&mut bytes, 1, 2, b"test").await.unwrap();
        bytes[0] = 4;
        assert!(read_hello(&mut bytes.as_slice()).await.is_err());
        bytes[0] = 3;
        bytes[1..9].fill(0);
        assert!(read_hello(&mut bytes.as_slice()).await.is_err());
        assert!(write_request(&mut Vec::new(), false, None).await.is_err());
        assert!(
            read_response(&mut [2, 0, 0, 0, 0, 0, 0].as_slice())
                .await
                .is_err()
        );
        assert_eq!(
            rates(
                200,
                400,
                &Hello {
                    up: 800,
                    down: 100,
                    auth: vec![]
                }
            ),
            (100, 400)
        );
        assert_eq!(
            rates(
                0,
                0,
                &Hello {
                    up: 800,
                    down: 100,
                    auth: vec![]
                }
            ),
            (100, 800)
        );
    }
}
