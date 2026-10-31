//! 按精确边界读取头部，保留后续业务数据。

use crate::protocol;
use kerlico_core::{Address, Destination, Error, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(crate) fn address(target: &Destination) -> Vec<u8> {
    let mut out = Vec::with_capacity(260);
    match target.address() {
        Address::Ip(IpAddr::V4(ip)) => {
            out.push(1);
            out.extend_from_slice(&ip.octets());
        }
        Address::Ip(IpAddr::V6(ip)) => {
            out.push(4);
            out.extend_from_slice(&ip.octets());
        }
        Address::Domain(name) => {
            out.push(3);
            out.push(name.len() as u8);
            out.extend_from_slice(name.as_bytes());
        }
    }
    out.extend_from_slice(&target.port().to_be_bytes());
    out
}
pub(crate) async fn read_address<R: AsyncRead + Unpin>(
    reader: &mut R,
    first: u8,
) -> Result<Destination> {
    let host = match first {
        1 => {
            let mut bytes = [0; 4];
            reader.read_exact(&mut bytes).await?;
            Ipv4Addr::from(bytes).to_string()
        }
        4 => {
            let mut bytes = [0; 16];
            reader.read_exact(&mut bytes).await?;
            Ipv6Addr::from(bytes).to_string()
        }
        3 => {
            let len = reader.read_u8().await? as usize;
            if len == 0 {
                return Err(protocol());
            }
            let mut bytes = vec![0; len];
            reader.read_exact(&mut bytes).await?;
            String::from_utf8(bytes).map_err(|_| protocol())?
        }
        _ => return Err(protocol()),
    };
    let port = reader.read_u16().await?;
    Destination::new(&host, port).map_err(|_| protocol())
}
pub(crate) async fn crlf<R: AsyncRead + Unpin>(reader: &mut R) -> Result<()> {
    let mut value = [0; 2];
    reader.read_exact(&mut value).await?;
    if value != *b"\r\n" {
        return Err(protocol());
    }
    Ok(())
}
pub(crate) async fn write_request<W: AsyncWrite + Unpin>(
    writer: &mut W,
    key: &[u8; 56],
    target: &Destination,
    udp: bool,
) -> Result<()> {
    let mut value = Vec::with_capacity(320);
    value.extend_from_slice(key);
    value.extend_from_slice(b"\r\n");
    value.push(if udp { 3 } else { 1 });
    value.extend_from_slice(&address(target));
    value.extend_from_slice(b"\r\n");
    writer.write_all(&value).await?;
    writer.flush().await?;
    Ok(())
}
pub(crate) async fn request<R: AsyncRead + Unpin>(
    reader: &mut R,
    users: &[[u8; 56]],
) -> Result<(Destination, bool)> {
    use subtle::ConstantTimeEq;
    let mut key = [0; 56];
    reader.read_exact(&mut key).await?;
    let mut valid = subtle::Choice::from(0);
    for user in users {
        valid |= user.ct_eq(&key);
    }
    if !bool::from(valid) {
        return Err(protocol());
    }
    crlf(reader).await?;
    let udp = match reader.read_u8().await? {
        1 => false,
        3 => true,
        _ => return Err(protocol()),
    };
    let kind = reader.read_u8().await?;
    let target = read_address(reader, kind).await?;
    crlf(reader).await?;
    Ok((target, udp))
}
pub(crate) async fn packet<R: AsyncRead + Unpin>(
    reader: &mut R,
    maximum: usize,
) -> Result<Option<(Destination, Vec<u8>)>> {
    let mut kind = [0];
    if reader.read(&mut kind).await? == 0 {
        return Ok(None);
    }
    let target = read_address(reader, kind[0]).await?;
    let len = reader.read_u16().await? as usize;
    if len > maximum {
        return Err(Error::ResourceLimit);
    }
    crlf(reader).await?;
    let mut value = vec![0; len];
    reader.read_exact(&mut value).await?;
    Ok(Some((target, value)))
}
pub(crate) async fn write_packet<W: AsyncWrite + Unpin>(
    writer: &mut W,
    target: &Destination,
    payload: &[u8],
    maximum: usize,
) -> Result<()> {
    if payload.len() > maximum.min(u16::MAX as usize) {
        return Err(Error::ResourceLimit);
    }
    let mut frame = address(target);
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(b"\r\n");
    frame.extend_from_slice(payload);
    writer.write_all(&frame).await?;
    writer.flush().await?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn request_and_udp_exact_boundaries() {
        let key = crate::key("test-only-password").unwrap();
        for host in ["127.0.0.1", "::1", "example.invalid"] {
            let target = Destination::new(host, 53).unwrap();
            let mut bytes = Vec::new();
            write_request(&mut bytes, &key, &target, true)
                .await
                .unwrap();
            bytes.extend_from_slice(b"tail");
            let mut input = bytes.as_slice();
            assert_eq!(
                request(&mut input, &[key]).await.unwrap(),
                (target.clone(), true)
            );
            assert_eq!(input, b"tail");
            for payload in [Vec::new(), vec![37; 8192], vec![19; 65535]] {
                let mut wire = Vec::new();
                write_packet(&mut wire, &target, &payload, 65535)
                    .await
                    .unwrap();
                let mut input = wire.as_slice();
                assert_eq!(
                    packet(&mut input, 65535).await.unwrap(),
                    Some((target.clone(), payload))
                );
                assert!(packet(&mut input, 65535).await.unwrap().is_none());
            }
        }
    }
    #[tokio::test]
    async fn bad_auth_command_delimiters_and_truncated_packets() {
        let key = crate::key("test-only-password").unwrap();
        let target = Destination::new("127.0.0.1", 80).unwrap();
        let mut original = Vec::new();
        write_request(&mut original, &key, &target, false)
            .await
            .unwrap();
        for index in [0, 56, 58, 59, original.len() - 1] {
            let mut bad = original.clone();
            bad[index] ^= 255;
            assert!(request(&mut bad.as_slice(), &[key]).await.is_err());
        }
        let mut wire = Vec::new();
        write_packet(&mut wire, &target, b"packet", 65535)
            .await
            .unwrap();
        for len in 1..wire.len() {
            assert!(packet(&mut &wire[..len], 65535).await.is_err());
        }
        assert!(packet(&mut wire.as_slice(), 2).await.is_err());
    }
    #[test]
    fn sha224_known_value_and_invalid_passwords() {
        assert_eq!(
            crate::key("password").unwrap().as_slice(),
            b"d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
        );
        assert!(crate::key("").is_err());
        assert!(crate::key(&"x".repeat(4097)).is_err());
    }
}
