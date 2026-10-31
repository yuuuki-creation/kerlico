use kerlico_core::{Address, Destination, Error, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncRead, AsyncReadExt};

pub fn invalid() -> Error {
    Error::Protocol("SOCKS 报文格式或状态不合法")
}

pub fn encode(target: &Destination, bytes: &mut Vec<u8>) {
    match target.address() {
        Address::Ip(IpAddr::V4(ip)) => {
            bytes.push(1);
            bytes.extend(ip.octets());
        }
        Address::Ip(IpAddr::V6(ip)) => {
            bytes.push(4);
            bytes.extend(ip.octets());
        }
        Address::Domain(name) => {
            bytes.extend([3, name.len() as u8]);
            bytes.extend(name.as_bytes());
        }
    }
    bytes.extend(target.port().to_be_bytes());
}

pub async fn read_address(reader: &mut (impl AsyncRead + Unpin + ?Sized)) -> Result<(String, u16)> {
    let host = match reader.read_u8().await? {
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
            let len = reader.read_u8().await?;
            if len == 0 {
                return Err(invalid());
            }
            let mut bytes = vec![0; usize::from(len)];
            reader.read_exact(&mut bytes).await?;
            String::from_utf8(bytes).map_err(|_| invalid())?
        }
        _ => return Err(invalid()),
    };
    Ok((host, reader.read_u16().await?))
}

pub async fn cstring(
    reader: &mut (impl AsyncRead + Unpin + ?Sized),
    limit: usize,
) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    loop {
        let byte = reader.read_u8().await?;
        if byte == 0 {
            return Ok(bytes);
        }
        if bytes.len() == limit {
            return Err(invalid());
        }
        bytes.push(byte);
    }
}

pub fn packet(bytes: &[u8]) -> Result<(Destination, &[u8])> {
    if bytes.len() < 4 || bytes[..3] != [0, 0, 0] {
        return Err(invalid());
    }
    let (host, offset) = match bytes[3] {
        1 if bytes.len() >= 10 => (
            Ipv4Addr::from(<[u8; 4]>::try_from(&bytes[4..8]).map_err(|_| invalid())?).to_string(),
            8,
        ),
        4 if bytes.len() >= 22 => (
            Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[4..20]).map_err(|_| invalid())?).to_string(),
            20,
        ),
        3 if bytes.len() >= 5 => {
            let count = usize::from(bytes[4]);
            if count == 0 || bytes.len() < 7 + count {
                return Err(invalid());
            }
            (
                std::str::from_utf8(&bytes[5..5 + count])
                    .map_err(|_| invalid())?
                    .to_owned(),
                5 + count,
            )
        }
        _ => return Err(invalid()),
    };
    let port = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
    Ok((Destination::new(&host, port)?, &bytes[offset + 2..]))
}

pub fn datagram(target: &Destination, payload: &[u8]) -> Result<Vec<u8>> {
    let mut bytes = vec![0, 0, 0];
    encode(target, &mut bytes);
    bytes.extend(payload);
    if bytes.len() > 65_507 {
        return Err(Error::ResourceLimit);
    }
    Ok(bytes)
}
