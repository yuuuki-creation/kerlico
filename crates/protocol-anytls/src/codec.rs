use kerlico_core::{Address, Destination, Error, Result};
use std::net::{Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncRead, AsyncReadExt};

pub const WASTE: u8 = 0;
pub const SYN: u8 = 1;
pub const PSH: u8 = 2;
pub const FIN: u8 = 3;
pub const SETTINGS: u8 = 4;
pub const ALERT: u8 = 5;
pub const PADDING: u8 = 6;
pub const SYNACK: u8 = 7;
pub const HEART_REQUEST: u8 = 8;
pub const HEART_RESPONSE: u8 = 9;
pub const SERVER_SETTINGS: u8 = 10;
pub const UOT: &str = "sp.v2.udp-over-tcp.arpa";

pub struct Frame {
    pub command: u8,
    pub id: u32,
    pub data: Vec<u8>,
}
impl Frame {
    pub fn new(command: u8, id: u32, data: Vec<u8>) -> Self {
        Self { command, id, data }
    }
    pub fn encode_into(&self, bytes: &mut Vec<u8>) -> Result<()> {
        let length = u16::try_from(self.data.len()).map_err(|_| Error::ResourceLimit)?;
        bytes.reserve(7 + self.data.len());
        bytes.push(self.command);
        bytes.extend_from_slice(&self.id.to_be_bytes());
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(&self.data);
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(7 + self.data.len());
        self.encode_into(&mut bytes)?;
        Ok(bytes)
    }
    pub async fn read(reader: &mut (impl AsyncRead + Unpin)) -> Result<Self> {
        let mut header = [0u8; 7];
        reader.read_exact(&mut header).await?;
        let command = header[0];
        let id = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
        let length = u16::from_be_bytes([header[5], header[6]]) as usize;
        let mut data = Vec::with_capacity(length);
        while data.len() < length {
            if reader.read_buf(&mut data).await? == 0 {
                return Err(Error::Io(std::io::ErrorKind::UnexpectedEof.into()));
            }
        }
        Ok(Self { command, id, data })
    }
}

pub fn address(target: &Destination, uot: bool) -> Vec<u8> {
    let mut bytes = Vec::new();
    match target.address() {
        Address::Ip(std::net::IpAddr::V4(ip)) => {
            bytes.push(if uot { 0 } else { 1 });
            bytes.extend_from_slice(&ip.octets());
        }
        Address::Ip(std::net::IpAddr::V6(ip)) => {
            bytes.push(if uot { 1 } else { 4 });
            bytes.extend_from_slice(&ip.octets());
        }
        Address::Domain(name) => {
            bytes.push(if uot { 2 } else { 3 });
            bytes.push(name.len() as u8);
            bytes.extend_from_slice(name.as_bytes());
        }
    }
    bytes.extend_from_slice(&target.port().to_be_bytes());
    bytes
}

pub fn uot_target() -> Vec<u8> {
    let mut bytes = vec![3, UOT.len() as u8];
    bytes.extend_from_slice(UOT.as_bytes());
    bytes.extend_from_slice(&[0, 0]);
    bytes
}

pub async fn read_address(
    reader: &mut (impl AsyncRead + Unpin),
    uot: bool,
) -> Result<(String, u16)> {
    let kind = reader.read_u8().await?;
    let host = if kind == if uot { 0 } else { 1 } {
        let mut ip = [0; 4];
        reader.read_exact(&mut ip).await?;
        Ipv4Addr::from(ip).to_string()
    } else if kind == if uot { 1 } else { 4 } {
        let mut ip = [0; 16];
        reader.read_exact(&mut ip).await?;
        Ipv6Addr::from(ip).to_string()
    } else if kind == if uot { 2 } else { 3 } {
        let len = reader.read_u8().await? as usize;
        if len == 0 {
            return Err(Error::InvalidAddress);
        }
        let mut name = vec![0; len];
        reader.read_exact(&mut name).await?;
        String::from_utf8(name).map_err(|_| Error::InvalidAddress)?
    } else {
        return Err(Error::Protocol("AnyTLS 地址类型不合法"));
    };
    Ok((host, reader.read_u16().await?))
}

pub async fn destination(reader: &mut (impl AsyncRead + Unpin), uot: bool) -> Result<Destination> {
    let (host, port) = read_address(reader, uot).await?;
    Destination::new(&host, port)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn address_and_frame_roundtrip() {
        for host in ["127.0.0.1", "::1", "example.invalid"] {
            let target = Destination::new(host, 443).unwrap();
            for uot in [false, true] {
                let bytes = address(&target, uot);
                assert_eq!(
                    destination(&mut bytes.as_slice(), uot).await.unwrap(),
                    target
                );
            }
        }
        let frame = Frame::new(PSH, 7, vec![1, 2, 3]);
        let bytes = frame.encode().unwrap();
        let decoded = Frame::read(&mut bytes.as_slice()).await.unwrap();
        assert_eq!(
            (decoded.command, decoded.id, decoded.data),
            (PSH, 7, vec![1, 2, 3])
        );
        assert!(Frame::new(PSH, 1, vec![0; 65536]).encode().is_err());
        assert!(destination(&mut [9u8].as_slice(), false).await.is_err());
        assert!(
            Frame::read(&mut [2u8, 0, 0, 0, 1, 0, 3, 1].as_slice())
                .await
                .is_err()
        );
    }
}
