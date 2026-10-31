use kerlico_core::{Address, Destination, Error, Result};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt};

pub(crate) fn invalid() -> Error {
    Error::Protocol("Gost Relay 帧不合法")
}
fn feature(output: &mut Vec<u8>, kind: u8, bytes: &[u8]) {
    output.push(kind);
    output.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    output.extend_from_slice(bytes);
}
pub(crate) fn request(
    target: Option<&Destination>,
    username: &str,
    password: &str,
    udp: bool,
) -> Vec<u8> {
    let mut features = Vec::new();
    if !username.is_empty() || !password.is_empty() {
        let mut auth = vec![username.len() as u8];
        auth.extend_from_slice(username.as_bytes());
        auth.push(password.len() as u8);
        auth.extend_from_slice(password.as_bytes());
        feature(&mut features, 1, &auth);
    }
    if let Some(target) = target {
        let mut address = Vec::new();
        match target.address() {
            Address::Ip(std::net::IpAddr::V4(ip)) => {
                address.push(1);
                address.extend_from_slice(&ip.octets());
            }
            Address::Ip(std::net::IpAddr::V6(ip)) => {
                address.push(4);
                address.extend_from_slice(&ip.octets());
            }
            Address::Domain(name) => {
                address.extend_from_slice(&[3, name.len() as u8]);
                address.extend_from_slice(name.as_bytes());
            }
        }
        address.extend_from_slice(&target.port().to_be_bytes());
        feature(&mut features, 2, &address);
    }
    feature(&mut features, 4, &[0, u8::from(udp)]);
    let mut bytes = vec![1, if udp { 0x81 } else { 1 }];
    bytes.extend_from_slice(&(features.len() as u16).to_be_bytes());
    bytes.extend(features);
    bytes
}

pub(crate) fn features_valid(mut bytes: &[u8]) -> Result<()> {
    while !bytes.is_empty() {
        if bytes.len() < 3 {
            return Err(invalid());
        }
        let len = u16::from_be_bytes([bytes[1], bytes[2]]) as usize;
        if len > bytes.len() - 3 {
            return Err(invalid());
        }
        let body = &bytes[3..3 + len];
        let valid = match bytes[0] {
            1 => {
                body.len() >= 2
                    && (body[0] as usize + 1) < body.len()
                    && body.len() == body[0] as usize + 2 + body[body[0] as usize + 1] as usize
            }
            2 => match body.first() {
                Some(1) => body.len() == 7,
                Some(4) => body.len() == 19,
                Some(3) => body.len() >= 4 && body.len() == body[1] as usize + 4,
                _ => false,
            },
            3 => body.len() == 20,
            4 => body.len() == 2,
            _ => true,
        };
        if !valid {
            return Err(invalid());
        }
        bytes = &bytes[3 + len..];
    }
    Ok(())
}

pub(crate) async fn response<R: AsyncRead + Unpin>(stream: &mut R) -> Result<()> {
    let mut head = [0; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 1 {
        return Err(invalid());
    }
    // 失败响应不等待不可信扩展，不发送业务。
    match head[1] {
        0 => {}
        2 | 3 => return Err(Error::Rejected),
        4 => return Err(Error::Timeout),
        5..=7 => {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "Relay 目标不可达",
            )));
        }
        _ => return Err(invalid()),
    }
    let mut extensions = vec![0; u16::from_be_bytes([head[2], head[3]]) as usize];
    stream.read_exact(&mut extensions).await?;
    features_valid(&extensions)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_request_bytes_and_features() {
        let target = Destination::new("192.0.2.1", 443).unwrap();
        assert_eq!(
            request(Some(&target), "u", "p", true),
            [
                1, 129, 0, 22, 1, 0, 4, 1, b'u', 1, b'p', 2, 0, 7, 1, 192, 0, 2, 1, 1, 187, 4, 0,
                2, 0, 1
            ]
        );
        assert_eq!(request(None, "", "", false), [1, 1, 0, 5, 4, 0, 2, 0, 0]);
        for bytes in [
            &[1, 0, 1, 0][..],
            &[2, 0, 2, 3, 0][..],
            &[4, 0, 1, 0][..],
            &[99, 0, 1][..],
        ] {
            assert!(features_valid(bytes).is_err());
        }
        assert!(features_valid(&[99, 0, 2, 8, 9, 4, 0, 2, 0, 1]).is_ok());
    }
}
