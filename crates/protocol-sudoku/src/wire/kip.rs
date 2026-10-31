use kerlico_core::{Error, Result};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub(crate) const CLIENT_HELLO: u8 = 1;
pub(crate) const SERVER_HELLO: u8 = 2;
pub(crate) const OPEN_TCP: u8 = 0x10;
pub(crate) const START_MUX: u8 = 0x11;
pub(crate) const START_UOT: u8 = 0x12;
pub(crate) const KEEPALIVE: u8 = 0x14;
pub(crate) const FEATURES: u32 = 0x17;

pub(crate) struct Message {
    pub kind: u8,
    pub payload: Vec<u8>,
}
pub(crate) fn encode(kind: u8, payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() > u16::MAX as usize {
        return Err(Error::ResourceLimit);
    }
    let mut message = Vec::with_capacity(6 + payload.len());
    message.extend_from_slice(b"kip");
    message.push(kind);
    message.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    message.extend_from_slice(payload);
    Ok(message)
}
pub(crate) async fn write(
    stream: &mut (impl AsyncWrite + Unpin),
    kind: u8,
    payload: &[u8],
) -> Result<()> {
    stream.write_all(&encode(kind, payload)?).await?;
    stream.flush().await?;
    Ok(())
}
pub(crate) async fn read(stream: &mut (impl AsyncRead + Unpin)) -> Result<Message> {
    let mut head = [0; 6];
    stream.read_exact(&mut head).await?;
    if &head[..3] != b"kip" {
        return Err(crate::invalid());
    }
    let mut payload = vec![0; u16::from_be_bytes(head[4..].try_into().unwrap()) as usize];
    stream.read_exact(&mut payload).await?;
    Ok(Message {
        kind: head[3],
        payload,
    })
}
pub(crate) fn now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| Error::Protocol("系统时间早于Unix纪元"))
}

pub(crate) struct ClientHello {
    pub timestamp: u64,
    pub user_hash: [u8; 8],
    pub nonce: [u8; 16],
    pub public: [u8; 32],
    pub features: u32,
    pub table_hint: Option<u32>,
}
impl ClientHello {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(72);
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.user_hash);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.public);
        out.extend_from_slice(&self.features.to_be_bytes());
        if let Some(hint) = self.table_hint {
            out.extend_from_slice(&hint.to_be_bytes());
        }
        out
    }
    pub fn decode(bytes: &[u8], time: u64) -> Result<Self> {
        if bytes.len() != 68 && bytes.len() != 72 {
            return Err(crate::invalid());
        }
        let timestamp = u64::from_be_bytes(bytes[..8].try_into().unwrap());
        if timestamp.abs_diff(time) > 60 {
            return Err(crate::invalid());
        }
        Ok(Self {
            timestamp,
            user_hash: bytes[8..16].try_into().unwrap(),
            nonce: bytes[16..32].try_into().unwrap(),
            public: bytes[32..64].try_into().unwrap(),
            features: u32::from_be_bytes(bytes[64..68].try_into().unwrap()),
            table_hint: if bytes.len() == 72 {
                Some(u32::from_be_bytes(bytes[68..72].try_into().unwrap()))
            } else {
                None
            },
        })
    }
}
pub(crate) struct ServerHello {
    pub nonce: [u8; 16],
    pub public: [u8; 32],
    pub features: u32,
}
impl ServerHello {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.nonce.to_vec();
        out.extend_from_slice(&self.public);
        out.extend_from_slice(&self.features.to_be_bytes());
        out
    }
    pub fn decode(bytes: &[u8], expected_nonce: [u8; 16], requested: u32) -> Result<Self> {
        if bytes.len() != 52 || bytes[..16] != expected_nonce {
            return Err(crate::invalid());
        }
        let features = u32::from_be_bytes(bytes[48..52].try_into().unwrap());
        if features & !requested != 0 {
            return Err(crate::invalid());
        }
        Ok(Self {
            nonce: expected_nonce,
            public: bytes[16..48].try_into().unwrap(),
            features,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact_hello_boundaries_time_nonce_and_u16_lengths() {
        let hello = ClientHello {
            timestamp: 1000,
            user_hash: [1; 8],
            nonce: [2; 16],
            public: [3; 32],
            features: FEATURES,
            table_hint: None,
        };
        let mut bytes = hello.encode();
        assert_eq!(bytes.len(), 68);
        assert!(ClientHello::decode(&bytes, 1060).is_ok());
        assert!(ClientHello::decode(&bytes, 1061).is_err());
        bytes.extend_from_slice(&123u32.to_be_bytes());
        assert_eq!(
            ClientHello::decode(&bytes, 1000).unwrap().table_hint,
            Some(123)
        );
        bytes.push(0);
        assert!(ClientHello::decode(&bytes, 1000).is_err());
        let reply = ServerHello {
            nonce: hello.nonce,
            public: [4; 32],
            features: FEATURES,
        }
        .encode();
        assert!(ServerHello::decode(&reply, hello.nonce, FEATURES).is_ok());
        assert!(ServerHello::decode(&reply, [0; 16], FEATURES).is_err());
        assert!(ServerHello::decode(&reply, hello.nonce, 1).is_err());
        assert!(encode(OPEN_TCP, &vec![0; 65535]).is_ok());
        assert!(encode(OPEN_TCP, &vec![0; 65536]).is_err());
        assert_eq!(encode(KEEPALIVE, &[]).unwrap(), b"kip\x14\0\0");
    }
}
