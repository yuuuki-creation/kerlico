use std::io;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::{invalid, padding, put_varint, split_address, MAX_ADDRESS};

pub const FRAME_TYPE: u64 = 0x401;
pub const FRAME_PREFIX: [u8; 2] = (FRAME_TYPE as u16 | 0x4000).to_be_bytes();
const MAX_MESSAGE: usize = 2048;
const MAX_PADDING: usize = 4096;

pub fn request(address: &str) -> io::Result<Vec<u8>> {
    split_address(address)?;
    let mut wire = Vec::from(FRAME_PREFIX);
    write_field(&mut wire, address.as_bytes());
    write_field(&mut wire, padding(64, 512)?.as_bytes());
    Ok(wire)
}

/// Reads the fields following the TCP request's stream type.
pub async fn read_request(mut read: impl AsyncRead + Unpin) -> io::Result<String> {
    let address = read_text(&mut read, MAX_ADDRESS).await?;
    read_padding(&mut read).await?;
    split_address(&address)?;
    Ok(address)
}

pub fn response(ok: bool, message: &str) -> io::Result<Vec<u8>> {
    if message.len() > MAX_MESSAGE {
        return Err(invalid("Hysteria response message too long"));
    }
    let mut wire = vec![u8::from(!ok)];
    write_field(&mut wire, message.as_bytes());
    write_field(&mut wire, padding(128, 1024)?.as_bytes());
    Ok(wire)
}

pub async fn read_response(mut read: impl AsyncRead + Unpin) -> io::Result<(bool, String)> {
    let status = read.read_u8().await?;
    let message = read_text(&mut read, MAX_MESSAGE).await?;
    read_padding(&mut read).await?;
    Ok((status == 0, message))
}

fn write_field(out: &mut Vec<u8>, bytes: &[u8]) {
    put_varint(out, bytes.len());
    out.extend_from_slice(bytes);
}

async fn read_len(read: &mut (impl AsyncRead + Unpin), cap: usize) -> io::Result<usize> {
    let mut wire = [0; 8];
    wire[0] = read.read_u8().await?;
    let len = 1 << (wire[0] >> 6);
    read.read_exact(&mut wire[1..len]).await?;
    crate::read_len(&mut &wire[..len], cap)
}

async fn read_text(read: &mut (impl AsyncRead + Unpin), cap: usize) -> io::Result<String> {
    let len = read_len(read, cap).await?;
    let mut bytes = vec![0; len];
    read.read_exact(&mut bytes).await?;
    String::from_utf8(bytes).map_err(|_| invalid("invalid Hysteria text"))
}

async fn read_padding(read: &mut (impl AsyncRead + Unpin)) -> io::Result<()> {
    let len = read_len(read, MAX_PADDING).await?;
    let mut buf = [0; 256];
    let mut remaining = len;
    while remaining != 0 {
        let size = remaining.min(buf.len());
        read.read_exact(&mut buf[..size]).await?;
        remaining -= size;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tcp_fields_leave_application_bytes_unread() {
        let mut wire = &b"\x44\x01\x09[::1]:443\x03padbody"[..];
        assert_eq!(crate::read_varint(&mut wire).unwrap(), FRAME_TYPE);
        assert_eq!(read_request(&mut wire).await.unwrap(), "[::1]:443");
        assert_eq!(wire, b"body");

        let mut wire = &b"\x01\x06denied\x03padbody"[..];
        assert_eq!(
            read_response(&mut wire).await.unwrap(),
            (false, "denied".to_owned())
        );
        assert_eq!(wire, b"body");
    }

    #[tokio::test]
    async fn oversized_or_truncated_length_and_invalid_destinations_are_rejected() {
        assert!(read_request(&b"\x48\x01"[..]).await.is_err());
        assert!(read_request(&b"\x05two"[..]).await.is_err());
        assert!(request("[localhost]:443").is_err());
        assert!(request("localhost:0").is_err());
    }
}
