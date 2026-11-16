//! The Hysteria 2 wire format, shared by the proxy and the VLESS carrier.

pub mod auth;
pub mod datagram;
pub mod masquerade;
pub mod obfs;
pub mod quic;
pub mod tcp;

use std::io::{self, Read};
use std::net::Ipv6Addr;

pub const MAX_ADDRESS: usize = 2048;

pub fn split_address(address: &str) -> io::Result<(&str, u16)> {
    let (host, port) = address.rsplit_once(':').ok_or_else(invalid_address)?;
    let port = port
        .parse::<u16>()
        .ok()
        .filter(|&port| port != 0)
        .ok_or_else(invalid_address)?;
    let host = if let Some(host) = host.strip_prefix('[').and_then(|v| v.strip_suffix(']')) {
        if host
            .split_once('%')
            .map_or(host, |(ip, _)| ip)
            .parse::<Ipv6Addr>()
            .is_err()
        {
            return Err(invalid_address());
        }
        host
    } else {
        if host.contains(['[', ']', ':']) {
            return Err(invalid_address());
        }
        host
    };
    if address.len() > MAX_ADDRESS
        || host.is_empty()
        || host
            .bytes()
            .any(|v| v.is_ascii_whitespace() || v.is_ascii_control())
    {
        return Err(invalid_address());
    }
    Ok((host, port))
}

pub fn format_address(host: &str, port: u16) -> io::Result<String> {
    let address = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    split_address(&address)?;
    Ok(address)
}

fn invalid_address() -> io::Error {
    invalid("invalid Hysteria target address")
}

fn invalid(reason: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

pub fn read_varint(mut read: impl Read) -> io::Result<u64> {
    let mut wire = [0; 8];
    read.read_exact(&mut wire[..1])?;
    let len = 1 << (wire[0] >> 6);
    wire[0] &= 0x3f;
    read.read_exact(&mut wire[1..len])?;
    Ok(u64::from_be_bytes(wire) >> ((8 - len) * 8))
}

fn varint_len(value: usize) -> usize {
    if value <= 63 {
        1
    } else if value <= 16_383 {
        2
    } else {
        4
    }
}

fn put_varint(out: &mut Vec<u8>, value: usize) {
    debug_assert!(value <= 0x3fff_ffff);
    match varint_len(value) {
        1 => out.push(value as u8),
        2 => out.extend((0x4000 | value as u16).to_be_bytes()),
        _ => out.extend((0x8000_0000 | value as u32).to_be_bytes()),
    }
}

fn read_len(read: &mut impl Read, max: usize) -> io::Result<usize> {
    let len = read_varint(read)?;
    if len > max as u64 {
        return Err(invalid("Hysteria field exceeds its size limit"));
    }
    Ok(len as usize)
}

fn padding(min: usize, max: usize) -> io::Result<String> {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut seed = [0; 2];
    getrandom::getrandom(&mut seed).map_err(|error| io::Error::other(error.to_string()))?;
    let mut bytes = vec![0; min + usize::from(u16::from_be_bytes(seed)) % (max - min)];
    getrandom::getrandom(&mut bytes).map_err(|error| io::Error::other(error.to_string()))?;
    Ok(bytes
        .into_iter()
        .map(|v| ALPHABET[usize::from(v) % ALPHABET.len()] as char)
        .collect())
}
