//! 应用请求头和数据报地址；UDP 每条记录独立解析。
use crate::{io_protocol, protocol};
use kerlico_core::{Address, Destination, Result};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};
pub(crate) struct Request {
    pub command: u8,
    pub userkey: Vec<u8>,
    pub target: Option<Destination>,
    pub tail: Vec<u8>,
}
fn byte(input: &mut &[u8]) -> io::Result<u8> {
    let Some((&value, rest)) = input.split_first() else {
        return Err(io_protocol());
    };
    *input = rest;
    Ok(value)
}
fn take<'a>(input: &mut &'a [u8], n: usize) -> io::Result<&'a [u8]> {
    if input.len() < n {
        return Err(io_protocol());
    }
    let (out, rest) = input.split_at(n);
    *input = rest;
    Ok(out)
}
fn port(input: &mut &[u8]) -> io::Result<u16> {
    let bytes = take(input, 2)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}
fn target(host: &str, port: u16) -> io::Result<Destination> {
    Destination::new(host, port).map_err(|_| io_protocol())
}
pub(crate) fn request(command: u8, userkey: &[u8], destination: Option<&Destination>) -> Vec<u8> {
    let mut out = vec![1, command, userkey.len() as u8];
    out.extend_from_slice(userkey);
    if let Some(destination) = destination {
        let host = destination.host();
        out.push(host.len() as u8);
        out.extend_from_slice(host.as_bytes());
        out.extend_from_slice(&destination.port().to_be_bytes());
    }
    out
}
pub(crate) fn parse_request(mut input: &[u8]) -> io::Result<Request> {
    if byte(&mut input)? != 1 {
        return Err(io_protocol());
    }
    let command = byte(&mut input)?;
    let length = byte(&mut input)? as usize;
    let userkey = take(&mut input, length)?.to_vec();
    let target = match command {
        1 | 5 => {
            let n = byte(&mut input)? as usize;
            let host = std::str::from_utf8(take(&mut input, n)?).map_err(|_| io_protocol())?;
            let p = port(&mut input)?;
            Some(target(host, p)?)
        }
        0 | 6 => None,
        _ => return Err(io_protocol()),
    };
    Ok(Request {
        command,
        userkey,
        target,
        tail: input.to_vec(),
    })
}
pub(crate) fn error_reply(code: u8, message: &str) -> Vec<u8> {
    let bytes = message.as_bytes();
    let n = bytes.len().min(255);
    let mut out = vec![2, code, n as u8];
    out.extend_from_slice(&bytes[..n]);
    out
}
pub(crate) fn reply(mut input: Vec<u8>) -> io::Result<Vec<u8>> {
    if input.first() != Some(&0) {
        return Err(io_protocol());
    }
    input.remove(0);
    Ok(input)
}
fn ip_address(out: &mut Vec<u8>, target: &Destination) -> Result<()> {
    match target.address() {
        Address::Ip(IpAddr::V4(ip)) => {
            out.push(4);
            out.extend_from_slice(&ip.octets());
        }
        Address::Ip(IpAddr::V6(ip)) => {
            out.push(6);
            out.extend_from_slice(&ip.octets());
        }
        _ => return Err(protocol()),
    };
    out.extend_from_slice(&target.port().to_be_bytes());
    Ok(())
}
pub(crate) fn udp_request(target: &Destination, payload: &[u8]) -> Result<Vec<u8>> {
    let mut out = vec![1];
    match target.address() {
        Address::Domain(host) => {
            out.push(host.len() as u8);
            out.extend_from_slice(host.as_bytes());
            out.extend_from_slice(&target.port().to_be_bytes());
        }
        _ => {
            out.push(0);
            ip_address(&mut out, target)?;
        }
    }
    out.extend_from_slice(payload);
    Ok(out)
}
pub(crate) fn udp_response(target: &Destination, payload: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    ip_address(&mut out, target)?;
    out.extend_from_slice(payload);
    Ok(out)
}
fn read_ip(input: &mut &[u8]) -> io::Result<Destination> {
    let host = match byte(input)? {
        4 => {
            let bytes: [u8; 4] = take(input, 4)?.try_into().map_err(|_| io_protocol())?;
            Ipv4Addr::from(bytes).to_string()
        }
        6 => {
            let bytes: [u8; 16] = take(input, 16)?.try_into().map_err(|_| io_protocol())?;
            Ipv6Addr::from(bytes).to_string()
        }
        _ => return Err(io_protocol()),
    };
    target(&host, port(input)?)
}
pub(crate) fn parse_udp(mut input: &[u8], response: bool) -> io::Result<(Destination, Vec<u8>)> {
    let destination = if response {
        read_ip(&mut input)?
    } else {
        if byte(&mut input)? != 1 {
            return Err(io_protocol());
        }
        let n = byte(&mut input)? as usize;
        if n == 0 {
            read_ip(&mut input)?
        } else {
            let host = std::str::from_utf8(take(&mut input, n)?).map_err(|_| io_protocol())?;
            let p = port(&mut input)?;
            target(host, p)?
        }
    };
    Ok((destination, input.to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn requests_packets_and_zero_datagram_are_distinct_from_eof() {
        for host in ["127.0.0.1", "::1", "example.invalid"] {
            let target = Destination::new(host, 53).unwrap();
            let header = request(5, b"test-key", Some(&target));
            let parsed = parse_request(&header).unwrap();
            assert_eq!(parsed.command, 5);
            assert_eq!(parsed.userkey, b"test-key");
            assert_eq!(parsed.target, Some(target.clone()));
            for bytes in [Vec::new(), vec![19; 4096]] {
                let encoded = udp_request(&target, &bytes).unwrap();
                assert_eq!(parse_udp(&encoded, false).unwrap(), (target.clone(), bytes));
            }
            if matches!(target.address(), Address::Ip(_)) {
                assert_eq!(
                    parse_udp(&udp_response(&target, &[]).unwrap(), true).unwrap(),
                    (target, Vec::new())
                );
            }
        }
        for wire in [
            vec![],
            vec![0],
            vec![1, 255, 0],
            vec![1, 1, 0, 255],
            vec![1, 6, 2, 0],
        ] {
            assert!(parse_request(&wire).is_err());
        }
        assert!(parse_udp(&[2, 0, 4, 127, 0, 0, 1, 0, 53], false).is_err());
        assert!(parse_udp(&[3, 0, 0, 53], true).is_err());
        assert!(reply(vec![2, 1, 0]).is_err());
    }
}
