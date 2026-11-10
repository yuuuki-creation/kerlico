use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeaderError {
    Short,
    Bad,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Command {
    Tcp,
    Udp,
    Mux,
    Reverse,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Addr {
    V4(Ipv4Addr),
    Domain(String),
    V6(Ipv6Addr),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    pub id: [u8; 16],
    pub flow: String,
    pub seed: Vec<u8>,
    pub command: Command,
    pub port: u16,
    pub address: Addr,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Response {
    pub flow: String,
    pub seed: Vec<u8>,
}

pub fn encode_request(request: &Request) -> Result<Vec<u8>, HeaderError> {
    let mut out = Vec::with_capacity(64);
    out.push(0);
    out.extend_from_slice(&request.id);
    write_addons(&mut out, &request.flow, &request.seed)?;
    out.push(command_byte(request.command));
    if !matches!(request.command, Command::Mux | Command::Reverse) {
        out.extend_from_slice(&request.port.to_be_bytes());
        write_addr(&mut out, &request.address)?;
    }
    Ok(out)
}

pub fn decode_request(input: &[u8]) -> Result<(Request, usize), HeaderError> {
    if input.len() < 18 {
        return Err(HeaderError::Short);
    }
    if input[0] != 0 {
        return Err(HeaderError::Bad);
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(&input[1..17]);
    let addon_len = input[17] as usize;
    let addon_end = 18 + addon_len;
    if input.len() < addon_end + 1 {
        return Err(HeaderError::Short);
    }
    let (flow, seed) = read_addons(&input[18..addon_end])?;
    let command = command_from(input[addon_end])?;
    if matches!(command, Command::Mux | Command::Reverse) {
        return Ok((
            Request {
                id,
                flow,
                seed,
                command,
                port: 0,
                address: if command == Command::Reverse {
                    Addr::Domain("v1.rvs.cool".to_string())
                } else {
                    Addr::Domain(String::new())
                },
            },
            addon_end + 1,
        ));
    }
    if input.len() < addon_end + 4 {
        return Err(HeaderError::Short);
    }
    let port = u16::from_be_bytes([input[addon_end + 1], input[addon_end + 2]]);
    let (address, used) = read_addr(&input[addon_end + 3..])?;
    Ok((
        Request {
            id,
            flow,
            seed,
            command,
            port,
            address,
        },
        addon_end + 3 + used,
    ))
}

pub fn encode_response(response: &Response) -> Result<Vec<u8>, HeaderError> {
    let mut out = Vec::with_capacity(8);
    out.push(0);
    write_addons(&mut out, &response.flow, &response.seed)?;
    Ok(out)
}

pub fn decode_response(input: &[u8]) -> Result<(Response, usize), HeaderError> {
    if input.len() < 2 {
        return Err(HeaderError::Short);
    }
    if input[0] != 0 {
        return Err(HeaderError::Bad);
    }
    let addon_len = input[1] as usize;
    if input.len() < 2 + addon_len {
        return Err(HeaderError::Short);
    }
    let (flow, seed) = read_addons(&input[2..2 + addon_len])?;
    Ok((Response { flow, seed }, 2 + addon_len))
}

/// Xray's `buf.Size`. Xray reads each UDP datagram into one buffer this large, and its Mux
/// reader ends the whole Mux connection on a packet frame longer than one buffer.
const XRAY_BUFFER: usize = 8192;

/// How a datagram rides the VLESS wire. Xray skips a datagram larger than its framing allows
/// without an error, and the flow goes on.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UdpFraming {
    /// The UDP command's two-byte length. `MultiLengthPacketWriter` skips `length+2 > buf.Size`.
    Plain,
    /// The only session on a client's XUDP carrier, `v1.mux.cool:666`. `xudp.PacketWriter`
    /// skips `length+666 > buf.Size`.
    Xudp,
    /// Every other Mux packet frame. `mux.Writer` has no check because each datagram it writes
    /// came out of one buffer.
    Mux,
}

impl UdpFraming {
    pub const fn carries(self, datagram: &[u8]) -> bool {
        datagram.len()
            <= match self {
                Self::Plain => XRAY_BUFFER - 2,
                Self::Xudp => XRAY_BUFFER - 666,
                Self::Mux => XRAY_BUFFER,
            }
    }
}

pub fn encode_udp(payload: &[u8]) -> Result<Vec<u8>, HeaderError> {
    if payload.len() > u16::MAX as usize {
        return Err(HeaderError::Bad);
    }
    let mut out = Vec::with_capacity(2 + payload.len());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

pub fn decode_udp(input: &[u8]) -> Result<(&[u8], usize), HeaderError> {
    if input.len() < 2 {
        return Err(HeaderError::Short);
    }
    let len = u16::from_be_bytes([input[0], input[1]]) as usize;
    if input.len() < 2 + len {
        return Err(HeaderError::Short);
    }
    Ok((&input[2..2 + len], 2 + len))
}

fn command_byte(command: Command) -> u8 {
    match command {
        Command::Tcp => 1,
        Command::Udp => 2,
        Command::Mux => 3,
        Command::Reverse => 4,
    }
}

fn command_from(byte: u8) -> Result<Command, HeaderError> {
    match byte {
        1 => Ok(Command::Tcp),
        2 => Ok(Command::Udp),
        3 => Ok(Command::Mux),
        4 => Ok(Command::Reverse),
        _ => Err(HeaderError::Bad),
    }
}

fn write_addr(out: &mut Vec<u8>, address: &Addr) -> Result<(), HeaderError> {
    match address {
        Addr::V4(ip) => {
            out.push(1);
            out.extend_from_slice(&ip.octets());
        }
        Addr::Domain(name) => {
            if name.is_empty() || name.len() > 255 {
                return Err(HeaderError::Bad);
            }
            out.push(2);
            out.push(name.len() as u8);
            out.extend_from_slice(name.as_bytes());
        }
        Addr::V6(ip) => {
            out.push(3);
            out.extend_from_slice(&ip.octets());
        }
    }
    Ok(())
}

fn read_addr(input: &[u8]) -> Result<(Addr, usize), HeaderError> {
    if input.is_empty() {
        return Err(HeaderError::Short);
    }
    match input[0] {
        1 => {
            if input.len() < 5 {
                return Err(HeaderError::Short);
            }
            Ok((Addr::V4(Ipv4Addr::new(input[1], input[2], input[3], input[4])), 5))
        }
        2 => {
            if input.len() < 2 {
                return Err(HeaderError::Short);
            }
            let len = input[1] as usize;
            if len == 0 {
                return Err(HeaderError::Bad);
            }
            if input.len() < 2 + len {
                return Err(HeaderError::Short);
            }
            let name = std::str::from_utf8(&input[2..2 + len]).map_err(|_| HeaderError::Bad)?;
            Ok((Addr::Domain(name.to_string()), 2 + len))
        }
        3 => {
            if input.len() < 17 {
                return Err(HeaderError::Short);
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&input[1..17]);
            Ok((Addr::V6(Ipv6Addr::from(octets)), 17))
        }
        _ => Err(HeaderError::Bad),
    }
}

fn write_addons(out: &mut Vec<u8>, flow: &str, seed: &[u8]) -> Result<(), HeaderError> {
    if flow.is_empty() && seed.is_empty() {
        out.push(0);
        return Ok(());
    }
    let mut body = Vec::new();
    if !flow.is_empty() {
        write_field(&mut body, 1, flow.as_bytes())?;
    }
    if !seed.is_empty() {
        write_field(&mut body, 2, seed)?;
    }
    if body.len() > 255 {
        return Err(HeaderError::Bad);
    }
    out.push(body.len() as u8);
    out.extend_from_slice(&body);
    Ok(())
}

fn write_field(out: &mut Vec<u8>, field: u8, bytes: &[u8]) -> Result<(), HeaderError> {
    if bytes.len() > 255 {
        return Err(HeaderError::Bad);
    }
    out.push((field << 3) | 2);
    let mut len = bytes.len();
    while len >= 128 {
        out.push((len as u8 & 0x7f) | 0x80);
        len >>= 7;
    }
    out.push(len as u8);
    out.extend_from_slice(bytes);
    Ok(())
}

fn read_addons(input: &[u8]) -> Result<(String, Vec<u8>), HeaderError> {
    let mut flow = String::new();
    let mut seed = Vec::new();
    let mut cursor = 0;
    while cursor < input.len() {
        let key = read_varint(input, &mut cursor)?;
        let wire = key & 7;
        let field = key >> 3;
        if field == 0 || (matches!(field, 1 | 2) && wire != 2) {
            return Err(HeaderError::Bad);
        }
        let len = match wire {
            0 => { read_varint(input, &mut cursor)?; continue; }
            1 => 8,
            2 => usize::try_from(read_varint(input, &mut cursor)?).map_err(|_| HeaderError::Bad)?,
            5 => 4,
            _ => return Err(HeaderError::Bad),
        };
        let end = cursor.checked_add(len).ok_or(HeaderError::Bad)?;
        let bytes = input.get(cursor..end).ok_or(HeaderError::Bad)?;
        cursor = end;
        if field == 1 {
            flow = std::str::from_utf8(bytes).map_err(|_| HeaderError::Bad)?.to_string();
        } else if field == 2 {
            seed = bytes.to_vec();
        }
    }
    Ok((flow, seed))
}

fn read_varint(input: &[u8], cursor: &mut usize) -> Result<u64, HeaderError> {
    let mut value = 0u64;
    for shift in (0..70).step_by(7) {
        let byte = *input.get(*cursor).ok_or(HeaderError::Bad)?;
        *cursor += 1;
        if shift == 63 && byte > 1 {
            return Err(HeaderError::Bad);
        }
        value |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 { return Ok(value); }
    }
    Err(HeaderError::Bad)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_ipv4_header_roundtrip() {
        let request = Request {
            id: [0x11; 16],
            flow: String::new(),
            seed: Vec::new(),
            command: Command::Tcp,
            port: 443,
            address: Addr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        };
        let bytes = encode_request(&request).unwrap();
        assert_eq!(
            bytes,
            [
                0, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0,
                1, 0x01, 0xbb, 1, 1, 2, 3, 4
            ]
        );
        let (decoded, used) = decode_request(&bytes).unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(decoded, request);
    }

    #[test]
    fn udp_domain_keeps_flow_and_seed() {
        let request = Request {
            id: [0x22; 16],
            flow: "xtls-rprx-vision".to_string(),
            seed: vec![9, 8, 7],
            command: Command::Udp,
            port: 80,
            address: Addr::Domain("example.com".to_string()),
        };
        let bytes = encode_request(&request).unwrap();
        let (decoded, used) = decode_request(&bytes).unwrap();
        assert_eq!(used, bytes.len());
        assert_eq!(decoded, request);
        let packet = encode_udp(b"dns").unwrap();
        assert_eq!(packet, [0, 3, b'd', b'n', b's']);
        assert_eq!(decode_udp(&packet).unwrap().0, b"dns");
    }

    #[test]
    fn response_is_version_and_addons() {
        let bytes = encode_response(&Response {
            flow: String::new(),
            seed: Vec::new(),
        })
        .unwrap();
        assert_eq!(bytes, [0, 0]);
        let (decoded, used) = decode_response(&bytes).unwrap();
        assert_eq!(used, 2);
        assert!(decoded.flow.is_empty());
    }
}
