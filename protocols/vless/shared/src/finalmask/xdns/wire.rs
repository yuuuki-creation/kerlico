use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use data_encoding::BASE32_NOPAD;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use rand_core::{OsRng, RngCore};
use serde::Deserialize;

use super::super::{invalid, malformed, random_below, UDP_SIZE};

const TYPES: [RecordType; 4] = [
    RecordType::A,
    RecordType::CNAME,
    RecordType::TXT,
    RecordType::AAAA,
];
const POLL_MARK: u8 = 8;
const DATA_MARK: u8 = 3;
const FRAGMENT_FLAG: u8 = 0xc0;
const DATA_HEADER: usize = 12;
const FRAGMENT_HEADER: usize = 15;

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct DomainConfig {
    pub(super) names: Vec<String>,
    len_limit: usize,
    label_limit: usize,
    types: Vec<u16>,
    edns0: u16,
}

pub(super) struct Domain {
    name: Name,
    label_limit: usize,
    types: Vec<RecordType>,
    edns: u16,
    capacity: usize,
    max_name: usize,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct ClientId([u8; 8]);

impl ClientId {
    pub(super) fn new() -> io::Result<Self> {
        let mut id = [0; 8];
        fill(&mut id)?;
        Ok(Self::from_bytes(id))
    }

    fn from_bytes(mut bytes: [u8; 8]) -> Self {
        bytes[0] &= 0xfc;
        Self(bytes)
    }

    pub(super) fn from_addr(addr: SocketAddr) -> Option<Self> {
        let SocketAddr::V6(addr) = addr else {
            return None;
        };
        let bytes = addr.ip().octets();
        if bytes[..8] != [0xfd, 0, 0, 0, 0, 0, 0, 0] || addr.port() != 0 {
            return None;
        }
        Some(Self::from_bytes(bytes[8..].try_into().ok()?))
    }

    pub(super) fn addr(self) -> SocketAddr {
        let mut bytes = [0; 16];
        bytes[0] = 0xfd;
        bytes[8..].copy_from_slice(&self.0);
        SocketAddr::new(Ipv6Addr::from(bytes).into(), 0)
    }
}

pub(super) enum Uplink {
    Poll,
    Data(Vec<u8>),
    Fragment {
        id: u8,
        index: u8,
        count: u8,
        data: Vec<u8>,
    },
}

impl DomainConfig {
    pub(super) fn domains(self) -> io::Result<Vec<Domain>> {
        let limit = if self.len_limit == 0 {
            255
        } else {
            self.len_limit
        };
        let label_limit = if self.label_limit == 0 {
            63
        } else {
            self.label_limit
        };
        if limit > 255
            || label_limit > 63
            || (self.edns0 != 0 && !(512..=4096).contains(&self.edns0))
        {
            return Err(invalid("invalid XDNS domain limits or EDNS size"));
        }
        let types = self
            .types
            .into_iter()
            .map(|kind| {
                let kind = RecordType::from(kind);
                if TYPES.contains(&kind) {
                    Ok(kind)
                } else {
                    Err(invalid("XDNS domain type must be A, CNAME, TXT, or AAAA"))
                }
            })
            .collect::<io::Result<Vec<_>>>()?;
        self.names
            .into_iter()
            .map(|name| {
                let name = name.trim_end_matches('.');
                if name.is_empty() || name.contains("..") {
                    return Err(invalid("invalid XDNS domain name"));
                }
                let name = Name::from_labels(name.as_bytes().split(|&byte| byte == b'.'))
                    .map_err(invalid)?;
                let name_bytes = wire_name_len(&name);
                let available = limit
                    .checked_sub(name_bytes)
                    .ok_or_else(|| invalid("XDNS domain exceeds lenLimit"))?;
                let total = (available / (label_limit + 1)) * label_limit
                    + (available % (label_limit + 1)).saturating_sub(1);
                let capacity = total * 5 / 8;
                if capacity < 17 {
                    return Err(invalid("XDNS domain leaves fewer than 17 payload bytes"));
                }
                let encoded = (capacity * 8).div_ceil(5);
                let max_name = name_bytes + encoded + encoded.div_ceil(label_limit);
                Ok(Domain {
                    name,
                    label_limit,
                    types: types.clone(),
                    edns: self.edns0,
                    capacity,
                    max_name,
                })
            })
            .collect()
    }
}

impl Domain {
    fn client_type(&self) -> RecordType {
        if self.types.is_empty() {
            return RecordType::TXT;
        }
        self.types[random_below(self.types.len() as u32) as usize]
    }

    fn supports(&self, kind: RecordType) -> bool {
        if self.types.is_empty() {
            TYPES.contains(&kind)
        } else {
            self.types.contains(&kind)
        }
    }

    fn matches(&self, name: &Name) -> bool {
        name.num_labels() > self.name.num_labels() && self.name.zone_of(name)
    }

    fn encode(&self, data: &[u8]) -> io::Result<Name> {
        if data.len() > self.capacity {
            return Err(invalid("XDNS name payload exceeds domain capacity"));
        }
        let encoded = BASE32_NOPAD.encode(data).to_ascii_lowercase();
        let labels = encoded
            .as_bytes()
            .chunks(self.label_limit)
            .chain(self.name.iter());
        Name::from_labels(labels).map_err(invalid)
    }

    fn decode(&self, name: &Name) -> Option<Vec<u8>> {
        if !self.matches(name) {
            return None;
        }
        let labels = usize::from(name.num_labels() - self.name.num_labels());
        let mut encoded: Vec<u8> = name.iter().take(labels).flatten().copied().collect();
        encoded.make_ascii_uppercase();
        BASE32_NOPAD.decode(&encoded).ok()
    }

    pub(super) fn queries(
        &self,
        client: ClientId,
        fragment: u8,
        packet: &[u8],
    ) -> io::Result<Vec<Vec<u8>>> {
        let kind = self.client_type();
        let tag = TYPES
            .iter()
            .position(|value| *value == kind)
            .expect("XDNS record type") as u8;
        let mut prefix = [0; 17];
        prefix[..8].copy_from_slice(&client.0);
        prefix[0] |= tag;
        if packet.is_empty() {
            prefix[8] = POLL_MARK;
            fill(&mut prefix[9..])?;
            return Ok(vec![self.query(kind, &prefix)?]);
        }
        prefix[8] = DATA_MARK;
        fill(&mut prefix[9..DATA_HEADER])?;
        if packet.len() <= self.capacity - DATA_HEADER {
            return Ok(vec![
                self.query(kind, &[&prefix[..DATA_HEADER], packet].concat())?
            ]);
        }
        prefix[8] |= FRAGMENT_FLAG;
        let width = self.capacity - FRAGMENT_HEADER;
        let count = packet.len().div_ceil(width);
        if count > u8::MAX.into() {
            return Err(invalid("XDNS datagram requires more than 255 fragments"));
        }
        prefix[12] = fragment;
        prefix[14] = count as u8;
        packet
            .chunks(width)
            .enumerate()
            .map(|(index, part)| {
                prefix[13] = index as u8;
                self.query(kind, &[&prefix[..FRAGMENT_HEADER], part].concat())
            })
            .collect()
    }

    fn query(&self, kind: RecordType, payload: &[u8]) -> io::Result<Vec<u8>> {
        let mut msg = Message::new();
        msg.set_id(OsRng.next_u32() as u16)
            .set_recursion_desired(true)
            .add_query(Query::query(self.encode(payload)?, kind));
        if self.edns != 0 {
            let mut edns = Edns::new();
            edns.set_max_payload(self.edns);
            msg.set_edns(edns);
        }
        msg.to_vec().map_err(io::Error::other)
    }
}

pub(super) struct Response {
    domain: Arc<Domain>,
    question: Query,
    id: u16,
    edns: Option<u16>,
    capacity: usize,
}

pub(super) enum ParsedQuery {
    Reject(Vec<u8>),
    Tunnel {
        response: Response,
        client: ClientId,
        packet: Uplink,
    },
}

pub(super) fn read_query(domains: &[Arc<Domain>], wire: &[u8]) -> Option<ParsedQuery> {
    let msg = Message::from_vec(wire).ok()?;
    if msg.message_type() == MessageType::Response {
        return None;
    }
    if msg.op_code() != OpCode::Query {
        return reject(msg, ResponseCode::NotImp, false);
    }
    if msg.queries().len() != 1 {
        return reject(msg, ResponseCode::FormErr, false);
    }
    if msg
        .extensions()
        .as_ref()
        .is_some_and(|edns| edns.version() != 0)
    {
        return reject(msg, ResponseCode::BADVERS, false);
    }
    let question = msg.query()?.clone();
    let Some(domain) = domains
        .iter()
        .find(|domain| domain.matches(question.name()))
        .cloned()
    else {
        return reject(msg, ResponseCode::NXDomain, false);
    };
    let kind = question.query_type();
    if !domain.supports(kind) {
        return reject(msg, ResponseCode::NoError, true);
    }
    let Some(data) = domain.decode(question.name()) else {
        return reject(msg, ResponseCode::NoError, true);
    };
    let Some((client, packet)) = read_uplink(kind, &data) else {
        return reject(msg, ResponseCode::NoError, true);
    };
    let edns = msg
        .extensions()
        .as_ref()
        .map(|edns| edns.max_payload().clamp(512, 4096));
    let response = Response::new(domain, question, msg.id(), edns);
    Some(ParsedQuery::Tunnel {
        response,
        client,
        packet,
    })
}

fn reject(mut msg: Message, code: ResponseCode, authoritative: bool) -> Option<ParsedQuery> {
    msg.set_message_type(MessageType::Response)
        .set_response_code(code)
        .set_authoritative(authoritative);
    msg.to_vec().ok().map(ParsedQuery::Reject)
}

fn read_uplink(kind: RecordType, data: &[u8]) -> Option<(ClientId, Uplink)> {
    if data.len() < 9 || TYPES[usize::from(data[0] & 3)] != kind {
        return None;
    }
    let client = ClientId::from_bytes(data[..8].try_into().ok()?);
    let packet = match data[8] & 0x3f {
        POLL_MARK if data.len() == 17 => Uplink::Poll,
        DATA_MARK if data.len() > DATA_HEADER && data[8] & FRAGMENT_FLAG != FRAGMENT_FLAG => {
            Uplink::Data(data[DATA_HEADER..].to_vec())
        }
        DATA_MARK if data.len() > FRAGMENT_HEADER && data[8] & FRAGMENT_FLAG == FRAGMENT_FLAG => {
            Uplink::Fragment {
                id: data[12],
                index: data[13],
                count: data[14],
                data: data[FRAGMENT_HEADER..].to_vec(),
            }
        }
        _ => return None,
    };
    Some((client, packet))
}

impl Response {
    fn new(domain: Arc<Domain>, question: Query, id: u16, edns: Option<u16>) -> Self {
        let max = usize::from(edns.unwrap_or(512).min(domain.edns.max(512)));
        let left = max.saturating_sub(
            12 + wire_name_len(question.name()) + 4 + if edns.is_some() { 11 } else { 0 },
        );
        let packed = |width: usize, record: usize| {
            (left / record)
                .min(255)
                .saturating_mul(width)
                .saturating_sub(1)
        };
        let capacity = match question.query_type() {
            RecordType::A => packed(3, 16),
            RecordType::AAAA => packed(15, 28),
            RecordType::CNAME => packed(domain.capacity - 1, 12 + domain.max_name),
            RecordType::TXT => {
                let left = left.saturating_sub(12);
                (left / 255) * 254 + (left % 255).saturating_sub(1)
            }
            _ => 0,
        };
        Self {
            domain,
            question,
            id,
            edns,
            capacity,
        }
    }

    pub(super) fn capacity(&self) -> usize {
        self.capacity
    }

    pub(super) fn encode(self, packets: &[Vec<u8>]) -> io::Result<Vec<u8>> {
        let mut data = Vec::new();
        for (index, packet) in packets.iter().enumerate() {
            let mut length = u16::try_from(packet.len()).map_err(invalid)?;
            if index + 1 == packets.len() {
                length |= 0xc000;
            }
            data.extend_from_slice(&length.to_be_bytes());
            data.extend_from_slice(packet);
        }
        if data.len() > self.capacity {
            return Err(invalid("XDNS answer exceeds its DNS packet capacity"));
        }
        let mut msg = Message::new();
        msg.set_id(self.id)
            .set_message_type(MessageType::Response)
            .set_authoritative(true);
        let name = self.question.name().clone();
        let kind = self.question.query_type();
        msg.add_query(self.question);
        if let Some(payload) = self.edns {
            let mut edns = Edns::new();
            edns.set_max_payload(payload);
            msg.set_edns(edns);
        }
        if kind == RecordType::TXT {
            let txt = TXT::from_bytes(data.chunks(255).collect());
            msg.add_answer(Record::from_rdata(name, 60, RData::TXT(txt)));
        } else if !data.is_empty() {
            let width = match kind {
                RecordType::A => 4,
                RecordType::AAAA => 16,
                RecordType::CNAME => self.domain.capacity,
                _ => return Err(invalid("unknown XDNS response type")),
            };
            let count = 1 + data.len().saturating_sub(width - 2).div_ceil(width - 1);
            let mut data = data.as_slice();
            for index in 0..count {
                let mut chunk = vec![index as u8];
                if index == 0 {
                    chunk.push(count as u8);
                }
                let len = data.len().min(width - chunk.len());
                chunk.extend_from_slice(&data[..len]);
                data = &data[len..];
                let record = match kind {
                    RecordType::A => {
                        chunk.resize(4, 0);
                        let octets: [u8; 4] = chunk.try_into().expect("IPv4 field");
                        RData::A(A(Ipv4Addr::from(octets)))
                    }
                    RecordType::AAAA => {
                        chunk.resize(16, 0);
                        let octets: [u8; 16] = chunk.try_into().expect("IPv6 field");
                        RData::AAAA(AAAA(Ipv6Addr::from(octets)))
                    }
                    _ => RData::CNAME(CNAME(self.domain.encode(&chunk)?)),
                };
                msg.add_answer(Record::from_rdata(name.clone(), 60, record));
            }
        }
        msg.to_vec().map_err(io::Error::other)
    }
}

pub(super) fn read_response(
    domains: &[Arc<Domain>],
    client: ClientId,
    wire: &[u8],
) -> Option<Vec<Vec<u8>>> {
    let msg = Message::from_vec(wire).ok()?;
    if msg.message_type() != MessageType::Response
        || msg.truncated()
        || msg.response_code() != ResponseCode::NoError
        || msg.queries().len() != 1
    {
        return None;
    }
    let question = msg.query()?;
    let domain = domains
        .iter()
        .find(|domain| domain.matches(question.name()))?;
    let kind = question.query_type();
    if !domain.supports(kind) {
        return None;
    }
    let payload = domain.decode(question.name())?;
    if read_uplink(kind, &payload)?.0 != client {
        return None;
    }
    let data = if kind == RecordType::TXT {
        let [answer] = msg.answers() else {
            return None;
        };
        if !domain.matches(answer.name()) {
            return None;
        }
        let RData::TXT(txt) = answer.data() else {
            return None;
        };
        txt.iter().flat_map(|chunk| chunk.iter().copied()).collect()
    } else {
        let mut chunks: Vec<Vec<u8>> = msg
            .answers()
            .iter()
            .filter(|answer| domain.matches(answer.name()))
            .filter_map(|answer| match (kind, answer.data()) {
                (RecordType::A, RData::A(addr)) => Some(addr.0.octets().to_vec()),
                (RecordType::AAAA, RData::AAAA(addr)) => Some(addr.0.octets().to_vec()),
                (RecordType::CNAME, RData::CNAME(name)) => {
                    domain.decode(&name.0).filter(|value| !value.is_empty())
                }
                _ => None,
            })
            .collect();
        chunks.sort_unstable_by_key(|chunk| chunk[0]);
        let first = chunks.first()?;
        if first.len() < 2 || first[0] != 0 || usize::from(first[1]) != chunks.len() {
            return None;
        }
        let mut data = first[2..].to_vec();
        for (index, chunk) in chunks.into_iter().enumerate().skip(1) {
            if usize::from(chunk[0]) != index {
                return None;
            }
            data.extend_from_slice(&chunk[1..]);
        }
        data
    };
    decode_packets(&data).ok()
}

fn decode_packets(mut data: &[u8]) -> io::Result<Vec<Vec<u8>>> {
    if data.len() > UDP_SIZE {
        return Err(malformed("XDNS answer packet list exceeds 4096 bytes"));
    }
    let mut packets = Vec::new();
    while let Some(header) = data.get(..2) {
        let size = usize::from(u16::from_be_bytes([header[0], header[1]]) & 0x3fff);
        let packet = data
            .get(2..2 + size)
            .ok_or_else(|| malformed("truncated XDNS answer packet"))?;
        packets.push(packet.to_vec());
        if header[0] & 0xc0 == 0xc0 {
            return Ok(packets);
        }
        data = &data[2 + size..];
    }
    Err(malformed("XDNS answer lacks its final packet"))
}

fn wire_name_len(name: &Name) -> usize {
    1 + name.iter().map(|label| label.len() + 1).sum::<usize>()
}

fn fill(bytes: &mut [u8]) -> io::Result<()> {
    OsRng
        .try_fill_bytes(bytes)
        .map_err(|error| io::Error::other(error.to_string()))
}
