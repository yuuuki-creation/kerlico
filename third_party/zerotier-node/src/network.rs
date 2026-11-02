// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// (c) ZeroTier, Inc.
// https://www.zerotier.com/
//
// Translated to Rust from ZeroTierOne tag 1.16.2: node/NetworkConfig.hpp, node/NetworkConfig.cpp
// (fromDictionary), node/Network.cpp (handleConfigChunk), and the address embedding checks of
// Switch::onLocalEthernet in node/Switch.cpp.

use crate::address::Address;
use crate::certificate::CertificateOfMembership;
use crate::dictionary::Dictionary;
use crate::identity::{Identity, SIGNATURE_LEN};
use crate::inet;
use crate::reader::Reader;
use std::net::{IpAddr, Ipv6Addr};

const DICT_CAPACITY: usize = 1 << 20;
const MAX_INCOMING_UPDATES: usize = 3;
const MAX_UPDATE_CHUNKS: usize = 1024;
const MAX_ROUTES: usize = 128;
const MAX_ASSIGNED_ADDRESSES: usize = 32;
const MAX_SPECIALISTS: usize = 256;
const DEFAULT_MTU: u64 = 2800;
const MIN_MTU: u64 = 1280;
const MAX_MTU: u64 = 10000;
const MIN_DICT_VERSION: u64 = 6;

const FLAG_ENABLE_BROADCAST: u64 = 0x02;
const FLAG_ENABLE_IPV6_NDP_EMULATION: u64 = 0x04;
const SPECIALIST_TYPE_ACTIVE_BRIDGE: u64 = 0x0000_0200_0000_0000;
const TYPE_PUBLIC: u64 = 1;
const TYPE_PRIVATE: u64 = 0;

/// A managed route. `target` carries the network address with host bits as the controller sent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Route {
    pub target: IpAddr,
    pub prefix: u8,
    pub via: Option<IpAddr>,
    pub flags: u16,
    pub metric: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetworkConfig {
    pub network_id: u64,
    pub timestamp: u64,
    pub revision: u64,
    pub issued_to: Address,
    pub mtu: u32,
    pub multicast_limit: u32,
    pub com: Option<CertificateOfMembership>,
    pub routes: Vec<Route>,
    pub static_ips: Vec<(IpAddr, u8)>,
    flags: u64,
    network_type: u64,
    specialists: Vec<u64>,
}

impl NetworkConfig {
    /// A private network config with no addresses or routes, to be filled in by the caller.
    pub fn empty(network_id: u64, issued_to: Address) -> Self {
        Self {
            network_id,
            timestamp: 0,
            revision: 0,
            issued_to,
            mtu: DEFAULT_MTU as u32,
            multicast_limit: 0,
            com: None,
            routes: Vec::new(),
            static_ips: Vec::new(),
            flags: 0,
            network_type: TYPE_PRIVATE,
            specialists: Vec::new(),
        }
    }

    pub(crate) fn from_dictionary(data: &[u8]) -> Option<Self> {
        let dictionary = Dictionary::new(data);
        let network_id = dictionary.get_u64("nwid").filter(|value| *value != 0)?;
        let issued_to = dictionary.get_u64("id").filter(|value| *value != 0)?;
        if dictionary.get_u64("v").unwrap_or(0) < MIN_DICT_VERSION {
            return None;
        }
        let com = match dictionary.get("C") {
            Some(bytes) if !bytes.is_empty() => Some(CertificateOfMembership::deserialize(
                &mut Reader::new(&bytes),
            )?),
            _ => None,
        };
        let mut specialists = Vec::new();
        if let Some(bytes) = dictionary.get("S") {
            for chunk in bytes.chunks_exact(8).take(MAX_SPECIALISTS) {
                specialists.push(u64::from_be_bytes(chunk.try_into().ok()?));
            }
        }
        let mut routes = Vec::new();
        if let Some(bytes) = dictionary.get("RT") {
            let mut reader = Reader::new(&bytes);
            while reader.remaining() > 0 && routes.len() < MAX_ROUTES {
                let target = inet::deserialize(&mut reader)?;
                let via = inet::deserialize(&mut reader)?;
                let flags = reader.u16()?;
                let metric = reader.u16()?;
                if let Some(target) = target {
                    routes.push(Route {
                        target: target.ip(),
                        prefix: u8::try_from(target.port()).ok()?,
                        via: via.map(|via| via.ip()),
                        flags,
                        metric,
                    });
                }
            }
        }
        let mut static_ips = Vec::new();
        if let Some(bytes) = dictionary.get("I") {
            let mut reader = Reader::new(&bytes);
            while reader.remaining() > 0 && static_ips.len() < MAX_ASSIGNED_ADDRESSES {
                if let Some(address) = inet::deserialize(&mut reader)? {
                    static_ips.push((address.ip(), u8::try_from(address.port()).ok()?));
                }
            }
        }
        Some(Self {
            network_id,
            timestamp: dictionary.get_u64("ts").unwrap_or(0),
            revision: dictionary.get_u64("r").unwrap_or(0),
            issued_to: Address::new(issued_to),
            mtu: dictionary
                .get_u64("mtu")
                .unwrap_or(DEFAULT_MTU)
                .clamp(MIN_MTU, MAX_MTU) as u32,
            multicast_limit: dictionary
                .get_u64("ml")
                .unwrap_or(0)
                .min(u64::from(u32::MAX)) as u32,
            com,
            routes,
            static_ips,
            flags: dictionary.get_u64("f").unwrap_or(0),
            network_type: dictionary.get_u64("t").unwrap_or(TYPE_PRIVATE),
            specialists,
        })
    }

    pub fn is_public(&self) -> bool {
        self.network_type == TYPE_PUBLIC
    }
    pub fn enable_broadcast(&self) -> bool {
        self.flags & FLAG_ENABLE_BROADCAST != 0
    }
    pub(crate) fn active_bridges(&self) -> impl Iterator<Item = Address> + '_ {
        self.specialists
            .iter()
            .filter(|value| **value & SPECIALIST_TYPE_ACTIVE_BRIDGE != 0)
            .map(|value| Address::new(*value))
    }
}

/// The node address embedded in a ZT-RFC4193 or ZT-6PLANE destination that shares a prefix with
/// one of our assigned addresses. Such destinations need no neighbor discovery on the wire.
pub fn embedded_address(config: &NetworkConfig, destination: Ipv6Addr) -> Option<Address> {
    if config.flags & FLAG_ENABLE_IPV6_NDP_EMULATION == 0 {
        return None;
    }
    let target = destination.octets();
    let folded = ((config.network_id ^ (config.network_id >> 32)) & 0xffff_ffff) as u32;
    for (ip, bits) in &config.static_ips {
        let IpAddr::V6(ip) = ip else {
            continue;
        };
        let mine = ip.octets();
        let range = if *bits == 88 && mine[0] == 0xfd && mine[9] == 0x99 && mine[10] == 0x93 {
            (mine[..11] == target[..11]).then_some(11..16)
        } else if *bits == 40 && mine[0] == 0xfc && mine[1..5] == folded.to_be_bytes() {
            (mine[..5] == target[..5]).then_some(5..10)
        } else {
            None
        };
        if let Some(range) = range {
            return Some(Address::from_bytes(target[range].try_into().ok()?));
        }
    }
    None
}

#[derive(Default)]
struct IncomingUpdate {
    update_id: u64,
    age: u64,
    chunk_ids: Vec<u64>,
    data: Vec<u8>,
    have_bytes: usize,
}

/// Reassembles signed config chunks, which may belong to up to three concurrent updates.
#[derive(Default)]
pub(crate) struct ConfigAssembler {
    updates: Vec<IncomingUpdate>,
    clock: u64,
}

pub(crate) struct AssembledConfig {
    pub(crate) update_id: u64,
    pub(crate) config: NetworkConfig,
}

impl ConfigAssembler {
    /// `payload` starts at the network ID. Unsigned legacy chunks are only taken from the
    /// controller itself; everything else needs a valid controller signature.
    pub(crate) fn accept(
        &mut self,
        packet_id: u64,
        source: Address,
        controller: &Identity,
        payload: &[u8],
    ) -> Option<AssembledConfig> {
        let mut reader = Reader::new(payload);
        reader.skip(8)?;
        let chunk_length = usize::from(reader.u16()?);
        let chunk = reader.bytes(chunk_length)?;

        let (update_id, chunk_id, total, index) = if reader.remaining() > 0 {
            reader.skip(1)?;
            let update_id = reader.u64()?;
            let total = reader.u32()? as usize;
            let index = reader.u32()? as usize;
            if index.checked_add(chunk_length)? > total || total >= DICT_CAPACITY {
                return None;
            }
            let signed = &payload[..reader.position()];
            if reader.u8()? != 1 || usize::from(reader.u16()?) != SIGNATURE_LEN {
                return None;
            }
            let signature = reader.bytes(SIGNATURE_LEN)?;
            let mut chunk_id = [0u8; 8];
            for (position, byte) in signature[..16].iter().enumerate() {
                chunk_id[position & 7] ^= byte;
            }
            let chunk_id = u64::from_ne_bytes(chunk_id);
            if self.is_duplicate(update_id, chunk_id) || !controller.verify(signed, signature) {
                return None;
            }
            (update_id, chunk_id, total, index)
        } else if source == controller.address() {
            if chunk_length >= DICT_CAPACITY {
                return None;
            }
            (packet_id, packet_id, chunk_length, 0)
        } else {
            return None;
        };

        self.clock += 1;
        let clock = self.clock;
        let slot = self.slot_for(update_id);
        slot.age = clock;
        if slot.update_id != update_id {
            *slot = IncomingUpdate {
                update_id,
                age: clock,
                ..IncomingUpdate::default()
            };
        }
        if slot.chunk_ids.len() >= MAX_UPDATE_CHUNKS {
            return None;
        }
        slot.chunk_ids.push(chunk_id);
        if slot.data.len() < total {
            slot.data.resize(total, 0);
        }
        slot.data[index..index + chunk_length].copy_from_slice(chunk);
        slot.have_bytes += chunk_length;
        if slot.have_bytes != total {
            return None;
        }
        let config = NetworkConfig::from_dictionary(&slot.data[..total])?;
        Some(AssembledConfig { update_id, config })
    }

    fn is_duplicate(&self, update_id: u64, chunk_id: u64) -> bool {
        self.updates
            .iter()
            .any(|update| update.update_id == update_id && update.chunk_ids.contains(&chunk_id))
    }

    fn slot_for(&mut self, update_id: u64) -> &mut IncomingUpdate {
        if let Some(index) = self
            .updates
            .iter()
            .position(|update| update.update_id == update_id)
        {
            return &mut self.updates[index];
        }
        if self.updates.len() < MAX_INCOMING_UPDATES {
            self.updates.push(IncomingUpdate::default());
            return self.updates.last_mut().expect("just pushed");
        }
        self.updates
            .iter_mut()
            .min_by_key(|update| update.age)
            .expect("three slots exist")
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::certificate::tests::issue;

    pub(crate) const CONTROLLER: &str = "6c386dc869:0:6b92e4ccfd2426e77d67f1e4d88ec6947f207054f6f8e71db4cd423be2031a4a30b73c8cf406e630ee51ac777f2af39c8f85a87a0d29c760ab7c3abc45db7a8e:0f48db623afef19c59353992b69aa426cfbe4146a362f19334f4461ac7dc042f3f98bca50ba4dca9c49a21a49fb664ca5d671af47a49fdaed668f746c2e94ff7";
    const NETWORK: u64 = 0x6c38_6dc8_6900_0001;

    fn escape(bytes: &[u8]) -> Vec<u8> {
        let mut output = Vec::new();
        for byte in bytes {
            match byte {
                0 => output.extend_from_slice(b"\\0"),
                13 => output.extend_from_slice(b"\\r"),
                10 => output.extend_from_slice(b"\\n"),
                b'\\' => output.extend_from_slice(b"\\\\"),
                b'=' => output.extend_from_slice(b"\\e"),
                other => output.push(*other),
            }
        }
        output
    }

    /// Builds a dictionary in the same layout as `NetworkConfig::toDictionary`.
    pub(crate) fn dictionary_for(
        controller: &Identity,
        member: &Identity,
        ip: &str,
        timestamp: u64,
    ) -> Vec<u8> {
        let mut output = Vec::new();
        for (key, value) in [
            ("v", 7),
            ("nwid", NETWORK),
            ("ts", timestamp),
            ("r", 3),
            ("id", member.address().value()),
            ("f", FLAG_ENABLE_BROADCAST | FLAG_ENABLE_IPV6_NDP_EMULATION),
            ("ml", 32),
            ("t", TYPE_PRIVATE),
            ("mtu", 2800),
            ("ctmd", 7_200_000),
        ] {
            output.extend_from_slice(format!("{key}={value:x}\n").as_bytes());
        }
        let mut com = Vec::new();
        issue(controller, NETWORK, member, timestamp, 7_200_000).serialize(&mut com);
        output.extend_from_slice(b"C=");
        output.extend_from_slice(&escape(&com));
        output.push(b'\n');

        let mut route = Vec::new();
        inet::serialize("10.9.0.0:24".parse().unwrap(), &mut route);
        route.push(0);
        route.extend_from_slice(&[0, 0, 0, 1]);
        inet::serialize("192.168.9.0:24".parse().unwrap(), &mut route);
        inet::serialize("10.9.0.1:0".parse().unwrap(), &mut route);
        route.extend_from_slice(&[0, 0, 0, 2]);
        output.extend_from_slice(b"RT=");
        output.extend_from_slice(&escape(&route));
        output.push(b'\n');

        let mut ips = Vec::new();
        inet::serialize(format!("{ip}:24").parse().unwrap(), &mut ips);
        output.extend_from_slice(b"I=");
        output.extend_from_slice(&escape(&ips));
        output.push(b'\n');
        output
    }

    pub(crate) fn signed_chunk(
        controller: &Identity,
        dictionary: &[u8],
        update_id: u64,
        range: std::ops::Range<usize>,
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&NETWORK.to_be_bytes());
        payload.extend_from_slice(&(range.len() as u16).to_be_bytes());
        payload.extend_from_slice(&dictionary[range.clone()]);
        payload.push(0);
        payload.extend_from_slice(&update_id.to_be_bytes());
        payload.extend_from_slice(&(dictionary.len() as u32).to_be_bytes());
        payload.extend_from_slice(&(range.start as u32).to_be_bytes());
        let signature = controller.sign(&payload).unwrap();
        payload.push(1);
        payload.extend_from_slice(&(SIGNATURE_LEN as u16).to_be_bytes());
        payload.extend_from_slice(&signature);
        payload
    }

    fn member() -> Identity {
        Identity::parse(&format!("1111111111:0:{}", "01".repeat(64))).unwrap()
    }

    #[test]
    fn dictionary_decodes_assigned_addresses_routes_and_certificate() {
        let controller = Identity::parse(CONTROLLER).unwrap();
        let member = member();
        let config =
            NetworkConfig::from_dictionary(&dictionary_for(&controller, &member, "10.9.0.7", 5000))
                .unwrap();
        assert_eq!(config.network_id, NETWORK);
        assert_eq!(config.issued_to, member.address());
        assert_eq!(config.mtu, 2800);
        assert_eq!(config.multicast_limit, 32);
        assert!(!config.is_public());
        assert!(config.enable_broadcast());
        assert_eq!(config.static_ips, vec![("10.9.0.7".parse().unwrap(), 24)]);
        assert_eq!(config.routes.len(), 2);
        assert_eq!(config.routes[0].via, None);
        assert_eq!(config.routes[1].via, Some("10.9.0.1".parse().unwrap()));
        assert_eq!(config.routes[1].metric, 2);
        assert!(config.com.unwrap().verify(&controller));
    }

    #[test]
    fn older_dictionary_versions_and_missing_identifiers_are_refused() {
        assert!(NetworkConfig::from_dictionary(b"v=5\nnwid=1\nid=1\n").is_none());
        assert!(NetworkConfig::from_dictionary(b"v=7\nid=1\n").is_none());
        assert!(NetworkConfig::from_dictionary(b"v=7\nnwid=1\n").is_none());
    }

    #[test]
    fn signed_chunks_assemble_out_of_order_and_duplicates_do_not_complete() {
        let controller = Identity::parse(CONTROLLER).unwrap();
        let dictionary = dictionary_for(&controller, &member(), "10.9.0.7", 5000);
        let middle = dictionary.len() / 2;
        let first = signed_chunk(&controller, &dictionary, 42, 0..middle);
        let second = signed_chunk(&controller, &dictionary, 42, middle..dictionary.len());
        let stranger = Address::new(0x22_2222_2222);

        let mut assembler = ConfigAssembler::default();
        assert!(
            assembler
                .accept(1, stranger, &controller, &second)
                .is_none()
        );
        assert!(
            assembler
                .accept(1, stranger, &controller, &second)
                .is_none()
        );
        let done = assembler.accept(2, stranger, &controller, &first).unwrap();
        assert_eq!(done.update_id, 42);
        assert_eq!(done.config.timestamp, 5000);
    }

    #[test]
    fn forged_chunks_and_foreign_legacy_chunks_are_refused() {
        let controller = Identity::parse(CONTROLLER).unwrap();
        let dictionary = dictionary_for(&controller, &member(), "10.9.0.7", 5000);
        let mut forged = signed_chunk(&controller, &dictionary, 42, 0..dictionary.len());
        forged[12] ^= 1;
        let mut assembler = ConfigAssembler::default();
        assert!(
            assembler
                .accept(1, controller.address(), &controller, &forged)
                .is_none()
        );

        let mut legacy = Vec::new();
        legacy.extend_from_slice(&NETWORK.to_be_bytes());
        legacy.extend_from_slice(&(dictionary.len() as u16).to_be_bytes());
        legacy.extend_from_slice(&dictionary);
        assert!(
            assembler
                .accept(2, Address::new(0x22_2222_2222), &controller, &legacy)
                .is_none()
        );
        assert!(
            assembler
                .accept(3, controller.address(), &controller, &legacy)
                .is_some()
        );
    }

    #[test]
    fn embedded_addresses_follow_rfc4193_and_sixplane_layouts() {
        let controller = Identity::parse(CONTROLLER).unwrap();
        let mut config = NetworkConfig::from_dictionary(&dictionary_for(
            &controller,
            &member(),
            "10.9.0.7",
            5000,
        ))
        .unwrap();
        config.static_ips = vec![("fd6c:386d:c869:0:199:9311:1111:1111".parse().unwrap(), 88)];
        let target = "fd6c:386d:c869:0:199:93aa:bbcc:ddee".parse().unwrap();
        assert_eq!(
            embedded_address(&config, target).unwrap().value(),
            0xaa_bbcc_ddee
        );
        assert!(embedded_address(&config, "fd00::1".parse().unwrap()).is_none());

        let folded = ((NETWORK ^ (NETWORK >> 32)) & 0xffff_ffff) as u32;
        let mut mine = [0u8; 16];
        mine[0] = 0xfc;
        mine[1..5].copy_from_slice(&folded.to_be_bytes());
        mine[5..10].copy_from_slice(&[0x11; 5]);
        config.static_ips = vec![(IpAddr::V6(mine.into()), 40)];
        let mut target = mine;
        target[5..10].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
        assert_eq!(
            embedded_address(&config, target.into()).unwrap().value(),
            0xaa_bbcc_ddee
        );
    }
}
