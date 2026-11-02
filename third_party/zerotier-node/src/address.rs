// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// (c) ZeroTier, Inc.
// https://www.zerotier.com/
//
// Translated to Rust from ZeroTierOne tag 1.16.2: node/Address.hpp, node/MAC.hpp,
// node/MulticastGroup.hpp.

use std::fmt;
use std::net::IpAddr;

const RESERVED_PREFIX: u64 = 0xff;
const ADDRESS_MASK: u64 = 0xff_ffff_ffff;

/// A 40-bit ZeroTier node address.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Address(u64);

impl Address {
    pub const LENGTH: usize = 5;

    pub fn new(value: u64) -> Self {
        Self(value & ADDRESS_MASK)
    }
    pub fn from_bytes(bytes: &[u8; 5]) -> Self {
        let mut wide = [0; 8];
        wide[3..].copy_from_slice(bytes);
        Self(u64::from_be_bytes(wide))
    }
    pub fn to_bytes(self) -> [u8; 5] {
        let wide = self.0.to_be_bytes();
        [wide[3], wide[4], wide[5], wide[6], wide[7]]
    }
    pub fn value(self) -> u64 {
        self.0
    }
    pub fn is_reserved(self) -> bool {
        self.0 == 0 || (self.0 >> 32) == RESERVED_PREFIX
    }
    /// The controller address is the most significant 40 bits of a network ID.
    pub fn controller_of(network_id: u64) -> Self {
        Self(network_id >> 24)
    }
}

impl fmt::Display for Address {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:010x}", self.0)
    }
}

/// A 48-bit Ethernet MAC. Unicast MACs on a network derive from the node address.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Mac(u64);

fn network_mask(network_id: u64) -> u64 {
    (((network_id >> 8) & 0xff) << 32)
        ^ (((network_id >> 16) & 0xff) << 24)
        ^ (((network_id >> 24) & 0xff) << 16)
        ^ (((network_id >> 32) & 0xff) << 8)
        ^ ((network_id >> 40) & 0xff)
}

fn first_octet_for_network(network_id: u64) -> u8 {
    let octet = (network_id as u8 & 0xfe) | 0x02;
    if octet == 0x52 { 0x32 } else { octet }
}

impl Mac {
    pub const BROADCAST: Self = Self(0xffff_ffff_ffff);

    pub fn from_bytes(bytes: &[u8; 6]) -> Self {
        let mut wide = [0; 8];
        wide[2..].copy_from_slice(bytes);
        Self(u64::from_be_bytes(wide))
    }
    pub fn to_bytes(self) -> [u8; 6] {
        let wide = self.0.to_be_bytes();
        [wide[2], wide[3], wide[4], wide[5], wide[6], wide[7]]
    }
    pub fn from_address(address: Address, network_id: u64) -> Self {
        let first = u64::from(first_octet_for_network(network_id)) << 40;
        Self((first | address.value()) ^ network_mask(network_id))
    }
    pub fn to_address(self, network_id: u64) -> Address {
        Address::new((self.0 & ADDRESS_MASK) ^ network_mask(network_id))
    }
    pub fn is_multicast(self) -> bool {
        self.0 & 0x0100_0000_0000 != 0
    }
    pub fn is_zero(self) -> bool {
        self.0 == 0
    }
}

/// An Ethernet multicast address plus ZeroTier's additional distinguishing information.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct MulticastGroup {
    pub mac: Mac,
    pub adi: u32,
}

impl MulticastGroup {
    pub const BROADCAST: Self = Self {
        mac: Mac::BROADCAST,
        adi: 0,
    };

    /// The group a node joins to answer ARP or NDP for `ip`.
    pub fn for_address_resolution(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(ip) => Self {
                mac: Mac::BROADCAST,
                adi: u32::from(ip),
            },
            IpAddr::V6(ip) => {
                let octets = ip.octets();
                Self {
                    mac: Mac::from_bytes(&[0x33, 0x33, 0xff, octets[13], octets[14], octets[15]]),
                    adi: 0,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_derivation_is_reversible_and_avoids_reserved_first_octet() {
        let network_id = 0x8056_c2e2_1c00_0001;
        let address = Address::new(0x6c_386d_c869);
        let mac = Mac::from_address(address, network_id);
        assert_eq!(mac.to_address(network_id), address);
        assert_eq!(mac.to_bytes()[0] & 0x03, 0x02);
        assert!(!mac.is_multicast());
        assert_eq!(first_octet_for_network(0x52), 0x32);
    }

    #[test]
    fn address_resolution_groups_match_arp_and_ndp_conventions() {
        let group = MulticastGroup::for_address_resolution("10.1.2.3".parse().unwrap());
        assert_eq!(group.mac, Mac::BROADCAST);
        assert_eq!(group.adi, 0x0a01_0203);
        let group = MulticastGroup::for_address_resolution("fd00::ab:cdef".parse().unwrap());
        assert_eq!(group.mac.to_bytes(), [0x33, 0x33, 0xff, 0xab, 0xcd, 0xef]);
        assert_eq!(group.adi, 0);
    }

    #[test]
    fn reserved_addresses_are_detected() {
        assert!(Address::new(0).is_reserved());
        assert!(Address::new(0xff_0000_0001).is_reserved());
        assert!(!Address::new(0x6c_386d_c869).is_reserved());
    }
}
