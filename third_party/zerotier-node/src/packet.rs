// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// (c) ZeroTier, Inc.
// https://www.zerotier.com/
//
// Translated to Rust from ZeroTierOne tag 1.16.2: node/Packet.hpp, node/Packet.cpp, and the
// fragmentation step of Switch::_sendViaSpecificPath in node/Switch.cpp. LZ4 comes from the
// lz4_flex crate; Salsa20/12 and Poly1305 come from the salsa20 and poly1305 crates.

use crate::address::Address;
use poly1305::Poly1305;
use poly1305::universal_hash::KeyInit;
use rand::RngCore;
use salsa20::Salsa12;
use salsa20::cipher::{KeyIvInit, StreamCipher};
use zeroize::Zeroizing;

pub(crate) const IDX_DESTINATION: usize = 8;
pub(crate) const IDX_SOURCE: usize = 13;
pub(crate) const IDX_FLAGS: usize = 18;
pub(crate) const IDX_MAC: usize = 19;
pub(crate) const IDX_VERB: usize = 27;
pub(crate) const IDX_PAYLOAD: usize = 28;
pub(crate) const MIN_PACKET_LENGTH: usize = IDX_PAYLOAD;

pub(crate) const FRAGMENT_IDX_INDICATOR: usize = 13;
pub(crate) const FRAGMENT_IDX_NUMBER: usize = 14;
pub(crate) const FRAGMENT_IDX_PAYLOAD: usize = 16;
pub(crate) const FRAGMENT_INDICATOR: u8 = 0xff;

pub(crate) const PHYSICAL_MTU: usize = 1432;
pub(crate) const MAX_FRAGMENTS: usize = 7;
pub(crate) const MAX_PACKET_LENGTH: usize = MAX_FRAGMENTS * PHYSICAL_MTU;

pub(crate) const FLAG_EXTENDED_ARMOR: u8 = 0x80;
pub(crate) const FLAG_FRAGMENTED: u8 = 0x40;
const VERB_FLAG_COMPRESSED: u8 = 0x80;

pub(crate) const CIPHER_POLY1305_NONE: u8 = 0;
pub(crate) const CIPHER_POLY1305_SALSA2012: u8 = 1;

pub(crate) mod verb {
    pub(crate) const HELLO: u8 = 0x01;
    pub(crate) const ERROR: u8 = 0x02;
    pub(crate) const OK: u8 = 0x03;
    pub(crate) const WHOIS: u8 = 0x04;
    pub(crate) const RENDEZVOUS: u8 = 0x05;
    pub(crate) const FRAME: u8 = 0x06;
    pub(crate) const EXT_FRAME: u8 = 0x07;
    pub(crate) const ECHO: u8 = 0x08;
    pub(crate) const MULTICAST_LIKE: u8 = 0x09;
    pub(crate) const NETWORK_CREDENTIALS: u8 = 0x0a;
    pub(crate) const NETWORK_CONFIG_REQUEST: u8 = 0x0b;
    pub(crate) const NETWORK_CONFIG: u8 = 0x0c;
    pub(crate) const MULTICAST_GATHER: u8 = 0x0d;
    pub(crate) const MULTICAST_FRAME: u8 = 0x0e;
}

pub(crate) mod error_code {
    pub(crate) const OBJ_NOT_FOUND: u8 = 0x03;
    pub(crate) const IDENTITY_COLLISION: u8 = 0x04;
    pub(crate) const UNSUPPORTED_OPERATION: u8 = 0x05;
    pub(crate) const NEED_MEMBERSHIP_CERTIFICATE: u8 = 0x06;
    pub(crate) const NETWORK_ACCESS_DENIED: u8 = 0x07;
    pub(crate) const UNWANTED_MULTICAST: u8 = 0x08;
    pub(crate) const NETWORK_AUTHENTICATION_REQUIRED: u8 = 0x09;
}

pub(crate) fn new_packet(
    destination: Address,
    source: Address,
    verb: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut packet = vec![0u8; IDX_PAYLOAD + payload.len()];
    rand::rngs::OsRng.fill_bytes(&mut packet[..8]);
    packet[IDX_DESTINATION..IDX_SOURCE].copy_from_slice(&destination.to_bytes());
    packet[IDX_SOURCE..IDX_FLAGS].copy_from_slice(&source.to_bytes());
    packet[IDX_VERB] = verb;
    packet[IDX_PAYLOAD..].copy_from_slice(payload);
    packet
}

pub(crate) fn packet_id(packet: &[u8]) -> u64 {
    u64::from_be_bytes(packet[..8].try_into().expect("packet has a full header"))
}

pub(crate) fn source(packet: &[u8]) -> Address {
    Address::from_bytes(
        packet[IDX_SOURCE..IDX_FLAGS]
            .try_into()
            .expect("address range is 5 bytes"),
    )
}

pub(crate) fn destination(packet: &[u8]) -> Address {
    Address::from_bytes(
        packet[IDX_DESTINATION..IDX_SOURCE]
            .try_into()
            .expect("address range is 5 bytes"),
    )
}

pub(crate) fn cipher(packet: &[u8]) -> u8 {
    (packet[IDX_FLAGS] & 0x38) >> 3
}

/// Only meaningful with the clear cipher: before protocol 13 the same bit was a legacy
/// "encrypted" flag, which ZeroTierOne 1.14 still sets on every encrypted packet.
pub(crate) fn is_extended_armor(packet: &[u8]) -> bool {
    packet[IDX_FLAGS] & FLAG_EXTENDED_ARMOR != 0 && cipher(packet) == CIPHER_POLY1305_NONE
}

pub(crate) fn hops(packet: &[u8]) -> u8 {
    packet[IDX_FLAGS] & 0x07
}

pub(crate) fn verb_of(packet: &[u8]) -> u8 {
    packet[IDX_VERB] & 0x1f
}

/// Derives the per-packet key from IV, addresses, flags (hops masked) and total size.
fn mangle_key(key: &[u8; 32], packet: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut mangled = Zeroizing::new(*key);
    for index in 0..IDX_FLAGS {
        mangled[index] ^= packet[index];
    }
    mangled[18] ^= packet[IDX_FLAGS] & 0xf8;
    mangled[19] ^= packet.len() as u8;
    mangled[20] ^= (packet.len() >> 8) as u8;
    mangled
}

fn packet_cipher(key: &[u8; 32], packet: &[u8]) -> (Salsa12, Zeroizing<[u8; 32]>) {
    let mangled = mangle_key(key, packet);
    let iv: [u8; 8] = packet[..8].try_into().expect("packet has a full header");
    let mut cipher = Salsa12::new(&(*mangled).into(), &iv.into());
    // The first keystream block supplies the MAC key; its second half is discarded.
    let mut block = Zeroizing::new([0u8; 64]);
    cipher.apply_keystream(&mut block[..]);
    let mut mac_key = Zeroizing::new([0u8; 32]);
    mac_key.copy_from_slice(&block[..32]);
    (cipher, mac_key)
}

fn packet_mac(mac_key: &[u8; 32], data: &[u8]) -> [u8; 8] {
    let tag = Poly1305::new(mac_key.into()).compute_unpadded(data);
    let mut mac = [0; 8];
    mac.copy_from_slice(&tag.as_slice()[..8]);
    mac
}

pub(crate) fn armor(packet: &mut [u8], key: &[u8; 32], encrypt: bool) {
    let suite = if encrypt {
        CIPHER_POLY1305_SALSA2012
    } else {
        CIPHER_POLY1305_NONE
    };
    packet[IDX_FLAGS] = (packet[IDX_FLAGS] & !FLAG_EXTENDED_ARMOR & 0xc7) | (suite << 3);
    let (mut cipher, mac_key) = packet_cipher(key, packet);
    if encrypt {
        cipher.apply_keystream(&mut packet[IDX_VERB..]);
    }
    let mac = packet_mac(&mac_key, &packet[IDX_VERB..]);
    packet[IDX_MAC..IDX_VERB].copy_from_slice(&mac);
}

/// Authenticates and decrypts. AES-GMAC-SIV is never negotiated because HELLO advertises
/// protocol version 11, so only the two Salsa20/12 suites are accepted.
pub(crate) fn dearmor(packet: &mut [u8], key: &[u8; 32]) -> bool {
    let suite = cipher(packet);
    if suite != CIPHER_POLY1305_NONE && suite != CIPHER_POLY1305_SALSA2012 {
        return false;
    }
    if is_extended_armor(packet) {
        return false;
    }
    let (mut stream, mac_key) = packet_cipher(key, packet);
    let mac = packet_mac(&mac_key, &packet[IDX_VERB..]);
    let difference = mac
        .iter()
        .zip(&packet[IDX_MAC..IDX_VERB])
        .fold(0u8, |acc, (left, right)| acc | (left ^ right));
    if difference != 0 {
        return false;
    }
    if suite == CIPHER_POLY1305_SALSA2012 {
        stream.apply_keystream(&mut packet[IDX_VERB..]);
    }
    true
}

/// Masks the tail of HELLO. Keyed by the unmangled key, so it must not repeat within a packet.
pub(crate) fn crypt_field(packet: &mut [u8], key: &[u8; 32], start: usize) {
    let mut iv: [u8; 8] = packet[..8].try_into().expect("packet has a full header");
    iv[7] &= 0xf8;
    Salsa12::new(key.into(), &iv.into()).apply_keystream(&mut packet[start..]);
}

pub(crate) fn uncompress(packet: &mut Vec<u8>) -> bool {
    if packet[IDX_VERB] & VERB_FLAG_COMPRESSED == 0 {
        return true;
    }
    if packet.len() > IDX_PAYLOAD {
        let mut output = vec![0u8; MAX_PACKET_LENGTH];
        let Ok(count) = lz4_flex::block::decompress_into(&packet[IDX_PAYLOAD..], &mut output)
        else {
            return false;
        };
        if count == 0 {
            return false;
        }
        packet.truncate(IDX_PAYLOAD);
        packet.extend_from_slice(&output[..count]);
    }
    packet[IDX_VERB] &= !VERB_FLAG_COMPRESSED;
    true
}

/// Armors and splits into datagrams. Fragment headers are unauthenticated: the MAC over the
/// assembled packet covers fragment content.
pub(crate) fn seal(mut packet: Vec<u8>, key: &[u8; 32], encrypt: bool) -> Option<Vec<Vec<u8>>> {
    if packet.len() > MAX_PACKET_LENGTH {
        return None;
    }
    if packet.len() <= PHYSICAL_MTU {
        packet[IDX_FLAGS] &= !FLAG_FRAGMENTED;
        armor(&mut packet, key, encrypt);
        return Some(vec![packet]);
    }
    packet[IDX_FLAGS] |= FLAG_FRAGMENTED;
    armor(&mut packet, key, encrypt);
    let chunk = PHYSICAL_MTU - FRAGMENT_IDX_PAYLOAD;
    let rest = &packet[PHYSICAL_MTU..];
    let total = 1 + rest.len().div_ceil(chunk);
    if total > MAX_FRAGMENTS {
        return None;
    }
    let mut output = Vec::with_capacity(total);
    output.push(packet[..PHYSICAL_MTU].to_vec());
    for (index, data) in rest.chunks(chunk).enumerate() {
        let mut fragment = Vec::with_capacity(FRAGMENT_IDX_PAYLOAD + data.len());
        fragment.extend_from_slice(&packet[..FRAGMENT_IDX_INDICATOR]);
        fragment.push(FRAGMENT_INDICATOR);
        fragment.push(((total as u8) << 4) | (index as u8 + 1));
        fragment.push(0);
        fragment.extend_from_slice(data);
        output.push(fragment);
    }
    Some(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7; 32];

    fn sample(payload: &[u8]) -> Vec<u8> {
        let mut packet = new_packet(
            Address::new(0x11_2233_4455),
            Address::new(0x66_7788_99aa),
            verb::FRAME,
            payload,
        );
        packet[..8].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        packet
    }

    #[test]
    fn header_layout_matches_upstream_indexes() {
        let packet = sample(b"xy");
        assert_eq!(packet_id(&packet), 0x0102_0304_0506_0708);
        assert_eq!(destination(&packet).value(), 0x11_2233_4455);
        assert_eq!(source(&packet).value(), 0x66_7788_99aa);
        assert_eq!(packet[IDX_VERB], 0x06);
        assert_eq!(&packet[IDX_PAYLOAD..], b"xy");
    }

    #[test]
    fn encrypted_packet_round_trips_and_detects_tampering() {
        let mut packet = sample(b"payload bytes");
        armor(&mut packet, &KEY, true);
        assert_eq!(cipher(&packet), CIPHER_POLY1305_SALSA2012);
        assert_ne!(&packet[IDX_PAYLOAD..IDX_PAYLOAD + 7], b"payload");

        let mut good = packet.clone();
        assert!(dearmor(&mut good, &KEY));
        assert_eq!(&good[IDX_PAYLOAD..], b"payload bytes");

        let mut wrong_key = packet.clone();
        assert!(!dearmor(&mut wrong_key, &[8; 32]));

        let mut flipped = packet.clone();
        *flipped.last_mut().unwrap() ^= 1;
        assert!(!dearmor(&mut flipped, &KEY));

        let mut truncated = packet.clone();
        truncated.pop();
        assert!(!dearmor(&mut truncated, &KEY));
    }

    #[test]
    fn hop_count_changes_do_not_break_authentication() {
        let mut packet = sample(b"relayed");
        armor(&mut packet, &KEY, true);
        packet[IDX_FLAGS] += 2;
        assert_eq!(hops(&packet), 2);
        assert!(dearmor(&mut packet, &KEY));
        assert_eq!(&packet[IDX_PAYLOAD..], b"relayed");
    }

    #[test]
    fn hello_cipher_authenticates_without_encrypting() {
        let mut packet = sample(b"clear");
        armor(&mut packet, &KEY, false);
        assert_eq!(cipher(&packet), CIPHER_POLY1305_NONE);
        assert_eq!(&packet[IDX_PAYLOAD..], b"clear");
        assert!(dearmor(&mut packet, &KEY));
        *packet.last_mut().unwrap() ^= 1;
        assert!(!dearmor(&mut packet, &KEY));
    }

    #[test]
    fn extended_armor_and_unknown_ciphers_are_refused() {
        let mut clear = sample(b"x");
        armor(&mut clear, &KEY, false);
        clear[IDX_FLAGS] |= FLAG_EXTENDED_ARMOR;
        assert!(!dearmor(&mut clear, &KEY));

        let mut aes = sample(b"x");
        armor(&mut aes, &KEY, true);
        aes[IDX_FLAGS] = (aes[IDX_FLAGS] & 0xc7) | (3 << 3);
        assert!(!dearmor(&mut aes, &KEY));
    }

    #[test]
    fn legacy_encrypted_flag_from_older_peers_is_accepted() {
        // The flag is covered by the key mangling, so a sender sets it before computing the MAC.
        let mut packet = sample(b"from 1.14");
        packet[IDX_FLAGS] = FLAG_EXTENDED_ARMOR | (CIPHER_POLY1305_SALSA2012 << 3);
        let (mut stream, mac_key) = packet_cipher(&KEY, &packet);
        stream.apply_keystream(&mut packet[IDX_VERB..]);
        let mac = packet_mac(&mac_key, &packet[IDX_VERB..]);
        packet[IDX_MAC..IDX_VERB].copy_from_slice(&mac);
        assert!(dearmor(&mut packet, &KEY));
        assert_eq!(&packet[IDX_PAYLOAD..], b"from 1.14");
    }

    #[test]
    fn compressed_payload_is_expanded_and_corrupt_input_rejected() {
        let plain = vec![0x41u8; 900];
        let compressed = lz4_flex::block::compress(&plain);
        let mut packet = sample(&compressed);
        packet[IDX_VERB] |= VERB_FLAG_COMPRESSED;
        assert!(uncompress(&mut packet));
        assert_eq!(verb_of(&packet), verb::FRAME);
        assert_eq!(&packet[IDX_PAYLOAD..], &plain[..]);

        let mut corrupt = sample(&[0xf0, 0xff]);
        corrupt[IDX_VERB] |= VERB_FLAG_COMPRESSED;
        assert!(!uncompress(&mut corrupt));
    }

    #[test]
    fn large_packet_splits_into_upstream_fragment_layout_and_reassembles() {
        let payload: Vec<u8> = (0..3000u32).map(|value| value as u8).collect();
        let datagrams = seal(sample(&payload), &KEY, true).unwrap();
        assert_eq!(datagrams.len(), 3);
        assert_eq!(datagrams[0].len(), PHYSICAL_MTU);
        assert_ne!(datagrams[0][IDX_FLAGS] & FLAG_FRAGMENTED, 0);
        let mut assembled = datagrams[0].clone();
        for (index, fragment) in datagrams[1..].iter().enumerate() {
            assert_eq!(fragment[..8], datagrams[0][..8]);
            assert_eq!(fragment[8..13], datagrams[0][8..13]);
            assert_eq!(fragment[FRAGMENT_IDX_INDICATOR], FRAGMENT_INDICATOR);
            assert_eq!(fragment[FRAGMENT_IDX_NUMBER], 0x30 | (index as u8 + 1));
            assert_eq!(fragment[15], 0);
            assert!(fragment.len() <= PHYSICAL_MTU);
            assembled.extend_from_slice(&fragment[FRAGMENT_IDX_PAYLOAD..]);
        }
        assert!(dearmor(&mut assembled, &KEY));
        assert_eq!(&assembled[IDX_PAYLOAD..], &payload[..]);
    }

    #[test]
    fn oversized_packets_are_refused() {
        assert!(seal(sample(&vec![0; MAX_PACKET_LENGTH]), &KEY, true).is_none());
    }
}
