// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// (c) ZeroTier, Inc.
// https://www.zerotier.com/
//
// Translated to Rust from ZeroTierOne tag 1.16.2: node/CertificateOfMembership.hpp,
// node/CertificateOfMembership.cpp.

use crate::address::Address;
use crate::identity::{Identity, SIGNATURE_LEN};
use crate::reader::Reader;

const MAX_QUALIFIERS: usize = 8;
const ID_TIMESTAMP: u64 = 0;
const ID_NETWORK_ID: u64 = 1;
const ID_ISSUED_TO: u64 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Qualifier {
    id: u64,
    value: u64,
    max_delta: u64,
}

/// Controller-signed proof of membership. Two members trust each other when their
/// certificates agree, meaning they were issued for the same network close enough in time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertificateOfMembership {
    qualifiers: Vec<Qualifier>,
    signed_by: Address,
    signature: [u8; SIGNATURE_LEN],
}

impl CertificateOfMembership {
    pub(crate) fn deserialize(reader: &mut Reader<'_>) -> Option<Self> {
        if reader.u8()? != 1 {
            return None;
        }
        let count = usize::from(reader.u16()?);
        if count > MAX_QUALIFIERS {
            return None;
        }
        let mut qualifiers = Vec::with_capacity(count);
        let mut last_id = 0;
        for _ in 0..count {
            let id = reader.u64()?;
            if id < last_id {
                return None;
            }
            last_id = id;
            qualifiers.push(Qualifier {
                id,
                value: reader.u64()?,
                max_delta: reader.u64()?,
            });
        }
        let signed_by = Address::from_bytes(&reader.array()?);
        let signature = if signed_by.value() == 0 {
            [0; SIGNATURE_LEN]
        } else {
            reader.array()?
        };
        Some(Self {
            qualifiers,
            signed_by,
            signature,
        })
    }

    pub(crate) fn serialize(&self, output: &mut Vec<u8>) {
        output.push(1);
        output.extend_from_slice(&(self.qualifiers.len() as u16).to_be_bytes());
        for qualifier in &self.qualifiers {
            output.extend_from_slice(&qualifier.id.to_be_bytes());
            output.extend_from_slice(&qualifier.value.to_be_bytes());
            output.extend_from_slice(&qualifier.max_delta.to_be_bytes());
        }
        output.extend_from_slice(&self.signed_by.to_bytes());
        if self.signed_by.value() != 0 {
            output.extend_from_slice(&self.signature);
        }
    }

    fn qualifier(&self, id: u64) -> Option<u64> {
        self.qualifiers
            .iter()
            .find(|qualifier| qualifier.id == id)
            .map(|qualifier| qualifier.value)
    }

    pub fn timestamp(&self) -> Option<u64> {
        self.qualifier(ID_TIMESTAMP)
    }
    pub fn network_id(&self) -> Option<u64> {
        self.qualifier(ID_NETWORK_ID)
    }
    pub fn issued_to(&self) -> Option<Address> {
        self.qualifier(ID_ISSUED_TO).map(Address::new)
    }
    pub fn signed_by(&self) -> Address {
        self.signed_by
    }

    /// Checks the signature against the network's controller.
    pub fn verify(&self, controller: &Identity) -> bool {
        if self.signed_by != controller.address() {
            return false;
        }
        let mut message = Vec::with_capacity(self.qualifiers.len() * 24);
        for qualifier in &self.qualifiers {
            message.extend_from_slice(&qualifier.id.to_be_bytes());
            message.extend_from_slice(&qualifier.value.to_be_bytes());
            message.extend_from_slice(&qualifier.max_delta.to_be_bytes());
        }
        controller.verify(&message, &self.signature)
    }

    /// Called on our own certificate with a peer's. Every qualifier of ours must exist in
    /// theirs within our maximum delta, and any identity hash must match their full identity.
    pub fn agrees_with(&self, other: &Self, other_identity: &Identity) -> bool {
        if self.qualifiers.is_empty() || other.qualifiers.is_empty() {
            return false;
        }
        let mut full_identity_verification = false;
        for qualifier in &self.qualifiers {
            if (3..=6).contains(&qualifier.id) {
                full_identity_verification = true;
            }
            let Some(value) = other.qualifier(qualifier.id) else {
                return false;
            };
            if qualifier.value.abs_diff(value) > qualifier.max_delta {
                return false;
            }
        }
        if full_identity_verification {
            let hash = other_identity.public_key_hash();
            for index in 0..4 {
                let start = index * 8;
                let expected = u64::from_be_bytes(
                    hash[start..start + 8]
                        .try_into()
                        .expect("hash range is 8 bytes"),
                );
                if other.qualifier(index as u64 + 3) != Some(expected) {
                    return false;
                }
            }
        }
        true
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    const WIDE: u64 = u64::MAX;

    /// Mirrors the upstream constructor that controllers use, signing with `controller`.
    pub(crate) fn issue(
        controller: &Identity,
        network_id: u64,
        member: &Identity,
        timestamp: u64,
        max_delta: u64,
    ) -> CertificateOfMembership {
        let hash = member.public_key_hash();
        let mut qualifiers = vec![
            Qualifier {
                id: ID_TIMESTAMP,
                value: timestamp,
                max_delta,
            },
            Qualifier {
                id: ID_NETWORK_ID,
                value: network_id,
                max_delta: 0,
            },
            Qualifier {
                id: ID_ISSUED_TO,
                value: member.address().value(),
                max_delta: WIDE,
            },
        ];
        for index in 0..4usize {
            let start = index * 8;
            qualifiers.push(Qualifier {
                id: index as u64 + 3,
                value: u64::from_be_bytes(hash[start..start + 8].try_into().unwrap()),
                max_delta: WIDE,
            });
        }
        let mut message = Vec::new();
        for qualifier in &qualifiers {
            message.extend_from_slice(&qualifier.id.to_be_bytes());
            message.extend_from_slice(&qualifier.value.to_be_bytes());
            message.extend_from_slice(&qualifier.max_delta.to_be_bytes());
        }
        CertificateOfMembership {
            qualifiers,
            signed_by: controller.address(),
            signature: controller.sign(&message).unwrap(),
        }
    }

    const CONTROLLER: &str = "6c386dc869:0:6b92e4ccfd2426e77d67f1e4d88ec6947f207054f6f8e71db4cd423be2031a4a30b73c8cf406e630ee51ac777f2af39c8f85a87a0d29c760ab7c3abc45db7a8e:0f48db623afef19c59353992b69aa426cfbe4146a362f19334f4461ac7dc042f3f98bca50ba4dca9c49a21a49fb664ca5d671af47a49fdaed668f746c2e94ff7";

    fn parties() -> (Identity, Identity, Identity) {
        let controller = Identity::parse(CONTROLLER).unwrap();
        // The memberships here never validate proof of work, so any well-formed public keys do.
        let member = |address: &str, byte: u8| {
            Identity::parse(&format!("{address}:0:{}", format!("{byte:02x}").repeat(64))).unwrap()
        };
        (controller, member("1111111111", 1), member("2222222222", 2))
    }

    const NETWORK: u64 = 0x6c38_6dc8_6900_0001;

    #[test]
    fn serialized_form_round_trips_and_signature_binds_contents() {
        let (controller, alice, _) = parties();
        let certificate = issue(&controller, NETWORK, &alice, 1000, 500);
        assert!(certificate.verify(&controller));
        assert_eq!(certificate.network_id(), Some(NETWORK));
        assert_eq!(certificate.issued_to(), Some(alice.address()));
        assert_eq!(certificate.timestamp(), Some(1000));

        let mut bytes = Vec::new();
        certificate.serialize(&mut bytes);
        assert_eq!(bytes.len(), 1 + 2 + 7 * 24 + 5 + 96);
        let mut reader = Reader::new(&bytes);
        let parsed = CertificateOfMembership::deserialize(&mut reader).unwrap();
        assert_eq!(parsed, certificate);
        assert_eq!(reader.remaining(), 0);

        bytes[3 + 8 + 7] ^= 1;
        let tampered = CertificateOfMembership::deserialize(&mut Reader::new(&bytes)).unwrap();
        assert!(!tampered.verify(&controller));
    }

    #[test]
    fn agreement_requires_same_network_recent_time_and_matching_identity() {
        let (controller, alice, bob) = parties();
        let ours = issue(&controller, NETWORK, &alice, 1000, 500);
        assert!(ours.agrees_with(&issue(&controller, NETWORK, &bob, 1400, 500), &bob));
        assert!(!ours.agrees_with(&issue(&controller, NETWORK, &bob, 1501, 500), &bob));
        assert!(!ours.agrees_with(&issue(&controller, NETWORK + 1, &bob, 1000, 500), &bob));
        // A certificate issued to someone else does not vouch for this identity.
        assert!(!ours.agrees_with(&issue(&controller, NETWORK, &alice, 1000, 500), &bob));
    }

    #[test]
    fn parse_rejects_bad_type_too_many_and_unordered_qualifiers() {
        assert!(CertificateOfMembership::deserialize(&mut Reader::new(&[2])).is_none());
        assert!(CertificateOfMembership::deserialize(&mut Reader::new(&[1, 0, 9])).is_none());
        let mut unordered = vec![1, 0, 2];
        for id in [5u64, 1] {
            unordered.extend_from_slice(&id.to_be_bytes());
            unordered.extend_from_slice(&[0; 16]);
        }
        unordered.extend_from_slice(&[0; 5]);
        assert!(CertificateOfMembership::deserialize(&mut Reader::new(&unordered)).is_none());
    }
}
