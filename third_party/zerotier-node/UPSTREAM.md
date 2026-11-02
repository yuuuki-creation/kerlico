# Upstream

This crate is a Rust translation of parts of ZeroTierOne and is licensed under MPL-2.0 (see `LICENSE`).

- Project: ZeroTierOne, (c) ZeroTier, Inc., https://www.zerotier.com/
- Tag: `1.16.2`
- Commit: `fc5c3ec22090b5b2a0f274e863651fe9ca489bf4`
- Upstream license for these files: `LICENSE-MPL.txt` (MPL-2.0). None carries an "Incompatible With Secondary Licenses" notice.
- Never read or derived from: `nonfree/`, `ext/`, or any tag under the Business Source License.

## Source files

| This crate | Upstream `node/` files |
| --- | --- |
| `src/address.rs` | `Address.hpp`, `MAC.hpp`, `MulticastGroup.hpp` |
| `src/certificate.rs` | `CertificateOfMembership.hpp`, `CertificateOfMembership.cpp` |
| `src/dictionary.rs` | `Dictionary.hpp` |
| `src/identity.rs` | `Identity.hpp`, `Identity.cpp`, `ECC.hpp`, `ECC.cpp` |
| `src/inet.rs` | `InetAddress.hpp` |
| `src/network.rs` | `NetworkConfig.hpp`, `NetworkConfig.cpp`, `Network.cpp`, `Switch.cpp` |
| `src/node.rs` | `Switch.cpp`, `IncomingPacket.cpp`, `Peer.cpp`, `Peer.hpp`, `Network.cpp`, `Membership.cpp`, `Multicaster.cpp`, `Topology.cpp`, `Constants.hpp` |
| `src/packet.rs` | `Packet.hpp`, `Packet.cpp`, `Switch.cpp` |
| `src/reader.rs` | `Buffer.hpp` |
| `src/world.rs` | `World.hpp`, `Topology.cpp` (`ZT_DEFAULT_WORLD`, copied byte for byte) |

## Differences from upstream

- Cryptographic primitives and LZ4 come from Rust crates instead of the upstream C++: `x25519-dalek`, `ed25519-dalek`, `salsa20`, `poly1305`, `sha2`, `lz4_flex`.
- Reduced to a sans-IO client for one network. Removed: relaying, the flow rule engine, bridging, multipath and bonding, AES-GMAC-SIV, extended armor, trusted paths, moons and world updates, tracing and metrics.
- HELLO advertises protocol version 11 and software version 1.4.8, the last versions before AES-GMAC-SIV, so peers select Salsa20/12 with Poly1305.
