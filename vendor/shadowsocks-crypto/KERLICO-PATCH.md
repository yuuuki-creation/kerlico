# Shadowsocks 2022 in Kerlico

The workspace patches these verified crates.io packages:

| Package | Upstream commit | Package SHA-256 |
| --- | --- | --- |
| `shadowsocks-crypto` 0.8.0 | [2ac3f4f](https://github.com/shadowsocks/shadowsocks-crypto/tree/2ac3f4f6194476ff7b7be2a43c3a83e33510663b) | `b404a62ebea5003f44b9a2748dee7555c5f9ae39896508e466a2a91ee6fa5df5` |
| `shadowsocks` 1.25.0 | [ab388c7](https://github.com/shadowsocks/shadowsocks-rust/tree/ab388c7466d21f979430e33cc9ef10e22fb05955) | `e2065b026dbe4f47048eca384adf07f693bf901050d80abd3adb7b2422709b2d` |

The patch registers SIP022's optional ChaCha12 method under the existing
`v2-extra` feature. The reduced-round wrappers use the same RustCrypto crate
and the same derives and nonce handling as the existing methods. The
Shadowsocks UDP layer uses the cipher's nonce length for all three XChaCha
methods. Those methods use the PSK directly and need no per-session cipher
cache. AES retains its per-session derive and cache.

See the MIT license files for [`shadowsocks-crypto`](LICENSE) and
[`shadowsocks`](../shadowsocks/LICENSE); include both notices with binaries.
