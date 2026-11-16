# BoringTun in Kerlico

This is the crates.io `boringtun` 0.7.1 package from upstream commit
[`051c9d47`](https://github.com/cloudflare/boringtun/tree/051c9d47dc9c5cb36e461b7d36dcd673820dc98b).
The package SHA-256 is `15dd6a8a89cbe8997f37ca0cf035e6ea4d64cd2ecea4aed83ffb9f99f7126939`.
The upstream BSD terms are in [LICENSE.md](LICENSE.md).

- `Tunn::set_preshared_key` changes only the key mixed into the next handshake
  response, whether the local peer creates or verifies it. Existing transport
  keys, replay state, timers and packet queues keep their normal lifetimes.
- `Tunn::take_handshake_completed` exposes the moment a handshake is confirmed
  without changing session selection. An initiator verifies the response, and
  a responder receives authenticated transport under the new keys.
- `RateLimiter` binds cookies to the source IP and UDP port with a two-minute
  rotation. Kerlico uses `VerifiedPacket` to route datagrams through one
  interface-wide limiter before passing them to the peer's Noise state.
- Under load, valid cookies are followed by the Linux admission rate of 20
  handshakes per second with a burst of 5 per IPv4 address or IPv6 /64.
- Receive replay protection uses the 8,128-packet window from 64-bit Linux
  WireGuard and wireguard-go, with the Linux receive counter ceiling.
- `Tunn::reset_transport` clears ephemeral keys and queued packets when a Linux
  interface goes down while retaining the last authenticated handshake timestamp.

The handshake calculation is unchanged. Use the upstream crate again when it
offers the same operations.
