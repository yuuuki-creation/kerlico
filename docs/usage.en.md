# Usage Guide

[简体中文](usage.md)

`kerlico` is a single executable. A JSON, JSONC, YAML, or TOML configuration makes it a proxy client, a proxy server, or both.

## Install

Download the Linux `x86_64` `kerlico` binary from [Releases](https://github.com/yuuuki-creation/kerlico/releases) and verify it with `SHA256SUMS`. It needs glibc 2.34 or newer.

To build from source, use Rust `1.99.1`:

```sh
export PROTOC="$(tools/fetch_protoc.sh ~/.cache/kerlico)"
cargo build --locked --release -p kerlico
```

Only the EasyTier outbound needs `protoc`. Otherwise select protocols with `--no-default-features`.

## Commands

| Command | Purpose |
| --- | --- |
| `kerlico run -c <file> [-C <dir>]` | Start with single or merged multi-file configs, `SIGHUP` hot reload, and graceful shutdown on `Ctrl-C` / `SIGTERM` |
| `kerlico check -c <file> [-C <dir>]` | Validate configuration and module capabilities without opening ports |
| `kerlico format -c <file> [-w]` | Format configuration files |
| `kerlico merge [output] -c <f1> -c <f2> [-C <dir>]` | Deep-merge multiple configuration files or directories |
| `kerlico modules` | List the protocols and inbound/outbound roles in this build |
| `kerlico account-new --prefix <name>` | Read an admin password from stdin and print account JSON |
| `kerlico history --kind <kind>` | Query statistics history (`usage`, `flows`, `bandwidth`, or `events`) |
| `kerlico rule-set <compile\|decompile\|convert\|format\|match\|merge\|upgrade>` | Compile, decompile, convert (`.srs`/`.mrs`/JSON/YAML), format, merge, and test rule-sets |
| `kerlico geoip / geosite <list\|lookup\|export> -f <db>` | List categories, look up IPs/domains, or export rule-sets from GeoIP / Geosite databases |
| `kerlico generate <uuid\|rand\|reality-keypair\|wg-keypair\|ech-keypair\|tls-keypair\|vlessenc\|mldsa65\|mlkem768>` | Generate UUIDs, random bytes, and X25519/WireGuard/ECH/TLS/post-quantum/VLESS keys |
| `kerlico tls <cert\|ping>` | Generate self-signed TLS certificates with SHA-256 fingerprints or probe remote TLS servers |
| `kerlico tools <connect\|fetch\|resolve\|synctime> [-c <cfg> -o <tag>]` | Diagnose TCP connectivity, HTTP fetching, DNS resolution, and NTP time sync |

The global `--lang zh-CN` or `--lang en` option selects the output language. Environment variables `KERLICO_LOG_LEVEL`, `KERLICO_CONTROL_LISTEN`, `KERLICO_CONTROL_SECRET`, and `KERLICO_EXTERNAL_UI` override the matching settings at startup.

## Configuration

`kerlico` accepts JSON v2, JSONC (with comments), YAML (including anchors `&`/`*`/`<<`), and TOML, and can also load Mihomo (`proxies`/`proxy-groups`/`rules`) and sing-box (`inbounds`/`outbounds`/`route`) configurations directly:

- `outbounds`: named outbounds and proxy groups (`select`, `url-test`, `fallback`, `load-balance`, `balancer`), with `dialer-proxy` / `detour` chaining.
- `proxy_providers`: file, HTTP, or inline subscription providers (Mihomo YAML, Base64 subscriptions, and URI lines with field `override`).
- `nodes`: public or local protocol nodes (`mixed`, `redirect`, `tproxy`, `tun`, `masque`, `openvpn`, and 20 other protocols) authenticated via `members`.
- `local_inbounds` / `inbounds`: loopback-bound protocol entries and fixed-target port forwards.
- `routes` / `rule_providers`: rules matching domain, CIDR, GeoIP/GeoSite, `rule-set` (`.srs`/`.mrs`/JSON/YAML), process, sniffed protocol, or boolean logic (`and`/`or`) with actions (`route`, `sniff`, `resolve`, `hijack-dns`, `reject`).
- `accounts`, `telemetry`, `device`, `dns`, `ntp`, `control`, `limits`: accounts, statistics, WARP, DNS (including Fake-IP and DoH/DoQ), built-in NTP, control interface, and limits.

Field details are in the [configuration interface](interfaces/config.md) (Chinese). Protocol `options` are in the [interface documents](interfaces/README.md).

## As a client

[examples/client-routes-v2.json](../examples/client-routes-v2.json) opens a local SOCKS port. Traffic goes to a remote proxy by default, LAN addresses go direct, and ad domains are rejected. Replace the `options` of `proxy` with your server and run:

```sh
kerlico run -c client-routes-v2.json
```

## As a server

Create an admin account first:

```sh
printf '%s' 'your-admin-password' | kerlico account-new --prefix alice
```

Put the output in `accounts`, then use its `user_id` as a node member. Create separate nodes for IPv4 and IPv6. Each node has its own credentials and quotas. Protocol `options` and `native_credential` are in the matching interface document.

```json
{
  "version": 2,
  "accounts": [{ "user_id": "...", "username": "...", "password_hash": "..." }],
  "outbounds": [{ "tag": "direct", "type": "direct" }],
  "nodes": [{
    "tag": "ss-v4",
    "type": "ss2022",
    "listen": "0.0.0.0:8388",
    "outbound": "direct",
    "options": { "method": "2022-blake3-aes-128-gcm" },
    "members": [{ "user_id": "...", "native_credential": { "key": "<Base64 key>" } }]
  }]
}
```

## Routing and rule-sets

Rules match in order and the first match wins. Unmatched traffic uses the node's `outbound`. Rules can match domain, keyword, regex, CIDR, port, network, node, user, sniffed protocol (TLS SNI, HTTP Host, QUIC SNI, BitTorrent, SSH, RDP), and external rule-sets. When `sniff` or Fake-IP is enabled, IP targets recover their domain name for domain rule matching.

## WARP fill-in

On an IPv4-only or IPv6-only machine, configure `device` so `direct` traffic from `dual-stack` nodes can reach the missing family through Cloudflare WARP:

```json
"device": { "state_directory": "/var/lib/kerlico/device" }
```

It registers with Cloudflare once when first needed and keeps the identity in this directory. The path must be absolute with mode `0700`.

## Tunnel and overlay networks

`wireguard`, `masque`, and `openvpn` support both client outbound and server inbound roles; `openconnect`, `tailscale`, `easytier`, and `zerotier` connect to a remote network as client outbounds. Reference their `tag` from a node or a rule. Options and limits are in the [interface documents](interfaces/README.md).

## TUN

[examples/tun-v2.json](../examples/tun-v2.json) creates a `kerlico0` interface and hands its TCP and UDP to an outbound. It supports `auto-route`, `auto-redirect` (nftables), `strict-route`, and `auto-detect-interface` loop prevention, and pairs with Fake-IP and packet sniffing to recover domain names. It needs `CAP_NET_ADMIN` on Linux.

## DNS and Fake-IP

The `dns` section configures upstreams (`udp://`, `tcp://`, `tls://`, `https://` DoH, `quic://` DoQ), dual-stack Fake-IP pools (`198.18.0.0/15` and `fc00::/18`), optimistic caching, EDNS Client Subnet (ECS), DNS routing rules, and static `hosts`. Without it, the system resolver is used.

## Control interface and Web UI

The `control` section enables the HTTP/WebSocket control plane, serving both read-only `/v1/*` endpoints (`/v1/health`, `/v1/usage`, `/v1/online`, `/v1/flows`, `/v1/stats`) and Clash/Mihomo-compatible endpoints (`/proxies`, `/connections`, `/rules`, `/configs`, `/logs`, `/traffic`, `/memory`, `/dns/query`, `/cache/fakeip/flush`) plus static Web UI hosting at `/ui` (`external_ui`):

```sh
curl -H 'Authorization: Bearer <secret>' http://127.0.0.1:9090/v1/usage
curl -H 'Authorization: Bearer <secret>' http://127.0.0.1:9090/proxies
```

A non-loopback `listen` address requires `secret`.

## Statistics

With `telemetry` configured, usage, bandwidth, access records, DNS and error events go to SQLite:

```sh
kerlico history --directory state/telemetry --kind usage
kerlico history --directory state/telemetry --kind events --limit 100
```
