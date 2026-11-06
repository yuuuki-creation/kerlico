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
- `proxy_providers`: file, HTTP, or inline subscription providers (Mihomo YAML, Base64 subscriptions, and `vmess://`/`ss://`/`ssr://`/`vless://`/`trojan://`/`hy2://`/`tuic://`/`anytls://`/`wg://` share links with field `override`).
- `nodes`: public or local protocol nodes (`mixed`, `redirect`, `tproxy`, `tun`, `masque`, `openvpn`, and 20 other protocols) authenticated via `members`.
- `local_inbounds` / `inbounds`: loopback-bound protocol entries and fixed-target port forwards, plus top-level Mihomo `port`, `socks-port`, `mixed-port`, `allow-lan`, and `bind-address`.
- `routes` / `rule_providers` / `sub_rules`: rules matching domain, CIDR, GeoIP/GeoSite, `rule-set` (`.srs`/`.mrs`/JSON/YAML), local process (`PROCESS-NAME*`/`PROCESS-PATH*`), sniffed protocol, `SUB-RULE`, or boolean logic (`and`/`or`/`not`) with actions (`route`, `sniff`, `resolve`, `hijack-dns`, `reject`).
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

## Subscriptions, remote rule-sets, and Geo data

`proxy_providers` of type `http`, `rule_set` entries with `type: remote`, and `rule_providers` of type `http` download from their URL and cache the content at `path` (default `proxies/<name>` or `rules/<tag>`, relative to the working directory).

- **Download path**: when `proxy` or `download_detour` names an outbound or proxy group, the download goes through it and that outbound receives the target domain. Empty or `DIRECT` downloads directly. HTTP and HTTPS, up to 5 redirects, gzip, `header`, and `size-limit` are supported (0 or unset caps the body at 64 MiB). When the previous response carried `ETag` or `Last-Modified`, the request is conditional and a 304 keeps the current content.
- **Startup**: a cache younger than `interval` is used as is; otherwise the resource downloads first. If the download fails and a cache exists, the stale cache is used and a log entry is written. A rule-set referenced by route or DNS rules with no cache and a failed download stops startup. A missing file for a `type: local` rule-set or a `file` rule provider fails the configuration check. A provider with no content has no members, `GET /providers/proxies/<name>` reports `error`, and groups that use it reject connections.
- **Refresh**: resources refresh in the background every `interval` (sing-box `update_interval`, default `1d`). Rule-sets are replaced in place and new connections match the new content immediately. When provider content changes, the engine is rebuilt from the current configuration so new members take effect; inbounds close briefly and existing connections drain within `drain_timeout_ms`. Content that fails validation (for example a provider with no usable proxies) does not overwrite the cache.
- **Manual refresh**: `PUT /providers/proxies/<name>` and `PUT /providers/rules/<name>` refresh immediately and return 503 with `message` on failure.
- **Geo data**: the `geoip`, `geosite`, `mmdb`, and `asn` entries of `geox-url` download to `GeoIP.dat`, `GeoSite.dat`, `Country.mmdb`, and `GeoLite2-ASN.mmdb` in the working directory. With `geo-auto-update: true` they refresh every `geo-update-interval` hours (default 24); `POST /upgrade/geo` downloads them immediately. Runtime GeoIP/GeoSite rules still use the built-in category tables and do not read these files yet.

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

After editing the configuration, send `kill -HUP <pid>` or call `PUT /configs`. kerlico reads the configuration again and replaces the running engine. If the new configuration is invalid, the old one keeps serving. During the switch the listeners close briefly and new connections are refused; existing sessions drain within `limits.drain_timeout_ms`. The `reloads` counters in `/v1/health` show the result:

```sh
curl -X PUT -H 'Authorization: Bearer <secret>' -d '{}' http://127.0.0.1:9090/configs
```

`PUT /configs` also accepts `payload` (configuration text) or an absolute `path` inside the startup configuration directory, as in Mihomo. Changes to `control.listen`, adding or removing the `control` section, and `device` changes need a process restart.

## Statistics

With `telemetry` configured, usage, bandwidth, access records, DNS and error events go to SQLite:

```sh
kerlico history --directory state/telemetry --kind usage
kerlico history --directory state/telemetry --kind events --limit 100
```
