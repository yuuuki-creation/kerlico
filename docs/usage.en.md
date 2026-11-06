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
| `kerlico rule-set <compile\|decompile\|convert\|format\|match\|merge\|upgrade>` | Convert rule-sets between sing-box source JSON, `.srs`, and Mihomo yaml/text/`.mrs`; format, merge, and test targets |
| `kerlico geoip / geosite <list\|lookup\|export> -f <db>` | Read `geoip.dat`/`geosite.dat`/`.mmdb`: list categories, look up IPs/domains/ASNs, export rule-sets |
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

### Mihomo proxy compatibility

Top-level `proxies`, `proxy-providers` members (Mihomo YAML), and share links use one field mapping table (`crates/config/src/mihomo.rs`). The three forms of one node produce the same kerlico `options`. An entry with a `tag` or `options` key (such as the JSON subscription `[{"tag":"n1","type":"direct"}]`) is a native kerlico outbound and is kept as written. A native entry allows only `tag` (or `name` when `options` is present), `type`, and `options`; any other field is an error.

- Field leniency follows the Mihomo structure decoder. A key matches exactly first, then case-insensitively with `_` read as `-` (`disable_mtu_discovery` equals `disable-mtu-discovery`). The mapping table records the fields that each Mihomo option struct in `adapter/outbound/*.go` defines for the type:
  - A field that Mihomo does not define for the type is ignored silently, for example `up` on vmess or `udp` on hysteria2. A subscription `override` writes its fields into every member, and these fields do not affect loading.
  - A field that Mihomo defines, that kerlico does not implement, and that changes security or routing semantics fails that proxy when its value takes effect. The error names the proxy and the field path. These fields are `tls` (for example socks5 `tls: true`), `fingerprint`, `name-cert-verify`, `certificate`, `private-key`, `ech-opts`, `reality-opts` (types other than VLESS), `shadow-tls-opts`, `restls-opts`, `jls-opts`, `tlsmirror-opts`, `realm-opts`, `disable-sni: true`, `remote-dns-resolve: true`, and any `ip-version` other than `dual`. Values `false`, empty strings, and `enable: false` take no effect and load normally.
  - Other unimplemented fields print a warning with the proxy name and field path on stderr and are ignored, for example trojan `alpn`, tuic `reduce-rtt: true`, `udp: false` (kerlico still carries UDP according to the protocol), and unknown keys inside `ws-opts`.
  - Without TLS, Mihomo does not read TLS fields such as `sni`, `servername`, `alpn`, `client-fingerprint`, and `skip-cert-verify`, and kerlico ignores them too. Only the `*-opts` that matches the selected `network` is read.
- Subscription members map one by one. A failing member is skipped and the other members load. A stderr warning and `CompiledProxyProvider.failed_members` list each failing member with its error. Top-level `proxies` also map one by one. If a failing proxy is referenced by `proxy-groups[].proxies` or by a rule, config loading fails with its error. An unreferenced failing proxy is skipped with a warning.
- Common fields: `interface-name`, `routing-mark`, `dialer-proxy`, `tfo`, and `mptcp` go to the dialer and apply to every TCP and UDP carrier socket of the node. For UDP and QUIC protocols, `dialer-proxy` carries datagrams through the upstream outbound's UDP channel; unsupported combinations (see [core interfaces](interfaces/core.md#出站套接字工厂)) fail at load time. kerlico carries UDP according to each protocol's capability. `udp: false` turns UDP off only for SSR, Hysteria, TrustTunnel, and Sudoku.
- `skip-cert-verify: true` maps to the skip-verification option of each TLS carrier and prints one warning on stderr: vmess `tls.insecure`, trojan `security.insecure`, vless `security.allow_insecure`, anytls/http/hysteria/hysteria2/tuic/trusttunnel/gost-relay `tls.insecure`, and ss `plugin-opts` (`plugin_opts.skip_cert_verify` for v2ray-plugin/gost-plugin, `tls.insecure` for shadow-tls). REALITY nodes do not read it. sing-box `tls.insecure` uses the same options.
- `client-fingerprint` sends a uTLS ClientHello (xray-transport profiles) for the Mihomo values `chrome`, `firefox`, `safari`, `ios`, `android`, `edge`, `qq`, `random`, `randomized`, `chrome120`, `firefox120`, and `safari16`. Versions follow the `*_Auto` aliases of the utls that Mihomo uses (`firefox` is Firefox 120, `safari` is Safari 16.0). The ClientHello carries the profile's full cipher suite list; CBC and RSA key exchange suites that kerlico lacks appear only in the list, and a server that picks one fails the handshake. An empty value or `none` sends an unshaped hello; any other value prints a warning and sends an unshaped hello, as in Mihomo. `360` does the same, because the 360 7.5 profile offers only cipher suites kerlico lacks. It maps to vmess `tls.fingerprint`, trojan/vless `security.fingerprint`, anytls/trusttunnel/gost-relay `tls.fingerprint`, and `tls.fingerprint` of ss `plugin: shadow-tls` (v3 writes its authenticated session ID into the shaped hello), across the tcp, ws, httpupgrade, and grpc transports of vmess/trojan/vless. Mihomo does not define the field for hysteria, hysteria2, tuic, http, or socks5, and kerlico ignores it there too; trusttunnel with `quic: true` is not shaped. Top-level `global-client-fingerprint` is the default for proxies and subscription members without `client-fingerprint` (Mihomo v1.18 behavior; Mihomo v1.19 removed the key). `tools/compare_client_hello.py` compares the ClientHello of kerlico and mihomo for one fingerprint on a worker.
- `alpn` maps on VLESS, Hysteria, TUIC, and ShadowQUIC; Hysteria2 accepts only `[h3]`.
- Unsupported types: `masque` (Mihomo's WARP-style key authentication differs from the kerlico MASQUE client) and `rematch`.

| Mihomo `type` | kerlico type | Supported fields | Common unimplemented fields (fail or warn by the rules above) |
| --- | --- | --- | --- |
| `ss` | `shadowsocks`; `2022-*` ciphers become `ss2022`; `plugin: shadow-tls` becomes `shadowtls` | `cipher`, `password` (2022 as `iPSK:uPSK`), `udp-over-tcp`, `udp-over-tcp-version`, `smux`, `plugin: obfs` (`mode`, `host`), `plugin: v2ray-plugin`/`gost-plugin` (`mode: websocket`, `tls`, `host`, `path`, `mux`, `headers`, `v2ray-http-upgrade`), `shadow-tls` (`host`, `password`, `version`, `alpn`) | `plugin: restls`/`kcptun`/`jls`, `plugin-opts.fingerprint`; legacy non-AEAD ciphers get `allow_insecure` automatically |
| `ssr` | `shadowsocksr` | `cipher`, `password`, `protocol`, `obfs`, `protocol-param`, `obfs-param`, `udp` | none |
| `snell` | `snell` | `psk`, `version` (3, 4), `reuse`, `obfs-opts.mode: http`, `obfs-opts.host` | `version` 1, 2, 5 or absent (Mihomo default 1), `obfs-opts.mode: tls` |
| `vmess` | `vmess` | `uuid`, `alterId: 0`, `cipher` (`auto`, `aes-128-gcm`, `chacha20-poly1305`, `zero`), `global-padding` (default false, as in Mihomo), `authenticated-length`, `tls`, `servername`, `network: tcp/ws/grpc`, `ws-opts.path`, `ws-opts.headers.Host`, `ws-opts.v2ray-http-upgrade`, `grpc-opts.grpc-service-name`, `smux` | non-zero `alterId`, `cipher: none`, `xudp`/`packet-encoding`, `network: h2/http`, `ws-opts` headers other than `Host`, `max-early-data` |
| `vless` | `vless` | `uuid`, `flow`, `encryption`, `packet-encoding`, `xudp`, `packet-addr`, `tls`, `servername`, `client-fingerprint`, `alpn`, `skip-cert-verify`, `reality-opts.public-key`, `reality-opts.short-id`, `network: tcp/ws/grpc`, `ws-opts` (`path`, `headers`, `max-early-data`, `early-data-header-name: Sec-WebSocket-Protocol`, `v2ray-http-upgrade`), `grpc-opts` (`grpc-service-name`, `grpc-user-agent`), `smux` | `network: h2/http/xhttp`, `ws-headers`, `fingerprint` |
| `trojan` | `trojan` | `password`, `sni`, `network: tcp/ws/grpc` with the matching `*-opts` (as VLESS), `ss-opts.enabled: false`, `client-fingerprint`, `skip-cert-verify`, `smux` | `alpn`, `ss-opts.enabled: true`, `reality-opts` |
| `anytls` | `anytls` | `password`, `sni`, `idle-session-timeout` | `idle-session-check-interval`, `min-idle-session`, `client-metadata`, `alpn` |
| `http` | `http` | `username`, `password`, `tls`, `sni`, `headers` | `fingerprint` |
| `socks5` | `socks` | `username`, `password`, `udp` | `tls: true`, `fingerprint` |
| `hysteria` | `hysteria1` | `ports`, `hop-interval`, `auth-str`, `auth`, `up`/`down` (or `up-speed`/`down-speed`; no unit means Mbps; required), `obfs`, `protocol`/`obfs-protocol` (`udp`, `wechat-video`), `sni`, `alpn`, `ca-str`, `udp` | `protocol: faketcp`, `ca` (path), `recv-window*`, `fast-open: true` |
| `hysteria2` | `hysteria2` | `ports`, `hop-interval` (integer or `15-30`), `password`, `up`, `down` (when set, negotiated as Brutal; units in the [Hysteria2 interface](interfaces/hysteria2.md)), `skip-cert-verify`, `obfs: salamander`, `obfs-password`, `sni`, `ca-str` | `obfs: gecko`, `realm-opts`, `bbr-profile`, receive windows, `cwnd`, `udp-mtu` |
| `tuic` | `tuic` | `token` (V4) or `uuid` + `password` (V5), `ip`, `ports`, `hop-interval`, `sni`, `alpn`, `ca-str`, `heartbeat-interval`, `udp-relay-mode`, `congestion-controller` (`cubic`, `new_reno`, `bbr`) | `disable-sni: true`, `reduce-rtt: true`, `request-timeout`, `max-udp-relay-packet-size`, `max-open-streams`, `udp-over-stream: true` |
| `shadowquic` | `shadowquic` | `username`, `password`, `sni`, `alpn`, `udp-over-stream`, `congestion-controller` | `zero-rtt: true`, `quic-versions`, `up`, `down`, window fields |
| `wireguard` | `wireguard` | `ip`, `ipv6` (prefix length removed), `private-key`, `public-key`, `pre-shared-key`, `reserved`, `allowed-ips` (default `0.0.0.0/0`, `::/0`), `persistent-keepalive`, `mtu`, a single `peers` entry | several `peers`, `dns`, `remote-dns-resolve: true`, `amnezia-wg-option`, `ip-stack`, `workers` |
| `ssh` | `ssh` | `username`, `password`, `private-key` (PEM or path), `private-key-passphrase`, `host-key` (converted to `SHA256:` pins) | missing `host-key` (kerlico requires pinned host keys), `host-key-algorithms` |
| `mieru` | `mieru` | `port` or `port-range`, `transport: TCP`, `username`, `password`, `multiplexing`, `handshake-mode` | `transport: UDP`, `traffic-pattern` |
| `sudoku` | `sudoku` | `key`, `aead-method`, `padding-min`, `padding-max`, `table-type`, `custom-table`, `custom-tables`, `enable-pure-downlink`, `httpmask` (`disable`, `mode`, `tls`, `host`, `path-root`, `multiplex`), `udp` | legacy flat `http-mask*` fields |
| `trusttunnel` | `trusttunnel` | `username`, `password`, `sni`, `quic`, `max-connections`, `max-streams`, `health-check: true`, `udp` | `min-streams`, `congestion-controller`, `bbr-profile`, `health-check: false` |
| `gost-relay` | `gost-relay` | `username`, `password`, `mux`, `tls`, `sni`; without `tls` it gets `allow_insecure` automatically | `forward` |
| `tailscale` | `tailscale` | `auth-key`, `control-url` (default: the official control plane), `hostname`, `ephemeral`, `accept-routes`, `exit-node` | `state-dir`, `exit-node-allow-lan-access` |
| `openvpn` | `openvpn` | `server`, `port`, `proto`, `username`, `password`, `ca` (PEM text), `cert`, `key`, `tls-auth`, `key-direction`, `auth`, `tls-crypt`, `tls-crypt-v2`, `cipher`, `data-ciphers`, `ping`, `ping-restart`, `handshake-timeout`, `mtu` | `peer-info`, `tran-window`, `dev`, `comp-lzo`, `dns`, `ip-stack` |
| `easytier` | `easytier` | `network-name`, `network-secret`, `peers`, `hostname`, `ipv4`, `dhcp`, `secure-mode`, `exit-nodes`, `enable-encryption`, `encryption-algorithm` | listeners, P2P, KCP/QUIC proxy, `mtu`, and the other fields |
| `zerotier` | `zerotier` | `network`, `identity-secret`, `tcp-fallback-mode`, `tcp-fallback-relay`; uses the public planet | `planet`, `state-dir`, port and MTU fields |
| `direct`, `reject`, `dns` | same name | common fields | everything else |

Share links: `ss://` (including SIP002 `plugin=obfs-local`/`v2ray-plugin`), `ssr://`, `vmess://` (v2rayN Base64 JSON and URL form), `vless://`, `trojan://`, `hysteria2://`/`hy2://`, `hysteria://`, `tuic://`, `socks://`/`socks5://`, `http://`/`https://`, `anytls://`, and `wireguard://`/`wg://`. Link parameters become the Mihomo fields above first. An unknown parameter fails and the error names it.

`proxy-providers.<name>.override` follows the Mihomo order. `filter`, `exclude-filter`, and `exclude-type` run first on the original name. Then `tfo`, `mptcp`, `udp`, `udp-over-tcp`, `up`, `down`, `dialer-proxy`, `skip-cert-verify`, `name-cert-verify`, `interface-name`, `routing-mark`, and `ip-version` overwrite the member's Mihomo proxy map. The result goes through the same field mapping as a hand-written proxy. As in Mihomo, an override field that the type lacks is ignored (for example `up` on a vmess member), and a value whose semantics kerlico cannot implement fails only that member (for example `ip-version: ipv6`). Names change in this order: `proxy-name` (regex `pattern` replaced by `target`, `$1` refers to a capture group, rules run in list order), `additional-prefix`, then `additional-suffix`. `pattern` uses Rust `regex` syntax, without look-around or backreferences. Native kerlico members (with `tag` or `options`) accept only the name options, and a field override on them is an error. `override-expr` is not supported.

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

Rules match in order and the first match wins. Unmatched traffic uses the node's `outbound`. The top-level `mode` works as in Mihomo: `rule` (default) applies the rules, `global` sends everything to the `GLOBAL` select group, and `direct` sends everything to `DIRECT`. `PATCH /configs` switches it at runtime. When no group or outbound is named `GLOBAL`, kerlico creates one whose members are `DIRECT`, `REJECT`, the configured outbounds, and then the groups. Rules can match domain, keyword, regex, CIDR, port, network, node, user, sniffed protocol (TLS SNI, HTTP Host, QUIC SNI, BitTorrent, SSH, RDP), and external rule-sets. When `sniff` or Fake-IP is enabled, IP targets recover their domain name for domain rule matching.

## Subscriptions, remote rule-sets, and Geo data

`proxy_providers` of type `http`, `rule_set` entries with `type: remote`, and `rule_providers` of type `http` download from their URL and cache the content at `path` (default `proxies/<name>` or `rules/<tag>`, relative to the working directory).

- **Download path**: when `proxy` or `download_detour` names an outbound or proxy group, the download goes through it and that outbound receives the target domain. Empty or `DIRECT` downloads directly. HTTP and HTTPS, up to 5 redirects, gzip, `header`, and `size-limit` are supported (0 or unset caps the body at 64 MiB). When the previous response carried `ETag` or `Last-Modified`, the request is conditional and a 304 keeps the current content.
- **Startup**: a cache younger than `interval` is used as is; otherwise the resource downloads first. If the download fails and a cache exists, the stale cache is used and a log entry is written. A rule-set referenced by route or DNS rules with no cache and a failed download stops startup. A missing file for a `type: local` rule-set or a `file` rule provider fails the configuration check. A provider with no content has no members, `GET /providers/proxies/<name>` reports `error`, and groups that use it reject connections.
- **Refresh**: resources refresh in the background every `interval` (sing-box `update_interval`, default `1d`). Rule-sets are replaced in place and new connections match the new content immediately. When provider content changes, the engine is rebuilt from the current configuration so new members take effect; inbounds close briefly and existing connections drain within `drain_timeout_ms`. Content that fails validation (for example a provider with no usable proxies) does not overwrite the cache.
- **Manual refresh**: `PUT /providers/proxies/<name>` and `PUT /providers/rules/<name>` refresh immediately and return 503 with `message` on failure.
- **Geo data**: see the next section.

## Geo data and rule-set formats

`GEOSITE`, `GEOIP`, `IP-ASN`, `SRC-GEOIP`, and `SRC-IP-ASN` (native fields `geosite`, `geoip`, `ip_asn`, `source_geoip`, `source_ip_asn`) read database files in the working directory:

| Rule | File | Notes |
| --- | --- | --- |
| `GEOSITE` | `GeoSite.dat` (V2Ray format) | Write `cn`, `cn@cn` (entries must carry the attribute), or `!cn` (negated). Entry types: plain is a substring, regex a regular expression, domain the domain and its subdomains, full an exact match |
| `GEOIP`, `geodata-mode: false` (default) | `Country.mmdb` | MaxMind GeoLite2-Country (`country.iso_code`), `sing-geoip`, and Mihomo `geoip.metadb` (`Meta-geoip0`) |
| `GEOIP`, `geodata-mode: true` | `GeoIP.dat` (V2Ray format) | `lan` matches private, loopback, and link-local addresses without reading a file |
| `IP-ASN` | `GeoLite2-ASN.mmdb` | GeoLite2-ASN, DB-IP ASN Lite, and ipinfo ASN databases |

- **Only referenced categories load**: startup decodes only the categories and attribute combinations that rules reference. A referenced category missing from the file fails the configuration check and the error names it. `mmdb` files map IPs to codes and have no category list to check.
- **Download**: files come from the `geoip`, `geosite`, `mmdb`, and `asn` entries of `geox-url`. When a rule needs a file and `geox-url` does not name it, the Mihomo default URL (MetaCubeX/meta-rules-dat) is used. A needed file that is missing downloads at startup, and startup fails if the download fails. With `geo-auto-update: true` files refresh every `geo-update-interval` hours (default 24); `POST /upgrade/geo` downloads them immediately. A new file that decodes is swapped in whole and new connections use it without a restart. A new file that lacks a referenced category is rejected, the old data stays, and the API returns 503.
- **Options**: every value of `geodata-loader` (`standard`, `memconservative`) and `geosite-matcher` (`mph`, `succinct`, `default`) uses the same implementation: a compact hash table probed label by label. geosite:cn (about 110,000 entries) takes about 3 MiB.
- **Differences**: `cn@!cn` selects entries without the `cn` attribute; Mihomo treats `!cn` as an attribute name and gets an empty set. `GEOIP,private` checks private ranges and does not read a database.

Rule-set files support these formats:

| Source | Format | Notes |
| --- | --- | --- |
| sing-box `rule_set` | `source` (JSON), `binary` (`.srs`, versions 1–5) | Without `format` the content decides. A `domain_suffix` starting with `.` matches subdomains only. Platform conditions such as `query_type`, `package_name`, `wifi_*`, and `network_type` never hold for routed connections, as in sing-box. AdGuard domain items and `network_interface_address` are not supported yet and fail to load |
| Mihomo `rule-providers` | `yaml` (default, needs `payload:`), `text`, `mrs` | Behaviors `domain`, `ipcidr`, `classical`; `mrs` supports the first two. Domain syntax: `example.com` exact, `.example.com` subdomains only, `+.example.com` the domain and its subdomains, `*` one label. Invalid entries are skipped |

`kerlico rule-set convert <input> -o <output>` detects the input format from its content and writes the format named by the output extension (`.srs`, `.mrs`, `.yaml`, `.txt`/`.list`, `.json`). Pass `--behavior` for Mihomo text input. `compile` writes `.srs` unless the output name ends in `.mrs`. `match <rule-set> <targets...>` prints one JSON line per target. `geosite -f GeoSite.dat lookup [--code cn] <domains...>` and `geoip -f Country.mmdb lookup <IPs...>` look up membership; with an ASN database the output has `asn` and `organization`.

## WARP fill-in

On an IPv4-only or IPv6-only machine, configure `device` so `direct` traffic from `dual-stack` nodes can reach the missing family through Cloudflare WARP:

```json
"device": { "state_directory": "/var/lib/kerlico/device" }
```

It registers with Cloudflare once when first needed and keeps the identity in this directory. The path must be absolute with mode `0700`.

## Tunnel and overlay networks

`wireguard`, `masque`, and `openvpn` support both client outbound and server inbound roles; `openconnect`, `tailscale`, `easytier`, and `zerotier` connect to a remote network as client outbounds. Reference their `tag` from a node or a rule. Options and limits are in the [interface documents](interfaces/README.md).

An OpenVPN server node runs in TLS mode only and needs a server certificate and private key. It can verify client certificates against a CA, a CRL, pinned fingerprints, and `verify-x509-name`, and it can authenticate members by password. Each client gets its own address from the `address` pool, receives a `PUSH_REPLY` built from `push`, and returns the address when it disconnects. Official OpenVPN 2.6 and 2.4 clients connect directly. See the [OpenVPN interface](interfaces/openvpn.md#服务端入站nodeoptions) for the fields.

## TUN

[examples/tun-v2.json](../examples/tun-v2.json) creates a `kerlico0` interface and hands its TCP and UDP to an outbound. A Mihomo top-level `tun:` section works as is:

```yaml
tun:
  enable: true
  stack: system
  auto-route: true
  strict-route: true
  auto-detect-interface: true
  dns-hijack: [any:53, tcp://any:53]
```

On Linux, `auto-route` installs routing table 2022 and policy rules from priority 9000, one set for IPv4 and one for IPv6. `strict-route` makes an address family unreachable when the TUN has no address in it. `auto-redirect` uses nftables to hand TCP to the kernel stack. When `routing-mark` is not set, every kerlico outbound and DNS upstream socket carries mark `0x2024`, the policy rules let that mark bypass the TUN, and sockets bind the physical egress interface by default, so kerlico's own traffic does not loop into the TUN. `route-address-set` and `route-exclude-address-set` reference rule sets, and the routing table follows rule-set refreshes. `dns-hijack` only hijacks DNS queries that enter through this TUN. Stale rules in the same priority range and table are removed before start and on exit, so a restart after `kill -9` does not stack rules. All three `stack` values run on kerlico's user-space stack. It needs `CAP_NET_ADMIN`. See [TUN inbound](interfaces/tun.md).

## DNS and Fake-IP

The `dns` section follows Mihomo semantics. `Local` egress, route rules, DNS hijacking, `dns.listen`, the DNS outbound, and `/dns/query` share one pipeline: hosts → DNS rules → Fake-IP (`fake-ip-filter`, `fake-ip-filter-mode`) → cache (LRU/ARC, optimistic, ECS) → `nameserver-policy` → `nameserver` and `fallback` (`fallback-filter`). Upstreams support UDP, TCP, DoT, DoH (HTTP/2, HTTP/3), DoQ, `system`, and `rcode://`; `#outbound-name` or `respect-rules` dials them through an outbound, and upstream hostnames resolve through `default-nameserver`. Proxy server hostnames use `proxy-server-nameserver`. Mihomo IP rules without `no-resolve` resolve a domain target for matching only; the remote still receives the domain. In the old form `tls://IP#name`, the part after `#` is now an outbound name; write `#sni=name` for the certificate name. Without the section, or with `enable: false`, the system resolver is used. See [DNS](interfaces/dns.md) (Chinese).

## Control interface and Web UI

The `control` section (or the Mihomo top-level `external-controller`, `external-ui`, and `secret`) enables the HTTP/WebSocket control plane, serving both read-only `/v1/*` endpoints (`/v1/health`, `/v1/usage`, `/v1/online`, `/v1/flows`, `/v1/stats`) and Clash/Mihomo-compatible endpoints (`/proxies`, `/connections`, `/rules`, `/configs`, `/logs`, `/traffic`, `/memory`, `/dns/query`, `/cache/fakeip/flush`, `/cache/dns/flush`) plus static Web UI hosting at `/ui` (`external_ui`). `/traffic`, `/memory`, `/logs`, and `/connections` push over WebSocket; browsers authenticate with `?token=<secret>`. Put metacubexd in the `external_ui` directory and open `http://127.0.0.1:9090/ui/` for the overview, proxy switching, connections, logs, rules, and mode switching:

```sh
curl -H 'Authorization: Bearer <secret>' http://127.0.0.1:9090/v1/usage
curl -H 'Authorization: Bearer <secret>' http://127.0.0.1:9090/proxies
```

A non-loopback `listen` address requires `secret`.

After editing the configuration, send `kill -HUP <pid>` or call `PUT /configs`. kerlico reads the configuration again and replaces the running engine. If the new configuration is invalid, the old one keeps serving. During the switch the listeners close briefly and new connections are refused; existing sessions drain within `limits.drain_timeout_ms`. The `reloads` counters in `/v1/health` show the result:

```sh
curl -X PUT -H 'Authorization: Bearer <secret>' -d '{}' http://127.0.0.1:9090/configs
```

`PATCH /configs` applies `mode` and `log-level` in place. Changing listener fields such as `mixed-port`, `port`, `socks-port`, `allow-lan`, or `tun.enable` rebuilds the engine from the patched configuration.

## Logs

Logs go to standard output and to `/logs` subscribers. The level comes from `log.level`, then the top-level `log-level` (Mihomo), and defaults to `info`. Levels are `silent`, `error`, `warning`, `info`, and `debug`. When `log.output` is a file path, lines are appended to that file; `stderr` writes to standard error. `log.timestamp: true` prefixes each line with the UTC time, and `log.disabled: true` turns output off. Connections are logged at `info` in the Mihomo format:

```text
2026-11-06T08:00:00.000Z INFO [TCP] 127.0.0.1:50312 --> example.com:443 match DomainSuffix(example.com) using Proxy[node-a]
```

`PUT /configs` also accepts `payload` (configuration text) or an absolute `path` inside the startup configuration directory, as in Mihomo. Changes to `control.listen`, adding or removing the `control` section, and `device` changes need a process restart.

## Statistics

With `telemetry` configured, usage, bandwidth, access records, DNS and error events go to SQLite:

```sh
kerlico history --directory state/telemetry --kind usage
kerlico history --directory state/telemetry --kind events --limit 100
```
