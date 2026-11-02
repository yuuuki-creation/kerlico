# Usage Guide

[简体中文](usage.md)

`kerlico` is a single executable. A JSON configuration makes it a proxy client, a proxy server, or both.

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
| `kerlico run -c <file>` | Start. Shuts down gracefully on `Ctrl-C` or `SIGTERM` |
| `kerlico check -c <file>` | Validate a configuration without opening ports |
| `kerlico modules` | List the protocols in this build |
| `kerlico account-new --prefix <name>` | Read an admin password from stdin and print account JSON |
| `kerlico history --kind <kind>` | Query statistics history. `kind` is `usage`, `flows`, `bandwidth` or `events` |

The global `--lang zh-CN` or `--lang en` option selects the output language.

## Configuration

The configuration is JSON v2 with these parts:

- `outbounds`: named outbounds, where traffic finally leaves.
- `nodes`: public protocol nodes that authenticate with `members`.
- `local_inbounds`: protocol entries bound to loopback, such as a local SOCKS port.
- `inbounds`: fixed-target forwards bound to loopback.
- `routes`: rules that choose an outbound.
- `accounts`, `telemetry`, `device`, `dns`, `control`, `limits`: accounts, statistics, WARP, DNS, control interface and limits.

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

## Routing

Rules match in order and the first match wins. Unmatched traffic uses the node's `outbound`. Rules can match domain, CIDR, port, network, node and user. Routing never queries DNS, so a domain target does not match a CIDR. Multi-target UDP associations always use the node's outbound.

## WARP fill-in

On an IPv4-only or IPv6-only machine, configure `device` so `direct` traffic from `dual-stack` nodes can reach the missing family through Cloudflare WARP:

```json
"device": { "state_directory": "/var/lib/kerlico/device" }
```

It registers with Cloudflare once when first needed and keeps the identity in this directory. The path must be absolute with mode `0700`.

## Tunnel and overlay outbounds

`masque`, `openvpn`, `openconnect`, `tailscale`, `easytier` and `zerotier` turn a remote network into an outbound. Reference their `tag` from a node or a rule. Targets must be reachable in that network, and domains resolve locally. Options and limits are in the [interface documents](interfaces/README.md).

## TUN

[examples/tun-v2.json](../examples/tun-v2.json) creates a `kerlico0` interface and hands its TCP and UDP to an outbound. kerlico does not change system routes, so add routes yourself and avoid loops: bind `direct` with `"options": {"interface": "eth0"}` and give the proxy server and DNS upstreams explicit routes through the physical gateway. TUN sees IP targets only, so domain rules do not match. It needs `CAP_NET_ADMIN` and has only been verified on Linux.

## DNS

The `dns` section sets upstreams (`udp://IP`, `tcp://IP`, `tls://IP#name`) and static `hosts` for the `direct` path. Without it, the system resolver is used.

## Control interface

The `control` section enables a read-only HTTP API (`/v1/health`, `/v1/usage`, `/v1/online`, `/v1/flows`, `/v1/stats`):

```sh
curl -H 'Authorization: Bearer <secret>' http://127.0.0.1:9090/v1/usage
```

A non-loopback `listen` address requires `secret`.

## Statistics

With `telemetry` configured, usage, bandwidth, access records, DNS and error events go to SQLite:

```sh
kerlico history --directory state/telemetry --kind usage
kerlico history --directory state/telemetry --kind events --limit 100
```
