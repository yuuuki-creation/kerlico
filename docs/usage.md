# 使用指南

[English](usage.en.md)

`kerlico` 是一个可执行文件，按 JSON、JSONC、YAML 或 TOML 配置充当代理客户端、代理服务端，或两者兼有。

## 安装

从 [Releases](https://github.com/yuuuki-creation/kerlico/releases) 下载 Linux `x86_64` 的 `kerlico`，用 `SHA256SUMS` 校验。运行需要 glibc 2.34 或更高版本。

从源码构建需要 Rust `1.99.1`：

```sh
export PROTOC="$(tools/fetch_protoc.sh ~/.cache/kerlico)"
cargo build --locked --release -p kerlico
```

`protoc` 只有 EasyTier 出站需要。不需要时用 `--no-default-features` 选择协议。

## 命令

| 命令 | 作用 |
| --- | --- |
| `kerlico run -c <file> [-C <dir>]` | 启动，支持多文件/目录深度合并与 `SIGHUP` 热重载，收到 `Ctrl-C` 或 `SIGTERM` 后优雅退出 |
| `kerlico check -c <file> [-C <dir>]` | 校验配置和模块能力，不监听端口 |
| `kerlico format -c <file> [-w]` | 格式化配置文件 |
| `kerlico merge [output] -c <f1> -c <f2> [-C <dir>]` | 深度合并多个配置文件或配置目录 |
| `kerlico modules` | 列出此构建包含的协议与入站/出站角色 |
| `kerlico account-new --prefix <name>` | 从标准输入读取管理密码，输出账户 JSON |
| `kerlico history --kind <kind>` | 查询统计历史，`kind` 为 `usage`、`flows`、`bandwidth` 或 `events` |
| `kerlico rule-set <compile\|decompile\|convert\|format\|match\|merge\|upgrade>` | 规则集编译（JSON/YAML 与 `.srs`/`.mrs` 互转）、格式化、合并与目标匹配测试 |
| `kerlico geoip / geosite <list\|lookup\|export> -f <db>` | GeoIP / Geosite 数据库分类列表、IP/域名归属查询与规则集导出 |
| `kerlico generate <uuid\|rand\|reality-keypair\|wg-keypair\|ech-keypair\|tls-keypair\|vlessenc\|mldsa65\|mlkem768>` | 生成 UUID、随机数、X25519/WireGuard/ECH/TLS/后量子及 VLESS Encryption 密钥对 |
| `kerlico tls <cert\|ping>` | 生成自签名证书（含 SHA-256 指纹）或探测远端 TLS 握手与证书链 |
| `kerlico tools <connect\|fetch\|resolve\|synctime> [-c <cfg> -o <tag>]` | 经指定配置或出站测试 TCP 连通、HTTP 获取、DNS 解析与 NTP 时间同步 |

全局参数 `--lang zh-CN` 或 `--lang en` 指定输出语言。运行期可通过环境变量 `KERLICO_LOG_LEVEL`、`KERLICO_CONTROL_LISTEN`、`KERLICO_CONTROL_SECRET`、`KERLICO_EXTERNAL_UI` 覆盖对应配置项。

## 配置

支持 JSON v2、带注释 JSONC、YAML（含锚点别名 `&`/`*`/`<<`）与 TOML，也兼容直接加载 Mihomo（`proxies`/`proxy-groups`/`rules`）与 sing-box（`inbounds`/`outbounds`/`route`）风格配置。主结构包含：

- `outbounds`：命名出站与策略组（`select`、`url-test`、`fallback`、`load-balance`、`balancer`），支持 `dialer-proxy` / `detour` 链式代理。
- `proxy_providers`：外部或内联节点订阅提供者（支持 Mihomo YAML、Base64 订阅与 URI 行解析及字段 `override`）。
- `nodes`：对外服务的协议节点，用 `members` 鉴权；支持 `mixed`、`redirect`、`tproxy`、`tun`、`masque`、`openvpn` 等 26 种入站。
- `local_inbounds` / `inbounds`：只监听回环地址的本地协议入口与固定目标转发。
- `routes` / `rule_providers`：按域名、CIDR、GeoIP/GeoSite、`rule-set`（`.srs`/`.mrs`/JSON/YAML）、进程、协议嗅探结果或逻辑组合（`and`/`or`）选择出站或执行 `sniff`/`resolve`/`hijack-dns`/`reject`。
- `accounts`、`telemetry`、`device`、`dns`、`ntp`、`control`、`limits`：账户、统计、WARP、DNS（含 Fake-IP 与 DoH/DoQ）、内置 NTP、控制面接口和限额。

字段细节见[配置接口](interfaces/config.md)，各协议的 `options` 见[接口文档](interfaces/README.md)。

## 作为客户端

[examples/client-routes-v2.json](../examples/client-routes-v2.json) 在本机开 SOCKS 入口，默认走远端代理，局域网直连，广告域名拒绝。把 `proxy` 的 `options` 换成你的服务器后运行：

```sh
kerlico run -c client-routes-v2.json
```

## 作为服务端

先创建管理账户：

```sh
printf '%s' 'your-admin-password' | kerlico account-new --prefix alice
```

把输出放进 `accounts`，再用它的 `user_id` 在节点上配置成员。IPv4 和 IPv6 分别建节点，每个节点有独立的凭据和配额。各协议的 `options` 和 `native_credential` 见对应接口文档。

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

## 路由与规则集

规则按顺序匹配，首条命中生效，未命中走节点绑定的 `outbound`。可按域名、关键字、正则、CIDR、端口、网络、节点、用户、协议嗅探（TLS SNI、HTTP Host、QUIC SNI、BitTorrent、SSH、RDP）和外部规则集匹配。开启 `sniff` 或 Fake-IP 时，IP 目标可还原域名并参与域名规则匹配。详见[路由规则](interfaces/config.md)。

## WARP 补齐

机器只有 IPv4 或只有 IPv6 时，配置 `device` 后，`dual-stack` 节点的 `direct` 流量可经 Cloudflare WARP 访问缺失的地址族：

```json
"device": { "state_directory": "/var/lib/kerlico/device" }
```

首次需要时向 Cloudflare 注册一次，身份保存在此目录。目录必须是绝对路径，权限 `0700`。

## 隧道与覆盖网络

`wireguard`、`masque`、`openvpn` 支持客户端出站与服务端入站双端运行；`openconnect`、`tailscale`、`easytier`、`zerotier` 把远端网络接成客户端出站。在节点或规则里引用它们的 `tag`。选项和限制见各[接口文档](interfaces/README.md)。

## TUN

[examples/tun-v2.json](../examples/tun-v2.json) 创建 `kerlico0` 接口，把进入接口的 TCP 和 UDP 交给出站。支持配置 `auto-route`、`auto-redirect`（nftables）、`strict-route` 与 `auto-detect-interface` 防回环，也可配合 Fake-IP 与首包嗅探还原域名。详见 [TUN 入站](interfaces/tun.md)。

## DNS 与 Fake-IP

`dns` 段配置上游（`udp://`、`tcp://`、`tls://`、`https://` DoH、`quic://` DoQ）、Fake-IP 双栈地址池（默认 `198.18.0.0/15` 与 `fc00::/18`）、乐观缓存、EDNS Client Subnet（ECS）、DNS 分流规则和静态 `hosts`。未配置时使用系统解析器。详见 [DNS](interfaces/dns.md)。

## 控制接口与 Web 面板

`control` 段开启 HTTP/WebSocket 控制面接口，同时提供原生只读 `/v1/*` 接口、Clash/Mihomo 兼容接口（`/proxies`、`/connections`、`/rules`、`/configs`、`/logs`、`/traffic`、`/memory`、`/dns/query`、`/cache/fakeip/flush`）与 `/ui` 静态 Web 面板托管（配置 `external_ui` 目录）：

```sh
curl -H 'Authorization: Bearer <secret>' http://127.0.0.1:9090/v1/usage
curl -H 'Authorization: Bearer <secret>' http://127.0.0.1:9090/proxies
```

详见[控制接口](interfaces/control.md)。

## 统计

配置 `telemetry` 后，用量、带宽、访问记录、DNS 与错误事件写入 SQLite：

```sh
kerlico history --directory state/telemetry --kind usage
kerlico history --directory state/telemetry --kind events --limit 100
```

详见[统计历史](interfaces/history.md)。
