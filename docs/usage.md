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
- `proxy_providers`：外部或内联节点订阅提供者（支持 Mihomo YAML、Base64 订阅与 `vmess://`/`ss://`/`ssr://`/`vless://`/`trojan://`/`hy2://`/`tuic://`/`anytls://`/`wg://` 分享链接解析及字段 `override`）。
- `nodes`：对外服务的协议节点，用 `members` 鉴权；支持 `mixed`、`redirect`、`tproxy`、`tun`、`masque`、`openvpn` 等 26 种入站。
- `local_inbounds` / `inbounds`：只监听回环地址的本地协议入口与固定目标转发，也支持 Mihomo 顶层 `port`、`socks-port`、`mixed-port`、`allow-lan`、`bind-address`。
- `routes` / `rule_providers` / `sub_rules`：按域名、CIDR、GeoIP/GeoSite、`rule-set`（`.srs`/`.mrs`/JSON/YAML）、本机进程（`PROCESS-NAME*`/`PROCESS-PATH*`）、协议嗅探结果、`SUB-RULE` 子规则表或逻辑组合（`and`/`or`/`not`）选择出站或执行 `sniff`/`resolve`/`hijack-dns`/`reject`。
- `accounts`、`telemetry`、`device`、`dns`、`ntp`、`control`、`limits`：账户、统计、WARP、DNS（含 Fake-IP 与 DoH/DoQ）、内置 NTP、控制面接口和限额。

字段细节见[配置接口](interfaces/config.md)，各协议的 `options` 见[接口文档](interfaces/README.md)。

### Mihomo 代理兼容

顶层 `proxies`、`proxy-providers` 成员（Mihomo YAML）与分享链接走同一张字段映射表（`crates/config/src/mihomo.rs`），同一节点三种写法得到相同的 kerlico `options`。带 `tag` 或 `options` 键的条目（如 JSON 订阅 `[{"tag":"n1","type":"direct"}]`）视为 kerlico 原生出站，原样保留；原生条目只允许 `tag`（带 `options` 时也可写 `name`）、`type`、`options`，其他字段报错。

- 映射表未列出的字段一律报错，错误信息给出代理名和字段路径（如 `ws-opts.bogus`），不会静默丢弃或原样透传。
- 公共字段：`interface-name`、`routing-mark`、`dialer-proxy`、`tfo` 交给拨号层。以下取值无效果、允许出现：`udp: true`、`skip-cert-verify: false`、`mptcp: false`、`ip-version: dual`、`smux.enabled: false`；其他取值报错。kerlico 按协议能力承载 UDP，未写 `udp` 的节点也会承载 UDP；`udp: false` 只在 SSR、Hysteria、TrustTunnel、Sudoku 上映射为关闭 UDP，其他类型报错。HTTP、SSH 的 `udp` 任意取值都忽略（Mihomo 同样不为它们承载 UDP）。
- `skip-cert-verify: true` 与 `client-fingerprint` 只在 VLESS 上支持，其他类型报错；`fingerprint`（证书指纹）均不支持。`alpn` 只在 VLESS、Hysteria、TUIC、ShadowQUIC 上支持；Hysteria2 只接受 `[h3]`。
- 不支持的类型：`masque`（Mihomo 的 WARP 式密钥认证与 kerlico MASQUE 客户端不同）、`rematch`。

| Mihomo `type` | kerlico 类型 | 支持的字段 | 报错的常见字段 |
| --- | --- | --- | --- |
| `ss` | `shadowsocks`；`2022-*` 加密为 `ss2022`；`plugin: shadow-tls` 为 `shadowtls` | `cipher`、`password`（2022 写作 `iPSK:uPSK`）、`udp-over-tcp`、`udp-over-tcp-version`、`smux`、`plugin: obfs`（`mode`、`host`）、`plugin: v2ray-plugin`/`gost-plugin`（`mode: websocket`、`tls`、`host`、`path`、`mux`、`headers`、`v2ray-http-upgrade`）、`shadow-tls`（`host`、`password`、`version`、`alpn`） | `plugin: restls`/`kcptun`/`jls`、`client-fingerprint`、`plugin-opts.fingerprint`；非 AEAD 旧式加密自动带 `allow_insecure` |
| `ssr` | `shadowsocksr` | `cipher`、`password`、`protocol`、`obfs`、`protocol-param`、`obfs-param`、`udp` | 无 |
| `snell` | `snell` | `psk`、`version`（3、4）、`reuse`、`obfs-opts.mode: http`、`obfs-opts.host` | `version` 1、2、5 或未写（Mihomo 默认 1），`obfs-opts.mode: tls` |
| `vmess` | `vmess` | `uuid`、`alterId: 0`、`cipher`（`auto`、`aes-128-gcm`、`chacha20-poly1305`、`zero`）、`global-padding`（默认 false，与 Mihomo 一致）、`authenticated-length`、`tls`、`servername`、`network: tcp/ws/grpc`、`ws-opts.path`、`ws-opts.headers.Host`、`ws-opts.v2ray-http-upgrade`、`grpc-opts.grpc-service-name`、`smux` | `alterId` 非 0、`cipher: none`、`xudp`/`packet-encoding`、`network: h2/http`、`ws-opts` 中除 `Host` 外的请求头与 `max-early-data` |
| `vless` | `vless` | `uuid`、`flow`、`encryption`、`packet-encoding`、`xudp`、`packet-addr`、`tls`、`servername`、`client-fingerprint`、`alpn`、`skip-cert-verify`、`reality-opts.public-key`、`reality-opts.short-id`、`network: tcp/ws/grpc`、`ws-opts`（`path`、`headers`、`max-early-data`、`early-data-header-name: Sec-WebSocket-Protocol`、`v2ray-http-upgrade`）、`grpc-opts`（`grpc-service-name`、`grpc-user-agent`）、`smux` | `network: h2/http/xhttp`、`ws-headers`、`fingerprint` |
| `trojan` | `trojan` | `password`、`sni`、`network: tcp/ws/grpc` 与对应 `*-opts`（同 VLESS）、`ss-opts.enabled: false`、`smux` | `alpn`、`client-fingerprint`、`ss-opts.enabled: true`、`reality-opts` |
| `anytls` | `anytls` | `password`、`sni`、`idle-session-timeout` | `idle-session-check-interval`、`min-idle-session`、`client-metadata`、`alpn` |
| `http` | `http` | `username`、`password`、`tls`、`sni`、`headers` | `fingerprint` |
| `socks5` | `socks` | `username`、`password`、`udp` | `tls: true`、`fingerprint` |
| `hysteria` | `hysteria1` | `ports`、`hop-interval`、`auth-str`、`auth`、`up`/`down`（或 `up-speed`/`down-speed`，无单位为 Mbps，必填）、`obfs`、`protocol`/`obfs-protocol`（`udp`、`wechat-video`）、`sni`、`alpn`、`ca-str`、`udp` | `protocol: faketcp`、`ca`（路径）、`recv-window*`、`fast-open: true` |
| `hysteria2` | `hysteria2` | `ports`、`hop-interval`（整数或 `15-30`）、`password`、`up`、`down`、`obfs: salamander`、`obfs-password`、`sni`、`ca-str` | `obfs: gecko`、`realm-opts`、`bbr-profile`、各接收窗口、`cwnd`、`udp-mtu` |
| `tuic` | `tuic` | `token`（V4）或 `uuid` + `password`（V5）、`ip`、`ports`、`hop-interval`、`sni`、`alpn`、`ca-str`、`heartbeat-interval`、`udp-relay-mode`、`congestion-controller`（`cubic`、`new_reno`、`bbr`） | `disable-sni: true`、`reduce-rtt: true`、`request-timeout`、`max-udp-relay-packet-size`、`max-open-streams`、`udp-over-stream: true` |
| `shadowquic` | `shadowquic` | `username`、`password`、`sni`、`alpn`、`udp-over-stream`、`congestion-controller` | `zero-rtt: true`、`quic-versions`、`up`、`down`、窗口类字段 |
| `wireguard` | `wireguard` | `ip`、`ipv6`（去掉前缀长度）、`private-key`、`public-key`、`pre-shared-key`、`reserved`、`allowed-ips`（默认 `0.0.0.0/0`、`::/0`）、`persistent-keepalive`、`mtu`、单个 `peers` 条目 | 多个 `peers`、`dns`、`remote-dns-resolve: true`、`amnezia-wg-option`、`ip-stack`、`workers` |
| `ssh` | `ssh` | `username`、`password`、`private-key`（PEM 或路径）、`private-key-passphrase`、`host-key`（转为 `SHA256:` 指纹） | 未写 `host-key`（kerlico 要求固定主机密钥）、`host-key-algorithms` |
| `mieru` | `mieru` | `port` 或 `port-range`、`transport: TCP`、`username`、`password`、`multiplexing`、`handshake-mode` | `transport: UDP`、`traffic-pattern` |
| `sudoku` | `sudoku` | `key`、`aead-method`、`padding-min`、`padding-max`、`table-type`、`custom-table`、`custom-tables`、`enable-pure-downlink`、`httpmask`（`disable`、`mode`、`tls`、`host`、`path-root`、`multiplex`）、`udp` | 旧式扁平 `http-mask*` 字段 |
| `trusttunnel` | `trusttunnel` | `username`、`password`、`sni`、`quic`、`max-connections`、`max-streams`、`health-check: true`、`udp` | `min-streams`、`congestion-controller`、`bbr-profile`、`health-check: false` |
| `gost-relay` | `gost-relay` | `username`、`password`、`mux`、`tls`、`sni`；未开 `tls` 时自动带 `allow_insecure` | `forward` |
| `tailscale` | `tailscale` | `auth-key`、`control-url`（默认官方控制面）、`hostname`、`ephemeral`、`accept-routes`、`exit-node` | `state-dir`、`exit-node-allow-lan-access` |
| `openvpn` | `openvpn` | `server`、`port`、`proto`、`username`、`password`、`ca`（PEM 文本）、`cert`、`key`、`tls-auth`、`key-direction`、`auth`、`tls-crypt`、`tls-crypt-v2`、`cipher`、`data-ciphers`、`ping`、`ping-restart`、`handshake-timeout`、`mtu` | `peer-info`、`tran-window`、`dev`、`comp-lzo`、`dns`、`ip-stack` |
| `easytier` | `easytier` | `network-name`、`network-secret`、`peers`、`hostname`、`ipv4`、`dhcp`、`secure-mode`、`exit-nodes`、`enable-encryption`、`encryption-algorithm` | 监听、P2P、KCP/QUIC 代理、`mtu` 等其余字段 |
| `zerotier` | `zerotier` | `network`、`identity-secret`、`tcp-fallback-mode`、`tcp-fallback-relay`；使用公共 planet | `planet`、`state-dir`、端口与 MTU 字段 |
| `direct`、`reject`、`dns` | 同名 | 公共字段 | 其余字段 |

分享链接支持 `ss://`（含 SIP002 `plugin=obfs-local`/`v2ray-plugin`）、`ssr://`、`vmess://`（v2rayN Base64 JSON 与 URL 形式）、`vless://`、`trojan://`、`hysteria2://`/`hy2://`、`hysteria://`、`tuic://`、`socks://`/`socks5://`、`http://`/`https://`、`anytls://`、`wireguard://`/`wg://`。链接参数先转成上表的 Mihomo 字段，未识别的参数报错并给出参数名。

`proxy-providers` 的 `override.skip-cert-verify` 与 `override.udp` 目前直接写入 kerlico `options`，对多数类型会在编译时报错；需要时请在节点本身设置。

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

规则按顺序匹配，首条命中生效，未命中走节点绑定的 `outbound`。顶层 `mode` 同 Mihomo：`rule`（默认）按规则分流，`global` 全部交给 `GLOBAL` 选择组，`direct` 全部走 `DIRECT`；运行中可用 `PATCH /configs` 切换。没有同名策略组或出站时，kerlico 自动生成 `GLOBAL`，成员依次为 `DIRECT`、`REJECT`、配置中的出站、策略组。可按域名、关键字、正则、CIDR、端口、网络、节点、用户、协议嗅探（TLS SNI、HTTP Host、QUIC SNI、BitTorrent、SSH、RDP）和外部规则集匹配。开启 `sniff` 或 Fake-IP 时，IP 目标可还原域名并参与域名规则匹配。详见[路由规则](interfaces/config.md)。

## 订阅、远程规则集与 Geo 数据

`http` 类型的 `proxy_providers`、`type: remote` 的 `rule_set` 与 `http` 类型的 `rule_providers` 从 URL 下载，缓存到 `path`（未写时为 `proxies/<名称>`、`rules/<标签>`，相对工作目录）。

- **下载路径**：`proxy`、`download_detour` 指定命名出站或策略组时经它下载，目标域名交给该出站；留空或写 `DIRECT` 时直连。支持 HTTP/HTTPS、最多 5 次重定向、gzip、`header` 与 `size-limit`（0 或未写时上限 64 MiB）。上次响应带 `ETag` 或 `Last-Modified` 时发条件请求，304 保留现有内容。
- **启动**：缓存存在且未超过 `interval` 时直接使用；否则先下载。下载失败而缓存存在时继续用旧缓存并记日志。被路由或 DNS 规则引用的规则集既无缓存又下载失败时拒绝启动；`type: local` 规则集或 `file` 规则提供者的文件不存在时配置检查失败。提供者没有内容时成员为空，`GET /providers/proxies/<name>` 带 `error`，使用它的策略组拒绝连接。
- **刷新**：按 `interval`（sing-box `update_interval`，默认 `1d`）在后台刷新。规则集原地替换，新连接立即按新内容匹配。提供者内容变化时用当前配置重建引擎，新成员生效，期间入口短暂关闭、已有连接按 `drain_timeout_ms` 排空。内容校验失败（例如提供者没有可用节点）时不覆盖缓存。
- **手动刷新**：`PUT /providers/proxies/<name>`、`PUT /providers/rules/<name>` 立即刷新，失败回 503 与 `message`。
- **Geo 数据**：`geox-url` 中配置的 `geoip`、`geosite`、`mmdb`、`asn` 下载到工作目录的 `GeoIP.dat`、`GeoSite.dat`、`Country.mmdb`、`GeoLite2-ASN.mmdb`。`geo-auto-update: true` 时按 `geo-update-interval`（小时，默认 24）刷新；`POST /upgrade/geo` 立即下载。运行时 GeoIP/GeoSite 规则目前仍使用内置分类表，不读这些文件。

## WARP 补齐

机器只有 IPv4 或只有 IPv6 时，配置 `device` 后，`dual-stack` 节点的 `direct` 流量可经 Cloudflare WARP 访问缺失的地址族：

```json
"device": { "state_directory": "/var/lib/kerlico/device" }
```

首次需要时向 Cloudflare 注册一次，身份保存在此目录。目录必须是绝对路径，权限 `0700`。

## 隧道与覆盖网络

`wireguard`、`masque`、`openvpn` 支持客户端出站与服务端入站双端运行；`openconnect`、`tailscale`、`easytier`、`zerotier` 把远端网络接成客户端出站。在节点或规则里引用它们的 `tag`。选项和限制见各[接口文档](interfaces/README.md)。

OpenVPN 服务端节点只支持 TLS 模式，必须配置服务端证书与私钥，可按 CA、CRL、指纹与 `verify-x509-name` 校验客户端证书，也可用成员口令认证。每个客户端从 `address` 地址池分到独立地址，推送内容由 `push` 生成，断开后地址回收。官方 OpenVPN 2.6 与 2.4 客户端可直接连接，字段见 [OpenVPN 接口](interfaces/openvpn.md#服务端入站nodeoptions)。

## TUN

[examples/tun-v2.json](../examples/tun-v2.json) 创建 `kerlico0` 接口，把进入接口的 TCP 和 UDP 交给出站。支持配置 `auto-route`、`auto-redirect`（nftables）、`strict-route` 与 `auto-detect-interface` 防回环，也可配合 Fake-IP 与首包嗅探还原域名。详见 [TUN 入站](interfaces/tun.md)。

## DNS 与 Fake-IP

`dns` 段配置上游（`udp://`、`tcp://`、`tls://`、`https://` DoH、`quic://` DoQ）、Fake-IP 双栈地址池（默认 `198.18.0.0/15` 与 `fc00::/18`）、乐观缓存、EDNS Client Subnet（ECS）、DNS 分流规则和静态 `hosts`。未配置时使用系统解析器。详见 [DNS](interfaces/dns.md)。

## 控制接口与 Web 面板

`control` 段（或 Mihomo 顶层 `external-controller`、`external-ui`、`secret`）开启 HTTP/WebSocket 控制面接口，同时提供原生只读 `/v1/*` 接口、Clash/Mihomo 兼容接口（`/proxies`、`/connections`、`/rules`、`/configs`、`/logs`、`/traffic`、`/memory`、`/dns/query`、`/cache/fakeip/flush`、`/cache/dns/flush`）与 `/ui` 静态 Web 面板托管（配置 `external_ui` 目录）。`/traffic`、`/memory`、`/logs`、`/connections` 支持 WebSocket 推送，浏览器用 `?token=<secret>` 鉴权。metacubexd 放在 `external_ui` 目录后，打开 `http://127.0.0.1:9090/ui/` 即可使用总览、代理切换、连接、日志、规则与运行模式切换：

```sh
curl -H 'Authorization: Bearer <secret>' http://127.0.0.1:9090/v1/usage
curl -H 'Authorization: Bearer <secret>' http://127.0.0.1:9090/proxies
```

修改配置文件后发送 `kill -HUP <pid>`，或调用 `PUT /configs`，kerlico 重读配置并替换运行中的引擎。新配置无效时继续用旧配置服务；切换期间监听短暂关闭，新连接被拒绝，已有会话按 `limits.drain_timeout_ms` 排空。结果见 `/v1/health` 的 `reloads` 计数：

```sh
curl -X PUT -H 'Authorization: Bearer <secret>' -d '{}' http://127.0.0.1:9090/configs
```

`PATCH /configs` 改 `mode`、`log-level` 时就地生效；改 `mixed-port`、`port`、`socks-port`、`allow-lan`、`tun.enable` 等监听字段时按改后的配置重建引擎。

详见[控制接口](interfaces/control.md)与[配置重载](interfaces/control.md#配置重载)。

## 日志

日志写到标准输出，并推送给 `/logs` 订阅者。级别取 `log.level`，其次顶层 `log-level`（Mihomo），默认 `info`；可选 `silent`、`error`、`warning`、`info`、`debug`。`log.output` 为文件路径时追加写入该文件，写 `stderr` 时写标准错误；`log.timestamp: true` 在每行前加 UTC 时间；`log.disabled: true` 关闭输出。连接按 Mihomo 格式记 `info` 日志：

```text
2026-11-06T08:00:00.000Z INFO [TCP] 127.0.0.1:50312 --> example.com:443 match DomainSuffix(example.com) using Proxy[node-a]
```

## 统计

配置 `telemetry` 后，用量、带宽、访问记录、DNS 与错误事件写入 SQLite：

```sh
kerlico history --directory state/telemetry --kind usage
kerlico history --directory state/telemetry --kind events --limit 100
```

详见[统计历史](interfaces/history.md)。
