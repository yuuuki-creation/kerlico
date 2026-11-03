# 入站

由 `tools/capability_matrix.py build` 生成，不要手改。

## anytls

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | AnyTLS 入站 | 有 | 有 |  | 已实现 | 通过 | 取值：`anytls`<br>约束：可作 detour 注入目标（Injectable：TCP）<br>约束：自 sing-box 1.12.0 起 |
| `combo` | AnyTLS 入站组合 | 有 | 有 |  | 部分 | 通过 | security：`jls`、`none`、`res-tls`、`shadow-tls`、`tls`<br>ech：`off`、`on`<br>allow-insecure：`false`、`true`<br>约束：allow-insecure 不为 true 时至少填 certificate+private-key、shadow-tls、res-tls、jls-config 之一<br>约束：source:listener/anytls/server.go：四者互斥<br>约束：启用 ShadowTLS、ResTLS、JLS 时不要填证书<br>security：`none`、`reality`、`tls`<br>padding_scheme：`custom`、`default`<br>约束：reality 组合来自 TLS 通用字段，协议页未单列，需实测<br>约束：users 必填<br>约束：文档未写入站 tls 必填 |
| `allow-insecure` | 允许不开启 tls，仅用于 nginx、caddy 前置 | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `certificate` | TLS 证书，PEM 或路径 | 有 |  |  | 已实现 | 通过 | 取值：`PEM`、`路径`<br>约束：与 private-key 同时填写才开启 tls |
| `client-auth-cert` | mTLS 客户端证书 | 有 |  |  | 未实现 | 未测 | 取值：`PEM`、`路径` |
| `client-auth-type` | mTLS 类型 | 有 |  |  | 未实现 | 未测 | 取值：``、`request`、`require-and-verify`、`require-any`、`verify-if-given`<br>约束：verify-if-given、require-and-verify 时 client-auth-cert 必填 |
| `ech-key` | ECH 密钥，填写即开启；可由 mihomo generate ech-keypair 生成 | 有 |  |  | 未实现 | 未测 | 取值：`PEM` |
| `jls-config-alpn` | ALPN | 有 |  |  | 未实现 | 未测 | 取值：`列表` |
| `jls-config-dest` | 回落目标 | 有 |  |  | 未实现 | 未测 | 取值：`host:port` |
| `jls-config-enable` | 启用 JLS，替代普通 TLS；未认证连接回落 dest | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `jls-config-proxy` | 回落目标使用的代理 | 有 |  |  | 未实现 | 未测 | 取值：`出站名` |
| `jls-config-rate-limit` | fallback 转发限速，bit/s，0 不限 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `jls-config-sni` | SNI，留空从 dest 推导 | 有 |  |  | 未实现 | 未测 | 取值：`域名` |
| `jls-config-users-password` | JLS 密码 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `jls-config-users-username` | JLS 用户名 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `padding-scheme` | AnyTLS 填充方案 | 有 | 有 |  | 已实现 | 通过 | 取值：`字符串`<br>约束：自 sing-box 1.12.0 起<br>约束：默认填充方案: |
| `private-key` | TLS 私钥，PEM 或路径 | 有 |  |  | 已实现 | 通过 | 取值：`PEM`、`路径`<br>约束：与 certificate 同时填写 |
| `res-tls-dest` | 回落目标 | 有 |  |  | 未实现 | 未测 | 取值：`host:port` |
| `res-tls-enable` | 启用 ResTLS | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `res-tls-min-record-len` | 最小记录长度 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `res-tls-password` | ResTLS 密码 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `res-tls-proxy` | 回落目标使用的代理 | 有 |  |  | 未实现 | 未测 | 取值：`出站名` |
| `res-tls-rate-limit` | fallback 双向转发限速，bit/s，0 不限 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `res-tls-restls-script` | Restls 剧本 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `shadow-tls-enable` | 启用 ShadowTLS | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `shadow-tls-handshake-dest` | 握手目标 | 有 |  |  | 未实现 | 未测 | 取值：`host:port` |
| `shadow-tls-handshake-for-server-name` | 按 SNI 选握手目标（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`映射` |
| `shadow-tls-handshake-proxy` | 握手目标使用的代理 | 有 |  |  | 未实现 | 未测 | 取值：`出站名` |
| `shadow-tls-password` | v2 密码 | 有 |  |  | 未实现 | 未测 | 取值：`字符串`<br>约束：v2 配置项 |
| `shadow-tls-strict-mode` | ShadowTLS 严格模式（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `shadow-tls-users-name` | v3 用户名 | 有 |  |  | 未实现 | 未测 | 取值：`字符串`<br>约束：v3 配置项 |
| `shadow-tls-users-password` | v3 用户密码 | 有 |  |  | 未实现 | 未测 | 取值：`字符串`<br>约束：v3 配置项 |
| `shadow-tls-version` | ShadowTLS 版本 | 有 |  |  | 未实现 | 未测 | 取值：`1`、`2`、`3` |
| `shadow-tls-wildcard-sni` | ShadowTLS 通配 SNI（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `tls` | TLS 配置, 参阅 TLS。 |  | 有 |  | 部分 | 通过 | 约束：自 sing-box 1.12.0 起 |
| `users` | 用户映射 | 有 | 有 |  | 已实现 | 通过 | 取值：`username: password`<br>约束：必填<br>约束：自 sing-box 1.12.0 起 |
| `users-name` | 用户名称，用于日志和 auth_user 匹配 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.12.0 起 |
| `users-password` | 密码 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.12.0 起 |

## cloudflared

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | cloudflared 入站的边缘协议和 IP 版本组合 |  | 有 |  | 未实现 | 未测 | protocol：`http2`、`quic`<br>datagram_version：`v2`、`v3`<br>edge_ip_version：`0`、`4`、`6`<br>post_quantum：`off`、`on`<br>约束：datagram_version 只在 protocol 为 quic 时有意义<br>约束：region 与 token 内嵌端点冲突<br>约束：token 必填<br>约束：需要 with_cloudflared 构建标签 |
| `control-dialer` | 隧道客户端拨向 Cloudflare 控制面时使用的拨号字段。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `datagram-version` | 通过 QUIC 进行 UDP 代理时使用的数据报协议版本。 |  | 有 |  | 未实现 | 未测 | 取值：`v2`、`v3`<br>约束：仅在 `protocol` 为 `quic` 时有效。<br>约束：自 sing-box 1.14.0 起 |
| `edge-ip-version` | 连接 Cloudflare edge 时使用的 IP 版本。 |  | 有 |  | 未实现 | 未测 | 取值：`0`、`4`、`6`<br>约束：自 sing-box 1.14.0 起 |
| `grace-period` | 正在处理的 edge 连接的优雅关闭窗口。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `ha-connections` | 到 Cloudflare edge 的高可用连接数。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `post-quantum` | 在控制连接上启用后量子密钥交换。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `protocol` | edge 连接使用的传输协议。 |  | 有 |  | 未实现 | 未测 | 取值：`cloudflared`、`http2`、`quic`<br>约束：不可作 detour 注入目标<br>约束：自 sing-box 1.14.0 起 |
| `region` | Cloudflare edge 区域选择器。 |  | 有 |  | 未实现 | 未测 | 约束：与 `token` 中嵌入的 endpoint 冲突。<br>约束：自 sing-box 1.14.0 起 |
| `token` | 来自 Cloudflare Zero Trust 仪表板的 Base64 编码隧道令牌（`Networks → Tunnels → Install connector`）。 |  | 有 |  | 未实现 | 未测 | 约束：必填<br>约束：自 sing-box 1.14.0 起 |
| `tunnel-dialer` | 隧道客户端拨向 Cloudflare edge 数据面时使用的拨号字段。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |

## common

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `listen` | 监听地址 | 有 |  | 有 | 已实现 | 通过 | 取值：`0.0.0.0`、`::`、`IP`、`地址`<br>约束：:: 与 0.0.0.0 都同时监听 IPv4 和 IPv6；仅 IPv6 需 sockopt.V6Only<br>约束：UDP 入站在多 IP 网卡且连接非首选地址时可能以错误源地址回复，应监听具体 IP |
| `listen-uds` | 监听 Unix domain socket |  |  | 有 | 未实现 | 未测 | 取值：`/dev/shm/domain.socket`、`/dev/shm/domain.socket,0666`、`@@padded`、`@abstract`<br>约束：port 被忽略<br>约束：仅基于 TCP 的传输，如 tcp、websocket、grpc；不支持 mkcp<br>约束：协议目前可选 VLESS、VMess、Trojan |
| `name` | 入站名称，可被 IN-NAME 匹配 | 有 |  |  | 已实现 | 通过 | 取值：`字符串` |
| `port` | 监听端口，支持 ports 范围格式 | 有 |  | 有 | 部分 | 通过 | 取值：`"11,13,15-17"`、`"1234"`、`"5-10"`、`114-514/810-1919,65530`、`env:变量名`、`整数`、`端口`<br>约束：监听数量接近四位数时可能出问题 |
| `protocol` | 入站协议名 |  |  | 有 | 部分 | 通过 | 取值：`http`、`hysteria`、`masque`、`shadowsocks`、`socks`、`trojan`、`tun`、`tunnel`、`vless`、`vmess`、`wireguard`<br>约束：源码另接受别名 dokodemo-door、mixed（source:infra/conf/xray.go） |
| `proxy` | 入站直接交给指定出站或策略组 | 有 |  |  | 已实现 | 通过 | 取值：`出站名`<br>约束：不为空时名称必须合法，否则出错 |
| `routing-mark` | 监听 socket 的 routing-mark | 有 |  |  | 未实现 | 未测 | 取值：`整数`<br>约束：仅 Linux |
| `rule` | 入站使用的子规则，为空或未找到时用 rules | 有 |  |  | 未实现 | 未测 | 取值：`sub-rule 名` |
| `settings` | 协议专属配置对象 |  |  | 有 | 已实现 | 通过 |  |
| `sniffing` | 入站流量探测配置 |  |  | 有 | 未实现 | 未测 |  |
| `stream-settings` | 入站传输配置 |  |  | 有 | 部分 | 通过 |  |
| `tag` | 入站的标签。 |  | 有 | 有 | 已实现 | 通过 | 约束：非空时必须在所有 tag 中唯一 |
| `type` | 入站类型 | 有 | 有 |  | 部分 | 通过 | 取值：`anytls`、`cloudflared`、`direct`、`http`、`hysteria`、`hysteria2`、`hysteria2-realm`、`mieru`、`mixed`、`naive`、`redir`、`redirect`、`shadowquic`、`shadowsocks`、`shadowtls`、`snell`、`socks`、`sudoku`、`tailcat`、`tproxy`、`trojan`、`trusttunnel`、`tuic`、`tun`…… |

## direct

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | 隧道服务器入站 |  | 有 |  | 已实现 | 通过 | 取值：`direct`<br>约束：不可作 detour 注入目标 |
| `combo` | direct 入站的网络与目标覆盖组合 |  | 有 |  | 部分 | 通过 | network：`tcp`、`tcp+udp`、`udp`<br>override_address：`off`、`on`<br>override_port：`off`、`on`<br>约束：network 留空时 TCP、UDP 都启用 |
| `network` | 监听的网络协议，`tcp` `udp` 之一。 |  | 有 |  | 已实现 | 通过 | 取值：`tcp`、`udp`<br>约束：默认所有。 |
| `override-address` | 覆盖连接目标地址。 |  | 有 |  | 已实现 | 通过 |  |
| `override-port` | 覆盖连接目标端口。 |  | 有 |  | 已实现 | 通过 |  |

## fallback

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | 回落组合 |  |  | 有 | 已实现 | 通过 | protocol：`trojan`、`vless`<br>transport：`raw`<br>security：`tls`<br>match：`alpn`、`default`、`name`、`path`<br>dest：`tcp`、`uds`<br>xver：`0`、`1`、`2`<br>约束：gRPC 不支持回落到其他服务<br>约束：其他传输必须删掉 fallbacks<br>约束：只能用于 TCP+TLS<br>约束：有子元素时 Inbound TLS 需 alpn ["http/1.1"]<br>约束：被分流的 WS 入站无需 TLS<br>约束：通常先配一个默认回落 |
| `alpn` | 匹配协商出的 ALPN，默认任意 |  |  | 有 | 已实现 | 通过 | 约束：fallbacks alpn 有 h2 时 Inbound TLS 须 alpn ["h2","http/1.1"] |
| `dest` | 回落目标，必填 |  |  | 有 | 已实现 | 通过 | 取值：`"80"`、`/dev/shm/domain.socket`、`80`、`@@padded`、`@abstract`、`addr:port`<br>约束：只写端口时 addr 为 localhost（v25.7.26 起，之前 127.0.0.1）<br>约束：域名直接发 TCP，不走内置 DNS |
| `match-priority` | 匹配最精确子元素，与顺序无关；alpn 和 path 相同时以最后为准 |  |  | 有 | 已实现 | 通过 |  |
| `name` | 匹配 TLS SNI，默认任意 |  |  | 有 | 已实现 | 通过 |  |
| `overview` | VLESS/Trojan 回落：解密后首包不合法或认证失败时转发到 dest |  |  | 有 | 已实现 | 通过 | 约束：VLESS 触发：解密后首包长度小于 18、版本无效或认证失败 |
| `path` | 匹配首包 HTTP PATH，默认任意 |  |  | 有 | 已实现 | 通过 | 约束：alpn h2 不支持 path（source:infra/conf/vless.go）<br>约束：不支持 h2c<br>约束：最多看 55 字节<br>约束：非空必须以 / 开头 |
| `type` | 回落网络类型，文档未写 |  |  | 有 | 已实现 | 通过 |  |
| `xver` | 发送 PROXY protocol 版本，默认 0 |  |  | 有 | 未实现 | 未测 | 取值：`0`、`1`、`2` |

## global

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `allow-lan` | 允许其他设备经代理端口访问 | 有 |  |  | 部分 | 通过 | 取值：`false`、`true` |
| `bind-address` | 绑定地址，仅允许经此地址访问 | 有 |  |  | 已实现 | 通过 | 取值：`*`、`IPv4 地址`、`[IPv6 地址]`<br>约束：仅 allow-lan 为 true 时有意义 |
| `inbound-mptcp` | 入站 MPTCP（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `inbound-tfo` | 入站 TCP Fast Open（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `lan-allowed-ips` | 允许连接的地址段白名单，默认 0.0.0.0/0 与 ::/0 | 有 |  |  | 已实现 | 通过 | 取值：`CIDR 列表`<br>约束：仅作用于 allow-lan 为 true |
| `lan-disallowed-ips` | 禁止连接的地址段黑名单，默认空 | 有 |  |  | 已实现 | 通过 | 取值：`CIDR 列表`<br>约束：黑名单优先级高于白名单 |
| `listeners` | 多入站列表，可同时建多个类型、地址、端口的入站并单独设 rule、proxy | 有 |  |  | 已实现 | 通过 | 取值：`数组`<br>约束：listen: 0.0.0.0 监听所有接口，未启用 TLS 的 HTTP、SOCKS、Mixed 不应直接暴露公网<br>约束：listener 中的 tun 面向高级场景 |
| `mixed-port` | 混合端口，同时支持 HTTP(S) 与 SOCKS5 | 有 |  |  | 已实现 | 通过 | 取值：`端口` |
| `port` | http(s) 代理端口 | 有 |  |  | 已实现 | 通过 | 取值：`端口` |
| `redir-port` | redirect 透明代理端口 | 有 |  |  | 已实现 | 通过 | 取值：`端口`<br>约束：仅 Linux(Android)、macOS<br>约束：仅代理 TCP |
| `socks-port` | socks4/4a/5 代理端口 | 有 |  |  | 已实现 | 通过 | 取值：`端口` |
| `tproxy-port` | tproxy 透明代理端口 | 有 |  |  | 已实现 | 通过 | 取值：`端口`<br>约束：仅 Linux(Android)<br>约束：代理 TCP 与 UDP |

## http

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `http` | HTTP 代理入站，只能代理 TCP |  |  | 有 | 已实现 | 通过 | 取值：`http` |
| `protocol` | HTTP 入站 | 有 | 有 |  | 已实现 | 通过 | 取值：`http`<br>约束：可作 detour 注入目标（Injectable：TCP） |
| `combo` | HTTP 入站组合 | 有 | 有 | 有 | 部分 | 通过 | tls：`mtls`、`none`、`tls`<br>ech：`off`、`on`<br>auth：`global`、`users`、`users: []`<br>约束：ech 依赖 tls<br>约束：source:listener/inbound/http.go 另有 reality-config<br>version：`1`、`2`、`3`<br>security：`none`、`tls`<br>auth：`none`、`users`<br>set_system_proxy：`off`、`on`<br>tuning：`http2-fields`、`quic-fields`<br>约束：3 必须配 TLS<br>约束：version 含 2 时用 HTTP2 字段，含 3 时替换为 QUIC 字段<br>约束：version 自 1.15.0 起<br>约束：默认提供 1 和 2<br>transport：`grpc`、`httpupgrade`、`hysteria`、`mkcp`、`raw`、`websocket`、`xhttp`<br>security：`none`、`reality`、`tls`<br>auth：`basic`、`none`<br>约束：masque 传输不适用<br>约束：只代理 TCP，UDP 不通过 |
| `accounts` | users 的别名 |  |  | 有 | 已实现 | 通过 |  |
| `allow-transparent` | true 时转发所有 HTTP 请求而非仅代理请求 |  |  | 有 | 未实现 | 未测 | 约束：配置不当会死循环 |
| `certificate` | TLS 证书，PEM 或路径 | 有 |  |  | 已实现 | 通过 | 取值：`PEM`、`路径`<br>约束：与 private-key 同时填写才开启 tls |
| `client-auth-cert` | mTLS 客户端证书 | 有 |  |  | 未实现 | 未测 | 取值：`PEM`、`路径` |
| `client-auth-type` | mTLS 类型 | 有 |  |  | 未实现 | 未测 | 取值：``、`request`、`require-and-verify`、`require-any`、`verify-if-given`<br>约束：verify-if-given、require-and-verify 时 client-auth-cert 必填 |
| `domain-resolver` | http 入站的 domain_resolver，配置文档未列 |  | 有 |  | 未实现 | 未测 |  |
| `ech-key` | ECH 密钥，填写即开启；可由 mihomo generate ech-keypair 生成 | 有 |  |  | 未实现 | 未测 | 取值：`PEM` |
| `pass` | UserObject 密码，必填 |  |  | 有 | 已实现 | 通过 |  |
| `private-key` | TLS 私钥，PEM 或路径 | 有 |  |  | 已实现 | 通过 | 取值：`PEM`、`路径`<br>约束：与 certificate 同时填写 |
| `reality-config` | http 入站字段 reality-config（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `set-system-proxy` | 启动时自动设置系统代理，停止时自动清理。 |  | 有 |  | 未实现 | 未测 | 约束：仅支持 Linux、Android、Windows 和 macOS。 |
| `tls` | TLS 配置, 参阅 TLS。 |  | 有 |  | 部分 | 通过 |  |
| `user` | UserObject 用户名，必填 |  |  | 有 | 已实现 | 通过 |  |
| `user-level` | 用户等级，默认 0 |  |  | 有 | 未实现 | 未测 |  |
| `users` | HTTP 用户如果为空则不需要验证。 |  | 有 | 有 | 已实现 | 通过 |  |
| `users-password` | 密码 | 有 | 有 |  | 已实现 | 通过 | 取值：`字符串` |
| `users-username` | 用户名 | 有 | 有 |  | 已实现 | 通过 | 取值：`字符串`<br>约束：不填 users 遵从全局验证；填写忽略全局；users: [] 跳过该入站验证 |
| `version` | 提供的 HTTP 版本列表。 |  | 有 |  | 部分 | 通过 | 取值：`1`、`2`、`3`<br>约束：`3` 需要 TLS。<br>约束：自 sing-box 1.15.0 起<br>约束：默认为 `1` 和 `2`。 |

## hysteria

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `hysteria` | Hysteria2 代理协议入站 |  |  | 有 | 已实现 | 通过 | 取值：`hysteria`<br>约束：协议本身无认证，users 仅搭配 hysteria 传输层生效 |
| `protocol` | Hysteria 入站 |  | 有 |  | 已实现 | 通过 | 取值：`hysteria`<br>约束：不可作 detour 注入目标 |
| `combo` | Hysteria 入站的带宽写法、混淆和认证组合 |  | 有 | 有 | 部分 | 通过 | bandwidth_format：`up/down`、`up_mbps/down_mbps`<br>obfs：`off`、`on`<br>auth：`auth`、`auth_str`<br>tuning：`deprecated-window-fields`、`quic-fields`<br>约束：recv_window_conn、recv_window_client、max_conn_client、disable_mtu_discovery 自 1.14.0 废弃，改用 QUIC 字段<br>约束：tls 必填<br>约束：up、down 必填<br>transport：`hysteria`<br>security：`tls`<br>约束：security 必须 tls<br>约束：不支持 none 和 reality<br>约束：只能配 hysteria 传输 |
| `auth` | 任意长度字符串 |  |  | 有 | 已实现 | 通过 |  |
| `clients` | users 的别名 |  |  | 有 | 已实现 | 通过 |  |
| `disable-mtu-discovery` | 请使用 QUIC 字段 `disable_path_mtu_discovery` 代替。 |  | 废弃 |  | 未实现 | 未测 |  |
| `down` | 格式: `[Integer] [Unit]` 例如： `100 Mbps, 640 KBps, 2 Gbps`支持的单位 (大小写敏感, b = bits, B = bytes, 8b=1B)： |  | 有 |  | 部分 | 通过 | 约束：单位区分大小写：bps Bps Kbps KBps Mbps MBps Gbps GBps Tbps TBps<br>约束：必填 |
| `down-mbps` | 以 Mbps 为单位的 `up, down`。 |  | 有 |  | 部分 | 通过 | 约束：必填 |
| `email` | 用户邮箱 |  |  | 有 | 已实现 | 通过 |  |
| `level` | 用户等级，默认 0 |  |  | 有 | 未实现 | 未测 |  |
| `max-conn-client` | 请使用 QUIC 字段 `max_concurrent_streams` 代替。 |  | 废弃 |  | 已实现 | 通过 |  |
| `obfs` | 混淆密码。 |  | 有 |  | 已实现 | 通过 |  |
| `recv-window-client` | 请使用 QUIC 字段 `connection_receive_window` 代替。 |  | 废弃 |  | 未实现 | 未测 |  |
| `recv-window-conn` | 请使用 QUIC 字段 `stream_receive_window` 代替。 |  | 废弃 |  | 未实现 | 未测 |  |
| `tls` | TLS 配置, 参阅 TLS。 |  | 有 |  | 部分 | 通过 | 约束：必填 |
| `up` | 格式: `[Integer] [Unit]` 例如： `100 Mbps, 640 KBps, 2 Gbps`支持的单位 (大小写敏感, b = bits, B = bytes, 8b=1B)： |  | 有 |  | 部分 | 通过 | 约束：单位区分大小写：bps Bps Kbps KBps Mbps MBps Gbps GBps Tbps TBps<br>约束：必填 |
| `up-mbps` | 以 Mbps 为单位的 `up, down`。 |  | 有 |  | 部分 | 通过 | 约束：必填 |
| `users` | Hysteria 用户 |  | 有 | 有 | 已实现 | 通过 |  |
| `users-auth` | base64 编码的认证密码。 |  | 有 |  | 已实现 | 通过 |  |
| `users-auth-str` | 认证密码。 |  | 有 |  | 已实现 | 通过 |  |
| `users-name` | 用户名称，用于日志和 auth_user 匹配 |  | 有 |  | 已实现 | 通过 |  |
| `version` | Hysteria 版本 |  |  | 有 | 已实现 | 通过 | 取值：`2`<br>约束：必须为 2 |

## hysteria2

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | Hysteria2 入站 | 有 | 有 |  | 已实现 | 通过 | 取值：`hysteria2`<br>约束：不可作 detour 注入目标 |
| `combo` | Hysteria2 入站组合 | 有 | 有 |  | 部分 | 通过 | obfs：`none`、`salamander`<br>masquerade：`file`、`http`、`https`、`none`<br>ignore-client-bandwidth：`false`、`true`<br>bbr-profile：`aggressive`、`conservative`、`standard`<br>realm：`off`、`on`<br>ech：`off`、`on`<br>client-auth-type：``、`request`、`require-and-verify`、`require-any`、`verify-if-given`<br>mux：`brutal`、`off`、`padding`<br>约束：listener 文档 obfs 只列 salamander；gecko 仅出站页写明，source:listener/inbound/hysteria2.go 另有 obfs-min-packet-size、obfs-max-packet-size<br>约束：obfs 启用后与标准 QUIC 不兼容<br>obfs：`gecko`、`none`、`salamander`<br>congestion：`bbr(ignore_client_bandwidth)`、`brutal(up/down)`<br>bbr_profile：`aggressive`、`conservative`、`standard`<br>masquerade：`file://`、`http(s)://`、`none`、`type:file`、`type:proxy`、`type:string`<br>realm_ip_version：`4`、`6`、`both`<br>port_mapping：`off`、`on`<br>brutal_debug：`off`、`on`<br>约束：listen 地址必须与 realm.ip_version 兼容<br>约束：masquerade 字符串与 masquerade.type 对象冲突<br>约束：obfs.min_packet_size、max_packet_size 仅 gecko<br>约束：realm.port_mapping 需要 IPv4，与 ip_version 6 冲突<br>约束：sing-box 不提供 userpass 别名，对接官方程序时用 <用户名>:<密码> 作为密码<br>约束：tls 必填<br>约束：up_mbps、down_mbps 与 ignore_client_bandwidth 冲突 |
| `alpn` | ALPN，默认 h3；客户端需写入其中之一否则认证失败 | 有 |  |  | 未实现 | 未测 | 取值：`列表` |
| `bbr-profile` | BBR 档位，默认 standard | 有 | 有 |  | 未实现 | 未测 | 取值：`aggressive`、`conservative`、`standard`<br>约束：自 sing-box 1.14.0 起<br>约束：默认使用 `standard`。 |
| `brutal-debug` | 启用 Hysteria Brutal CC 的调试信息日志记录。 |  | 有 |  | 未实现 | 未测 |  |
| `certificate` | TLS 证书，PEM 或路径 | 有 |  |  | 已实现 | 通过 | 取值：`PEM`、`路径`<br>约束：与 private-key 同时填写才开启 tls |
| `client-auth-cert` | mTLS 客户端证书 | 有 |  |  | 未实现 | 未测 | 取值：`PEM`、`路径` |
| `client-auth-type` | mTLS 类型 | 有 |  |  | 未实现 | 未测 | 取值：``、`request`、`require-and-verify`、`require-any`、`verify-if-given`<br>约束：verify-if-given、require-and-verify 时 client-auth-cert 必填 |
| `cwnd` | hysteria2 入站字段 cwnd（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `down` | 速率，默认 Mbps | 有 |  |  | 已实现 | 通过 | 取值：`整数` |
| `down-mbps` | 支持的速率，默认不限制。 |  | 有 |  | 已实现 | 通过 | 约束：与 `ignore_client_bandwidth` 冲突。 |
| `ech-key` | ECH 密钥，填写即开启；可由 mihomo generate ech-keypair 生成 | 有 |  |  | 未实现 | 未测 | 取值：`PEM` |
| `ignore-client-bandwidth` | 忽略客户端带宽，永远用传统拥塞控制 BBR | 有 | 有 |  | 部分 | 通过 | 取值：`false`、`true` |
| `initial-connection-receive-window` | hysteria2 入站字段 initial-connection-receive-window（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `initial-stream-receive-window` | hysteria2 入站字段 initial-stream-receive-window（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `masquerade` | 伪装 HTTP/3，为空始终返回 404 | 有 | 有 |  | 已实现 | 通过 | 取值：`file:///path`、`file:///var/www`、`http://127.0.0.1:8080`、`http://host`、`https://`、`https://host`<br>约束：仅支持 file、http/https<br>约束：与 `masquerade.type` 冲突。 |
| `masquerade-content` | 固定响应内容。 |  | 有 |  | 已实现 | 通过 |  |
| `masquerade-directory` | 文件服务器根目录。 |  | 有 |  | 已实现 | 通过 |  |
| `masquerade-headers` | 固定响应头。 |  | 有 |  | 已实现 | 通过 |  |
| `masquerade-rewrite-host` | 重写请求头中的 Host 字段到目标 URL。 |  | 有 |  | 已实现 | 通过 |  |
| `masquerade-status-code` | 固定响应状态码。 |  | 有 |  | 已实现 | 通过 |  |
| `masquerade-type` | HTTP3 服务器认证失败时的行为 （对象配置）。 |  | 有 |  | 已实现 | 通过 | 取值：`file`、`proxy`、`string`<br>约束：与 `masquerade` 冲突。 |
| `masquerade-url` | 反向代理目标 URL。 |  | 有 |  | 已实现 | 通过 |  |
| `max-connection-receive-window` | hysteria2 入站字段 max-connection-receive-window（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `max-idle-time` | hysteria2 入站字段 max-idle-time（文档页未写，配置结构存在） | 有 |  |  | 已实现 | 通过 |  |
| `max-stream-receive-window` | hysteria2 入站字段 max-stream-receive-window（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `mux-option-brutal-down` | Brutal 下行，默认 Mbps | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `mux-option-brutal-enabled` | 入站 TCP Brutal | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `mux-option-brutal-up` | Brutal 上行，默认 Mbps | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `mux-option-padding` | 入站 sing-mux 填充 | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true` |
| `obfs` | QUIC 混淆，为空禁用 | 有 | 有 |  | 部分 | 通过 | 取值：`salamander`<br>约束：启用混淆与标准 QUIC 不兼容，失去 HTTP/3 伪装 |
| `obfs-max-packet-size` | hysteria2 入站字段 obfs-max-packet-size（文档页未写，配置结构存在） | 有 | 有 |  | 未实现 | 未测 | 约束：仅限 Gecko。<br>约束：自 sing-box 1.14.0 起<br>约束：默认使用 `1200`。 |
| `obfs-min-packet-size` | hysteria2 入站字段 obfs-min-packet-size（文档页未写，配置结构存在） | 有 | 有 |  | 未实现 | 未测 | 约束：仅限 Gecko。<br>约束：自 sing-box 1.14.0 起<br>约束：默认使用 `512`。 |
| `obfs-password` | 混淆密码 | 有 | 有 |  | 已实现 | 通过 | 取值：`字符串` |
| `obfs-type` | QUIC 流量混淆器类型，可选 `salamander` `gecko`。 |  | 有 |  | 部分 | 通过 | 取值：`gecko`、`salamander` |
| `private-key` | TLS 私钥，PEM 或路径 | 有 |  |  | 已实现 | 通过 | 取值：`PEM`、`路径`<br>约束：与 certificate 同时填写 |
| `realm` | 将此入站注册到 Hysteria Realm 会合服务，以启用 NAT 穿透。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `realm-http-client` | 与 realm 通信使用的 HTTP 客户端。 |  | 有 |  | 未实现 | 未测 |  |
| `realm-ip-version` | 将 realm 连接（STUN、打洞与最终的 QUIC 路径）限制为单一 IP 版本。 |  | 有 |  | 未实现 | 未测 | 取值：`4`、`6`<br>约束：`listen` 地址必须与所选版本兼容。<br>约束：默认使用两者。 |
| `realm-opts-alpn` | server-url 的 TLS 配置：ALPN | 有 |  |  | 未实现 | 未测 |  |
| `realm-opts-certificate` | server-url 的 TLS 配置：客户端证书 | 有 |  |  | 未实现 | 未测 |  |
| `realm-opts-enable` | 启用 realm，必须手动开启 | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `realm-opts-fingerprint` | server-url 的 TLS 配置：证书指纹 | 有 |  |  | 未实现 | 未测 |  |
| `realm-opts-name-cert-verify` | server-url 的 TLS 配置：校验名 | 有 |  |  | 未实现 | 未测 |  |
| `realm-opts-private-key` | server-url 的 TLS 配置：客户端私钥 | 有 |  |  | 未实现 | 未测 |  |
| `realm-opts-proxy` | server-url 经过的代理 | 有 |  |  | 未实现 | 未测 | 取值：`出站名` |
| `realm-opts-realm-id` | realm ID | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `realm-opts-server-url` | realm 服务器 URL | 有 |  |  | 未实现 | 未测 | 取值：`URL` |
| `realm-opts-skip-cert-verify` | server-url 的 TLS 配置：跳过验证 | 有 |  |  | 未实现 | 未测 |  |
| `realm-opts-sni` | server-url 的 TLS 配置：SNI | 有 |  |  | 未实现 | 未测 |  |
| `realm-opts-stun-servers` | STUN 服务器 | 有 |  |  | 未实现 | 未测 | 取值：`host:port 列表` |
| `realm-opts-token` | realm Bearer 令牌 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `realm-port-mapping` | 通过 UPnP 或 NAT-PMP 在本地网关上维护 UDP 端口映射。 |  | 有 |  | 未实现 | 未测 | 约束：需要 IPv4：与 `"ip_version": 6` 冲突。 |
| `realm-port-mapping-enabled` | 启用端口映射。 |  | 有 |  | 未实现 | 未测 |  |
| `realm-port-mapping-lifetime` | 映射的租约时长。 |  | 有 |  | 未实现 | 未测 | 约束：默认使用 `10m`。 |
| `realm-port-mapping-timeout` | 网关发现与映射操作的超时。 |  | 有 |  | 未实现 | 未测 | 约束：默认使用 `10s`。 |
| `realm-realm-id` | Realm 上的槽位标识符。 |  | 有 |  | 未实现 | 未测 | 约束：必填 |
| `realm-server-url` | Realm 会合服务 URL。 |  | 有 |  | 未实现 | 未测 | 约束：必填 |
| `realm-stun-domain-resolver` | 用于解析 STUN 服务器域名的域名解析器。 |  | 有 |  | 未实现 | 未测 | 约束：如果为空，则使用默认域名解析器。 |
| `realm-stun-servers` | 用于发现公网地址的 STUN 服务器列表（`host` 或 `host:port`）。 |  | 有 |  | 未实现 | 未测 | 约束：必填 |
| `realm-token` | Realm 的 Bearer 令牌，需与 realm 上配置的 `users[].token` 之一匹配。 |  | 有 |  | 未实现 | 未测 |  |
| `tls` | TLS 配置, 参阅 TLS。 |  | 有 |  | 部分 | 通过 | 约束：必填 |
| `udp-mtu` | hysteria2 入站字段 udp-mtu（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `up` | 速率，默认 Mbps | 有 |  |  | 已实现 | 通过 | 取值：`整数` |
| `up-mbps` | 支持的速率，默认不限制。 |  | 有 |  | 已实现 | 通过 | 约束：与 `ignore_client_bandwidth` 冲突。 |
| `users` | 用户映射；用户名不参与认证，仅用于 IN-USER | 有 | 有 |  | 已实现 | 通过 | 取值：`username: password` |
| `users-name` | 用户名称，用于日志和 auth_user 匹配 |  | 有 |  | 已实现 | 通过 |  |
| `users-password` | 认证密码。 |  | 有 |  | 已实现 | 通过 |  |

## hysteria2-realm

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | Hysteria2 realm-opts.server-url 的 HTTP/HTTPS 服务端 | 有 |  |  | 未实现 | 未测 |  |
| `combo` | Hysteria2 realm 入站组合 | 有 |  |  | 未实现 | 未测 | scheme：`http`、`https`<br>client-auth-type：``、`request`、`require-and-verify`、`require-any`、`verify-if-given`<br>ech：`off`、`on`<br>约束：配置证书提供 HTTPS，否则明文 HTTP |
| `alpn` | ALPN | 有 |  |  | 未实现 | 未测 | 取值：`h2`、`http/1.1` |
| `certificate` | TLS 证书，PEM 或路径 | 有 |  |  | 未实现 | 未测 | 取值：`PEM`、`路径`<br>约束：与 private-key 同时填写才开启 tls |
| `client-auth-cert` | mTLS 客户端证书 | 有 |  |  | 未实现 | 未测 | 取值：`PEM`、`路径` |
| `client-auth-type` | mTLS 类型 | 有 |  |  | 未实现 | 未测 | 取值：``、`request`、`require-and-verify`、`require-any`、`verify-if-given`<br>约束：verify-if-given、require-and-verify 时 client-auth-cert 必填 |
| `ech-key` | ECH 密钥，填写即开启；可由 mihomo generate ech-keypair 生成 | 有 |  |  | 未实现 | 未测 | 取值：`PEM` |
| `max-realms` | 最大 realm 总数，0 不限 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `max-realms-per-ip` | 每 IP 最大 realm 数，0 不限 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `private-key` | TLS 私钥，PEM 或路径 | 有 |  |  | 未实现 | 未测 | 取值：`PEM`、`路径`<br>约束：与 certificate 同时填写 |
| `realm-name-pattern` | realm 名正则 | 有 |  |  | 未实现 | 未测 | 取值：`正则` |
| `token` | Bearer 令牌 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `trusted-proxy-header` | 读取真实客户端 IP 的头 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |

## list

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocols` | 入站协议列表页 |  |  | 有 | 不适用 | 未测 | 取值：`http`、`hysteria`、`masque`、`shadowsocks`、`socks`、`trojan`、`tun`、`tunnel`、`vless`、`vmess`、`wireguard` |

## listen

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | 入站通用监听字段的维度 |  | 有 |  | 部分 | 通过 | bind：`bind_interface`、`listen`、`netns`、`reuse_addr`、`routing_mark`<br>tcp：`disable_tcp_keep_alive`、`tcp_fast_open`、`tcp_keep_alive`、`tcp_keep_alive_interval`、`tcp_multi_path`<br>udp：`udp_fragment`、`udp_timeout`<br>detour：`off`、`on`<br>约束：detour 目标必须是 Injectable 入站<br>约束：listen 必填<br>约束：routing_mark、netns 仅 Linux<br>约束：sniff、domain_strategy 等旧字段 1.13.0 移除，配置后启动报错（source:option/inbound.go） |
| `bind-interface` | 要绑定到的网络接口。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.12.0 起 |
| `detour` | 如果设置，连接将被转发到指定的入站。 |  | 有 |  | 未实现 | 未测 | 约束：需要目标入站支持，参阅 注入支持。 |
| `disable-tcp-keep-alive` | 禁用 TCP keep alive。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.13.0 起 |
| `domain-strategy` | 可选值： `prefer_ipv4` `prefer_ipv6` `ipv4_only` `ipv6_only`。 |  | 已移除 |  | 部分 | 通过 | 取值：`ipv4_only`、`ipv6_only`、`prefer_ipv4`、`prefer_ipv6`<br>约束：入站字段已废弃且将在 sing-box 1.12.0 中被移除，参阅 迁移指南. |
| `listen` | 监听地址。 |  | 有 |  | 已实现 | 通过 | 约束：必填 |
| `listen-port` | 监听端口。 |  | 有 |  | 已实现 | 通过 |  |
| `netns` | 设置网络命名空间，名称或路径。 |  | 有 |  | 未实现 | 未测 | 约束：仅支持 Linux。<br>约束：自 sing-box 1.12.0 起 |
| `proxy-protocol` | Proxy Protocol 入站字段，已移除 |  | 已移除 |  | 不适用 | 未测 | 约束：1.6.0 移除 |
| `proxy-protocol-accept-no-header` | Proxy Protocol 接受无头连接，已移除 |  | 已移除 |  | 不适用 | 未测 | 约束：1.6.0 移除 |
| `reuse-addr` | 重用监听地址。 |  | 有 |  | 部分 | 通过 | 约束：自 sing-box 1.12.0 起 |
| `routing-mark` | 设置 netfilter 路由标记。 |  | 有 |  | 未实现 | 未测 | 约束：仅支持 Linux。<br>约束：自 sing-box 1.12.0 起 |
| `sniff` | 启用协议探测。 |  | 已移除 |  | 未实现 | 未测 | 约束：入站字段已废弃且将在 sing-box 1.12.0 中被移除，参阅 迁移指南. |
| `sniff-override-destination` | 用探测出的域名覆盖连接目标地址。 |  | 已移除 |  | 未实现 | 未测 | 约束：入站字段已废弃且将在 sing-box 1.12.0 中被移除。<br>约束：如果域名无效（如 Tor），将不生效。 |
| `sniff-timeout` | 探测超时时间。 |  | 已移除 |  | 未实现 | 未测 | 约束：入站字段已废弃且将在 sing-box 1.12.0 中被移除，参阅 迁移指南.<br>约束：默认使用 300ms。 |
| `tcp-fast-open` | 启用 TCP Fast Open。 |  | 有 |  | 未实现 | 未测 |  |
| `tcp-keep-alive` | TCP keep alive 初始周期。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.13.0 起<br>约束：默认使用 `5m`。<br>约束：默认值从 `10m` 更改为 `5m`。 |
| `tcp-keep-alive-interval` | TCP keep alive 间隔。 |  | 有 |  | 未实现 | 未测 | 约束：默认使用 `75s`。 |
| `tcp-multi-path` | 启用 TCP Multi Path。 |  | 有 |  | 未实现 | 未测 | 约束：需要 Go 1.21。 |
| `udp-disable-domain-unmapping` | 如果启用，对于地址为域的 UDP 代理请求，将在响应中发送原始包地址而不是映射的域。 |  | 已移除 |  | 未实现 | 未测 | 约束：入站字段已废弃且将在 sing-box 1.12.0 中被移除，参阅 迁移指南.<br>约束：此选项用于兼容不支持接收带有域地址的 UDP 包的客户端，如 Surge。 |
| `udp-fragment` | 启用 UDP 分段。 |  | 有 |  | 未实现 | 未测 |  |
| `udp-timeout` | UDP NAT 过期时间。 |  | 有 |  | 部分 | 通过 | 约束：默认使用 `5m`。 |

## masque

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `masque` | MASQUE CONNECT-IP（RFC 9484）服务端 |  |  | 有 | 已实现 | 通过 | 取值：`masque`<br>约束：只能配 masque 传输且必须 tls<br>约束：每条隧道 HTTP Basic 认证，失败 401<br>约束：隧道内 TCP/UDP 还原后进路由；发往其他隧道地址的包直接转发 |
| `protocol` | MASQUE（CONNECT-IP，RFC 9484）服务端端点 |  | 有 |  | 已实现 | 通过 | 取值：`masque-server`<br>约束：自 sing-box 1.15.0 起<br>约束：配置在顶层 endpoints，同时具备入站和出站行为 |
| `combo` | MASQUE 服务端端点的版本、安全层和路由通告组合 |  | 有 | 有 | 已实现 | 通过 | version：`1`、`2`、`3`<br>security：`none(behind-tls-terminator)`、`tls`<br>auth：`none`、`users`<br>interface：`internal`、`system`<br>advertise_routes：`all`、`custom`<br>约束：IP 代理必须跑在 TLS 或 QUIC 上，只有前置终止 TLS 时才能不配<br>约束：address 必填，每个 IP 版本至多一个前缀<br>约束：发往未通告目标的客户端流量被拒绝<br>约束：默认提供全部 HTTP 版本，3 必须配 TLS<br>transport：`masque`<br>security：`tls`<br>http_version：`h2`、`h2+h3`、`h3`<br>ip_family：`dual`、`ipv4`、`ipv6`<br>约束：alpn 含 h2 时 TCP 提供 HTTP/2；含 h3 或不含 h2 时 UDP 提供 HTTP/3；都有时同端口同时提供<br>约束：不支持 REALITY |
| `address` | 隧道网络的 IP 前缀列表，每个 IP 版本最多一个。 |  | 有 | 有 | 已实现 | 通过 | 约束：必填<br>约束：自 sing-box 1.15.0 起<br>约束：IPv4 前缀最大 30，IPv6 最大 126<br>约束：地址耗尽时只发另一地址族；都耗尽返回 503<br>约束：最多一个 IPv4 和一个 IPv6 前缀 |
| `advertise-routes` | 除隧道网络外，向客户端声明的 IP 前缀列表。 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.15.0 起<br>约束：默认声明全部地址。 |
| `email` | 用户名，必填 |  |  | 有 | 已实现 | 通过 | 约束：不区分大小写不能重复<br>约束：不能含 : |
| `level` | 用户等级，只使用其流量统计设置 |  |  | 有 | 已实现 | 通过 |  |
| `mtu` | 隧道 MTU。 |  | 有 | 有 | 已实现 | 通过 | 取值：`1280-65535`<br>约束：自 sing-box 1.15.0 起<br>约束：默认使用 `1280`。 |
| `name` | 系统接口的自定义接口名称。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.15.0 起<br>约束：默认使用自动生成的 `masque` 接口名称。 |
| `pass` | 密码，必填 |  |  | 有 | 已实现 | 通过 |  |
| `path` | IP 代理资源的 URI 模板路径，可以包含 `target` 和 `ipproto` 变量。 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.15.0 起<br>约束：默认使用 `/.well-known/masque/ip/{target}/{ipproto}/`。 |
| `system` | 使用系统接口。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.15.0 起<br>约束：需要特权且不能与已有系统接口冲突。 |
| `tls` | TLS 配置，参阅 TLS。 |  | 有 |  | 已实现 | 通过 | 约束：IP 代理必须运行在 TLS 或 QUIC 之上。<br>约束：仅当服务器位于终止 TLS 的 HTTP 中间层之后时才可以不启用。<br>约束：自 sing-box 1.15.0 起 |
| `users` | HTTP 用户，通过 `Authorization` 标头验证。 |  | 有 | 有 | 已实现 | 通过 | 约束：如果为空则不需要验证。<br>约束：自 sing-box 1.15.0 起<br>约束：API 删除用户时立即关闭其隧道<br>约束：没有用户时所有连接被拒绝 |
| `users-password` | 密码 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.15.0 起 |
| `users-username` | 用户名 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.15.0 起 |
| `version` | 提供的 HTTP 版本列表。 |  | 有 |  | 已实现 | 通过 | 取值：`1`、`2`、`3`<br>约束：`3` 需要 TLS。<br>约束：自 sing-box 1.15.0 起<br>约束：默认提供全部版本。 |

## mieru

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | Mieru 入站 | 有 |  |  | 已实现 | 通过 |  |
| `combo` | Mieru 入站组合 | 有 |  |  | 部分 | 通过 | transport：`TCP`、`UDP`<br>user-hint-is-mandatory：`false`、`true` |
| `traffic-pattern` | base64 字符串，微调网络行为 | 有 |  |  | 部分 | 通过 | 取值：`base64` |
| `transport` | 传输 | 有 |  |  | 部分 | 通过 | 取值：`TCP`、`UDP` |
| `user-hint-is-mandatory` | 客户端不发用户提示则拒绝 | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true` |
| `users` | 用户映射 | 有 |  |  | 已实现 | 通过 | 取值：`username: password` |

## mixed

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `mixed` | socks 配置的协议别名，Socks 入站同时接受 HTTP |  |  | 有 | 已实现 | 通过 | 取值：`mixed` |
| `protocol` | Mixed 入站 | 有 | 有 |  | 已实现 | 通过 | 取值：`mixed`<br>约束：可作 detour 注入目标（Injectable：TCP） |
| `combo` | Mixed 入站组合 | 有 | 有 |  | 已实现 | 通过 | tls：`mtls`、`none`、`tls`<br>ech：`off`、`on`<br>auth：`global`、`users`、`users: []`<br>udp：`false`、`true`<br>protocol：`http`、`socks5`<br>约束：ech 依赖 tls<br>约束：source:listener/inbound/mixed.go 另有 reality-config<br>protocol：`http`、`socks4`、`socks4a`、`socks5`<br>auth：`none`、`users`<br>set_system_proxy：`off`、`on`<br>约束：Android 和 Apple 无特权时用 tun.platform.http_proxy<br>约束：set_system_proxy 仅支持 Linux、Android、Windows、macOS |
| `certificate` | TLS 证书，PEM 或路径 | 有 |  |  | 未实现 | 未测 | 取值：`PEM`、`路径`<br>约束：与 private-key 同时填写才开启 tls |
| `client-auth-cert` | mTLS 客户端证书 | 有 |  |  | 未实现 | 未测 | 取值：`PEM`、`路径` |
| `client-auth-type` | mTLS 类型 | 有 |  |  | 未实现 | 未测 | 取值：``、`request`、`require-and-verify`、`require-any`、`verify-if-given`<br>约束：verify-if-given、require-and-verify 时 client-auth-cert 必填 |
| `domain-resolver` | mixed 入站的 domain_resolver，配置文档未列 |  | 有 |  | 未实现 | 未测 |  |
| `ech-key` | ECH 密钥，填写即开启；可由 mihomo generate ech-keypair 生成 | 有 |  |  | 未实现 | 未测 | 取值：`PEM` |
| `private-key` | TLS 私钥，PEM 或路径 | 有 |  |  | 未实现 | 未测 | 取值：`PEM`、`路径`<br>约束：与 certificate 同时填写 |
| `reality-config` | mixed 入站字段 reality-config（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `set-system-proxy` | 启动时自动设置系统代理，停止时自动清理。 |  | 有 |  | 未实现 | 未测 | 约束：仅支持 Linux、Android、Windows 和 macOS。 |
| `tls` | mixed 入站的 TLS 字段，配置文档未列 |  | 有 |  | 未实现 | 未测 |  |
| `udp` | 是否监听 UDP | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true` |
| `users` | SOCKS 和 HTTP 用户如果为空则不需要验证。 |  | 有 |  | 已实现 | 通过 |  |
| `users-password` | 密码 | 有 | 有 |  | 已实现 | 通过 | 取值：`字符串` |
| `users-username` | 用户名 | 有 | 有 |  | 已实现 | 通过 | 取值：`字符串`<br>约束：不填 users 遵从全局验证；填写忽略全局；users: [] 跳过该入站验证 |

## naive

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | NaiveProxy 入站 |  | 有 |  | 已实现 | 通过 | 取值：`naive`<br>约束：不可作 detour 注入目标 |
| `combo` | NaiveProxy 入站的网络、TLS 和拥塞控制组合 |  | 有 |  | 部分 | 通过 | network：`tcp`、`tcp+udp`、`udp`<br>security：`none`、`tls`<br>quic_congestion_control：`bbr`、`cubic`、`reno`<br>约束：network 含 udp 时走 QUIC，QUIC 服务必须配 TLS（source:protocol/naive/inbound.go）<br>约束：quic_congestion_control 自 1.13.0 起<br>约束：users 必填 |
| `network` | 监听的网络协议，`tcp` `udp` 之一。 |  | 有 |  | 已实现 | 通过 | 取值：`tcp`、`udp`<br>约束：默认所有。 |
| `quic-congestion-control` | QUIC 拥塞控制算法。 |  | 有 |  | 部分 | 通过 | 取值：`bbr`、`cubic`、`reno`<br>约束：自 sing-box 1.13.0 起<br>约束：默认使用 `bbr`。 |
| `tls` | TLS 配置, 参阅 TLS。 |  | 有 |  | 部分 | 通过 |  |
| `users` | Naive 用户。 |  | 有 |  | 已实现 | 通过 | 约束：必填 |
| `users-password` | 密码 |  | 有 |  | 已实现 | 通过 |  |
| `users-username` | 用户名 |  | 有 |  | 已实现 | 通过 |  |

## openvpn

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | OpenVPN 服务端端点 |  | 有 |  | 未实现 | 未测 | 取值：`openvpn-server`<br>约束：自 sing-box 1.14.0 起<br>约束：配置在顶层 endpoints，同时具备入站和出站行为 |
| `combo` | OpenVPN 服务端端点的模式、传输、客户端校验和推送组合 |  | 有 |  | 未实现 | 未测 | mode：`static_key`、`tls`<br>network：`tcp`、`udp`<br>topology：`net30`、`p2p`、`subnet`<br>control_wrap：`none`、`tls_auth`、`tls_crypt`、`tls_crypt_v2`<br>data_cipher_class：`aead`、`cbc`、`cfb`、`none`、`ofb`<br>certificate_profile：`insecure`、`legacy`、`preferred`、`suiteb`<br>mss_fix_mode：``、`fixed`、`mtu`<br>interface：`internal`、`system`<br>verify_client_certificate：`none`、`optional`、`require`<br>auth：`certificate`、`certificate+users`、`peer_fingerprint`、`users`<br>push：`block_outside_dns`、`dhcp_options`、`dns`、`dns_servers`、`ping_interval`、`ping_restart`、`redirect_gateway`、`routes`、`search_domains`<br>force_cookie：`off`、`on`<br>约束：UDP static_key 模式 remote、remote_port 必填<br>约束：address 必填，IPv4、IPv6 前缀各至多一个<br>约束：cipher 仅 static_key 模式<br>约束：control_wrap.direction 仅 tls_auth<br>约束：duplicate_cn、users、data_ciphers、renegotiate_*、handshake_window 仅 TLS 模式<br>约束：force_cookie 仅 tls_crypt_v2<br>约束：push.redirect_gateway_flags 仅在 push.redirect_gateway 开启时可用，默认 def1<br>约束：static_key 模式 max_clients 只能 0 或 1<br>约束：verify_client_certificate 为 require 或 optional 时 client_certificate、client_certificate_path、peer_fingerprint 必有其一<br>约束：每个端点只服务一种 network，同时服务 TCP、UDP 要配两个端点和不同 address |
| `address` | OpenVPN 服务器地址前缀列表。 |  | 有 |  | 未实现 | 未测 | 约束：必填<br>约束：自 sing-box 1.14.0 起 |
| `auth` | OpenVPN 数据信道认证摘要。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：默认使用 `SHA1`，仅对非 AEAD 数据信道加密方式和 `tls_auth` 生效。 |
| `cipher` | `static_key` 模式使用的数据信道加密方式。 |  | 有 |  | 未实现 | 未测 | 约束：为空时使用上游静态密钥模式的默认值 `BF-CBC`。<br>约束：仅在 `static_key` 模式下可用。<br>约束：自 sing-box 1.14.0 起 |
| `data-ciphers` | 允许的 OpenVPN 数据信道加密方式。 |  | 有 |  | 未实现 | 未测 | 约束：CFB 和 OFB 仅可用于 TLS 模式。<br>约束：仅在 TLS 模式下可用。<br>约束：自 sing-box 1.14.0 起<br>约束：默认使用 `AES-256-GCM`、`AES-128-GCM` 和 `CHACHA20-POLY1305`。 |
| `data-ciphers-fallback` | 用于不支持加密方式协商的遗留客户端的 OpenVPN 数据信道加密方式。 |  | 有 |  | 未实现 | 未测 | 约束：仅在 TLS 模式下可用。<br>约束：自 sing-box 1.14.0 起<br>约束：默认禁用。 |
| `duplicate-cn` | 允许具有相同认证证书 common name 或用户名的多个客户端同时在线。 |  | 有 |  | 未实现 | 未测 | 约束：仅在 TLS 模式下可用。<br>约束：自 sing-box 1.14.0 起<br>约束：默认禁用。 |
| `handshake-window` | 初始 TLS 握手和每次 TLS 重协商允许使用的最长时间。 |  | 有 |  | 未实现 | 未测 | 约束：仅在 TLS 模式下可用。<br>约束：自 sing-box 1.14.0 起<br>约束：默认使用 `1m`。 |
| `key-direction` | 静态密钥方向，`server` 或 `client` 之一。 |  | 有 |  | 未实现 | 未测 | 取值：`client`、`server`<br>约束：仅在 `static_key` 模式下可用。<br>约束：自 sing-box 1.14.0 起 |
| `max-clients` | 已建立与握手中的 TLS 客户端会话的最大数量。 |  | 有 |  | 未实现 | 未测 | 约束：在 `static_key` 模式下必须为 `0` 或 `1`。<br>约束：自 sing-box 1.14.0 起<br>约束：默认使用 `1024`。 |
| `mode` | OpenVPN 会话模式，`tls` 或 `static_key` 之一。 |  | 有 |  | 未实现 | 未测 | 取值：`static_key`、`tls`<br>约束：自 sing-box 1.14.0 起<br>约束：默认使用 `tls`。 |
| `mss-fix` | 用于限制 TCP MSS 的最大封装数据包大小。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：默认 MTU 下使用上游默认值 `1492` 计算。 |
| `mss-fix-disabled` | 禁用 MSS 限制，包括默认限制。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `mss-fix-mode` | 显式 `mss_fix` 的计算模式，`mtu` 或 `fixed` 之一。 |  | 有 |  | 未实现 | 未测 | 取值：`fixed`、`mtu`<br>约束：自 sing-box 1.14.0 起<br>约束：需要 `mss_fix`。 |
| `mtu` | OpenVPN 接口 MTU。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：默认使用 `1500`。 |
| `name` | 系统接口的自定义接口名称。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：默认使用自动生成的 `ovpn` 接口名称。 |
| `network` | OpenVPN 传输网络，`udp` 或 `tcp` 之一。 |  | 有 |  | 未实现 | 未测 | 取值：`tcp`、`udp`<br>约束：每个端点仅服务一种传输网络；如需同时服务 TCP 与 UDP，需要配置两个端点并使用互不重叠的 `address` 子网。<br>约束：自 sing-box 1.14.0 起<br>约束：默认使用 `udp`。 |
| `peer-address` | IPv4 隧道对端地址。 |  | 有 |  | 未实现 | 未测 | 约束：在 `static_key` 模式下配置 IPv4 `address` 时必填。<br>约束：自 sing-box 1.14.0 起 |
| `peer-address-ipv6` | IPv6 隧道对端地址。 |  | 有 |  | 未实现 | 未测 | 约束：在 `static_key` 模式下配置 IPv6 `address` 时必填。<br>约束：自 sing-box 1.14.0 起 |
| `ping-interval` | 服务器未向客户端发送任何 packet 时，发送 data channel ping 的间隔。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：该值必须使用整秒。<br>约束：默认禁用。 |
| `ping-restart` | 服务器未收到任何 packet 后关闭客户端会话的时间。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：该值必须使用整秒。<br>约束：默认禁用。 |
| `push` | 推送给客户端的选项。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `push-block-outside-dns` | 向客户端推送 `block-outside-dns`，在 Windows 客户端上阻止 VPN 之外的 DNS 查询。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `push-dhcp-options` | 推送的额外传统 `dhcp-option` 值，不包含 `dhcp-option` 前缀。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `push-dns` | 推送给客户端的 DNS 服务器地址。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `push-dns-servers` | 推送的现代 OpenVPN DNS 服务器组。 |  | 有 |  | 未实现 | 未测 | 约束：OpenVPN 客户端仅应用优先级数字最低的服务器组。<br>约束：OpenVPN 客户端只应用优先级数字最小的一组<br>约束：dnssec 取 yes、optional、no<br>约束：transport 取 plain、dot、doh<br>约束：自 sing-box 1.14.0 起 |
| `push-dns-servers-addresses` | OpenVPN 推送的现代 DNS 服务器组字段：DNS 服务器地址，IP 或 IP:port，IPv6 端口写 [IPv6]:port |  | 有 |  | 未实现 | 未测 |  |
| `push-dns-servers-dnssec` | OpenVPN 推送的现代 DNS 服务器组字段：DNSSEC 模式 |  | 有 |  | 未实现 | 未测 | 取值：`no`、`optional`、`yes` |
| `push-dns-servers-priority` | OpenVPN 推送的现代 DNS 服务器组字段：优先级，数字最小的一组生效 |  | 有 |  | 未实现 | 未测 |  |
| `push-dns-servers-resolve-domains` | OpenVPN 推送的现代 DNS 服务器组字段：由这组服务器解析的域名 |  | 有 |  | 未实现 | 未测 |  |
| `push-dns-servers-sni` | OpenVPN 推送的现代 DNS 服务器组字段：TLS SNI |  | 有 |  | 未实现 | 未测 |  |
| `push-dns-servers-transport` | OpenVPN 推送的现代 DNS 服务器组字段：传输方式 |  | 有 |  | 未实现 | 未测 | 取值：`doh`、`dot`、`plain` |
| `push-ping-interval` | 推送给客户端的 OpenVPN `ping` 间隔。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：该值必须使用整秒。<br>约束：默认禁用。 |
| `push-ping-restart` | 推送给客户端的 OpenVPN `ping-restart` 超时。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：该值必须使用整秒。<br>约束：默认禁用。 |
| `push-redirect-gateway` | 向客户端推送 `redirect-gateway`，根据 `push.redirect_gateway_flags` 通过 VPN 路由客户端流量。 |  | 有 |  | 未实现 | 未测 | 约束：当 `push.redirect_gateway_flags` 为空时，默认使用 `def1`。<br>约束：自 sing-box 1.14.0 起 |
| `push-redirect-gateway-flags` | 向客户端推送的 OpenVPN `redirect-gateway` flag。 |  | 有 |  | 未实现 | 未测 | 约束：仅当启用 `push.redirect_gateway` 时可用。<br>约束：自 sing-box 1.14.0 起<br>约束：默认使用 `def1`。 |
| `push-routes` | 推送给客户端的路由。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `push-search-domains` | 推送的现代 OpenVPN 搜索域。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `remote` | UDP `static_key` 服务器的固定远端地址。 |  | 有 |  | 未实现 | 未测 | 约束：在 UDP `static_key` 模式下与 `remote_port` 一起必填。<br>约束：自 sing-box 1.14.0 起 |
| `remote-port` | UDP `static_key` 服务器的固定远端端口。 |  | 有 |  | 未实现 | 未测 | 约束：在 UDP `static_key` 模式下与 `remote` 一起必填。<br>约束：自 sing-box 1.14.0 起 |
| `renegotiate-bytes` | 传输指定字节数后重新协商数据通道密钥。 |  | 有 |  | 未实现 | 未测 | 约束：`0` 使用与密码算法相关的 OpenVPN 默认值。<br>约束：仅在 TLS 模式下可用。<br>约束：自 sing-box 1.14.0 起 |
| `renegotiate-disabled` | 禁用基于时间的 TLS 重协商，包括默认间隔。 |  | 有 |  | 未实现 | 未测 | 约束：仅在 TLS 模式下可用。<br>约束：自 sing-box 1.14.0 起 |
| `renegotiate-interval` | OpenVPN TLS 重协商间隔。 |  | 有 |  | 未实现 | 未测 | 约束：为空时使用 OpenVPN 默认值 `1h`。<br>约束：仅在 TLS 模式下可用。<br>约束：自 sing-box 1.14.0 起 |
| `renegotiate-packets` | 传输指定数据包数后重新协商数据通道密钥。 |  | 有 |  | 未实现 | 未测 | 约束：`0` 使用与密码算法相关的 OpenVPN 默认值。<br>约束：仅在 TLS 模式下可用。<br>约束：自 sing-box 1.14.0 起 |
| `replay-window` | UDP 数据通道重放窗口大小。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：默认使用 `64`。 |
| `replay-window-time` | UDP 重放窗口时长。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：该值必须使用整秒。<br>约束：默认使用 `15s`。 |
| `static-key` | OpenVPN 静态密钥内容。 |  | 有 |  | 未实现 | 未测 | 约束：与 `static_key_path` 冲突。<br>约束：在 `static_key` 模式下必填。<br>约束：自 sing-box 1.14.0 起 |
| `static-key-path` | OpenVPN 静态密钥路径。 |  | 有 |  | 未实现 | 未测 | 约束：与 `static_key` 冲突。<br>约束：在 `static_key` 模式下未设置 `static_key` 时必填。<br>约束：自 sing-box 1.14.0 起 |
| `system` | 使用系统接口。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：需要特权且不能与已有系统接口冲突。 |
| `tls` | 在 TLS 模式下必填。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `tls-certificate` | TLS 服务器证书内容。 |  | 有 |  | 未实现 | 未测 | 约束：`tls.certificate` 或 `tls.certificate_path` 必填其一。<br>约束：与 `tls.certificate_path` 冲突。<br>约束：自 sing-box 1.14.0 起 |
| `tls-certificate-path` | TLS 服务器证书路径。 |  | 有 |  | 未实现 | 未测 | 约束：`tls.certificate` 或 `tls.certificate_path` 必填其一。<br>约束：与 `tls.certificate` 冲突。<br>约束：自 sing-box 1.14.0 起 |
| `tls-certificate-profile` | 证书 profile，可选值为 `insecure`、`legacy`、`preferred` 或 `suiteb`。 |  | 有 |  | 未实现 | 未测 | 取值：`insecure`、`legacy`、`preferred`、`suiteb`<br>约束：`insecure` 为兼容不可变对端而接受使用 MD5 或 SHA-1 签名的证书链和较小的旧密钥，仅应在对端无法升级时使用。<br>约束：自 sing-box 1.14.0 起<br>约束：选择 `suiteb` 且 `tls.cipher` 为空时，TLS 1.2 cipher 列表默认使用 Suite B ECDHE-ECDSA AES-GCM 套件。<br>约束：默认使用 `legacy`。 |
| `tls-cipher` | TLS 1.2 及更低版本允许的 OpenSSL cipher suite 名称，以冒号分隔。 |  | 有 |  | 未实现 | 未测 | 约束：为空时使用默认 TLS cipher suite。<br>约束：自 sing-box 1.14.0 起 |
| `tls-client-certificate` | TLS CA 证书内容，用于验证客户端证书。 |  | 有 |  | 未实现 | 未测 | 约束：与 `tls.client_certificate_path` 冲突。<br>约束：当 `tls.verify_client_certificate` 为 `require` 或 `optional` 时，`tls.client_certificate`、`tls.client_certificate_path` 或 `tls.peer_fingerprint` 必填其一。<br>约束：自 sing-box 1.14.0 起 |
| `tls-client-certificate-path` | TLS CA 证书路径，用于验证客户端证书。 |  | 有 |  | 未实现 | 未测 | 约束：与 `tls.client_certificate` 冲突。<br>约束：当 `tls.verify_client_certificate` 为 `require` 或 `optional` 时，`tls.client_certificate`、`tls.client_certificate_path` 或 `tls.peer_fingerprint` 必填其一。<br>约束：自 sing-box 1.14.0 起 |
| `tls-client-name` | 期望的客户端证书名称。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `tls-client-name-type` | tls.client_name 匹配的证书字段 |  | 有 |  | 未实现 | 未测 | 取值：`name`、`name-prefix`、`subject`<br>约束：自 sing-box 1.14.0 起<br>约束：配置 `tls.client_name` 时默认使用 `name`。 |
| `tls-control-wrap` | OpenVPN 控制信道包装。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：默认禁用。 |
| `tls-control-wrap-direction` | OpenVPN `tls-auth` 密钥方向，`server` 或 `client` 之一。 |  | 有 |  | 未实现 | 未测 | 取值：`client`、`server`<br>约束：仅当 `tls.control_wrap.type` 为 `tls_auth` 时可用。<br>约束：自 sing-box 1.14.0 起 |
| `tls-control-wrap-force-cookie` | 要求 UDP 上的 `tls-crypt-v2` 客户端支持无状态 session cookie。 |  | 有 |  | 未实现 | 未测 | 约束：仅当 `tls.control_wrap.type` 为 `tls_crypt_v2` 时可用。<br>约束：禁用时，不支持 cookie 的客户端会按照上游 `allow-noncookie` 行为被接受。<br>约束：自 sing-box 1.14.0 起<br>约束：默认禁用。 |
| `tls-control-wrap-key` | 控制信道包装密钥内容。 |  | 有 |  | 未实现 | 未测 | 约束：`tls.control_wrap.key` 或 `tls.control_wrap.key_path` 必填其一。<br>约束：与 `tls.control_wrap.key_path` 冲突。<br>约束：自 sing-box 1.14.0 起 |
| `tls-control-wrap-key-path` | 控制信道包装密钥路径。 |  | 有 |  | 未实现 | 未测 | 约束：`tls.control_wrap.key` 或 `tls.control_wrap.key_path` 必填其一。<br>约束：与 `tls.control_wrap.key` 冲突。<br>约束：自 sing-box 1.14.0 起 |
| `tls-control-wrap-type` | 控制信道包装类型，`tls_auth`、`tls_crypt` 或 `tls_crypt_v2` 之一。 |  | 有 |  | 未实现 | 未测 | 取值：`tls_auth`、`tls_crypt`、`tls_crypt_v2`<br>约束：必填<br>约束：自 sing-box 1.14.0 起 |
| `tls-crl-path` | 用于拒绝已吊销客户端证书的证书吊销列表路径。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `tls-groups` | 按偏好顺序排列的 TLS key exchange group，以冒号分隔。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `tls-key` | TLS 服务器私钥内容。 |  | 有 |  | 未实现 | 未测 | 约束：`tls.key` 或 `tls.key_path` 必填其一。<br>约束：与 `tls.key_path` 冲突。<br>约束：自 sing-box 1.14.0 起 |
| `tls-key-path` | TLS 服务器私钥路径。 |  | 有 |  | 未实现 | 未测 | 约束：`tls.key` 或 `tls.key_path` 必填其一。<br>约束：与 `tls.key` 冲突。<br>约束：自 sing-box 1.14.0 起 |
| `tls-ns-certificate-type` | 已弃用的 Netscape 证书类型检查，`server` 或 `client` 之一。 |  | 废弃 |  | 未实现 | 未测 | 取值：`client`、`server`<br>约束：自 sing-box 1.14.0 起 |
| `tls-peer-fingerprint` | 允许的客户端叶证书 SHA-256 指纹。 |  | 有 |  | 未实现 | 未测 | 约束：可以在没有客户端 CA 时仅使用指纹验证。<br>约束：自 sing-box 1.14.0 起 |
| `tls-remote-certificate-eku` | 客户端证书所需的 Extended Key Usage。 |  | 有 |  | 未实现 | 未测 | 约束：与显式配置的 `tls.remote_certificate_tls` 冲突。<br>约束：自 sing-box 1.14.0 起 |
| `tls-remote-certificate-ku` | OpenVPN `remote-cert-ku` 格式的客户端证书 Key Usage mask。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `tls-remote-certificate-tls` | 客户端证书用途检查，`server`、`client` 或 `none` 之一。 |  | 有 |  | 未实现 | 未测 | 取值：`client`、`none`、`server`<br>约束：自 sing-box 1.14.0 起<br>约束：默认使用 `client`。 |
| `tls-verify-client-certificate` | OpenVPN 客户端证书策略，`require`、`optional` 或 `none` 之一。 |  | 有 |  | 未实现 | 未测 | 取值：`none`、`optional`、`require`<br>约束：自 sing-box 1.14.0 起<br>约束：默认使用 `require`。 |
| `tls-version-max` | 最高 TLS 版本。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：默认使用支持的最高版本。 |
| `tls-version-min` | 最低 TLS 版本。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：默认使用 `1.2`。 |
| `topology` | 推送给客户端的 OpenVPN topology，`subnet`、`p2p` 或 `net30` 之一。 |  | 有 |  | 未实现 | 未测 | 取值：`net30`、`p2p`、`subnet`<br>约束：TLS 模式默认使用 `subnet`，`static_key` 模式默认使用 `p2p`。<br>约束：自 sing-box 1.14.0 起 |
| `users` | OpenVPN 用户名/密码用户列表。 |  | 有 |  | 未实现 | 未测 | 约束：仅在 TLS 模式下可用。<br>约束：如果设置，客户端除了通过 `tls.verify_client_certificate` 配置的证书策略外，还必须通过用户名/密码认证。<br>约束：自 sing-box 1.14.0 起 |
| `users-password` | 密码。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `users-username` | 用户名。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |

## redirect

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | Redirect 透明代理入站，type 写 redir | 有 |  |  | 已实现 | 通过 | 取值：`redir`<br>约束：仅 Linux(Android)、macOS<br>约束：仅 TCP |
| `combo` | Redirect 入站组合 | 有 |  |  | 已实现 | 通过 | network：`tcp`<br>platform：`android`、`linux`、`macos`<br>约束：不代理 UDP |

## shadowquic

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | ShadowQUIC 入站 | 有 |  |  | 已实现 | 通过 |  |
| `combo` | ShadowQUIC 入站组合 | 有 |  |  | 部分 | 通过 | quic-versions：`v1`、`v2`<br>congestion-controller：`bbr`、`cubic`、`new_reno`<br>bbr-profile：`aggressive`、`conservative`、`standard`<br>zero-rtt：`false`、`true`<br>brutal：`off`、`up/down`<br>ignore-client-bandwidth：`false`、`true` |
| `alpn` | ALPN | 有 |  |  | 已实现 | 通过 | 取值：`列表` |
| `bbr-profile` | BBR 档位，默认 standard | 有 |  |  | 未实现 | 未测 | 取值：`aggressive`、`conservative`、`standard` |
| `congestion-controller` | 拥塞控制，默认 cubic | 有 |  |  | 已实现 | 通过 | 取值：`bbr`、`cubic`、`new_reno` |
| `cwnd` | 初始拥塞窗口，默认 32 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `disable-mtu-discovery` | 禁用路径 MTU 发现 | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `down` | Brutal 协商：服务端下载请求速度 | 有 |  |  | 未实现 | 未测 | 取值：`100 Mbps` |
| `ignore-client-bandwidth` | Brutal 使用，忽略出站 down | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `jls-upstream-addr` | 未认证连接转发的 QUIC 伪装上游 | 有 |  |  | 已实现 | 通过 | 取值：`host:port` |
| `jls-upstream-proxy` | 伪装上游使用的代理 | 有 |  |  | 未实现 | 未测 | 取值：`出站名` |
| `jls-upstream-rate-limit` | 转发限速，bit/s，0 不限 | 有 |  |  | 部分 | 通过 | 取值：`整数` |
| `jls-upstream-sni` | JLS 伪装 SNI，留空从 addr 推导 | 有 |  |  | 已实现 | 通过 | 取值：`域名` |
| `max-datagram-frame-size` | 最大 UDP datagram frame | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `max-idle-time` | 最大空闲时间，毫秒 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `mux-option-brutal-down` | Brutal 下行，默认 Mbps | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `mux-option-brutal-enabled` | 入站 TCP Brutal | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `mux-option-brutal-up` | Brutal 上行，默认 Mbps | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `mux-option-padding` | 入站 sing-mux 填充 | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true` |
| `quic-versions` | 支持的 QUIC 版本 | 有 |  |  | 已实现 | 通过 | 取值：`v1`、`v2` |
| `recv-window` | 连接级接收窗口，0 内部默认 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `recv-window-conn` | 流级接收窗口，0 内部默认 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `up` | Brutal 协商：服务端上传上限 | 有 |  |  | 未实现 | 未测 | 取值：`100 Mbps` |
| `users-password` | 密码 | 有 |  |  | 已实现 | 通过 | 取值：`字符串` |
| `users-username` | 用户名 | 有 |  |  | 已实现 | 通过 | 取值：`字符串` |
| `zero-rtt` | 启用 0-RTT | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |

## shadowsocks

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | Shadowsocks 入站，type 写 shadowsocks | 有 | 有 |  | 已实现 | 通过 | 取值：`shadowsocks`<br>约束：可作 detour 注入目标（Injectable：TCP） |
| `shadowsocks` | Shadowsocks 入站 |  |  | 有 | 已实现 | 通过 | 取值：`shadowsocks`<br>约束：源码启动时打印不移除的弃用告警，建议 VLESS Encryption |
| `combo` | Shadowsocks 入站组合 | 有 | 有 | 有 | 部分 | 通过 | cipher：`2022-blake3-aes-128-gcm`、`2022-blake3-aes-256-gcm`、`2022-blake3-chacha20-poly1305`、`aes-128-gcm`、`aes-192-gcm`、`aes-256-gcm`、`chacha20-ietf-poly1305`、`none`、`xchacha20-ietf-poly1305`<br>wrapper：`jls`、`kcp-tun`、`none`、`res-tls`、`shadow-tls-v1`、`shadow-tls-v2`、`shadow-tls-v3`、`simple-obfs-http`、`simple-obfs-tls`<br>udp：`false`、`true`<br>mux：`brutal`、`off`、`padding`<br>约束：JLS 仅封装 TCP；认证失败或普通 TLS 透明回落 dest<br>约束：source:listener/sing_shadowsocks/server.go：shadow-tls、res-tls、jls 互斥<br>method：`2022-blake3-aes-128-gcm`、`2022-blake3-aes-256-gcm`、`2022-blake3-chacha20-poly1305`、`aes-128-gcm`、`aes-192-gcm`、`aes-256-gcm`、`chacha20-ietf-poly1305`、`none`、`xchacha20-ietf-poly1305`<br>mode：`managed`、`multi-user`、`relay`、`single`<br>network：`tcp`、`tcp+udp`、`udp`<br>multiplex：`off`、`on`<br>multiplex_padding：`off`、`on`<br>brutal：`off`、`on`<br>约束：2022 方法密钥长度：128-gcm 16 字节，256-gcm 与 chacha20 32 字节<br>约束：brutal 服务端需要 Linux 和 brutal 内核模块<br>约束：managed 不能配 users、destinations（source:protocol/shadowsocks/inbound.go）<br>约束：max_connections、min_streams 与 max_streams 冲突<br>约束：multi-user 只支持 2022 与 AEAD 方法，none 不支持（source:protocol/shadowsocks/inbound_multi.go）<br>约束：relay 只支持 2022 方法（source:protocol/shadowsocks/inbound_relay.go）<br>约束：users 与 destinations 不能同时配（source:protocol/shadowsocks/inbound.go）<br>约束：入站 padding 开启后拒绝未填充连接<br>约束：入站不提供流加密方法<br>transport：`grpc`、`httpupgrade`、`hysteria`、`mkcp`、`raw`、`websocket`、`xhttp`<br>security：`none`、`reality`、`tls`<br>method：`2022-blake3-aes-128-gcm`、`2022-blake3-aes-256-gcm`、`2022-blake3-chacha20-poly1305`、`aes-128-gcm`、`aes-256-gcm`、`chacha20-ietf-poly1305`、`chacha20-poly1305`、`xchacha20-ietf-poly1305`、`xchacha20-poly1305`<br>users：`multi`、`single`<br>network：`tcp`、`tcp,udp`、`udp`<br>约束：SS2022 多用户 users 的 method 必须为空<br>约束：SS2022 多用户只支持 blake3-aes-*-gcm（source:infra/conf/shadowsocks.go）<br>约束：masque 传输不适用<br>约束：未启用 XUDP 时 UDP 走原生路径，绕过已配置传输和 TLS/REALITY |
| `address` | SS2022 中继模式用户目标地址 |  |  | 有 | 未实现 | 未测 | 约束：中继模式所有用户必须有 relay address 且 method 为空 |
| `cipher` | 加密方法 | 有 |  |  | 部分 | 通过 | 取值：`2022-blake3-aes-128-gcm`、`2022-blake3-aes-256-gcm`、`2022-blake3-chacha20-poly1305`、`aes-128-gcm`、`aes-192-gcm`、`aes-256-gcm`、`chacha20-ietf-poly1305`、`none`、`xchacha20-ietf-poly1305`<br>约束：2022-blake3-aes-128-gcm 密码长度 16<br>约束：2022-blake3-aes-256-gcm、2022-blake3-chacha20-poly1305 密码长度 32 |
| `clients` | users 的别名 |  |  | 有 | 已实现 | 通过 |  |
| `destinations` | Shadowsocks 中继目标列表 |  | 有 |  | 未实现 | 未测 |  |
| `destinations-name` | 用户名称，用于日志和 auth_user 匹配 |  | 有 |  | 未实现 | 未测 |  |
| `destinations-password` | 密码 |  | 有 |  | 未实现 | 未测 |  |
| `destinations-server` | 服务器地址 |  | 有 |  | 未实现 | 未测 |  |
| `destinations-server-port` | 服务器端口 |  | 有 |  | 未实现 | 未测 |  |
| `email` | 用户邮箱 |  |  | 有 | 已实现 | 通过 |  |
| `jls-config-alpn` | ALPN | 有 |  |  | 未实现 | 未测 | 取值：`列表` |
| `jls-config-dest` | 回落目标 | 有 |  |  | 未实现 | 未测 | 取值：`host:port` |
| `jls-config-enable` | 启用 JLS，替代普通 TLS；未认证连接回落 dest | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `jls-config-proxy` | 回落目标使用的代理 | 有 |  |  | 未实现 | 未测 | 取值：`出站名` |
| `jls-config-rate-limit` | fallback 转发限速，bit/s，0 不限 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `jls-config-sni` | SNI，留空从 dest 推导 | 有 |  |  | 未实现 | 未测 | 取值：`域名` |
| `jls-config-users-password` | JLS 密码 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `jls-config-users-username` | JLS 用户名 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `kcp-tun-acknodelay` | 收包立即刷新 ack | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `kcp-tun-autoexpire` | 单 UDP 连接自动过期秒数，0 禁用 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `kcp-tun-conn` | 到服务端的 UDP 连接数 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `kcp-tun-crypt` | 加密方式 | 有 |  |  | 未实现 | 未测 | 取值：`3des`、`aes`、`aes-128`、`aes-128-gcm`、`aes-192`、`blowfish`、`cast5`、`none`、`null`、`salsa20`、`tea`、`twofish`、`xor`、`xtea` |
| `kcp-tun-datashard` | Reed-Solomon 数据分片 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `kcp-tun-dscp` | DSCP（6 位） | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `kcp-tun-enable` | 启用 kcptun 服务端 | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `kcp-tun-framesize` | smux 最大帧 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `kcp-tun-interval` | interval 参数 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `kcp-tun-keepalive` | 心跳间隔秒 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `kcp-tun-key` | 预共享密钥 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `kcp-tun-mode` | 模式档位 | 有 |  |  | 未实现 | 未测 | 取值：`fast`、`fast2`、`fast3`、`manual`、`normal` |
| `kcp-tun-mtu` | UDP 包 MTU | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `kcp-tun-nocomp` | 禁用压缩 | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `kcp-tun-nodelay` | nodelay 参数 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `kcp-tun-parityshard` | Reed-Solomon 校验分片 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `kcp-tun-ratelimit` | 单 KCP 连接出站限速，字节/秒，0 禁用 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `kcp-tun-rcvwnd` | 接收窗口（包数） | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `kcp-tun-resend` | resend 参数 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `kcp-tun-scavengettl` | 过期连接存活秒数 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `kcp-tun-smuxbuf` | smux 解复用总缓冲字节 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `kcp-tun-smuxver` | smux 版本 | 有 |  |  | 未实现 | 未测 | 取值：`1`、`2` |
| `kcp-tun-sndwnd` | 发送窗口（包数） | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `kcp-tun-sockbuf` | 每 socket 缓冲字节 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `kcp-tun-streambuf` | 每流接收缓冲，smux v2+ | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `level` | 用户等级，默认 0 |  |  | 有 | 未实现 | 未测 |  |
| `managed` | 默认为 `false`。 |  | 有 |  | 未实现 | 未测 | 约束：当该入站需要由 SSM API 管理用户时必须启用此字段。 |
| `method` | 加密方法 |  | 有 | 有 | 部分 | 通过 | 取值：`2022-blake3-aes-128-gcm`、`2022-blake3-aes-256-gcm`、`2022-blake3-chacha20-poly1305`、`aes-128-gcm`、`aes-192-gcm`、`aes-256-gcm`、`chacha20-ietf-poly1305`、`chacha20-poly1305`、`none`、`xchacha20-ietf-poly1305`、`xchacha20-poly1305`<br>约束：必填<br>约束：上层 method 非 SS2022 时可设置且仅支持非 SS2022，上层 password 被忽略<br>约束：上层为 SS2022 时不支持单用户 method |
| `multiplex` | 参阅 多路复用。 |  | 有 |  | 已实现 | 通过 |  |
| `mux-option-brutal-down` | Brutal 下行，默认 Mbps | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `mux-option-brutal-enabled` | 入站 TCP Brutal | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `mux-option-brutal-up` | Brutal 上行，默认 Mbps | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `mux-option-padding` | 入站 sing-mux 填充 | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true` |
| `network` | 监听的网络协议，`tcp` `udp` 之一。 |  | 有 | 有 | 部分 | 通过 | 取值：`tcp`、`tcp,udp`、`udp`<br>约束：默认所有。<br>约束：tcp 不代表拒绝 UDP 代理请求，UDP 仍可经 XUDP 走 TCP |
| `password` | 密码 | 有 | 有 | 有 | 已实现 | 通过 | 取值：`2022 methods`、`base64`、`none`、`other methods`、`任意字符串`<br>约束：2022 用 openssl rand --base64 <长度><br>约束：none 无密码<br>约束：必填<br>约束：SS2022 客户端密码写 ServerPassword:UserPassword<br>约束：SS2022 用预共享密钥：128-gcm 16 字节，256-gcm 与 chacha20 32 字节<br>约束：其他方法任意字符串 |
| `res-tls-dest` | 回落目标 | 有 |  |  | 未实现 | 未测 | 取值：`host:port` |
| `res-tls-enable` | 启用 ResTLS | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `res-tls-min-record-len` | 最小记录长度 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `res-tls-password` | ResTLS 密码 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `res-tls-proxy` | 回落目标使用的代理 | 有 |  |  | 未实现 | 未测 | 取值：`出站名` |
| `res-tls-rate-limit` | fallback 双向转发限速，bit/s，0 不限 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `res-tls-restls-script` | Restls 剧本 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `shadow-tls-enable` | 启用 ShadowTLS | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true` |
| `shadow-tls-handshake-dest` | 握手目标 | 有 |  |  | 已实现 | 通过 | 取值：`host:port` |
| `shadow-tls-handshake-for-server-name` | 按 SNI 选握手目标（文档未写） | 有 |  |  | 已实现 | 通过 | 取值：`映射` |
| `shadow-tls-handshake-proxy` | 握手目标使用的代理 | 有 |  |  | 未实现 | 未测 | 取值：`出站名` |
| `shadow-tls-password` | v2 密码 | 有 |  |  | 已实现 | 通过 | 取值：`字符串`<br>约束：v2 配置项 |
| `shadow-tls-strict-mode` | ShadowTLS 严格模式（文档未写） | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true` |
| `shadow-tls-users-name` | v3 用户名 | 有 |  |  | 未实现 | 未测 | 取值：`字符串`<br>约束：v3 配置项 |
| `shadow-tls-users-password` | v3 用户密码 | 有 |  |  | 已实现 | 通过 | 取值：`字符串`<br>约束：v3 配置项 |
| `shadow-tls-version` | ShadowTLS 版本 | 有 |  |  | 已实现 | 通过 | 取值：`1`、`2`、`3` |
| `shadow-tls-wildcard-sni` | ShadowTLS 通配 SNI（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `simple-obfs-enable` | 启用 simple-obfs | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `simple-obfs-mode` | simple-obfs 模式 | 有 |  |  | 未实现 | 未测 | 取值：`http`、`tls` |
| `udp` | 是否监听 UDP | 有 |  |  | 部分 | 通过 | 取值：`false`、`true` |
| `users` | 用户列表 |  | 有 | 有 | 已实现 | 通过 |  |
| `users-name` | 用户名称，用于日志和 auth_user 匹配 |  | 有 |  | 已实现 | 通过 |  |
| `users-password` | 密码 |  | 有 |  | 已实现 | 通过 |  |

## shadowsocksr

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | ShadowsocksR 入站，已移除，配置后报错 |  | 已移除 |  | 已实现 | 通过 | 取值：`shadowsocksr`<br>约束：1.6.0 移除（source:include/registry.go） |

## shadowtls

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | ShadowTLS 入站 |  | 有 |  | 已实现 | 通过 | 取值：`shadowtls`<br>约束：可作 detour 注入目标（Injectable：TCP） |
| `combo` | ShadowTLS 入站的版本、认证和握手模式组合 |  | 有 |  | 部分 | 通过 | version：`1`、`2`、`3`<br>auth：`none`、`password`、`users`<br>handshake_for_server_name：`off`、`on`<br>strict_mode：`off`、`on`<br>wildcard_sni：`all`、`authed`、`off`<br>约束：handshake 必填，wildcard_sni 为 all 时服务器地址可选<br>约束：handshake_for_server_name 仅 v2、v3<br>约束：password 仅 v2<br>约束：strict_mode 仅 v3<br>约束：users 仅 v3<br>约束：wildcard_sni 仅 v3<br>约束：匹配 handshake_for_server_name 的连接不受 wildcard_sni 影响 |
| `handshake` | 握手服务器地址和 拨号参数。 |  | 有 |  | 已实现 | 通过 | 约束：必填 |
| `handshake-for-server-name` | 对于特定服务器名称的握手服务器地址和 拨号参数。 |  | 有 |  | 已实现 | 通过 | 约束：仅在 ShadowTLS 协议版本 2/3 中可用。<br>约束：必填 |
| `handshake-for-server-name-server` | 服务器地址 |  | 有 |  | 已实现 | 通过 |  |
| `handshake-for-server-name-server-port` | 服务器端口 |  | 有 |  | 已实现 | 通过 |  |
| `handshake-server` | 服务器地址 |  | 有 |  | 已实现 | 通过 |  |
| `handshake-server-port` | 服务器端口 |  | 有 |  | 已实现 | 通过 |  |
| `password` | ShadowTLS 密码。 |  | 有 |  | 已实现 | 通过 | 约束：仅在 ShadowTLS 协议版本 2 中可用。 |
| `strict-mode` | ShadowTLS 严格模式。 |  | 有 |  | 已实现 | 通过 | 约束：仅在 ShadowTLS 协议版本 3 中可用。 |
| `users` | ShadowTLS 用户。 |  | 有 |  | 已实现 | 通过 | 约束：仅在 ShadowTLS 协议版本 3 中可用。 |
| `users-name` | 用户名称，用于日志和 auth_user 匹配 |  | 有 |  | 未实现 | 未测 |  |
| `users-password` | 密码 |  | 有 |  | 已实现 | 通过 |  |
| `version` | ShadowTLS 协议版本。 |  | 有 |  | 已实现 | 通过 | 取值：`1`、`2`、`3` |
| `wildcard-sni` | ShadowTLS 通配符 SNI 模式。 |  | 有 |  | 未实现 | 未测 | 取值：`all`、`authed`、`off`<br>约束：* `off`：（默认）禁用。<br>约束：仅在 ShadowTLS 协议 3 中可用。<br>约束：自 sing-box 1.12.0 起 |

## shortcut

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `ss-config` | 快速创建 Shadowsocks 入站的 URI | 有 |  |  | 未实现 | 未测 | 取值：`ss:// URI`<br>约束：等价于对应 Listener |
| `tuic-server-alpn` | ALPN 列表 | 有 |  |  | 已实现 | 通过 | 取值：`列表` |
| `tuic-server-authentication-timeout` | 认证超时，毫秒 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `tuic-server-certificate` | 证书 | 有 |  |  | 已实现 | 通过 | 取值：`PEM`、`路径` |
| `tuic-server-congestion-controller` | 拥塞控制 | 有 |  |  | 已实现 | 通过 | 取值：`bbr`、`cubic`、`new_reno` |
| `tuic-server-cwnd` | TUIC 快捷入站初始拥塞窗口（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `tuic-server-enable` | 快速创建 TUIC 入站开关 | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true` |
| `tuic-server-listen` | TUIC 快捷入站监听地址 | 有 |  |  | 已实现 | 通过 | 取值：`host:port` |
| `tuic-server-max-idle-time` | 最大空闲时间，毫秒 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `tuic-server-max-udp-relay-packet-size` | UDP 中继包最大大小 | 有 |  |  | 部分 | 通过 | 取值：`整数` |
| `tuic-server-private-key` | 私钥 | 有 |  |  | 已实现 | 通过 | 取值：`PEM`、`路径` |
| `tuic-server-token` | TUIC v4 token 列表 | 有 |  |  | 已实现 | 通过 | 取值：`列表`<br>约束：与 users 不能同时配置 |
| `tuic-server-users` | TUIC v5 用户映射 | 有 |  |  | 已实现 | 通过 | 取值：`uuid: password`<br>约束：与 token 不能同时配置 |
| `vmess-config` | 快速创建 VMess 入站的 URI | 有 |  |  | 未实现 | 未测 | 取值：`vmess:// URI`<br>约束：等价于对应 Listener |

## snell

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | Snell 入站 | 有 | 有 |  | 已实现 | 通过 | 取值：`snell`<br>约束：可作 detour 注入目标（Injectable：TCP）<br>约束：自 sing-box 1.14.0 起 |
| `combo` | Snell 入站组合 | 有 | 有 |  | 部分 | 通过 | version：`1`、`2`、`3`、`4`、`5`<br>wrapper：`jls`、`none`、`obfs-http`、`obfs-tls`、`res-tls`、`shadow-tls-v1`、`shadow-tls-v2`、`shadow-tls-v3`<br>udp：`false`、`true`<br>约束：shadow-tls、res-tls、jls-config 互斥<br>version：`5`、`6`<br>auth：`psk`、`psk+users`<br>obfs_mode：`http`、`none`<br>mode：`default`、`unsafe-raw`、`unshaped`<br>约束：mode 仅 v6<br>约束：obfs_mode 仅 v5<br>约束：v6 的 psk 为 12 到 255 字节<br>约束：version、psk 必填<br>约束：不支持 Snell v5 的 QUIC 代理模式 |
| `jls-config-alpn` | ALPN | 有 |  |  | 未实现 | 未测 | 取值：`列表` |
| `jls-config-dest` | 回落目标 | 有 |  |  | 未实现 | 未测 | 取值：`host:port` |
| `jls-config-enable` | 启用 JLS，替代普通 TLS；未认证连接回落 dest | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `jls-config-proxy` | 回落目标使用的代理 | 有 |  |  | 未实现 | 未测 | 取值：`出站名` |
| `jls-config-rate-limit` | fallback 转发限速，bit/s，0 不限 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `jls-config-sni` | SNI，留空从 dest 推导 | 有 |  |  | 未实现 | 未测 | 取值：`域名` |
| `jls-config-users-password` | JLS 密码 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `jls-config-users-username` | JLS 用户名 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `mode` | 流量整形模式，`default` `unshaped` `unsafe-raw` 之一。 |  | 有 |  | 已实现 | 通过 | 取值：`default`、`unsafe-raw`、`unshaped`<br>约束：仅版本 6<br>约束：自 sing-box 1.14.0 起<br>约束：默认为 `default`。 |
| `obfs-mode` | HTTP 混淆模式，`none` `http` 之一。 |  | 有 |  | 已实现 | 通过 | 取值：`http`、`none`<br>约束：仅版本 5<br>约束：自 sing-box 1.14.0 起<br>约束：默认为 `none`。 |
| `obfs-opts-host` | 混淆域名 | 有 |  |  | 已实现 | 通过 | 取值：`域名` |
| `obfs-opts-mode` | 混淆模式 | 有 |  |  | 部分 | 通过 | 取值：`http`、`tls` |
| `psk` | 预共享密钥 | 有 | 有 |  | 已实现 | 通过 | 取值：`字符串`<br>约束：必填<br>约束：自 sing-box 1.14.0 起 |
| `res-tls-dest` | 回落目标 | 有 |  |  | 未实现 | 未测 | 取值：`host:port` |
| `res-tls-enable` | 启用 ResTLS | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `res-tls-min-record-len` | 最小记录长度 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `res-tls-password` | ResTLS 密码 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `res-tls-proxy` | 回落目标使用的代理 | 有 |  |  | 未实现 | 未测 | 取值：`出站名` |
| `res-tls-rate-limit` | fallback 双向转发限速，bit/s，0 不限 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `res-tls-restls-script` | Restls 剧本 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `shadow-tls-enable` | 启用 ShadowTLS | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `shadow-tls-handshake-dest` | 握手目标 | 有 |  |  | 未实现 | 未测 | 取值：`host:port` |
| `shadow-tls-handshake-for-server-name` | 按 SNI 选握手目标（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`映射` |
| `shadow-tls-handshake-proxy` | 握手目标使用的代理 | 有 |  |  | 未实现 | 未测 | 取值：`出站名` |
| `shadow-tls-password` | v2 密码 | 有 |  |  | 未实现 | 未测 | 取值：`字符串`<br>约束：v2 配置项 |
| `shadow-tls-strict-mode` | ShadowTLS 严格模式（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `shadow-tls-users-name` | v3 用户名 | 有 |  |  | 未实现 | 未测 | 取值：`字符串`<br>约束：v3 配置项 |
| `shadow-tls-users-password` | v3 用户密码 | 有 |  |  | 未实现 | 未测 | 取值：`字符串`<br>约束：v3 配置项 |
| `shadow-tls-version` | ShadowTLS 版本 | 有 |  |  | 未实现 | 未测 | 取值：`1`、`2`、`3` |
| `shadow-tls-wildcard-sni` | ShadowTLS 通配 SNI（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `udp` | UDP over TCP tunnel，默认 true | 有 |  |  | 部分 | 通过 | 取值：`false`、`true` |
| `users` | Snell 用户。 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.14.0 起 |
| `users-name` | 用户名称，用于日志和 auth_user 匹配 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.14.0 起 |
| `users-userkey` | Snell 用户密钥 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.14.0 起 |
| `version` | Snell 版本 | 有 | 有 |  | 部分 | 通过 | 取值：`1`、`2`、`3`、`4`、`5`、`6`<br>约束：必填<br>约束：由于我们有意不支持 Snell v5 的 QUIC 代理模式，v5 的线路协议实际上与 v4 没有区别，因此不提供独立的 v4 服务器和 v5 客户端。<br>约束：自 sing-box 1.14.0 起 |

## socks

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | SOCKS 入站 | 有 | 有 |  | 已实现 | 通过 | 取值：`socks`<br>约束：可作 detour 注入目标（Injectable：TCP） |
| `socks` | Socks 入站，兼容 Socks4、Socks4a、Socks5 和 HTTP |  |  | 有 | 部分 | 通过 | 取值：`socks` |
| `combo` | SOCKS 入站组合 | 有 | 有 | 有 | 部分 | 通过 | tls：`mtls`、`none`、`tls`<br>ech：`off`、`on`<br>auth：`global`、`users`、`users: []`<br>udp：`false`、`true`<br>version：`socks4`、`socks4a`、`socks5`<br>约束：ech 依赖 tls<br>约束：source:listener/inbound/socks.go 另有 reality-config<br>protocol_version：`socks4`、`socks4a`、`socks5`<br>auth：`none`、`users`<br>约束：users 为空时不需要认证<br>transport：`grpc`、`httpupgrade`、`hysteria`、`mkcp`、`raw`、`websocket`、`xhttp`<br>security：`none`、`reality`、`tls`<br>auth：`noauth`、`password`<br>version：`http`、`socks4`、`socks4a`、`socks5`<br>约束：masque 传输不适用<br>约束：未启用 XUDP 时 UDP 改走协议原生路径，绕过已配置传输和 TLS/REALITY；TCP 不受影响 |
| `accounts` | users 的别名 |  |  | 有 | 已实现 | 通过 |  |
| `auth` | 认证方式，默认 noauth |  |  | 有 | 部分 | 通过 | 取值：`noauth`、`password`<br>约束：password 时 HTTP 请求也要求同样账号密码 |
| `certificate` | TLS 证书，PEM 或路径 | 有 |  |  | 未实现 | 未测 | 取值：`PEM`、`路径`<br>约束：与 private-key 同时填写才开启 tls |
| `client-auth-cert` | mTLS 客户端证书 | 有 |  |  | 未实现 | 未测 | 取值：`PEM`、`路径` |
| `client-auth-type` | mTLS 类型 | 有 |  |  | 未实现 | 未测 | 取值：``、`request`、`require-and-verify`、`require-any`、`verify-if-given`<br>约束：verify-if-given、require-and-verify 时 client-auth-cert 必填 |
| `domain-resolver` | socks 入站的 domain_resolver，配置文档未列 |  | 有 |  | 未实现 | 未测 |  |
| `ech-key` | ECH 密钥，填写即开启；可由 mihomo generate ech-keypair 生成 | 有 |  |  | 未实现 | 未测 | 取值：`PEM` |
| `ip` | UDP 回复给客户端的本机地址，默认 TCP 连接的本地 IP |  |  | 有 | 未实现 | 未测 | 约束：NAT 环境需改为公网 IP<br>约束：多 IP 时受 UDP 监听 0.0.0.0 问题影响 |
| `pass` | UserObject 密码，必填 |  |  | 有 | 已实现 | 通过 |  |
| `private-key` | TLS 私钥，PEM 或路径 | 有 |  |  | 未实现 | 未测 | 取值：`PEM`、`路径`<br>约束：与 certificate 同时填写 |
| `reality-config` | socks 入站字段 reality-config（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `udp` | 是否监听 UDP | 有 |  | 有 | 部分 | 通过 | 取值：`false`、`true` |
| `user` | UserObject 用户名，必填 |  |  | 有 | 已实现 | 通过 |  |
| `user-level` | 用户等级，默认 0 |  |  | 有 | 未实现 | 未测 |  |
| `users` | SOCKS 用户如果为空则不需要验证。 |  | 有 | 有 | 已实现 | 通过 | 约束：仅 auth 为 password 时有效 |
| `users-password` | 密码 | 有 | 有 |  | 已实现 | 通过 | 取值：`字符串` |
| `users-username` | 用户名 | 有 | 有 |  | 已实现 | 通过 | 取值：`字符串`<br>约束：不填 users 遵从全局验证；填写忽略全局；users: [] 跳过该入站验证 |

## sudoku

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | Sudoku 入站 | 有 |  |  | 已实现 | 通过 | 约束：port 仅支持单端口 |
| `combo` | Sudoku 入站组合 | 有 |  |  | 部分 | 通过 | aead-method：`aes-128-gcm`、`chacha20-poly1305`、`none`<br>table-type：`prefer_ascii`、`prefer_entropy`、`up_ascii_down_entropy`、`up_entropy_down_ascii`<br>httpmask.mode：`auto`、`disabled`、`legacy`、`poll`、`stream`、`ws`<br>enable-pure-downlink：`false`、`true`<br>mux：`brutal`、`off`、`padding`<br>约束：enable-pure-downlink 需与对端一致 |
| `aead-method` | AEAD 方法 | 有 |  |  | 已实现 | 通过 | 取值：`aes-128-gcm`、`chacha20-poly1305`、`none`<br>约束：none 不提供 AEAD 保护 |
| `custom-table` | 自定义字节布局 | 有 |  |  | 已实现 | 通过 | 取值：`xpxvvpvv`<br>约束：只对 entropy 方向生效<br>约束：必须含 2 个 x、2 个 p、4 个 v |
| `custom-tables` | 自定义字节布局列表 | 有 |  |  | 已实现 | 通过 | 取值：`列表`<br>约束：非空时覆盖 custom-table |
| `disable-http-mask` | httpmask.disable 的兼容写法 | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true` |
| `enable-pure-downlink` | false 带宽优化下行，true 纯 Sudoku 下行 | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true` |
| `fallback` | 像 HTTP 但不符合 tunnel/auth 时透传目标 | 有 |  |  | 已实现 | 通过 | 取值：`host:port`<br>约束：需启用 HTTPMask |
| `handshake-timeout` | 握手超时秒 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `http-mask-mode` | httpmask.mode 的兼容写法 | 有 |  |  | 已实现 | 通过 | 取值：`auto`、`legacy`、`poll`、`stream`、`ws` |
| `httpmask-disable` | 禁用所有 HTTP 伪装/隧道 | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true` |
| `httpmask-mode` | HTTPMask 模式 | 有 |  |  | 已实现 | 通过 | 取值：`auto`、`legacy`、`poll`、`stream`、`ws` |
| `httpmask-path-root` | 隧道端点一级路径前缀 | 有 |  |  | 已实现 | 通过 | 取值：`字符串`<br>约束：双方需一致 |
| `key` | 服务端 key，ED25519 公钥或任意 uuid | 有 |  |  | 已实现 | 通过 | 取值：`字符串` |
| `mux-option-brutal-down` | Brutal 下行，默认 Mbps | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `mux-option-brutal-enabled` | 入站 TCP Brutal | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `mux-option-brutal-up` | Brutal 上行，默认 Mbps | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `mux-option-padding` | 入站 sing-mux 填充 | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true` |
| `padding-max` | 最大填充率 | 有 |  |  | 已实现 | 通过 | 取值：`0-100`<br>约束：必须 >= padding-min |
| `padding-min` | 最小填充率 | 有 |  |  | 已实现 | 通过 | 取值：`0-100` |
| `path-root` | httpmask.path-root 的兼容写法 | 有 |  |  | 已实现 | 通过 | 取值：`字符串` |
| `table-type` | 表类型 | 有 |  |  | 已实现 | 通过 | 取值：`prefer_ascii`、`prefer_entropy`、`up_ascii_down_entropy`、`up_entropy_down_ascii` |

## tailcat

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | Tailcat 入站 |  | 有 |  | 未实现 | 未测 | 取值：`tailcat`<br>约束：不可作 detour 注入目标<br>约束：自 sing-box 1.15.0 起 |
| `combo` | Tailcat 入站的客户端校验和 DERP 选择组合 |  | 有 |  | 未实现 | 未测 | client_verify：`none`、`users`<br>derp：`derp_map_url`、`derp_map_url+derp_region`、`derp_servers`<br>pre_shared_key：`off`、`on`<br>约束：derp_region 与 derp_servers 冲突<br>约束：derp_servers 与 derp_map_url、derp_region 冲突<br>约束：private_key 必填<br>约束：拨号字段只影响连接 DERP |
| `derp-map-url` | DERP map 的 URL。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.15.0 起<br>约束：默认使用 `https://tailcat.dev/derpmap.json`。 |
| `derp-region` | DERP map 中的 DERP 区域 ID。 |  | 有 |  | 未实现 | 未测 | 约束：与 `derp_servers` 冲突。<br>约束：自 sing-box 1.15.0 起 |
| `derp-servers` | 自定义 DERP 服务器，为 DERPNode 格式，字段名使用 snake_case。 |  | 有 |  | 未实现 | 未测 | 约束：与 `derp_map_url` 和 `derp_region` 冲突。<br>约束：自 sing-box 1.15.0 起 |
| `derp-servers-cert-name` | Tailcat derp_servers 条目的 cert_name（DERPNode 字段），页面只引用外部格式 |  | 有 |  | 未实现 | 未测 |  |
| `derp-servers-derp-port` | Tailcat derp_servers 条目的 derp_port（DERPNode 字段），页面只引用外部格式 |  | 有 |  | 未实现 | 未测 |  |
| `derp-servers-host` | Tailcat derp_servers 条目的 host（DERPNode 字段），页面只引用外部格式 |  | 有 |  | 未实现 | 未测 |  |
| `derp-servers-ipv4` | Tailcat derp_servers 条目的 ipv4（DERPNode 字段），页面只引用外部格式 |  | 有 |  | 未实现 | 未测 |  |
| `derp-servers-ipv6` | Tailcat derp_servers 条目的 ipv6（DERPNode 字段），页面只引用外部格式 |  | 有 |  | 未实现 | 未测 |  |
| `derp-servers-stun-port` | Tailcat derp_servers 条目的 stun_port（DERPNode 字段），页面只引用外部格式 |  | 有 |  | 未实现 | 未测 |  |
| `http-client` | 用于获取 DERP map 的 HTTP 客户端。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.15.0 起 |
| `pre-shared-key` | 预共享密钥。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.15.0 起 |
| `private-key` | 私钥。 |  | 有 |  | 未实现 | 未测 | 约束：必填<br>约束：自 sing-box 1.15.0 起 |
| `users` | Tailcat 用户。 |  | 有 |  | 未实现 | 未测 | 约束：如需使用带客户端验证的 DERP 服务器，在 DERP 服务中设置 `verify_client_inbound` 或 `verify_client_key`，且客户端必须使用固定的私钥。<br>约束：自 sing-box 1.15.0 起 |
| `users-name` | 用户名称，用于日志和 auth_user 匹配 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.15.0 起 |
| `users-public-key` | 客户端公钥。 |  | 有 |  | 未实现 | 未测 | 约束：必填<br>约束：自 sing-box 1.15.0 起 |

## tproxy

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | TProxy 透明代理入站 | 有 |  |  | 已实现 | 通过 | 约束：仅 Linux(Android) |
| `combo` | TProxy 入站组合 | 有 |  |  | 已实现 | 通过 | network：`tcp`、`udp`<br>约束：DSCP 规则仅限 tproxy udp 入站 |
| `udp` | 是否监听 UDP | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true` |

## trojan

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | Trojan 入站 | 有 | 有 |  | 已实现 | 通过 | 取值：`trojan`<br>约束：可作 detour 注入目标（Injectable：TCP） |
| `trojan` | Trojan 入站 |  |  | 有 | 已实现 | 通过 | 取值：`trojan`<br>约束：源码启动时打印不移除的弃用告警，建议 VLESS |
| `combo` | Trojan 入站组合 | 有 | 有 | 有 | 部分 | 通过 | transport：`grpc`、`tcp`、`ws`<br>security：`jls`、`none`、`reality`、`res-tls`、`shadow-tls`、`tls`<br>ss-option：`aes-128-gcm`、`aes-256-gcm`、`chacha20-ietf-poly1305`、`off`<br>ech：`off`、`on`<br>mux：`brutal`、`off`、`padding`<br>allow-insecure：`false`、`true`<br>约束：allow-insecure 不为 true 时至少填 certificate+private-key、shadow-tls、res-tls、jls-config、reality-config、ss-option 之一<br>约束：reality 不可与 certificate、private-key 同填<br>约束：source:listener/trojan/server.go：certificate、reality、shadow-tls、res-tls、jls 互斥<br>security：`none`、`reality`、`tls`、`tls+ech`<br>transport：`grpc`、`http`、`httpupgrade`、`none`、`quic`、`ws`<br>fallback：`fallback`、`fallback_for_alpn`、`off`<br>multiplex：`off`、`on`<br>multiplex_padding：`off`、`on`<br>brutal：`off`、`on`<br>约束：QUIC 下自定义 TLS 只支持 ECH，所以 reality、utls 不能配 quic 传输（docs/configuration/shared/tls.md）<br>约束：brutal 服务端需要 Linux 和 brutal 内核模块<br>约束：fallback_for_alpn 必须配 TLS（source:protocol/trojan/inbound.go）<br>约束：fallback_for_alpn 非空时，ALPN 不在表内的回退请求被拒绝<br>约束：http 传输不强制 TLS，无 TLS 时走明文 HTTP/1.1<br>约束：max_connections、min_streams 与 max_streams 冲突<br>约束：quic 传输要求 TLS（source:transport/v2ray/transport.go）<br>约束：入站 padding 开启后拒绝未填充连接<br>约束：标准 gRPC 不默认编入，需 with_grpc 构建标签，否则用默认 gRPC 实现<br>约束：没有 TCP 传输（明文 HTTP 并入 http 传输）、mKCP、DomainSocket（docs/configuration/shared/v2ray-transport.md）<br>transport：`grpc`、`httpupgrade`、`hysteria`、`mkcp`、`raw`、`websocket`、`xhttp`<br>security：`none`、`reality`、`tls`<br>fallback：`fallbacks`、`none`<br>约束：masque 传输不适用<br>约束：reality 只能配 raw、xhttp、grpc<br>约束：公网还要求启用 Mux，避免 TiT<br>约束：必须配 TLS；security none 仅对端私有地址且受信网络 |
| `allow-insecure` | 允许不开启 tls，仅用于 nginx、caddy 前置 | 有 |  |  | 部分 | 通过 | 取值：`false`、`true` |
| `certificate` | TLS 证书，PEM 或路径 | 有 |  |  | 已实现 | 通过 | 取值：`PEM`、`路径`<br>约束：与 private-key 同时填写才开启 tls |
| `client-auth-cert` | mTLS 客户端证书 | 有 |  |  | 未实现 | 未测 | 取值：`PEM`、`路径` |
| `client-auth-type` | mTLS 类型 | 有 |  |  | 未实现 | 未测 | 取值：``、`request`、`require-and-verify`、`require-any`、`verify-if-given`<br>约束：verify-if-given、require-and-verify 时 client-auth-cert 必填 |
| `clients` | users 的别名 |  |  | 有 | 已实现 | 通过 |  |
| `ech-key` | ECH 密钥，填写即开启；可由 mihomo generate ech-keypair 生成 | 有 |  |  | 未实现 | 未测 | 取值：`PEM` |
| `email` | 邮箱 |  |  | 有 | 已实现 | 通过 | 约束：多用户时不可重复 |
| `fallback` | 回退服务器配置。 |  | 有 |  | 已实现 | 通过 |  |
| `fallback-for-alpn` | 为 ALPN 指定回退服务器配置。 |  | 有 |  | 已实现 | 通过 |  |
| `fallback-for-alpn-server` | 服务器地址 |  | 有 |  | 已实现 | 通过 |  |
| `fallback-for-alpn-server-port` | 服务器端口 |  | 有 |  | 已实现 | 通过 |  |
| `fallback-server` | 服务器地址 |  | 有 |  | 已实现 | 通过 |  |
| `fallback-server-port` | 服务器端口 |  | 有 |  | 已实现 | 通过 |  |
| `fallbacks` | 回落配置数组 |  |  | 有 | 已实现 | 通过 | 约束：触发条件：首包长度小于 58、第 57 字节不是 \r 或认证失败 |
| `flow` | Trojan flow |  |  | 已移除 | 未实现 | 未测 | 约束：配置时报错 |
| `grpc-service-name` | 不为空开启 gRPC 传输 | 有 |  |  | 已实现 | 通过 | 取值：`字符串` |
| `jls-config-alpn` | ALPN | 有 |  |  | 未实现 | 未测 | 取值：`列表` |
| `jls-config-dest` | 回落目标 | 有 |  |  | 未实现 | 未测 | 取值：`host:port` |
| `jls-config-enable` | 启用 JLS，替代普通 TLS；未认证连接回落 dest | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `jls-config-proxy` | 回落目标使用的代理 | 有 |  |  | 未实现 | 未测 | 取值：`出站名` |
| `jls-config-rate-limit` | fallback 转发限速，bit/s，0 不限 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `jls-config-sni` | SNI，留空从 dest 推导 | 有 |  |  | 未实现 | 未测 | 取值：`域名` |
| `jls-config-users-password` | JLS 密码 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `jls-config-users-username` | JLS 用户名 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `level` | 用户等级，默认 0 |  |  | 有 | 未实现 | 未测 |  |
| `multiplex` | 参阅 多路复用。 |  | 有 |  | 已实现 | 通过 |  |
| `mux-option-brutal-down` | Brutal 下行，默认 Mbps | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `mux-option-brutal-enabled` | 入站 TCP Brutal | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `mux-option-brutal-up` | Brutal 上行，默认 Mbps | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `mux-option-padding` | 入站 sing-mux 填充 | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true` |
| `password` | 密码，必填 |  |  | 有 | 已实现 | 通过 |  |
| `private-key` | TLS 私钥，PEM 或路径 | 有 |  |  | 已实现 | 通过 | 取值：`PEM`、`路径`<br>约束：与 certificate 同时填写 |
| `reality-config-dest` | REALITY 回落目标 | 有 |  |  | 未实现 | 未测 | 取值：`host:port`<br>约束：不可与 certificate、private-key 同时填写 |
| `reality-config-limit-fallback-download-after-bytes` | 回落下载传输该字节后开始限速 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `reality-config-limit-fallback-download-burst-bytes-per-sec` | 回落下载突发速率 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `reality-config-limit-fallback-download-bytes-per-sec` | 回落下载基准速率 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `reality-config-limit-fallback-upload-after-bytes` | 回落上传传输该字节后开始限速 | 有 |  |  | 未实现 | 未测 | 取值：`整数`<br>约束：回落限速是一种特征，不建议启用 |
| `reality-config-limit-fallback-upload-burst-bytes-per-sec` | 回落上传突发速率 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `reality-config-limit-fallback-upload-bytes-per-sec` | 回落上传基准速率 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `reality-config-max-time-difference` | 最大时间差，微秒 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `reality-config-private-key` | REALITY 私钥，可由 mihomo generate reality-keypair 生成 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `reality-config-proxy` | 回落目标使用的代理 | 有 |  |  | 未实现 | 未测 | 取值：`出站名` |
| `reality-config-server-names` | 允许的 SNI | 有 |  |  | 未实现 | 未测 | 取值：`域名列表` |
| `reality-config-short-id` | 允许的 short id | 有 |  |  | 未实现 | 未测 | 取值：`十六进制列表` |
| `res-tls-dest` | 回落目标 | 有 |  |  | 未实现 | 未测 | 取值：`host:port` |
| `res-tls-enable` | 启用 ResTLS | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `res-tls-min-record-len` | 最小记录长度 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `res-tls-password` | ResTLS 密码 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `res-tls-proxy` | 回落目标使用的代理 | 有 |  |  | 未实现 | 未测 | 取值：`出站名` |
| `res-tls-rate-limit` | fallback 双向转发限速，bit/s，0 不限 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `res-tls-restls-script` | Restls 剧本 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `shadow-tls-enable` | 启用 ShadowTLS | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `shadow-tls-handshake-dest` | 握手目标 | 有 |  |  | 未实现 | 未测 | 取值：`host:port` |
| `shadow-tls-handshake-for-server-name` | 按 SNI 选握手目标（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`映射` |
| `shadow-tls-handshake-proxy` | 握手目标使用的代理 | 有 |  |  | 未实现 | 未测 | 取值：`出站名` |
| `shadow-tls-password` | v2 密码 | 有 |  |  | 未实现 | 未测 | 取值：`字符串`<br>约束：v2 配置项 |
| `shadow-tls-strict-mode` | ShadowTLS 严格模式（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `shadow-tls-users-name` | v3 用户名 | 有 |  |  | 未实现 | 未测 | 取值：`字符串`<br>约束：v3 配置项 |
| `shadow-tls-users-password` | v3 用户密码 | 有 |  |  | 未实现 | 未测 | 取值：`字符串`<br>约束：v3 配置项 |
| `shadow-tls-version` | ShadowTLS 版本 | 有 |  |  | 未实现 | 未测 | 取值：`1`、`2`、`3` |
| `shadow-tls-wildcard-sni` | ShadowTLS 通配 SNI（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `ss-option-enabled` | trojan-go shadowsocks AEAD | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `ss-option-method` | ss-option 加密方法 | 有 |  |  | 未实现 | 未测 | 取值：`aes-128-gcm`、`aes-256-gcm`、`chacha20-ietf-poly1305` |
| `ss-option-password` | ss-option 密码 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `tls` | TLS 配置，参阅 TLS。 |  | 有 |  | 部分 | 通过 |  |
| `transport` | V2Ray 传输配置，参阅 V2Ray 传输层。 |  | 有 |  | 部分 | 通过 |  |
| `users` | Trojan 用户。 |  | 有 | 有 | 已实现 | 通过 | 约束：必填 |
| `users-name` | 用户名称，用于日志和 auth_user 匹配 |  | 有 |  | 已实现 | 通过 |  |
| `users-password` | 用户密码 | 有 | 有 |  | 已实现 | 通过 | 取值：`字符串` |
| `users-username` | 用户名 | 有 |  |  | 已实现 | 通过 | 取值：`字符串` |
| `ws-path` | 不为空开启 WebSocket 传输 | 有 |  |  | 已实现 | 通过 | 取值：`路径` |

## trusttunnel

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | TrustTunnel 入站 | 有 |  |  | 已实现 | 通过 | 约束：certificate 与 private-key 必要 |
| `combo` | TrustTunnel 入站组合 | 有 |  |  | 部分 | 通过 | network：`tcp`、`tcp+udp`<br>http：`h2`、`h3`<br>ech：`off`、`on`<br>client-auth-type：``、`request`、`require-and-verify`、`require-any`、`verify-if-given` |
| `bbr-profile` | BBR 档位 | 有 |  |  | 未实现 | 未测 | 取值：`aggressive`、`conservative`、`standard` |
| `certificate` | TLS 证书，PEM 或路径 | 有 |  |  | 已实现 | 通过 | 取值：`PEM`、`路径`<br>约束：与 private-key 同时填写才开启 tls |
| `client-auth-cert` | mTLS 客户端证书 | 有 |  |  | 已实现 | 通过 | 取值：`PEM`、`路径` |
| `client-auth-type` | mTLS 类型 | 有 |  |  | 部分 | 通过 | 取值：``、`request`、`require-and-verify`、`require-any`、`verify-if-given`<br>约束：verify-if-given、require-and-verify 时 client-auth-cert 必填 |
| `congestion-controller` | QUIC 拥塞控制 | 有 |  |  | 未实现 | 未测 | 取值：`bbr`、`cubic`、`new_reno` |
| `cwnd` | trusttunnel 入站字段 cwnd（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `ech-key` | ECH 密钥，填写即开启；可由 mihomo generate ech-keypair 生成 | 有 |  |  | 未实现 | 未测 | 取值：`PEM` |
| `network` | 为空或仅 tcp 时只 HTTP2；含 udp 时开启 HTTP3 | 有 |  |  | 部分 | 通过 | 取值：`tcp`、`udp` |
| `private-key` | TLS 私钥，PEM 或路径 | 有 |  |  | 已实现 | 通过 | 取值：`PEM`、`路径`<br>约束：与 certificate 同时填写 |
| `users-password` | 密码 | 有 |  |  | 已实现 | 通过 | 取值：`字符串` |
| `users-username` | 用户名 | 有 |  |  | 已实现 | 通过 | 取值：`字符串` |

## tuic

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | TUIC 入站 |  | 有 |  | 已实现 | 通过 | 取值：`tuic`<br>约束：不可作 detour 注入目标 |
| `v4` | TUIC v4 入站 | 有 |  |  | 已实现 | 通过 | 约束：token 与 users 不能同时配置 |
| `v5` | TUIC v5 入站 | 有 |  |  | 已实现 | 通过 | 约束：token 与 users 不能同时配置 |
| `combo` | TUIC 入站组合 | 有 | 有 |  | 部分 | 通过 | version：`v4`、`v5`<br>congestion-controller：`bbr`、`cubic`、`new_reno`<br>bbr-profile：`aggressive`、`conservative`、`standard`<br>ech：`off`、`on`<br>client-auth-type：``、`request`、`require-and-verify`、`require-any`、`verify-if-given`<br>mux：`brutal`、`off`、`padding`<br>congestion_control：`bbr`、`cubic`、`new_reno`<br>zero_rtt_handshake：`off`、`on`<br>auth：`uuid`、`uuid+password`<br>约束：tls 必填<br>约束：users.uuid 必填<br>约束：zero_rtt_handshake 有重放风险，文档建议关闭 |
| `alpn` | ALPN | 有 |  |  | 已实现 | 通过 | 取值：`h3` |
| `auth-timeout` | 服务器等待客户端发送认证命令的时间默认使用 `3s`。 |  | 有 |  | 未实现 | 未测 |  |
| `authentication-timeout` | 认证超时，毫秒 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `bbr-profile` | BBR 档位 | 有 |  |  | 未实现 | 未测 | 取值：`aggressive`、`conservative`、`standard` |
| `certificate` | TLS 证书，PEM 或路径 | 有 |  |  | 已实现 | 通过 | 取值：`PEM`、`路径`<br>约束：与 private-key 同时填写才开启 tls |
| `client-auth-cert` | mTLS 客户端证书 | 有 |  |  | 未实现 | 未测 | 取值：`PEM`、`路径` |
| `client-auth-type` | mTLS 类型 | 有 |  |  | 未实现 | 未测 | 取值：``、`request`、`require-and-verify`、`require-any`、`verify-if-given`<br>约束：verify-if-given、require-and-verify 时 client-auth-cert 必填 |
| `congestion-control` | QUIC 拥塞控制算法可选值: `cubic`, `new_reno`, `bbr`默认使用 `cubic`。 |  | 有 |  | 已实现 | 通过 | 取值：`bbr`、`cubic`、`new_reno` |
| `congestion-controller` | 拥塞控制 | 有 |  |  | 已实现 | 通过 | 取值：`bbr`、`cubic`、`new_reno` |
| `cwnd` | tuic 入站字段 cwnd（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `ech-key` | ECH 密钥，填写即开启；可由 mihomo generate ech-keypair 生成 | 有 |  |  | 未实现 | 未测 | 取值：`PEM` |
| `heartbeat` | 发送心跳包以保持连接存活的时间间隔默认使用 `10s`。 |  | 有 |  | 未实现 | 未测 |  |
| `max-idle-time` | 最大空闲时间，毫秒 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `max-udp-relay-packet-size` | UDP 中继包最大大小 | 有 |  |  | 部分 | 通过 | 取值：`整数` |
| `mux-option-brutal-down` | Brutal 下行，默认 Mbps | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `mux-option-brutal-enabled` | 入站 TCP Brutal | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `mux-option-brutal-up` | Brutal 上行，默认 Mbps | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `mux-option-padding` | 入站 sing-mux 填充 | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true` |
| `private-key` | TLS 私钥，PEM 或路径 | 有 |  |  | 已实现 | 通过 | 取值：`PEM`、`路径`<br>约束：与 certificate 同时填写 |
| `tls` | TLS 配置, 参阅 TLS。 |  | 有 |  | 部分 | 通过 | 约束：必填 |
| `token` | TUIC v4 token 列表 | 有 |  |  | 已实现 | 通过 | 取值：`列表` |
| `users` | TUIC v5 用户 | 有 | 有 |  | 已实现 | 通过 | 取值：`UUID: PASSWORD` |
| `users-name` | 用户名称，用于日志和 auth_user 匹配 |  | 有 |  | 已实现 | 通过 |  |
| `users-password` | TUIC 用户密码 |  | 有 |  | 已实现 | 通过 |  |
| `users-uuid` | TUIC 用户 UUID |  | 有 |  | 已实现 | 通过 | 约束：必填 |
| `zero-rtt-handshake` | 在客户端启用 0-RTT QUIC 连接握手这对性能影响不大，因为协议是完全复用的强烈建议禁用此功能，因为它容易受到重放攻击。 |  | 有 |  | 未实现 | 未测 |  |

## tun

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | listeners 中的 TUN，面向高级用户 | 有 |  |  | 已实现 | 通过 | 约束：普通用户用顶层 tun |
| `tun` | 创建 TUN 接口接入流量 |  |  | 有 | 已实现 | 通过 | 取值：`tun`<br>约束：Android/iOS 需外部 APP 通过 XRAY_TUN_FD 传 FD<br>约束：Windows、Linux、macOS、FreeBSD 独立运行 |
| `combo` | listener TUN 组合，取值同顶层 tun | 有 |  |  | 部分 | 通过 | stack：`gvisor`、`mips`、`mixed`、`system`<br>dns-mode：``、`disabled`、`hijack`、`native`<br>auto-route：`false`、`true`<br>strict-route：`false`、`true` |
| `auto-detect-interface` | 自动选择出口接口 | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `auto-redirect` | tun 入站字段 auto-redirect（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `auto-redirect-input-mark` | tun 入站字段 auto-redirect-input-mark（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `auto-redirect-iproute2-fallback-rule-index` | tun 入站字段 auto-redirect-iproute2-fallback-rule-index（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `auto-redirect-output-mark` | tun 入站字段 auto-redirect-output-mark（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `auto-route` | 自动全局路由 | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `congestion-controller` | TCP 拥塞控制 | 有 |  |  | 未实现 | 未测 | 取值：`bbr`、`bbr3`、`cubic`、`reno`<br>约束：仅 mips 协议栈 |
| `device` | tun 入站字段 device（文档页未写，配置结构存在） | 有 |  |  | 已实现 | 通过 |  |
| `disable-icmp-forwarding` | tun 入站字段 disable-icmp-forwarding（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `dns-hijack` | DNS 劫持列表 | 有 |  |  | 未实现 | 未测 | 取值：`0.0.0.0:53` |
| `dns-mode` | 系统 DNS 配置方式 | 有 |  |  | 未实现 | 未测 | 取值：`disabled`、`hijack`、`native` |
| `endpoint-independent-nat` | 独立于端点的 NAT | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `exclude-dst-port` | tun 入站字段 exclude-dst-port（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `exclude-dst-port-range` | tun 入站字段 exclude-dst-port-range（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `exclude-interface` | tun 入站字段 exclude-interface（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `exclude-mac-address` | 排除的来源 MAC | 有 |  |  | 未实现 | 未测 | 取值：`MAC 列表` |
| `exclude-package` | 排除的 Android 包 | 有 |  |  | 未实现 | 未测 | 取值：`包名列表` |
| `exclude-src-port` | tun 入站字段 exclude-src-port（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `exclude-src-port-range` | tun 入站字段 exclude-src-port-range（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `exclude-uid` | 排除的 UID | 有 |  |  | 未实现 | 未测 | 取值：`整数列表` |
| `exclude-uid-range` | 排除的 UID 范围 | 有 |  |  | 未实现 | 未测 | 取值：`1000-99999` |
| `file-descriptor` | tun 入站字段 file-descriptor（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `gso` | tun 入站字段 gso（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `gso-max-size` | tun 入站字段 gso-max-size（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `icmp-timeout` | tun 入站字段 icmp-timeout（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `include-android-user` | 包含的 Android 用户 | 有 |  |  | 未实现 | 未测 | 取值：`整数列表` |
| `include-interface` | tun 入站字段 include-interface（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `include-mac-address` | 包含的来源 MAC | 有 |  |  | 未实现 | 未测 | 取值：`MAC 列表` |
| `include-package` | 包含的 Android 包 | 有 |  |  | 未实现 | 未测 | 取值：`包名列表` |
| `include-uid` | 包含的 UID | 有 |  |  | 未实现 | 未测 | 取值：`整数列表` |
| `include-uid-range` | 包含的 UID 范围 | 有 |  |  | 未实现 | 未测 | 取值：`1000-99999` |
| `inet4-address` | TUN IPv4 地址 | 有 |  |  | 已实现 | 通过 | 取值：`CIDR 列表` |
| `inet4-route-address` | IPv4 自定义路由 | 有 |  |  | 未实现 | 未测 | 取值：`CIDR 列表` |
| `inet4-route-exclude-address` | tun 入站字段 inet4-route-exclude-address（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `inet6-address` | TUN IPv6 地址 | 有 |  |  | 已实现 | 通过 | 取值：`CIDR 列表` |
| `inet6-route-address` | IPv6 自定义路由 | 有 |  |  | 未实现 | 未测 | 取值：`CIDR 列表` |
| `inet6-route-exclude-address` | tun 入站字段 inet6-route-exclude-address（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `iproute2-rule-index` | tun 入站字段 iproute2-rule-index（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `iproute2-table-index` | tun 入站字段 iproute2-table-index（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `loopback-address` | tun 入站字段 loopback-address（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `mtu` | MTU | 有 |  |  | 已实现 | 通过 | 取值：`整数` |
| `processors-per-channel` | tun 入站字段 processors-per-channel（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `recvmsgx` | tun 入站字段 recvmsgx（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `route-address` | tun 入站字段 route-address（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `route-address-set` | tun 入站字段 route-address-set（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `route-exclude-address` | tun 入站字段 route-exclude-address（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `route-exclude-address-set` | tun 入站字段 route-exclude-address-set（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `sendmsgx` | tun 入站字段 sendmsgx（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `stack` | 协议栈 | 有 |  |  | 部分 | 通过 | 取值：`gvisor`、`mips`、`mixed`、`system` |
| `strict-route` | 严格路由 | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `udp-timeout` | tun 入站字段 udp-timeout（文档页未写，配置结构存在） | 有 |  |  | 部分 | 通过 |  |

## tunnel

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | 端口转发入站 | 有 |  |  | 已实现 | 通过 |  |
| `tunnel` | Tunnel，旧称 dokodemo-door，端口映射与透明代理入站 |  |  | 有 | 部分 | 通过 | 取值：`tunnel` |
| `combo` | Tunnel 入站组合 | 有 |  | 有 | 部分 | 通过 | network：`tcp`、`tcp+udp`、`udp`<br>egress：`proxy`、`rules`<br>network：`tcp`、`tcp,udp`、`udp`<br>target：`followRedirect`、`portMap`、`rewrite`<br>tproxy：`off`、`redirect`、`tproxy`<br>约束：Redirect 只支持 TCP；TProxy 支持 TCP 和 UDP；透明代理仅 Linux<br>约束：TLS FromMitM 依赖 tunnel 入站解密的 TLS<br>约束：传输组合速查表未列 tunnel |
| `address` | rewriteAddress 的旧名 |  |  | 有 | 不适用 | 未测 |  |
| `allowed-network` | 可接收的网络类型，默认 tcp |  |  | 有 | 部分 | 通过 | 取值：`tcp`、`tcp,udp`、`udp` |
| `dokodemo-door` | 协议名别名 dokodemo-door，指向 Tunnel 页 |  |  | 有 | 不适用 | 未测 |  |
| `follow-redirect` | 识别 iptables 转发数据并转发到原目标 |  |  | 有 | 已实现 | 通过 | 取值：`false`、`true`<br>约束：sockopt.tproxy 为空时被设为 redirect |
| `network` | 转发的网络 | 有 |  | 有 | 已实现 | 通过 | 取值：`tcp`、`udp` |
| `port` | rewritePort 的旧名 |  |  | 有 | 不适用 | 未测 |  |
| `port-map` | 本地端口到远端地址/端口映射，未命中按 rewrite 处理 |  |  | 有 | 未实现 | 未测 | 取值：`"5555":"1.1.1.1:7777"`、`"5556":":8888"`、`"5557":"example.com:"` |
| `rewrite-address` | 转发目标地址，默认 localhost |  |  | 有 | 已实现 | 通过 | 取值：`IP`、`域名` |
| `rewrite-port` | 转发目标端口，0 或不填时为监听端口 |  |  | 有 | 部分 | 通过 | 取值：`0-65535` |
| `target` | 转发目标 | 有 |  |  | 已实现 | 通过 | 取值：`host:port` |
| `user-level` | 用户等级，默认 0 |  |  | 有 | 未实现 | 未测 | 取值：`number` |

## tunnels

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `address` | 本地监听地址 | 有 |  |  | 已实现 | 通过 | 取值：`host:port` |
| `network` | 监听网络类型 | 有 |  |  | 已实现 | 通过 | 取值：`tcp`、`udp` |
| `proxy` | 可选，经指定 proxies 或 proxy-groups 发送 | 有 |  |  | 已实现 | 通过 | 取值：`出站名` |
| `single-line` | 单行写法，顺序对应 network/address/target/proxy | 有 |  |  | 不适用 | 未测 | 取值：`tcp/udp,127.0.0.1:6553,8.8.8.8:53,proxy` |
| `target` | 转发目标地址 | 有 |  |  | 已实现 | 通过 | 取值：`host:port` |

## vless

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | VLESS 入站 | 有 | 有 |  | 已实现 | 通过 | 取值：`vless`<br>约束：可作 detour 注入目标（Injectable：TCP） |
| `vless` | VLESS 入站 |  |  | 有 | 已实现 | 通过 | 取值：`vless` |
| `combo` | VLESS 入站组合 | 有 | 有 | 有 | 部分 | 通过 | transport：`grpc`、`tcp`、`ws`、`xhttp`<br>security：`jls`、`none`、`reality`、`res-tls`、`shadow-tls`、`tls`<br>decryption：`native`、`none`、`random`、`xorpub`<br>flow：``、`xtls-rprx-vision`<br>ech：`off`、`on`<br>xhttp.mode：`auto`、`packet-up`、`stream-one`、`stream-up`<br>mux：`brutal`、`off`、`padding`<br>allow-insecure：`false`、`true`<br>约束：allow-insecure 不为 true 时至少填 certificate+private-key、shadow-tls、res-tls、jls-config、reality-config、decryption 之一<br>约束：reality 不可与 certificate、private-key 同填<br>约束：source:listener/sing_vless/server.go：certificate、reality、shadow-tls、res-tls、jls 互斥<br>security：`none`、`reality`、`tls`、`tls+ech`<br>transport：`grpc`、`http`、`httpupgrade`、`none`、`quic`、`ws`<br>multiplex：`off`、`on`<br>multiplex_padding：`off`、`on`<br>brutal：`off`、`on`<br>约束：QUIC 下自定义 TLS 只支持 ECH，所以 reality、utls 不能配 quic 传输（docs/configuration/shared/tls.md）<br>约束：brutal 服务端需要 Linux 和 brutal 内核模块<br>约束：http 传输不强制 TLS，无 TLS 时走明文 HTTP/1.1<br>约束：max_connections、min_streams 与 max_streams 冲突<br>约束：quic 传输要求 TLS（source:transport/v2ray/transport.go）<br>约束：sing-box 文档未写 Vision 对传输层和安全层的限制，需实测<br>约束：入站 padding 开启后拒绝未填充连接<br>约束：标准 gRPC 不默认编入，需 with_grpc 构建标签，否则用默认 gRPC 实现<br>约束：没有 TCP 传输（明文 HTTP 并入 http 传输）、mKCP、DomainSocket（docs/configuration/shared/v2ray-transport.md）<br>transport：`grpc`、`httpupgrade`、`hysteria`、`mkcp`、`raw`、`websocket`、`xhttp`<br>security：`none`、`reality`、`tls`<br>decryption：`mlkem768x25519plus`、`none`<br>fallback：`fallbacks`、`none`<br>reverse：`off`、`on`<br>约束：REALITY 只能配 raw、xhttp、grpc<br>约束：VLESS 必须配传输安全；security none 仅允许对端私有地址且受信网络，或已启用 VLESS Encryption<br>约束：Vision 只能配 TCP+TLS/REALITY，或 VLESS Encryption（无传输限制）<br>约束：fallbacks 只能用于 TCP+TLS<br>约束：hysteria 传输须配 tls<br>约束：masque 传输不适用 |
| `allow-insecure` | 允许不开启 tls，仅用于 nginx、caddy 前置 | 有 |  |  | 部分 | 通过 | 取值：`false`、`true` |
| `certificate` | TLS 证书，PEM 或路径 | 有 |  |  | 已实现 | 通过 | 取值：`PEM`、`路径`<br>约束：与 private-key 同时填写才开启 tls |
| `client-auth-cert` | mTLS 客户端证书 | 有 |  |  | 未实现 | 未测 | 取值：`PEM`、`路径` |
| `client-auth-type` | mTLS 类型 | 有 |  |  | 未实现 | 未测 | 取值：``、`request`、`require-and-verify`、`require-any`、`verify-if-given`<br>约束：verify-if-given、require-and-verify 时 client-auth-cert 必填 |
| `clients` | users 的别名 |  |  | 有 | 已实现 | 通过 |  |
| `decryption` | vless encryption 服务端配置；可由 mihomo generate vless-x25519、vless-mlkem768 生成 | 有 |  | 有 | 部分 | 通过 | 取值：`mlkem768x25519plus.<外观>.<票据>.<padding...>.<认证参数>`、`mlkem768x25519plus.native\|xorpub\|random.600s(300-600s)\|0s.<padding len>.<padding gap>.<X25519 PrivateKey>.<ML-KEM-768 Seed>`、`none`<br>约束：1-RTT 下发 ticket 或只允许 1-RTT<br>约束：padding 默认 100-111-1111.75-0-111.50-0-3333<br>约束：第一个 padding 需概率 100%、至少 35 字节<br>约束：不能与 fallbacks 同用（source:infra/conf/vless.go）<br>约束：不能留空 |
| `decryption-appearance` | 第 2 块流量外观 |  |  | 有 | 已实现 | 通过 | 取值：`native`、`random`、`xorpub`<br>约束：两端一致 |
| `decryption-auth` | 最后一块认证参数 |  |  | 有 | 已实现 | 通过 | 取值：`mlkem768 Seed`、`x25519 PrivateKey`<br>约束：与客户端对应 |
| `decryption-handshake` | 第 1 块握手方式 |  |  | 有 | 已实现 | 通过 | 取值：`mlkem768x25519plus`<br>约束：两端一致 |
| `decryption-padding` | padding/delay 块，格式 probability-min-max |  |  | 有 | 未实现 | 未测 | 取值：`100-111-1111`、`50-0-3333`、`75-0-111`<br>约束：两个 padding 之间必须有 delay<br>约束：无 padding 时默认 100-111-1111.75-0-111.50-0-3333<br>约束：无需与客户端相同<br>约束：第一个 padding 概率 100% 且最小长度大于 0 |
| `decryption-ticket` | 第 3 块会话恢复票据有效时间 |  |  | 有 | 部分 | 通过 | 取值：`100-500s`、`600s`<br>约束：600s 表示 300-600s 随机 |
| `ech-key` | ECH 密钥，填写即开启；可由 mihomo generate ech-keypair 生成 | 有 |  |  | 未实现 | 未测 | 取值：`PEM` |
| `email` | 用户邮箱，用于日志和统计 |  |  | 有 | 已实现 | 通过 |  |
| `fallbacks` | 回落配置数组 |  |  | 有 | 已实现 | 通过 |  |
| `flow` | 单用户流控 |  |  | 有 | 已实现 | 通过 | 取值：``、`xtls-rprx-vision`<br>约束：XTLS 仅在 TCP+TLS/REALITY 或 VLESS Encryption 下可用<br>约束：非空时无法把单用户 flow 设为空 |
| `grpc-service-name` | 不为空开启 gRPC 传输 | 有 |  |  | 已实现 | 通过 | 取值：`字符串` |
| `id` | 用户 ID：UUID 或小于 30 字节字符串（映射 UUIDv5） |  |  | 有 | 部分 | 通过 |  |
| `jls-config-alpn` | ALPN | 有 |  |  | 未实现 | 未测 | 取值：`列表` |
| `jls-config-dest` | 回落目标 | 有 |  |  | 未实现 | 未测 | 取值：`host:port` |
| `jls-config-enable` | 启用 JLS，替代普通 TLS；未认证连接回落 dest | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `jls-config-proxy` | 回落目标使用的代理 | 有 |  |  | 未实现 | 未测 | 取值：`出站名` |
| `jls-config-rate-limit` | fallback 转发限速，bit/s，0 不限 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `jls-config-sni` | SNI，留空从 dest 推导 | 有 |  |  | 未实现 | 未测 | 取值：`域名` |
| `jls-config-users-password` | JLS 密码 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `jls-config-users-username` | JLS 用户名 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `level` | 用户等级，默认 0 |  |  | 有 | 未实现 | 未测 |  |
| `multiplex` | 参阅 多路复用。 |  | 有 |  | 已实现 | 通过 |  |
| `mux-option-brutal-down` | Brutal 下行，默认 Mbps | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `mux-option-brutal-enabled` | 入站 TCP Brutal | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `mux-option-brutal-up` | Brutal 上行，默认 Mbps | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `mux-option-padding` | 入站 sing-mux 填充 | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true` |
| `private-key` | TLS 私钥，PEM 或路径 | 有 |  |  | 已实现 | 通过 | 取值：`PEM`、`路径`<br>约束：与 certificate 同时填写 |
| `reality-config-dest` | REALITY 回落目标 | 有 |  |  | 已实现 | 通过 | 取值：`host:port`<br>约束：不可与 certificate、private-key 同时填写 |
| `reality-config-limit-fallback-download-after-bytes` | 回落下载传输该字节后开始限速 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `reality-config-limit-fallback-download-burst-bytes-per-sec` | 回落下载突发速率 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `reality-config-limit-fallback-download-bytes-per-sec` | 回落下载基准速率 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `reality-config-limit-fallback-upload-after-bytes` | 回落上传传输该字节后开始限速 | 有 |  |  | 未实现 | 未测 | 取值：`整数`<br>约束：回落限速是一种特征，不建议启用 |
| `reality-config-limit-fallback-upload-burst-bytes-per-sec` | 回落上传突发速率 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `reality-config-limit-fallback-upload-bytes-per-sec` | 回落上传基准速率 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `reality-config-max-time-difference` | 最大时间差，微秒 | 有 |  |  | 已实现 | 通过 | 取值：`整数` |
| `reality-config-private-key` | REALITY 私钥，可由 mihomo generate reality-keypair 生成 | 有 |  |  | 已实现 | 通过 | 取值：`字符串` |
| `reality-config-proxy` | 回落目标使用的代理 | 有 |  |  | 未实现 | 未测 | 取值：`出站名` |
| `reality-config-server-names` | 允许的 SNI | 有 |  |  | 已实现 | 通过 | 取值：`域名列表` |
| `reality-config-short-id` | 允许的 short id | 有 |  |  | 已实现 | 通过 | 取值：`十六进制列表` |
| `res-tls-dest` | 回落目标 | 有 |  |  | 未实现 | 未测 | 取值：`host:port` |
| `res-tls-enable` | 启用 ResTLS | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `res-tls-min-record-len` | 最小记录长度 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `res-tls-password` | ResTLS 密码 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `res-tls-proxy` | 回落目标使用的代理 | 有 |  |  | 未实现 | 未测 | 取值：`出站名` |
| `res-tls-rate-limit` | fallback 双向转发限速，bit/s，0 不限 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `res-tls-restls-script` | Restls 剧本 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `reverse` | 极简反向代理：存在时该用户连接用于建立反向隧道，同时禁用正向代理 |  |  | 有 | 未实现 | 未测 |  |
| `shadow-tls-enable` | 启用 ShadowTLS | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `shadow-tls-handshake-dest` | 握手目标 | 有 |  |  | 未实现 | 未测 | 取值：`host:port` |
| `shadow-tls-handshake-for-server-name` | 按 SNI 选握手目标（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`映射` |
| `shadow-tls-handshake-proxy` | 握手目标使用的代理 | 有 |  |  | 未实现 | 未测 | 取值：`出站名` |
| `shadow-tls-password` | v2 密码 | 有 |  |  | 未实现 | 未测 | 取值：`字符串`<br>约束：v2 配置项 |
| `shadow-tls-strict-mode` | ShadowTLS 严格模式（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `shadow-tls-users-name` | v3 用户名 | 有 |  |  | 未实现 | 未测 | 取值：`字符串`<br>约束：v3 配置项 |
| `shadow-tls-users-password` | v3 用户密码 | 有 |  |  | 未实现 | 未测 | 取值：`字符串`<br>约束：v3 配置项 |
| `shadow-tls-version` | ShadowTLS 版本 | 有 |  |  | 未实现 | 未测 | 取值：`1`、`2`、`3` |
| `shadow-tls-wildcard-sni` | ShadowTLS 通配 SNI（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `tag` | 反向代理的出站 tag |  |  | 有 | 未实现 | 未测 | 约束：tag 不能为空<br>约束：入站 reverse 不能有 sniffing（source:infra/conf/vless.go）<br>约束：多连接接入时每个请求随机选一条 |
| `testseed` | Vision padding 种子，文档未写 |  |  | 实验 | 未实现 | 未测 |  |
| `tls` | TLS 配置, 参阅 TLS。 |  | 有 |  | 部分 | 通过 |  |
| `transport` | V2Ray 传输配置，参阅 V2Ray 传输层。 |  | 有 |  | 部分 | 通过 |  |
| `users` | VLESS 用户。 |  | 有 | 有 | 已实现 | 通过 | 约束：必填 |
| `users-flow` | 用户流控 | 有 | 有 |  | 已实现 | 通过 | 取值：`xtls-rprx-vision` |
| `users-name` | 用户名称，用于日志和 auth_user 匹配 |  | 有 |  | 已实现 | 通过 |  |
| `users-username` | 用户名 | 有 |  |  | 已实现 | 通过 | 取值：`字符串` |
| `users-uuid` | 用户 UUID | 有 | 有 |  | 已实现 | 通过 | 取值：`UUID`<br>约束：必填 |
| `wire-format` | VLESS 线格式：版本、等价 UUID、附加信息 ProtoBuf、指令、端口、地址 |  |  | 有 | 已实现 | 通过 | 取值：`版本 0/1` |
| `ws-path` | 不为空开启 WebSocket 传输 | 有 |  |  | 已实现 | 通过 | 取值：`路径` |
| `xhttp-config-host` | xhttp 主机 | 有 |  |  | 未实现 | 未测 | 取值：`域名` |
| `xhttp-config-mode` | xhttp 模式 | 有 |  |  | 已实现 | 通过 | 取值：`auto`、`packet-up`、`stream-one`、`stream-up` |
| `xhttp-config-no-sse-header` | 不发 SSE 头 | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `xhttp-config-path` | xhttp 路径 | 有 |  |  | 已实现 | 通过 | 取值：`路径` |
| `xhttp-config-sc-max-buffered-posts` | 服务端最多缓冲 POST 数 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `xhttp-config-sc-max-each-post-bytes` | 单 POST 最大字节 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `xhttp-config-sc-stream-up-server-secs` | stream-up 服务端保活范围 | 有 |  |  | 未实现 | 未测 | 取值：`20-80` |
| `xhttp-config-seq-key` | 序列号键名 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `xhttp-config-seq-placement` | 序列号位置 | 有 |  |  | 未实现 | 未测 | 取值：`cookie`、`header`、`path`、`query` |
| `xhttp-config-session-key` | 会话 ID 键名 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `xhttp-config-session-length` | 会话 ID 长度范围 | 有 |  |  | 未实现 | 未测 | 取值：`16-32`<br>约束：起始值不可为 0，总 id 空间须大于 21 亿，仅 session-table 不为空或为 uuid 时生效 |
| `xhttp-config-session-placement` | 会话 ID 位置 | 有 |  |  | 未实现 | 未测 | 取值：`cookie`、`header`、`path`、`query` |
| `xhttp-config-session-table` | 会话 ID 字符表 | 有 |  |  | 未实现 | 未测 | 取值：``、`ALPHABET`、`Alphabet`、`BASE36`、`Base62`、`HEX`、`alphabet`、`base36`、`hex`、`number`、`uuid` |
| `xhttp-config-uplink-chunk-size` | 上行块大小 | 有 |  |  | 未实现 | 未测 | 取值：`整数`<br>约束：仅 uplink-data-placement 不为 body |
| `xhttp-config-uplink-data-key` | 上行数据键名 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `xhttp-config-uplink-data-placement` | 上行数据位置 | 有 |  |  | 未实现 | 未测 | 取值：`body`、`cookie`、`header` |
| `xhttp-config-uplink-http-method` | 上行 HTTP 方法 | 有 |  |  | 未实现 | 未测 | 取值：`DELETE`、`PATCH`、`POST`、`PUT` |
| `xhttp-config-x-padding-bytes` | 填充长度范围 | 有 |  |  | 未实现 | 未测 | 取值：`100-1000` |
| `xhttp-config-x-padding-header` | 填充所用标头 | 有 |  |  | 未实现 | 未测 | 取值：`Referer` |
| `xhttp-config-x-padding-key` | 填充键名 | 有 |  |  | 未实现 | 未测 | 取值：`x_padding` |
| `xhttp-config-x-padding-method` | 填充生成方式 | 有 |  |  | 未实现 | 未测 | 取值：`repeat-x`、`tokenish` |
| `xhttp-config-x-padding-obfs-mode` | 填充混淆 | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `xhttp-config-x-padding-placement` | 填充位置 | 有 |  |  | 未实现 | 未测 | 取值：`cookie`、`header`、`query`、`queryInHeader` |

## vless-reverse

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | VLESS 极简反向代理组合 |  |  | 有 | 未实现 | 未测 | role：`client(outbound.reverse)`、`server(users.reverse)`<br>transport：`grpc`、`httpupgrade`、`hysteria`、`mkcp`、`raw`、`websocket`、`xhttp`<br>sniffing：`off`、`outbound reverse sniffing`<br>约束：入站用户 reverse 禁用该用户正向代理<br>约束：客户端必须用简化写法<br>约束：来自反向代理的流量经 Freedom 默认阻止所有目标，需 finalRules allow（docs/config/outbounds/freedom.md） |

## vmess

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | VMess 入站 | 有 | 有 |  | 已实现 | 通过 | 取值：`vmess`<br>约束：可作 detour 注入目标（Injectable：TCP） |
| `vmess` | VMess 入站 |  |  | 有 | 已实现 | 通过 | 取值：`vmess`<br>约束：UTC 时间误差须在 120 秒内<br>约束：源码启动时打印不移除的弃用告警，建议 VLESS Encryption |
| `combo` | VMess 入站组合 | 有 | 有 | 有 | 部分 | 通过 | transport：`grpc`、`mekya`、`mkcp`、`tcp`、`ws`<br>security：`jls`、`none`、`reality`、`res-tls`、`shadow-tls`、`tls`、`tlsmirror`<br>ech：`off`、`on`<br>mkcp.header：`dtls`、`none`、`srtp`、`utp`、`wechat-video`、`wireguard`<br>mux：`brutal`、`off`、`padding`<br>约束：mekya 不可与 mkcp、ws、grpc 同用<br>约束：reality、tlsmirror 不可与 certificate、private-key 同填<br>约束：source:listener/sing_vmess/server.go：certificate、reality、tlsmirror、shadow-tls、res-tls、jls 互斥<br>约束：source:listener/sing_vmess/server.go：mKCP 不可配 ShadowTLS、Restls、JLS<br>security：`none`、`reality`、`tls`、`tls+ech`<br>transport：`grpc`、`http`、`httpupgrade`、`none`、`quic`、`ws`<br>alter_id：`0`、`>0`<br>multiplex：`off`、`on`<br>multiplex_padding：`off`、`on`<br>brutal：`off`、`on`<br>约束：QUIC 下自定义 TLS 只支持 ECH，所以 reality、utls 不能配 quic 传输（docs/configuration/shared/tls.md）<br>约束：alterId 大于 0 启用旧版 MD5 认证，不建议大于 1<br>约束：brutal 服务端需要 Linux 和 brutal 内核模块<br>约束：http 传输不强制 TLS，无 TLS 时走明文 HTTP/1.1<br>约束：max_connections、min_streams 与 max_streams 冲突<br>约束：quic 传输要求 TLS（source:transport/v2ray/transport.go）<br>约束：入站 padding 开启后拒绝未填充连接<br>约束：标准 gRPC 不默认编入，需 with_grpc 构建标签，否则用默认 gRPC 实现<br>约束：没有 TCP 传输（明文 HTTP 并入 http 传输）、mKCP、DomainSocket（docs/configuration/shared/v2ray-transport.md）<br>transport：`grpc`、`httpupgrade`、`hysteria`、`mkcp`、`raw`、`websocket`、`xhttp`<br>security：`none`、`reality`、`tls`<br>约束：hysteria 传输须配 tls<br>约束：masque 传输不适用<br>约束：reality 只能配 raw、xhttp、grpc |
| `certificate` | TLS 证书，PEM 或路径 | 有 |  |  | 已实现 | 通过 | 取值：`PEM`、`路径`<br>约束：与 private-key 同时填写才开启 tls |
| `client-auth-cert` | mTLS 客户端证书 | 有 |  |  | 未实现 | 未测 | 取值：`PEM`、`路径` |
| `client-auth-type` | mTLS 类型 | 有 |  |  | 未实现 | 未测 | 取值：``、`request`、`require-and-verify`、`require-any`、`verify-if-given`<br>约束：verify-if-given、require-and-verify 时 client-auth-cert 必填 |
| `clients` | users 的别名 |  |  | 有 | 已实现 | 通过 |  |
| `default` | users 默认配置，仅配合 detour 有效 |  |  | 有 | 未实现 | 未测 |  |
| `dynamic-port-command` | 协议文档中的动态端口指令 0x01 |  |  | 有 | 未实现 | 未测 | 约束：配置页只提及动态端口和 detour；infra/conf 的 VMess 入站结构无 detour 字段 |
| `ech-key` | ECH 密钥，填写即开启；可由 mihomo generate ech-keypair 生成 | 有 |  |  | 未实现 | 未测 | 取值：`PEM` |
| `email` | 用户邮箱 |  |  | 有 | 已实现 | 通过 |  |
| `grpc-service-name` | 不为空开启 gRPC 传输 | 有 |  |  | 已实现 | 通过 | 取值：`字符串` |
| `id` | 用户 ID：UUID 或小于 30 字节字符串 |  |  | 有 | 部分 | 通过 |  |
| `jls-config-alpn` | ALPN | 有 |  |  | 未实现 | 未测 | 取值：`列表` |
| `jls-config-dest` | 回落目标 | 有 |  |  | 未实现 | 未测 | 取值：`host:port` |
| `jls-config-enable` | 启用 JLS，替代普通 TLS；未认证连接回落 dest | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `jls-config-proxy` | 回落目标使用的代理 | 有 |  |  | 未实现 | 未测 | 取值：`出站名` |
| `jls-config-rate-limit` | fallback 转发限速，bit/s，0 不限 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `jls-config-sni` | SNI，留空从 dest 推导 | 有 |  |  | 未实现 | 未测 | 取值：`域名` |
| `jls-config-users-password` | JLS 密码 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `jls-config-users-username` | JLS 用户名 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `level` | 用户等级，默认 0 |  |  | 有 | 未实现 | 未测 |  |
| `mekya-config-enable` | 启用 v2ray 兼容 Mekya 入站 | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true`<br>约束：不可与 mkcp、ws、grpc 同时使用 |
| `mekya-config-h2-pool-size` | vmess mekya-config 字段 h2-pool-size（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `mekya-config-kcp-congestion` | 启用拥塞控制 | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `mekya-config-kcp-downlink-capacity` | 下行容量，MB/s | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `mekya-config-kcp-header` | 伪装包头 | 有 |  |  | 未实现 | 未测 | 取值：`dtls`、`none`、`srtp`、`utp`、`wechat-video`、`wireguard` |
| `mekya-config-kcp-mtu` | KCP MTU | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `mekya-config-kcp-read-buffer` | 读缓冲，字节 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `mekya-config-kcp-seed` | AES-GCM 认证种子，留空用默认认证 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `mekya-config-kcp-tti` | 传输时间间隔，毫秒 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `mekya-config-kcp-uplink-capacity` | 上行容量，MB/s | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `mekya-config-kcp-write-buffer` | 写缓冲，字节 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `mekya-config-max-request-size` | vmess mekya-config 字段 max-request-size（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `mekya-config-max-simultaneous-write-connection` | 同会话同时等待写回的请求数 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `mekya-config-max-write-delay` | vmess mekya-config 字段 max-write-delay（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `mekya-config-max-write-duration-ms` | 单响应写回最大时长，毫秒 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `mekya-config-max-write-size` | 单响应写回最大负载，字节 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `mekya-config-packet-writing-buffer` | 写包缓冲 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `mekya-config-polling-interval-initial` | vmess mekya-config 字段 polling-interval-initial（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `mekya-config-url` | vmess mekya-config 字段 url（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `mkcp-config-congestion` | 启用拥塞控制 | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `mkcp-config-downlink-capacity` | 下行容量，MB/s | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `mkcp-config-enable` | 启用 v2ray 兼容 mKCP 入站 | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `mkcp-config-header` | 伪装包头 | 有 |  |  | 未实现 | 未测 | 取值：`dtls`、`none`、`srtp`、`utp`、`wechat-video`、`wireguard` |
| `mkcp-config-mtu` | KCP MTU | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `mkcp-config-read-buffer` | 读缓冲，字节 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `mkcp-config-seed` | AES-GCM 认证种子，留空用默认认证 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `mkcp-config-tti` | 传输时间间隔，毫秒 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `mkcp-config-uplink-capacity` | 上行容量，MB/s | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `mkcp-config-write-buffer` | 写缓冲，字节 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `multiplex` | 参阅 多路复用。 |  | 有 |  | 已实现 | 通过 |  |
| `mux-option-brutal-down` | Brutal 下行，默认 Mbps | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `mux-option-brutal-enabled` | 入站 TCP Brutal | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `mux-option-brutal-up` | Brutal 上行，默认 Mbps | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `mux-option-padding` | 入站 sing-mux 填充 | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true` |
| `private-key` | TLS 私钥，PEM 或路径 | 有 |  |  | 已实现 | 通过 | 取值：`PEM`、`路径`<br>约束：与 certificate 同时填写 |
| `reality-config-dest` | REALITY 回落目标 | 有 |  |  | 未实现 | 未测 | 取值：`host:port`<br>约束：不可与 certificate、private-key 同时填写 |
| `reality-config-limit-fallback-download-after-bytes` | 回落下载传输该字节后开始限速 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `reality-config-limit-fallback-download-burst-bytes-per-sec` | 回落下载突发速率 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `reality-config-limit-fallback-download-bytes-per-sec` | 回落下载基准速率 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `reality-config-limit-fallback-upload-after-bytes` | 回落上传传输该字节后开始限速 | 有 |  |  | 未实现 | 未测 | 取值：`整数`<br>约束：回落限速是一种特征，不建议启用 |
| `reality-config-limit-fallback-upload-burst-bytes-per-sec` | 回落上传突发速率 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `reality-config-limit-fallback-upload-bytes-per-sec` | 回落上传基准速率 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `reality-config-max-time-difference` | 最大时间差，微秒 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `reality-config-private-key` | REALITY 私钥，可由 mihomo generate reality-keypair 生成 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `reality-config-proxy` | 回落目标使用的代理 | 有 |  |  | 未实现 | 未测 | 取值：`出站名` |
| `reality-config-server-names` | 允许的 SNI | 有 |  |  | 未实现 | 未测 | 取值：`域名列表` |
| `reality-config-short-id` | 允许的 short id | 有 |  |  | 未实现 | 未测 | 取值：`十六进制列表` |
| `res-tls-dest` | 回落目标 | 有 |  |  | 未实现 | 未测 | 取值：`host:port` |
| `res-tls-enable` | 启用 ResTLS | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `res-tls-min-record-len` | 最小记录长度 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `res-tls-password` | ResTLS 密码 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `res-tls-proxy` | 回落目标使用的代理 | 有 |  |  | 未实现 | 未测 | 取值：`出站名` |
| `res-tls-rate-limit` | fallback 双向转发限速，bit/s，0 不限 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `res-tls-restls-script` | Restls 剧本 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `shadow-tls-enable` | 启用 ShadowTLS | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `shadow-tls-handshake-dest` | 握手目标 | 有 |  |  | 未实现 | 未测 | 取值：`host:port` |
| `shadow-tls-handshake-for-server-name` | 按 SNI 选握手目标（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`映射` |
| `shadow-tls-handshake-proxy` | 握手目标使用的代理 | 有 |  |  | 未实现 | 未测 | 取值：`出站名` |
| `shadow-tls-password` | v2 密码 | 有 |  |  | 未实现 | 未测 | 取值：`字符串`<br>约束：v2 配置项 |
| `shadow-tls-strict-mode` | ShadowTLS 严格模式（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `shadow-tls-users-name` | v3 用户名 | 有 |  |  | 未实现 | 未测 | 取值：`字符串`<br>约束：v3 配置项 |
| `shadow-tls-users-password` | v3 用户密码 | 有 |  |  | 未实现 | 未测 | 取值：`字符串`<br>约束：v3 配置项 |
| `shadow-tls-version` | ShadowTLS 版本 | 有 |  |  | 未实现 | 未测 | 取值：`1`、`2`、`3` |
| `shadow-tls-wildcard-sni` | ShadowTLS 通配 SNI（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `tls` | TLS 配置, 参阅 TLS。 |  | 有 |  | 部分 | 通过 |  |
| `tlsmirror-config-connection-enrolment-primary-ingress-outbound` | v2ray 兼容字段，连接登记入站控制出站 tag | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `tlsmirror-config-defer-instance-derived-write-time-base-nanoseconds` | 首写前固定延迟，纳秒 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `tlsmirror-config-defer-instance-derived-write-time-uniform-random-multiplier-nanoseconds` | 首写前额外随机延迟上限，纳秒 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `tlsmirror-config-dest` | tlsmirror 目标 | 有 |  |  | 未实现 | 未测 | 取值：`host:port`<br>约束：不可与 certificate、private-key 同时填写 |
| `tlsmirror-config-explicit-nonce-ciphersuites` | TLS 1.2 载体显式 nonce 套件 | 有 |  |  | 未实现 | 未测 | 取值：`整数列表` |
| `tlsmirror-config-primary-egress-outbound` | vmess tlsmirror-config 字段 primary-egress-outbound（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `tlsmirror-config-primary-key` | 必填，32 字节主密钥 base64 | 有 |  |  | 未实现 | 未测 | 取值：`base64` |
| `tlsmirror-config-proxy` | 目标使用的代理 | 有 |  |  | 未实现 | 未测 | 取值：`出站名` |
| `tlsmirror-config-sequence-watermarking-enabled` | 启用序列水印 | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `tlsmirror-config-transport-layer-padding-enabled` | 启用传输层填充 | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `transport` | V2Ray 传输配置，参阅 V2Ray 传输层。 |  | 有 |  | 部分 | 通过 |  |
| `users` | VMess 用户。 |  | 有 | 有 | 已实现 | 通过 | 约束：必填<br>约束：提供旧协议支持（VMess MD5 身份验证）仅出于兼容性目的，不建议使用 alterId > 1。<br>约束：用作动态端口时自动创建用户 |
| `users-alter-id` | VMess 用户 alterId，0 关闭旧协议，大于 0 开启 |  | 有 |  | 未实现 | 未测 |  |
| `users-alterid` | alterId | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `users-name` | 用户名称，用于日志和 auth_user 匹配 |  | 有 |  | 已实现 | 通过 |  |
| `users-username` | 用户名 | 有 |  |  | 已实现 | 通过 | 取值：`字符串` |
| `users-uuid` | 用户 UUID | 有 | 有 |  | 已实现 | 通过 | 取值：`UUID` |
| `wire-format` | VMess 线格式：认证、指令 AES-128-CFB、数据段 |  |  | 有 | 部分 | 通过 | 取值：`0x00 AES-128-CFB`、`0x01 不加密`、`0x02 AES-128-GCM`、`0x03 ChaCha20-Poly1305`<br>约束：配置 security 只开放 aes-128-gcm、chacha20-poly1305、auto |
| `ws-path` | 不为空开启 WebSocket 传输 | 有 |  |  | 已实现 | 通过 | 取值：`路径` |

## wireguard

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `wireguard` | 用户态 WireGuard 入站 |  |  | 有 | 已实现 | 通过 | 取值：`wireguard` |
| `combo` | WireGuard 入站不使用 streamSettings 传输和安全 |  |  | 有 | 已实现 | 通过 | transport：`不适用`<br>security：`不适用`<br>network：`tcp`、`udp`<br>约束：传输方式和传输安全均不适用<br>约束：协议自带加密隧道 |
| `allowed-ips` | 允许的客户端源 IP，默认全部 |  |  | 有 | 已实现 | 通过 | 约束：多客户端时不应重叠 |
| `email` | 用户邮箱 |  |  | 有 | 已实现 | 通过 |  |
| `keep-alive` | 向客户端发保活的间隔（秒），默认 0 |  |  | 有 | 已实现 | 通过 |  |
| `level` | 用户等级，默认 0 |  |  | 有 | 未实现 | 未测 |  |
| `mtu` | 隧道内层 MTU，默认 1420 |  |  | 有 | 已实现 | 通过 | 约束：IPv4 endpoint 可 1440，IPv6 endpoint 1420，PPPoE 再减 8 |
| `peers` | 客户端 peers 列表 |  |  | 有 | 已实现 | 通过 |  |
| `pre-shared-key` | 预共享密钥，可选 |  |  | 有 | 已实现 | 通过 |  |
| `public-key` | 客户端公钥，必填 |  |  | 有 | 已实现 | 通过 |  |
| `secret-key` | 服务器私钥，必填，xray wg 的 PrivateKey |  |  | 有 | 已实现 | 通过 |  |
