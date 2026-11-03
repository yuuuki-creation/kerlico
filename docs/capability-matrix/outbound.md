# 出站

由 `tools/capability_matrix.py build` 生成，不要手改。

## anytls

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | AnyTLS 出站 | 有 | 有 |  | 已实现 | 通过 | 取值：`anytls`<br>约束：自 sing-box 1.12.0 起 |
| `combo` | AnyTLS 出站维度 | 有 | 有 |  | 部分 | 通过 | security：`jls`、`restls`、`shadow-tls`、`tls`<br>ech：`off`、`on`<br>client-fingerprint：`360`、`android`、`chrome`、`edge`、`firefox`、`ios`、`none`、`qq`、`random`、`safari`<br>verify：`default`、`fingerprint`、`name-cert-verify`、`skip-cert-verify`<br>mtls：`off`、`on`<br>udp：`false`、`true`<br>约束：source:adapter/outbound/anytls.go：ShadowTLS、Restls、JLS 互斥<br>约束：不支持 AnyTLS+Reality，未来也不支持<br>约束：隐藏 SNI 用 ECH，或组合 ShadowTLS、ResTLS、JLS<br>client_metadata：`custom`、`empty`<br>security：`reality+utls`、`tls`<br>约束：client_metadata 默认空，自 1.13.16 起可设<br>约束：tcp_fast_open 不支持（source:protocol/anytls/outbound.go）<br>约束：tls 必填 |
| `client-metadata` | 发送给服务端的元数据，v1.19.30 起默认不发 | 有 | 有 |  | 未实现 | 未测 | 取值：`字符串`<br>约束：自 sing-box 1.13.16 起 |
| `disable-reuse` | anytls 出站字段 disable-reuse（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `idle-session-check-interval` | 检查空闲会话间隔，默认 30 秒 | 有 | 有 |  | 未实现 | 未测 | 取值：`整数`<br>约束：自 sing-box 1.12.0 起<br>约束：默认值：30秒。 |
| `idle-session-timeout` | 空闲超过此值关闭，默认 30 秒 | 有 | 有 |  | 已实现 | 通过 | 取值：`整数`<br>约束：自 sing-box 1.12.0 起<br>约束：默认值：30秒。 |
| `min-idle-session` | 检查时保留的空闲会话数，默认 0 | 有 | 有 |  | 未实现 | 未测 | 取值：`整数`<br>约束：自 sing-box 1.12.0 起<br>约束：默认值：`n`=0 |
| `password` | 密码 | 有 | 有 |  | 已实现 | 通过 | 取值：`字符串`<br>约束：必填<br>约束：自 sing-box 1.12.0 起 |
| `server` | 服务器地址。 |  | 有 |  | 已实现 | 通过 | 约束：必填<br>约束：自 sing-box 1.12.0 起 |
| `server-port` | 服务器端口。 |  | 有 |  | 已实现 | 通过 | 约束：必填<br>约束：自 sing-box 1.12.0 起 |
| `tls` | TLS 配置, 参阅 TLS。 |  | 有 |  | 部分 | 通过 | 约束：必填<br>约束：自 sing-box 1.12.0 起 |

## block

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `blackhole` | 黑洞出站，丢弃数据并关闭连接；别名 block |  |  | 有 | 已实现 | 通过 | 取值：`blackhole` |
| `protocol` | 配置中的 reject 类型（文档未写） | 有 | 废弃 |  | 已实现 | 通过 | 取值：`block`、`reject`<br>约束：docs/deprecated.md 写 1.13.0 已移除；source:include/registry.go 仍注册 block，以实测为准<br>约束：用 reject 规则动作替代 |
| `combo` | 黑洞响应维度 |  |  | 有 | 部分 | 通过 | response：`http`、`none` |
| `custom-response-data` | 自定义响应数据字段，文档未写 |  |  | 有 | 未实现 | 未测 |  |
| `response` | 黑洞响应配置，不指定时直接关闭 |  |  | 有 | 未实现 | 未测 |  |
| `type` | 响应类型，默认 none |  |  | 有 | 未实现 | 未测 | 取值：`http`、`none`<br>约束：http 发回 HTTP 403 后关闭 |

## bridge

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | L3 直连出站，把 L3 连接从网卡转发出去 |  | 有 |  | 未实现 | 未测 | 取值：`bridge`<br>约束：L4 连接被拒绝<br>约束：发往本机地址的流量被拒绝<br>约束：自 sing-box 1.14.0 起<br>约束：需要特权：Linux、macOS、Windows、已 root 的 Android、越狱 iOS |
| `combo` | bridge 出站的网络和接口组合 |  | 有 |  | 未实现 | 未测 | network：`icmp`、`tcp`、`udp`<br>interface：`default`、`named`<br>bridge_name：`custom`、`default`<br>约束：L4 连接被拒绝<br>约束：bridge_name 在 Apple 平台无效<br>约束：iproute2_table_index、iproute2_rule_index 仅 Linux<br>约束：只能经预匹配的 route 动作接收 L3 流量<br>约束：建议用 preferred_by 作 route 规则门控 |
| `bridge-name` | 自定义 bridge TUN 接口名前缀，默认使用 `bridge`。 |  | 有 |  | 未实现 | 未测 | 约束：在 Apple 平台上无效。<br>约束：自 sing-box 1.14.0 起 |
| `interface` | 转发流量流出的网络接口名称。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：默认使用默认接口。 |
| `iproute2-rule-index` | Linux iproute2 规则起始索引。 |  | 有 |  | 未实现 | 未测 | 约束：仅支持 Linux。<br>约束：自 sing-box 1.14.0 起<br>约束：默认使用 `100`。 |
| `iproute2-table-index` | Linux iproute2 路由表索引。 |  | 有 |  | 未实现 | 未测 | 约束：仅支持 Linux。<br>约束：自 sing-box 1.14.0 起<br>约束：默认使用 `2200` + 实例索引。 |

## common

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `default-first` | 列表第一个元素为主 outbound，路由未命中时使用 |  |  | 有 | 部分 | 通过 |  |
| `mux` | Mux 配置 |  |  | 有 | 部分 | 通过 |  |
| `name` | 必须，代理名称，不可重复 | 有 |  |  | 已实现 | 通过 | 取值：`字符串` |
| `port` | 必须，端口 | 有 |  |  | 已实现 | 通过 | 取值：`端口` |
| `protocol` | 出站协议名 |  |  | 有 | 部分 | 通过 | 取值：`blackhole`、`dns`、`freedom`、`http`、`hysteria`、`loopback`、`masque`、`shadowsocks`、`socks`、`trojan`、`vless`、`vmess`、`wireguard`<br>约束：源码另接受别名 block、direct |
| `proxy-settings` | 出站 proxySettings |  |  | 已移除 | 未实现 | 未测 | 约束：配置时报错，改用 sockopt.dialerProxy |
| `send-through` | 发送数据的本地 IP，默认 0.0.0.0 |  |  | 有 | 部分 | 通过 | 取值：`IP`、`IPv6 CIDR`、`origin`、`srcip`<br>约束：CIDR 时随机选 IP，需系统允许 bind；ndp 网络不建议小于 /120<br>约束：origin 用本机被连接的 IP；对 UDP 无效<br>约束：srcip 用入站源 IP |
| `server` | 必须，服务器域名或 IP | 有 |  |  | 已实现 | 通过 | 取值：`IP`、`域名` |
| `settings` | 协议专属配置对象 |  |  | 有 | 已实现 | 通过 |  |
| `stream-settings` | 出站传输配置 |  |  | 有 | 部分 | 通过 |  |
| `tag` | 出站的标签。 |  | 有 | 有 | 已实现 | 通过 | 约束：非空时必须在所有 tag 中唯一 |
| `target-strategy` | 被代理目标域名的本地解析策略，默认 AsIs |  |  | 有 | 部分 | 通过 | 取值：`AsIs`、`ForceIP`、`ForceIPv4`、`ForceIPv4v6`、`ForceIPv6`、`ForceIPv6v4`、`UseIP`、`UseIPv4`、`UseIPv4v6`、`UseIPv6`、`UseIPv6v4`<br>约束：Freedom 配置时自动迁移到 sockopt.domainStrategy（source:infra/conf/xray.go）<br>约束：适用于 Freedom 以外的出站 |
| `type` | 必须，节点类型 | 有 | 有 |  | 部分 | 通过 | 取值：`anytls`、`block`、`bridge`、`direct`、`dns`、`easytier`、`gost-relay`、`http`、`hysteria`、`hysteria2`、`masque`、`mieru`、`naive`、`openvpn`、`reject`、`rematch`、`selector`、`shadowquic`、`shadowsocks`、`shadowtls`、`snell`、`socks`、`socks5`、`ss`…… |
| `udp` | 是否允许 UDP，默认 false | 有 |  |  | 部分 | 通过 | 取值：`false`、`true`<br>约束：TUIC 等基于 UDP 的协议及 direct、dns 默认开启 |

## direct

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `freedom` | 直连出站；别名 direct |  |  | 有 | 已实现 | 通过 | 取值：`freedom`<br>约束：存在默认安全策略 |
| `protocol` | 直连出站类型 | 有 | 有 |  | 已实现 | 通过 | 取值：`direct` |
| `combo` | direct 维度 | 有 | 有 | 有 | 部分 | 通过 | udp：`false`、`true`<br>ip-version：`dual`、`ipv4`、`ipv4-prefer`、`ipv6`、`ipv6-prefer`<br>binding：`interface-name`、`none`、`routing-mark`<br>domain_resolver：`off`、`on`<br>dial_fields：`bind_interface`、`inet4_bind_address`、`inet6_bind_address`、`netns`、`routing_mark`<br>约束：detour 不支持（source:protocol/direct/outbound.go）<br>约束：domain_resolver 对 direct 作用于请求域名<br>约束：override_address、override_port 已于 1.13.0 移除，配置后报错（source:option/direct.go）<br>stream：`sockopt`<br>domain_strategy：`AsIs`、`ForceIP`、`ForceIPv4`、`ForceIPv4v6`、`ForceIPv6`、`ForceIPv6v4`、`UseIP`、`UseIPv4`、`UseIPv4v6`、`UseIPv6`、`UseIPv6v4`<br>final_rule：`allow`、`block`、`none`<br>proxy_protocol：`0`、`1`、`2`<br>redirect：`:port`、`addr:0`、`addr:port`、`off`<br>约束：不支持 sockopt.addressPortStrategy（source:infra/conf/xray.go）<br>约束：只有 sockopt 可用<br>约束：配 dialerProxy 后不再是最终出站 |
| `allow` | 放行目标 |  |  | 有 | 未实现 | 未测 |  |
| `block` | 阻止目标 |  |  | 有 | 未实现 | 未测 |  |
| `block-delay` | 黑洞持续秒数，默认 30-90 |  |  | 有 | 未实现 | 未测 | 取值：`30`、`30-90`<br>约束：仅 action 为 block |
| `default-security-policy` | 未命中规则的默认策略：VLESS 反向代理流量全阻止；VLESS、VMess、Trojan、Shadowsocks、Hysteria、WireGuard 入站流量阻止私有及保留 IP；其他放行 |  |  | 有 | 未实现 | 未测 |  |
| `domain-strategy` | 旧域名策略 |  |  | 废弃 | 部分 | 通过 | 约束：自动迁移到 sockopt.domainStrategy |
| `final-rules` | 最终出站规则，按序匹配 |  |  | 有 | 未实现 | 未测 | 约束：UDP 逐包匹配<br>约束：拨号后再查实际远端 IP<br>约束：目标为域名时按 sockopt.domainStrategy 解析，任一 IP 被阻止则阻止整个请求<br>约束：配了 sockopt.dialerProxy 时不执行 |
| `fragment` | 旧分片字段 |  |  | 废弃 | 未实现 | 未测 | 取值：`interval`、`length`、`maxSplit`、`packets`<br>约束：改用 finalmask.tcp fragment |
| `ip` | 匹配目标 IP，写法同路由 ip |  |  | 有 | 未实现 | 未测 |  |
| `ips-blocked` | 旧封禁列表 |  |  | 已移除 | 未实现 | 未测 | 约束：只告警，改用 finalRules |
| `network` | 匹配网络 |  |  | 有 | 未实现 | 未测 | 取值：`["tcp","udp"]`、`tcp`、`tcp,udp`、`udp` |
| `noise` | 旧单对象噪声 |  |  | 已移除 | 未实现 | 未测 | 约束：配置时报错 |
| `noises` | 旧噪声字段 |  |  | 废弃 | 未实现 | 未测 | 取值：`applyTo: ip\|ipv4\|ipv6\|all`、`delay`、`packet`、`type: rand\|str\|hex\|base64`<br>约束：改用 finalmask.udp noise |
| `override-address` | 覆盖连接目标地址。 |  | 已移除 |  | 未实现 | 未测 | 约束：目标覆盖字段在 sing-box 1.11.0 中已废弃，并将在 sing-box 1.13.0 中被移除，参阅 迁移指南。 |
| `override-port` | 覆盖连接目标端口。 |  | 已移除 |  | 未实现 | 未测 | 约束：目标覆盖字段在 sing-box 1.11.0 中已废弃，并将在 sing-box 1.13.0 中被移除，参阅 迁移指南。 |
| `port` | 匹配目标端口，写法同路由 port |  |  | 有 | 未实现 | 未测 |  |
| `proxy-protocol` | 发 PROXY protocol 版本，默认 0 |  |  | 有 | 未实现 | 未测 | 取值：`0`、`1`、`2`<br>约束：后端不支持时连接断开 |
| `redirect` | 改写目标地址和端口 |  |  | 有 | 未实现 | 未测 | 取值：`127.0.0.1:80`、`:1234`、`xray.com:0`<br>约束：地址空时不改地址<br>约束：端口 0 时不改端口 |
| `target-strategy` | settings 内旧策略字段 |  |  | 废弃 | 部分 | 通过 |  |
| `user-level` | 用户等级，默认 0 |  |  | 有 | 未实现 | 未测 |  |

## dns

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `dns` | DNS 出站，接收路由送入的明文 DNS 查询 |  |  | 有 | 未实现 | 未测 | 取值：`dns`<br>约束：只支持 UDP 和 TCP 明文 DNS；DoH、DoT、DoQ 不适用 |
| `protocol` | DNS 出站，请求在内部 DNS 模块处理 | 有 | 已移除 |  | 未实现 | 未测 | 取值：`dns`<br>约束：1.11.0 废弃，1.13.0 移除；配置后启动报错（source:option/outbound.go）<br>约束：用 hijack-dns 规则动作替代 |
| `combo` | dns 出站维度 | 有 |  | 有 | 未实现 | 未测 | network：`tcp`、`udp`<br>约束：udp 默认开启<br>action：`direct`、`drop`、`hijack`、`return`<br>match：`domain`、`none`、`qType`<br>network：`tcp`、`udp`、`保持来源`<br>source：`tproxy`、`tun`、`tunnel`<br>约束：hijack 仅 A/AAAA<br>约束：rCode 仅 return 生效<br>约束：规则各条件为与关系 |
| `address` | rewriteAddress 旧名 |  |  | 有 | 不适用 | 未测 |  |
| `block-types` | 旧字段 |  |  | 废弃 | 不适用 | 未测 | 约束：不能与 rules 混用，改用 rules |
| `direct` | 放行到目标 DNS 服务器，按 rewrite 转发 |  |  | 有 | 未实现 | 未测 |  |
| `domain` | 匹配域名列表，写法同路由 domain |  |  | 有 | 未实现 | 未测 |  |
| `drop` | 丢弃请求，不返回响应 |  |  | 有 | 未实现 | 未测 |  |
| `hijack` | 导入内置 DNS 处理 |  |  | 有 | 未实现 | 未测 | 约束：目前仅 A 和 AAAA |
| `network` | rewriteNetwork 旧名 |  |  | 有 | 不适用 | 未测 |  |
| `non-ipquery` | 旧字段 |  |  | 废弃 | 不适用 | 未测 | 取值：`drop`、`reject`、`skip`<br>约束：不能与 rules 混用，改用 rules |
| `port` | rewritePort 旧名 |  |  | 有 | 不适用 | 未测 |  |
| `q-type` | 匹配 DNS 查询类型 |  |  | 有 | 未实现 | 未测 | 取值：`"11,13,15-17"`、`"28"`、`"5-10"`、`1` |
| `r-code` | return 使用的 RCODE，默认 0 |  |  | 有 | 未实现 | 未测 | 取值：`0-65535`<br>约束：仅 action 为 return 生效 |
| `return` | 返回指定 RCODE 的响应 |  |  | 有 | 未实现 | 未测 |  |
| `rewrite-address` | 改写 DNS 服务器地址 |  |  | 有 | 未实现 | 未测 |  |
| `rewrite-network` | 改写传输协议，默认保持来源 |  |  | 有 | 未实现 | 未测 | 取值：`tcp`、`udp` |
| `rewrite-port` | 改写 DNS 服务器端口 |  |  | 有 | 未实现 | 未测 |  |
| `rules` | 按序匹配的查询规则 |  |  | 有 | 未实现 | 未测 | 约束：未命中时：A/AAAA 进内置 DNS，其他类型返回空响应 RCODE 0 |
| `user-level` | 用户等级，默认 0 |  |  | 有 | 未实现 | 未测 |  |

## easytier

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | EasyTier 出站 | 有 |  |  | 已实现 | 通过 | 约束：overlay 仅 IPv4，ip-version 只影响底层 peer |
| `combo` | EasyTier 出站维度 | 有 |  |  | 部分 | 通过 | address：`dhcp`、`ipv4`<br>peer-scheme：`tcp`、`udp`<br>listener：`listeners`、`no-listener`<br>secure-mode：`off`、`on`<br>proxy：`kcp`、`none`、`quic`<br>p2p：`off`、`on`<br>udp：`false`、`true`<br>约束：no-listener 与 listeners 不能同时启用 |
| `accept-dns` | 接受网络下发 DNS | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `dhcp` | DHCP 取 overlay IPv4；ipv4 为空时默认开 | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true` |
| `disable-kcp-input` | 禁用 KCP 输入，默认 false | 有 |  |  | 部分 | 通过 | 取值：`false`、`true` |
| `disable-p2p` | 禁用 P2P，默认 false | 有 |  |  | 部分 | 通过 | 取值：`false`、`true` |
| `disable-quic-input` | 禁用 QUIC 输入，默认 false | 有 |  |  | 部分 | 通过 | 取值：`false`、`true` |
| `enable-encryption` | 节点间加密，默认 true | 有 |  |  | 部分 | 通过 | 取值：`false`、`true` |
| `enable-exit-node` | 作为 exit node，默认 false | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `enable-kcp-proxy` | TCP 经 KCP 转发，默认 false | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `enable-quic-proxy` | TCP 经 QUIC 转发，默认 false | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `encryption-algorithm` | 加密算法，默认 aes-gcm | 有 |  |  | 已实现 | 通过 | 取值：`aes-gcm` |
| `exit-nodes` | 要用的 exit node overlay IPv4 | 有 |  |  | 未实现 | 未测 | 取值：`IP 列表` |
| `hostname` | overlay 主机名 | 有 |  |  | 已实现 | 通过 | 取值：`字符串` |
| `instance-name` | 实例名，默认代理名 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `ipv4` | overlay IPv4 CIDR | 有 |  |  | 已实现 | 通过 | 取值：`CIDR` |
| `latency-first` | 延迟优先，默认 false | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `listeners` | 监听 URI 列表 | 有 |  |  | 未实现 | 未测 | 取值：`tcp://0.0.0.0:11010` |
| `local-private-key` | 本机 X25519 私钥 | 有 |  |  | 未实现 | 未测 | 取值：`base64` |
| `local-public-key` | 本机 X25519 公钥 | 有 |  |  | 未实现 | 未测 | 取值：`base64`<br>约束：必须与 local-private-key 一同配置 |
| `mapped-listeners` | 对外公告的映射监听地址 | 有 |  |  | 未实现 | 未测 | 取值：`URI 列表` |
| `mtu` | MTU，默认 1380 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `network-name` | 必须，网络名 | 有 |  |  | 已实现 | 通过 | 取值：`字符串` |
| `network-secret` | 网络密钥 | 有 |  |  | 已实现 | 通过 | 取值：`字符串` |
| `no-listener` | 禁用监听，默认 true | 有 |  |  | 部分 | 通过 | 取值：`false`、`true`<br>约束：false 且 listeners 为空时用 tcp://0.0.0.0:11010<br>约束：不能与 listeners 同时启用 |
| `peers` | 入口节点 URI；可加 peer-public-key 查询参数锁公钥 | 有 |  |  | 部分 | 通过 | 取值：`tcp://`、`udp://`<br>约束：listeners 为空时至少配一个<br>约束：默认不隐式连 public.easytier.top |
| `private-mode` | 隐私模式，默认 false | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `proxy-networks` | 经网络代理访问的子网 | 有 |  |  | 未实现 | 未测 | 取值：`CIDR 列表` |
| `secure-mode` | Noise 端到端加密 | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true`<br>约束：配置 local-private-key、local-public-key 或 peer-public-key 时自动开启 |
| `state-dir` | 状态目录，默认 easytier/<代理名称> | 有 |  |  | 未实现 | 未测 | 取值：`路径` |
| `tld-dns-zone` | MagicDNS TLD，默认 et.net. | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |

## gost-relay

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | GOST relay 出站（Wiki 无页面，官方示例有） | 有 |  |  | 已实现 | 通过 | 取值：`gost-relay`<br>约束：经 dialer-proxy 承载 ss、vmess、vless、trojan |
| `combo` | gost-relay 维度 | 有 |  |  | 部分 | 通过 | mode：`dynamic`、`forward`<br>tls：`off`、`on`<br>mux：`off`、`on`<br>udp：`false`、`true`<br>约束：mux 为 relay+mtls 时需 tls 同开 |
| `client-fingerprint` | uTLS 指纹 | 有 |  |  | 未实现 | 未测 | 取值：`360`、`android`、`chrome`、`edge`、`firefox`、`ios`、`qq`、`random`、`safari` |
| `forward` | 转发模式：服务端决定目标 | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true` |
| `mux` | relay+mtls（tls 同开） | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true` |
| `password` | 密码 | 有 |  |  | 已实现 | 通过 | 取值：`字符串` |
| `sni` | SNI | 有 |  |  | 已实现 | 通过 | 取值：`域名` |
| `tls` | TLS | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true` |
| `udp` | UDP | 有 |  |  | 部分 | 通过 | 取值：`false`、`true` |
| `username` | 用户名 | 有 |  |  | 已实现 | 通过 | 取值：`字符串` |

## http

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `http` | HTTP 代理出站，只能代理 TCP |  |  | 有 | 已实现 | 通过 | 取值：`http` |
| `protocol` | HTTP 代理出站 | 有 | 有 |  | 已实现 | 通过 | 取值：`http` |
| `combo` | HTTP 出站维度 | 有 | 有 | 有 | 部分 | 通过 | auth：`none`、`password`<br>tls：`mtls`、`off`、`on`<br>verify：`default`、`fingerprint`、`name-cert-verify`、`skip-cert-verify`<br>ip-version：`dual`、`ipv4`、`ipv4-prefer`、`ipv6`、`ipv6-prefer`<br>约束：无 UDP 字段<br>version：`1`、`2`、`3`<br>security：`none`、`tls`<br>auth：`basic`、`none`<br>disable_version_fallback：`off`、`on`<br>tuning：`http2-fields`、`quic-fields`<br>约束：path 和 Host 只用于 version 1<br>约束：version 3 用 QUIC 字段替代 HTTP2 字段<br>约束：version 自 1.15.0 起<br>约束：默认 2；设了 path 或 Host 时默认 1<br>transport：`grpc`、`httpupgrade`、`hysteria`、`mkcp`、`raw`、`websocket`、`xhttp`<br>security：`none`、`reality`、`tls`<br>约束：masque 传输不适用<br>约束：security 和 tlsSettings 生效<br>约束：只代理 TCP |
| `address` | 代理服务器地址，必填 |  |  | 有 | 已实现 | 通过 |  |
| `disable-version-fallback` | 禁用自动回退到更低的 HTTP 版本。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.15.0 起 |
| `email` | 邮箱 |  |  | 有 | 未实现 | 未测 |  |
| `fingerprint` | 协议独立证书指纹，忽略 experimental.fingerprints | 有 |  |  | 未实现 | 未测 | 取值：`sha256` |
| `headers` | 附加请求头 | 有 | 有 | 有 | 未实现 | 未测 | 取值：`映射` |
| `level` | 用户等级，默认 0 |  |  | 有 | 未实现 | 未测 |  |
| `pass` | 密码，需认证时必填 |  |  | 有 | 已实现 | 通过 |  |
| `password` | 密码 | 有 | 有 |  | 已实现 | 通过 | 取值：`字符串` |
| `path` | HTTP 请求路径。 |  | 有 |  | 未实现 | 未测 |  |
| `port` | 代理服务器端口，必填 |  |  | 有 | 已实现 | 通过 |  |
| `server` | 服务器地址。 |  | 有 |  | 已实现 | 通过 | 约束：必填 |
| `server-port` | 服务器端口。 |  | 有 |  | 已实现 | 通过 | 约束：必填 |
| `servers` | 旧多服务器写法 |  |  | 有 | 不适用 | 未测 | 约束：只能一个成员，users 至多一个 |
| `tls` | https | 有 | 有 |  | 已实现 | 通过 | 取值：`false`、`true` |
| `user` | 用户名，需认证时必填 |  |  | 有 | 已实现 | 通过 |  |
| `username` | 用户名 | 有 | 有 |  | 已实现 | 通过 | 取值：`字符串` |
| `version` | HTTP 版本。 |  | 有 |  | 部分 | 通过 | 取值：`1`、`2`、`3`<br>约束：`path` 和 `Host` 头仅在 `1` 时可用。<br>约束：自 sing-box 1.15.0 起<br>约束：默认使用 `2`；设置了 `path` 或 `Host` 头时默认使用 `1`。 |

## hysteria

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `hysteria` | Hysteria2 客户端 |  |  | 有 | 已实现 | 通过 | 取值：`hysteria`<br>约束：协议本身无认证<br>约束：搭配非 hysteria 传输无法代理 UDP，也不推荐 |
| `protocol` | Hysteria v1 出站 | 有 | 有 |  | 部分 | 通过 | 取值：`faketcp`、`hysteria`、`udp`、`wechat-video` |
| `combo` | Hysteria 出站维度 | 有 | 有 | 有 | 部分 | 通过 | protocol：`faketcp`、`udp`、`wechat-video`<br>port：`port`、`ports`<br>obfs：`off`、`on`<br>verify：`default`、`fingerprint`、`name-cert-verify`、`skip-cert-verify`<br>fast-open：`false`、`true`<br>port：`server_port`、`server_ports`<br>bandwidth_format：`up/down`、`up_mbps/down_mbps`<br>auth：`auth`、`auth_str`<br>network：`tcp`、`tcp+udp`、`udp`<br>约束：hop_interval 默认 30s<br>约束：network 留空时 TCP、UDP 都启用<br>约束：server_ports 与 server_port 冲突<br>约束：tls 必填<br>约束：up、down 必填<br>transport：`hysteria`<br>security：`tls`<br>congestion：`bbr`、`brutal`、`force-brutal`、`reno`<br>约束：security 必须 tls<br>约束：不支持 none 和 reality<br>约束：速查表：只支持 hysteria 传输 |
| `address` | 服务器地址，必填 |  |  | 有 | 已实现 | 通过 |  |
| `alpn` | ALPN | 有 |  |  | 已实现 | 通过 | 取值：`h3` |
| `auth` | hysteria 出站字段 auth（文档页未写，配置结构存在） | 有 | 有 |  | 已实现 | 通过 |  |
| `auth-str` | 认证字符串 | 有 | 有 |  | 已实现 | 通过 | 取值：`字符串` |
| `disable-mtu-discovery` | 禁用 MTU 发现（文档示例写作 disable_mtu_discovery） | 有 | 废弃 |  | 未实现 | 未测 | 取值：`false`、`true` |
| `down` | 下行，不写单位默认 Mbps | 有 | 有 |  | 部分 | 通过 | 取值：`200 Mbps`<br>约束：单位区分大小写：bps Bps Kbps KBps Mbps MBps Gbps GBps Tbps TBps<br>约束：必填 |
| `down-mbps` | 以 Mbps 为单位的 `up, down`。 |  | 有 |  | 部分 | 通过 | 约束：必填 |
| `down-speed` | hysteria 出站字段 down-speed（文档页未写，配置结构存在） | 有 |  |  | 部分 | 通过 |  |
| `fast-open` | Fast Open，默认 false | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `hop-interval` | hysteria 出站字段 hop-interval（文档页未写，配置结构存在） | 有 | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.12.0 起<br>约束：默认使用 `30s`。 |
| `network` | 启用的网络协议。 |  | 有 |  | 部分 | 通过 | 取值：`tcp`、`udp`<br>约束：默认所有。 |
| `obfs` | 混淆字符串 | 有 | 有 |  | 已实现 | 通过 | 取值：`字符串` |
| `obfs-protocol` | hysteria 出站字段 obfs-protocol（文档页未写，配置结构存在） | 有 |  |  | 部分 | 通过 |  |
| `port` | 服务器端口，必填 |  |  | 有 | 已实现 | 通过 |  |
| `ports` | 端口跳跃范围 | 有 |  |  | 未实现 | 未测 | 取值：`1000,2000-3000,4000`<br>约束：port 不可省略 |
| `recv-window` | 连接窗口 | 有 | 废弃 |  | 未实现 | 未测 | 取值：`整数` |
| `recv-window-conn` | 流窗口 | 有 | 废弃 |  | 未实现 | 未测 | 取值：`整数` |
| `server` | 服务器地址。 |  | 有 |  | 已实现 | 通过 | 约束：必填 |
| `server-port` | 服务器端口。 |  | 有 |  | 已实现 | 通过 | 约束：必填 |
| `server-ports` | 服务器端口范围列表。 |  | 有 |  | 未实现 | 未测 | 约束：与 `server_port` 冲突。<br>约束：自 sing-box 1.12.0 起 |
| `tls` | TLS 配置, 参阅 TLS。 |  | 有 |  | 部分 | 通过 | 约束：必填 |
| `up` | 上行，不写单位默认 Mbps | 有 | 有 |  | 部分 | 通过 | 取值：`30 Mbps`<br>约束：单位区分大小写：bps Bps Kbps KBps Mbps MBps Gbps GBps Tbps TBps<br>约束：必填 |
| `up-mbps` | 以 Mbps 为单位的 `up, down`。 |  | 有 |  | 部分 | 通过 | 约束：必填 |
| `up-speed` | hysteria 出站字段 up-speed（文档页未写，配置结构存在） | 有 |  |  | 部分 | 通过 |  |
| `version` | Hysteria 版本 |  |  | 有 | 已实现 | 通过 | 取值：`2`<br>约束：必须为 2 |

## hysteria2

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | Hysteria2 出站 | 有 | 有 |  | 已实现 | 通过 | 取值：`hysteria2` |
| `combo` | Hysteria2 出站维度 | 有 | 有 |  | 部分 | 通过 | obfs：`gecko`、`none`、`salamander`<br>port：`port`、`ports`<br>hop-interval：`固定`、`范围`<br>bbr-profile：`aggressive`、`conservative`、`standard`<br>bandwidth：`bbr`、`brutal up/down`<br>realm：`off`、`on`<br>verify：`default`、`fingerprint`、`name-cert-verify`、`skip-cert-verify`<br>ech：`off`、`on`<br>约束：obfs-min-packet-size、obfs-max-packet-size 仅 gecko<br>约束：ports 配置后忽略 port<br>connect：`realm`、`server_port`、`server_ports`<br>congestion：`bbr`、`brutal(up/down)`<br>bbr_profile：`aggressive`、`conservative`、`standard`<br>hop_interval_max：`off`、`on`<br>disable_chrome_parrot：`off`、`on`<br>network：`tcp`、`tcp+udp`、`udp`<br>realm_ip_version：`4`、`6`、`both`<br>port_mapping：`off`、`on`<br>约束：Chrome 伪装时服务端不能用 Ed25519 证书，且固定 idle_timeout 30 秒、覆盖 max_concurrent_streams 和 initial_packet_size<br>约束：network 留空时 TCP、UDP 都启用<br>约束：obfs.min_packet_size、max_packet_size 仅 gecko<br>约束：realm.port_mapping 与 ip_version 6 冲突<br>约束：server_ports 与 server_port 冲突<br>约束：server、server_port、server_ports 与 realm 冲突<br>约束：tls 必填<br>约束：up、down 留空时用 BBR |
| `bbr-profile` | BBR 档位，默认 standard | 有 | 有 |  | 未实现 | 未测 | 取值：`aggressive`、`conservative`、`standard`<br>约束：自 sing-box 1.14.0 起<br>约束：默认使用 `standard`。 |
| `brutal-debug` | 启用 Hysteria Brutal CC 的调试信息日志记录。 |  | 有 |  | 未实现 | 未测 |  |
| `cwnd` | hysteria2 出站字段 cwnd（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `disable-chrome-parrot` | 禁用 Chrome QUIC 指纹模仿。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `down` | brutal 下行，默认 Mbps | 有 |  |  | 未实现 | 未测 | 取值：`200 Mbps` |
| `down-mbps` | 最大带宽。 |  | 有 |  | 未实现 | 未测 |  |
| `handshake-timeout` | 握手超时秒，默认 0 仅用外层 | 有 |  |  | 部分 | 通过 | 取值：`整数` |
| `hop-interval` | 跳跃间隔秒，默认 30；可写 15-30 | 有 | 有 |  | 未实现 | 未测 | 取值：`15-30`、`整数`<br>约束：仅一个范围，不允许逗号<br>约束：自 sing-box 1.11.0 起<br>约束：默认使用 `30s`。 |
| `hop-interval-max` | 最大端口跳跃间隔，用于随机化。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `initial-connection-receive-window` | quic-go 初始连接窗口 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `initial-stream-receive-window` | quic-go 初始流窗口 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `max-connection-receive-window` | quic-go 最大连接窗口 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `max-stream-receive-window` | quic-go 最大流窗口 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `network` | 启用的网络协议。 |  | 有 |  | 部分 | 通过 | 取值：`tcp`、`udp`<br>约束：默认所有。 |
| `obfs` | QUIC 混淆，为空禁用 | 有 | 有 |  | 部分 | 通过 | 取值：`gecko`、`salamander` |
| `obfs-max-packet-size` | 最大线上包字节 | 有 | 有 |  | 未实现 | 未测 | 取值：`整数`<br>约束：仅 gecko<br>约束：仅限 Gecko。<br>约束：自 sing-box 1.14.0 起<br>约束：默认使用 `1200`。 |
| `obfs-min-packet-size` | 最小线上包字节 | 有 | 有 |  | 未实现 | 未测 | 取值：`整数`<br>约束：仅 gecko<br>约束：仅限 Gecko。<br>约束：自 sing-box 1.14.0 起<br>约束：默认使用 `512`。 |
| `obfs-password` | 混淆密码 | 有 | 有 |  | 已实现 | 通过 | 取值：`字符串` |
| `obfs-type` | QUIC 流量混淆器类型，可选 `salamander` `gecko`。 |  | 有 |  | 部分 | 通过 | 取值：`gecko`、`salamander` |
| `password` | 认证密码 | 有 | 有 |  | 已实现 | 通过 | 取值：`字符串` |
| `ports` | 端口跳跃，配置后忽略 port | 有 |  |  | 未实现 | 未测 | 取值：`443-8443` |
| `realm` | 通过 Hysteria Realm 会合服务连接 Hysteria2 服务器。 |  | 有 |  | 未实现 | 未测 | 约束：TLS SNI 默认使用 `server_url` 中的主机名。<br>约束：与 `server`、`server_port` 和 `server_ports` 冲突。<br>约束：自 sing-box 1.14.0 起 |
| `realm-http-client` | 与 realm 通信使用的 HTTP 客户端。 |  | 有 |  | 未实现 | 未测 |  |
| `realm-ip-version` | 将 realm 连接（STUN、打洞与最终的 QUIC 路径）限制为单一 IP 版本。 |  | 有 |  | 未实现 | 未测 | 取值：`4`、`6`<br>约束：默认使用两者。 |
| `realm-opts-alpn` | server-url 的 TLS 配置：ALPN | 有 |  |  | 未实现 | 未测 |  |
| `realm-opts-certificate` | server-url 的 TLS 配置：客户端证书 | 有 |  |  | 未实现 | 未测 |  |
| `realm-opts-enable` | 启用 realm，必须手动开启 | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `realm-opts-fingerprint` | server-url 的 TLS 配置：证书指纹 | 有 |  |  | 未实现 | 未测 |  |
| `realm-opts-name-cert-verify` | server-url 的 TLS 配置：校验名 | 有 |  |  | 未实现 | 未测 |  |
| `realm-opts-private-key` | server-url 的 TLS 配置：客户端私钥 | 有 |  |  | 未实现 | 未测 |  |
| `realm-opts-realm-id` | realm ID | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `realm-opts-server-url` | realm 服务器 URL | 有 |  |  | 未实现 | 未测 | 取值：`URL` |
| `realm-opts-skip-cert-verify` | server-url 的 TLS 配置：跳过验证 | 有 |  |  | 未实现 | 未测 |  |
| `realm-opts-sni` | server-url 的 TLS 配置：SNI | 有 |  |  | 未实现 | 未测 |  |
| `realm-opts-stun-servers` | STUN 服务器 | 有 |  |  | 未实现 | 未测 | 取值：`host:port 列表` |
| `realm-opts-token` | realm 令牌 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `realm-port-mapping` | 通过 UPnP 或 NAT-PMP 在本地网关上维护 UDP 端口映射。 |  | 有 |  | 未实现 | 未测 | 约束：需要 IPv4：与 `"ip_version": 6` 冲突。 |
| `realm-port-mapping-enabled` | 启用端口映射。 |  | 有 |  | 未实现 | 未测 |  |
| `realm-port-mapping-lifetime` | 映射的租约时长。 |  | 有 |  | 未实现 | 未测 | 约束：默认使用 `10m`。 |
| `realm-port-mapping-timeout` | 网关发现与映射操作的超时。 |  | 有 |  | 未实现 | 未测 | 约束：默认使用 `10s`。 |
| `realm-realm-id` | 目标 Hysteria2 服务器注册时使用的相同槽位标识符。 |  | 有 |  | 未实现 | 未测 | 约束：必填 |
| `realm-server-url` | Realm 会合服务 URL。 |  | 有 |  | 未实现 | 未测 | 约束：必填 |
| `realm-stun-servers` | 用于发现本客户端公网地址的 STUN 服务器列表（`host` 或 `host:port`）。 |  | 有 |  | 未实现 | 未测 | 约束：必填 |
| `realm-token` | Realm 的 Bearer 令牌，需与 realm 上配置的 `users[].token` 之一匹配。 |  | 有 |  | 未实现 | 未测 |  |
| `server` | 服务器地址。 |  | 有 |  | 已实现 | 通过 | 约束：与 `realm` 冲突。<br>约束：必填 |
| `server-port` | 服务器端口。 |  | 有 |  | 已实现 | 通过 | 约束：与 `realm` 冲突。<br>约束：如果设置了 `server_ports`，则忽略此项。<br>约束：必填 |
| `server-ports` | 服务器端口范围列表。 |  | 有 |  | 未实现 | 未测 | 约束：与 `server_port` 和 `realm` 冲突。<br>约束：自 sing-box 1.11.0 起 |
| `tls` | TLS 配置, 参阅 TLS。 |  | 有 |  | 部分 | 通过 | 约束：必填 |
| `udp-mtu` | hysteria2 出站字段 udp-mtu（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `up` | brutal 上行，默认 Mbps | 有 |  |  | 未实现 | 未测 | 取值：`30 Mbps` |
| `up-mbps` | 最大带宽。 |  | 有 |  | 未实现 | 未测 |  |

## list

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocols` | 出站协议列表页 |  |  | 有 | 不适用 | 未测 | 取值：`blackhole`、`dns`、`freedom`、`http`、`hysteria`、`loopback`、`masque`、`shadowsocks`、`socks`、`trojan`、`vless`、`vmess`、`wireguard` |

## loopback

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `loopback` | 环回出站，流量重新进路由 |  |  | 有 | 未实现 | 未测 | 取值：`loopback`<br>约束：避免规则再选回原出站形成循环 |
| `combo` | Loopback 用途 |  |  | 有 | 未实现 | 未测 | usage：`dialerProxy 用 balancer`、`fallbackTag 用 balancer`、`二次分流`<br>sniffing：`off`、`on` |
| `inbound-tag` | 重新进入路由时的入站标识 |  |  | 有 | 未实现 | 未测 |  |
| `sniffing` | 环回流量嗅探配置，默认不开 |  |  | 有 | 未实现 | 未测 |  |

## masque

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `masque` | MASQUE CONNECT-IP 客户端，可连 MASQUE 入站和 Cloudflare WARP |  |  | 有 | 已实现 | 通过 | 取值：`masque`<br>约束：不支持 Mux<br>约束：只能配 masque 传输且必须 tls<br>约束：同出站共用一条隧道，首次连接时建立，断开后下次重建 |
| `protocol` | MASQUE 出站，可由 usque 生成配置 | 有 | 有 |  | 已实现 | 通过 | 取值：`masque-client`<br>约束：自 sing-box 1.15.0 起<br>约束：配置在顶层 endpoints，同时具备入站和出站行为 |
| `combo` | MASQUE 出站维度 | 有 | 有 | 有 | 部分 | 通过 | network：`h2`、`h3-l4proxy`、`quic`<br>udp：`false`、`true`<br>ip-stack.mode：`auto`、`gvisor`、`mips`<br>remote-dns-resolve：`false`、`true`<br>congestion-controller：``、`bbr`<br>约束：h2 示例无 congestion-controller 字段<br>约束：h3-l4proxy 目前不支持 UDP<br>version：`1`、`2`、`3`<br>security：`none`、`tls`<br>auth：`basic`、`none`<br>disable_version_fallback：`off`、`on`<br>interface：`internal`、`system`<br>on_demand：`off`、`on`<br>advertise_routes：`off`、`on`<br>约束：HTTP/3 必须配 TLS<br>约束：path 模板可含 target、ipproto<br>约束：server、server_port 必填<br>约束：version 2 用 HTTP2 字段，version 3 用 QUIC 字段<br>约束：默认 version 3<br>transport：`masque`<br>security：`tls`<br>http_version：`h2`、`h3`<br>auth：`basic`、`headers`、`warp`<br>finalmask：`quicParams(h3)`、`tcp(h2)`、`udp(h3)`<br>约束：WARP 边缘不支持 ECH<br>约束：alpn 含 h2 且不含 h3 时 HTTP/2，否则 HTTP/3<br>约束：masque 传输只能被 masque 协议使用（source:infra/conf/xray.go）<br>约束：warp 不能和 user/pass 同用<br>约束：不支持 REALITY |
| `address` | 服务器地址，必填 |  |  | 有 | 已实现 | 通过 |  |
| `advertise-routes` | 向服务器声明的 IP 前缀列表。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.15.0 起 |
| `bbr-profile` | BBR 档位 | 有 |  |  | 未实现 | 未测 | 取值：`aggressive`、`conservative`、`standard` |
| `congestion-controller` | 拥塞控制，默认不启用 | 有 |  |  | 未实现 | 未测 | 取值：`bbr` |
| `cwnd` | masque 出站字段 cwnd（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `disable-version-fallback` | 禁用自动回退到更低的 HTTP 版本。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.15.0 起 |
| `dns` | 远程 DNS，remote-dns-resolve 启用时生效 | 有 |  |  | 未实现 | 未测 | 取值：`上游列表` |
| `handshake-timeout` | 握手超时秒，默认 0 | 有 |  |  | 部分 | 通过 | 取值：`整数` |
| `headers` | HTTP 请求的额外标头。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.15.0 起 |
| `ip` | 本地 IPv4 CIDR | 有 |  |  | 未实现 | 未测 | 取值：`CIDR` |
| `ip-stack-congestion-controller` | TCP 拥塞控制，默认 cubic | 有 |  |  | 未实现 | 未测 | 取值：`bbr`、`bbr3`、`cubic`、`reno`<br>约束：gVisor 下不生效 |
| `ip-stack-mode` | IP 协议栈，默认 auto | 有 |  |  | 未实现 | 未测 | 取值：`auto`、`gvisor`、`mips`<br>约束：auto 用 MIPS<br>约束：gvisor 需 -tags with_gvisor |
| `ipv6` | 本地 IPv6 CIDR | 有 |  |  | 未实现 | 未测 | 取值：`CIDR` |
| `mtu` | TUN MTU，默认 1280 | 有 | 有 |  | 未实现 | 未测 | 取值：`整数`<br>约束：自 sing-box 1.15.0 起<br>约束：默认使用 `1280`。 |
| `name` | 系统接口的自定义接口名称。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.15.0 起<br>约束：默认使用自动生成的 `masque` 接口名称。 |
| `network` | 默认 quic | 有 |  |  | 部分 | 通过 | 取值：`h2`、`h3-l4proxy`、`quic` |
| `on-demand` | 允许该 endpoint 在需要时断开连接。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.15.0 起 |
| `password` | Basic 认证密码。 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.15.0 起 |
| `path` | IP 代理资源的 URI 模板路径，可以包含 `target` 和 `ipproto` 变量。 |  | 有 |  | 部分 | 通过 | 约束：自 sing-box 1.15.0 起<br>约束：默认使用 `/.well-known/masque/ip/{target}/{ipproto}/`。 |
| `port` | 服务器端口，必填 |  |  | 有 | 已实现 | 通过 |  |
| `private-key` | 必须，base64 ECDSA 私钥 | 有 |  |  | 部分 | 通过 | 取值：`base64` |
| `public-key` | 必须，base64 ECDSA 服务端公钥 | 有 |  |  | 未实现 | 未测 | 取值：`base64`<br>约束：去掉 PEM 头尾与换行 |
| `remote-dns` | 隧道内解析域名的 DNS，默认 1.1.1.1、1.0.0.1、2606:4700:4700::1111、2606:4700:4700::1001 |  |  | 有 | 未实现 | 未测 | 约束：优先同地址族<br>约束：必须是 IP<br>约束：本地解析用 targetStrategy |
| `remote-dns-resolve` | 经隧道解析 DNS，默认 false | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `server` | 服务器地址。 |  | 有 |  | 已实现 | 通过 | 约束：必填<br>约束：自 sing-box 1.15.0 起 |
| `server-port` | 服务器端口。 |  | 有 |  | 已实现 | 通过 | 约束：必填<br>约束：自 sing-box 1.15.0 起 |
| `sni` | SNI | 有 |  |  | 已实现 | 通过 | 取值：`域名` |
| `system` | 使用系统接口。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.15.0 起<br>约束：需要特权且不能与已有系统接口冲突。 |
| `tls` | TLS 配置，参阅 TLS。 |  | 有 |  | 部分 | 通过 | 约束：HTTP/3 需要 TLS。<br>约束：自 sing-box 1.15.0 起 |
| `uri` | masque 出站字段 uri（文档页未写，配置结构存在） | 有 |  |  | 已实现 | 通过 |  |
| `username` | Basic 认证用户名。 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.15.0 起 |
| `version` | HTTP 版本。 |  | 有 |  | 部分 | 通过 | 取值：`1`、`2`、`3`<br>约束：自 sing-box 1.15.0 起<br>约束：默认使用 `3`。 |

## mieru

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | Mieru 出站 | 有 |  |  | 已实现 | 通过 |  |
| `combo` | Mieru 出站维度 | 有 |  |  | 部分 | 通过 | transport：`TCP`、`UDP`<br>port：`port`、`port-range`<br>multiplexing：`MULTIPLEXING_HIGH`、`MULTIPLEXING_LOW`、`MULTIPLEXING_MIDDLE`、`MULTIPLEXING_OFF`<br>handshake-mode：`HANDSHAKE_NO_WAIT`、`HANDSHAKE_STANDARD` |
| `handshake-mode` | 握手模式 | 有 |  |  | 已实现 | 通过 | 取值：`HANDSHAKE_NO_WAIT`、`HANDSHAKE_STANDARD` |
| `multiplexing` | 多路复用，默认 LOW | 有 |  |  | 部分 | 通过 | 取值：`MULTIPLEXING_HIGH`、`MULTIPLEXING_LOW`、`MULTIPLEXING_MIDDLE`、`MULTIPLEXING_OFF` |
| `password` | 密码 | 有 |  |  | 已实现 | 通过 | 取值：`字符串` |
| `port-range` | 端口范围 | 有 |  |  | 未实现 | 未测 | 取值：`2090-2099`<br>约束：不可与 port 同写 |
| `traffic-pattern` | base64 微调网络行为 | 有 |  |  | 部分 | 通过 | 取值：`base64` |
| `transport` | 协议 | 有 |  |  | 部分 | 通过 | 取值：`TCP`、`UDP` |
| `username` | 用户名 | 有 |  |  | 已实现 | 通过 | 取值：`字符串` |

## naive

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | NaiveProxy 出站 |  | 有 |  | 已实现 | 通过 | 取值：`naive`<br>约束：仅 Apple、Android、Windows 和部分 Linux 构建可用<br>约束：自 sing-box 1.13.0 起<br>约束：需要 with_naive_outbound 构建标签 |
| `combo` | NaiveProxy 出站的载体、拥塞控制和 UDP 组合 |  | 有 |  | 部分 | 通过 | carrier：`http2`、`quic`<br>quic_congestion_control：`bbr`、`bbr2`、`cubic`、`reno`<br>udp_over_tcp：`off`、`v1`、`v2`<br>tls_option：`certificate`、`certificate_path`、`ech`、`server_name`<br>约束：UDP 只在开 udp_over_tcp 时可用（source:protocol/naive/outbound.go）<br>约束：quic_session_receive_window 只在 quic 开启时生效<br>约束：stream_receive_window 在 quic 下是初始 QUIC 流窗口（默认 6 MB），否则是 HTTP/2 会话窗口<br>约束：tls 必填，只支持 server_name、certificate、certificate_path、ech |
| `extra-headers` | HTTP 请求中发送的额外头部。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.13.0 起 |
| `insecure-concurrency` | 并发隧道连接数。 |  | 有 |  | 部分 | 通过 | 约束：自 sing-box 1.13.0 起 |
| `password` | 认证密码。 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.13.0 起 |
| `quic` | 使用 QUIC 代替 HTTP/2。 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.13.0 起 |
| `quic-congestion-control` | QUIC 拥塞控制算法。 |  | 有 |  | 部分 | 通过 | 取值：`bbr`、`bbr2`、`cubic`、`reno`<br>约束：自 sing-box 1.13.0 起<br>约束：默认使用 `cubic`（NaiveProxy 基于的 Chromium 的默认值）。 |
| `quic-session-receive-window` | QUIC 初始会话接收窗口。 |  | 有 |  | 未实现 | 未测 | 约束：仅在 `quic` 启用时使用。<br>约束：自 sing-box 1.13.0 起<br>约束：默认使用 `15 MB`。 |
| `server` | 服务器地址。 |  | 有 |  | 已实现 | 通过 | 约束：必填<br>约束：自 sing-box 1.13.0 起 |
| `server-port` | 服务器端口。 |  | 有 |  | 已实现 | 通过 | 约束：必填<br>约束：自 sing-box 1.13.0 起 |
| `stream-receive-window` | 流量控制窗口。 |  | 有 |  | 未实现 | 未测 | 约束：否则，它设置 HTTP/2 会话接收窗口，流接收窗口被设置为它的一半，在 iOS 上默认使用 `4 MB`，在其他平台上默认使用 `128 MB`。<br>约束：当 `quic` 启用时，它设置 QUIC 初始流接收窗口，默认使用 `6 MB`。<br>约束：自 sing-box 1.13.0 起 |
| `tls` | TLS 配置, 参阅 TLS。 |  | 有 |  | 部分 | 通过 | 约束：只有 `server_name`、`certificate`、`certificate_path` 和 `ech` 是被支持的。<br>约束：必填<br>约束：自 sing-box 1.13.0 起 |
| `udp-over-tcp` | UDP over TCP 配置。 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.13.0 起 |
| `username` | 认证用户名。 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.13.0 起 |

## openconnect

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | OpenConnect 客户端端点 |  | 有 |  | 已实现 | 通过 | 取值：`openconnect`<br>约束：自 sing-box 1.14.0 起<br>约束：配置在顶层 endpoints，同时具备入站和出站行为 |
| `combo` | OpenConnect 端点的 flavor、认证、数据通道和合规检查组合 |  | 有 |  | 部分 | 通过 | flavor：`anyconnect`、`f5`、`fortinet`、`gp`、`nc`、`pulse`<br>auth：`auth_group`、`cookie`、`form_entries`、`interactive`、`token`、`username/password`<br>token_mode：`hotp`、`oidc`、`stoken`、`totp`<br>data_channel：`tls+dtls-or-esp`、`tls-only(no_udp)`<br>compression：`all`、`disabled`、`stateless`<br>host_check：`csd`、`fortinet_host_check`、`hip`、`tncc`<br>trust：`certificate_authority`、`insecure`、`peer_fingerprint`、`system`<br>client_cert：`client`、`client+mca`、`none`<br>interface：`internal`、`system`<br>约束：MCA 证书和私钥必须同时设置<br>约束：compression_disabled 与 compression_mode all 冲突<br>约束：mobile 三个字段配置时都必填<br>约束：server 必填<br>约束：tcp_keep_alive_enabled 与 disable_tcp_keep_alive 冲突<br>约束：tncc.certificates 需要 machine_identification_enabled<br>约束：tncc.wrapper_path 与 device_id、user_agent、machine_identification_enabled、certificates 冲突<br>约束：token.secret 与 token.secret_path 二选一<br>约束：客户端证书和私钥必须同时设置<br>约束：构建条件见 source:include/openconnect.go |
| `allow-insecure-crypto` | 启用旧版 VPN 服务器所需的弱 TLS 和 DTLS 密码套件及 TLS 1.0 兼容性。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：默认禁用；未启用时会拒绝低于 TLS 1.2 的版本。 |
| `auth-group` | 认证组，用于在所选 flavor 支持时预选匹配的组、realm、domain 或 gateway 选项。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `base-mtu` | 扣除外层 IP、传输和协议开销后，用于计算 AnyConnect、GlobalProtect、F5 和 Fortinet 隧道 MTU 的基础路径 MTU。 |  | 有 |  | 部分 | 通过 | 约束：自 sing-box 1.14.0 起<br>约束：默认使用 `1406`。 |
| `compression-disabled` | 禁用 AnyConnect 压缩协商。 |  | 有 |  | 部分 | 通过 | 约束：与设置为 `all` 的 `compression_mode` 冲突。<br>约束：自 sing-box 1.14.0 起<br>约束：默认情况下，当服务器支持时，CSTP 和 DTLS 会协商无状态 `oc-lz4` 和 `lzs` 压缩。 |
| `compression-mode` | AnyConnect 压缩模式，可选值为： |  | 有 |  | 未实现 | 未测 | 取值：`all`、`stateless`<br>约束：自 sing-box 1.14.0 起<br>约束：默认使用 `stateless`。 |
| `cookie` | 用于跳过凭据提示并直接连接的现有认证会话。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `csd` | AnyConnect CSD/host scan 合规性选项。 |  | 有 |  | 未实现 | 未测 | 约束：服务器请求 CSD 时，默认使用内置 CSD 处理。<br>约束：自 sing-box 1.14.0 起 |
| `csd-wrapper-path` | 外部 AnyConnect CSD wrapper 可执行文件的路径。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `dpd-interval` | 覆盖 Dead Peer Detection 间隔。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：默认使用服务器提供或 flavor 特定的间隔。 |
| `dtls-local-port` | 直连 DTLS 或 ESP 辅助数据通道使用的本地 UDP 端口。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：默认自动选择临时端口。 |
| `external-auth-disabled` | 禁用 AnyConnect、GlobalProtect 和 Fortinet 的 SSO、SAML 等外部浏览器认证。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `flavor` | OpenConnect 协议 flavor，可选值为 `anyconnect`、`gp`、`fortinet`、`f5`、`pulse` 或 `nc`。 |  | 有 |  | 部分 | 通过 | 取值：`anyconnect`、`f5`、`fortinet`、`gp`、`nc`、`pulse`<br>约束：自 sing-box 1.14.0 起<br>约束：默认使用 `anyconnect`。 |
| `form-entries` | 认证表单字段覆盖。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `form-entries-form-id` | `form_entries.submission_key` 为空时，与 `form_entries.name` 一起使用的认证表单标识符。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `form-entries-name` | 认证表单字段名，配合 form_id 使用 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `form-entries-promote` | 交互询问匹配的认证字段，而不是自动提供值。 |  | 有 |  | 未实现 | 未测 | 约束：与 `form_entries.value` 冲突。<br>约束：自 sing-box 1.14.0 起 |
| `form-entries-submission-key` | 认证字段提交键。 |  | 有 |  | 未实现 | 未测 | 约束：`form_entries.submission_key` 或 `form_entries.form_id` 与 `form_entries.name` 的组合之一必填。<br>约束：自 sing-box 1.14.0 起 |
| `form-entries-value` | 自动提供给匹配认证字段的值。 |  | 有 |  | 未实现 | 未测 | 约束：与 `form_entries.promote` 冲突。<br>约束：自 sing-box 1.14.0 起 |
| `fortinet-host-check` | Fortinet hostcheck 结果覆盖选项，在服务器要求时提交。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `fortinet-host-check-check-virtual-desktop` | Fortinet virtual desktop 检查结果字符串。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `fortinet-host-check-hostcheck` | Fortinet hostcheck 结果字符串。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `hip` | GlobalProtect HIP 检查和报告选项。 |  | 有 |  | 未实现 | 未测 | 约束：服务器请求 HIP 时，默认使用内置 HIP 报告。<br>约束：自 sing-box 1.14.0 起 |
| `hip-wrapper-path` | 外部 GlobalProtect HIP report wrapper 可执行文件的路径。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `http-keepalive-disabled` | 在认证和配置请求中禁用 HTTP 连接复用。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `ipv6-disabled` | 禁用请求和使用 IPv6 隧道配置。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `local-hostname` | 所选 flavor 支持时向 VPN 服务器报告的本地主机名。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：默认使用系统主机名；无法获取时使用 `localhost`。 |
| `mobile` | AnyConnect 移动客户端身份。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：配置时三个字段均为必填。 |
| `mobile-device-type` | 向 AnyConnect 服务器报告的移动设备型号或类型。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `mobile-device-unique-id` | 向 AnyConnect 服务器报告的移动设备标识符。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `mobile-platform-version` | 向 AnyConnect 服务器报告的移动操作系统版本。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `mtu` | 首选隧道 MTU。 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.14.0 起 |
| `name` | 系统接口的自定义接口名称。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：默认使用自动生成的 `oc` 接口名称。 |
| `no-udp` | 禁用 DTLS 或 ESP 辅助数据通道，仅使用 TLS 数据通道。 |  | 有 |  | 部分 | 通过 | 约束：自 sing-box 1.14.0 起 |
| `on-demand` | 允许该 endpoint 在需要时断开连接。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.15.0 起 |
| `password` | 用于填充匹配认证表单字段的密码。 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.14.0 起 |
| `password-authentication-disabled` | 如果服务器返回非成功的认证表单，则中止 AnyConnect 认证，与 OpenConnect `--no-passwd` 行为一致。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `pfs` | 要求 TLS 1.2 及更早版本使用具有前向保密性的 TLS 密码套件。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `queue-length` | VPN transport 与隧道接口之间的入站和出站数据包队列长度。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：默认使用 `32`。 |
| `reconnect-timeout` | 重连尝试失败后允许累计使用的最大退避时间。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：默认使用 `300s`。 |
| `reported-os` | 所选 flavor 支持时向 VPN 服务器报告的操作系统标识。 |  | 有 |  | 未实现 | 未测 | 取值：`android`、`apple-ios`、`linux`、`linux-64`、`mac-intel`、`win`<br>约束：自 sing-box 1.14.0 起<br>约束：默认值根据系统平台选择：Windows 使用 `win`，macOS 使用 `mac-intel`，Android 使用 `android`，iOS 使用 `apple-ios`，其他 64 位或 32 位系统使用 `linux-64` 或 `linux`。 |
| `server` | OpenConnect VPN 服务器 HTTPS URL。 |  | 有 |  | 已实现 | 通过 | 约束：不支持 URL 用户信息、查询和片段。<br>约束：必填<br>约束：自 sing-box 1.14.0 起 |
| `system` | 使用系统接口。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：需要权限，且不能与现有系统接口冲突。 |
| `tcp-keep-alive-enabled` | 为直接 VPN 服务器连接启用 TCP keep alive。 |  | 有 |  | 未实现 | 未测 | 约束：与 `disable_tcp_keep_alive` 冲突。<br>约束：启用但未设置这两个时间值时，使用操作系统默认值。<br>约束：自 sing-box 1.14.0 起 |
| `tls` | OpenConnect TLS 配置。 |  | 有 |  | 部分 | 通过 | 约束：自 sing-box 1.14.0 起 |
| `tls-certificate-authority` | PEM 格式的附加受信任 CA 证书内容。 |  | 有 |  | 已实现 | 通过 | 约束：与 `tls.certificate_authority_path` 冲突。<br>约束：自 sing-box 1.14.0 起 |
| `tls-certificate-authority-path` | PEM 格式的附加受信任 CA 证书路径。 |  | 有 |  | 未实现 | 未测 | 约束：与 `tls.certificate_authority` 冲突。<br>约束：自 sing-box 1.14.0 起 |
| `tls-client-certificate` | PEM 格式的客户端证书链内容。 |  | 有 |  | 未实现 | 未测 | 约束：与 `tls.client_certificate_path` 冲突。<br>约束：自 sing-box 1.14.0 起 |
| `tls-client-certificate-path` | PEM 格式的客户端证书链路径。 |  | 有 |  | 未实现 | 未测 | 约束：与 `tls.client_certificate` 冲突。<br>约束：自 sing-box 1.14.0 起 |
| `tls-client-key` | PEM 格式的客户端私钥内容。 |  | 有 |  | 未实现 | 未测 | 约束：与 `tls.client_key_path` 冲突。<br>约束：自 sing-box 1.14.0 起 |
| `tls-client-key-password` | 加密客户端私钥的密码。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `tls-client-key-path` | PEM 格式的客户端私钥路径。 |  | 有 |  | 未实现 | 未测 | 约束：与 `tls.client_key` 冲突。<br>约束：客户端证书和私钥必须同时设置或同时为空。<br>约束：自 sing-box 1.14.0 起 |
| `tls-insecure` | 禁用 VPN 服务器证书和主机名验证。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：默认禁用。 |
| `tls-mca-certificate` | PEM 格式的 AnyConnect 多证书认证（MCA）证书链内容。 |  | 有 |  | 未实现 | 未测 | 约束：与 `tls.mca_certificate_path` 冲突。<br>约束：自 sing-box 1.14.0 起 |
| `tls-mca-certificate-path` | PEM 格式的 AnyConnect 多证书认证（MCA）证书链路径。 |  | 有 |  | 未实现 | 未测 | 约束：与 `tls.mca_certificate` 冲突。<br>约束：自 sing-box 1.14.0 起 |
| `tls-mca-key` | PEM 格式的 AnyConnect 多证书认证（MCA）私钥内容。 |  | 有 |  | 未实现 | 未测 | 约束：与 `tls.mca_key_path` 冲突。<br>约束：自 sing-box 1.14.0 起 |
| `tls-mca-key-password` | 加密 MCA 私钥的密码。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `tls-mca-key-path` | PEM 格式的 AnyConnect 多证书认证（MCA）私钥路径。 |  | 有 |  | 未实现 | 未测 | 约束：MCA 证书和私钥必须同时设置或同时为空。<br>约束：与 `tls.mca_key` 冲突。<br>约束：自 sing-box 1.14.0 起 |
| `tls-peer-fingerprint` | 允许的服务器证书指纹。 |  | 有 |  | 未实现 | 未测 | 取值：`pin-sha256:<base64>`、`sha1:<hex>`、`sha256:<hex>`<br>约束：自 sing-box 1.14.0 起<br>约束：配置后，对端证书必须匹配其中一个指纹；匹配的指纹可以授权未通过其他方式信任的证书。 |
| `tls-server-name` | 用于 TLS SNI 和证书主机名验证的服务器名称。 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.14.0 起<br>约束：默认使用 `server` 中的主机名。 |
| `tls-system-trust-disabled` | 禁用系统 CA 证书池。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `tncc` | Network Connect TNCC 合规性选项。 |  | 有 |  | 未实现 | 未测 | 约束：服务器请求 TNCC 时，默认使用内置 TNCC 处理。<br>约束：自 sing-box 1.14.0 起 |
| `tncc-certificates` | 内置 TNCC 处理程序用于回答证书请求的机器证书。 |  | 有 |  | 未实现 | 未测 | 约束：与 `tncc.wrapper_path` 冲突。<br>约束：自 sing-box 1.14.0 起<br>约束：需要启用 `tncc.machine_identification_enabled`。 |
| `tncc-certificates-certificate` | PEM 格式的 TNCC 机器证书内容。 |  | 有 |  | 未实现 | 未测 | 约束：与 `tncc.certificates.certificate_path` 冲突。<br>约束：自 sing-box 1.14.0 起 |
| `tncc-certificates-certificate-path` | PEM 格式的 TNCC 机器证书路径。 |  | 有 |  | 未实现 | 未测 | 约束：与 `tncc.certificates.certificate` 冲突。<br>约束：自 sing-box 1.14.0 起 |
| `tncc-device-id` | 内置 TNCC 处理程序报告的设备 ID。 |  | 有 |  | 未实现 | 未测 | 约束：与 `tncc.wrapper_path` 冲突。<br>约束：自 sing-box 1.14.0 起 |
| `tncc-machine-identification-enabled` | 启用内置 TNCC 机器标识，包括平台、主机名和观测到的 MAC 地址。 |  | 有 |  | 未实现 | 未测 | 约束：与 `tncc.wrapper_path` 冲突。<br>约束：自 sing-box 1.14.0 起 |
| `tncc-user-agent` | 内置 TNCC 处理程序使用的 User-Agent。 |  | 有 |  | 未实现 | 未测 | 约束：与 `tncc.wrapper_path` 冲突。<br>约束：自 sing-box 1.14.0 起<br>约束：默认使用 `Neoteris HC Http`。 |
| `tncc-wrapper-path` | 外部 Network Connect TNCC wrapper 可执行文件的路径。 |  | 有 |  | 未实现 | 未测 | 约束：与 `tncc.device_id`、`tncc.user_agent`、`tncc.machine_identification_enabled` 和 `tncc.certificates` 冲突。<br>约束：自 sing-box 1.14.0 起 |
| `token` | 用于自动回答匹配 token 字段或进行 HTTP Bearer 认证的 token 配置。 |  | 有 |  | 未实现 | 未测 | 约束：必须设置 `token.secret` 或 `token.secret_path` 之一。<br>约束：自 sing-box 1.14.0 起 |
| `token-counter` | `hotp` 模式的初始计数器。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `token-device-id` | `stoken` 模式下用于解密设备绑定 RSA SecurID token 的设备 ID。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `token-mode` | Token 模式，可选值为： |  | 有 |  | 未实现 | 未测 | 取值：`hotp`、`oidc`、`stoken`、`totp`<br>约束：必填<br>约束：自 sing-box 1.14.0 起 |
| `token-password` | `stoken` 模式下用于解密受密码保护的 RSA SecurID token 的密码。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `token-pin` | `stoken` 模式的 RSA SecurID PIN。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `token-secret` | 软件 token 密钥。 |  | 有 |  | 未实现 | 未测 | 约束：与 `token.secret_path` 冲突。<br>约束：自 sing-box 1.14.0 起 |
| `token-secret-path` | 软件 token 密钥或 OIDC access token 的路径。 |  | 有 |  | 未实现 | 未测 | 约束：与 `token.secret` 冲突。<br>约束：自 sing-box 1.14.0 起 |
| `trojan-interval` | 覆盖 GlobalProtect HIP report 或 Network Connect TNCC check 的执行间隔。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：默认使用服务器提供的间隔。 |
| `user-agent` | 所选 flavor 支持时向 VPN 服务器报告的 User-Agent。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：默认值由 flavor 决定。 |
| `username` | 用于填充匹配认证表单字段的用户名。 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.14.0 起 |
| `version` | 所选 flavor 支持时，与 `user_agent` 分开报告的客户端版本。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：默认使用 `v9.21`。 |
| `xml-post-disabled` | 禁用 AnyConnect XML POST 认证，并直接使用旧版 GET 流程开始认证。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |

## openvpn

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | OpenVPN 出站 | 有 | 有 |  | 已实现 | 通过 | 取值：`openvpn-client`<br>约束：自 sing-box 1.14.0 起<br>约束：配置在顶层 endpoints，同时具备入站和出站行为 |
| `combo` | OpenVPN 出站维度 | 有 | 有 |  | 部分 | 通过 | proto：`tcp`、`udp`<br>auth-mode：`cert+key`、`username+password`<br>tls-wrap：`none`、`tls-auth`、`tls-crypt`、`tls-crypt-v2`<br>key-direction：``、`0`、`1`<br>cipher：`AES-128-CBC`、`AES-128-GCM`、`AES-256-CBC`、`AES-256-GCM`、`CHACHA20-POLY1305`<br>auth：`MD5`、`SHA1`、`SHA256`、`SHA384`、`SHA512`<br>comp-lzo：`adaptive`、`no`、`yes`<br>ip-stack.mode：`auto`、`gvisor`、`mips`<br>约束：AEAD cipher 忽略 auth<br>约束：tls-auth、tls-crypt、tls-crypt-v2 互斥<br>约束：username+password 与 cert+key 不能同时为空<br>mode：`static_key`、`tls`<br>network：`tcp`、`udp`<br>topology：`net30`、`p2p`、`subnet`<br>control_wrap：`none`、`tls_auth`、`tls_crypt`、`tls_crypt_v2`<br>data_cipher_class：`aead`、`cbc`、`cfb`、`none`、`ofb`<br>certificate_profile：`insecure`、`legacy`、`preferred`、`suiteb`<br>mss_fix_mode：``、`fixed`、`mtu`<br>interface：`internal`、`system`<br>server_select：`server`、`servers`、`servers+remote_random`<br>auth：`certificate`、`static_challenge`、`username/password`<br>auth_retry：`interact`、`nointeract`、`none`<br>compression：`disabled`、`lz4`、`lz4-v2`、`no`、`none`、`off`、`stub`、`stub-v2`<br>compression_lzo：`adaptive`、`asym`、`disabled`、`no`、`none`、`off`、`yes`<br>allow_compression：`asym`、`no`、`yes`<br>pull_filter：`accept`、`ignore`、`reject`<br>redirect_gateway：`off`、`on`<br>约束：allow_compression 为 no 时与非 stub 压缩冲突<br>约束：cipher 仅 static_key 模式；data_ciphers、data_ciphers_fallback 仅 TLS 模式；CFB、OFB 仅 TLS 模式<br>约束：control_wrap.direction 仅 tls_auth<br>约束：fragment 与 TCP 传输冲突，非零值至少 68<br>约束：mss_fix_disabled 与 mss_fix、mss_fix_mode 冲突；mss_fix_mode 需要 mss_fix<br>约束：ping_restart_disabled 与 ping_restart 冲突<br>约束：renegotiate_disabled 与 renegotiate_interval 冲突<br>约束：server 与 servers 二选一<br>约束：static_key 模式下有 IPv4 或 IPv6 address 时对应 peer_address 必填<br>约束：tls 模式 tls 必填；static_key 模式 static_key 或 static_key_path 必填，且 address 至少一个<br>约束：tls.certificate、certificate_path、peer_fingerprint 必有其一<br>约束：tls.remote_certificate_eku 与显式 remote_certificate_tls 冲突<br>约束：username 仅 TLS 模式 |
| `address` | 本地 IPv4 和 IPv6 隧道前缀。 |  | 有 |  | 未实现 | 未测 | 约束：`static_key` 模式至少需要一个地址。<br>约束：自 sing-box 1.14.0 起 |
| `allow-compression` | 服务器推送的 compression 策略，可选值为 `no`、`asym` 或 `yes`。 |  | 有 |  | 未实现 | 未测 | 取值：`asym`、`no`、`yes`<br>约束：当设为 `no` 时，与通过 `compression` 或 `compression_lzo` 启用的非 stub compression 冲突。<br>约束：自 sing-box 1.14.0 起<br>约束：默认使用 `no`，仅允许 compression stub framing。 |
| `auth` | 数据验证算法，默认 SHA256 | 有 | 有 |  | 部分 | 通过 | 取值：`MD5`、`SHA1`、`SHA256`、`SHA384`、`SHA512`<br>约束：AEAD 会忽略<br>约束：自 sing-box 1.14.0 起<br>约束：默认使用 `SHA1`，仅应用于非 AEAD 数据 cipher 和 `tls_auth`。 |
| `auth-retry` | 用户名/密码认证失败后的行为，可选值为 `none`、`nointeract` 或 `interact`。 |  | 有 |  | 未实现 | 未测 | 取值：`interact`、`nointeract`、`none`<br>约束：自 sing-box 1.14.0 起<br>约束：默认使用 `none`，并将永久认证失败视为终止错误。 |
| `block-ipv6` | 在本地拒绝 IPv6 流量，而不是通过 VPN 发送。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：默认禁用。 |
| `ca` | 必须，CA 证书 | 有 |  |  | 已实现 | 通过 | 取值：`PEM` |
| `cert` | 可选，客户端证书 | 有 |  |  | 已实现 | 通过 | 取值：`PEM` |
| `cipher` | 加密方式，默认 AES-128-GCM | 有 | 有 |  | 部分 | 通过 | 取值：`AES-128-CBC`、`AES-128-GCM`、`AES-256-CBC`、`AES-256-GCM`、`CHACHA20-POLY1305`<br>约束：AES-CBC 按 AES-128-CBC 处理<br>约束：为空时使用上游静态密钥模式的默认值 `BF-CBC`。<br>约束：仅在 `static_key` 模式下可用。<br>约束：自 sing-box 1.14.0 起 |
| `comp-lzo` | 数据压缩 | 有 |  |  | 未实现 | 未测 | 取值：`adaptive`、`no`、`yes` |
| `compression` | OpenVPN `compress` framing 模式，可选值为 `none`、`no`、`lz4`、`lz4-v2`、`stub`、`stub-v2`、`disabled` 或 `off`。 |  | 有 |  | 未实现 | 未测 | 取值：`disabled`、`lz4`、`lz4-v2`、`no`、`none`、`off`、`stub`、`stub-v2`<br>约束：自 sing-box 1.14.0 起<br>约束：默认禁用。 |
| `compression-lzo` | OpenVPN `comp-lzo` 模式，可选值为 `none`、`no`、`yes`、`adaptive`、`asym`、`disabled` 或 `off`。 |  | 有 |  | 未实现 | 未测 | 取值：`adaptive`、`asym`、`disabled`、`no`、`none`、`off`、`yes`<br>约束：自 sing-box 1.14.0 起<br>约束：默认禁用。 |
| `data-ciphers` | 数据通道 cipher 协商列表 | 有 | 有 |  | 已实现 | 通过 | 取值：`列表`<br>约束：CFB 和 OFB 仅可用于 TLS 模式。<br>约束：仅在 TLS 模式下可用。<br>约束：自 sing-box 1.14.0 起<br>约束：默认使用 `AES-256-GCM`、`AES-128-GCM` 和 `CHACHA20-POLY1305`。 |
| `data-ciphers-fallback` | 协商失败回退 cipher | 有 | 有 |  | 部分 | 通过 | 取值：`cipher`<br>约束：仅在 TLS 模式下可用。<br>约束：自 sing-box 1.14.0 起<br>约束：默认禁用。 |
| `dev` | 虚拟网卡类型，默认 tun | 有 |  |  | 已实现 | 通过 | 取值：`tun`<br>约束：当前仅支持 tun |
| `dns` | remote-dns-resolve 时使用的 DNS | 有 |  |  | 未实现 | 未测 | 取值：`IP 列表` |
| `explicit-exit-notify` | 关闭 UDP 连接时发送的 OpenVPN exit notification 数量。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `fragment` | 用于 OpenVPN 数据通道 fragmentation 的最大 OpenVPN UDP packet 大小。 |  | 有 |  | 未实现 | 未测 | 约束：与 TCP 传输冲突。<br>约束：自 sing-box 1.14.0 起<br>约束：非零值必须至少为 `68`。 |
| `handshake-timeout` | 握手超时秒，默认 0 | 有 |  |  | 已实现 | 通过 | 取值：`整数` |
| `handshake-window` | 初始 TLS 握手及每次重新协商的最长允许时间。 |  | 有 |  | 已实现 | 通过 | 约束：为空时使用 OpenVPN 默认值 `1m`。<br>约束：自 sing-box 1.14.0 起 |
| `ip-stack-congestion-controller` | TCP 拥塞控制，默认 cubic | 有 |  |  | 未实现 | 未测 | 取值：`bbr`、`bbr3`、`cubic`、`reno`<br>约束：gVisor 下不生效 |
| `ip-stack-mode` | IP 协议栈，默认 auto | 有 |  |  | 未实现 | 未测 | 取值：`auto`、`gvisor`、`mips`<br>约束：auto 用 MIPS<br>约束：gvisor 需 -tags with_gvisor |
| `key` | 可选，客户端私钥 | 有 |  |  | 已实现 | 通过 | 取值：`PEM` |
| `key-direction` | tls-auth 方向，空为双向 | 有 | 有 |  | 已实现 | 通过 | 取值：``、`0`、`1`、`client`、`server`<br>约束：仅在 `static_key` 模式下可用。<br>约束：自 sing-box 1.14.0 起 |
| `mode` | OpenVPN 会话模式，可选值为 `tls` 或 `static_key`。 |  | 有 |  | 部分 | 通过 | 取值：`static_key`、`tls`<br>约束：`static_key` 是已弃用的 OpenVPN 模式，不使用 TLS 控制通道且不提供前向保密。<br>约束：自 sing-box 1.14.0 起<br>约束：默认使用 `tls`。 |
| `mss-fix` | OpenVPN UDP packet 的最大大小，用于限制通过隧道发送的 TCP 连接 MSS。 |  | 有 |  | 未实现 | 未测 | 约束：为空时使用上游 OpenVPN 默认值：配置了 `fragment` 时使用其值；否则默认 tunnel MTU 使用 `1492`，自定义 tunnel MTU 使用该 MTU。<br>约束：自 sing-box 1.14.0 起 |
| `mss-fix-disabled` | 禁用 MSS 限制，包括默认限制。 |  | 有 |  | 未实现 | 未测 | 约束：与 `mss_fix` 和 `mss_fix_mode` 冲突。<br>约束：自 sing-box 1.14.0 起 |
| `mss-fix-mode` | 显式 `mss_fix` 的 OpenVPN MSS 计算模式，`mtu` 或 `fixed` 之一。 |  | 有 |  | 未实现 | 未测 | 取值：`fixed`、`mtu`<br>约束：自 sing-box 1.14.0 起<br>约束：需要 `mss_fix`。 |
| `mtu` | MTU，默认 1500 | 有 | 有 |  | 已实现 | 通过 | 取值：`整数`<br>约束：自 sing-box 1.14.0 起 |
| `name` | 系统接口的自定义接口名称。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：默认使用自动生成的 `ovpn` 接口名称。 |
| `network` | 默认 OpenVPN 传输网络，可选值为 `udp` 或 `tcp`。 |  | 有 |  | 已实现 | 通过 | 取值：`tcp`、`udp`<br>约束：自 sing-box 1.14.0 起<br>约束：默认使用 `udp`。 |
| `on-demand` | 允许该 endpoint 在需要时断开连接。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.15.0 起 |
| `password` | auth-user-pass 密码 | 有 | 有 |  | 已实现 | 通过 | 取值：`字符串`<br>约束：自 sing-box 1.14.0 起 |
| `peer-address` | IPv4 隧道对端地址及 VPN 网关。 |  | 有 |  | 未实现 | 未测 | 约束：在 `static_key` 模式下配置 IPv4 `address` 时必填。<br>约束：自 sing-box 1.14.0 起 |
| `peer-address-ipv6` | IPv6 隧道对端地址及 VPN 网关。 |  | 有 |  | 未实现 | 未测 | 约束：在 `static_key` 模式下配置 IPv6 `address` 时必填。<br>约束：自 sing-box 1.14.0 起 |
| `peer-info` | 透传 peer-info 键值 | 有 |  |  | 未实现 | 未测 | 取值：`映射` |
| `ping` | 默认 0 | 有 |  |  | 已实现 | 通过 | 取值：`整数` |
| `ping-interval` | 客户端未向服务器发送任何 packet 时，发送 data channel ping 的间隔。 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.14.0 起<br>约束：该值必须使用整秒。<br>约束：默认禁用。 |
| `ping-restart` | 默认 0 | 有 | 有 |  | 已实现 | 通过 | 取值：`整数`<br>约束：TCP 不使用默认接收超时。<br>约束：自 sing-box 1.14.0 起<br>约束：该值必须使用整秒。 |
| `ping-restart-disabled` | 禁用初始 `120s` UDP 拉取超时和本地配置的 ping 重启超时。 |  | 有 |  | 部分 | 通过 | 约束：与 `ping_restart` 冲突。<br>约束：自 sing-box 1.14.0 起 |
| `proto` | 协议，默认 udp | 有 |  |  | 已实现 | 通过 | 取值：`tcp`、`udp` |
| `pull-filters` | 服务器推送选项的有序 pull filter 列表。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `pull-filters-action` | Filter action，可选值为 `accept`、`ignore` 或 `reject`。 |  | 有 |  | 未实现 | 未测 | 取值：`accept`、`ignore`、`reject`<br>约束：必填<br>约束：自 sing-box 1.14.0 起 |
| `pull-filters-text` | 用于匹配推送选项名称和值的大小写敏感前缀。 |  | 有 |  | 未实现 | 未测 | 约束：必填<br>约束：自 sing-box 1.14.0 起 |
| `redirect-gateway` | 在 sing-box 路由中对所有 IPv4 目的地优先选择 OpenVPN endpoint。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：默认禁用。 |
| `redirect-gateway-flags` | OpenVPN redirect-gateway 标志 |  | 有 |  | 未实现 | 未测 | 取值：`!ipv4`、`autolocal`、`bypass-dhcp`、`bypass-dns`、`def1`、`ipv6`、`local`<br>约束：Empty by default.<br>约束：`block-local` is not supported.<br>约束：`local`, `autolocal`, `bypass-dhcp` and `bypass-dns` have no effect.<br>约束：`local`、`autolocal`、`bypass-dhcp` 和 `bypass-dns` 无效果。<br>约束：block-local 不支持<br>约束：local、autolocal、bypass-dhcp、bypass-dns 无效果<br>约束：不支持 `block-local`。<br>约束：自 sing-box 1.14.0 起<br>约束：默认为空。 |
| `redirect-private` | 接受 `redirect_gateway_flags`，但不添加默认路由偏好。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：默认禁用。 |
| `remote-dns-resolve` | 强制远程解析，默认 false | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `remote-random` | 连接前随机排列 `servers` 顺序。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：默认禁用。 |
| `renegotiate-bytes` | 传输指定字节数后重新协商数据通道密钥。 |  | 有 |  | 未实现 | 未测 | 约束：`0` 使用与密码算法相关的 OpenVPN 默认值。<br>约束：自 sing-box 1.14.0 起 |
| `renegotiate-disabled` | 禁用基于时间的 TLS 重新协商，包括默认间隔。 |  | 有 |  | 已实现 | 通过 | 约束：与 `renegotiate_interval` 冲突。<br>约束：自 sing-box 1.14.0 起 |
| `renegotiate-interval` | OpenVPN TLS 重新协商间隔。 |  | 有 |  | 已实现 | 通过 | 约束：为空时使用 OpenVPN 默认值 `1h`。<br>约束：自 sing-box 1.14.0 起 |
| `renegotiate-packets` | 传输指定数据包数后重新协商数据通道密钥。 |  | 有 |  | 未实现 | 未测 | 约束：`0` 使用与密码算法相关的 OpenVPN 默认值。<br>约束：自 sing-box 1.14.0 起 |
| `replay-window` | UDP 数据通道重放窗口大小。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：默认使用 `64`，最大值为 `65536`。 |
| `replay-window-time` | UDP 数据通道重放窗口时长。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：该值必须使用整秒。<br>约束：默认使用 `15s`，最大值为 `10m`。 |
| `route-gateway` | 通过 OpenVPN endpoint 路由的 IPv4 gateway。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `route-metric` | 通过 OpenVPN endpoint 路由的默认 metric。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：设为 `0` 时使用平台默认值。 |
| `route-no-pull` | 忽略服务器推送的 route、DNS 和 DHCP 设置、route metric、`redirect-gateway`、`redirect-private`、`block-ipv6` 和 `block-outside-dns`。 |  | 有 |  | 部分 | 通过 | 约束：自 sing-box 1.14.0 起<br>约束：默认禁用。 |
| `routes` | sing-box 路由优先选择此 OpenVPN endpoint 的 IPv4 和 IPv6 前缀。 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.14.0 起 |
| `server` | OpenVPN 服务器地址。 |  | 有 |  | 已实现 | 通过 | 约束：`server` 和 `servers` 之一必填。<br>约束：与 `servers` 冲突。<br>约束：自 sing-box 1.14.0 起 |
| `server-port` | OpenVPN 服务器端口。 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.14.0 起<br>约束：设置 `server` 时必填。 |
| `servers` | OpenVPN 服务器列表。 |  | 有 |  | 未实现 | 未测 | 约束：`server` 和 `servers` 之一必填。<br>约束：与 `server` 冲突。<br>约束：自 sing-box 1.14.0 起 |
| `servers-network` | 该服务器的 OpenVPN 传输网络，可选值为 `udp` 或 `tcp`。 |  | 有 |  | 未实现 | 未测 | 取值：`tcp`、`udp`<br>约束：自 sing-box 1.14.0 起<br>约束：默认使用顶层 `network`。 |
| `servers-server` | OpenVPN 服务器地址。 |  | 有 |  | 未实现 | 未测 | 约束：必填<br>约束：自 sing-box 1.14.0 起 |
| `servers-server-port` | OpenVPN 服务器端口。 |  | 有 |  | 未实现 | 未测 | 约束：必填<br>约束：自 sing-box 1.14.0 起 |
| `static-challenge` | 请求认证响应时显示的静态质询文本。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `static-challenge-echo` | 以明文显示静态质询响应。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `static-key` | OpenVPN 静态密钥内容。 |  | 有 |  | 未实现 | 未测 | 约束：与 `static_key_path` 冲突。<br>约束：在 `static_key` 模式下必填。<br>约束：自 sing-box 1.14.0 起 |
| `static-key-path` | OpenVPN 静态密钥路径。 |  | 有 |  | 未实现 | 未测 | 约束：与 `static_key` 冲突。<br>约束：在 `static_key` 模式下未设置 `static_key` 时必填。<br>约束：自 sing-box 1.14.0 起 |
| `system` | 使用系统接口。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：需要权限，且不能与现有系统接口冲突。 |
| `tls` | 在 TLS 模式下必填。 |  | 有 |  | 部分 | 通过 | 约束：自 sing-box 1.14.0 起 |
| `tls-auth` | 可选 | 有 |  |  | 已实现 | 通过 | 取值：`PEM`<br>约束：与 tls-crypt、tls-crypt-v2 互斥 |
| `tls-certificate` | 受信任 CA 证书内容。 |  | 有 |  | 已实现 | 通过 | 约束：`tls.certificate`、`tls.certificate_path` 和 `tls.peer_fingerprint` 之一必填。<br>约束：与 `tls.certificate_path` 冲突。<br>约束：自 sing-box 1.14.0 起 |
| `tls-certificate-path` | 受信任 CA 证书路径。 |  | 有 |  | 未实现 | 未测 | 约束：`tls.certificate`、`tls.certificate_path` 和 `tls.peer_fingerprint` 之一必填。<br>约束：与 `tls.certificate` 冲突。<br>约束：自 sing-box 1.14.0 起 |
| `tls-certificate-profile` | 证书 profile，可选值为 `insecure`、`legacy`、`preferred` 或 `suiteb`。 |  | 有 |  | 未实现 | 未测 | 取值：`insecure`、`legacy`、`preferred`、`suiteb`<br>约束：`insecure` 为兼容不可变对端而接受使用 MD5 或 SHA-1 签名的证书链和较小的旧密钥，仅应在对端无法升级时使用。<br>约束：自 sing-box 1.14.0 起<br>约束：选择 `suiteb` 且 `tls.cipher` 为空时，TLS 1.2 cipher 列表默认使用 Suite B ECDHE-ECDSA AES-GCM 套件。<br>约束：默认使用 `legacy`。 |
| `tls-cipher` | TLS 1.2 及更低版本允许的 OpenSSL cipher suite 名称，以冒号分隔。 |  | 有 |  | 未实现 | 未测 | 约束：为空时使用默认 TLS cipher suite。<br>约束：自 sing-box 1.14.0 起 |
| `tls-client-certificate` | 客户端证书内容。 |  | 有 |  | 已实现 | 通过 | 约束：与 `tls.client_certificate_path` 冲突。<br>约束：自 sing-box 1.14.0 起 |
| `tls-client-certificate-path` | 客户端证书路径。 |  | 有 |  | 未实现 | 未测 | 约束：与 `tls.client_certificate` 冲突。<br>约束：自 sing-box 1.14.0 起 |
| `tls-client-key` | 客户端私钥内容。 |  | 有 |  | 已实现 | 通过 | 约束：与 `tls.client_key_path` 冲突。<br>约束：自 sing-box 1.14.0 起 |
| `tls-client-key-path` | 客户端私钥路径。 |  | 有 |  | 未实现 | 未测 | 约束：与 `tls.client_key` 冲突。<br>约束：客户端证书和私钥必须同时设置或同时为空。<br>约束：自 sing-box 1.14.0 起 |
| `tls-control-wrap` | OpenVPN 控制通道封装。 |  | 有 |  | 部分 | 通过 | 约束：自 sing-box 1.14.0 起 |
| `tls-control-wrap-direction` | `tls-auth` 密钥方向，可选值为 `server` 或 `client`。 |  | 有 |  | 已实现 | 通过 | 取值：`client`、`server`<br>约束：仅当 `tls.control_wrap.type` 为 `tls_auth` 时可用。<br>约束：自 sing-box 1.14.0 起 |
| `tls-control-wrap-key` | 控制通道封装密钥内容。 |  | 有 |  | 已实现 | 通过 | 约束：与 `tls.control_wrap.key_path` 冲突。<br>约束：自 sing-box 1.14.0 起 |
| `tls-control-wrap-key-path` | 控制通道封装密钥路径。 |  | 有 |  | 未实现 | 未测 | 约束：与 `tls.control_wrap.key` 冲突。<br>约束：自 sing-box 1.14.0 起 |
| `tls-control-wrap-type` | 控制通道封装类型，可选值为 `tls_auth`、`tls_crypt` 或 `tls_crypt_v2`。 |  | 有 |  | 部分 | 通过 | 取值：`tls_auth`、`tls_crypt`、`tls_crypt_v2`<br>约束：自 sing-box 1.14.0 起 |
| `tls-crl-path` | 用于拒绝已吊销服务器证书的 PEM 或 DER CRL 文件路径。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：默认禁用。 |
| `tls-crypt` | 可选，TLS 加密密钥 | 有 |  |  | 已实现 | 通过 | 取值：`PEM`<br>约束：与 tls-auth、tls-crypt-v2 互斥 |
| `tls-crypt-v2` | 可选，客户端密钥 | 有 |  |  | 未实现 | 未测 | 取值：`PEM`<br>约束：与 tls-auth、tls-crypt 互斥 |
| `tls-groups` | 按偏好顺序排列的 TLS key exchange group，以冒号分隔。 |  | 有 |  | 未实现 | 未测 | 约束：为空时使用默认 TLS group。<br>约束：自 sing-box 1.14.0 起 |
| `tls-ns-certificate-type` | 已弃用的 Netscape 证书类型检查，`server` 或 `client` 之一。 |  | 废弃 |  | 未实现 | 未测 | 取值：`client`、`server`<br>约束：自 sing-box 1.14.0 起<br>约束：默认禁用。 |
| `tls-peer-fingerprint` | 允许的服务器 leaf certificate 的 SHA-256 fingerprint。 |  | 有 |  | 未实现 | 未测 | 约束：每个 fingerprint 必须是不带分隔符的 64 字符小写十六进制字符串。<br>约束：自 sing-box 1.14.0 起 |
| `tls-remote-certificate-eku` | 服务器证书所需的 Extended Key Usage。 |  | 有 |  | 未实现 | 未测 | 约束：与显式配置的 `tls.remote_certificate_tls` 冲突。<br>约束：自 sing-box 1.14.0 起<br>约束：设置后，该字段会替代默认的 `tls.remote_certificate_tls` 检查。 |
| `tls-remote-certificate-ku` | 服务器证书所需的 Key Usage mask，使用 OpenVPN `remote-cert-ku` 格式的十六进制值。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：证书必须包含至少一个已配置 mask 中的所有 bit。<br>约束：默认禁用。 |
| `tls-remote-certificate-tls` | 对端证书用途检查，可选值为 `server`、`client` 或 `none`。 |  | 有 |  | 未实现 | 未测 | 取值：`client`、`none`、`server`<br>约束：与 `tls.remote_certificate_eku` 冲突。<br>约束：自 sing-box 1.14.0 起<br>约束：默认使用 `server`。 |
| `tls-server-name` | 预期的服务器证书名称。 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.14.0 起 |
| `tls-server-name-type` | tls.server_name 匹配的证书字段 |  | 有 |  | 部分 | 通过 | 取值：`name`、`name-prefix`、`subject`<br>约束：自 sing-box 1.14.0 起<br>约束：设置 `tls.server_name` 时默认使用 `name`。 |
| `tls-timeout` | TLS 控制数据包的初始重传超时。 |  | 有 |  | 未实现 | 未测 | 约束：为空时使用 OpenVPN 默认值 `2s`。<br>约束：自 sing-box 1.14.0 起 |
| `tls-version-max` | 最高 TLS 版本，可选值为 `1.0`、`1.1`、`1.2` 或 `1.3`。 |  | 有 |  | 未实现 | 未测 | 取值：`1.0`、`1.1`、`1.2`、`1.3`<br>约束：自 sing-box 1.14.0 起<br>约束：该值不能低于 `tls.version_min`。<br>约束：默认使用支持的最高版本。 |
| `tls-version-min` | 最低 TLS 版本，可选值为 `1.0`、`1.1`、`1.2` 或 `1.3`。 |  | 有 |  | 未实现 | 未测 | 取值：`1.0`、`1.1`、`1.2`、`1.3`<br>约束：自 sing-box 1.14.0 起<br>约束：默认使用 `1.2`。 |
| `topology` | 隧道拓扑，可选值为 `net30`、`p2p` 或 `subnet`。 |  | 有 |  | 已实现 | 通过 | 取值：`net30`、`p2p`、`subnet`<br>约束：自 sing-box 1.14.0 起 |
| `tran-window` | 旧 key 保留秒，默认 3600，0 立即过期 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `username` | auth-user-pass 用户名 | 有 | 有 |  | 已实现 | 通过 | 取值：`字符串`<br>约束：与 cert、key 二选一，不能同时为空<br>约束：仅在 TLS 模式下可用。<br>约束：自 sing-box 1.14.0 起 |

## rematch

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | Rematch 出站，重新进入规则匹配 | 有 |  |  | 未实现 | 未测 |  |
| `combo` | Rematch 维度 | 有 |  |  | 未实现 | 未测 | mode：`target-rematch-name`、`target-sub-rule`<br>约束：REMATCH-NAME 规则应放在触发 rematch 的规则之前，避免循环<br>约束：子规则存在时建议 MATCH 兜底 |
| `target-rematch-name` | 覆盖 metadata 的 rematch-name | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `target-sub-rule` | 后续用指定 sub-rule；不存在或空回退主 rules | 有 |  |  | 未实现 | 未测 | 取值：`sub-rule 名` |

## shadowquic

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | ShadowQUIC 出站 | 有 |  |  | 已实现 | 通过 | 约束：强制启用 JLS，无需 jls-opts |
| `combo` | ShadowQUIC 出站维度 | 有 |  |  | 部分 | 通过 | quic-versions：`v1`、`v2`<br>udp：`datagram`、`udp-over-stream`<br>congestion-controller：`bbr`、`cubic`、`new_reno`<br>bbr-profile：`aggressive`、`conservative`、`standard`<br>brutal：`off`、`up/down`<br>zero-rtt：`false`、`true` |
| `alpn` | ALPN，默认 h3 | 有 |  |  | 已实现 | 通过 | 取值：`列表` |
| `bbr-profile` | BBR 档位 | 有 |  |  | 未实现 | 未测 | 取值：`aggressive`、`conservative`、`standard`<br>约束：仅 bbr 时有效 |
| `congestion-controller` | 拥塞控制，默认 cubic | 有 |  |  | 已实现 | 通过 | 取值：`bbr`、`cubic`、`new_reno` |
| `cwnd` | 初始拥塞窗口，默认 32 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `disable-mtu-discovery` | 禁用路径 MTU 发现 | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `down` | 请求下载速度，协商 Brutal；对端不支持回退 | 有 |  |  | 未实现 | 未测 | 取值：`100 Mbps` |
| `keep-alive-interval` | 心跳间隔，毫秒 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `max-datagram-frame-size` | 最大数据报帧，默认 1400 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `max-open-streams` | 最大并发流，默认 1024 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `password` | 必须，密码 | 有 |  |  | 已实现 | 通过 | 取值：`字符串` |
| `quic-versions` | QUIC 版本，默认 v1 | 有 |  |  | 已实现 | 通过 | 取值：`v1`、`v2` |
| `recv-window` | 连接级接收窗口，0 内部默认 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `recv-window-conn` | 流级接收窗口，0 内部默认 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `sni` | SNI | 有 |  |  | 已实现 | 通过 | 取值：`域名` |
| `udp-over-stream` | UDP over stream，默认 false | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true` |
| `up` | 客户端上传，协商 Brutal；对端不支持回退 | 有 |  |  | 未实现 | 未测 | 取值：`100 Mbps` |
| `username` | 必须，用户名 | 有 |  |  | 已实现 | 通过 | 取值：`字符串` |
| `zero-rtt` | 0-RTT | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true`<br>约束：官方 server v0.3.11 的 0-RTT 路径可能在 JLS 认证完成前读取用户状态 |

## shadowsocks

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | Shadowsocks 出站，type 写 ss | 有 | 有 |  | 已实现 | 通过 | 取值：`shadowsocks`、`ss` |
| `shadowsocks` | Shadowsocks 出站 |  |  | 有 | 已实现 | 通过 | 取值：`shadowsocks`<br>约束：源码启动时打印不移除的弃用告警，建议 VLESS Encryption |
| `combo` | Shadowsocks 出站维度 | 有 | 有 | 有 | 部分 | 通过 | cipher：`2022-blake3-aes-128-gcm`、`2022-blake3-aes-256-gcm`、`2022-blake3-chacha20-poly1305`、`aegis-128l`、`aegis-256`、`aes-128-ccm`、`aes-128-cfb`、`aes-128-ctr`、`aes-128-gcm`、`aes-128-gcm-siv`、`aes-192-ccm`、`aes-192-cfb`、`aes-192-ctr`、`aes-192-gcm`、`aes-256-ccm`、`aes-256-cfb`、`aes-256-ctr`、`aes-256-gcm`、`aes-256-gcm-siv`、`aez-384`、`chacha20`、`chacha20-ietf`、`chacha20-ietf-poly1305`、`chacha8-ietf-poly1305`、`deoxys-ii-256-128`、`lea-128-gcm`、`lea-192-gcm`、`lea-256-gcm`、`none`、`rabbit128-poly1305`、`rc4-md5`、`xchacha20`、`xchacha20-ietf-poly1305`、`xchacha8-ietf-poly1305`<br>plugin：`gost-plugin`、`jls`、`kcptun`、`none`、`obfs`、`restls`、`shadow-tls`、`v2ray-plugin`<br>obfs.mode：`http`、`tls`<br>udp：`false`、`true`<br>udp-over-tcp：`false`、`v1`、`v2`<br>smux：`h2mux`、`off`、`smux`、`yamux`<br>ip-version：`dual`、`ipv4`、`ipv4-prefer`、`ipv6`、`ipv6-prefer`<br>约束：source:adapter/outbound/shadowsocks.go：UoT 版本仅 1、2<br>约束：v2ray-plugin 无 QUIC<br>method：`2022-blake3-aes-128-gcm`、`2022-blake3-aes-256-gcm`、`2022-blake3-chacha20-poly1305`、`aes-128-cfb`、`aes-128-ctr`、`aes-128-gcm`、`aes-192-cfb`、`aes-192-ctr`、`aes-192-gcm`、`aes-256-cfb`、`aes-256-ctr`、`aes-256-gcm`、`chacha20-ietf`、`chacha20-ietf-poly1305`、`none`、`rc4-md5`、`xchacha20`、`xchacha20-ietf-poly1305`<br>plugin：`none`、`obfs-local`、`v2ray-plugin`<br>network：`tcp`、`tcp+udp`、`udp`<br>udp_over_tcp：`off`、`v1`、`v2`<br>multiplex：`h2mux`、`off`、`smux`、`yamux`<br>multiplex_padding：`off`、`on`<br>brutal：`off`、`on`<br>约束：brutal 服务端需要 Linux 和 brutal 内核模块<br>约束：max_connections、min_streams 与 max_streams 冲突<br>约束：network 留空时 TCP、UDP 都启用<br>约束：udp_over_tcp 与 multiplex 冲突<br>约束：入站 padding 开启后拒绝未填充连接<br>约束：文档建议只用 AEAD 2022 且开多路复用（docs/manual/proxy-protocol/shadowsocks.md）<br>transport：`grpc`、`httpupgrade`、`hysteria`、`mkcp`、`raw`、`websocket`、`xhttp`<br>security：`none`、`reality`、`tls`<br>method：`2022-blake3-aes-128-gcm`、`2022-blake3-aes-256-gcm`、`2022-blake3-chacha20-poly1305`、`aes-128-gcm`、`aes-256-gcm`、`chacha20-ietf-poly1305`、`chacha20-poly1305`、`xchacha20-ietf-poly1305`、`xchacha20-poly1305`<br>udp：`native`、`xudp`<br>约束：masque 传输不适用<br>约束：未启用 XUDP 时 UDP 走原生路径，绕过已配置传输和 TLS/REALITY |
| `address` | 服务端地址，必填 |  |  | 有 | 已实现 | 通过 |  |
| `cipher` | 加密方法 | 有 |  |  | 部分 | 通过 | 取值：`2022-blake3-aes-128-gcm`、`2022-blake3-aes-256-gcm`、`2022-blake3-chacha20-poly1305`、`aegis-128l`、`aegis-256`、`aes-128-ccm`、`aes-128-cfb`、`aes-128-ctr`、`aes-128-gcm`、`aes-128-gcm-siv`、`aes-192-ccm`、`aes-192-cfb`、`aes-192-ctr`、`aes-192-gcm`、`aes-256-ccm`、`aes-256-cfb`、`aes-256-ctr`、`aes-256-gcm`、`aes-256-gcm-siv`、`aez-384`、`chacha20`、`chacha20-ietf`、`chacha20-ietf-poly1305`、`chacha8-ietf-poly1305`…… |
| `client-fingerprint` | shadow-tls、restls、jls 插件 uTLS 指纹 | 有 |  |  | 未实现 | 未测 | 取值：`360`、`android`、`chrome`、`edge`、`firefox`、`ios`、`qq`、`random`、`safari`<br>约束：restls 文档示例列 chrome、ios、firefox、safari |
| `email` | 邮箱，可选 |  |  | 有 | 未实现 | 未测 |  |
| `level` | 用户等级，默认 0 |  |  | 有 | 未实现 | 未测 |  |
| `method` | 加密方法： |  | 有 | 有 | 部分 | 通过 | 取值：`2022-blake3-aes-128-gcm`、`2022-blake3-aes-256-gcm`、`2022-blake3-chacha20-poly1305`、`aes-128-cfb`、`aes-128-ctr`、`aes-128-gcm`、`aes-192-cfb`、`aes-192-ctr`、`aes-192-gcm`、`aes-256-cfb`、`aes-256-ctr`、`aes-256-gcm`、`chacha20-ietf`、`chacha20-ietf-poly1305`、`chacha20-poly1305`、`none`、`rc4-md5`、`xchacha20`、`xchacha20-ietf-poly1305`、`xchacha20-poly1305`<br>约束：后 9 种为旧版流加密方法<br>约束：必填 |
| `multiplex` | 参阅 多路复用。 |  | 有 |  | 未实现 | 未测 |  |
| `network` | 启用的网络协议`tcp` 或 `udp`。 |  | 有 |  | 部分 | 通过 | 取值：`tcp`、`udp`<br>约束：默认所有。 |
| `password` | 密码 | 有 | 有 | 有 | 已实现 | 通过 | 取值：`字符串`<br>约束：必填<br>约束：SS2022 预共享密钥：128-gcm 16 字节，其他 32 字节 |
| `plugin` | 插件 | 有 | 有 |  | 部分 | 通过 | 取值：`gost-plugin`、`jls`、`kcptun`、`obfs`、`obfs-local`、`restls`、`shadow-tls`、`v2ray-plugin`<br>约束：仅支持 `obfs-local` 和 `v2ray-plugin`。 |
| `plugin-opts` | Shadowsocks SIP003 插件参数。 |  | 有 |  | 部分 | 通过 |  |
| `plugin-opts-gost-plugin-fingerprint` | 证书指纹 | 有 |  |  | 未实现 | 未测 | 取值：`sha256` |
| `plugin-opts-gost-plugin-headers` | 请求头 | 有 |  |  | 未实现 | 未测 | 取值：`映射` |
| `plugin-opts-gost-plugin-host` | 主机 | 有 |  |  | 未实现 | 未测 | 取值：`域名` |
| `plugin-opts-gost-plugin-mode` | gost-plugin 模式 | 有 |  |  | 未实现 | 未测 | 取值：`websocket` |
| `plugin-opts-gost-plugin-mux` | 多路复用 | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `plugin-opts-gost-plugin-name-cert-verify` | 校验名 | 有 |  |  | 未实现 | 未测 | 取值：`域名` |
| `plugin-opts-gost-plugin-path` | 路径 | 有 |  |  | 未实现 | 未测 | 取值：`路径` |
| `plugin-opts-gost-plugin-skip-cert-verify` | 跳过验证 | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `plugin-opts-gost-plugin-tls` | wss | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `plugin-opts-jls-alpn` | ALPN | 有 |  |  | 未实现 | 未测 | 取值：`h2`、`http/1.1` |
| `plugin-opts-jls-host` | JLS 域名 | 有 |  |  | 未实现 | 未测 | 取值：`域名` |
| `plugin-opts-jls-password` | JLS 密码 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `plugin-opts-jls-username` | JLS 用户名 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `plugin-opts-kcptun-acknodelay` | 收包立即刷新 ack | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `plugin-opts-kcptun-autoexpire` | 单 UDP 连接自动过期秒数，0 禁用 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `plugin-opts-kcptun-conn` | 到服务端的 UDP 连接数 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `plugin-opts-kcptun-crypt` | 加密方式 | 有 |  |  | 未实现 | 未测 | 取值：`3des`、`aes`、`aes-128`、`aes-128-gcm`、`aes-192`、`blowfish`、`cast5`、`none`、`null`、`salsa20`、`tea`、`twofish`、`xor`、`xtea` |
| `plugin-opts-kcptun-datashard` | Reed-Solomon 数据分片 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `plugin-opts-kcptun-dscp` | DSCP（6 位） | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `plugin-opts-kcptun-framesize` | smux 最大帧 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `plugin-opts-kcptun-interval` | interval 参数 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `plugin-opts-kcptun-keepalive` | 心跳间隔秒 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `plugin-opts-kcptun-key` | 预共享密钥 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `plugin-opts-kcptun-mode` | 模式档位 | 有 |  |  | 未实现 | 未测 | 取值：`fast`、`fast2`、`fast3`、`manual`、`normal` |
| `plugin-opts-kcptun-mtu` | UDP 包 MTU | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `plugin-opts-kcptun-nocomp` | 禁用压缩 | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `plugin-opts-kcptun-nodelay` | nodelay 参数 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `plugin-opts-kcptun-parityshard` | Reed-Solomon 校验分片 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `plugin-opts-kcptun-ratelimit` | 单 KCP 连接出站限速，字节/秒，0 禁用 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `plugin-opts-kcptun-rcvwnd` | 接收窗口（包数） | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `plugin-opts-kcptun-resend` | resend 参数 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `plugin-opts-kcptun-scavengettl` | 过期连接存活秒数 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `plugin-opts-kcptun-smuxbuf` | smux 解复用总缓冲字节 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `plugin-opts-kcptun-smuxver` | smux 版本 | 有 |  |  | 未实现 | 未测 | 取值：`1`、`2` |
| `plugin-opts-kcptun-sndwnd` | 发送窗口（包数） | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `plugin-opts-kcptun-sockbuf` | 每 socket 缓冲字节 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `plugin-opts-kcptun-streambuf` | 每流接收缓冲，smux v2+ | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `plugin-opts-obfs-host` | obfs 域名 | 有 |  |  | 未实现 | 未测 | 取值：`域名` |
| `plugin-opts-obfs-mode` | obfs 模式 | 有 |  |  | 未实现 | 未测 | 取值：`http`、`tls` |
| `plugin-opts-restls-host` | 应为 TLS 1.3 服务器 | 有 |  |  | 未实现 | 未测 | 取值：`域名` |
| `plugin-opts-restls-password` | Restls 密码 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `plugin-opts-restls-restls-script` | 握手后行为脚本 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `plugin-opts-restls-version-hint` | 版本提示 | 有 |  |  | 未实现 | 未测 | 取值：`tls12`、`tls13` |
| `plugin-opts-shadow-tls-host` | ShadowTLS 域名 | 有 |  |  | 已实现 | 通过 | 取值：`域名` |
| `plugin-opts-shadow-tls-password` | ShadowTLS 密码 | 有 |  |  | 已实现 | 通过 | 取值：`字符串` |
| `plugin-opts-shadow-tls-version` | ShadowTLS 版本 | 有 |  |  | 已实现 | 通过 | 取值：`1`、`2`、`3` |
| `plugin-opts-v2ray-plugin-fingerprint` | 证书指纹 | 有 |  |  | 未实现 | 未测 | 取值：`sha256` |
| `plugin-opts-v2ray-plugin-headers` | 请求头 | 有 |  |  | 未实现 | 未测 | 取值：`映射` |
| `plugin-opts-v2ray-plugin-host` | 主机 | 有 |  |  | 未实现 | 未测 | 取值：`域名` |
| `plugin-opts-v2ray-plugin-mode` | v2ray-plugin 模式 | 有 |  |  | 未实现 | 未测 | 取值：`websocket`<br>约束：no QUIC now |
| `plugin-opts-v2ray-plugin-mux` | 多路复用 | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `plugin-opts-v2ray-plugin-name-cert-verify` | 校验名 | 有 |  |  | 未实现 | 未测 | 取值：`域名` |
| `plugin-opts-v2ray-plugin-path` | 路径 | 有 |  |  | 未实现 | 未测 | 取值：`路径` |
| `plugin-opts-v2ray-plugin-skip-cert-verify` | 跳过验证 | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `plugin-opts-v2ray-plugin-tls` | wss | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `plugin-opts-v2ray-plugin-v2ray-http-upgrade` | http upgrade | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `port` | 服务端端口，必填 |  |  | 有 | 已实现 | 通过 |  |
| `server` | 服务器地址。 |  | 有 |  | 已实现 | 通过 | 约束：必填 |
| `server-port` | 服务器端口。 |  | 有 |  | 已实现 | 通过 | 约束：必填 |
| `servers` | 旧多服务器写法 |  |  | 有 | 不适用 | 未测 | 约束：只能一个成员 |
| `udp-over-tcp` | 启用 UDP over TCP，默认 false | 有 | 有 |  | 未实现 | 未测 | 取值：`false`、`true`<br>约束：与 `multiplex` 冲突。 |
| `udp-over-tcp-version` | UoT 版本，默认 1 | 有 |  |  | 未实现 | 未测 | 取值：`1`、`2` |

## shadowsocksr

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | ShadowsocksR 出站，type 写 ssr | 有 | 已移除 |  | 已实现 | 通过 | 取值：`auth_aes128_md5`、`auth_aes128_sha1`、`auth_chain_a`、`auth_chain_b`、`auth_sha1_v4`、`origin`、`shadowsocksr`、`ssr`<br>约束：1.6.0 移除（source:include/registry.go） |
| `combo` | SSR 出站维度 | 有 |  |  | 已实现 | 通过 | obfs：`http_post`、`http_simple`、`plain`、`random_head`、`tls1.2_ticket_auth`、`tls1.2_ticket_fastauth`<br>protocol：`auth_aes128_md5`、`auth_aes128_sha1`、`auth_chain_a`、`auth_chain_b`、`auth_sha1_v4`、`origin`<br>udp：`false`、`true`<br>约束：文档页只给示例 cipher chacha20-ietf；obfs、protocol 取值来自 source:transport/ssr |
| `cipher` | 加密方法 | 有 |  |  | 已实现 | 通过 | 取值：`chacha20-ietf` |
| `obfs` | 混淆 | 有 |  |  | 已实现 | 通过 | 取值：`http_post`、`http_simple`、`plain`、`random_head`、`tls1.2_ticket_auth`、`tls1.2_ticket_fastauth` |
| `obfs-param` | 混淆参数 | 有 |  |  | 已实现 | 通过 | 取值：`字符串` |
| `password` | 密码 | 有 |  |  | 已实现 | 通过 | 取值：`字符串` |
| `protocol-param` | 协议参数 | 有 |  |  | 已实现 | 通过 | 取值：`字符串` |
| `udp` | UDP | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true` |

## shadowtls

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | ShadowTLS 出站 |  | 有 |  | 已实现 | 通过 | 取值：`shadowtls` |
| `combo` | ShadowTLS 出站的版本组合 |  | 有 |  | 已实现 | 通过 | version：`1`、`2`、`3`<br>password：`off`、`on`<br>约束：password 仅 v2、v3<br>约束：tls 必填 |
| `password` | 设置密码。 |  | 有 |  | 已实现 | 通过 | 约束：仅在 ShadowTLS v2/v3 协议中可用。 |
| `server` | 服务器地址。 |  | 有 |  | 已实现 | 通过 | 约束：必填 |
| `server-port` | 服务器端口。 |  | 有 |  | 已实现 | 通过 | 约束：必填 |
| `tls` | TLS 配置, 参阅 TLS。 |  | 有 |  | 部分 | 通过 | 约束：必填 |
| `version` | ShadowTLS 协议版本。 |  | 有 |  | 已实现 | 通过 | 取值：`1`、`2`、`3` |

## snell

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | Snell 出站 | 有 | 有 |  | 已实现 | 通过 | 取值：`snell`<br>约束：自 sing-box 1.14.0 起 |
| `combo` | Snell 出站维度 | 有 | 有 |  | 部分 | 通过 | version：`1`、`2`、`3`、`4`、`5`<br>obfs：`http`、`jls`、`none`、`restls`、`shadow-tls`、`tls`<br>udp：`false`、`true`<br>reuse：`false`、`true`<br>约束：reuse 仅 v4、v5<br>约束：udp 仅 v3、v4、v5<br>version：`4`、`6`<br>network：`tcp`、`tcp+udp`、`udp`<br>obfs_mode：`http`、`none`<br>mode：`default`、`unsafe-raw`、`unshaped`<br>reuse：`off`、`on`<br>userkey：`off`、`on`<br>约束：mode 仅 v6<br>约束：obfs_mode、obfs_host 仅 v4<br>约束：v6 的 psk 为 12 到 255 字节<br>约束：version、psk 必填<br>约束：不提供单独的 v4 服务端和 v5 客户端 |
| `client-fingerprint` | 可选，默认 chrome | 有 |  |  | 未实现 | 未测 | 取值：`360`、`android`、`chrome`、`edge`、`firefox`、`ios`、`qq`、`random`、`safari` |
| `mode` | 流量整形模式，`default` `unshaped` `unsafe-raw` 之一。 |  | 有 |  | 已实现 | 通过 | 取值：`default`、`unsafe-raw`、`unshaped`<br>约束：仅版本 6<br>约束：自 sing-box 1.14.0 起<br>约束：默认为 `default`。 |
| `network` | 启用的网络协议。 |  | 有 |  | 部分 | 通过 | 取值：`tcp`、`udp`<br>约束：自 sing-box 1.14.0 起<br>约束：默认所有。 |
| `obfs-host` | `obfs_mode` 为 `http` 时发送的 HTTP `Host` 头。 |  | 有 |  | 已实现 | 通过 | 约束：仅版本 4<br>约束：自 sing-box 1.14.0 起<br>约束：默认为 `bing.com`。 |
| `obfs-mode` | HTTP 混淆模式，`none` `http` 之一。 |  | 有 |  | 已实现 | 通过 | 取值：`http`、`none`<br>约束：仅版本 4<br>约束：自 sing-box 1.14.0 起<br>约束：默认为 `none`。 |
| `obfs-opts-alpn` | ALPN，仅 shadow-tls | 有 |  |  | 未实现 | 未测 | 取值：`h2`、`http1.1` |
| `obfs-opts-host` | 混淆域名 | 有 |  |  | 已实现 | 通过 | 取值：`域名` |
| `obfs-opts-mode` | 混淆模式 | 有 |  |  | 部分 | 通过 | 取值：`http`、`jls`、`restls`、`shadow-tls`、`tls` |
| `obfs-opts-password` | shadow-tls、restls、jls 密码 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `obfs-opts-restls-script` | Restls 脚本 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `obfs-opts-username` | JLS 用户名 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `obfs-opts-version` | shadow-tls 版本 | 有 |  |  | 未实现 | 未测 | 取值：`1`、`2`、`3` |
| `obfs-opts-version-hint` | Restls 版本提示 | 有 |  |  | 未实现 | 未测 | 取值：`tls12`、`tls13` |
| `psk` | 必须，预共享密钥 | 有 | 有 |  | 已实现 | 通过 | 取值：`字符串`<br>约束：必填<br>约束：自 sing-box 1.14.0 起 |
| `reuse` | 可选，默认 false | 有 | 有 |  | 已实现 | 通过 | 取值：`false`、`true`<br>约束：支持 v4、v5<br>约束：自 sing-box 1.14.0 起 |
| `server` | 服务器地址。 |  | 有 |  | 已实现 | 通过 | 约束：必填<br>约束：自 sing-box 1.14.0 起 |
| `server-port` | 服务器端口。 |  | 有 |  | 已实现 | 通过 | 约束：必填<br>约束：自 sing-box 1.14.0 起 |
| `udp` | UDP | 有 |  |  | 部分 | 通过 | 取值：`false`、`true`<br>约束：仅 v3、v4、v5 |
| `userkey` | 用户密钥，用于向多用户服务器进行认证。 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.14.0 起 |
| `version` | 版本 | 有 | 有 |  | 部分 | 通过 | 取值：`1`、`2`、`3`、`4`、`5`、`6`<br>约束：仅 v3、v4、v5 支持 udp<br>约束：必填<br>约束：由于我们有意不支持 Snell v5 的 QUIC 代理模式，v5 的线路协议实际上与 v4 没有区别，因此不提供独立的 v4 服务器和 v5 客户端。<br>约束：自 sing-box 1.14.0 起 |

## socks

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | SOCKS5 出站，type 写 socks5 | 有 | 有 |  | 已实现 | 通过 | 取值：`socks`、`socks5` |
| `socks` | Socks5 出站 |  |  | 有 | 已实现 | 通过 | 取值：`socks`<br>约束：仅支持连接 Socks5 服务器 |
| `combo` | SOCKS 出站维度 | 有 | 有 | 有 | 部分 | 通过 | auth：`none`、`password`<br>tls：`mtls`、`off`、`on`<br>verify：`default`、`fingerprint`、`name-cert-verify`、`skip-cert-verify`<br>udp：`false`、`true`<br>ip-version：`dual`、`ipv4`、`ipv4-prefer`、`ipv6`、`ipv6-prefer`<br>version：`4`、`4a`、`5`<br>auth：`none`、`username/password`<br>network：`tcp`、`tcp+udp`、`udp`<br>udp_over_tcp：`off`、`v1`、`v2`<br>约束：network 留空时 TCP、UDP 都启用<br>约束：password 只用于 SOCKS5<br>transport：`grpc`、`httpupgrade`、`hysteria`、`mkcp`、`raw`、`websocket`、`xhttp`<br>security：`none`、`reality`、`tls`<br>约束：masque 传输不适用<br>约束：未启用 XUDP 时 UDP 走原生路径，绕过已配置传输和 TLS/REALITY |
| `address` | 服务器地址，必填 |  |  | 有 | 已实现 | 通过 |  |
| `email` | 邮箱 |  |  | 有 | 未实现 | 未测 |  |
| `fingerprint` | 证书指纹 | 有 |  |  | 未实现 | 未测 | 取值：`sha256` |
| `level` | 用户等级，默认 0 |  |  | 有 | 未实现 | 未测 |  |
| `network` | 启用的网络协议`tcp` 或 `udp`。 |  | 有 |  | 部分 | 通过 | 取值：`tcp`、`udp`<br>约束：默认所有。 |
| `pass` | 密码，需认证时必填 |  |  | 有 | 已实现 | 通过 |  |
| `password` | 密码 | 有 | 有 |  | 已实现 | 通过 | 取值：`字符串` |
| `port` | 服务器端口，必填 |  |  | 有 | 已实现 | 通过 |  |
| `server` | 服务器地址。 |  | 有 |  | 已实现 | 通过 | 约束：必填 |
| `server-port` | 服务器端口。 |  | 有 |  | 已实现 | 通过 | 约束：必填 |
| `servers` | 旧多服务器写法 |  |  | 有 | 不适用 | 未测 | 约束：只能一个成员，users 至多一个 |
| `tls` | TLS | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `udp` | UDP | 有 |  |  | 部分 | 通过 | 取值：`false`、`true` |
| `udp-over-tcp` | UDP over TCP 配置。 |  | 有 |  | 未实现 | 未测 |  |
| `user` | 用户名，需认证时必填 |  |  | 有 | 已实现 | 通过 |  |
| `username` | 用户名 | 有 | 有 |  | 已实现 | 通过 | 取值：`字符串` |
| `version` | SOCKS 版本, 可为 `4` `4a` `5`. |  | 有 |  | 已实现 | 通过 | 取值：`4`、`4a`、`5`<br>约束：默认使用 SOCKS5。 |

## ssh

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | SSH 出站 | 有 | 有 |  | 已实现 | 通过 | 取值：`ssh` |
| `combo` | SSH 出站维度 | 有 | 有 |  | 部分 | 通过 | auth：`password`、`private-key`、`private-key+passphrase`<br>host-key：`固定`、`接受所有`<br>auth：`password`、`private_key`、`private_key+passphrase`、`private_key_path`<br>host_key：`any`、`pinned`<br>algorithms：`cipher`、`host_key_algorithms`、`kex_algorithm`、`mac`<br>约束：cipher、mac、kex_algorithm 自 1.14.0 起<br>约束：host_key 为空时接受任意主机密钥<br>约束：server 必填<br>约束：server_port 默认 22<br>约束：user 默认 root |
| `cipher` | 允许的加密算法。 |  | 有 |  | 未实现 | 未测 | 约束：留空使用默认值。<br>约束：自 sing-box 1.14.0 起 |
| `client-version` | 客户端版本，默认使用随机值。 |  | 有 |  | 未实现 | 未测 |  |
| `host-key` | 主机密钥，留空接受所有 | 有 | 有 |  | 部分 | 通过 | 取值：`列表` |
| `host-key-algorithms` | 主机密钥算法 | 有 | 有 |  | 未实现 | 未测 | 取值：`rsa` |
| `kex-algorithm` | 允许的密钥交换算法。 |  | 有 |  | 未实现 | 未测 | 约束：留空使用默认值。<br>约束：自 sing-box 1.14.0 起 |
| `mac` | 允许的 MAC 算法。 |  | 有 |  | 未实现 | 未测 | 约束：留空使用默认值。<br>约束：自 sing-box 1.14.0 起 |
| `password` | SSH 密码 | 有 | 有 |  | 已实现 | 通过 | 取值：`字符串` |
| `private-key` | 密钥内容或路径 | 有 | 有 |  | 已实现 | 通过 | 取值：`PEM`、`路径` |
| `private-key-passphrase` | 密钥密码（文档标题写作 private_key_passphrase） | 有 | 有 |  | 已实现 | 通过 | 取值：`字符串` |
| `private-key-path` | 密钥路径。 |  | 有 |  | 已实现 | 通过 |  |
| `server` | 服务器地址。 |  | 有 |  | 已实现 | 通过 | 约束：必填 |
| `server-port` | 服务器端口，默认使用 22。 |  | 有 |  | 已实现 | 通过 |  |
| `user` | SSH 用户, 默认使用 root。 |  | 有 |  | 已实现 | 通过 |  |
| `username` | SSH 用户 | 有 |  |  | 已实现 | 通过 | 取值：`字符串` |

## sudoku

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | Sudoku 出站 | 有 |  |  | 已实现 | 通过 |  |
| `combo` | Sudoku 出站维度 | 有 |  |  | 已实现 | 通过 | aead-method：`aes-128-gcm`、`chacha20-poly1305`、`none`<br>table-type：`prefer_ascii`、`prefer_entropy`、`up_ascii_down_entropy`、`up_entropy_down_ascii`<br>httpmask.mode：`auto`、`disabled`、`legacy`、`poll`、`stream`、`ws`<br>httpmask.tls：`false`、`true`<br>multiplex：`auto`、`off`、`on`<br>enable-pure-downlink：`false`、`true`<br>约束：multiplex auto 仅复用 HTTPMask 底层连接<br>约束：multiplex on 在原始 TCP 或 HTTPMask 上启用单会话多目标 mux |
| `aead-method` | AEAD | 有 |  |  | 已实现 | 通过 | 取值：`aes-128-gcm`、`chacha20-poly1305`、`none` |
| `custom-table` | 字节布局 | 有 |  |  | 已实现 | 通过 | 取值：`xpxvvpvv`<br>约束：2 个 x、2 个 p、4 个 v<br>约束：只对 entropy 方向生效 |
| `custom-tables` | 字节布局列表 | 有 |  |  | 已实现 | 通过 | 取值：`列表`<br>约束：非空覆盖 custom-table |
| `enable-pure-downlink` | 下行模式 | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true`<br>约束：需与服务端一致 |
| `http-mask` | sudoku 出站字段 http-mask（文档页未写，配置结构存在） | 有 |  |  | 已实现 | 通过 |  |
| `http-mask-host` | sudoku 出站字段 http-mask-host（文档页未写，配置结构存在） | 有 |  |  | 已实现 | 通过 |  |
| `http-mask-mode` | sudoku 出站字段 http-mask-mode（文档页未写，配置结构存在） | 有 |  |  | 已实现 | 通过 |  |
| `http-mask-multiplex` | sudoku 出站字段 http-mask-multiplex（文档页未写，配置结构存在） | 有 |  |  | 已实现 | 通过 |  |
| `http-mask-tls` | sudoku 出站字段 http-mask-tls（文档页未写，配置结构存在） | 有 |  |  | 已实现 | 通过 |  |
| `httpmask-disable` | 禁用 HTTP 伪装 | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true` |
| `httpmask-host` | 覆盖 Host、SNI | 有 |  |  | 已实现 | 通过 | 取值：`example.com:443`<br>约束：仅 stream、poll、auto、ws |
| `httpmask-mode` | 模式，stream、poll、auto、ws 支持 CDN | 有 |  |  | 已实现 | 通过 | 取值：`auto`、`legacy`、`poll`、`stream`、`ws` |
| `httpmask-multiplex` | 兼容旧配置，优先于顶层 multiplex | 有 |  |  | 已实现 | 通过 | 取值：`auto`、`off`、`on` |
| `httpmask-path-root` | 隧道一级路径前缀 | 有 |  |  | 已实现 | 通过 | 取值：`字符串`<br>约束：双方需一致 |
| `httpmask-tls` | true 强制 https，false 强制 http | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true`<br>约束：仅 stream、poll、auto、ws |
| `key` | ED25519 私钥或与服务端相同 uuid | 有 |  |  | 已实现 | 通过 | 取值：`字符串` |
| `multiplex` | 多路复用 | 有 |  |  | 已实现 | 通过 | 取值：`auto`、`off`、`on` |
| `padding-max` | 最大填充率 | 有 |  |  | 已实现 | 通过 | 取值：`0-100`<br>约束：>= padding-min |
| `padding-min` | 最小填充率 | 有 |  |  | 已实现 | 通过 | 取值：`0-100` |
| `table-type` | 表类型 | 有 |  |  | 已实现 | 通过 | 取值：`prefer_ascii`、`prefer_entropy`、`up_ascii_down_entropy`、`up_entropy_down_ascii` |

## tailcat

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | Tailcat 出站 |  | 有 |  | 未实现 | 未测 | 取值：`tailcat`<br>约束：自 sing-box 1.15.0 起 |
| `combo` | Tailcat 出站的密钥和 DERP 选择组合 |  | 有 |  | 未实现 | 未测 | private_key：`fixed`、`random`<br>derp：`derp_map_url`、`derp_map_url+derp_region`、`derp_servers`<br>pre_shared_key：`off`、`on`<br>约束：derp_region 与 derp_servers 冲突<br>约束：derp_servers 与 derp_map_url、derp_region 冲突<br>约束：server_public_key、server_disco_key 必填<br>约束：拨号字段只影响连接 DERP<br>约束：服务端校验 users 或 DERP 校验客户端时必须用固定 private_key |
| `derp-map-url` | DERP map 的 URL。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.15.0 起<br>约束：默认使用 `https://tailcat.dev/derpmap.json`。 |
| `derp-region` | DERP map 中的 DERP 区域 ID。 |  | 有 |  | 未实现 | 未测 | 约束：与 `derp_servers` 冲突。<br>约束：自 sing-box 1.15.0 起 |
| `derp-servers` | 自定义 DERP 服务器，参阅 Tailcat 入站的 derp_servers。 |  | 有 |  | 未实现 | 未测 | 约束：与 `derp_map_url` 和 `derp_region` 冲突。<br>约束：自 sing-box 1.15.0 起 |
| `http-client` | 用于获取 DERP map 的 HTTP 客户端。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.15.0 起 |
| `pre-shared-key` | 预共享密钥。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.15.0 起 |
| `private-key` | 私钥。 |  | 有 |  | 未实现 | 未测 | 约束：当服务器通过 `users` 验证客户端，或 DERP 服务器通过 `verify_client_inbound` 或 `verify_client_key`验证客户端时必须设置。<br>约束：自 sing-box 1.15.0 起<br>约束：默认使用随机密钥。 |
| `server-disco-key` | 服务器 disco 公钥。 |  | 有 |  | 未实现 | 未测 | 约束：必填<br>约束：自 sing-box 1.15.0 起 |
| `server-public-key` | 服务器公钥。 |  | 有 |  | 未实现 | 未测 | 约束：必填<br>约束：自 sing-box 1.15.0 起 |

## tailscale

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | Tailscale 出站 | 有 | 有 |  | 已实现 | 通过 | 取值：`tailscale`<br>约束：首次访问超时属正常，节点在首个匹配连接时才启动<br>约束：自 sing-box 1.12.0 起<br>约束：配置在顶层 endpoints，同时具备入站和出站行为 |
| `combo` | Tailscale 出站维度 | 有 | 有 |  | 部分 | 通过 | auth：`auth-key`、`interactive`<br>control：`control-url`、`default`<br>exit-node：`auto:any`、`ip`、`off`<br>accept-routes：`false`、`true`<br>ephemeral：`false`、`true`<br>udp：`false`、`true`<br>dialer-proxy：`off`、`on`<br>约束：访问公网需 exit-node 或覆盖目标的 subnet routes<br>auth：`auth_key`、`login-url`<br>exit_node：`advertise`、`none`、`use`<br>advertise：`advertise_exit_node`、`advertise_routes`、`advertise_tags`<br>interface：`internal`、`system_interface`<br>ssh_server：`object`、`off`、`on`<br>relay_server：`off`、`on`<br>taildrop_directory：`off`、`on`<br>ephemeral：`off`、`on`<br>on_demand：`off`、`on`<br>约束：exit_node 无对应通告路由时，exit_node_allow_lan_access 不能把私网流量发到出口节点<br>约束：ssh_server 的平台限制见页面：Windows 命令行拒绝跨账户、Apple 仅独立版或越狱版、tvOS 不支持<br>约束：拨号字段只影响连接控制面 |
| `accept-routes` | 接受 Tailnet subnet routes | 有 | 有 |  | 已实现 | 通过 | 取值：`false`、`true`<br>约束：自 sing-box 1.12.0 起 |
| `advertise-exit-node` | 指示节点是否应将自己通告为出口节点。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.12.0 起 |
| `advertise-routes` | 通告到 Tailscale 网络的 CIDR 前缀，作为可通过当前节点访问的路由。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.12.0 起 |
| `advertise-tags` | 为此节点通告的标签，用于 ACL 执行。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.13.0 起 |
| `auth-key` | 登录密钥；不填时日志输出交互式登录 URL | 有 | 有 |  | 已实现 | 通过 | 取值：`字符串`<br>约束：自 sing-box 1.12.0 起<br>约束：认证密钥不是必需的。<br>约束：默认情况下，sing-box 将记录登录 URL。 |
| `control-url` | control server 或 Headscale 地址 | 有 | 有 |  | 已实现 | 通过 | 取值：`URL`<br>约束：自 sing-box 1.12.0 起<br>约束：默认使用 `https://controlplane.tailscale.com`。 |
| `ephemeral` | ephemeral node，默认 false | 有 | 有 |  | 已实现 | 通过 | 取值：`false`、`true`<br>约束：自 sing-box 1.12.0 起 |
| `exit-node` | exit node | 有 | 有 |  | 部分 | 通过 | 取值：`auto:any`、`节点 IP`<br>约束：目标不在路由内时直接报错，不回退直连<br>约束：自 sing-box 1.12.0 起 |
| `exit-node-allow-lan-access` | 用 exit node 时允许访问 LAN | 有 | 有 |  | 未实现 | 未测 | 取值：`false`、`true`<br>约束：自 sing-box 1.12.0 起 |
| `hostname` | 设备名 | 有 | 有 |  | 已实现 | 通过 | 取值：`字符串`<br>约束：在 iOS、tvOS 和 Android 上，默认使用设备名称。<br>约束：自 sing-box 1.14.0 起<br>约束：默认使用系统主机名。 |
| `listen-port` | 监听 WireGuard 和点对点流量的 UDP 端口。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：默认自动选择端口。 |
| `on-demand` | 允许该 endpoint 在需要时断开连接。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.15.0 起 |
| `relay-server-port` | 监听来自其他 Tailscale 节点的中继连接的端口。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.13.0 起 |
| `relay-server-static-endpoints` | 为中继服务器通告的静态端点。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.13.0 起 |
| `ssh-server` | 在 tailnet 的 TCP 22 端口上运行 Tailscale SSH 服务器。 |  | 有 |  | 未实现 | 未测 | 约束：- Linux 和 macOS：要切换到 sing-box 运行身份以外的用户需要以 root 运行。<br>约束：- iOS：SSH 服务器仅在越狱版本中可用；App Store 和 TestFlight 版本不支持。<br>约束：- macOS：SSH 服务器仅在独立版本中可用，且需要辅助服务；App Store 版本不支持。<br>约束：- tvOS：暂不支持。<br>约束：以 sing-box 应用自身身份运行无需 root，其他用户则需要已授予的 root 权限。<br>约束：自 sing-box 1.14.0 起 |
| `ssh-server-disable-forwarding` | 拒绝本地和远程的 TCP 与 Unix 套接字转发，包括 SSH agent 转发。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.12.0 起 |
| `ssh-server-disable-pty` | 拒绝 PTY 分配请求。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.12.0 起 |
| `ssh-server-disable-sftp` | 拒绝 SFTP 子系统。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.12.0 起 |
| `ssh-server-enabled` | 启用 SSH 服务器。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.12.0 起 |
| `state-dir` | tsnet 状态目录，默认 tailscale | 有 |  |  | 部分 | 通过 | 取值：`路径` |
| `state-directory` | 存储 Tailscale 状态的目录。 |  | 有 |  | 部分 | 通过 | 约束：自 sing-box 1.12.0 起<br>约束：默认使用 `tailscale`。 |
| `system-interface` | 为 Tailscale 创建系统 TUN 接口。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.13.0 起 |
| `system-interface-mtu` | 覆盖 TUN 的 MTU。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.13.0 起<br>约束：默认使用 Tailscale 自己的 MTU。 |
| `system-interface-name` | 自定义 TUN 接口名。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.13.0 起<br>约束：默认使用 `tailscale`（macOS 上为 `utun`）。 |
| `taildrop-directory` | 存储从 tailnet 对等节点接收到的文件的目录。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：默认使用 `Taildrop`。 |
| `udp-timeout` | UDP NAT 过期时间。 |  | 有 |  | 部分 | 通过 | 约束：自 sing-box 1.12.0 起<br>约束：默认使用 `5m`。 |

## tor

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | Tor 出站 |  | 有 |  | 已实现 | 通过 | 取值：`tor`<br>约束：内嵌 Tor 需 with_embedded_tor 构建标签（需要 CGO） |
| `combo` | Tor 出站的运行方式组合 |  | 有 |  | 部分 | 通过 | binary：`embedded`、`executable_path`<br>data_directory：`off`、`on`<br>torrc：`off`、`on`<br>约束：不设 data_directory 时每次启动很慢<br>约束：内嵌 Tor 需要 with_embedded_tor<br>约束：设了 executable_path 时忽略内嵌 Tor |
| `data-directory` | Tor 的数据目录。 |  | 有 |  | 已实现 | 通过 | 约束：如未设置，每次启动都需要长时间。<br>约束：推荐 |
| `executable-path` | Tor 可执行文件路径如果设置，将覆盖嵌入式 Tor。 |  | 有 |  | 未实现 | 未测 |  |
| `extra-args` | 启动 Tor 时传递的附加参数列表。 |  | 有 |  | 未实现 | 未测 |  |
| `torrc` | torrc 参数表。 |  | 有 |  | 未实现 | 未测 |  |

## trojan

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | Trojan 出站 | 有 | 有 |  | 已实现 | 通过 | 取值：`trojan`<br>约束：tls 强制启用 |
| `trojan` | Trojan 出站 |  |  | 有 | 已实现 | 通过 | 取值：`trojan`<br>约束：源码启动时打印不移除的弃用告警，建议 VLESS |
| `combo` | Trojan 出站维度 | 有 | 有 | 有 | 部分 | 通过 | network：`grpc`、`httpupgrade`、`tcp`、`ws`<br>security：`jls`、`reality`、`restls`、`shadow-tls`、`tls`<br>ech：`off`、`on`<br>client-fingerprint：`360`、`android`、`chrome`、`edge`、`firefox`、`ios`、`none`、`qq`、`random`、`safari`<br>verify：`default`、`fingerprint`、`name-cert-verify`、`skip-cert-verify`<br>mtls：`off`、`on`<br>ss-opts：`aes-128-gcm`、`aes-256-gcm`、`chacha20-ietf-poly1305`、`off`<br>udp：`false`、`true`<br>smux：`h2mux`、`off`、`smux`、`yamux`<br>约束：source:adapter/outbound/trojan.go：ShadowTLS、Restls、JLS、REALITY 互斥<br>security：`none`、`reality+utls`、`tls`、`tls+ech`、`tls+utls`<br>transport：`grpc`、`http`、`httpupgrade`、`none`、`quic`、`ws`<br>network：`tcp`、`tcp+udp`、`udp`<br>multiplex：`h2mux`、`off`、`smux`、`yamux`<br>multiplex_padding：`off`、`on`<br>brutal：`off`、`on`<br>约束：QUIC 下自定义 TLS 只支持 ECH，所以 reality、utls 不能配 quic 传输（docs/configuration/shared/tls.md）<br>约束：brutal 服务端需要 Linux 和 brutal 内核模块<br>约束：http 传输不强制 TLS，无 TLS 时走明文 HTTP/1.1<br>约束：max_connections、min_streams 与 max_streams 冲突<br>约束：network 留空时 TCP、UDP 都启用<br>约束：quic 传输要求 TLS（source:transport/v2ray/transport.go）<br>约束：reality 需要启用 utls（source:common/tls/reality_client.go）<br>约束：入站 padding 开启后拒绝未填充连接<br>约束：标准 gRPC 不默认编入，需 with_grpc 构建标签，否则用默认 gRPC 实现<br>约束：没有 TCP 传输（明文 HTTP 并入 http 传输）、mKCP、DomainSocket（docs/configuration/shared/v2ray-transport.md）<br>transport：`grpc`、`httpupgrade`、`hysteria`、`mkcp`、`raw`、`websocket`、`xhttp`<br>security：`none`、`reality`、`tls`<br>mux：`off`、`on`<br>约束：hysteria 传输须配 tls<br>约束：masque 传输不适用<br>约束：reality 只能配 raw、xhttp、grpc<br>约束：security none 仅允许私有地址，否则启动报错（source:infra/conf/xray.go）<br>约束：公网还要求启用 Mux |
| `address` | 服务端地址，必填 |  |  | 有 | 已实现 | 通过 |  |
| `email` | 邮箱，可选 |  |  | 有 | 未实现 | 未测 |  |
| `flow` | Trojan flow |  |  | 已移除 | 未实现 | 未测 | 约束：配置时报错 |
| `level` | 用户等级，默认 0 |  |  | 有 | 未实现 | 未测 |  |
| `multiplex` | 参阅 多路复用。 |  | 有 |  | 未实现 | 未测 |  |
| `network` | 传输层，其他值为 tcp | 有 | 有 |  | 部分 | 通过 | 取值：`grpc`、`tcp`、`udp`、`ws`<br>约束：默认所有。 |
| `password` | 必须，密码 | 有 | 有 | 有 | 已实现 | 通过 | 取值：`字符串`<br>约束：必填 |
| `port` | 服务端端口 |  |  | 有 | 已实现 | 通过 |  |
| `server` | 服务器地址。 |  | 有 |  | 已实现 | 通过 | 约束：必填 |
| `server-port` | 服务器端口。 |  | 有 |  | 已实现 | 通过 | 约束：必填 |
| `servers` | 旧多服务器写法 |  |  | 有 | 不适用 | 未测 | 约束：只能一个成员 |
| `ss-opts-enabled` | trojan-go shadowsocks AEAD | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `ss-opts-method` | 加密方法 | 有 |  |  | 未实现 | 未测 | 取值：`aes-128-gcm`、`aes-256-gcm`、`chacha20-ietf-poly1305` |
| `ss-opts-password` | AEAD 密码 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `tls` | TLS 配置, 参阅 TLS。 |  | 有 |  | 部分 | 通过 |  |
| `transport` | V2Ray 传输配置，参阅 V2Ray 传输层。 |  | 有 |  | 部分 | 通过 |  |

## trusttunnel

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | TrustTunnel 出站 | 有 |  |  | 已实现 | 通过 |  |
| `combo` | TrustTunnel 出站维度 | 有 |  |  | 部分 | 通过 | http：`h2`、`h3 quic`<br>congestion-controller：`bbr`、`cubic`、`new_reno`<br>reuse：`max-connections+min-streams`、`max-streams`<br>verify：`default`、`fingerprint`、`name-cert-verify`、`skip-cert-verify`<br>client-fingerprint：`360`、`android`、`chrome`、`edge`、`firefox`、`ios`、`none`、`qq`、`random`、`safari`<br>udp：`false`、`true` |
| `bbr-profile` | BBR 档位 | 有 |  |  | 未实现 | 未测 | 取值：`aggressive`、`conservative`、`standard` |
| `congestion-controller` | QUIC 拥塞控制 | 有 |  |  | 未实现 | 未测 | 取值：`bbr`、`cubic`、`new_reno` |
| `cwnd` | trusttunnel 出站字段 cwnd（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `health-check` | 健康检查 | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true` |
| `max-connections` | 最大连接数 | 有 |  |  | 已实现 | 通过 | 取值：`整数`<br>约束：与 max-streams 冲突 |
| `max-streams` | 开新连接前最大流数 | 有 |  |  | 已实现 | 通过 | 取值：`整数`<br>约束：与 max-connections、min-streams 冲突 |
| `min-streams` | 开新连接前最小流数 | 有 |  |  | 未实现 | 未测 | 取值：`整数`<br>约束：与 max-streams 冲突 |
| `password` | 密码 | 有 |  |  | 已实现 | 通过 | 取值：`字符串` |
| `quic` | 开启 QUIC，默认 false | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true` |
| `username` | 用户名 | 有 |  |  | 已实现 | 通过 | 取值：`字符串` |

## tuic

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | TUIC 出站 | 有 | 有 |  | 已实现 | 通过 | 取值：`tuic` |
| `combo` | TUIC 出站维度 | 有 | 有 |  | 部分 | 通过 | version：`v4 token`、`v5 uuid+password`<br>udp-relay-mode：`native`、`quic`<br>congestion-controller：`bbr`、`cubic`、`new_reno`<br>bbr-profile：`aggressive`、`conservative`、`standard`<br>reduce-rtt：`false`、`true`<br>disable-sni：`false`、`true`<br>verify：`default`、`fingerprint`、`name-cert-verify`、`skip-cert-verify`<br>ech：`off`、`on`<br>约束：token 与 uuid、password 互斥<br>congestion_control：`bbr`、`cubic`、`new_reno`<br>udp_mode：`native`、`quic`、`udp_over_stream`<br>zero_rtt_handshake：`off`、`on`<br>network：`tcp`、`tcp+udp`、`udp`<br>约束：network 留空时 TCP、UDP 都启用<br>约束：tls 必填<br>约束：udp_over_stream 需要 sing-box 或兼容实现作服务端<br>约束：udp_relay_mode 与 udp_over_stream 冲突<br>约束：uuid 必填 |
| `alpn` | ALPN | 有 |  |  | 已实现 | 通过 | 取值：`h3` |
| `bbr-profile` | BBR 档位 | 有 |  |  | 未实现 | 未测 | 取值：`aggressive`、`conservative`、`standard` |
| `congestion-control` | QUIC 拥塞控制算法可选值: `cubic`, `new_reno`, `bbr`默认使用 `cubic`。 |  | 有 |  | 已实现 | 通过 | 取值：`bbr`、`cubic`、`new_reno` |
| `congestion-controller` | 拥塞控制 | 有 |  |  | 已实现 | 通过 | 取值：`bbr`、`cubic`、`new_reno` |
| `cwnd` | tuic 出站字段 cwnd（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `disable-mtu-discovery` | tuic 出站字段 disable-mtu-discovery（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `disable-sni` | 禁用 SNI | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `fast-open` | Fast Open | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `heartbeat` | 心跳包发送间隔，默认 10s |  | 有 |  | 已实现 | 通过 |  |
| `heartbeat-interval` | 心跳间隔，毫秒 | 有 |  |  | 已实现 | 通过 | 取值：`整数` |
| `ip` | 覆盖 server 的 DNS 结果 | 有 |  |  | 未实现 | 未测 | 取值：`IP` |
| `max-datagram-frame-size` | tuic 出站字段 max-datagram-frame-size（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `max-open-streams` | 最大打开流 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `max-udp-relay-packet-size` | UDP 中继最大包 | 有 |  |  | 部分 | 通过 | 取值：`整数` |
| `network` | 启用的网络协议。 |  | 有 |  | 部分 | 通过 | 取值：`tcp`、`udp`<br>约束：默认所有。 |
| `password` | 必须，TUIC V5 密码 | 有 | 有 |  | 已实现 | 通过 | 取值：`字符串`<br>约束：使用 V4 时不可书写 |
| `recv-window` | tuic 出站字段 recv-window（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `recv-window-conn` | tuic 出站字段 recv-window-conn（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `reduce-rtt` | 启用 QUIC 0-RTT | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `request-timeout` | 连接超时，毫秒 | 有 |  |  | 部分 | 通过 | 取值：`整数` |
| `server` | 服务器地址。 |  | 有 |  | 已实现 | 通过 | 约束：必填 |
| `server-port` | 服务器端口。 |  | 有 |  | 已实现 | 通过 | 约束：必填 |
| `tls` | TLS 配置, 参阅 TLS。 |  | 有 |  | 部分 | 通过 | 约束：必填 |
| `token` | 必须，TUIC V4 用户标识 | 有 |  |  | 已实现 | 通过 | 取值：`字符串`<br>约束：使用 V5 时不可书写 |
| `udp-over-stream` | tuic 出站字段 udp-over-stream（文档页未写，配置结构存在） | 有 | 有 |  | 未实现 | 未测 | 约束：与 `udp_relay_mode` 冲突。<br>约束：此模式在正确的 UDP 代理场景中没有任何积极作用，仅适用于中继流式 UDP 流量（基本上是 QUIC 流）。<br>约束：由于它是一个附加协议，因此您需要使用 sing-box 或其他兼容的程序作为服务器。 |
| `udp-over-stream-version` | tuic 出站字段 udp-over-stream-version（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `udp-relay-mode` | UDP 中继模式 | 有 | 有 |  | 已实现 | 通过 | 取值：`native`、`quic` |
| `uuid` | 必须，TUIC V5 用户 ID | 有 | 有 |  | 已实现 | 通过 | 取值：`UUID`<br>约束：使用 V4 时不可书写<br>约束：必填 |
| `zero-rtt-handshake` | 启用 QUIC 0-RTT 握手（有重放风险） |  | 有 |  | 未实现 | 未测 |  |

## vless

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | VLESS 出站 | 有 | 有 |  | 已实现 | 通过 | 取值：`vless` |
| `vless` | VLESS 出站 |  |  | 有 | 已实现 | 通过 | 取值：`vless` |
| `combo` | VLESS 出站维度 | 有 | 有 | 有 | 部分 | 通过 | network：`grpc`、`h2`、`http`、`httpupgrade`、`tcp`、`ws`、`xhttp`<br>security：`jls`、`none`、`reality`、`restls`、`shadow-tls`、`tls`<br>ech：`off`、`on`<br>client-fingerprint：`360`、`android`、`chrome`、`edge`、`firefox`、`ios`、`none`、`qq`、`random`、`safari`<br>verify：`default`、`fingerprint`、`name-cert-verify`、`skip-cert-verify`<br>mtls：`off`、`on`<br>flow：``、`xtls-rprx-vision`<br>encryption：``、`native`、`random`、`xorpub`<br>encryption.rtt：`0rtt`、`1rtt`<br>packet-encoding：``、`packetaddr`、`xudp`<br>xhttp.alpn：`h2`、`h3`、`http/1.1`<br>udp：`false`、`true`<br>smux：`h2mux`、`off`、`smux`、`yamux`<br>约束：shadow-tls、restls、jls 需 tls: true<br>约束：smux 仅限 tcp 传输<br>约束：source:adapter/outbound/vless.go：security 模式互斥且需 TLS；xhttp HTTP/3 需 TLS 且不支持这些模式<br>约束：xhttp 仅 VLESS<br>约束：文档未写 Vision 的传输层限制<br>security：`none`、`reality+utls`、`tls`、`tls+ech`、`tls+utls`<br>transport：`grpc`、`http`、`httpupgrade`、`none`、`quic`、`ws`<br>packet_encoding：``、`packetaddr`、`xudp`<br>network：`tcp`、`tcp+udp`、`udp`<br>multiplex：`h2mux`、`off`、`smux`、`yamux`<br>multiplex_padding：`off`、`on`<br>brutal：`off`、`on`<br>约束：QUIC 下自定义 TLS 只支持 ECH，所以 reality、utls 不能配 quic 传输（docs/configuration/shared/tls.md）<br>约束：brutal 服务端需要 Linux 和 brutal 内核模块<br>约束：http 传输不强制 TLS，无 TLS 时走明文 HTTP/1.1<br>约束：max_connections、min_streams 与 max_streams 冲突<br>约束：network 留空时 TCP、UDP 都启用<br>约束：packetaddr 不支持域名目标（source:protocol/vless/outbound.go）<br>约束：quic 传输要求 TLS（source:transport/v2ray/transport.go）<br>约束：reality 需要启用 utls（source:common/tls/reality_client.go）<br>约束：sing-box 文档未写 Vision 对传输层和安全层的限制，需实测<br>约束：入站 padding 开启后拒绝未填充连接<br>约束：标准 gRPC 不默认编入，需 with_grpc 构建标签，否则用默认 gRPC 实现<br>约束：没有 TCP 传输（明文 HTTP 并入 http 传输）、mKCP、DomainSocket（docs/configuration/shared/v2ray-transport.md）<br>约束：默认 xudp<br>transport：`grpc`、`httpupgrade`、`hysteria`、`mkcp`、`raw`、`websocket`、`xhttp`<br>security：`none`、`reality`、`tls`<br>encryption：`mlkem768x25519plus`、`none`<br>flow：``、`xtls-rprx-vision`、`xtls-rprx-vision-udp443`<br>mux：`off`、`on`<br>reverse：`off`、`on`<br>约束：REALITY 只能配 raw、xhttp、grpc<br>约束：Vision 只能配 TCP+TLS/REALITY，或 VLESS Encryption（无传输限制，非 TCP 只穿透 Encryption）<br>约束：hysteria 传输须配 tls<br>约束：masque 传输不适用<br>约束：未启用 Encryption 且 security none 时只允许私有地址，否则启动报错（source:infra/conf/xray.go） |
| `address` | 服务端地址，域名、IPv4、IPv6 |  |  | 有 | 已实现 | 通过 |  |
| `email` | 邮箱，文档未写 |  |  | 有 | 未实现 | 未测 |  |
| `encryption` | vless encryption 客户端配置 | 有 |  | 有 | 已实现 | 通过 | 取值：`mlkem768x25519plus.<外观>.<0rtt\|1rtt>.<padding...>.<认证参数>`、`mlkem768x25519plus.native\|xorpub\|random.1rtt\|0rtt.<padding len>.<padding gap>.<X25519 Password>.<ML-KEM-768 Client>`、`none`<br>约束：native、xorpub 的 Vision 可 Splice<br>约束：padding 默认 100-111-1111.75-0-111.50-0-3333<br>约束：第一个 padding 需概率 100%、至少 35 字节<br>约束：不能留空 |
| `encryption-appearance` | 第 2 块流量外观 |  |  | 有 | 已实现 | 通过 | 取值：`native`、`random`、`xorpub`<br>约束：两端一致 |
| `encryption-auth` | 认证参数 |  |  | 有 | 已实现 | 通过 | 取值：`mlkem768 Client`、`x25519 Password`<br>约束：与服务端对应 |
| `encryption-padding` | padding/delay 块 |  |  | 有 | 部分 | 通过 | 取值：`100-111-1111`、`50-0-3333`、`75-0-111`<br>约束：同入站格式；方向为客户端到服务端 |
| `encryption-resumption` | 第 3 块会话恢复 |  |  | 有 | 已实现 | 通过 | 取值：`0rtt`、`1rtt` |
| `flow` | VLESS 子协议 | 有 | 有 | 有 | 已实现 | 通过 | 取值：``、`xtls-rprx-vision`、`xtls-rprx-vision-udp443`<br>约束：XTLS 仅在 TCP+TLS/REALITY 或 VLESS Encryption 下可用<br>约束：xtls-rprx-vision 拦截 UDP 443，-udp443 不拦截 |
| `id` | 用户 ID：UUID 或小于 30 字节字符串 |  |  | 有 | 部分 | 通过 |  |
| `level` | 用户等级，默认 0 |  |  | 有 | 未实现 | 未测 |  |
| `multiplex` | 参阅 多路复用。 |  | 有 |  | 未实现 | 未测 |  |
| `network` | 传输层，其他值为 tcp | 有 | 有 |  | 部分 | 通过 | 取值：`grpc`、`h2`、`http`、`tcp`、`udp`、`ws`、`xhttp`<br>约束：默认所有。 |
| `packet-addr` | vless 出站字段 packet-addr（文档页未写，配置结构存在） | 有 |  |  | 已实现 | 通过 |  |
| `packet-encoding` | UDP 包编码，空为原始 | 有 | 有 |  | 已实现 | 通过 | 取值：``、`(none)`、`packetaddr`、`xudp` |
| `port` | 服务端端口 |  |  | 有 | 已实现 | 通过 |  |
| `reverse` | 极简反向代理：出站自动向服务端注册隧道，保留公网源 IP |  |  | 有 | 未实现 | 未测 | 约束：UUID 须是服务端配置了 reverse 的用户<br>约束：只支持简化写法，不能用 vnext（source:infra/conf/vless.go） |
| `seed` | Vision Seed 字段，文档未写 |  |  | 实验 | 未实现 | 未测 |  |
| `server` | 服务器地址。 |  | 有 |  | 已实现 | 通过 | 约束：必填 |
| `server-port` | 服务器端口。 |  | 有 |  | 已实现 | 通过 | 约束：必填 |
| `share-link` | VLESS 分享链接标准提案 issues/91 |  |  | 有 | 未实现 | 未测 | 取值：`vless://` |
| `sniffing` | 反向请求的嗅探配置 |  |  | 有 | 未实现 | 未测 |  |
| `tag` | 反向请求进入路由的入站 tag |  |  | 有 | 未实现 | 未测 | 约束：不能为空 |
| `testpre` | 预连接测试字段，文档未写 |  |  | 实验 | 未实现 | 未测 |  |
| `testseed` | padding 种子测试字段，文档未写 |  |  | 实验 | 未实现 | 未测 |  |
| `tls` | TLS 配置, 参阅 TLS。 |  | 有 |  | 部分 | 通过 |  |
| `transport` | V2Ray 传输配置，参阅 V2Ray 传输层。 |  | 有 |  | 部分 | 通过 |  |
| `uuid` | 必须，用户 ID | 有 | 有 |  | 已实现 | 通过 | 取值：`UUID`<br>约束：必填 |
| `vnext` | 旧服务器写法 |  |  | 有 | 不适用 | 未测 | 约束：只能一个成员且一个用户 |
| `ws-headers` | vless 出站字段 ws-headers（文档页未写，配置结构存在） | 有 |  |  | 已实现 | 通过 |  |
| `xudp` | vless 出站字段 xudp（文档页未写，配置结构存在） | 有 |  |  | 已实现 | 通过 |  |

## vmess

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | VMess 出站 | 有 | 有 |  | 已实现 | 通过 | 取值：`vmess` |
| `vmess` | VMess 出站 |  |  | 有 | 已实现 | 通过 | 取值：`vmess`<br>约束：UTC 时间误差须在 120 秒内<br>约束：源码启动时打印不移除的弃用告警，建议 VLESS Encryption |
| `combo` | VMess 出站维度 | 有 | 有 | 有 | 部分 | 通过 | network：`grpc`、`h2`、`http`、`httpupgrade`、`mekya`、`mkcp`、`tcp`、`ws`<br>security：`jls`、`none`、`reality`、`restls`、`shadow-tls`、`tls`、`tlsmirror`<br>ech：`off`、`on`<br>client-fingerprint：`360`、`android`、`chrome`、`edge`、`firefox`、`ios`、`none`、`qq`、`random`、`safari`<br>verify：`default`、`fingerprint`、`name-cert-verify`、`skip-cert-verify`<br>mtls：`off`、`on`<br>cipher：`aes-128-gcm`、`auto`、`chacha20-poly1305`、`none`、`zero`<br>alterId：`0`、`非 0`<br>packet-encoding：``、`packetaddr`、`xudp`<br>global-padding：`false`、`true`<br>authenticated-length：`false`、`true`<br>udp：`false`、`true`<br>smux：`h2mux`、`off`、`smux`、`yamux`<br>mkcp.header：`dtls`、`none`、`srtp`、`utp`、`wechat-video`、`wireguard`<br>约束：H2 未实现多路复用<br>约束：mkcp、mekya、tlsmirror 仅 VMess<br>约束：shadow-tls、restls、jls 需 tls: true<br>约束：smux 仅限 tcp 传输<br>约束：source:adapter/outbound/vmess.go：security 五种模式互斥，均需 TLS；mkcp 不支持 ShadowTLS、Restls、JLS<br>security_cipher：`aes-128-ctr`、`aes-128-gcm`、`auto`、`chacha20-poly1305`、`none`、`zero`<br>tls：`none`、`reality+utls`、`tls`、`tls+ech`、`tls+utls`<br>transport：`grpc`、`http`、`httpupgrade`、`none`、`quic`、`ws`<br>alter_id：`0`、`1`<br>packet_encoding：``、`packetaddr`、`xudp`<br>network：`tcp`、`tcp+udp`、`udp`<br>global_padding：`off`、`on`<br>authenticated_length：`off`、`on`<br>multiplex：`h2mux`、`off`、`smux`、`yamux`<br>multiplex_padding：`off`、`on`<br>brutal：`off`、`on`<br>约束：QUIC 下自定义 TLS 只支持 ECH，所以 reality、utls 不能配 quic 传输（docs/configuration/shared/tls.md）<br>约束：brutal 服务端需要 Linux 和 brutal 内核模块<br>约束：http 传输不强制 TLS，无 TLS 时走明文 HTTP/1.1<br>约束：max_connections、min_streams 与 max_streams 冲突<br>约束：network 留空时 TCP、UDP 都启用<br>约束：packetaddr 不支持域名目标（source:protocol/vmess/outbound.go）<br>约束：quic 传输要求 TLS（source:transport/v2ray/transport.go）<br>约束：reality 需要启用 utls（source:common/tls/reality_client.go）<br>约束：入站 padding 开启后拒绝未填充连接<br>约束：标准 gRPC 不默认编入，需 with_grpc 构建标签，否则用默认 gRPC 实现<br>约束：没有 TCP 传输（明文 HTTP 并入 http 传输）、mKCP、DomainSocket（docs/configuration/shared/v2ray-transport.md）<br>transport：`grpc`、`httpupgrade`、`hysteria`、`mkcp`、`raw`、`websocket`、`xhttp`<br>security：`none`、`reality`、`tls`<br>cipher：`aes-128-gcm`、`auto`、`chacha20-poly1305`<br>mux：`off`、`on`<br>约束：hysteria 传输须配 tls<br>约束：masque 传输不适用<br>约束：reality 只能配 raw、xhttp、grpc |
| `address` | 服务端地址 |  |  | 有 | 已实现 | 通过 |  |
| `alter-id` | VMess alter_id，0 用 AEAD，1 用旧协议，大于 1 等同 1 |  | 有 |  | 未实现 | 未测 | 取值：`0`、`1`、`> 1` |
| `alterid` | 必须，不为 0 启用旧协议 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `authenticated-length` | 长度块加密 | 有 | 有 |  | 已实现 | 通过 | 取值：`false`、`true` |
| `cipher` | 必须，加密方法 | 有 |  |  | 部分 | 通过 | 取值：`aes-128-gcm`、`auto`、`chacha20-poly1305`、`none`、`zero` |
| `email` | 邮箱，文档未写 |  |  | 有 | 未实现 | 未测 |  |
| `experiments` | 实验功能，用 \| 分隔 |  |  | 实验 | 已实现 | 通过 | 取值：`AuthenticatedLength`、`NoTerminationSignal`<br>约束：AuthenticatedLength 需两端同开且同版本<br>约束：NoTerminationSignal 现默认启用<br>约束：可能随时被移除 |
| `global-padding` | 随机浪费流量（v2ray 默认启用且不可禁） | 有 | 有 |  | 已实现 | 通过 | 取值：`false`、`true`<br>约束：如果启用会随机浪费流量（在 v2ray 中默认启用并且无法禁用）。 |
| `id` | 用户 ID：UUID 或小于 30 字节字符串 |  |  | 有 | 部分 | 通过 |  |
| `level` | 用户等级，默认 0 |  |  | 有 | 未实现 | 未测 |  |
| `max-simultaneous-write-connection` | vmess 出站字段 max-simultaneous-write-connection（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `max-write-duration-ms` | vmess 出站字段 max-write-duration-ms（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `max-write-size` | vmess 出站字段 max-write-size（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `multiplex` | 参阅 多路复用。 |  | 有 |  | 未实现 | 未测 |  |
| `network` | 传输层，其他值为 tcp | 有 | 有 |  | 部分 | 通过 | 取值：`grpc`、`h2`、`http`、`mekya`、`mkcp`、`tcp`、`udp`、`ws`<br>约束：默认所有。 |
| `packet-addr` | vmess 出站字段 packet-addr（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `packet-encoding` | UDP 包编码，空为原始 | 有 | 有 |  | 未实现 | 未测 | 取值：``、`(none)`、`packetaddr`、`xudp` |
| `packet-writing-buffer` | vmess 出站字段 packet-writing-buffer（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `port` | 服务端端口，必填 |  |  | 有 | 已实现 | 通过 |  |
| `security` | 加密方法： |  | 有 | 有 | 部分 | 通过 | 取值：`aes-128-ctr`、`aes-128-gcm`、`auto`、`chacha20-poly1305`、`none`、`zero`<br>约束：aes-128-ctr 为旧版方法<br>约束：auto 在 AMD64、ARM64、s390x 选 aes-128-gcm，其他 chacha20<br>约束：源码未知值按 auto（source:infra/conf/vmess.go） |
| `server` | 服务器地址。 |  | 有 |  | 已实现 | 通过 | 约束：必填 |
| `server-port` | 服务器端口。 |  | 有 |  | 已实现 | 通过 | 约束：必填 |
| `tls` | TLS 配置, 参阅 TLS。 |  | 有 |  | 部分 | 通过 |  |
| `transport` | V2Ray 传输配置，参阅 V2Ray 传输层。 |  | 有 |  | 部分 | 通过 |  |
| `uuid` | 必须，用户 ID | 有 | 有 |  | 已实现 | 通过 | 取值：`UUID`<br>约束：必填 |
| `vnext` | 旧服务器写法 |  |  | 有 | 不适用 | 未测 |  |
| `xudp` | vmess 出站字段 xudp（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |

## wireguard

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | WireGuard 出站，含 AmneziaWG | 有 | 已移除 |  | 已实现 | 通过 | 取值：`wireguard`<br>约束：1.11.0 废弃，1.13.0 移除；配置后启动报错（source:include/registry.go）<br>约束：用 WireGuard 端点替代<br>约束：自 sing-box 1.11.0 起<br>约束：配置在顶层 endpoints，同时具备入站和出站行为 |
| `wireguard` | 用户态 WireGuard 出站 |  |  | 有 | 已实现 | 通过 | 取值：`wireguard` |
| `combo` | WireGuard 出站维度 | 有 | 有 | 有 | 部分 | 通过 | topology：`peers`、`single-peer`<br>address：`ipv4`、`ipv4+ipv6`<br>amnezia：`off`、`v1.0`、`v1.5`、`v2`、`v3`、`v3.1`<br>ip-stack.mode：`auto`、`gvisor`、`mips`<br>remote-dns-resolve：`false`、`true`<br>udp：`false`、`true`<br>dialer-proxy：`off`、`on`<br>约束：relay 中不支持 wireguard<br>约束：多 peer 时 allowed-ips 需区分<br>interface：`internal`、`system`<br>peer_endpoint：`fixed`、`listen-only`<br>pre_shared_key：`off`、`on`<br>persistent_keepalive：`off`、`on`<br>reserved：`off`、`on`<br>on_demand：`off`、`on`<br>udp_nat：`udp_filtering`、`udp_mapping`、`udp_nat_max`、`udp_timeout`<br>约束：MTU 默认 1408<br>约束：address、private_key、peers、peers.public_key、peers.allowed_ips 必填<br>约束：on_demand 自 1.15.0 起<br>约束：system 需要特权且不能与现有系统接口冲突<br>transport：`不适用`<br>security：`不适用`<br>packet_stack：`gvisor`、`kernel_tun`<br>address_family：`dual`、`ipv4`、`ipv6`<br>finalmask：`none`、`udp`<br>chain：`dialerProxy`、`direct`<br>约束：udphop intervallocal 支持 wireguard（docs/config/transports/finalmask.md）<br>约束：传输方式和传输安全均不适用<br>约束：隧道内目标必须为 IP |
| `address` | 接口的 IPv4/IPv6 地址或地址段的列表。 |  | 有 | 有 | 已实现 | 通过 | 约束：必填<br>约束：自 sing-box 1.11.0 起<br>约束：多个时按 peer 自动选择 |
| `allowed-ips` | 可选，由服务端转发的段 | 有 |  | 有 | 已实现 | 通过 | 取值：`CIDR 列表` |
| `amnezia-wg-option-content-padding-addition` | AmneziaWG v3+ | 有 |  |  | 未实现 | 未测 | 取值：`0-32` |
| `amnezia-wg-option-disable-cookies` | AmneziaWG v3.1+ | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `amnezia-wg-option-h1` | v1.0、v1.5 仅单值；v2+ 支持范围 | 有 |  |  | 未实现 | 未测 | 取值：`整数`、`范围` |
| `amnezia-wg-option-h2` | v1.0、v1.5 仅单值；v2+ 支持范围 | 有 |  |  | 未实现 | 未测 | 取值：`整数`、`范围` |
| `amnezia-wg-option-h3` | v1.0、v1.5 仅单值；v2+ 支持范围 | 有 |  |  | 未实现 | 未测 | 取值：`整数`、`范围` |
| `amnezia-wg-option-h4` | v1.0、v1.5 仅单值；v2+ 支持范围 | 有 |  |  | 未实现 | 未测 | 取值：`整数`、`范围` |
| `amnezia-wg-option-header-protection-key` | AmneziaWG v3+ | 有 |  |  | 未实现 | 未测 | 取值：`base64` |
| `amnezia-wg-option-i1` | AmneziaWG v1.5+ | 有 |  |  | 未实现 | 未测 | 取值：`标签串` |
| `amnezia-wg-option-i2` | AmneziaWG v1.5+ | 有 |  |  | 未实现 | 未测 | 取值：`标签串` |
| `amnezia-wg-option-i3` | AmneziaWG v1.5+ | 有 |  |  | 未实现 | 未测 | 取值：`标签串` |
| `amnezia-wg-option-i4` | AmneziaWG v1.5+ | 有 |  |  | 未实现 | 未测 | 取值：`标签串` |
| `amnezia-wg-option-i5` | AmneziaWG v1.5+ | 有 |  |  | 未实现 | 未测 | 取值：`标签串` |
| `amnezia-wg-option-itime` | 仅 AmneziaWG v1.5 | 有 |  |  | 未实现 | 未测 | 取值：`整数`<br>约束：v2+ 已移除 |
| `amnezia-wg-option-j1` | 仅 AmneziaWG v1.5 | 有 |  |  | 未实现 | 未测 | 取值：`标签串`<br>约束：v2+ 已移除 |
| `amnezia-wg-option-j2` | 仅 AmneziaWG v1.5 | 有 |  |  | 未实现 | 未测 | 取值：`标签串`<br>约束：v2+ 已移除 |
| `amnezia-wg-option-j3` | 仅 AmneziaWG v1.5 | 有 |  |  | 未实现 | 未测 | 取值：`标签串`<br>约束：v2+ 已移除 |
| `amnezia-wg-option-jc` | AmneziaWG v1.0+ | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `amnezia-wg-option-jmax` | AmneziaWG v1.0+ | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `amnezia-wg-option-jmin` | AmneziaWG v1.0+ | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `amnezia-wg-option-keepalive-timeout` | AmneziaWG v3+ | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `amnezia-wg-option-max-handshake-attempts` | AmneziaWG v3+ | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `amnezia-wg-option-random-trailers` | AmneziaWG v3.1+ | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `amnezia-wg-option-reject-after-time` | AmneziaWG v3+ | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `amnezia-wg-option-rekey-after-time` | AmneziaWG v3+ | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `amnezia-wg-option-rekey-timeout` | AmneziaWG v3+ | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `amnezia-wg-option-s1` | AmneziaWG v1.0+ | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `amnezia-wg-option-s2` | AmneziaWG v1.0+ | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `amnezia-wg-option-s3` | AmneziaWG v1.5+ | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `amnezia-wg-option-s4` | AmneziaWG v1.5+ | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `amnezia-wg-option-version` | 只有 3 用 v3 实现，其余用旧版 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `dns` | 可选，remote-dns-resolve 时使用 | 有 |  |  | 未实现 | 未测 | 取值：`IP 列表` |
| `endpoint` | 服务器地址和端口，必填 |  |  | 有 | 已实现 | 通过 |  |
| `gso` | 尝试启用通用分段卸载。 |  | 已移除 |  | 未实现 | 未测 | 约束：仅支持 Linux。<br>约束：自 sing-box 1.8.0 起 |
| `interface-name` | 为系统接口自定义设备名称。 |  | 已移除 |  | 未实现 | 未测 |  |
| `ip` | 本机 IPv4 | 有 |  |  | 已实现 | 通过 | 取值：`IP` |
| `ip-stack-congestion-controller` | TCP 拥塞控制，默认 cubic | 有 |  |  | 未实现 | 未测 | 取值：`bbr`、`bbr3`、`cubic`、`reno`<br>约束：gVisor 下不生效 |
| `ip-stack-mode` | IP 协议栈，默认 auto | 有 |  |  | 未实现 | 未测 | 取值：`auto`、`gvisor`、`mips`<br>约束：auto 用 MIPS<br>约束：gvisor 需 -tags with_gvisor |
| `ipv6` | 本机 IPv6，可选 | 有 |  |  | 已实现 | 通过 | 取值：`IP` |
| `keep-alive` | 保活间隔（秒），默认 0 |  |  | 有 | 已实现 | 通过 |  |
| `listen-port` | WireGuard 本地监听端口 |  | 有 |  | 部分 | 通过 | 约束：自 sing-box 1.11.0 起 |
| `local-address` | 接口的 IPv4/IPv6 地址或地址段的列表。 |  | 已移除 |  | 已实现 | 通过 | 约束：必填 |
| `mtu` | 可选，MTU | 有 | 有 | 有 | 已实现 | 通过 | 取值：`整数`<br>约束：1408 will be used if empty.<br>约束：`1408` will be used by default.<br>约束：自 sing-box 1.11.0 起<br>约束：默认使用 1408。 |
| `name` | 为系统接口自定义设备名称。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.11.0 起 |
| `network` | 启用的网络协议`tcp` 或 `udp`。 |  | 已移除 |  | 部分 | 通过 | 取值：`tcp`、`udp`<br>约束：默认所有。 |
| `no-kernel-tun` | 强制不用系统 TUN，默认 false |  |  | 有 | 部分 | 通过 | 取值：`false`、`true`<br>约束：LXC/Docker 可能需 true<br>约束：用 TUN 时占 IPv6 路由表 10230 起，第二实例会冲突<br>约束：默认 Linux 且有 CAP_NET_ADMIN 时用 TUN，否则 gVisor |
| `on-demand` | 允许该 endpoint 在需要时断开连接。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.15.0 起 |
| `peer-public-key` | WireGuard 对等公钥。 |  | 已移除 |  | 已实现 | 通过 | 约束：必填 |
| `peers` | 完整写法多 peer；顶层 server、port、public-key、pre-shared-key、reserved 被忽略 | 有 | 有 | 有 | 部分 | 通过 | 取值：`列表`<br>约束：private-key 仍在顶层<br>约束：多 peer 时 allowed-ips 需区分<br>约束：If enabled, `server, server_port, peer_public_key, pre_shared_key` will be ignored.<br>约束：必填<br>约束：自 sing-box 1.11.0 起 |
| `peers-address` | 对等方的 IP 地址。 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.11.0 起 |
| `peers-allowed-ips` | 对等方的允许 IP 地址。 |  | 有 |  | 已实现 | 通过 | 约束：必填<br>约束：自 sing-box 1.11.0 起 |
| `peers-persistent-keepalive-interval` | 对等方的持久性保持活动间隔，以秒为单位。 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.11.0 起<br>约束：默认禁用。 |
| `peers-port` | 对等方的 WireGuard 端口。 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.11.0 起 |
| `peers-pre-shared-key` | 对等方的预共享密钥。 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.11.0 起 |
| `peers-public-key` | 对等方的 WireGuard 公钥。 |  | 有 |  | 已实现 | 通过 | 约束：必填<br>约束：自 sing-box 1.11.0 起 |
| `peers-reserved` | 对等方的保留字段字节。 |  | 有 |  | 未实现 | 未测 | 约束：`$outbound.reserved` will be used if empty.<br>约束：自 sing-box 1.11.0 起 |
| `peers-server` | 服务器地址 |  | 已移除 |  | 已实现 | 通过 |  |
| `peers-server-port` | 服务器端口 |  | 已移除 |  | 已实现 | 通过 |  |
| `persistent-keepalive` | 可选，保活 | 有 |  |  | 已实现 | 通过 | 取值：`整数` |
| `pre-shared-key` | 可选，预共享密钥 | 有 | 已移除 | 有 | 已实现 | 通过 | 取值：`base64` |
| `private-key` | base64 客户端私钥 | 有 | 有 |  | 已实现 | 通过 | 取值：`base64`<br>约束：必填<br>约束：自 sing-box 1.11.0 起 |
| `public-key` | base64 服务端公钥 | 有 |  | 有 | 已实现 | 通过 | 取值：`base64` |
| `refresh-server-ip-interval` | wireguard 出站字段 refresh-server-ip-interval（文档页未写，配置结构存在） | 有 |  |  | 未实现 | 未测 |  |
| `remote-dns` | 解析被代理域名的 DNS，默认 1.1.1.1、1.0.0.1、2606:4700:4700::1111、2606:4700:4700::1001 |  |  | 有 | 未实现 | 未测 | 约束：双栈优先 IPv4<br>约束：必须为 IP<br>约束：请求直接走隧道；接入内置 DNS 用 targetStrategy |
| `remote-dns-resolve` | 可选，强制远程解析，默认 false | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `reserved` | 可选，保留字段 | 有 | 已移除 | 有 | 未实现 | 未测 | 取值：`U4An`、`[209,98,59]`<br>约束：为空或 3 字节，否则报错（source:infra/conf/wireguard.go） |
| `secret-key` | 客户端私钥，必填 |  |  | 有 | 已实现 | 通过 |  |
| `server` | 服务器地址。 |  | 已移除 |  | 已实现 | 通过 | 约束：必填 |
| `server-port` | 服务器端口。 |  | 已移除 |  | 已实现 | 通过 | 约束：必填 |
| `system` | 使用系统设备。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.11.0 起<br>约束：需要特权且不能与已有系统接口冲突。 |
| `system-interface` | 使用系统设备。 |  | 已移除 |  | 未实现 | 未测 | 约束：需要特权且不能与已有系统接口冲突。 |
| `warp-guide` | 通过 WireGuard 接入 WARP、回国流量分流、链式代理用法 |  |  | 有 | 不适用 | 未测 |  |
| `workers` | wireguard 出站字段 workers（文档页未写，配置结构存在） | 有 | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.11.0 起<br>约束：默认使用 CPU 数量。 |

## zerotier

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | ZeroTier 出站 | 有 |  |  | 已实现 | 通过 |  |
| `combo` | ZeroTier 出站维度 | 有 |  |  | 部分 | 通过 | tcp-fallback-mode：`auto`、`disable`、`force`<br>root：`earth`、`orbit`、`planet`<br>ip-stack.mode：`auto`、`gvisor`、`mips`<br>remote-dns-resolve：`false`、`true` |
| `dns` | 覆盖控制器 DNS | 有 |  |  | 未实现 | 未测 | 取值：`IP 列表` |
| `encrypted-hello` | 默认 false | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `identity-secret` | identity.secret 内容，覆盖 state-dir 身份且不写入 | 有 |  |  | 已实现 | 通过 | 取值：`字符串` |
| `ip-stack-congestion-controller` | TCP 拥塞控制，默认 cubic | 有 |  |  | 未实现 | 未测 | 取值：`bbr`、`bbr3`、`cubic`、`reno`<br>约束：gVisor 下不生效 |
| `ip-stack-mode` | IP 协议栈，默认 auto | 有 |  |  | 未实现 | 未测 | 取值：`auto`、`gvisor`、`mips`<br>约束：auto 用 MIPS<br>约束：gvisor 需 -tags with_gvisor |
| `low-bandwidth` | 低带宽，默认 false | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `mtu` | 本地 MTU，不能超过控制器提供值 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `network` | 网络 ID | 有 |  |  | 已实现 | 通过 | 取值：`16 位十六进制` |
| `orbit-seed` | Moon 根节点 Node ID | 有 |  |  | 部分 | 通过 | 取值：`10 位` |
| `orbit-world` | Moon World ID | 有 |  |  | 部分 | 通过 | 取值：`16 位十六进制` |
| `physical-mtu` | UDP 负载 MTU，默认 1432 | 有 |  |  | 未实现 | 未测 | 取值：`510-10324` |
| `planet` | 私有 Planet 路径 | 有 |  |  | 部分 | 通过 | 取值：`路径` |
| `primary-port` | 主 UDP 端口，0 自动 | 有 |  |  | 部分 | 通过 | 取值：`端口` |
| `remote-dns-resolve` | 经控制器 DNS 解析目标 | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `remote-trace-level` | 诊断级别 | 有 |  |  | 未实现 | 未测 | 取值：`0`、`10`、`15`、`20`、`30` |
| `remote-trace-target` | 接收诊断的节点 ID | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `secondary-port` | 第二 UDP 端口，0 自动，-1 禁用 | 有 |  |  | 未实现 | 未测 | 取值：`-1`、`0`、`端口` |
| `state-dir` | 节点状态与默认身份目录 | 有 |  |  | 部分 | 通过 | 取值：`路径` |
| `tcp-fallback-mode` | TCP 回退，默认 auto | 有 |  |  | 未实现 | 未测 | 取值：`auto`、`disable`、`force` |
| `tcp-fallback-relay` | TCP 回退中继 | 有 |  |  | 未实现 | 未测 | 取值：`host:port` |
| `udp` | UDP，默认 true | 有 |  |  | 部分 | 通过 | 取值：`false`、`true` |
