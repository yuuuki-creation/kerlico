# 嗅探

由 `tools/capability_matrix.py build` 生成，不要手改。

## action

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | 嗅探动作的触发方式、嗅探器和超时组合 |  | 有 |  | 已实现 | 通过 | trigger：`pre-match sniff(UDP)`、`route action sniff`<br>sniffer：`bittorrent`、`dns`、`dtls`、`http`、`ntp`、`quic`、`rdp`、`ssh`、`stun`、`tls`<br>timeout：`custom`、`default-300ms`<br>约束：inbound.sniff 旧字段已移除<br>约束：默认启用全部嗅探器 |

## protocol

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `bittorrent` | 嗅探 bittorrent：网络 TCP/UDP，域名来源 无，客户端信息 无 |  | 有 | 有 | 未实现 | 未测 | 取值：`bittorrent`<br>约束：destOverride 不接受 bittorrent（source:infra/conf/xray.go）<br>约束：只有基础嗅探，对加密和混淆流量可能无效 |
| `dns` | 嗅探 dns：网络 TCP/UDP，域名来源 无，客户端信息 无 |  | 有 |  | 未实现 | 未测 | 取值：`dns` |
| `dtls` | 嗅探 dtls：网络 UDP，域名来源 无，客户端信息 无 |  | 有 |  | 未实现 | 未测 | 取值：`dtls` |
| `ech-limit` | ECH 时只能看到 Outer Hello 域名 |  |  | 有 | 未实现 | 未测 |  |
| `http` | 嗅探 http：网络 TCP，域名来源 Host，客户端信息 无 |  | 有 |  | 已实现 | 通过 | 取值：`http` |
| `ntp` | 嗅探 ntp：网络 UDP，域名来源 无，客户端信息 无 |  | 有 |  | 未实现 | 未测 | 取值：`ntp` |
| `quic` | 嗅探 quic：网络 UDP，域名来源 Server Name，客户端信息 QUIC 客户端类型 |  | 有 |  | 已实现 | 通过 | 取值：`quic` |
| `rdp` | 嗅探 rdp：网络 TCP，域名来源 无，客户端信息 无 |  | 有 |  | 未实现 | 未测 | 取值：`rdp` |
| `ssh` | 嗅探 ssh：网络 TCP，域名来源 无，客户端信息 SSH 客户端名 |  | 有 |  | 未实现 | 未测 | 取值：`ssh` |
| `stun` | 嗅探 stun：网络 UDP，域名来源 无，客户端信息 无 |  | 有 |  | 未实现 | 未测 | 取值：`stun` |
| `tls` | 嗅探 tls：网络 TCP，域名来源 Server Name，客户端信息 无 |  | 有 |  | 已实现 | 通过 | 取值：`tls` |

## quic-client

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `type` | QUIC 客户端类型识别结果 |  | 有 |  | 未实现 | 未测 | 取值：`chromium`、`firefox`、`quic-go`、`safari`<br>约束：Chromium/Cronet→chromium，Safari/Apple Network API→safari，Firefox/uquic firefox→firefox，quic-go/uquic chrome→quic-go |

## sniffer

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `enable` | 启用 sniffer | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true` |
| `force-dns-mapping` | 对 redir-host 识别的流量强制嗅探 | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `force-domain` | 强制嗅探域名列表，域名通配 | 有 |  |  | 已实现 | 未测 | 取值：`通配域名` |
| `override-destination` | 用嗅探结果作为实际访问，默认 true | 有 |  |  | 已实现 | 未测 | 取值：`false`、`true` |
| `parse-pure-ip` | 对所有未获取到域名的流量强制嗅探 | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true` |
| `port-whitelist` | 旧写法，仅对白名单端口嗅探，默认 443、80；配置 sniff 后无效 | 废弃 |  |  | 不适用 | 未测 | 取值：`端口列表` |
| `skip-domain` | 跳过嗅探的域名列表，域名通配 | 有 |  |  | 已实现 | 通过 | 取值：`通配域名` |
| `skip-dst-address` | 跳过嗅探的目标 IP 段 | 有 |  |  | 未实现 | 未测 | 取值：`CIDR 列表` |
| `skip-src-address` | 跳过嗅探的来源 IP 段 | 有 |  |  | 未实现 | 未测 | 取值：`CIDR 列表` |
| `sniff` | 需要嗅探的协议 | 有 |  |  | 已实现 | 未测 | 取值：`HTTP`、`QUIC`、`TLS`<br>约束：source:docs/config.yaml：TLS、QUIC 未配 ports 默认 443，HTTP 默认 80<br>约束：仅支持这三种 |
| `sniff-override-destination` | 协议级覆盖全局 override-destination | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `sniff-ports` | 协议嗅探端口范围 | 有 |  |  | 已实现 | 未测 | 取值：`端口范围` |
| `sniffing` | 旧写法，需要嗅探的协议；配置 sniff 后无效 | 废弃 |  |  | 不适用 | 未测 | 取值：`http`、`tls` |

## sniffing

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | 嗅探组合 |  |  | 有 | 已实现 | 通过 | protocols：`fakedns`、`http`、`quic`、`tls`<br>route_only：`false`、`true`<br>metadata_only：`false`、`true`<br>exclude：`domainsExcluded`、`ipsExcluded`、`none`<br>location：`inbound`、`loopback`、`vless reverse outbound`<br>约束：VLESS 入站 reverse 不能有 sniffing<br>约束：metadataOnly 时只能 fakedns<br>约束：routeOnly+destOverride+AsIs 可全程无 DNS 分流 |
| `dest-override` | 按指定类型重置目标 |  |  | 有 | 已实现 | 未测 | 取值：`fakedns`、`http`、`quic`、`tls`<br>约束：源码别名 https、ssl 同 tls；fakedns+others 同 fakedns（source:infra/conf/xray.go） |
| `domains-excluded` | 结果在列表内时不重置目标 |  |  | 有 | 已实现 | 未测 | 取值：`Mijia Cloud`、`courier.push.apple.com`、`dlg.io.mi.com` |
| `enabled` | 是否开启流量探测 |  |  | 有 | 已实现 | 未测 |  |
| `ips-excluded` | 目标 IP 在列表内时不重置 |  |  | 有 | 未实现 | 未测 |  |
| `metadata-only` | 只用元数据嗅探 |  |  | 有 | 未实现 | 未测 | 约束：关闭时客户端须先发数据，与服务端先发协议（SMTP）不兼容<br>约束：启用后除 fakedns 外不激活 |
| `route-only` | 嗅探域名只用于路由，默认 false |  |  | 有 | 已实现 | 未测 | 约束：需要 destOverride |
