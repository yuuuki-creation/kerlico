# UDP 处理

由 `tools/capability_matrix.py build` 生成，不要手改。

## handling

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | UDP 承载机制和使用它们的协议 |  | 有 |  | 部分 | 通过 | mechanism：`multiplex`、`packetaddr`、`tuic-native`、`tuic-quic`、`tuic-udp_over_stream`、`uot-v1`、`uot-v2`、`xudp`<br>uot_consumer：`naive`、`shadowsocks`、`socks`、`tuic(udp_over_stream)`<br>packet_encoding_consumer：`vless`、`vmess`<br>约束：UoT 是 SagerNet 私有协议，默认版本 2<br>约束：UoT 结构可写成布尔值<br>约束：shadowsocks 的 udp_over_tcp 与 multiplex 冲突 |

## hysteria

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `native` | Hysteria QUIC native UDP，udpIdleTimeout 控制空闲 |  |  | 有 | 已实现 | 通过 |  |

## matrix

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | UDP 处理组合 |  |  | 有 | 部分 | 通过 | protocol：`http`、`hysteria`、`masque`、`shadowsocks`、`socks`、`trojan`、`vless`、`vmess`、`wireguard`<br>mode：`ip_tunnel`、`native`、`quic_native`、`unsupported`、`uot`、`xudp`<br>约束：http 不支持 UDP<br>约束：hysteria 只有配 hysteria 传输才能代理 UDP<br>约束：shadowsocks、socks 未启用 XUDP 时走原生路径<br>约束：vless 原生为 UoT<br>约束：wireguard、masque 走 IP 隧道 |

## nat

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `udp-filtering` | UDP NAT 过滤行为。 |  | 有 |  | 未实现 | 未测 | 取值：`address_and_port_dependent`、`address_dependent`、`endpoint_independent`<br>约束：自 sing-box 1.14.0 起<br>约束：默认使用 `endpoint_independent`。 |
| `udp-mapping` | UDP NAT 映射行为。 |  | 有 |  | 未实现 | 未测 | 取值：`address_and_port_dependent`、`address_dependent`、`endpoint_independent`<br>约束：自 sing-box 1.14.0 起<br>约束：默认使用 `endpoint_independent`。 |
| `udp-nat-max` | UDP NAT 会话的最大数量。 |  | 有 |  | 部分 | 通过 | 约束：自 sing-box 1.14.0 起 |
| `udp-timeout` | UDP NAT 过期时间。 |  | 有 |  | 已实现 | 通过 | 约束：默认使用 `5m`。 |

## native

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `shadowsocks` | Shadowsocks 使用原生 UDP |  |  | 有 | 已实现 | 通过 |  |

## packet-encoding

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `packet-encoding` | VLESS 和 VMess 出站的 UDP 包编码 |  | 有 |  | 部分 | 通过 | 取值：``、`packetaddr`、`xudp`<br>约束：VLESS 默认 xudp<br>约束：packetaddr 不支持域名目标（source:protocol/vless/outbound.go）<br>约束：packetaddr 由 v2ray 5+ 支持<br>约束：xudp 由 xray 支持 |

## packetaddr

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | packetaddr 包编码 | 有 |  |  | 部分 | 通过 | 取值：`packetaddr`<br>约束：由 v2ray 5+ 支持 |

## relay

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `tuic-mode` | TUIC UDP 中继模式 | 有 |  |  | 已实现 | 通过 | 取值：`native`、`quic` |

## route

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `rule-fallthrough` | 请求为 udp 而节点无 udp 支持时继续向下匹配 | 有 |  |  | 未实现 | 未测 |  |

## socks

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `udp-associate` | Socks 入站 udp 开关与 ip |  |  | 有 | 部分 | 通过 |  |

## stream

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `shadowquic` | ShadowQUIC UDP over stream | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true` |

## tuic

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `udp-relay-mode` | TUIC UDP 中继模式 |  | 有 |  | 已实现 | 通过 | 取值：`native`、`quic`<br>约束：与 udp_over_stream 冲突<br>约束：默认 native |

## uot

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `shadowsocks` | Shadowsocks UDP over TCP，见 outbound.shadowsocks.udp-over-tcp | 有 |  |  | 已实现 | 通过 | 取值：`1`、`2` |
| `enabled` | 启用 UDP over TCP 协议。 |  | 有 |  | 部分 | 通过 |  |
| `magic-address-v1` | UoT v1 请求魔数地址 |  | 有 |  | 已实现 | 通过 | 取值：`sp.udp-over-tcp.arpa`<br>约束：流格式：ATYP、地址、端口 u16be、长度 u16be、数据 |
| `magic-address-v2` | UoT v2 请求魔数地址 |  | 有 |  | 已实现 | 通过 | 取值：`sp.v2.udp-over-tcp.arpa`<br>约束：isConnect 为 1 时用长度加数据的连接流格式<br>约束：请求格式：isConnect u8、ATYP、地址、端口 |
| `version` | 协议版本，`1` 或 `2`。 |  | 有 |  | 已实现 | 通过 | 取值：`1`、`2`<br>约束：默认使用 2。 |
| `vless-native` | VLESS 原生 UDP 方式为 UoT |  |  | 有 | 已实现 | 通过 |  |

## xudp

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | XUDP 包编码，VMess、VLESS packet-encoding: xudp | 有 |  |  | 部分 | 通过 | 取值：`xudp`<br>约束：由 xray 支持 |
| `xudp` | 经 Mux 分发 UDP，FullCone |  |  | 有 | 部分 | 通过 | 取值：`xudp`<br>约束：详见 discussion XTLS/Xray-core#252 |
| `global-id` | New 帧 8 字节 Global ID，重连时保持同一端口 |  |  | 有 | 已实现 | 通过 | 取值：`8 字节` |
| `id-zero` | Single XUDP 子连接 ID 始终为 0 |  |  | 有 | 已实现 | 通过 |  |
