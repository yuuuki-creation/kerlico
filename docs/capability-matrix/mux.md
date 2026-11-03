# 多路复用

由 `tools/capability_matrix.py build` 生成，不要手改。

## brutal

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `down-mbps` | 上传和下载带宽，以 Mbps 为单位。 |  | 有 |  | 未实现 | 未测 | 约束：必填 |
| `enabled` | 启用 TCP Brutal 拥塞控制算法。 |  | 有 |  | 未实现 | 未测 |  |
| `up-mbps` | 上传和下载带宽，以 Mbps 为单位。 |  | 有 |  | 未实现 | 未测 | 约束：必填 |

## h2mux

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | sing-mux 协议 h2mux | 有 |  |  | 已实现 | 通过 | 取值：`h2mux` |

## inbound

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `brutal` | 参阅 TCP Brutal。 |  | 有 |  | 未实现 | 未测 |  |
| `enabled` | 启用多路复用支持。 |  | 有 |  | 已实现 | 通过 |  |
| `padding` | 如果启用，将拒绝非填充连接。 |  | 有 |  | 已实现 | 通过 |  |

## multiplex

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | 多路复用的协议、宿主协议和限制组合 |  | 有 |  | 已实现 | 通过 | protocol：`h2mux`、`smux`、`yamux`<br>host_protocol：`shadowsocks`、`trojan`、`vless`、`vmess`<br>limit：`max_connections`、`max_streams`、`min_streams`<br>padding：`off`、`on`<br>brutal：`off`、`on`<br>约束：brutal 服务端需要 Linux 和 brutal 内核模块<br>约束：max_connections、min_streams 与 max_streams 冲突<br>约束：padding 需要服务端 1.3-beta9 以上<br>约束：入站 padding 开启后拒绝未填充连接<br>约束：只有 shadowsocks、vmess、trojan、vless 有 multiplex 字段<br>约束：默认 h2mux |

## mux

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `mux` | Mux.Cool 多路复用，只需客户端启用 |  |  | 有 | 部分 | 通过 | 取值：`mux.cool` |
| `combo` | Mux 组合 |  |  | 有 | 部分 | 通过 | tcp：`mux`、`no_mux`<br>udp：`native`、`same_tunnel`、`xudp_tunnel`<br>udp443：`allow`、`reject`、`skip`<br>protocol：`http`、`shadowsocks`、`socks`、`trojan`、`vless`、`vmess`<br>transport：`grpc`、`httpupgrade`、`hysteria`、`mkcp`、`raw`、`websocket`、`xhttp`<br>约束：MASQUE 不支持 Mux<br>约束：Mux 不用于看视频、下载、测速<br>约束：XDRIVE 出站需要 Mux（source:infra/conf/xray.go）<br>约束：XHTTP 不要启用 mux.cool，服务端只接受纯 XUDP（discussion:XTLS/Xray-core#4113）<br>约束：gRPC 不建议启用<br>约束：旧 reverse 默认开 Mux |
| `concurrency` | 单连接最大子连接，范围 1-128，0 或省略为 8 |  |  | 有 | 已实现 | 通过 | 取值：`0`、`1-128`、`负数`<br>约束：大于 128 视为 128<br>约束：负数：不用 Mux 承载 TCP |
| `enabled` | 是否启用，默认 false |  |  | 有 | 已实现 | 通过 |  |
| `xudp-concurrency` | XUDP 聚合隧道并发子 UoT，范围 1-1024 |  |  | 有 | 未实现 | 未测 | 取值：`0`、`1-1024`、`负数`<br>约束：0：与 TCP 同路<br>约束：负数：不用 Mux 承载 UDP，走协议原生方式 |
| `xudp-proxy-udp443` | UDP/443 处理 |  |  | 有 | 未实现 | 未测 | 取值：`allow`、`reject`、`skip`<br>约束：skip 走协议原生 UDP 方式<br>约束：默认 reject |

## outbound

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `brutal` | 参阅 TCP Brutal。 |  | 有 |  | 未实现 | 未测 |  |
| `enabled` | 启用多路复用。 |  | 有 |  | 已实现 | 通过 |  |
| `max-connections` | 最大连接数量。 |  | 有 |  | 已实现 | 通过 | 约束：与 `max_streams` 冲突。 |
| `max-streams` | 在打开新连接之前，连接中的最大多路复用流数量。 |  | 有 |  | 已实现 | 通过 | 约束：与 `max_connections` 和 `min_streams` 冲突。 |
| `min-streams` | 在打开新连接之前，连接中的最小多路复用流数量。 |  | 有 |  | 已实现 | 通过 | 约束：与 `max_streams` 冲突。 |
| `padding` | 启用填充。 |  | 有 |  | 已实现 | 通过 | 约束：需要 sing-box 服务器版本 1.3-beta9 或更高。 |
| `protocol` | 多路复用协议默认使用 h2mux。 |  | 有 |  | 已实现 | 通过 | 取值：`h2mux`、`smux`、`yamux` |

## sing-mux

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | sing-mux 维度 | 有 |  |  | 已实现 | 通过 | protocol：`h2mux`、`smux`、`yamux`<br>limit：`max-connections+min-streams`、`max-streams`<br>only-tcp：`false`、`true`<br>padding：`false`、`true`<br>brutal：`off`、`on`<br>outbound：`ss`、`trojan`、`vless`、`vmess`<br>约束：H2 传输层未实现多路复用，需复用用 gRPC 或 sing-mux<br>约束：max-streams 与 max-connections、min-streams 冲突<br>约束：仅限使用 tcp 传输的协议 |
| `brutal-opts-down` | 下载带宽，默认 Mbps | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `brutal-opts-enabled` | 启用 TCP Brutal | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `brutal-opts-up` | 上传带宽，默认 Mbps | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `enabled` | 启用 sing-mux | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true`<br>约束：仅限使用 tcp 传输的协议 |
| `max-connections` | 最大连接数 | 有 |  |  | 已实现 | 通过 | 取值：`整数`<br>约束：与 max-streams 冲突 |
| `max-streams` | 开新连接前的最大流数 | 有 |  |  | 已实现 | 通过 | 取值：`整数`<br>约束：与 max-connections、min-streams 冲突 |
| `min-streams` | 开新连接前的最小流数 | 有 |  |  | 已实现 | 通过 | 取值：`整数`<br>约束：与 max-streams 冲突 |
| `only-tcp` | smux 不作用于 udp，udp 走节点默认协议 | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true` |
| `padding` | 启用填充 | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true` |
| `protocol` | 复用协议，默认 h2mux | 有 |  |  | 已实现 | 通过 | 取值：`h2mux`、`smux`、`yamux` |
| `statistic` | 底层连接显示在面板 | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |

## smux

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | sing-mux 协议 smux | 有 |  |  | 已实现 | 通过 | 取值：`smux` |

## wire

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `address` | 子连接地址类型 |  |  | 有 | 已实现 | 通过 | 取值：`0x01 IPv4`、`0x02 域名`、`0x03 IPv6` |
| `frame` | Mux.Cool 帧：元数据长度+元数据+额外数据 |  |  | 有 | 已实现 | 通过 | 取值：`End 0x03`、`Keep 0x02`、`KeepAlive 0x04`、`New 0x01`<br>约束：服务器不能使用 New<br>约束：目标地址标记 v1.mux.cool |
| `network` | 子连接网络类型 |  |  | 有 | 已实现 | 通过 | 取值：`0x01 TCP`、`0x02 UDP` |

## xmux

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | xhttp 的链接复用，见 transport.xhttp.reuse-settings | 有 |  |  | 部分 | 通过 |  |

## yamux

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | sing-mux 协议 yamux | 有 |  |  | 已实现 | 通过 | 取值：`yamux` |
