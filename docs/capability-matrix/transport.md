# 传输层

由 `tools/capability_matrix.py build` 生成，不要手改。

## browser-dialer

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `enable` | 环境变量 XRAY_BROWSER_DIALER=127.0.0.1:8080 启用，浏览器打开页面后转发 |  |  | 有 | 未实现 | 未测 | 约束：SNI、host、address 必须相同<br>约束：address 必须为域名<br>约束：tlsSettings 和自定义头被忽略<br>约束：仅 WebSocket 和 XHTTP<br>约束：建议开 Mux.Cool<br>约束：浏览器连接必须直连<br>约束：需手动开浏览器 |
| `ws-early-data` | 浏览器 early data 编码用 base64.RawURLEncoding，服务端兼容 |  |  | 有 | 未实现 | 未测 |  |
| `xhttp-quic` | XHTTP 可用浏览器 QUIC，HTTP 版本由浏览器决定 |  |  | 有 | 未实现 | 未测 |  |

## common

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `type` | V2Ray 传输类型 |  | 有 |  | 部分 | 通过 | 取值：`grpc`、`http`、`httpupgrade`、`quic`、`ws` |

## finalmask

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | FinalMask 组合 |  |  | 有 | 部分 | 通过 | direction：`quicParams`、`tcp`、`udp`<br>scope：`inbound`、`outbound`<br>tcp_mask：`filter`、`fragment`、`header-custom`、`sudoku`、`xmc`<br>udp_mask：`filter`、`header-custom`、`mkcp-legacy`、`noise`、`realm`、`salamander`、`sudoku`、`udphop`、`xdns`、`xicmp`<br>layering：`single`、`stacked`<br>约束：filter 只对入站，应放最外层<br>约束：quicParams 用于 XHTTP H3、hysteria、MASQUE H3<br>约束：udphop intervallocal 仅 wireguard、hysteria、xhttp h3<br>约束：xdns 仅配 kcp<br>约束：在 TLS/REALITY 之后处理 |
| `quic-params` | XHTTP H3、Hysteria、MASQUE H3 的 QUIC 调整 |  |  | 有 | 部分 | 通过 |  |
| `tcp` | TCP 掩码数组，第一个为最内层 |  |  | 有 | 已实现 | 通过 | 取值：`filter`、`fragment`、`header-custom`、`sudoku`、`xmc`<br>约束：xmc 文档未写（source:infra/conf/transport_finalmask.go） |
| `udp` | UDP 掩码数组，第一个为最内层 |  |  | 有 | 部分 | 通过 | 取值：`filter`、`header-custom`、`mkcp-legacy`、`noise`、`realm`、`salamander`、`sudoku`、`udphop`、`xdns`、`xicmp` |

## finalmask-custom-transform

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `args` | transform 参数数组，文档未写 |  |  | 实验 | 未实现 | 未测 | 取值：`bytes`、`metadata`、`reuse`、`transform`、`type`、`u64` |
| `op` | header-custom transform 操作，文档未写 |  |  | 实验 | 未实现 | 未测 |  |

## finalmask-quic

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `bbr-profile` | BBR 预设，默认 standard |  |  | 有 | 部分 | 通过 | 取值：`aggressive`、`conservative`、`standard` |
| `brutal-disable-loss-compensation` | QUIC 调整字段，文档未写 |  |  | 实验 | 未实现 | 未测 |  |
| `brutal-down` | 下载速率，默认 0 |  |  | 有 | 已实现 | 通过 | 约束：不能低于 65535 bps |
| `brutal-up` | 上传速率 |  |  | 有 | 已实现 | 通过 | 取值：`1 tbps`、`100 mbps`、`1000000`、`100kb`、`1g`、`20 mb`<br>约束：不能低于 65535 bps<br>约束：客户端 0 用 BBR<br>约束：服务端值限制客户端，0 不限 |
| `congestion` | 拥塞控制 |  |  | 有 | 部分 | 通过 | 取值：`bbr`、`brutal`、`force-brutal`、`reno`<br>约束：Hysteria 默认 brutal；XHTTP H3 与 MASQUE 默认 bbr<br>约束：MASQUE 的 brutal 按 bbr 运行<br>约束：XHTTP H3 不能用 brutal，可用 force-brutal<br>约束：force-brutal 需 brutalUp |
| `debug` | 启用拥塞日志 |  |  | 有 | 未实现 | 未测 |  |
| `disable-chrome-parrot` | QUIC 调整字段，文档未写 |  |  | 实验 | 未实现 | 未测 |  |
| `disable-gso` | QUIC 调整字段，文档未写 |  |  | 实验 | 未实现 | 未测 |  |
| `disable-path-mtudiscovery` | 禁用路径 MTU 发现 |  |  | 有 | 未实现 | 未测 |  |
| `disable-stateless-reset` | QUIC 调整字段，文档未写 |  |  | 实验 | 未实现 | 未测 |  |
| `init-connection-receive-window` | QUIC 窗口参数 |  |  | 有 | 未实现 | 未测 | 约束：建议流窗口与连接窗口 2:5<br>约束：至少 16384（source:infra/conf/transport_finalmask.go） |
| `init-stream-receive-window` | QUIC 窗口参数 |  |  | 有 | 未实现 | 未测 | 约束：建议流窗口与连接窗口 2:5<br>约束：至少 16384（source:infra/conf/transport_finalmask.go） |
| `keep-alive-period` | KeepAlive 秒，范围 2-60，默认禁用 |  |  | 有 | 未实现 | 未测 |  |
| `max-connection-receive-window` | QUIC 窗口参数 |  |  | 有 | 未实现 | 未测 | 约束：建议流窗口与连接窗口 2:5<br>约束：至少 16384（source:infra/conf/transport_finalmask.go） |
| `max-idle-timeout` | 最长空闲秒，默认 30，范围 4-120 |  |  | 有 | 部分 | 通过 |  |
| `max-incoming-streams` | 服务端参数，不得小于 8 |  |  | 有 | 部分 | 通过 |  |
| `max-stream-receive-window` | QUIC 窗口参数 |  |  | 有 | 未实现 | 未测 | 约束：建议流窗口与连接窗口 2:5<br>约束：至少 16384（source:infra/conf/transport_finalmask.go） |
| `udp-hop` | UDP 端口跳跃 |  |  | 有 | 部分 | 未测 | 取值：`interval`、`ports`<br>约束：interval 至少 5，默认 30 |

## finalmask-tcp-filter

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `allowed-source-ips` | 来源 IP 白名单，支持 GeoIP、CIDR |  |  | 有 | 未实现 | 未测 | 约束：TCP 握手成功后过滤<br>约束：仅入站生效<br>约束：通常放数组最后 |
| `blocked-source-ips` | 来源 IP 黑名单 |  |  | 有 | 未实现 | 未测 | 约束：同时存在时须命中白名单且不命中黑名单 |

## finalmask-tcp-fragment

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `delays` | 分片间隔数组毫秒，Int32Range |  |  | 有 | 已实现 | 通过 | 约束：为 0 且 tlshello 时在一个 TCP 包内发<br>约束：源码也接受 delay |
| `lengths` | 分片包长数组，Int32Range |  |  | 有 | 已实现 | 通过 | 约束：源码也接受 length（source:infra/conf/transport_finalmask.go）<br>约束：除最后一项外可为 0 |
| `max-split` | 最大分片次数，0 不限 |  |  | 有 | 已实现 | 通过 |  |
| `packets` | 分片方式 |  |  | 有 | 已实现 | 通过 | 取值：`1-3`、`tlshello`<br>约束：tlshello 切 TLS 握手包；1-3 切客户端第 1~3 次写 |

## finalmask-tcp-header-custom

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `capture` | header-custom 高级字段，文档未写 |  |  | 实验 | 未实现 | 未测 |  |
| `clients` | 客户端发送序列（二维） |  |  | 有 | 未实现 | 未测 |  |
| `delay` | 毫秒，0 时与前面粘包 |  |  | 有 | 未实现 | 未测 |  |
| `errors` | 错误时发送序列（二维） |  |  | 有 | 未实现 | 未测 |  |
| `packet` | 固定数据，与 rand 冲突 |  |  | 有 | 未实现 | 未测 |  |
| `rand` | 随机字节长度，与 packet 冲突 |  |  | 有 | 未实现 | 未测 |  |
| `rand-range` | 随机字节范围，默认 0-255 |  |  | 有 | 未实现 | 未测 |  |
| `reuse` | header-custom 高级字段，文档未写 |  |  | 实验 | 未实现 | 未测 |  |
| `servers` | 服务端发送序列（二维） |  |  | 有 | 未实现 | 未测 |  |
| `transform` | header-custom 高级字段，文档未写 |  |  | 实验 | 未实现 | 未测 |  |
| `type` | packet 类型，默认 array |  |  | 有 | 未实现 | 未测 | 取值：`array`、`base64`、`hex`、`str` |

## finalmask-tcp-sudoku

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `ascii` | Sudoku 字段：ASCII 设置 |  |  | 有 | 未实现 | 未测 | 约束：含义见 Sudoku 官方文档 |
| `custom-table` | Sudoku 字段：旧 custom_table |  |  | 有 | 未实现 | 未测 | 约束：含义见 Sudoku 官方文档 |
| `custom-tables` | Sudoku 字段：旧 custom_tables |  |  | 有 | 未实现 | 未测 | 约束：含义见 Sudoku 官方文档 |
| `padding-max` | Sudoku 字段：旧 padding_max |  |  | 有 | 未实现 | 未测 | 约束：含义见 Sudoku 官方文档 |
| `padding-min` | Sudoku 字段：旧 padding_min |  |  | 有 | 未实现 | 未测 | 约束：含义见 Sudoku 官方文档 |
| `password` | Sudoku 字段：密码 |  |  | 有 | 未实现 | 未测 | 约束：含义见 Sudoku 官方文档 |

## finalmask-tcp-xmc

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `hostname` | xmc TCP 掩码字段，文档未写 |  |  | 实验 | 未实现 | 未测 |  |
| `password` | xmc TCP 掩码字段，文档未写 |  |  | 实验 | 未实现 | 未测 |  |
| `profiles` | xmc TCP 掩码字段，文档未写 |  |  | 实验 | 未实现 | 未测 |  |
| `textures-signature` | xmc TCP 掩码字段，文档未写 |  |  | 实验 | 未实现 | 未测 |  |
| `textures-value` | xmc TCP 掩码字段，文档未写 |  |  | 实验 | 未实现 | 未测 |  |
| `username` | xmc TCP 掩码字段，文档未写 |  |  | 实验 | 未实现 | 未测 |  |
| `uuid` | xmc TCP 掩码字段，文档未写 |  |  | 实验 | 未实现 | 未测 |  |

## finalmask-udp-filter

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `allowed-source-ips` | 来源 IP 白名单 |  |  | 有 | 未实现 | 未测 | 约束：仅入站，UDP 逐包过滤 |
| `blocked-source-ips` | 来源 IP 黑名单 |  |  | 有 | 未实现 | 未测 | 约束：仅入站，UDP 逐包过滤 |

## finalmask-udp-header-custom

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `client` | 客户端头序列 |  |  | 有 | 未实现 | 未测 |  |
| `mode` | 模式，文档未写 |  |  | 实验 | 未实现 | 未测 | 取值：`prefix`、`standalone` |
| `packet` | 固定数据，与 rand 冲突 |  |  | 有 | 未实现 | 未测 |  |
| `rand` | 随机字节长度，与 packet 冲突 |  |  | 有 | 未实现 | 未测 |  |
| `rand-range` | 随机字节范围 |  |  | 有 | 未实现 | 未测 |  |
| `server` | 服务端头序列 |  |  | 有 | 未实现 | 未测 |  |
| `type` | packet 类型，默认 array |  |  | 有 | 未实现 | 未测 | 取值：`array`、`base64`、`hex`、`str` |

## finalmask-udp-mkcp-legacy

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `header` | 旧 mKCP 包头 |  |  | 有 | 未实现 | 未测 | 取值：``、`dns`、`dtls`、`srtp`、`utp`、`wechat`、`wireguard`<br>约束：只是包头伪造<br>约束：空时 AES-128-GCM，value 为密码；value 空时简单 XOR |
| `value` | 随 header 变化：密码或域名 |  |  | 有 | 未实现 | 未测 | 约束：dns 默认 www.baidu.com，其他 header 无作用 |

## finalmask-udp-noise

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `delay` | 发噪声后延迟毫秒 |  |  | 有 | 未实现 | 未测 |  |
| `packet` | 固定数据或表达式 |  |  | 有 | 未实现 | 未测 | 取值：`<b hex>`、`<c>`、`<n>`、`<r A-B>`、`<r N>`、`<rc A-B>`、`<rc N>`、`<rd A-B>`、`<rd N>`、`<t>`<br>约束：表达式仅 type exp |
| `rand` | 随机字节长度范围，与 packet 冲突 |  |  | 有 | 未实现 | 未测 |  |
| `rand-range` | 随机字节范围 |  |  | 有 | 未实现 | 未测 |  |
| `reset` | 噪声重置秒，Int32Range，0 不重置 |  |  | 有 | 未实现 | 未测 |  |
| `script` | Lua 噪声脚本，文档未写 |  |  | 实验 | 未实现 | 未测 | 约束：不能与 noise 同用 |
| `type` | packet 类型，默认 array |  |  | 有 | 未实现 | 未测 | 取值：`array`、`base64`、`exp`、`hex`、`str` |

## finalmask-udp-realm

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `enabled` | 固定端口映射开关 |  |  | 有 | 未实现 | 未测 |  |
| `ip-mode` | 控制 STUN 解析与 peer 过滤 |  |  | 有 | 未实现 | 未测 | 取值：`dual`、`v4`、`v6`<br>约束：v4、v6 来自源码（source:transport/internet/finalmask/realm/client.go） |
| `lifetime` | 端口映射有效期秒 |  |  | 有 | 未实现 | 未测 |  |
| `port-mapping` | 固定端口映射配置，提高入站可达性 |  |  | 有 | 未实现 | 未测 |  |
| `stun-servers` | STUN 服务器列表 |  |  | 有 | 未实现 | 未测 |  |
| `timeout` | 端口映射超时秒 |  |  | 有 | 未实现 | 未测 |  |
| `tls-config` | 同 tlsSettings |  |  | 有 | 未实现 | 未测 |  |
| `url` | realm[+http]://token@host[:port]/id |  |  | 有 | 未实现 | 未测 | 取值：`realm`、`realm+http` |

## finalmask-udp-salamander

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `packet-size` | Gecko 分片大小，非空启用 |  |  | 有 | 未实现 | 未测 | 约束：上限 2048<br>约束：只对 QUIC 长包头额外分片填充 |
| `password` | Salamander 混淆密码 |  |  | 有 | 部分 | 通过 |  |

## finalmask-udp-sudoku

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `ascii` | UDP Sudoku 字段，同 TCP 版 |  |  | 有 | 未实现 | 未测 |  |
| `custom-table` | UDP Sudoku 字段，同 TCP 版 |  |  | 有 | 未实现 | 未测 |  |
| `custom-tables` | UDP Sudoku 字段，同 TCP 版 |  |  | 有 | 未实现 | 未测 |  |
| `padding-max` | UDP Sudoku 字段，同 TCP 版 |  |  | 有 | 未实现 | 未测 |  |
| `padding-min` | UDP Sudoku 字段，同 TCP 版 |  |  | 有 | 未实现 | 未测 |  |
| `password` | UDP Sudoku 字段，同 TCP 版 |  |  | 有 | 未实现 | 未测 |  |

## finalmask-udp-udphop

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `interval` | 跳变间隔秒 |  |  | 有 | 部分 | 未测 |  |
| `mode` | 逗号分隔 |  |  | 有 | 未实现 | 未测 | 取值：`intervallocal`、`intervallocal,intervalremote`、`intervalremote`、`perconnremote`<br>约束：intervallocal 仅 wireguard、hysteria、xhttp h3<br>约束：intervalremote、perconnremote 需 iptables 或 nftables |
| `remote-ips` | 远端 IP，支持 CIDR |  |  | 有 | 未实现 | 未测 | 约束：仅 mode 含 intervalremote 或 perconnremote<br>约束：未填继承上层 |
| `remote-ports` | 远端端口 |  |  | 有 | 部分 | 未测 | 约束：仅 mode 含 intervalremote 或 perconnremote<br>约束：未填继承上层 |

## finalmask-udp-xdns

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | XDNS 组合 |  |  | 有 | 未实现 | 未测 | query_type：`A`、`AAAA`、`CNAME`、`TXT`<br>edns0：`0`、`1232`、`512`<br>transport：`mkcp`<br>role：`client`、`server`<br>约束：edns0 512：A 39 TXT 215 AAAA 117；1232：A 174 TXT 932 AAAA 492<br>约束：仅可搭配 kcp<br>约束：推荐 tti 200，服务端配 mtu<br>约束：服务端监听 53，需自有域名 NS |
| `addrs` | 解析器地址 [protocol://]host[:port] |  |  | 有 | 未实现 | 未测 | 取值：`https://`、`tcp://`、`udp://`<br>约束：tcp、https 协议来自源码 |
| `edns0` | 0 或 512-4096，默认 0 |  |  | 有 | 未实现 | 未测 |  |
| `extra-poll` | 额外轮询字段，文档未写 |  |  | 实验 | 未实现 | 未测 |  |
| `label-limit` | 0-63，默认 63 |  |  | 有 | 未实现 | 未测 |  |
| `len-limit` | 0-255，默认 255 |  |  | 有 | 未实现 | 未测 |  |
| `names` | 域名列表 |  |  | 有 | 未实现 | 未测 |  |
| `quic-config` | 解析器字段，文档未写 |  |  | 实验 | 未实现 | 未测 |  |
| `tls-config` | 解析器字段，文档未写 |  |  | 实验 | 未实现 | 未测 |  |
| `types` | 查询类型；客户端默认 16，服务端默认全部 |  |  | 有 | 未实现 | 未测 | 取值：`1`、`16`、`28`、`5` |
| `worker` | 解析器字段，文档未写 |  |  | 实验 | 未实现 | 未测 |  |

## finalmask-udp-xicmp

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `dgram` | 低权限模式，仅客户端 Linux、Mac、iOS |  |  | 有 | 未实现 | 未测 |  |
| `ips` | IP 列表 |  |  | 有 | 未实现 | 未测 | 约束：暂不支持 CIDR |

## grpc

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `grpc` | gRPC 传输 |  |  | 有 | 已实现 | 通过 | 取值：`grpc`<br>约束：不建议同时开 mux.cool<br>约束：不支持回落到其他服务<br>约束：不支持指定 Host，须正确域名或 serverName<br>约束：文档建议换 XHTTP，源码打印不移除的弃用告警 |
| `protocol` | gRPC 传输 | 有 |  |  | 已实现 | 通过 | 取值：`grpc`<br>约束：VMess、VLESS、Trojan 可用 |
| `combo` | gRPC 组合 |  |  | 有 | 部分 | 通过 | mode：`gun`、`multi`<br>security：`none`、`reality`、`tls`<br>proxy：`caddy`、`direct`、`nginx`<br>health_check：`off`、`on`<br>约束：不能通过 Path 分流回落<br>约束：回落时 h2 必须是 alpn 第一项 |
| `authority` | 可当 Host 使用 |  |  | 有 | 已实现 | 通过 |  |
| `grpc-service-name` | gRPC 服务名 | 有 |  |  | 已实现 | 通过 | 取值：`字符串` |
| `grpc-user-agent` | gRPC UserAgent | 有 |  |  | 已实现 | 通过 | 取值：`字符串` |
| `health-check-timeout` | 仅出站，健康检查超时，默认 20 |  |  | 有 | 部分 | 通过 |  |
| `idle-timeout` | 在标准 gRPC 服务器/客户端： |  | 有 | 有 | 部分 | 通过 | 约束：在默认 gRPC 服务器/客户端：<br>约束：小于 10 取 10 |
| `initial-windows-size` | 仅出站，H2 流初始窗口，默认 0 不生效 |  |  | 有 | 部分 | 通过 | 约束：大于 65535 禁用动态窗口<br>约束：过 Cloudflare 可设 65536 以上 |
| `max-connections` | 最大连接数，默认 1 | 有 |  |  | 未实现 | 未测 | 取值：`整数`<br>约束：与 max-streams 冲突 |
| `max-streams` | 开新连接前最大流数 | 有 |  |  | 未实现 | 未测 | 取值：`整数`<br>约束：与 max-connections、min-streams 冲突 |
| `min-streams` | 开新连接前最小流数 | 有 |  |  | 未实现 | 未测 | 取值：`整数`<br>约束：与 max-streams 冲突 |
| `multi-mode` | 仅出站，默认 false |  |  | 实验 | 已实现 | 通过 | 取值：`false`、`true` |
| `permit-without-stream` | 在标准 gRPC 客户端： |  | 有 | 有 | 部分 | 通过 | 取值：`false`、`true`<br>约束：如果禁用，则在没有活动连接时，将忽略 `idle_timeout` 和 `ping_timeout`，并且不会发送 keepalive ping。<br>约束：默认禁用。 |
| `ping-interval` | 心跳间隔秒，默认关闭 | 有 |  |  | 部分 | 通过 | 取值：`整数` |
| `ping-timeout` | 在标准 gRPC 服务器/客户端： |  | 有 |  | 部分 | 通过 | 约束：在默认 gRPC 服务器/客户端： |
| `service-name` | gRPC 服务名称。 |  | 有 | 有 | 已实现 | 通过 | 约束：Path 为 /${serviceName}/Tun 或 /TunMulti<br>约束：以 / 起始可自定义 path，至少两个斜杠<br>约束：服务端可写 /my/sample/path1\|path2 |
| `type` | 类型字段 |  | 有 |  | 已实现 | 通过 |  |
| `user-agent` | 仅出站，用户代理 |  |  | 有 | 已实现 | 通过 |  |

## h2

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `h2` | HTTP/2 传输 |  |  | 已移除 | 不适用 | 未测 | 取值：`h2`<br>约束：改用 XHTTP stream-one H2<br>约束：配置时报错（source:infra/conf/transport_internet.go） |
| `protocol` | HTTP/2 传输 | 有 |  |  | 未实现 | 未测 | 取值：`h2`<br>约束：H2 未实现多路复用<br>约束：VMess、VLESS 可用 |
| `host` | 主机列表，客户端随机选择 | 有 |  |  | 未实现 | 未测 | 取值：`域名列表` |
| `path` | 请求路径 | 有 |  |  | 未实现 | 未测 | 取值：`路径` |

## http

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `http` | HTTP 传输，取值 h2/h3/http |  |  | 已移除 | 不适用 | 未测 | 取值：`h2`、`h3`、`http`<br>约束：改用 XHTTP stream-one H2 或 H3<br>约束：配置时报错（source:infra/conf/transport_internet.go） |
| `protocol` | HTTP 伪装传输 | 有 |  |  | 未实现 | 未测 | 取值：`http`<br>约束：VMess、VLESS 可用 |
| `headers` | 请求头 | 有 | 有 |  | 未实现 | 未测 | 取值：`映射` |
| `host` | 主机域名列表。 |  | 有 |  | 未实现 | 未测 |  |
| `idle-timeout` | 在 HTTP2 服务器中： |  | 有 |  | 未实现 | 未测 | 约束：需要注意的是，PING 响应被视为已接收的帧，因此如果连接上没有其他流量，则健康检查将在每个间隔执行一次。<br>约束：默认使用零。 |
| `method` | 请求方法 | 有 | 有 |  | 未实现 | 未测 | 取值：`HTTP 方法` |
| `path` | 请求路径列表 | 有 | 有 |  | 未实现 | 未测 | 取值：`路径列表`<br>约束：V2Ray 文档称服务端和客户端的路径必须一致，但实际代码允许客户端向路径添加任何后缀。 |
| `ping-timeout` | 在 HTTP2 客户端中： |  | 有 |  | 未实现 | 未测 | 约束：指定发送 PING 帧后，在指定的超时时间内必须接收到响应。<br>约束：默认超时持续时间为 15 秒。 |
| `type` | 类型字段 |  | 有 |  | 未实现 | 未测 |  |

## http2-consumers

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | HTTP2 字段被哪些协议使用 |  | 有 |  | 部分 | 通过 | consumer：`http`、`http-client`、`hysteria-realm`、`masque`<br>field：`connection_receive_window`、`idle_timeout`、`keep_alive_period`、`max_concurrent_streams`、`stream_receive_window`<br>约束：窗口值接受内存大小格式，如 64 MB<br>约束：自 1.14.0 起 |

## http2-fields

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `connection-receive-window` | HTTP2 连接级别流控接收窗口大小。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `idle-timeout` | 空闲连接超时，采用 golang 的 Duration 格式。 |  | 有 |  | 部分 | 通过 | 约束：自 sing-box 1.14.0 起 |
| `keep-alive-period` | Keep alive 周期，采用 golang 的 Duration 格式。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `max-concurrent-streams` | 每个连接的最大并发流数。 |  | 有 |  | 部分 | 通过 | 约束：自 sing-box 1.14.0 起 |
| `stream-receive-window` | HTTP2 流级别流控接收窗口大小。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |

## httpupgrade

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `httpupgrade` | HTTPUpgrade 传输 |  |  | 有 | 已实现 | 通过 | 取值：`httpupgrade`<br>约束：不推荐单独使用<br>约束：文档建议换 XHTTP，源码打印不移除的弃用告警 |
| `protocol` | ws-opts.v2ray-http-upgrade 启用的 HTTP Upgrade | 有 |  |  | 已实现 | 通过 |  |
| `combo` | HTTPUpgrade 组合 |  |  | 有 | 部分 | 通过 | security：`none`、`tls`<br>early_data：`ed`、`off`<br>proxy_protocol：`off`、`on`<br>约束：uTLS 下默认 alpn http/1.1<br>约束：不支持 reality |
| `accept-proxy-protocol` | 仅入站，接收 PROXY protocol |  |  | 有 | 已实现 | 通过 |  |
| `headers` | HTTP 请求的额外标头。 |  | 有 | 有 | 部分 | 通过 | 约束：源码：headers 不能含 host（source:infra/conf/transport_method.go），与文档优先级说明不一致 |
| `host` | 主机域名。 |  | 有 | 有 | 已实现 | 通过 | 约束：客户端优先级 host > headers > address<br>约束：服务端值为空不校验 |
| `path` | HTTP 请求路径服务器将验证。 |  | 有 | 有 | 已实现 | 通过 | 取值：`/`、`/mypath?ed=2560`<br>约束：ed 启用 Early Data，建议 2560 |
| `type` | 类型字段 |  | 有 |  | 已实现 | 通过 |  |

## hysteria

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `hysteria` | Hysteria2 QUIC 传输，搭配 hysteria 协议时兼容官方实现 |  |  | 有 | 已实现 | 通过 | 取值：`hysteria` |
| `combo` | Hysteria 传输组合 |  |  | 有 | 部分 | 未测 | security：`tls`<br>masquerade：`404`、`file`、`proxy`、`string`<br>congestion：`bbr`、`brutal`、`force-brutal`、`reno`<br>obfs：`gecko`、`none`、`salamander`<br>port_hop：`finalmask udphop`、`off`、`quicParams.udpHop`<br>protocol：`http`、`hysteria`、`shadowsocks`、`socks`、`trojan`、`vless`、`vmess`<br>约束：hysteria 协议配其他传输不能代理 UDP<br>约束：udphop intervallocal 支持 hysteria<br>约束：必须 tls<br>约束：默认拥塞 brutal |
| `auth` | 认证密码，两端一致 |  |  | 有 | 已实现 | 通过 | 约束：搭配 hysteria inbound 时被 users 覆盖 |
| `content` | string 类型内容 |  |  | 有 | 已实现 | 通过 |  |
| `dir` | file 类型目录 |  |  | 有 | 未实现 | 未测 |  |
| `headers` | string 类型响应头 |  |  | 有 | 已实现 | 通过 |  |
| `insecure` | proxy 类型跳过证书校验 |  |  | 有 | 已实现 | 通过 |  |
| `masquerade` | HTTP/3 页面伪装 |  |  | 有 | 已实现 | 通过 |  |
| `rewrite-host` | proxy 类型改写 Host |  |  | 有 | 已实现 | 通过 |  |
| `status-code` | string 类型状态码 |  |  | 有 | 已实现 | 通过 |  |
| `type` | 伪装类型，不填默认 404 |  |  | 有 | 已实现 | 通过 | 取值：`file`、`proxy`、`string` |
| `udp-idle-timeout` | QUIC native UDP 空闲秒，默认 60 |  |  | 有 | 部分 | 通过 | 约束：源码范围 2-600（source:infra/conf/transport_method.go） |
| `url` | proxy 类型目标 |  |  | 有 | 已实现 | 通过 |  |
| `version` | 版本 |  |  | 有 | 已实现 | 通过 | 取值：`2`<br>约束：必须为 2 |
| `x-forwarded` | proxy 类型 X-Forwarded 头，文档未写 |  |  | 有 | 未实现 | 未测 |  |

## list

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `methods` | 传输配置列表页 |  |  | 有 | 不适用 | 未测 | 取值：`finalmask`、`grpc`、`httpupgrade`、`hysteria`、`masque`、`mkcp`、`raw`、`reality`、`sockopt`、`tls`、`websocket`、`xhttp` |

## masque

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `masque` | MASQUE CONNECT-IP 传输，HTTP/3 用 QUIC DATAGRAM，HTTP/2 用扩展 CONNECT |  |  | 有 | 部分 | 通过 | 取值：`masque`<br>约束：只能被 masque 协议使用 |
| `finalmask-mapping` | UDP 掩码作用于 HTTP/3，TCP 掩码作用于 HTTP/2 |  |  | 有 | 未实现 | 未测 | 约束：HTTP/2 时 quicParams 不生效<br>约束：HTTP/2 时出站 TLS 用 fingerprint，默认 chrome |
| `headers` | 仅出站，附加头 |  |  | 有 | 未实现 | 未测 | 取值：`chrome`、`curl`、`edge`、`firefox`、`golang`、`safari`<br>约束：不能含 Host、Capsule-Protocol<br>约束：设 user/pass 时不能含 Authorization<br>约束：默认不发 User-Agent，特殊值用于 User-Agent |
| `host` | 仅出站，:authority，host > serverName > address |  |  | 有 | 已实现 | 通过 |  |
| `http3-fixed-params` | HTTP/3 初始包固定 1350 字节，不模仿 Chrome QUIC；brutal 按 bbr 运行 |  |  | 有 | 部分 | 通过 | 约束：路径 MTU 更小时无法连接<br>约束：需 Brutal 用 force-brutal |
| `pass` | 仅出站，Basic 密码 |  |  | 有 | 已实现 | 通过 |  |
| `path` | 两端须一致，默认 /.well-known/masque/ip/{target}/{ipproto}/ |  |  | 有 | 部分 | 通过 | 约束：不支持其他变量，须以 / 开头<br>约束：入站路径不匹配返回 404<br>约束：只支持完整隧道，{target}、{ipproto} 填 * |
| `user` | 仅出站，Basic 用户名 |  |  | 有 | 已实现 | 通过 | 约束：不能含 : |
| `warp` | 接入 Cloudflare WARP 的设备信息 |  |  | 有 | 未实现 | 未测 | 约束：host 默认 cloudflareaccess.com，path 默认 /<br>约束：不能再设 user/pass<br>约束：设 pinnedPeerCertSha256 或 verifyPeerCertByName 时忽略 publicKey |
| `xmux` | XMUX 配置，文档未写 |  |  | 有 | 未实现 | 未测 | 约束：maxConnections 不能与 maxConcurrency 同用 |

## masque-warp

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | WARP over MASQUE 组合 |  |  | 有 | 未实现 | 未测 | account：`WARP`、`WARP+`、`Zero Trust`<br>http_version：`h2`、`h3`<br>sni：`consumer-masque.cloudflareclient.com`、`普通域名`<br>verify：`pinnedPeerCertSha256`、`publicKey`、`verifyPeerCertByName`<br>finalmask：`tcp fragment`、`udp noise`<br>约束：H2 用 finalmask.tcp fragment，H3 用 finalmask.udp noise<br>约束：IP 端点：WARP 162.159.198.2；WARP+ 162.159.199.2；Zero Trust 162.159.197.2<br>约束：边缘不支持 ECH |
| `address` | WARP 分配的地址 |  |  | 有 | 未实现 | 未测 | 约束：最多一个 IPv4 和一个 IPv6（source:infra/conf/transport_method.go） |
| `private-key` | 设备 P-256 私钥，PEM 或 base64，PKCS#8 或 SEC 1 |  |  | 有 | 未实现 | 未测 | 约束：WireGuard 的 Curve25519 密钥不能用<br>约束：需开启 warp_enabled |
| `public-key` | 端点证书 P-256 公钥，服务端证书 pin 到它 |  |  | 有 | 未实现 | 未测 |  |

## matrix

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `method-security` | 传输方式与传输安全总表 |  |  | 有 | 部分 | 通过 | transport：`grpc`、`httpupgrade`、`hysteria`、`masque`、`mkcp`、`raw`、`websocket`、`xhttp`<br>security：`none`、`reality`、`tls`<br>约束：hysteria、masque：必须 tls，不支持 none 和 reality<br>约束：raw、xhttp、grpc：none、tls、reality 都支持<br>约束：websocket、httpupgrade、mkcp：支持 none、tls，不支持 reality |
| `protocol-method` | 代理协议与传输方式总表 |  |  | 有 | 部分 | 通过 | protocol：`http`、`hysteria`、`masque`、`shadowsocks`、`socks`、`trojan`、`vless`、`vmess`、`wireguard`<br>transport：`grpc`、`httpupgrade`、`hysteria`、`masque`、`mkcp`、`raw`、`websocket`、`xhttp`<br>约束：http、vmess、vless、trojan：除 masque 外都支持<br>约束：hysteria：只支持 hysteria<br>约束：masque：只支持 masque<br>约束：socks、shadowsocks：除 masque 外受限，未启用 XUDP 时 UDP 绕过传输<br>约束：wireguard：全部不适用 |
| `protocol-security` | 代理协议与传输安全总表 |  |  | 有 | 部分 | 通过 | protocol：`http`、`hysteria`、`masque`、`shadowsocks`、`socks`、`trojan`、`vless`、`vmess`、`wireguard`<br>security：`none`、`reality`、`tls`<br>约束：http、vmess：none、tls、reality 都支持<br>约束：hysteria、masque：必须 tls<br>约束：socks、shadowsocks：tls、reality 受限，未启用 XUDP 时 UDP 绕过<br>约束：vless、trojan：none 受限，仅私网地址；VLESS 启用 Encryption 后可连公网<br>约束：wireguard：不适用 |

## mekya

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | Mekya 传输 | 有 |  |  | 未实现 | 未测 | 取值：`mekya`<br>约束：仅 VMess |
| `h2-pool-size` | HTTP/2 连接池大小 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `kcp-congestion` | Mekya 内部 KCP：拥塞控制 | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `kcp-downlink-capacity` | Mekya 内部 KCP：下行容量 MB/s | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `kcp-header` | Mekya 内部 KCP：伪装包头 | 有 |  |  | 未实现 | 未测 | 取值：`dtls`、`none`、`srtp`、`utp`、`wechat-video`、`wireguard` |
| `kcp-mtu` | Mekya 内部 KCP：最大传输单元 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `kcp-read-buffer` | Mekya 内部 KCP：读缓冲字节 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `kcp-seed` | Mekya 内部 KCP：AES-GCM 种子，留空默认认证 | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `kcp-tti` | Mekya 内部 KCP：传输时间间隔，毫秒 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `kcp-uplink-capacity` | Mekya 内部 KCP：上行容量 MB/s | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `kcp-write-buffer` | Mekya 内部 KCP：写缓冲字节 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `max-request-size` | 单次 HTTP 请求最大负载，字节 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `max-write-delay` | 首包后最大聚合等待，毫秒 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `polling-interval-initial` | 空轮询间隔，毫秒 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `url` | Mekya 服务端 URL | 有 |  |  | 未实现 | 未测 | 取值：`URL` |

## mkcp

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `mkcp` | mKCP 传输，UDP 模拟 TCP；源码别名 kcp |  |  | 有 | 未实现 | 未测 | 取值：`kcp`、`mkcp` |
| `protocol` | mKCP 传输 | 有 |  |  | 未实现 | 未测 | 取值：`mkcp`<br>约束：仅 VMess |
| `combo` | mKCP 组合 |  |  | 有 | 未实现 | 未测 | security：`none`、`tls`<br>finalmask_udp：`filter`、`header-custom`、`mkcp-legacy`、`noise`、`none`、`salamander`、`sudoku`、`xdns`、`xicmp`<br>legacy_compat：`mkcp-legacy`、`off`<br>约束：xdns 仅可搭配 kcp（docs/config/transports/finalmask.md）<br>约束：不支持 reality<br>约束：连接旧版服务端需 mkcp-legacy，header 与 value 留空即旧默认 XOR |
| `congestion` | 拥塞控制 | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `cwnd-multiplier` | 拥塞窗口倍数，默认 1，最小 1 |  |  | 有 | 未实现 | 未测 |  |
| `downlink-capacity` | 下行容量 MB/s | 有 |  | 有 | 未实现 | 未测 | 取值：`整数`<br>约束：两端取较小值<br>约束：可为 0 |
| `header` | 伪装包头 | 有 |  | 已移除 | 未实现 | 未测 | 取值：`dtls`、`none`、`srtp`、`utp`、`wechat-video`、`wireguard`<br>约束：改用 finalmask mkcp-legacy |
| `max-sending-window` | 最大发送窗口字节，默认 2097152 |  |  | 有 | 未实现 | 未测 | 约束：不得小于 mtu |
| `mtu` | 最大传输单元 | 有 |  | 有 | 未实现 | 未测 | 取值：`整数`<br>约束：源码只要求至少 21（source:infra/conf/transport_method.go） |
| `read-buffer` | 读缓冲字节 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `seed` | AES-GCM 种子，留空默认认证 | 有 |  | 已移除 | 未实现 | 未测 | 取值：`字符串`<br>约束：改用 finalmask mkcp-legacy |
| `tti` | 传输时间间隔，毫秒 | 有 |  | 有 | 未实现 | 未测 | 取值：`整数`<br>约束：文档示例写 20，源码范围 10-1000（source:infra/conf/transport_method.go） |
| `uplink-capacity` | 上行容量 MB/s | 有 |  | 有 | 未实现 | 未测 | 取值：`整数`<br>约束：可为 0 |
| `wire-format` | mKCP 线格式：无版本和握手，数据包含 FNV-1a 认证，片段分数据、确认、心跳 |  |  | 有 | 未实现 | 未测 | 取值：`ack`、`data 0x01`、`ping`<br>约束：不保证版本间兼容 |
| `write-buffer` | 写缓冲字节 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |

## none

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `tcp` | 不配 transport 时走原始 TCP；sing-box 无独立 TCP 传输、mKCP、DomainSocket、XHTTP |  | 有 |  | 已实现 | 通过 | 约束：文档只列 HTTP、WebSocket、QUIC、gRPC、HTTPUpgrade |

## quic

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `quic` | QUIC 传输 |  |  | 已移除 | 不适用 | 未测 | 取值：`quic`<br>约束：改用 XHTTP stream-one H3<br>约束：配置时报错（source:infra/conf/transport_internet.go） |
| `type` | 类型字段 |  | 有 |  | 未实现 | 未测 |  |

## quic-consumers

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | QUIC 字段被哪些协议使用 |  | 有 |  | 部分 | 通过 | consumer：`http(version 3)`、`http-client(version 3)`、`hysteria`、`hysteria2`、`masque`、`tuic`<br>field：`connection_receive_window`、`disable_path_mtu_discovery`、`idle_timeout`、`initial_packet_size`、`keep_alive_period`、`max_concurrent_streams`、`stream_receive_window`<br>约束：QUIC 字段包含 HTTP2 字段<br>约束：窗口值接受内存大小格式，如 64 MB<br>约束：自 1.14.0 起 |

## quic-fields

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `disable-path-mtu-discovery` | 禁用 QUIC 路径 MTU 发现。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `initial-packet-size` | 初始 QUIC 数据包大小。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |

## stream-settings

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `address-port` | downloadSettings 内用于指向另一入口的 address 和 port |  |  | 有 | 部分 | 通过 | 取值：`address`、`port` |
| `finalmask` | 最终伪装配置 |  |  | 有 | 未实现 | 未测 |  |
| `grpc-settings` | grpc 传输配置 |  |  | 有 | 已实现 | 通过 | 约束：仅当 method 为 grpc 时有效 |
| `httpupgrade-settings` | httpupgrade 传输配置 |  |  | 有 | 已实现 | 通过 | 约束：仅当 method 为 httpupgrade 时有效 |
| `hysteria-settings` | hysteria 传输配置 |  |  | 有 | 部分 | 通过 | 约束：仅当 method 为 hysteria 时有效 |
| `kcp-settings` | mkcp 传输配置 |  |  | 有 | 未实现 | 未测 | 约束：仅当 method 为 mkcp 时有效 |
| `masque-settings` | masque 传输配置 |  |  | 有 | 部分 | 通过 | 约束：仅当 method 为 masque 时有效 |
| `method` | 传输方式，默认 raw |  |  | 有 | 部分 | 通过 | 取值：`grpc`、`httpupgrade`、`hysteria`、`masque`、`mkcp`、`raw`、`websocket`、`xhttp`<br>约束：源码别名：network 同 method；tcp 同 raw；splithttp 同 xhttp；kcp 同 mkcp；ws 同 websocket（source:infra/conf/transport_internet.go） |
| `network` | method 的旧名 |  |  | 有 | 不适用 | 未测 |  |
| `raw-settings` | raw 传输配置 |  |  | 有 | 部分 | 通过 | 约束：仅当 method 为 raw 时有效 |
| `sockopt` | 底层网络行为配置 |  |  | 有 | 部分 | 未测 |  |
| `splithttp-settings` | xhttpSettings 的旧名 |  |  | 有 | 不适用 | 未测 |  |
| `tcp-settings` | rawSettings 的旧名 |  |  | 有 | 不适用 | 未测 |  |
| `ws-settings` | websocket 传输配置 |  |  | 有 | 已实现 | 通过 | 约束：仅当 method 为 websocket 时有效 |
| `xdrive-settings` | xdrive 传输配置，文档未写 |  |  | 实验 | 已实现 | 通过 | 约束：仅当 method 为 xdrive 时有效 |
| `xhttp-settings` | xhttp 传输配置 |  |  | 有 | 部分 | 通过 | 约束：仅当 method 为 xhttp 时有效 |

## tcp

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | 默认传输；network 不配置或其他值时为 tcp | 有 |  |  | 已实现 | 通过 | 取值：`tcp` |
| `combo` | RAW 组合 |  |  | 有 | 部分 | 通过 | security：`none`、`reality`、`tls`<br>header：`http`、`none`<br>proxy_protocol：`off`、`on`<br>finalmask_tcp：`filter`、`fragment`、`header-custom`、`none`、`sudoku`、`xmc` |
| `accept-proxy-protocol` | 仅入站，接收 PROXY protocol，默认 false |  |  | 有 | 已实现 | 通过 | 约束：请求方必须先发 v1 或 v2，否则关闭 |
| `header` | 包头伪装，默认 none |  |  | 有 | 未实现 | 未测 | 取值：`http`、`none`<br>约束：HTTP 伪装两端必须一致<br>约束：可被 fallbacks path 分流，不能被 Nginx 分流 |
| `headers` | 请求头，每键随机一个值 |  |  | 有 | 未实现 | 未测 |  |
| `method` | 请求方法，默认 GET |  |  | 有 | 未实现 | 未测 |  |
| `path` | 请求路径列表，默认 ["/"]，多值随机 |  |  | 有 | 未实现 | 未测 |  |
| `reason` | 响应说明，默认 OK |  |  | 有 | 未实现 | 未测 |  |
| `status` | 响应状态，默认 200 |  |  | 有 | 未实现 | 未测 |  |
| `tcp` | tcp 是 RAW 的旧名 |  |  | 有 | 已实现 | 通过 | 取值：`raw`、`tcp` |
| `version` | 请求 HTTP 版本，默认 1.1 |  |  | 有 | 未实现 | 未测 |  |

## v2ray

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | V2Ray 传输层的类型、协议和安全层组合 |  | 有 |  | 部分 | 通过 | type：`grpc`、`http`、`httpupgrade`、`quic`、`ws`<br>protocol：`trojan`、`vless`、`vmess`<br>security：`none`、`reality`、`tls`、`tls+ech`<br>grpc_engine：`default`、`standard(with_grpc)`<br>ws_early_data：`header(Sec-WebSocket-Protocol)`、`off`、`path`<br>约束：QUIC 下自定义 TLS 只支持 ECH，所以 reality、utls 不能配 quic 传输（docs/configuration/shared/tls.md）<br>约束：early_data_header_name 必须两端一致<br>约束：http 传输不强制 TLS，无 TLS 时走明文 HTTP/1.1<br>约束：quic 传输要求 TLS（source:transport/v2ray/transport.go）<br>约束：ws、httpupgrade 的 path 不允许客户端加后缀，http 允许<br>约束：只有 vmess、trojan、vless 有 transport 字段<br>约束：标准 gRPC 不默认编入，需 with_grpc 构建标签，否则用默认 gRPC 实现<br>约束：没有 TCP 传输（明文 HTTP 并入 http 传输）、mKCP、DomainSocket（docs/configuration/shared/v2ray-transport.md） |

## ws

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | WebSocket 传输 | 有 |  |  | 已实现 | 通过 | 取值：`ws`<br>约束：VMess、VLESS、Trojan 可用 |
| `ws` | WebSocket 传输；源码别名 ws |  |  | 有 | 已实现 | 通过 | 取值：`websocket`、`ws`<br>约束：X-Forwarded-For 覆写源地址，优先于 PROXY protocol<br>约束：文档建议换 XHTTP，源码打印不移除的弃用告警 |
| `combo` | WebSocket 组合 |  |  | 有 | 部分 | 通过 | security：`none`、`tls`<br>early_data：`ed`、`off`<br>proxy_protocol：`off`、`on`<br>browser_dialer：`off`、`on`<br>heartbeat：`off`、`on`<br>约束：uTLS 下默认 alpn http/1.1<br>约束：不支持 reality<br>约束：可被 Nginx 或 fallbacks path 分流 |
| `accept-proxy-protocol` | 仅入站，接收 PROXY protocol |  |  | 有 | 已实现 | 通过 |  |
| `browser-dialer` | WebSocket 可用 Browser Dialer |  |  | 有 | 未实现 | 未测 |  |
| `early-data-header-name` | Early Data 头名 | 有 | 有 |  | 未实现 | 未测 | 取值：`字符串`<br>约束：它需要与服务器保持一致。 |
| `headers` | 请求头 | 有 | 有 | 有 | 部分 | 通过 | 取值：`映射` |
| `headers-host` | headers 内写 host |  |  | 废弃 | 不适用 | 未测 | 约束：改用独立 host 字段 |
| `heartbeat-period` | Ping 保活间隔秒，默认不发 |  |  | 有 | 部分 | 通过 |  |
| `host` | Host，默认空 |  |  | 有 | 已实现 | 通过 | 约束：客户端优先级 host > headers > address<br>约束：服务端值为空不校验 |
| `max-early-data` | Early Data 首包长度阈值 | 有 | 有 |  | 部分 | 未测 | 取值：`整数`<br>约束：默认启用。 |
| `path` | 请求路径 | 有 | 有 | 有 | 已实现 | 通过 | 取值：`/`、`/mypath?ed=2560`、`路径`<br>约束：ed 启用 Early Data，经 Sec-WebSocket-Protocol，推荐 2560，最大 8192 |
| `type` | 类型字段 |  | 有 |  | 已实现 | 通过 |  |
| `v2ray-http-upgrade` | 使用 http upgrade | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true` |
| `v2ray-http-upgrade-fast-open` | http upgrade fast open | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |

## xdrive

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `xdrive` | XDRIVE 传输：经云盘转发，文档未写 |  |  | 实验 | 部分 | 通过 | 取值：`xdrive`<br>约束：不支持 flow、testpre<br>约束：入站只能一个端口（source:infra/conf/xray.go）<br>约束：出站需开 mux，无负 concurrency/xudpConcurrency，无 skip（reverse 除外）<br>约束：只能用于 VLESS 且需 Encryption |
| `concurrency` | XDRIVE 字段，文档未写 |  |  | 实验 | 已实现 | 通过 |  |
| `eager-window-ms` | XDRIVE 字段，文档未写 |  |  | 实验 | 已实现 | 通过 |  |
| `flush-interval-ms` | XDRIVE 字段，文档未写 |  |  | 实验 | 已实现 | 通过 |  |
| `hole-timeout-ms` | XDRIVE 字段，文档未写 |  |  | 实验 | 已实现 | 通过 |  |
| `max-poll-interval-ms` | XDRIVE 字段，文档未写 |  |  | 实验 | 已实现 | 通过 |  |
| `poll-interval-ms` | XDRIVE 字段，文档未写 |  |  | 实验 | 已实现 | 通过 |  |
| `remote-folder` | XDRIVE 字段，文档未写 |  |  | 实验 | 已实现 | 通过 |  |
| `s3` | XDRIVE 字段，文档未写 |  |  | 实验 | 已实现 | 通过 | 取值：`bucket`、`endpoint`、`pathStyle`、`region` |
| `secrets` | XDRIVE 字段，文档未写 |  |  | 实验 | 已实现 | 通过 | 约束：google-drive 需 3 个 secrets |
| `segment-bytes` | XDRIVE 字段，文档未写 |  |  | 实验 | 已实现 | 通过 |  |
| `service` | XDRIVE 字段，文档未写 |  |  | 实验 | 部分 | 未测 | 取值：`google-drive`、`local`、`s3`、`template` |
| `session-ttl-seconds` | XDRIVE 字段，文档未写 |  |  | 实验 | 已实现 | 通过 |  |
| `template` | XDRIVE 字段，文档未写 |  |  | 实验 | 已实现 | 通过 |  |
| `xmux` | XDRIVE 字段，文档未写 |  |  | 实验 | 未实现 | 未测 |  |

## xhttp

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | XHTTP 传输 | 有 |  |  | 已实现 | 通过 | 取值：`xhttp`<br>约束：仅 VLESS |
| `xhttp` | XHTTP 传输，文档页只指向官方讨论 #4113 |  |  | 有 | 已实现 | 通过 | 取值：`splithttp`、`xhttp` |
| `combo` | XHTTP 维度 | 有 |  | 有 | 部分 | 通过 | mode：`auto`、`packet-up`、`stream-one`、`stream-up`<br>alpn：`h2`、`h3`、`http/1.1`<br>security：`jls`、`none`、`reality`、`restls`、`shadow-tls`、`tls`<br>reuse-settings：`max-concurrency`、`max-connections`、`off`<br>download-settings：`off`、`on`<br>x-padding-placement：`cookie`、`header`、`query`、`queryInHeader`<br>session-placement：`cookie`、`header`、`path`、`query`<br>uplink-data-placement：`body`、`cookie`、`header`<br>约束：cookie、header 上行仅 packet-up<br>约束：session-placement 为 path 时 seq-placement 也须为 path<br>约束：source:adapter/outbound/vless.go：xhttp HTTP/3 需 TLS，且不支持 ShadowTLS、Restls、JLS、REALITY<br>约束：默认仅 h2；h3 需 alpn: [h3]；http/1.1 需 alpn: [http/1.1]<br>http_version：`h2`、`h3`、`http/1.1`<br>security：`none`、`reality`、`tls`<br>separation：`downloadSettings`、`same`<br>uplink_placement：`auto`、`body`、`cookie`、`header`<br>proxy：`caddy`、`cdn`、`direct`、`nginx`<br>browser_dialer：`off`、`on`<br>约束：Browser Dialer 时 HTTP 版本由浏览器决定<br>约束：REALITY 下无 H3 路径（讨论只对 TLS 说明，未验证）<br>约束：TLS 时 alpn 仅 h3 用 quic-go H3；服务端此时监听 UDP<br>约束：TLS 时 alpn 仅 http/1.1 用 HTTP/1.1，但不覆盖 uTLS 指纹<br>约束：downloadSettings 不能用于 stream-one<br>约束：packet-up 和 stream-up 支持上下行分离<br>约束：uplinkDataPlacement cookie/header 只能 packet-up<br>约束：uplinkHTTPMethod GET 只能 packet-up<br>约束：不要启用 mux.cool；新版服务端只接受纯 XUDP<br>约束：默认 TLS/REALITY 用 H2，否则 HTTP/1.1 |
| `browser-dialer` | XHTTP 可用 Browser Dialer |  |  | 有 | 未实现 | 未测 |  |
| `download-settings` | 仅客户端，上下行分离，一套独立 streamSettings，多 address、port |  |  | 有 | 部分 | 通过 | 约束：network 必须 xhttp 且不可省略，security 可为 tls 或 reality<br>约束：stream-one 不可用<br>约束：除 sockopt.penetrate 外不继承上行配置 |
| `download-settings-alpn` | 下行 ALPN | 有 |  |  | 已实现 | 通过 | 取值：`列表`<br>约束：上下行分离；未填沿用上行，仅覆盖示例列出的选项 |
| `download-settings-certificate` | 下行客户端证书 | 有 |  |  | 未实现 | 未测 | 取值：`PEM`、`路径`<br>约束：上下行分离；未填沿用上行，仅覆盖示例列出的选项 |
| `download-settings-client-fingerprint` | 下行 uTLS 指纹 | 有 |  |  | 已实现 | 通过 | 取值：`360`、`android`、`chrome`、`edge`、`firefox`、`ios`、`qq`、`random`、`safari`<br>约束：上下行分离；未填沿用上行，仅覆盖示例列出的选项 |
| `download-settings-ech-opts` | 下行 ECH | 有 |  |  | 未实现 | 未测 | 取值：`对象`<br>约束：上下行分离；未填沿用上行，仅覆盖示例列出的选项 |
| `download-settings-fingerprint` | 下行证书指纹 | 有 |  |  | 未实现 | 未测 | 取值：`sha256`<br>约束：上下行分离；未填沿用上行，仅覆盖示例列出的选项 |
| `download-settings-headers` | 下行请求头 | 有 |  |  | 已实现 | 通过 | 取值：`映射`<br>约束：上下行分离；未填沿用上行，仅覆盖示例列出的选项 |
| `download-settings-host` | 下行主机 | 有 |  |  | 已实现 | 通过 | 取值：`域名`<br>约束：上下行分离；未填沿用上行，仅覆盖示例列出的选项 |
| `download-settings-jls-opts` | 下行 JLS | 有 |  |  | 未实现 | 未测 | 取值：`对象`<br>约束：上下行分离；未填沿用上行，仅覆盖示例列出的选项 |
| `download-settings-name-cert-verify` | 下行校验名 | 有 |  |  | 未实现 | 未测 | 取值：`域名`<br>约束：上下行分离；未填沿用上行，仅覆盖示例列出的选项 |
| `download-settings-path` | 下行路径 | 有 |  |  | 已实现 | 通过 | 取值：`路径`<br>约束：上下行分离；未填沿用上行，仅覆盖示例列出的选项 |
| `download-settings-port` | 下行端口 | 有 |  |  | 已实现 | 通过 | 取值：`端口`<br>约束：上下行分离；未填沿用上行，仅覆盖示例列出的选项 |
| `download-settings-private-key` | 下行客户端私钥 | 有 |  |  | 未实现 | 未测 | 取值：`PEM`、`路径`<br>约束：上下行分离；未填沿用上行，仅覆盖示例列出的选项 |
| `download-settings-reality-opts` | 下行 REALITY | 有 |  |  | 已实现 | 通过 | 取值：`对象`<br>约束：上下行分离；未填沿用上行，仅覆盖示例列出的选项 |
| `download-settings-restls-opts` | 下行 Restls | 有 |  |  | 未实现 | 未测 | 取值：`对象`<br>约束：上下行分离；未填沿用上行，仅覆盖示例列出的选项 |
| `download-settings-reuse-settings` | 下行 XMUX | 有 |  |  | 已实现 | 通过 | 取值：`对象`<br>约束：上下行分离；未填沿用上行，仅覆盖示例列出的选项 |
| `download-settings-server` | 下行服务器 | 有 |  |  | 已实现 | 通过 | 取值：`地址`<br>约束：上下行分离；未填沿用上行，仅覆盖示例列出的选项 |
| `download-settings-servername` | 下行 SNI | 有 |  |  | 已实现 | 通过 | 取值：`域名`<br>约束：上下行分离；未填沿用上行，仅覆盖示例列出的选项 |
| `download-settings-shadow-tls-opts` | 下行 ShadowTLS | 有 |  |  | 未实现 | 未测 | 取值：`对象`<br>约束：上下行分离；未填沿用上行，仅覆盖示例列出的选项 |
| `download-settings-skip-cert-verify` | 下行跳过验证 | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true`<br>约束：上下行分离；未填沿用上行，仅覆盖示例列出的选项 |
| `download-settings-tls` | 下行 tls | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true`<br>约束：上下行分离；未填沿用上行，仅覆盖示例列出的选项 |
| `extra` | 除 host、path、mode 外全部参数的原始 JSON 分享方案 |  |  | 有 | 未实现 | 未测 | 约束：extra 存在时外层只有 host、path、mode 生效 |
| `h2-params` | HTTP/2 参数原始 JSON，讨论未解释 |  |  | 有 | 未实现 | 未测 |  |
| `headers` | 请求头 | 有 |  | 有 | 已实现 | 通过 | 取值：`映射`<br>约束：不能含 host |
| `host` | 主机名 | 有 |  | 有 | 已实现 | 通过 | 取值：`域名`<br>约束：不可写在 headers 内 |
| `mode` | 模式 | 有 |  | 有 | 已实现 | 通过 | 取值：`auto`、`packet-up`、`stream-one`、`stream-up`<br>约束：客户端 auto：TLS H2 用 stream-up，REALITY 用 stream-one（有 downloadSettings 时 stream-up），其他 packet-up<br>约束：服务端 auto 接受全部；设具体值只接受它，stream-up 还接受 stream-one |
| `no-grpc-header` | stream-up、stream-one 上行是否发 Content-Type: application/grpc | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true` |
| `no-grpcheader` | stream-up/one，仅客户端，关闭 gRPC Content-Type 伪装 |  |  | 有 | 已实现 | 通过 | 取值：`false`、`true` |
| `no-sseheader` | 仅服务端，关闭 text/event-stream 响应头 |  |  | 有 | 未实现 | 未测 | 取值：`false`、`true` |
| `path` | 请求路径 | 有 |  | 有 | 已实现 | 通过 | 取值：`路径` |
| `reuse-settings` | XMUX 链接复用；无默认值，不填则不开启 | 有 |  |  | 部分 | 通过 | 取值：`对象` |
| `reuse-settings-c-max-reuse-times` | 连接最多被复用次数 | 有 |  |  | 部分 | 通过 | 取值：`0` |
| `reuse-settings-h-keep-alive-period` | H2、H3 空闲保活秒，默认 0；不允许范围，可为负 | 有 |  |  | 部分 | 通过 | 取值：`整数` |
| `reuse-settings-h-max-request-times` | 连接累计承载次数 | 有 |  |  | 部分 | 通过 | 取值：`600-900`<br>约束：文档不建议填写 |
| `reuse-settings-h-max-reusable-secs` | 连接持续该时间后不分配新请求 | 有 |  |  | 部分 | 通过 | 取值：`1800-3000` |
| `reuse-settings-max-concurrency` | 每底层连接最多并发代理请求 | 有 |  |  | 部分 | 通过 | 取值：`16-32`<br>约束：与 max-connections 二选一 |
| `reuse-settings-max-connections` | 最多同时连接数 | 有 |  |  | 部分 | 通过 | 取值：`0`<br>约束：与 max-concurrency 二选一 |
| `sc-max-buffered-posts` | packet-up，仅服务端，单请求缓存 POST 数，默认 30，超限断连 |  |  | 有 | 部分 | 未测 |  |
| `sc-max-each-post-bytes` | 每 POST 最大字节，默认 1000000 | 有 |  | 有 | 部分 | 未测 | 取值：`整数`<br>约束：服务端拒绝大于该值的 POST |
| `sc-min-posts-interval-ms` | POST 最小间隔，默认 30 毫秒 | 有 |  | 有 | 已实现 | 通过 | 取值：`整数` |
| `sc-stream-up-server-secs` | stream-up，仅服务端，保活间隔，默认 20-80 |  |  | 有 | 部分 | 未测 | 取值：`-1`、`20-80`<br>约束：-1 关闭保活 |
| `seq-key` | 序列号键名 | 有 |  | 有 | 已实现 | 通过 | 取值：`字符串`<br>约束：placement 为 path 时不适用 |
| `seq-placement` | 序列号位置 | 有 |  | 有 | 已实现 | 通过 | 取值：`cookie`、`header`、`path`、`query`<br>约束：session-placement 为 path 时也必须为 path |
| `server-max-header-bytes` | 服务端最大请求头字节 |  |  | 有 | 未实现 | 未测 | 约束：不能为负 |
| `session-idkey` | 会话 ID 键名，cookie/query 默认 x_session，header 默认 X-Session |  |  | 有 | 已实现 | 通过 |  |
| `session-idlength` | 会话 ID 长度 Int32Range |  |  | 有 | 未实现 | 未测 | 约束：sessionIDTable 非空时 from 必须大于 0 |
| `session-idplacement` | 会话 ID 位置，默认 path |  |  | 有 | 已实现 | 通过 | 取值：`cookie`、`header`、`path`、`query` |
| `session-idtable` | 会话 ID 字符表 |  |  | 有 | 未实现 | 未测 | 取值：`ALPHABET`、`Alphabet`、`BASE36`、`Base62`、`HEX`、`alphabet`、`base36`、`hex`、`自定义 ASCII`<br>约束：必须 ASCII<br>约束：组合空间须不小于 2^31 |
| `session-key` | 会话 ID 键名 | 有 |  |  | 已实现 | 通过 | 取值：`字符串`<br>约束：placement 为 path 时不适用 |
| `session-length` | 会话 ID 长度范围 | 有 |  |  | 未实现 | 未测 | 取值：`16-32`<br>约束：仅 session-table 不为空或为 uuid 时生效<br>约束：起始值不可为 0，总 id 空间须大于 21 亿 |
| `session-placement` | 会话 ID 位置 | 有 |  |  | 已实现 | 通过 | 取值：`cookie`、`header`、`path`、`query` |
| `session-table` | 会话 ID 字符表 | 有 |  |  | 未实现 | 未测 | 取值：``、`ALPHABET`、`Alphabet`、`BASE36`、`Base62`、`HEX`、`alphabet`、`base36`、`hex`、`number`、`uuid` |
| `source-xff` | 服务端接受 X-Forwarded-For 取真实 IP，受 sockopt.trustedXForwardedFor 约束 |  |  | 有 | 未实现 | 未测 |  |
| `splithttp` | SplitHTTP 是 XHTTP 的旧名 |  |  | 有 | 不适用 | 未测 |  |
| `uplink-chunk-size` | 上行块最大字节 | 有 |  | 有 | 部分 | 未测 | 取值：`整数`<br>约束：仅 uplink-data-placement 不为 body<br>约束：最小 64；cookie 默认 3072，header 默认 4096 |
| `uplink-data-key` | 数据片段键基础名 | 有 |  | 有 | 已实现 | 通过 | 取值：`字符串` |
| `uplink-data-placement` | 上行数据片段位置 | 有 |  | 有 | 已实现 | 通过 | 取值：`auto`、`body`、`cookie`、`header`<br>约束：cookie、header 仅 packet-up<br>约束：cookie、header 只能用于 packet-up |
| `uplink-http-method` | 上行方法 | 有 |  |  | 已实现 | 通过 | 取值：`DELETE`、`PATCH`、`POST`、`PUT` |
| `uplink-httpmethod` | 上行 HTTP 方法，默认 POST |  |  | 有 | 已实现 | 通过 | 取值：`GET`、`POST`、`任意方法`<br>约束：GET 只能用于 packet-up |
| `x-padding-bytes` | 填充长度范围，默认 100-1000 | 有 |  | 有 | 部分 | 未测 | 取值：`100-1000`<br>约束：不能禁用，0 或负值报错 |
| `x-padding-header` | 填充标头 | 有 |  | 有 | 部分 | 未测 | 取值：`Referer`<br>约束：仅 placement 为 header、queryInHeader |
| `x-padding-key` | 填充键名 | 有 |  | 有 | 部分 | 未测 | 取值：`x_padding` |
| `x-padding-method` | 填充生成方式 | 有 |  | 有 | 部分 | 未测 | 取值：`repeat-x`、`tokenish` |
| `x-padding-obfs-mode` | 填充混淆，默认 false | 有 |  | 有 | 部分 | 未测 | 取值：`false`、`true` |
| `x-padding-placement` | 填充位置 | 有 |  | 有 | 部分 | 未测 | 取值：`cookie`、`header`、`query`、`queryInHeader`<br>约束：仅 x-padding-obfs-mode 为 true |

## xmux

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `c-max-reuse-times` | XMUX：单连接最大复用次数，默认 0 不限 |  |  | 有 | 部分 | 通过 | 取值：`0`<br>约束：主要用于 H2/H3，仅客户端<br>约束：填任一项后其他项失去默认值 |
| `h-keep-alive-period` | XMUX：空闲保活秒数，默认 0（H2 45 秒，H3 10 秒），-1 关闭 |  |  | 有 | 部分 | 通过 | 取值：`-1`、`0`<br>约束：主要用于 H2/H3，仅客户端<br>约束：唯一不允许范围、允许负数的项<br>约束：填任一项后其他项失去默认值 |
| `h-max-request-times` | XMUX：单连接累计 HTTP 请求数，XMUX 全零时默认 600-900 |  |  | 有 | 部分 | 通过 | 取值：`600-900`<br>约束：主要用于 H2/H3，仅客户端<br>约束：填任一项后其他项失去默认值 |
| `h-max-reusable-secs` | XMUX：单连接可复用秒数，XMUX 全零时默认 1800-3000 |  |  | 有 | 部分 | 通过 | 取值：`1800-3000`<br>约束：主要用于 H2/H3，仅客户端<br>约束：填任一项后其他项失去默认值 |
| `max-concurrency` | XMUX：每条连接最大同时代理请求，XMUX 全零时默认 16-32 |  |  | 有 | 部分 | 通过 | 取值：`16-32`<br>约束：不能与 maxConnections/maxConcurrency 同用<br>约束：主要用于 H2/H3，仅客户端<br>约束：填任一项后其他项失去默认值 |
| `max-connections` | XMUX：最大连接数，默认 0 不限 |  |  | 有 | 部分 | 通过 | 取值：`0`<br>约束：不能与 maxConnections/maxConcurrency 同用<br>约束：主要用于 H2/H3，仅客户端<br>约束：填任一项后其他项失去默认值 |
