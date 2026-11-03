# 拨号选项

由 `tools/capability_matrix.py build` 生成，不要手改。

## common

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `dialer-proxy` | 当前节点经指定策略组或出站建立连接 | 有 |  |  | 已实现 | 通过 | 取值：`出站名`、`策略组名` |
| `interface-name` | 节点绑定接口 | 有 |  |  | 部分 | 通过 | 取值：`接口名` |
| `ip-version` | 出站 IP 版本，默认 dual | 有 |  |  | 部分 | 通过 | 取值：`dual`、`ipv4`、`ipv4-prefer`、`ipv6`、`ipv6-prefer`<br>约束：ipv4-prefer、ipv6-prefer：TCP 双栈并发优先指定族；UDP 取解析结果中第一个指定族<br>约束：非 direct 时影响 server 为域名时用的 IP |
| `mptcp` | TCP Multi Path | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true`<br>约束：仅 TCP 协议 |
| `routing-mark` | 节点连接的路由标记 | 有 |  |  | 已实现 | 通过 | 取值：`整数` |
| `tfo` | TCP Fast Open | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true`<br>约束：仅 TCP 协议 |

## custom-sockopt

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `level` | 协议级别，默认 6 |  |  | 有 | 未实现 | 未测 |  |
| `network` | 生效网络类型 |  |  | 有 | 未实现 | 未测 | 取值：`tcp`、`tcp4`、`tcp6`、`udp`、`udp4`、`udp6` |
| `opt` | 选项号，十进制 |  |  | 有 | 未实现 | 未测 |  |
| `system` | 生效系统，留空直接执行 |  |  | 有 | 未实现 | 未测 | 取值：`android`、`darwin`、`linux`、`windows` |
| `type` | 必填，值类型 |  |  | 有 | 未实现 | 未测 | 取值：`int`、`str` |
| `value` | 选项值 |  |  | 有 | 未实现 | 未测 | 约束：type 为 int 时用十进制 |

## dial

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | 拨号字段的维度和约束 |  | 有 |  | 部分 | 通过 | mode：`detour`、`direct-fields`<br>bind：`bind_address_no_port`、`bind_interface`、`inet4_bind_address`、`inet6_bind_address`、`netns`、`reuse_addr`、`routing_mark`<br>tcp：`disable_tcp_keep_alive`、`tcp_fast_open`、`tcp_keep_alive`、`tcp_keep_alive_interval`、`tcp_multi_path`<br>udp：`udp_fragment`<br>resolve：`domain_resolver:object`、`domain_resolver:string`、`domain_strategy(deprecated)`<br>network_strategy：`default`、`fallback`、`hybrid`<br>network_type：`cellular`、`ethernet`、`other`、`wifi`<br>约束：bind_address_no_port、routing_mark、netns 仅 Linux<br>约束：network_* 和 fallback_delay 仅图形客户端且需 auto_detect_interface<br>约束：network_strategy 与 bind_interface、inet4_bind_address、inet6_bind_address 冲突<br>约束：只有一个 DNS 服务器时 domain_resolver 可省略<br>约束：服务器地址为域名时，domain_resolver 或 route.default_domain_resolver 在 1.14.0 后必需（文档写法）<br>约束：设了 detour 时其他字段被忽略 |
| `bind-address-no-port` | 绑定到源地址时不保留端口。 |  | 有 |  | 未实现 | 未测 | 约束：仅支持 Linux。<br>约束：自 sing-box 1.13.0 起 |
| `bind-interface` | 要绑定到的网络接口。 |  | 有 |  | 部分 | 通过 |  |
| `connect-timeout` | 连接超时，采用 golang 的 Duration 格式。 |  | 有 |  | 部分 | 通过 |  |
| `detour` | 上游出站的标签。 |  | 有 |  | 已实现 | 通过 | 约束：启用时，其他拨号字段将被忽略。 |
| `disable-tcp-keep-alive` | 禁用 TCP keep alive。 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.13.0 起 |
| `domain-resolver` | 用于设置解析域名的域名解析器。 |  | 有 |  | 部分 | 通过 | 约束：`outbound` DNS 规则项已弃用，且将在 sing-box 1.14.0 中被移除。<br>约束：当只有一个 DNS 服务器已配置时，`domain_resolver` 或 `route.default_domain_resolver` 是可选的。 |
| `domain-strategy` | 可选值：`prefer_ipv4` `prefer_ipv6` `ipv4_only` `ipv6_only`。 |  | 废弃 |  | 部分 | 通过 | 取值：`ipv4_only`、`ipv6_only`、`prefer_ipv4`、`prefer_ipv6`<br>约束：`domain_strategy` 已废弃且将在 sing-box 1.14.0 中被移除，参阅 迁移指南。 |
| `fallback-delay` | 在生成 RFC 6555 快速回退连接之前等待的时间长度。 |  | 有 |  | 部分 | 通过 | 约束：仅当 `domain_strategy` 或 `network_strategy` 已设置时生效。<br>约束：自 sing-box 1.11.0 起<br>约束：默认使用 `300ms`。 |
| `fallback-network-type` | 当使用 `fallback` 网络策略时，在首选网络不可用或超时的情况下要使用的回退网络类型。 |  | 有 |  | 未实现 | 未测 | 取值：`cellular`、`ethernet`、`other`、`wifi`<br>约束：仅在 Android 与 iOS 平台图形客户端中支持，并且需要 `route.auto_detect_interface`。<br>约束：自 sing-box 1.11.0 起<br>约束：默认使用除首选网络外的所有其他网络。 |
| `inet4-bind-address` | 要绑定的 IPv4 地址。 |  | 有 |  | 部分 | 通过 |  |
| `inet6-bind-address` | 要绑定的 IPv6 地址。 |  | 有 |  | 部分 | 通过 |  |
| `netns` | 设置网络命名空间，名称或路径。 |  | 有 |  | 未实现 | 未测 | 约束：仅支持 Linux。<br>约束：自 sing-box 1.12.0 起 |
| `network-strategy` | 用于选择网络接口的策略。 |  | 有 |  | 未实现 | 未测 | 取值：`default`、`fallback`、`hybrid`<br>约束：- `default`（默认值）：按顺序连接默认网络或 `network_type` 中指定的网络。<br>约束：- `fallback`：同时连接默认网络或 `network_type` 中指定的首选网络，当不可用或超时时尝试回退网络。<br>约束：与 `bind_interface`, `bind_inet4_address` 和 `bind_inet6_address` 冲突。<br>约束：仅在 Android 与 iOS 平台图形客户端中支持，并且需要 `route.auto_detect_interface`。<br>约束：自 sing-box 1.11.0 起 |
| `network-type` | 当使用 `default` 或 `hybrid` 网络策略时要使用的网络类型，或当使用 `fallback` 网络策略时要使用的首选网络类型。 |  | 有 |  | 未实现 | 未测 | 取值：`cellular`、`ethernet`、`other`、`wifi`<br>约束：仅在 Android 与 iOS 平台图形客户端中支持，并且需要 `route.auto_detect_interface`。<br>约束：自 sing-box 1.11.0 起<br>约束：默认使用设备默认网络。 |
| `protect-path` | 拨号 socket 保护路径，文档未列 |  | 有 |  | 未实现 | 未测 |  |
| `reuse-addr` | 重用监听地址。 |  | 有 |  | 部分 | 通过 |  |
| `routing-mark` | 设置 netfilter 路由标记。 |  | 有 |  | 已实现 | 通过 | 约束：仅支持 Linux。 |
| `tcp-fast-open` | 启用 TCP Fast Open。 |  | 有 |  | 已实现 | 通过 |  |
| `tcp-keep-alive` | TCP keep alive 初始周期。 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.13.0 起<br>约束：默认使用 `5m`。<br>约束：默认值从 `10m` 更改为 `5m`。 |
| `tcp-keep-alive-interval` | TCP keep alive 间隔。 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.13.0 起<br>约束：默认使用 `75s`。 |
| `tcp-multi-path` | 启用 TCP Multi Path。 |  | 有 |  | 未实现 | 未测 | 约束：需要 Go 1.21。 |
| `udp-fragment` | 启用 UDP 分段。 |  | 有 |  | 未实现 | 未测 |  |

## dialer-proxy

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `chain` | dialer-proxy 代理链，ss1 经 ss2 建立连接 | 有 |  |  | 已实现 | 通过 | 取值：`provider override`、`proxy`、`select`<br>约束：策略组不直接支持 dialer-proxy，可经 provider override 设置<br>约束：被中转落地不建议用 udp 类协议或 tls 伪装类协议 |
| `provider-override` | 用 provider override.dialer-proxy 给集合内全部节点设前置 | 有 |  |  | 未实现 | 未测 |  |
| `relay-migration` | relay 策略组迁移到 dialer-proxy 的方案 | 有 |  |  | 未实现 | 未测 |  |

## global

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `disable-keep-alive` | 禁用 TCP Keep Alive | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true`<br>约束：Android 强制为 true |
| `interface-name` | 全局流量出站接口 | 有 |  |  | 部分 | 通过 | 取值：`接口名` |
| `keep-alive-idle` | TCP Keep Alive 最大空闲时间 | 有 |  |  | 已实现 | 通过 | 取值：`整数` |
| `keep-alive-interval` | TCP Keep Alive 包间隔，单位秒 | 有 |  |  | 已实现 | 通过 | 取值：`整数` |
| `routing-mark` | Linux 出站连接默认流量标记 | 有 |  |  | 已实现 | 通过 | 取值：`整数`<br>约束：仅 Linux |
| `tcp-concurrent` | 并发连接 DNS 解析出的所有 IP，用第一个成功的连接 | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |

## happy-eyeballs

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `interleave` | First Address Family count，默认 1 |  |  | 有 | 未实现 | 未测 |  |
| `max-concurrent-try` | 最大并发，默认 4，0 禁用 |  |  | 有 | 未实现 | 未测 |  |
| `prioritize-ipv6` | 首个 IP 类型，默认 false |  |  | 有 | 未实现 | 未测 |  |
| `try-delay-ms` | 竞速间隔毫秒，默认 0 禁用，推荐 250 |  |  | 有 | 未实现 | 未测 |  |

## sockopt

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | Dialer 组合 |  |  | 有 | 部分 | 通过 | domain_strategy：`AsIs`、`ForceIP`、`ForceIPv4`、`ForceIPv4v6`、`ForceIPv6`、`ForceIPv6v4`、`UseIP`、`UseIPv4`、`UseIPv4v6`、`UseIPv6`、`UseIPv6v4`<br>chain：`dialerProxy`、`none`<br>bind：`interface`、`mark`、`none`、`sendThrough`<br>tcp：`congestion`、`keepalive`、`maxSeg`、`mptcp`、`tfo`、`userTimeout`、`windowClamp`<br>happy_eyeballs：`off`、`on`<br>address_port：`none`、`srv`、`txt`<br>scope：`inbound`、`outbound`<br>约束：Freedom 不支持 addressPortStrategy<br>约束：UseIPv4v6/ForceIPv4v6 配 happyEyeballs 时列表缩减，不推荐，建议 UseIP/ForceIP+interleave<br>约束：domainStrategy 配置不当可能循环<br>约束：happyEyeballs 与 dialerProxy 互斥 |
| `accept-proxy-protocol` | 仅入站，接收 PROXY protocol |  |  | 有 | 已实现 | 通过 |  |
| `address-port-strategy` | 用 SRV/TXT 记录指定地址端口，默认 none |  |  | 有 | 未实现 | 未测 | 取值：`SrvAddressOnly`、`SrvPortAndAddress`、`SrvPortOnly`、`TxtAddressOnly`、`TxtPortAndAddress`、`TxtPortOnly`、`none`<br>约束：Freedom 不支持<br>约束：在 domainStrategy 前生效<br>约束：失败按原地址发出<br>约束：查询走系统 DNS |
| `custom-sockopt` | 自定义 sockopt 数组 |  |  | 有 | 未实现 | 未测 | 约束：支持 Linux、Windows、Darwin |
| `dialer-proxy` | 经指定出站发起连接，用于链式代理 |  |  | 有 | 已实现 | 通过 | 约束：Freedom 配置后不执行 finalRules<br>约束：happyEyeballs 不能同用 |
| `domain-strategy` | 出站底层连接的目标域名解析策略，默认 AsIs |  |  | 有 | 部分 | 通过 | 取值：`AsIs`、`ForceIP`、`ForceIPv4`、`ForceIPv4v6`、`ForceIPv6`、`ForceIPv6v4`、`UseIP`、`UseIPv4`、`UseIPv4v6`、`UseIPv6`、`UseIPv6v4`<br>约束：Force 开头失败不连接<br>约束：Freedom 控制请求目标；代理出站控制服务器域名<br>约束：Use 开头失败回退 AsIs<br>约束：与 dns.queryStrategy 取交集<br>约束：与 sendThrough 地址族不符会失败 |
| `happy-eyeballs` | RFC 8305 竞速，仅 TCP |  |  | 有 | 未实现 | 未测 | 约束：不能与 dialerProxy 同用<br>约束：目标为域名且 domainStrategy 非 AsIs 才生效 |
| `interface` | 绑定出口网卡 |  |  | 有 | 部分 | 通过 | 约束：支持 linux、iOS、Mac OS、Windows |
| `mark` | SO_MARK |  |  | 有 | 已实现 | 通过 | 约束：仅 Linux<br>约束：需 CAP_NET_ADMIN |
| `penetrate` | XHTTP 上下行分离时上行 sockopt 覆盖下行 |  |  | 有 | 未实现 | 未测 |  |
| `tcp-fast-open` | TCP Fast Open |  |  | 有 | 已实现 | 通过 | 取值：`0`、`false`、`true`、`正整数`、`负数`<br>约束：Windows 实现不正确<br>约束：false 或负数强关，缺省或 0 用系统设置<br>约束：入站正整数为待处理上限：Linux/FreeBSD 生效，true 取 256 |
| `tcp-keep-alive-idle` | TCP 空闲阈值秒 |  |  | 有 | 已实现 | 通过 | 约束：入站默认禁用，非零启用<br>约束：出站默认 idle 与 interval 45 秒，负数禁用 |
| `tcp-keep-alive-interval` | Keep-Alive 间隔秒 |  |  | 有 | 已实现 | 通过 |  |
| `tcp-max-seg` | TCP 最大分段 |  |  | 有 | 未实现 | 未测 |  |
| `tcp-mptcp` | 启用 MPTCP，默认 false |  |  | 有 | 未实现 | 未测 | 约束：仅 Linux，内核 5.6+<br>约束：仅客户端参数 |
| `tcp-user-timeout` | TCP_USER_TIMEOUT 毫秒 |  |  | 有 | 未实现 | 未测 |  |
| `tcp-window-clamp` | 绑定通告窗口大小 |  |  | 有 | 未实现 | 未测 |  |
| `tcpcongestion` | TCP 拥塞算法，仅 Linux |  |  | 有 | 未实现 | 未测 | 取值：`bbr`、`cubic`、`reno` |
| `trusted-xforwarded-for` | 可信 XFF 判定头名单 |  |  | 有 | 未实现 | 未测 | 约束：仅 XHTTP、WebSocket、HTTPUpgrade、gRPC<br>约束：任一头存在时用 XFF 第 0 个值覆盖源 IP |
| `v6-only` | 监听 :: 只接受 IPv6 |  |  | 有 | 部分 | 通过 | 约束：仅 Linux |
