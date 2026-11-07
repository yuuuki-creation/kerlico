# TUN 与系统接入

由 `tools/capability_matrix.py build` 生成，不要手改。

## iptables

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `bypass` | iptables 绕过列表（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`列表` |
| `dns-redirect` | iptables DNS 重定向（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `enable` | iptables 自动配置开关（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `inbound-interface` | iptables 入站接口（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`接口名` |

## redirect

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | 透明代理 Redirect 入站 |  | 有 |  | 未实现 | 未测 | 取值：`redirect`<br>约束：不可作 detour 注入目标<br>约束：仅支持 Linux、macOS |

## system-proxy

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `http-proxy-env` | 文档只给环境变量接入方式，无自动系统代理配置 |  |  | 有 | 未实现 | 未测 | 取值：`http_proxy`、`https_proxy` |
| `set-system-proxy` | http、mixed 入站自动设置和清理系统代理 |  | 有 |  | 未实现 | 未测 | 取值：`false`、`true`<br>约束：Android 和 Apple 无特权时用 tun.platform.http_proxy<br>约束：仅支持 Linux、Android、Windows、macOS |

## tproxy

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | 透明代理 TProxy 入站 |  | 有 |  | 已实现 | 通过 | 取值：`tproxy`<br>约束：不可作 detour 注入目标<br>约束：仅支持 Linux |
| `combo` | 透明代理组合 |  |  | 有 | 已实现 | 通过 | mode：`redirect`、`tproxy`<br>network：`tcp`、`udp`<br>ip：`ipv4`、`ipv6`<br>inbound：`tunnel`<br>domain_recover：`fakedns`、`sniffing`<br>约束：redirect 不支持 UDP<br>约束：tunnel 须 followRedirect 才取原目标<br>约束：仅 Linux<br>约束：透明代理教程见 docs/document/level-2/tproxy.md |
| `network` | 监听的网络协议，`tcp` `udp` 之一。 |  | 有 |  | 已实现 | 通过 | 取值：`tcp`、`udp`<br>约束：默认所有。 |
| `tproxy` | 透明代理模式 |  |  | 有 | 已实现 | 通过 | 取值：`off`、`redirect`、`tproxy`<br>约束：redirect 支持 IPv4/6 TCP<br>约束：tproxy 支持 IPv4/6 TCP 和 UDP<br>约束：tunnel.followRedirect=true 且 tproxy 为空时设为 redirect<br>约束：仅 Linux<br>约束：需 Root 或 CAP_NET_ADMIN |

## transparent

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | 透明接入和系统代理方式的组合 |  | 有 |  | 已实现 | 通过 | inbound：`redirect`、`tproxy`、`tun`<br>network：`tcp`、`tcp+udp`、`udp`<br>system_proxy：`set_system_proxy`、`tun.platform.http_proxy`<br>约束：platform.http_proxy.match_domain 仅 Apple 图形客户端<br>约束：redirect 仅 Linux、macOS<br>约束：tproxy 仅 Linux<br>约束：tproxy 有 network 和 UDP NAT 字段（udp_mapping、udp_filtering、udp_nat_max 自 1.14.0） |

## tun

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | TUN 虚拟网卡入站 |  | 有 |  | 已实现 | 通过 | 取值：`tun`<br>约束：不可作 detour 注入目标<br>约束：仅支持 Linux、Windows、macOS |
| `combo` | 顶层 TUN 维度 | 有 | 有 | 有 | 部分 | 通过 | stack：`gvisor`、`mips`、`mixed`、`system`<br>auto-route：`false`、`true`<br>auto-redirect：`false`、`true`<br>strict-route：`false`、`true`<br>dns-mode：``、`disabled`、`hijack`、`native`<br>gso：`false`、`true`<br>endpoint-independent-nat：`false`、`true`<br>congestion-controller：`bbr`、`bbr3`、`cubic`、`reno`<br>enhanced-mode：`fake-ip`、`redir-host`<br>ip-family：`ipv4`、`ipv4+ipv6`<br>约束：auto-redirect 需要 auto-route 且仅 Linux<br>约束：congestion-controller 仅 mips<br>约束：dns-mode hijack：Windows 需 strict-route，Linux 需 auto-redirect<br>约束：include-interface 与 exclude-interface 互斥<br>约束：include-mac-address、exclude-mac-address 需 auto-route、auto-redirect<br>约束：inet6-address 需顶层 ipv6 true<br>约束：route-address-set、route-exclude-address-set 需 nftables、auto-route、auto-redirect，且与 routing-mark 冲突<br>stack：`default(sing-tun)`、`gvisor`、`mixed`、`system`<br>address_family：`dual`、`ipv4`、`ipv6`<br>auto_route：`off`、`on`<br>auto_redirect：`off`、`on`<br>strict_route：`off`、`on`<br>dns_mode：`disabled`、`hijack`、`native`<br>route_filter：`route_address`、`route_address_set`、`route_exclude_address`、`route_exclude_address_set`<br>multi_queue：`off`、`on`<br>selector：`exclude_interface`、`exclude_mac_address`、`exclude_package`、`exclude_uid`、`exclude_uid_range`、`include_android_user`、`include_interface`、`include_mac_address`、`include_package`、`include_uid`、`include_uid_range`<br>netns：`off`、`on`<br>udp_nat：`udp_filtering`、`udp_mapping`、`udp_nat_max`<br>exclude_mptcp：`off`、`on`<br>约束：auto_redirect 需要 auto_route，仅 Linux；与 route.default_mark、拨号 routing_mark 冲突<br>约束：dns_mode 默认：开 auto_route 时 hijack，否则 disabled<br>约束：exclude_mptcp 需要 Linux nftables、auto_route、auto_redirect<br>约束：include_interface 与 exclude_interface 冲突<br>约束：include_mac_address 与 exclude_mac_address 冲突，都需要 Linux、auto_route、auto_redirect<br>约束：multi_queue 仅 Linux，需要 sing-tun 自研栈（source:protocol/tun/inbound.go）<br>约束：netns 仅 Linux，与 platform 冲突<br>约束：route_address_set 不开 auto_redirect 时不适用于 Android 和 Apple 图形客户端<br>约束：stack 自 1.15.0 废弃，1.17.0 移除<br>约束：strict_route 下 exclude_interface 的回程要自行排除<br>约束：接口和 UID 规则仅 Linux 且需要 auto_route；Android 用户和包规则仅 Android 且需要 auto_route<br>约束：未设 dns_address 时用 address 的下一个地址并按 hijack-dns 处理；设置后要配 hijack-dns 路由规则<br>约束：避免回环需设 route.auto_detect_interface、route.default_interface 或 outbound.bind_interface<br>platform：`android`、`freebsd`、`ios`、`linux`、`macos`、`windows`<br>route：`autoSystemRoutingTable`、`manual`<br>outbound_interface：`autoOutboundsInterface`、`manual_sockopt_interface`、`sendThrough`<br>fd：`XRAY_TUN_FD`、`created`<br>约束：Android/iOS 只能传 FD<br>约束：FreeBSD 需手动路由表<br>约束：未配 autoSystemRoutingTable 时需手动配路由<br>约束：注意回环，优先 autoOutboundsInterface<br>约束：进程路由可限定代理进程 |
| `address` | tun 接口的 IPv4 和 IPv6 前缀。 |  | 有 |  | 已实现 | 通过 | 约束：必填<br>约束：自 sing-box 1.10.0 起 |
| `auto-detect-interface` | 自动选择出口接口 | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true` |
| `auto-outbounds-interface` | 为所有出站自动绑定物理接口，防回环 |  |  | 有 | 已实现 | 通过 | 取值：`auto`、`null`、`接口名`<br>约束：也覆盖内置 DNS 的 local 模式<br>约束：手动 sockopt 可覆盖<br>约束：配了 autoSystemRoutingTable 未显式指定时按 auto |
| `auto-redirect` | 自动配置 iptables/nftables 重定向 TCP | 有 | 有 |  | 未实现 | 未测 | 取值：`false`、`true`<br>约束：Android 仅转发本地 IPv4<br>约束：仅 Linux<br>约束：需要 auto-route<br>约束：与 `route.default_mark` 和 `[dialOptions].routing_mark` 冲突。<br>约束：仅支持 Linux，且需要 `auto_route` 已启用。<br>约束：在 Linux 上始终推荐使用 `auto_redirect`，它提供更好的路由、更高的性能（优于 tproxy），并避免了 TUN 和 Docker 桥接网络之间的冲突。<br>约束：自 sing-box 1.10.0 起<br>约束：预匹配需要内核支持 nfqueue（`nfnetlink_queue`）。 |
| `auto-redirect-input-mark` | auto-redirect 输入标记（文档未写） | 有 | 有 |  | 未实现 | 未测 | 取值：`整数`<br>约束：自 sing-box 1.10.0 起<br>约束：默认使用 `0x2023`（Android 上为 `0x400000`）。 |
| `auto-redirect-iproute2-fallback-rule-index` | auto-redirect 回退规则索引（文档未写） | 有 | 有 |  | 未实现 | 未测 | 取值：`整数`<br>约束：此规则在系统默认规则（32766: main，32767: default）之后检查，仅当系统路由表中未找到路由时才将流量路由到 sing-box 路由表。<br>约束：自 sing-box 1.12.18 起<br>约束：默认使用 `32768`。 |
| `auto-redirect-nfqueue` | `auto_redirect` 预匹配使用的 NFQueue 编号。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.13.0 起<br>约束：默认使用 `100`。 |
| `auto-redirect-output-mark` | auto-redirect 输出标记（文档未写） | 有 | 有 |  | 未实现 | 未测 | 取值：`整数`<br>约束：自 sing-box 1.10.0 起<br>约束：默认使用 `0x2024`（Android 上为 `0x200000`）。 |
| `auto-redirect-reset-mark` | `auto_redirect` 预匹配使用的连接重置标记。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.13.0 起<br>约束：默认使用 `0x2025`（Android 上为 `0x600000`）。 |
| `auto-redirect-tproxy-mark` | `auto_redirect` iptables 后端为 IPv6 TCP 使用的连接 TPROXY 标记。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.15.0 起<br>约束：默认使用 `0x2026`（Android 上为 `0x800000`）。 |
| `auto-route` | 自动全局路由 | 有 | 有 |  | 已实现 | 通过 | 取值：`false`、`true`<br>约束：VPN 默认优先于 tun。<br>约束：在 Linux 上始终推荐使用 `auto_redirect`，它提供更好的路由， 更高的性能（优于 tproxy）， 并避免 TUN 与 Docker 桥接网络冲突。 |
| `auto-system-dns-to-gateway` | 把系统 DNS 指向网关 |  |  | 有 | 已实现 | 通过 | 约束：Linux/FreeBSD 需设置 gateway<br>约束：文档未写 |
| `auto-system-routing-table` | 自动写入系统路由表的 CIDR 列表 |  |  | 有 | 已实现 | 通过 | 取值：`0.0.0.0/0`、`::/0`<br>约束：支持 Windows、macOS、Linux；FreeBSD 需手动 |
| `auto-system-wfp-block-leak` | Windows WFP 防泄漏过滤 |  |  | 有 | 未实现 | 未测 | 取值：`<cidr>:<值>`、`<port>`、`[<ipv6cidr>]:<值>`、`all`、`allexceptlan`、`dns`、`icmp`、`misconfigtun`、`tcp`、`tcp/<port>`、`udp`、`udp/<low>-<high>`、`windnsclient`<br>约束：all、allexceptlan、dns、windnsclient、TCP/UDP 53 需 dns<br>约束：文档未写<br>约束：需 autoSystemRoutingTable |
| `congestion-controller` | TCP 拥塞控制，默认 cubic | 有 |  |  | 部分 | 通过 | 取值：`bbr`、`bbr3`、`cubic`、`reno`<br>约束：仅 mips 协议栈 |
| `desc` | Windows 接口描述，默认 Wintun |  |  | 有 | 未实现 | 未测 |  |
| `device` | tun 网卡名 | 有 |  |  | 已实现 | 通过 | 取值：`名称`<br>约束：macOS 只能用 utun 开头 |
| `disable-icmp-forwarding` | 禁用 ICMP 转发 | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `dns` | 接口 DNS 列表 |  |  | 有 | 已实现 | 通过 | 约束：只在 Windows 有效 |
| `dns-address` | `dns_mode` 使用的 DNS 服务器地址列表。 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.14.0 起 |
| `dns-hijack` | DNS 劫持，不写协议为 udp:// | 有 |  |  | 已实现 | 通过 | 取值：`any:53`、`tcp://any:53`<br>约束：Android 开启私人 DNS 时无法自动劫持<br>约束：macOS、Windows 无法自动劫持发往局域网的 DNS |
| `dns-mode` | 系统 DNS 配置方式 | 有 | 有 |  | 已实现 | 通过 | 取值：``、`disabled`、`hijack`、`native`<br>约束：hijack：Windows 需 strict-route，Linux 需 auto-redirect<br>约束：留空：Windows、Linux 启用 auto-route 时默认 hijack，否则 disabled；macOS 默认 disabled<br>约束：启用 `auto_route` 时默认使用 `hijack`，否则默认使用 `disabled`。<br>约束：自 sing-box 1.14.0 起 |
| `enable` | 启用 tun | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true` |
| `endpoint-independent-nat` | 独立于端点的 NAT | 有 | 废弃 |  | 未实现 | 未测 | 取值：`false`、`true` |
| `exclude-dst-port` | 排除目标端口（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`端口列表` |
| `exclude-dst-port-range` | 排除目标端口范围（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`范围列表` |
| `exclude-interface` | 排除路由接口 | 有 | 有 |  | 未实现 | 未测 | 取值：`接口列表`<br>约束：与 include-interface 冲突<br>约束：与 `include_interface` 冲突。 |
| `exclude-mac-address` | 按来源 MAC 排除局域网设备 | 有 | 有 |  | 未实现 | 未测 | 取值：`MAC 列表`<br>约束：仅 Linux，需 auto-route、auto-redirect<br>约束：与 `include_mac_address` 冲突。<br>约束：仅支持 Linux，且需要 `auto_route` 和 `auto_redirect` 已启用。<br>约束：自 sing-box 1.14.0 起 |
| `exclude-mptcp` | 由于协议限制，MPTCP 无法被透明代理。 |  | 有 |  | 未实现 | 未测 | 约束：仅支持 Linux，且需要 nftables，`auto_route` 和 `auto_redirect` 已启用。<br>约束：自 sing-box 1.13.0 起 |
| `exclude-package` | 排除的 Android 包 | 有 | 有 |  | 未实现 | 未测 | 取值：`包名列表`<br>约束：仅 Android，需 auto-route |
| `exclude-src-port` | 排除来源端口（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`端口列表` |
| `exclude-src-port-range` | 排除来源端口范围（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`范围列表` |
| `exclude-uid` | 排除用户 | 有 | 有 |  | 未实现 | 未测 | 取值：`整数列表`<br>约束：仅 Linux，需 auto-route |
| `exclude-uid-range` | 排除用户范围 | 有 | 有 |  | 未实现 | 未测 | 取值：`1000:9999`<br>约束：仅 Linux，需 auto-route |
| `file-descriptor` | 外部传入 tun 文件描述符（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `gateway` | 接口地址前缀列表 |  |  | 有 | 已实现 | 通过 | 取值：`10.0.0.1/16`、`fc00::1/64`<br>约束：macOS 仅 IPv4 生效，未设置用 169.254.10.1/30 |
| `gso` | 通用分段卸载 | 有 | 已移除 |  | 未实现 | 未测 | 取值：`false`、`true`<br>约束：仅 Linux<br>约束：GSO 对于透明代理场景没有优势，已废弃和不再生效，且将在 sing-box 1.12.0 中被移除。<br>约束：仅支持 Linux。<br>约束：自 sing-box 1.8.0 起 |
| `gso-max-size` | GSO 数据块最大长度 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `icmp-timeout` | ICMP 超时（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `include-android-user` | 包含的 Android 用户 | 有 | 有 |  | 未实现 | 未测 | 取值：`0`、`10`、`999`<br>约束：仅 Android，需 auto-route<br>约束：Android 用户和应用规则仅在 Android 下被支持，并且需要 `auto_route`。 |
| `include-interface` | 限制被路由接口 | 有 | 有 |  | 未实现 | 未测 | 取值：`接口列表`<br>约束：与 exclude-interface 冲突<br>约束：与 `exclude_interface` 冲突。<br>约束：接口规则仅在 Linux 下被支持，并且需要 `auto_route`。<br>约束：默认不限制。 |
| `include-mac-address` | 按来源 MAC 限制局域网设备 | 有 | 有 |  | 未实现 | 未测 | 取值：`MAC 列表`<br>约束：仅 Linux，需 auto-route、auto-redirect<br>约束：与 `exclude_mac_address` 冲突。<br>约束：仅支持 Linux，且需要 `auto_route` 和 `auto_redirect` 已启用。<br>约束：自 sing-box 1.14.0 起<br>约束：默认不限制。 |
| `include-package` | 包含的 Android 包 | 有 | 有 |  | 未实现 | 未测 | 取值：`包名列表`<br>约束：仅 Android，需 auto-route |
| `include-uid` | 包含的用户 | 有 | 有 |  | 未实现 | 未测 | 取值：`整数列表`<br>约束：仅 Linux，需 auto-route<br>约束：UID 规则仅在 Linux 下被支持，并且需要 `auto_route`。<br>约束：默认不限制。 |
| `include-uid-range` | 包含的用户范围 | 有 | 有 |  | 未实现 | 未测 | 取值：`1000:9999`<br>约束：仅 Linux，需 auto-route |
| `inet4-address` | tun IPv4 地址（文档未写） | 有 | 已移除 |  | 已实现 | 通过 | 取值：`CIDR 列表`<br>约束：`inet4_address` 已合并到 `address` 且将在 sing-box 1.12.0 中被移除。<br>约束：必填 |
| `inet4-route-address` | 旧写法 IPv4 路由 | 废弃 | 已移除 |  | 不适用 | 未测 | 取值：`CIDR 列表`<br>约束：`inet4_route_address` 已合并到 `route_address` 且将在 sing-box 1.12.0 中被移除。 |
| `inet4-route-exclude-address` | 旧写法 IPv4 排除 | 废弃 | 已移除 |  | 不适用 | 未测 | 取值：`CIDR 列表`<br>约束：`inet4_route_exclude_address` 已合并到 `route_exclude_address` 且将在 sing-box 1.12.0 中被移除。 |
| `inet6-address` | tun IPv6 地址 | 有 | 已移除 |  | 已实现 | 通过 | 取值：`CIDR 列表`<br>约束：启动时无 IPv6 网卡会禁用，可设 SKIP_SYSTEM_IPV6_CHECK=1<br>约束：需顶层 ipv6 为 true<br>约束：`inet6_address` 已合并到 `address` 且将在 sing-box 1.12.0 中被移除。 |
| `inet6-route-address` | 旧写法 IPv6 路由 | 废弃 | 已移除 |  | 不适用 | 未测 | 取值：`CIDR 列表`<br>约束：`inet6_route_address` 已合并到 `route_address` 且将在 sing-box 1.12.0 中被移除。 |
| `inet6-route-exclude-address` | 旧写法 IPv6 排除 | 废弃 | 已移除 |  | 不适用 | 未测 | 取值：`CIDR 列表`<br>约束：`inet6_route_exclude_address` 已合并到 `route_exclude_address` 且将在 sing-box 1.12.0 中被移除。 |
| `interface-name` | 虚拟设备名称，默认自动选择。 |  | 有 |  | 已实现 | 通过 |  |
| `iproute2-rule-index` | auto-route 规则起始索引，默认 9000 | 有 | 有 |  | 已实现 | 通过 | 取值：`整数`<br>约束：自 sing-box 1.10.0 起<br>约束：默认使用 `9000`。 |
| `iproute2-table-index` | auto-route 路由表索引，默认 2022 | 有 | 有 |  | 已实现 | 通过 | 取值：`整数`<br>约束：自 sing-box 1.10.0 起<br>约束：默认使用 `2022`。 |
| `loopback-address` | 环回地址（文档未写） | 有 | 有 |  | 未实现 | 未测 | 取值：`地址列表`<br>约束：当启用 `auto_redirect` 时，可以作为网关为局域网设备（而不仅仅是本地）实现相同的行为。<br>约束：自 sing-box 1.12.0 起 |
| `mtu` | MTU | 有 | 有 | 有 | 已实现 | 通过 | 取值：`整数` |
| `multi-queue` | 启用基于 `IFF_MULTI_QUEUE` 的多队列支持，使吞吐量能够随 CPU 核心数量扩展。 |  | 有 |  | 未实现 | 未测 | 约束：仅在 Linux 下被支持，且需要使用 sing-tun 自有的 TCP/IP stack。 |
| `name` | 接口名，默认 utunN，N 为 10~1024 随机 |  |  | 有 | 已实现 | 通过 |  |
| `netns` | 在指定的网络命名空间中创建 tun 接口，可以是名称、路径，或网络命名空间的标签。 |  | 有 |  | 未实现 | 未测 | 约束：与 `platform` 冲突。<br>约束：仅支持 Linux。<br>约束：自 sing-box 1.14.0 起 |
| `platform` | 平台特定的设置，由客户端应用提供。 |  | 有 |  | 未实现 | 未测 |  |
| `platform-http-proxy` | 系统 HTTP 代理设置。 |  | 有 |  | 未实现 | 未测 |  |
| `platform-http-proxy-bypass-domain` | 绕过 HTTP 代理的主机名 |  | 有 |  | 未实现 | 未测 |  |
| `platform-http-proxy-enabled` | 启用系统 HTTP 代理 |  | 有 |  | 未实现 | 未测 |  |
| `platform-http-proxy-match-domain` | 使用 HTTP 代理的主机名 |  | 有 |  | 未实现 | 未测 | 约束：Only supported in graphical clients on Apple platforms. |
| `platform-http-proxy-server` | HTTP 代理服务器地址 |  | 有 |  | 未实现 | 未测 | 约束：必填 |
| `platform-http-proxy-server-port` | HTTP 代理服务器端口 |  | 有 |  | 未实现 | 未测 | 约束：必填 |
| `processors-per-channel` | 每通道处理器数（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `recvmsgx` | 启用 recvmsgx（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `route-address` | auto-route 自定义路由 | 有 | 有 |  | 已实现 | 通过 | 取值：`CIDR 列表`<br>约束：自 sing-box 1.10.0 起 |
| `route-address-set` | 规则集 CIDR 加入防火墙，不匹配绕过 | 有 | 有 |  | 未实现 | 未测 | 取值：`规则集名`<br>约束：与任意 routing-mark 冲突<br>约束：仅 Linux，需 nftables、auto-route、auto-redirect<br>约束：仅支持 Linux，且需要 `auto_route` 和 `auto_redirect` 已启用。<br>约束：自 sing-box 1.10.0 起 |
| `route-exclude-address` | auto-route 排除网段 | 有 | 有 |  | 已实现 | 通过 | 取值：`CIDR 列表`<br>约束：自 sing-box 1.10.0 起 |
| `route-exclude-address-set` | 规则集 CIDR 加入防火墙，匹配绕过 | 有 | 有 |  | 未实现 | 未测 | 取值：`规则集名`<br>约束：与任意 routing-mark 冲突<br>约束：仅 Linux，需 nftables、auto-route、auto-redirect<br>约束：与 `route.default_mark` 和 `[dialOptions].routing_mark` 冲突。<br>约束：仅支持 Linux，且需要 `auto_route` 和 `auto_redirect` 已启用。<br>约束：自 sing-box 1.10.0 起 |
| `sendmsgx` | 启用 sendmsgx（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `stack` | tun 协议栈，默认 mips | 有 | 废弃 | 有 | 已实现 | 通过 | 取值：`gvisor`、`mips`、`mixed`、`system`<br>约束：防火墙开启时 system、mixed 需放行内核<br>约束：`stack` 已废弃，并将在 sing-box 1.17.0 中被移除。<br>约束：gvisor、mixed 需 with_gvisor 构建标签<br>约束：旧的 LWIP 栈已被弃用并移除。<br>约束：移除 `stack` 参数以使用 sing-tun 自有的 TCP/IP stack。<br>约束：移除该选项后使用 sing-tun 自研栈（source:protocol/tun/inbound.go 内部名 go） |
| `strict-route` | 严格路由，防地址泄漏 | 有 | 有 |  | 已实现 | 通过 | 取值：`false`、`true`<br>约束：Windows 可能使 VirtualBox 等异常<br>约束：auto-route 启用时<br>约束：* 使不支持的网络不可达。 |
| `udp-timeout` | UDP NAT 过期秒，默认 300 | 有 |  |  | 部分 | 通过 | 取值：`整数` |
| `user-level` | 用户等级，默认 0 |  |  | 有 | 未实现 | 未测 |  |
| `xray-tun-fd` | XRAY_TUN_FD 传入 FD，Linux 可选用于轻量或非特权实现 |  |  | 有 | 未实现 | 未测 |  |
