# 路由

由 `tools/capability_matrix.py build` 生成，不要手改。

## action

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `bypass` | `bypass` 在预匹配中为 auto redirect 连接在内核层面绕过 sing-box。 |  | 有 |  | 未实现 | 未测 | 取值：`bypass`<br>约束：仅支持 Linux，且需要启用 `auto_redirect`。<br>约束：可带 route-options 全部字段<br>约束：终结动作<br>约束：自 sing-box 1.13.0 起 |
| `client-subnet` | 默认情况下，将带有指定 IP 前缀的 `edns0-subnet` OPT 附加记录附加到每个查询。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.12.0 起 |
| `compatible` | 策略组筛选不出节点时出现，等效 DIRECT | 有 |  |  | 未实现 | 未测 |  |
| `direct` | 直连出站 | 有 |  |  | 已实现 | 通过 |  |
| `disable-cache` | 在此查询中禁用缓存。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.12.0 起 |
| `disable-optimistic-cache` | 在此查询中禁用乐观 DNS 缓存。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `fallback-delay` | 详情参阅 拨号字段。 |  | 有 |  | 未实现 | 未测 |  |
| `fallback-network-type` | 详情参阅 拨号字段。 |  | 有 |  | 未实现 | 未测 |  |
| `hijack-dns` | dns 出站把请求劫持到内部 DNS 模块 | 有 | 有 |  | 已实现 | 通过 | 取值：`hijack-dns`<br>约束：终结动作 |
| `method` | 对于 TCP 和 UDP 连接： |  | 有 |  | 未实现 | 未测 | 取值：`default`、`drop`、`reply` |
| `network-strategy` | 详情参阅 拨号字段。 |  | 有 |  | 未实现 | 未测 | 取值：`default`、`fallback`、`hybrid`<br>约束：仅当出站为 `direct` 且 `outbound.bind_interface`, `outbound.inet4_bind_address`且 `outbound.inet6_bind_address` 未设置时生效。 |
| `network-type` | 详情参阅 拨号字段。 |  | 有 |  | 未实现 | 未测 | 取值：`cellular`、`ethernet`、`other`、`wifi` |
| `no-drop` | 如果未启用，则 30 秒内触发 50 次后，`method` 将被暂时覆盖为 `drop`。 |  | 有 |  | 未实现 | 未测 | 约束：当 `method` 设为 `drop` 时不可用。 |
| `outbound` | 目标出站的标签。 |  | 有 |  | 已实现 | 通过 | 约束：如果未指定，规则仅在来自 auto redirect 的预匹配中匹配，在其他场景中将被跳过。<br>约束：必填<br>约束：自 sing-box 1.13.0 起 |
| `override-address` | 覆盖目标地址。 |  | 有 |  | 已实现 | 通过 |  |
| `override-port` | 覆盖目标端口。 |  | 有 |  | 已实现 | 通过 |  |
| `pass` | 跳过当前命中分支继续匹配；在 SUB-RULE 中命中跳回主规则 | 有 |  |  | 未实现 | 未测 |  |
| `pass-rule` | 同 PASS，但在 SUB-RULE 中不跳出，继续匹配子规则 | 有 |  |  | 未实现 | 未测 |  |
| `proxy-or-group` | 规则目标为出站或策略组名 | 有 |  |  | 部分 | 通过 |  |
| `reject` | 拒绝 | 有 | 有 |  | 已实现 | 通过 | 取值：`reject`<br>约束：终结动作 |
| `reject-drop` | 拒绝并静默丢弃 | 有 |  |  | 未实现 | 未测 |  |
| `rematch` | rematch 出站写入名称或切子规则后重新匹配 | 有 |  |  | 未实现 | 未测 |  |
| `resolve` | `resolve` 将请求的目标从域名解析为 IP 地址。 |  | 有 |  | 已实现 | 通过 | 取值：`resolve`<br>约束：非终结动作 |
| `rewrite-ttl` | 重写 DNS 回应中的 TTL。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.12.0 起 |
| `route` | `route` 继承了将连接路由到指定出站的经典规则动作。 |  | 有 |  | 已实现 | 通过 | 取值：`route`<br>约束：可带 route-options 全部字段<br>约束：终结动作 |
| `route-options` | `route-options` 为路由设置选项。 |  | 有 |  | 已实现 | 通过 | 取值：`route-options`<br>约束：当内容只有一项时，可以忽略 JSON 数组 [] 标签<br>约束：非终结动作 |
| `server` | 指定要使用的 DNS 服务器的标签，而不是通过 DNS 路由进行选择。 |  | 有 |  | 未实现 | 未测 |  |
| `sniff` | `sniff` 对连接执行协议嗅探。 |  | 有 |  | 已实现 | 通过 | 取值：`sniff`<br>约束：非终结动作 |
| `sniffer` | 启用的探测器。 |  | 有 |  | 已实现 | 通过 | 取值：`bittorrent`、`dns`、`dtls`、`http`、`ntp`、`quic`、`rdp`、`ssh`、`stun`、`tls`<br>约束：默认启用所有探测器。 |
| `strategy` | DNS 解析策略，可用值有：`prefer_ipv4`、`prefer_ipv6`、`ipv4_only`、`ipv6_only`。 |  | 有 |  | 已实现 | 通过 | 取值：`ipv4_only`、`ipv6_only`、`prefer_ipv4`、`prefer_ipv6`<br>约束：默认使用 `dns.strategy`。 |
| `timeout` | 探测超时时间。 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.14.0 起<br>约束：默认使用 300ms。 |
| `tls-fragment` | 通过分段 TLS 握手数据包来绕过防火墙检测。 |  | 有 |  | 未实现 | 未测 | 约束：在 Linux、Apple 平台和需要管理员权限的 Windows 系统上，可自动检测等待时间。<br>约束：由于性能不佳，请首先尝试 `tls_record_fragment`，且仅应用于已知被阻止的服务器名称。<br>约束：自 sing-box 1.12.0 起 |
| `tls-fragment-fallback-delay` | 当 TLS 分片功能无法自动判定等待时间时使用的回退值。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.12.0 起<br>约束：默认使用 `500ms`。 |
| `tls-record-fragment` | 通过分段 TLS 握手数据包到多个 TLS 记录来绕过防火墙检测。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.12.0 起 |
| `tls-spoof` | 在真实 ClientHello 之前注入携带本字段所指定 SNI 的伪造 TLS ClientHello，用于欺骗仅放行特定主机名的 SNI 过滤中间盒。 |  | 有 |  | 未实现 | 未测 | 约束：仅支持 Linux、macOS 和 Windows，需要提升的权限。<br>约束：自 sing-box 1.14.0 起 |
| `tls-spoof-method` | 控制伪造报文被真实服务器拒绝的方式。 |  | 有 |  | 未实现 | 未测 | 取值：`wrong-ack`、`wrong-checksum`、`wrong-md5`、`wrong-sequence`、`wrong-timestamp`<br>约束：自 sing-box 1.14.0 起 |
| `udp-connect` | 如果启用，将尝试将 UDP 连接 connect 到目标而不是 listen。 |  | 有 |  | 未实现 | 未测 |  |
| `udp-disable-domain-unmapping` | 如果启用，对于地址为域的 UDP 代理请求，将在响应中发送原始包地址而不是映射的域。 |  | 有 |  | 未实现 | 未测 | 约束：此选项用于兼容不支持接收带有域地址的 UDP 包的客户端，如 Surge。 |
| `udp-timeout` | UDP 连接超时时间。 |  | 有 |  | 未实现 | 未测 | 约束：如果没有探测到协议，以下端口将默认识别为协议：<br>约束：已探测协议连接的默认值：<br>约束：设置比入站 UDP 超时更大的值将无效。 |

## config

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `auto-detect-interface` | 默认将出站连接绑定到默认网卡，以防止在 tun 下出现路由环路。 |  | 有 |  | 已实现 | 通过 | 约束：仅支持 Linux、Windows 和 macOS。 |
| `default-domain-resolver` | 详情参阅 拨号字段。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.12.0 起 |
| `default-fallback-delay` | 详情参阅 拨号字段。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.11.0 起 |
| `default-fallback-network-type` | 详情参阅 拨号字段。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.11.0 起 |
| `default-http-client` | 远程规则集使用的默认 HTTP 客户端 的标签。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `default-interface` | 默认将出站连接绑定到指定网卡，以防止在 tun 下出现路由环路。 |  | 有 |  | 部分 | 通过 | 约束：仅支持 Linux、Windows 和 macOS。 |
| `default-mark` | 默认为出站连接设置路由标记。 |  | 有 |  | 已实现 | 通过 | 约束：仅支持 Linux。 |
| `default-network-strategy` | 默认网络策略，语义同拨号字段 network_strategy |  | 有 |  | 未实现 | 未测 | 约束：Conflicts with `default_interface`.<br>约束：Takes no effect if `outbound.bind_interface`, `outbound.inet4_bind_address` or `outbound.inet6_bind_address` is set.<br>约束：自 sing-box 1.11.0 起 |
| `default-network-type` | 详情参阅 拨号字段。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.11.0 起 |
| `dhcp-lease-files` | 用于主机名和 MAC 地址解析的自定义 DHCP 租约文件路径。 |  | 有 |  | 未实现 | 未测 | 约束：仅支持 Linux 和 macOS。<br>约束：自 sing-box 1.14.0 起 |
| `final` | 默认出站标签。 |  | 有 |  | 部分 | 通过 |  |
| `find-neighbor` | 在没有 `source_mac_address` 或 `source_hostname` 规则时启用邻居解析以输出日志。 |  | 有 |  | 未实现 | 未测 | 约束：仅支持 Linux 和 macOS。<br>约束：自 sing-box 1.14.0 起 |
| `find-process` | 在没有 `process_name`、`process_path`、`package_name`、`user` 或 `user_id` 规则时启用进程搜索以输出日志。 |  | 有 |  | 未实现 | 未测 | 约束：仅支持 Linux、Windows 和 macOS。 |
| `geoip` | 旧版 GeoIP 配置对象 |  | 已移除 |  | 不适用 | 未测 |  |
| `geosite` | 旧版 Geosite 配置对象 |  | 已移除 |  | 不适用 | 未测 |  |
| `override-android-vpn` | 启用 `auto_detect_interface` 时接受 Android VPN 作为上游网卡。 |  | 有 |  | 未实现 | 未测 | 约束：仅支持 Android。 |
| `rule-set` | 一组 规则集。 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.8.0 起 |
| `rules` | 路由规则列表 |  | 有 |  | 已实现 | 通过 |  |

## geoip

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `download-detour` | 用于下载 GeoIP 资源的出站的标签。 |  | 已移除 |  | 不适用 | 未测 | 约束：如果为空，将使用默认出站。 |
| `download-url` | 指定 GeoIP 资源的下载链接。 |  | 已移除 |  | 不适用 | 未测 | 约束：默认为 `https://github.com/SagerNet/sing-geoip/releases/latest/download/geoip.db`。 |
| `path` | 指定 GeoIP 资源的路径。 |  | 已移除 |  | 不适用 | 未测 | 约束：默认 `geoip.db`。 |

## geosite

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `download-detour` | 用于下载 GeoSite 资源的出站的标签。 |  | 已移除 |  | 不适用 | 未测 | 约束：如果为空，将使用默认出站。 |
| `download-url` | 指定 GeoSite 资源的下载链接。 |  | 已移除 |  | 不适用 | 未测 | 约束：默认为 `https://github.com/SagerNet/sing-geosite/releases/latest/download/geosite.db`。 |
| `path` | 指定 GeoSite 资源的路径。 |  | 已移除 |  | 不适用 | 未测 | 约束：默认 `geosite.db`。 |

## global

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `find-process-mode` | 进程匹配模式，默认 strict | 有 |  |  | 未实现 | 未测 | 取值：`always`、`off`、`strict` |
| `mode` | 运行模式，默认 rule | 有 |  |  | 未实现 | 未测 | 取值：`direct`、`global`、`rule`<br>约束：global 需在 GLOBAL 策略组选择代理 |

## neighbor

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `resolution` | 按 MAC 和主机名匹配局域网设备的邻居解析 |  | 有 |  | 未实现 | 未测 | 取值：`android`、`linux`、`macos`<br>约束：Android 需 Android 11 以上、ROOT、VPNHotspot<br>约束：Linux 主机名依赖 DHCP 租约文件<br>约束：macOS 需要独立版<br>约束：route.find_neighbor 可强制启用<br>约束：存在 source_mac_address、source_hostname 或 local DNS 的 neighbor_domain 时自动启用 |

## network-icmp

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | 路由规则对 ICMP 回显请求的处理组合 |  | 有 |  | 未实现 | 未测 | network：`icmp`、`tcp`、`udp`<br>icmp_source：`tailscale`、`tun`、`wireguard`<br>icmp_target：`direct`、`tailscale`、`wireguard`<br>reject_icmp：`default`、`drop`、`reply`<br>约束：ICMP 匹配自 1.13.0 起 |

## pre-match

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | 预匹配的入站、动作和目标组合 |  | 有 |  | 未实现 | 未测 | l3_inbound：`tailscale`、`tun`、`wireguard`<br>action：`bypass`、`reject`、`route`、`sniff`<br>route_target_icmp：`bridge`、`direct`、`tailscale`、`wireguard`<br>route_target_tcp_udp：`bridge`、`tailscale`、`wireguard`<br>约束：FakeIP 目标需要在预匹配里先 resolve，否则连接被拒绝<br>约束：TCP 的 sniff 总是停止预匹配<br>约束：TCP、UDP 走 L3 转发自 1.14.0 起<br>约束：bypass 无 outbound 时只在 auto_redirect 预匹配中匹配，其他场景跳过<br>约束：动作需要的连接数据超出已有范围时，预匹配在该规则停止 |
| `bypass` | 在内核层面绕过 sing-box 直接连接。 |  | 有 |  | 未实现 | 未测 | 约束：仅支持 Linux，且需要启用 `auto_redirect`。<br>约束：如果未指定 `outbound`，规则仅在来自 auto redirect 的预匹配中匹配，在其他场景中将被跳过。<br>约束：自 sing-box 1.13.0 起 |
| `reject` | 以 TCP RST / ICMP 不可达拒绝。 |  | 有 |  | 未实现 | 未测 |  |
| `route` | 将连接直接在 L3 转发到指定出站，不经过 L3 到 L4 转换。 |  | 有 |  | 未实现 | 未测 | 约束：FakeIP 目标需要在预匹配中先执行 `resolve` 动作，否则连接将被拒绝。<br>约束：当没有规则匹配且默认出站为受支持的目标时，L3 转发同样生效；对于出站组，使用当前选中的出站。<br>约束：自 sing-box 1.14.0 起，TCP 和 UDP 连接也可以在 L3 转发；此前仅支持 ICMP 连接。 |
| `sniff` | 对于 UDP 连接，协议探测在首个数据包上运行，随后规则匹配将携带探测结果继续。 |  | 有 |  | 未实现 | 未测 | 约束：当探测器需要更多数据时（如分片的 QUIC Client Hello），预匹配将在该规则处停止。<br>约束：自 sing-box 1.14.0 起 |

## routing

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `balancers` | 负载均衡器数组 |  |  | 有 | 未实现 | 未测 |  |
| `domain-strategy` | 路由域名解析策略，默认 AsIs |  |  | 有 | 部分 | 通过 | 取值：`AsIs`、`IPIfNonMatch`、`IPOnDemand`<br>约束：IPIfNonMatch：一轮未命中且含域名时第二轮解析<br>约束：IPOnDemand：遇 ip 规则即解析，失败用原始 IP<br>约束：不能与 script 同用（source:infra/conf/router.go）<br>约束：解析结果受 dns.queryStrategy 限制<br>约束：路由不改变真实目标 |
| `rules` | 规则数组，从上到下第一条生效 |  |  | 有 | 已实现 | 通过 | 约束：未命中由第一个 outbound 发出 |
| `script` | Lua 路由脚本路径，设置后接管路由选择 |  |  | 有 | 未实现 | 未测 | 约束：balancers 仍可用<br>约束：rules、domainStrategy 不生效，同配报错 |

## rule

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | 路由规则维度 | 有 | 有 | 有 | 部分 | 通过 | match：`AND`、`DOMAIN`、`DOMAIN-KEYWORD`、`DOMAIN-REGEX`、`DOMAIN-SUFFIX`、`DOMAIN-WILDCARD`、`DSCP`、`DST-PORT`、`GEOIP`、`GEOSITE`、`IN-NAME`、`IN-PORT`、`IN-TYPE`、`IN-USER`、`IP-ASN`、`IP-CIDR`、`IP-CIDR6`、`IP-SUFFIX`、`MATCH`、`NETWORK`、`NOT`、`OR`、`PROCESS-NAME`、`PROCESS-NAME-REGEX`、`PROCESS-NAME-WILDCARD`、`PROCESS-PATH`、`PROCESS-PATH-REGEX`、`PROCESS-PATH-WILDCARD`、`REMATCH-NAME`、`RULE-SET`、`SRC-GEOIP`、`SRC-IP-ASN`、`SRC-IP-CIDR`、`SRC-IP-SUFFIX`、`SRC-PORT`、`SUB-RULE`、`UID`<br>target：`DIRECT`、`PASS`、`PASS-RULE`、`REJECT`、`REJECT-DROP`、`dns 出站`、`rematch 出站`、`出站名`、`策略组名`<br>param：``、`no-resolve`、`src`<br>scope：`listener.rule`、`rematch.target-sub-rule`、`rules`、`sub-rules`<br>mode：`direct`、`global`、`rule`<br>约束：classical 规则集不支持 RULE-SET、SUB-RULE<br>约束：no-resolve、src 仅目标 IP 规则<br>rule_type：`default`、`logical`<br>logical_mode：`and`、`or`<br>invert：`off`、`on`<br>action：`bypass`、`hijack-dns`、`reject`、`resolve`、`route`、`route-options`、`sniff`<br>match_group_or：`domain`、`domain_keyword`、`domain_regex`、`domain_suffix`、`geoip`、`geosite`、`ip_cidr`、`ip_is_private`<br>port_group_or：`port`、`port_range`<br>source_group_or：`source_geoip`、`source_ip_cidr`、`source_ip_is_private`<br>source_port_group_or：`source_port`、`source_port_range`<br>约束：network_type、network_is_expensive、network_is_constrained 仅图形客户端<br>约束：process_*、user、user_id 等有平台限制，见各字段<br>约束：匹配逻辑：各 OR 组内为或，组与组及其他字段之间为与<br>约束：规则集只含一条无 invert 的默认规则时，其字段并入外层规则按上述逻辑；否则作为其他字段匹配；不同规则集之间保持或<br>match：`attrs`、`domain`、`inboundTag`、`ip`、`localIP`、`localPort`、`network`、`port`、`process`、`protocol`、`sourceIP`、`sourcePort`、`user`、`vlessRoute`<br>target：`balancerTag`、`outboundTag`<br>domain_strategy：`AsIs`、`IPIfNonMatch`、`IPOnDemand`<br>sniff：`destOverride`、`off`、`routeOnly`<br>约束：DNS 非 local 请求跳过 IPIfNonMatch、IPOnDemand 解析<br>约束：outboundTag 和 balancerTag 须二选一<br>约束：routeOnly 时路由同时看到原始目标和嗅探域名，嗅探优先<br>约束：同一规则多条件须同时满足 |
| `action` | 参阅 规则动作。 |  | 有 |  | 部分 | 通过 | 取值：`bypass`、`hijack-dns`、`reject`、`resolve`、`route`、`route-options`、`sniff`<br>约束：必填 |
| `and` | 逻辑与 | 有 |  |  | 部分 | 通过 | 取值：`AND,((DOMAIN,baidu.com),(NETWORK,UDP)),DIRECT`<br>约束：注意括号 |
| `attrs` | HTTP 属性 |  |  | 有 | 未实现 | 未测 | 取值：`{":method":"GET"}`、`{":path":"/test"}`、`{"accept":"text/html"}`<br>约束：HTTP 入站非 CONNECT 直接可得，其他需 sniffing<br>约束：仅 HTTP 1.0、1.1<br>约束：键大小写不敏感，值子串或正则 |
| `auth-user` | 认证用户名，参阅入站设置。 |  | 有 |  | 部分 | 通过 |  |
| `balancer-tag` | 命中后由负载均衡器选出站 |  |  | 有 | 已实现 | 通过 | 约束：与 outboundTag 二选一，缺失时报错 |
| `clash-mode` | 匹配 Clash 模式。 |  | 有 |  | 未实现 | 未测 |  |
| `client` | 探测到的客户端类型, 参阅 协议探测。 |  | 有 |  | 未实现 | 未测 | 取值：`chromium`、`firefox`、`quic-go`、`safari`<br>约束：自 sing-box 1.10.0 起 |
| `default-interface-address` | 匹配默认接口地址。 |  | 有 |  | 未实现 | 未测 | 约束：仅支持 Linux、Windows 和 macOS.<br>约束：自 sing-box 1.13.0 起 |
| `dns-search-domain` | 匹配指定 DNS 服务器的搜索域。 |  | 有 |  | 未实现 | 未测 | 取值：`dhcp`、`local`、`openconnect`、`openvpn`、`resolved`、`tailscale`<br>约束：自 sing-box 1.15.0 起 |
| `dns-server-address` | 匹配指定 DNS 服务器的服务器地址。 |  | 有 |  | 未实现 | 未测 | 取值：`dhcp`、`local`、`openconnect`、`openvpn`、`resolved`、`tailscale`<br>约束：自 sing-box 1.15.0 起 |
| `domain` | 匹配完整域名 | 有 | 有 | 有 | 已实现 | 通过 | 取值：`DOMAIN,ad.com,REJECT`、`sina.com`<br>约束：规则内多条件为与关系 |
| `domain-dotless` | 无点域名子串匹配 |  |  | 有 | 未实现 | 未测 | 取值：`dotless:pc-`<br>约束：余下字符串不能含点<br>约束：大小写敏感 |
| `domain-ext` | 从资源目录文件加载 |  |  | 有 | 未实现 | 未测 | 取值：`ext:file:tag`<br>约束：tag 必须存在<br>约束：文件格式同 geosite.dat |
| `domain-full` | 完整匹配 |  |  | 有 | 已实现 | 通过 | 取值：`full:xray.com` |
| `domain-keyword` | 域名关键字 | 有 | 有 | 有 | 已实现 | 通过 | 取值：`DOMAIN-KEYWORD,google,auto`、`keyword:sina.com` |
| `domain-regex` | 域名正则 | 有 | 有 |  | 已实现 | 通过 | 取值：`DOMAIN-REGEX,^abc.*com,PROXY` |
| `domain-regexp` | 正则匹配 |  |  | 有 | 已实现 | 通过 | 取值：`regexp:\.goo.*\.com$`<br>约束：大小写敏感 |
| `domain-suffix` | 匹配域名后缀 | 有 | 有 | 有 | 已实现 | 通过 | 取值：`DOMAIN-SUFFIX,google.com,auto`、`domain:xray.com` |
| `domain-wildcard` | 通配符匹配，仅 * 和 ? | 有 |  |  | 已实现 | 通过 | 取值：`DOMAIN-WILDCARD,*.google.com,auto`<br>约束：与 Clash 通配符不同 |
| `domains` | domain 的别名 |  |  | 有 | 不适用 | 未测 |  |
| `dscp` | DSCP 标记 | 有 |  |  | 未实现 | 未测 | 取值：`DSCP,4,DIRECT`<br>约束：仅限 tproxy udp 入站 |
| `dst-port` | 目标端口范围 | 有 |  |  | 部分 | 通过 | 取值：`DST-PORT,80,DIRECT` |
| `geoip` | 匹配 IP 所属国家代码 | 有 | 已移除 | 有 | 已实现 | 通过 | 取值：`GEOIP,CN,DIRECT`、`geoip:cn`<br>约束：GeoIP 已废弃且可能在不久的将来移除，参阅 迁移指南。<br>约束：必须小写 geoip:<br>约束：默认精简版只含 cn、ir、ru |
| `geoip-private` | 私有地址 |  |  | 有 | 已实现 | 通过 | 取值：`geoip:private` |
| `geosite` | 匹配 Geosite 内域名 | 有 | 已移除 | 有 | 已实现 | 通过 | 取值：`GEOSITE,youtube,PROXY`、`geosite:cn`、`geosite:google`<br>约束：Geosite 已废弃且可能在不久的将来移除，参阅 迁移指南。<br>约束：必须小写 geosite: |
| `geosite-attr` | 按属性筛选 geosite |  |  | 有 | 未实现 | 未测 | 取值：`geosite:google@cn` |
| `in-name` | 入站名称 | 有 |  |  | 已实现 | 通过 | 取值：`IN-NAME,ss,PROXY` |
| `in-port` | 入站端口，可用范围 | 有 |  |  | 部分 | 通过 | 取值：`IN-PORT,7890,PROXY` |
| `in-type` | 入站类型 | 有 |  |  | 未实现 | 未测 | 取值：`IN-TYPE,SOCKS/HTTP,PROXY` |
| `in-user` | 入站用户名，/ 分隔多个 | 有 |  |  | 部分 | 通过 | 取值：`IN-USER,mihomo,PROXY` |
| `inbound` | 入站 标签。 |  | 有 |  | 已实现 | 通过 |  |
| `inbound-tag` | 入站标识 |  |  | 有 | 已实现 | 通过 |  |
| `interface-address` | 匹配接口地址。 |  | 有 |  | 未实现 | 未测 | 约束：仅支持 Linux、Windows 和 macOS.<br>约束：自 sing-box 1.13.0 起 |
| `invert` | 反选匹配结果。 |  | 有 |  | 已实现 | 通过 |  |
| `ip` | 单个 IP |  |  | 有 | 已实现 | 通过 | 取值：`127.0.0.1` |
| `ip-asn` | 匹配 IP 所属 ASN | 有 |  |  | 未实现 | 未测 | 取值：`IP-ASN,13335,DIRECT` |
| `ip-cidr` | 匹配 IP 范围 | 有 | 有 | 有 | 部分 | 通过 | 取值：`0.0.0.0/0`、`10.0.0.0/8`、`::/0`、`IP-CIDR,127.0.0.0/8,DIRECT,no-resolve`<br>约束：支持 no-resolve、src |
| `ip-cidr6` | IP-CIDR 的别名 | 有 |  |  | 部分 | 通过 | 取值：`IP-CIDR6,2620:0:2d0:200::7/32,auto`<br>约束：效果同 IP-CIDR |
| `ip-ext` | 从资源目录文件加载 |  |  | 有 | 未实现 | 未测 | 取值：`ext:file:tag`<br>约束：tag 必须存在<br>约束：文件格式同 geoip.dat |
| `ip-invert` | 反选 |  |  | 有 | 未实现 | 未测 | 取值：`!10.0.0.0/8`、`!geoip:cn`<br>约束：反选项之间 AND；正选项之间及正选项与反选项之间 OR |
| `ip-is-private` | 匹配非公开 IP。 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.8.0 起 |
| `ip-suffix` | 匹配 IP 后缀范围 | 有 |  |  | 未实现 | 未测 | 取值：`IP-SUFFIX,8.8.8.8/24,PROXY` |
| `ip-version` | 4 或 6。 |  | 有 |  | 已实现 | 通过 | 取值：`4`、`6`<br>约束：默认不限制。 |
| `local-ip` | 入站本地 IP |  |  | 有 | 部分 | 通过 | 取值：`CIDR`、`GeoIP`、`IP`、`ext`<br>约束：对 UDP 无效，总是 listen IP |
| `local-os` | 运行系统，文档未写 |  |  | 有 | 未实现 | 未测 |  |
| `local-port` | 入站本地端口 |  |  | 有 | 部分 | 通过 | 取值：`1000-2000`、`53`、`53,443,1000-2000` |
| `logical-mode` | `and` 或 `or` |  | 有 |  | 已实现 | 通过 | 取值：`and`、`or`<br>约束：必填 |
| `logical-rules` | 包括的规则。 |  | 有 |  | 已实现 | 通过 | 约束：必填 |
| `logical-type` | 逻辑规则类型，固定为 logical |  | 有 |  | 已实现 | 通过 | 取值：`logical` |
| `match` | 匹配所有请求 | 有 |  |  | 部分 | 通过 | 取值：`MATCH,auto` |
| `network` | tcp 或 udp | 有 | 有 | 有 | 部分 | 通过 | 取值：`NETWORK,udp,DIRECT`、`icmp`、`tcp`、`tcp,udp`、`udp`<br>约束：仅含 tcp,udp 的规则可 catch all |
| `network-interface-address` | 匹配网络接口（可用值同 `network_type`）地址。 |  | 有 |  | 未实现 | 未测 | 约束：仅在 Android 与 Apple 平台图形客户端中支持。<br>约束：自 sing-box 1.13.0 起 |
| `network-is-constrained` | 匹配如果网络在低数据模式下。 |  | 有 |  | 未实现 | 未测 | 约束：仅在 Apple 平台图形客户端中支持。<br>约束：自 sing-box 1.11.0 起 |
| `network-is-expensive` | 匹配如果网络被视为计费 (在 Android) 或被视为昂贵，像蜂窝网络或个人热点 (在 Apple 平台)。 |  | 有 |  | 未实现 | 未测 | 约束：仅在 Android 与 Apple 平台图形客户端中支持。<br>约束：自 sing-box 1.11.0 起 |
| `network-type` | 匹配网络类型。 |  | 有 |  | 未实现 | 未测 | 取值：`cellular`、`ethernet`、`other`、`wifi`<br>约束：仅在 Android 与 Apple 平台图形客户端中支持。<br>约束：自 sing-box 1.11.0 起 |
| `no-resolve` | 目标 IP 规则跳过 DNS 解析 | 有 |  |  | 部分 | 通过 | 取值：`no-resolve`<br>约束：仅目标 IP 规则<br>约束：更早规则已触发解析时仍会匹配 |
| `not` | 逻辑非 | 有 |  |  | 已实现 | 通过 | 取值：`NOT,((DOMAIN,baidu.com)),PROXY`<br>约束：注意括号 |
| `or` | 逻辑或 | 有 |  |  | 部分 | 通过 | 取值：`OR,((NETWORK,UDP),(DOMAIN,baidu.com)),REJECT`<br>约束：注意括号 |
| `order` | 规则自上而下匹配，顶部优先 | 有 |  |  | 已实现 | 通过 | 约束：请求为 udp 而节点无 udp 支持时继续向下匹配 |
| `outbound` | 已移动到 规则动作. |  | 废弃 |  | 不适用 | 未测 |  |
| `outbound-tag` | 命中后发往指定出站 |  |  | 有 | 已实现 | 通过 | 约束：同时指定时 outboundTag 优先 |
| `package-name` | 匹配 Android 应用包名。 |  | 有 |  | 未实现 | 未测 |  |
| `package-name-regex` | 使用正则表达式匹配 Android 应用包名。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `port` | 匹配端口。 |  | 有 | 有 | 部分 | 通过 | 取值：`1000-2000`、`53`、`53,443,1000-2000` |
| `port-range` | 匹配端口范围。 |  | 有 |  | 已实现 | 通过 |  |
| `preferred-by` | 匹配制定出站的首选路由。 |  | 有 |  | 未实现 | 未测 | 取值：`bridge`、`tailscale`、`wireguard`<br>约束：自 sing-box 1.13.0 起 |
| `process` | 本机进程 |  |  | 有 | 未实现 | 未测 | 取值：`/usr/bin/`、`C:/Windows/System32/curl.exe`、`curl`、`self/`、`xray/`<br>约束：Android 需注册查找器<br>约束：仅 Windows、Linux<br>约束：大小写敏感<br>约束：进程名自动去 .exe；绝对路径不去 |
| `process-name` | 进程名；Android 可匹配包名 | 有 | 有 |  | 未实现 | 未测 | 取值：`PROCESS-NAME,curl,PROXY`<br>约束：仅支持 Linux、Windows 和 macOS。 |
| `process-name-regex` | 进程名正则；Android 可匹配包名 | 有 |  |  | 未实现 | 未测 | 取值：`PROCESS-NAME-REGEX,curl$,PROXY` |
| `process-name-wildcard` | 进程名通配；Android 可匹配包名 | 有 |  |  | 未实现 | 未测 | 取值：`PROCESS-NAME-WILDCARD,*telegram*,PROXY` |
| `process-path` | 完整进程路径 | 有 | 有 |  | 未实现 | 未测 | 取值：`PROCESS-PATH,/usr/bin/wget,PROXY`<br>约束：仅支持 Linux、Windows 和 macOS. |
| `process-path-regex` | 进程路径正则 | 有 | 有 |  | 未实现 | 未测 | 取值：`PROCESS-PATH-REGEX,.*bin/wget,PROXY`<br>约束：仅支持 Linux、Windows 和 macOS.<br>约束：自 sing-box 1.10.0 起 |
| `process-path-wildcard` | 进程路径通配，仅 * 和 ? | 有 |  |  | 未实现 | 未测 | 取值：`PROCESS-PATH-WILDCARD,/usr/*/wget,PROXY` |
| `protocol` | 探测到的协议, 参阅 协议探测。 |  | 有 | 有 | 已实现 | 通过 | 取值：`bittorrent`、`dns`、`dtls`、`http`、`ntp`、`quic`、`rdp`、`ssh`、`stun`、`tls`<br>约束：bittorrent 只有基础嗅探<br>约束：http 仅 1.0 和 1.1<br>约束：tls 1.0~1.3<br>约束：必须开启入站 sniffing |
| `rematch-name` | 匹配 rematch 出站写入的名称 | 有 |  |  | 未实现 | 未测 | 取值：`REMATCH-NAME,rematch1,PROXY` |
| `rule-set` | 引用规则集合 | 有 | 有 |  | 已实现 | 通过 | 取值：`RULE-SET,providername,proxy`<br>约束：需配置 rule-providers<br>约束：自 sing-box 1.8.0 起 |
| `rule-set-ip-cidr-match-source` | 使规则集中的 `ip_cidr` 规则匹配源 IP。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.10.0 起 |
| `rule-set-ipcidr-match-source` | 使规则集中的 `ip_cidr` 规则匹配源 IP。 |  | 已移除 |  | 不适用 | 未测 | 约束：`rule_set_ipcidr_match_source` 已重命名为 `rule_set_ip_cidr_match_source` 且将在 sing-box 1.11.0 中被移除。<br>约束：自 sing-box 1.8.0 起 |
| `rule-tag` | 规则名，命中时 Info 日志输出 |  |  | 有 | 未实现 | 未测 |  |
| `source-geoip` | 匹配源 GeoIP。 |  | 已移除 |  | 不适用 | 未测 | 约束：GeoIP 已废弃且可能在不久的将来移除，参阅 迁移指南。 |
| `source-hostname` | 匹配源设备从 DHCP 租约获取的主机名。 |  | 有 |  | 未实现 | 未测 | 约束：仅支持 Linux、macOS，或在 Android 和 macOS 图形客户端中支持。<br>约束：自 sing-box 1.14.0 起 |
| `source-ip` | 来源 IP；别名 source |  |  | 有 | 已实现 | 通过 | 取值：`CIDR`、`GeoIP`、`IP`、`ext` |
| `source-ip-cidr` | 匹配源 IP CIDR。 |  | 有 |  | 已实现 | 通过 |  |
| `source-ip-is-private` | 匹配非公开源 IP。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.8.0 起 |
| `source-mac-address` | 匹配源设备 MAC 地址。 |  | 有 |  | 未实现 | 未测 | 约束：仅支持 Linux、macOS，或在 Android 和 macOS 图形客户端中支持。<br>约束：自 sing-box 1.14.0 起 |
| `source-port` | 匹配源端口。 |  | 有 | 有 | 未实现 | 未测 | 取值：`1000-2000`、`53`、`53,443,1000-2000` |
| `source-port-range` | 匹配源端口范围。 |  | 有 |  | 未实现 | 未测 |  |
| `src` | 把目标 IP 匹配转为来源 IP 匹配 | 有 |  |  | 未实现 | 未测 | 取值：`src`<br>约束：仅目标 IP 规则 |
| `src-geoip` | 来源 IP 国家代码 | 有 |  |  | 未实现 | 未测 | 取值：`SRC-GEOIP,cn,DIRECT` |
| `src-ip-asn` | 来源 IP ASN | 有 |  |  | 未实现 | 未测 | 取值：`SRC-IP-ASN,9808,DIRECT` |
| `src-ip-cidr` | 来源 IP 范围 | 有 |  |  | 已实现 | 通过 | 取值：`SRC-IP-CIDR,192.168.1.201/32,DIRECT` |
| `src-ip-suffix` | 来源 IP 后缀 | 有 |  |  | 未实现 | 未测 | 取值：`SRC-IP-SUFFIX,192.168.1.201/8,DIRECT` |
| `src-port` | 来源端口范围 | 有 |  |  | 未实现 | 未测 | 取值：`SRC-PORT,7777,DIRECT` |
| `sub-rule` | 匹配至子规则 | 有 |  |  | 未实现 | 未测 | 取值：`SUB-RULE,(NETWORK,tcp),sub-rule`<br>约束：注意括号 |
| `uid` | Linux USER ID | 有 |  |  | 未实现 | 未测 | 取值：`UID,1001,DIRECT` |
| `user` | 匹配用户名。 |  | 有 | 有 | 部分 | 通过 | 取值：`regexp:...`、`邮箱样例`<br>约束：仅支持 Linux. |
| `user-id` | 匹配用户 ID。 |  | 有 |  | 未实现 | 未测 | 约束：仅支持 Linux. |
| `vless-route` | VLESS UUID 第 7、8 字节路由值 |  |  | 有 | 未实现 | 未测 | 取值：`1000-2000`、`53`、`53,443,1000-2000`<br>约束：非 VLESS 视为 0 |
| `webhook` | 命中时 POST 通知，内容含 email、level、protocol、network、source、destination、routeTarget、originalTarget、inboundTag、inboundName、inboundLocal、outboundTag、ts |  |  | 有 | 未实现 | 未测 |  |
| `wifi-bssid` | 匹配 WiFi BSSID。 |  | 有 |  | 未实现 | 未测 |  |
| `wifi-ssid` | 匹配 WiFi SSID。 |  | 有 |  | 未实现 | 未测 |  |

## sub-rules

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `definition` | 命名子规则集合 | 有 |  |  | 未实现 | 未测 | 取值：`名称: 规则列表` |

## webhook

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `deduplication` | 相同事件去重秒数 |  |  | 有 | 未实现 | 未测 |  |
| `headers` | HTTP 请求头 |  |  | 有 | 未实现 | 未测 |  |
| `url` | 通知目标 |  |  | 有 | 未实现 | 未测 | 取值：`/var/run/webhook.sock`、`/var/run/webhook.sock:/alert`、`@@padded:/webhook`、`@abstract:/webhook`、`https://api.example.com/alert`<br>约束：abstract 仅 Linux/Android |

## wifi-state

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `monitor` | 监控 Wi-Fi 状态以支持 wifi_ssid、wifi_bssid 规则 |  | 有 |  | 未实现 | 未测 | 取值：`android`、`apple`、`linux`、`windows`<br>约束：Linux 后端按序探测：NetworkManager、IWD、wpa_supplicant、ConnMan<br>约束：Linux、Windows 支持自 1.13.0 起<br>约束：Windows 用 WLAN API |
