# TUN 入站

`kerlico-tun` 注册节点类型 `tun`，只能放在 `local_inbounds` 或根配置 `tun` 段。它创建内核 TUN 接口并配置地址，把内核交来的 IP 包还原成 TCP 流和 UDP 数据报，经本地会话进入共享 `Dispatcher`。需要 `CAP_NET_ADMIN`。自动路由只支持 Linux（iproute2 与 nftables 命令行）。

```json
{
  "local_inbounds": [{
    "tag": "tun",
    "type": "tun",
    "listen": "127.0.0.1:0",
    "outbound": "proxy",
    "options": {
      "name": "kerlico0",
      "addresses": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
      "mtu": 1500,
      "stack": "mixed",
      "auto_route": true,
      "strict_route": true,
      "dns_hijack": ["any:53", "tcp://any:53"]
    }
  }]
}
```

Mihomo 顶层 `tun:` 段（`enable: true`）按同名键读取，编译期合入 `local_inbounds`。`listen` 是配置结构要求的字段，TUN 不监听它。键名接受下划线与连字符两种写法。

| 字段 | 约束说明 |
| --- | --- |
| `name` / `device` / `interface_name` | 接口名，默认 `kerlico0`，最长 15 字符 |
| `addresses` / `inet4_address` / `inet6_address` | 接口地址，1 至 2 个，每个地址族最多一个。IPv4 前缀不超过 `/30`，IPv6 不超过 `/126`。下一个地址留给用户态栈 |
| `mtu` | 1280 至 9000，默认 1500 |
| `max_flows` | 同时存在的 TCP 流和 UDP 来源数上限，1 至 4096，默认 1024 |
| `stack` | `system`、`gvisor`、`mixed`、`lwip` 都由 kerlico 的用户态 TCP/IP 栈承载；非 `gvisor` 时启动日志记一行。其他值报错 |
| `udp_timeout` | UDP 来源空闲超时，秒数或 `30s`、`5m`、`1h`，默认 60 秒，同时受 `limits.idle_timeout_ms` 约束 |
| `endpoint_independent_nat` | 接受。UDP 按来源端口建立多目标关联，映射本身与目标无关 |
| `gso` / `gso_max_size` | 接受，不生效 |
| `auto_route` | 安装专用路由表与策略规则，见下文 |
| `strict_route` | 去掉局域网直连优先规则；TUN 没有地址的地址族不可达 |
| `auto_redirect` | 需要 `auto_route`。nftables 把经 TUN 路由的 TCP 重定向到本节点的监听端口，由内核 TCP 栈承载 |
| `auto_redirect_input_mark` | 重定向连接的 conntrack 标记，默认 `0x2023` |
| `auto_redirect_output_mark` | 未配置 `routing-mark` 时 kerlico 出站套接字的默认标记，默认 `0x2024` |
| `auto_redirect_iproute2_fallback_rule_index` | `auto_redirect` 的兜底规则优先级，默认 32768 |
| `iproute2_table_index` / `iproute2_rule_index` | 路由表号，默认 2022；规则起始优先级，默认 9000 |
| `route_address` / `inet4_route_address` / `inet6_route_address` / `auto_system_routing_table` | 只把这些网段导入 TUN；某地址族没有条目且未配置包含规则集时导入全部 |
| `route_exclude_address` / `inet4_route_exclude_address` / `inet6_route_exclude_address` | 不进 TUN 的网段 |
| `route_address_set` / `route_exclude_address_set` | 规则集标签，取其中的 `ip_cidr`；规则集刷新后 5 秒内更新路由表 |
| `include_uid` / `include_uid_range` / `exclude_uid` / `exclude_uid_range` | 按本机进程 UID 选择流量，范围写 `1000-2000` 或 `1000:2000` |
| `include_interface` / `exclude_interface` | 按入接口选择被转发的流量 |
| `include_package` / `exclude_package` / `include_android_user` | Android 专用，记录日志后忽略 |
| `dns_hijack` | `any:53`、`tcp://any:53`、`udp://8.8.8.8:53`、`[2001:db8::1]:53`。编译为只匹配本节点来源的 `hijack-dns` 路由规则，排在全部规则之前 |
| `dns_mode` / `dns_address` | `dns_mode: hijack` 等价于对 `dns_address` 中每个地址（为空时任意地址）劫持 53 端口；`native`、`disabled` 不加规则 |
| `auto_detect_interface` | 开启 `auto_route` 时默认为真：全局出站套接字绑定默认路由所在网卡，跳过 TUN |
| `auto_outbounds_interface` | 出站固定绑定此网卡；`auto` 等同 `auto_detect_interface` |
| `auto_system_dns_to_gateway` / `dns` | 用 `resolvectl` 把接口 DNS 指向 `dns`（为空时用 TUN 网关）并设 `~.` 路由域，退出时恢复。失败只告警 |

## 并发上限

隧道本身常驻占用一个会话配额，每条 TCP 流和每个 UDP 来源再各占一个。实际并发是 `max_flows`、节点 `max_sessions` 减一、全局 `limits.max_sessions` 剩余配额三者的最小值。`limits.max_sessions` 默认 128，要用满默认的 `max_flows` 须调高它。节点会话上限为 1 时没有配额留给流，`kerlico check` 直接拒绝。

## 自动路由

布局沿用 sing-tun 的 Linux `auto_route`。P 为 `iproute2_rule_index`，T 为 `iproute2_table_index`，每个地址族各装一套：

| 优先级 | 规则 | 作用 |
| --- | --- | --- |
| P | `fwmark <出站标记> goto P+10` | kerlico 自身出站跳过 TUN |
| P | `uidrange …` / `iif …` `goto P+10` | `exclude_uid`、`exclude_interface` |
| P+1 | `lookup main suppress_prefixlength 0` | 仅非严格模式：主表里比默认路由更具体的路由（局域网）优先 |
| P+2 | `lookup T`，或逐条 `uidrange …` / `iif … lookup T` | 导入 TUN；配置 `include_uid`、`include_interface` 时只导入匹配的流量 |
| P+3 | `unreachable` | 仅严格模式且 TUN 没有该地址族地址时，阻止该地址族经主表泄漏 |
| P+10 | `nop` | 跳转终点，之后是系统的 `main` 与 `default` |
| fallback | `lookup T` | 仅 `auto_redirect` |

表 T 只放 TUN 网段：包含网段（默认 `0.0.0.0/0`、`::/0`）是 `dev <接口>` 路由，排除网段是 `throw` 路由，查表落空后经 `nop` 落到主表。网段数量不影响规则条数，规则集刷新只按差异增删路由。

`auto_redirect` 另建 nft 表 `inet kerlico_<接口名>`：`output` 链对出接口为 TUN 的 TCP 做 `redirect`，带出站标记的包直接放行；`prerouting` 链对转发来、经 `fib` 查到出接口为 TUN 的 TCP 做同样的重定向。重定向监听在本节点随机端口的 `0.0.0.0` 与 `[::]`，只接受带 NAT 原始目标的连接，监听套接字带出站标记，回包不会再进 TUN。UDP 与其他协议仍走表 T。

### 防回环

开启 `auto_route` 时，kerlico 自身的出站与 DNS 上游套接字不能再进 TUN。两层机制：

1. 未配置全局 `routing-mark`（`dialer.routing_mark`、`route.default_mark`）时，全局拨号选项取 `auto_redirect_output_mark`，默认 `0x2024`。全部出站经 `DialerOptions` 套接字工厂建立，都带这个标记，命中 P 处的 `fwmark` 规则。配置了 `routing-mark` 时规则用该值。单个出站自带不同的 `routing-mark` 时，P 处为每个不同的标记各装一条 `fwmark` 跳过规则，`auto_redirect` 的 nftables 输出链也逐个放行，这些出站同样不进 TUN。Mihomo 与 sing-tun 对出站自带标记不做处理，靠绑定物理网卡防回环；kerlico 两者都做。`auto_redirect_input_mark` 与任一标记相同时拒绝加载。规则按配置加载时的出站计算，订阅成员变化触发重载后随之更新。
2. `auto_detect_interface` 默认开启：出站套接字绑定默认路由所在网卡（跳过 TUN），表 T 的 `dev <TUN>` 路由与绑定网卡不符，查表落空。

### 清理

安装前先按所有权清理一次，退出时再清理一次：两个地址族中优先级在 `[P, P+10]` 内的规则、优先级为 fallback 且查表 T 的规则、表 T 的全部路由、nft 表 `inet kerlico_<接口名>`。清理后重新列出规则和路由核对，有残留就报错。`kill -9` 留下的规则在下次启动时被清掉，重复启动不会叠加规则。每条 `ip`、`nft` 命令都检查退出码，安装失败时节点报错退出。

同一台机器上同时运行 Mihomo、sing-box 时，各自默认也用 9000 与 2022，要改 `iproute2_rule_index` 与 `iproute2_table_index` 错开。

### 手动路由

不开 `auto_route` 时可手动把网段指向接口：

```sh
ip route add 203.0.113.0/24 dev kerlico0
```

此时出站要自行设置 `interface-name` 或 `routing-mark` 避免回环。严格反向路径过滤（`rp_filter=1`）下，回包可能被内核丢弃，把 TUN 接口设为 `0` 或 `2`。

可作网关：接受已配置地址族内任意来源的包，来源不限于接口地址。本机转发其他主机的流量时，自行开启 `ip_forward`。

## 接口故障

`ip link set <name> down` 期间写接口失败的包计入节点 `dropped`，节点继续运行，接口恢复后流量恢复。接口被删除时节点停止：kerlico 向标准错误打印诊断，`/v1/health` 转为 `degraded` 并列出该标签，其余入口继续运行，节点不会自行恢复。启动时创建接口失败（如缺少 `CAP_NET_ADMIN`）按同样方式报告。见[控制接口](control.md)。

## 限制

- TUN 看到的目标是 IP 时，可通过 Fake-IP 映射（`dns.fake_ip_range` / `fakedns`）、DNS 反向映射或首包嗅探还原目标域名并参与 `domain*`、`geosite`、`rule_set` 路由匹配。
- TUN 的 UDP 使用多目标关联，固定走节点绑定的 `outbound`，该出站须支持多目标 UDP 关联。TCP 按 `routes` / `route` 选择出站。
- `outbound` 为 `direct` 且目标是本机地址时，回包来源是本机地址，内核会丢弃。
- 只转发 TCP 和 UDP。发往用户态栈地址的 ICMP 回显由本地应答，发往其他地址的回显返回不可达，其他 ICMP 不处理。其他 IP 协议返回不可达。
- 没有鉴权。流量归属为 `Source::Local`，不计入 `users` 用量。
- 没有活动流时，关闭也要等 `limits.drain_timeout_ms` 的一半才退出：节点先等宽限期结束，再强制结束接口读写循环。

## 验证

- 单元测试：`crates/protocol-tun/src/automation.rs` 的 `strict_route_without_ipv6_address_makes_ipv6_unreachable`、`non_strict_route_prefers_main_table_specific_routes`、`address_sets_become_device_and_throw_routes`、`uid_and_interface_filters_scope_the_lookup_rule`、`auto_redirect_adds_fallback_rule_and_nft_redirect`；`lib.rs` 的 `accepts_mihomo_tun_section_keys`；`crates/config/src/tun.rs` 的 `dns_hijack_entries_become_node_scoped_rules`、`auto_route_defaults_mark_and_interface_detection`。
- `crates/protocol-tun/tests/netns.rs` 在独立网络命名空间内创建真实接口，验证内核 TCP 256 KiB 双向往返、UDP 往返、非接口地址来源、用量计量、接口 down 后恢复、接口删除后节点停止和 300 条并发流：

```sh
cargo test -p kerlico-tun --test netns --no-run
unshare -n cargo test -p kerlico-tun --test netns --offline -- --ignored
```

- `tools/tun_netns_e2e.py --kerlico <二进制> --mihomo <二进制>` 建三个命名空间（客户端、SOCKS5 代理、回显目标），把同一份 Mihomo YAML 交给两者，检查 auto-route + strict-route 下 IPv4/IPv6 TCP 经代理到达、UDP/TCP DNS 劫持返回 Fake-IP、`auto-redirect`、只有 IPv4 地址时严格模式下 IPv6 不可达、`kill -9` 后重启不叠加规则、正常退出后规则与路由表与 nft 恢复原状。2026-11-07 在 `perf-02` 对 Mihomo v1.19.33 运行，两者 16 项检查全部通过。Mihomo 用 `iif lo` 加来源地址规则区分自身流量，kerlico 用出站标记；两者 `kill -9` 后都留下规则，重启后都不叠加。
