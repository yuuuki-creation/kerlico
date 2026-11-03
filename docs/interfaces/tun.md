# TUN 入站

`kerlico-tun` 注册节点类型 `tun`，只能放在 `local_inbounds` 或根配置 `tun` 段。它创建内核 TUN 接口并配置地址，把内核交来的 IP 包还原成 TCP 流和 UDP 数据报，经本地会话进入共享 `Dispatcher`。需要 `CAP_NET_ADMIN`，仅 Linux 经过验证。

```json
{
  "local_inbounds": [{
    "tag": "tun",
    "type": "tun",
    "listen": "127.0.0.1:0",
    "outbound": "proxy",
    "options": {
      "name": "kerlico0",
      "addresses": ["198.18.0.1/16"],
      "mtu": 1500,
      "stack": "mixed",
      "auto_route": true,
      "auto_redirect": true,
      "strict_route": true,
      "dns_hijack": ["any:53"]
    }
  }]
}
```

| 字段 | 约束说明 |
| --- | --- |
| `name` / `device` / `interface_name` | 接口名，默认 `kerlico0`，最长 15 字符 |
| `addresses` / `address` / `inet4_address` / `inet6_address` | 接口地址，1 至 2 个，每个地址族最多一个。IPv4 前缀不超过 `/30`，IPv6 不超过 `/126`。下一个地址留给用户态栈 |
| `mtu` | 1280 至 9000，默认 1500 |
| `max_flows` | 同时存在的 TCP 流和 UDP 来源数上限，1 至 4096，默认 1024 |
| `stack` | 协议栈模式：`system`、`gvisor`、`mixed`（默认 `system`） |
| `auto_route` / `strict_route` | 自动规划路由表、策略路由与严格路由防泄漏规则 |
| `auto_redirect` | 自动规划 nftables/iptables 重定向规则及输入输出标记（`auto_redirect_input_mark`、`auto_redirect_output_mark`、`auto_redirect_reset_mark`、`auto_redirect_nfqueue`） |
| `auto_detect_interface` | 自动探测默认物理出口网卡 |
| `route_address` / `route_exclude_address` / `route_address_set` / `route_exclude_address_set` | 包含或排除的 IPv4/IPv6 路由网段与规则集标签 |
| `include_interface` / `exclude_interface` / `include_uid` / `exclude_uid` | 按网卡或 UID 包含/排除流量 |
| `dns_hijack` | DNS 劫持匹配规则列表（如 `any:53`、`tcp://any:53`） |
| `endpoint_independent_nat` / `udp_timeout` | 端点无关 NAT 开关与 UDP 会话超时（秒） |
| `gso` / `recvmsgx` / `sendmsgx` / `iproute2_table_index` / `iproute2_rule_index` | 平台卸载特性与策略路由表/规则索引 |

也支持在根配置直接编写顶层 `tun` 对象（`enable: true`），编译期自动合入 `local_inbounds`。`listen` 是配置结构要求的字段，TUN 不监听它。

## 并发上限

隧道本身常驻占用一个会话配额，每条 TCP 流和每个 UDP 来源再各占一个。实际并发是 `max_flows`、节点 `max_sessions` 减一、全局 `limits.max_sessions` 剩余配额三者的最小值。`limits.max_sessions` 默认 128，要用满默认的 `max_flows` 须调高它。节点会话上限为 1 时没有配额留给流，`kerlico check` 直接拒绝。

## 路由规划与防回环

可通过 `auto_route`、`auto_redirect`、`strict_route` 生成策略路由与重定向规则计划，也可手动把需要代理的网段指向接口：

```sh
ip route add 203.0.113.0/24 dev kerlico0
```

全局接管时要避免回环，出站流量不能再进入 TUN：

- 出站设置 `interface_name` / `dialer.interface`（如 `"eth0"`）或 `routing_mark`（如 `255`），绑定物理接口或策略路由标记。
- 远端代理的服务器地址和 `dns.servers` 用明细路由或策略路由走物理网关。

```sh
ip route add <proxy-server>/32 via <gateway> dev eth0
ip route add default dev kerlico0 metric 1
```

严格反向路径过滤（`rp_filter=1`）下，回包可能被内核丢弃，把 TUN 接口设为 `0` 或 `2`。

可作网关：接受已配置地址族内任意来源的包，来源不限于接口地址。本机转发其他主机的流量时，自行开启 `ip_forward` 并把这些主机的回程路由指向它们所在的接口。

## 接口故障

`ip link set <name> down` 期间写接口失败的包计入节点 `dropped`，节点继续运行，接口恢复后流量恢复。接口被删除时节点停止：kerlico 向标准错误打印诊断，`/v1/health` 转为 `degraded` 并列出该标签，其余入口继续运行，节点不会自行恢复。启动时创建接口失败（如缺少 `CAP_NET_ADMIN`）按同样方式报告。见[控制接口](control.md)。

## 限制

- TUN 看到的目标是 IP 时，可通过 Fake-IP 映射（`dns.fake_ip_range` / `fakedns`）、DNS 反向映射（`dns.reverse_mapping`）或首包嗅探（`sniffer` / 入站 `sniff: true`）还原目标域名并参与 `domain*`、`geosite`、`rule_set` 路由匹配。
- TUN 的 UDP 使用多目标关联，固定走节点绑定的 `outbound`，该出站须支持多目标 UDP 关联。TCP 按 `routes` / `route` 选择出站。
- `outbound` 为 `direct` 且目标是本机地址时，回包来源是本机地址，内核会丢弃。
- 只转发 TCP 和 UDP。发往用户态栈地址的 ICMP 回显由本地应答，发往其他地址的回显返回不可达，其他 ICMP 不处理。其他 IP 协议返回不可达。
- 没有鉴权。流量归属为 `Source::Local`，不计入 `users` 用量。
- 没有活动流时，关闭也要等 `limits.drain_timeout_ms` 的一半才退出：节点先等宽限期结束，再强制结束接口读写循环。

## 验证

`crates/protocol-tun/tests/netns.rs` 在独立网络命名空间内创建真实接口，验证内核 TCP 256 KiB 双向往返、UDP 往返、非接口地址来源、用量计量、接口 down 后恢复、接口删除后节点停止和 300 条并发流：

```sh
cargo test -p kerlico-tun --test netns --no-run
unshare -n cargo test -p kerlico-tun --test netns --offline -- --ignored
```
