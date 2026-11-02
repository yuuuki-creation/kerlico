# TUN 入站

`kerlico-tun` 注册节点类型 `tun`，只能放在 `local_inbounds`。它创建内核 TUN 接口并配置地址，把内核交来的 IP 包还原成 TCP 流和 UDP 数据报，经本地会话进入共享 `Dispatcher`。需要 `CAP_NET_ADMIN`，仅 Linux 经过验证。

```json
{
  "local_inbounds": [{
    "tag": "tun",
    "type": "tun",
    "listen": "127.0.0.1:0",
    "outbound": "proxy",
    "options": { "name": "kerlico0", "addresses": ["198.18.0.1/16"], "mtu": 1500 }
  }]
}
```

| 字段 | 约束说明 |
| --- | --- |
| `name` | 接口名，默认 `kerlico0`，最长 15 字符 |
| `addresses` | 接口地址，1 至 2 个，每个地址族最多一个。IPv4 前缀不超过 `/30`，IPv6 不超过 `/126`。下一个地址留给用户态栈 |
| `mtu` | 1280 至 9000，默认 1500 |

`listen` 是配置结构要求的字段，TUN 不监听它。

## 路由由用户配置

kerlico 不修改系统路由。创建接口后，自行把需要代理的网段指向它：

```sh
ip route add 203.0.113.0/24 dev kerlico0
```

全局接管时要避免回环，出站流量不能再进入 TUN：

- `direct` 出站设置 `"options": {"interface": "eth0"}`，绑定物理接口。
- 远端代理的服务器地址和 `dns.servers` 用明细路由走物理网关。多数协议的载体 socket 不经过设备层，不受 `interface` 影响。

```sh
ip route add <proxy-server>/32 via <gateway> dev eth0
ip route add default dev kerlico0 metric 1
```

严格反向路径过滤（`rp_filter=1`）下，回包可能被内核丢弃，把 TUN 接口设为 `0` 或 `2`。

## 限制

- TUN 看到的目标都是 IP，域名规则不会命中，只有 `ip_cidr`、`port`、`network` 等条件生效。暂无 Fake-IP 或首包嗅探。
- TUN 的 UDP 使用多目标关联，固定走节点绑定的 `outbound`，该出站须支持多目标 UDP 关联。TCP 按 `routes` 选择出站。
- `outbound` 为 `direct` 且目标是本机地址时，回包来源是本机地址，内核会丢弃。
- 只转发 TCP、UDP 和 ICMP 回显；其他 IP 协议返回不可达。
- 没有鉴权。流量归属为 `Source::Local`，不计入 `users` 用量。

## 验证

`crates/protocol-tun/tests/netns.rs` 在独立网络命名空间内创建真实接口，验证内核 TCP 256 KiB 双向往返、UDP 往返和用量计量：

```sh
cargo test -p kerlico-tun --test netns --no-run
unshare -n cargo test -p kerlico-tun --test netns --offline -- --ignored
```
