# DNS

配置 `dns` 段后，`Local` 路径（`direct`、`wireguard`）的网站域名由 `kerlico-dns` 解析，不再走系统解析器。未配置时使用系统解析器。`Remote` 出站由远端解析，不受影响。

```json
{
  "dns": {
    "servers": ["tls://1.1.1.1#cloudflare-dns.com", "udp://8.8.8.8", "tcp://[2001:4860:4860::8888]:53"],
    "hosts": { "svc.internal": ["10.0.0.5"] }
  }
}
```

| 字段 | 约束说明 |
| --- | --- |
| `servers` | 上游列表。`udp://IP[:端口]`、`tcp://IP[:端口]`、`tls://IP[:端口]#证书名`，默认端口 53 或 853。IPv6 写作 `[2001:db8::1]`，不带端口时括号可省略。只接受字面 IP，避免解析上游本身时递归。`udp://` 收到截断响应时改用同地址同端口的 TCP |
| `hosts` | 静态映射，优先于上游。键按 IDNA 小写规范化；键只能是具体域名，`*.`、`+.` 这类通配写法被拒绝 |

`servers` 和 `hosts` 至少配置一项。只配 `hosts` 时，其他域名解析失败。配置 `dns` 后不读系统 `/etc/hosts`，只有 `hosts` 字段能覆盖上游。

同时查询 A 和 AAAA，按响应 TTL 缓存。TLS 使用内置的 WebPKI 根证书。解析结果再按节点的 `mode` 筛选，`dual-stack` 时 IPv4 优先。

解析结果写入统计事件，见[统计历史](history.md)。

上游查询从系统路由出去，不经过任何命名出站，也不受 `direct` 的 `interface` 影响。TUN 全局接管时要为上游地址加明细路由，见 [TUN 入站](tun.md)。
