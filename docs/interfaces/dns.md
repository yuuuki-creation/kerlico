# DNS

配置 `dns` 段或顶层 `fakedns` 后，`Local` 路径（`direct`、`wireguard`）的网站域名由 `kerlico-dns` 解析，不再走系统解析器。未配置时使用系统解析器。`Remote` 出站默认由远端解析；若路由规则命中 `action: "resolve"` 并指定解析策略，则先在本地按该策略解析再连接远端。

```json
{
  "dns": {
    "servers": [
      "tls://1.1.1.1#cloudflare-dns.com",
      "https://1.1.1.1/dns-query#cloudflare-dns.com",
      "udp://8.8.8.8",
      "tcp://[2001:4860:4860::8888]:53"
    ],
    "rules": [
      {
        "query_type": ["A", "AAAA"],
        "server": "fakeip",
        "rewrite_ttl": 1
      }
    ],
    "final": "tls://1.1.1.1#cloudflare-dns.com",
    "reverse_mapping": true,
    "enhanced_mode": "fake-ip",
    "fake_ip_range": "198.18.0.0/15",
    "fake_ip_range6": "fc00::/18",
    "hosts": { "svc.internal": ["10.0.0.5"] }
  }
}
```

| 字段 | 约束说明 |
| --- | --- |
| `servers` / `nameserver` | 上游列表。支持字符串简写（`udp://IP[:端口]`、`tcp://IP[:端口]`、`tls://IP[:端口]#证书名`、`https://IP[:端口][/路径]#证书名`、`https+local://...`、`fakeip`）或结构化对象（`tag`、`type`、`address`、`detour`、`inet4_range`、`inet6_range`） |
| `rules` | DNS 规则列表，支持 `domain`、`domain_suffix`、`domain_keyword`、`domain_regex`、`geosite`、`rule_set`、`query_type`、`inbound`、`ip_cidr`、`clash_mode`、`action`（`route`/`reject`/`predefined`）、`server`、`strategy`、`disable_cache`、`rewrite_ttl`、`client_subnet` |
| `final` / `final_server` | 默认上游标签或地址 |
| `fake_ip_range` / `fake_ip_range6` / `fakedns` / `enhanced_mode` | Fake-IP 池配置（含 `fake_ip_filter`、`fake_ip_ttl`），配合 `cache_file.store_fakeip` 或 `profile.store_fake_ip` 可持久化映射 |
| `reverse_mapping` | 开启后缓存真实解析结果的 IP 到域名反向映射，供入站 IP 目标还原域名 |
| `nameserver_policy` / `proxy_server_nameserver` / `proxy_server_nameserver_policy` | 按域名策略指定上游及代理节点服务器域名专用上游 |
| `hosts` | 静态映射，优先于上游。键按 IDNA 小写规范化 |

同时查询 A 和 AAAA，按响应 TTL 缓存。当路由规则命中 `action: "hijack-dns"` 时，DNS 报文直接交由内置 `DnsResolver::exchange_packet` 交换应答。

解析结果写入统计事件，见[统计历史](history.md)。
