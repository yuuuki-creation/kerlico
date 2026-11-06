# DNS

`kerlico-dns` 提供一条 DNS 管线，以下使用方都走它：`Local` 出网解析、路由规则的域名解析、DNS 劫持报文、`dns.listen`、DNS 出站、控制面 `/dns/query`、代理服务器域名解析。未配置 `dns` 段或写 `enable: false` 时使用系统解析器。

## 查询顺序

与 Mihomo 一致：

1. `hosts`（`use-hosts` 默认开）：精确名优先，其次通配（`*.x` 一级、`.x` 多级子域、`+.x` 含自身），再次系统 hosts 文件（`use-system-hosts` 默认开）。值可为 IP、IP 列表或另一个域名（别名，链尾交上游解析）。只回答 A/AAAA，TTL 10。
2. sing-box `rules`：`domain`、`domain_suffix`、`domain_keyword`、`domain_regex`、`geosite`、`rule_set`（按规则集内容匹配）、`query_type`、`invert`；动作 `route`（`server` 必须是已定义的上游标签或 `fakeip`）与 `reject`（`method: default` 回 REFUSED，`drop` 不回应；30 秒内 50 次自动转丢弃，`no_drop` 关闭）。
3. Fake-IP：只对 DNS 报文（劫持、`dns.listen`、DNS 出站）生效。A 分配 IPv4、AAAA 分配 IPv6（缺网段时空应答），HTTPS/SVCB 空应答，其他类型继续向下。`fake-ip-filter` 支持通配、`geosite:`、`rule-set:`；`fake-ip-filter-mode` 为 `blacklist`（默认，名单内不分配）或 `whitelist`（只为名单分配）。
4. `ipv6: false` 时 AAAA 回空 NOERROR。
5. 缓存：键为（名称、类型、解析器）。
6. 上游组：`nameserver-policy` 命中则只查该组；A/AAAA 且配置了 `fallback` 时，`fallback-filter.domain`/`geosite` 命中只查 fallback，否则主组与 fallback 并发，主组应答为空或任一地址触发过滤（`geoip` 不属于 `geoip-code` 且非私有地址，或落在 `ipcidr`）时用 fallback 的结果；其余查主组。sing-box `final` 替换主组。

组内并发查询，第一个有效应答胜出：SERVFAIL、REFUSED 与出错视为失败；A/AAAA 无地址的应答只在全组都无地址时采用且不缓存；组内有 `rcode://` 时直接用它。上游应答原样转发，任意记录类型透传，ID 恢复为客户端 ID。

## 解析器

| 使用方 | 上游 | Fake-IP |
| --- | --- | --- |
| DNS 报文 | 主解析器 | 是 |
| `Local` 出网与路由规则 | `direct-nameserver`（`direct-nameserver-follow-policy` 为真时先查 `nameserver-policy`），未配置时主解析器 | 否 |
| 代理服务器域名 | `proxy-server-nameserver` 与 `proxy-server-nameserver-policy`，未配置时主解析器 | 否 |
| `/dns/query` | 主解析器 | 否 |

`Local` 与代理服务器解析并发查 A 和 AAAA；A 有结果后最多再等 `ipv6-timeout`（默认 100 毫秒）。sing-box `strategy`（`prefer_ipv4` 默认、`prefer_ipv6`、`ipv4_only`、`ipv6_only`）决定地址族与顺序。

代理服务器域名经进程级入口 `kerlico_core::lookup_host` / `connect_host` 解析，`kerlico-net` 的连接器与 hysteria1/2、masque、mieru、naive、openvpn、shadowquic、shadowsocks、shadowsocksr、shadowtls、socks、ss2022、ssh、sudoku、trojan、trusttunnel、tuic、vless、vmess、wireguard 的客户端已改用它。

## 上游写法

Mihomo URL：

| 写法 | 传输 |
| --- | --- |
| `8.8.8.8`、`udp://IP[:端口]` | UDP，截断时改用 TCP |
| `tcp://` | TCP |
| `tls://主机[:853]` | DoT，证书按主机名校验 |
| `https://主机[:443][/路径]` | DoH over HTTP/2（POST，ID 为 0）；`#h3=true` 或 `h3://` 只用 HTTP/3；全局 `prefer-h3` 先试 HTTP/3 再退 HTTP/2 |
| `quic://主机[:853]` | DoQ（RFC 9250） |
| `system`、`dhcp://接口` | 读 `/etc/resolv.conf` 的 nameserver；`dhcp://` 不做 DHCP，与 `system` 相同 |
| `rcode://success\|format_error\|server_failure\|name_error\|not_implemented\|refused` | 固定 RCODE |

`#` 之后用 `&` 分隔：单独的名字是出站或代理组（`RULES` 按路由规则选出站，`DIRECT` 直连），以及 `ecs=前缀`、`ecs-override=true`、`skip-cert-verify=true`、`sni=名称`。未知参数报错。`tls://1.1.1.1#cloudflare-dns.com` 这类旧写法里 `#` 后的名字现在按出站名解释，引用不存在的出站时启动失败；证书名改写 `#sni=cloudflare-dns.com`。

上游主机名用 `default-nameserver`（只接受 IP 上游）解析，未配置时用系统解析器；经出站拨号时主机名交给出站。`respect-rules: true` 让主组、fallback 与策略组的直连上游按路由规则拨号，要求同时配置 `proxy-server-nameserver`。DoQ 与 DoH3 不支持经出站拨号，配置时报错。经出站的 DNS 流量不计入业务计量。

结构化对象（sing-box）：`tag`、`type`（`udp`、`tcp`、`tls`、`https`、`h3`、`quic`、`local`、`fakeip`）、`server`、`server_port`、`path`、`headers`、`tls`（`server_name`、`insecure`、`ca_pem`、`certificate_path`）、`domains`、`detour`、`client_subnet`、`inet4_range`、`inet6_range`。

## 缓存与 ECS

- TTL 取应答中除 OPT 外记录的最小值，SERVFAIL 存 1 秒，TTL 为 0 不缓存；命中时 TTL 改为剩余秒数。
- `cache-algorithm`：`lru`（默认）或 `arc`；`cache-max-size` / `cache_capacity` 默认 4096；`disable-cache` 关闭。
- `optimistic-cache` 默认开（Mihomo 行为）：过期条目以 TTL 1 返回，同时后台刷新。
- `client-subnet`（全局）或上游 `#ecs=`、`client_subnet` 写入 EDNS Client Subnet；查询已带 ECS 时只有 `ecs-override=true` 替换（结构化对象的 `client_subnet` 总是替换）。
- `POST /cache/dns/flush` 清空缓存，`POST /cache/fakeip/flush` 清空 Fake-IP 映射。

## 监听

`listen: 127.0.0.1:1053`（`:53` 表示 `0.0.0.0:53`）在同一端口提供 UDP 与 TCP，报文走 DNS 报文解析器（含 Fake-IP）。绑定失败时启动失败。

## 路由解析

Mihomo 规则行中 `IP-CIDR`、`IP-CIDR6`、`GEOIP`、含 IP 内容的 `RULE-SET` 以及含 IP 条件的逻辑规则，未写 `no-resolve` 时（规则对象字段 `resolve_ip: true`），目标是域名的连接在求值到该规则时经 `Local` 解析器解析一次，有 IPv4 时只用 IPv4，结果对该规则及之后的规则可见；解析失败按无地址继续。sing-box `action: resolve` 同样在命中时解析，结果对之后的规则可见。

解析结果只用于匹配。命中 `Remote` 出站时远端仍收到原域名，本机不改写目标，与 AGENTS.md 中 `Remote` 不替远端解析网站域名的约定一致；命中 `Local` 出站时连接阶段再按节点 `mode` 解析（同一缓存）。`resolve` 动作带 `strategy` 时沿用原行为：先解析再把 IP 交给出站。

Mihomo 只取一个随机 IPv4 匹配，kerlico 用全部 IPv4 中任一命中；记录分属不同网段时结果可能不同。

## DNS 出站

`type: dns` 出站未配置 `servers`/`hosts` 时，发往它的报文交给引擎 DNS 管线（与 `hijack-dns` 相同）；配置了则用自己的 `servers`/`hosts` 管线。两种情况都透传全部记录类型。

## Mihomo 键

接受：`enable`、`listen`、`ipv6`、`ipv6-timeout`、`use-hosts`、`use-system-hosts`、`prefer-h3`、`respect-rules`、`cache-algorithm`、`enhanced-mode`（`normal`、`redir-host`、`fake-ip`）、`fake-ip-range`、`fake-ip-range6`、`fake-ip-ttl`、`fake-ip-filter`、`fake-ip-filter-mode`、`default-nameserver`、`nameserver`、`fallback`、`fallback-filter`、`nameserver-policy`（键可用逗号列多个条件）、`proxy-server-nameserver`、`proxy-server-nameserver-policy`、`direct-nameserver`、`direct-nameserver-follow-policy`。顶层 `hosts` 并入 `dns.hosts`，`dns.hosts` 中的同名键优先。其他键报错。

与 Mihomo 的差异：

- `nameserver-policy` 写成 JSON 对象时键按字母排列，域名通配取最具体者，`geosite:`/`rule-set:` 在通配之后检查；要按书写顺序匹配，写成单键对象数组 `[{"rule-set:a": "..."}, {"+.x": "..."}]`。
- `fallback-filter.geoip` 对 GeoIP 库查不到国家的地址也视为“不属于”，Mihomo 视为不触发 fallback。
- 没有 singleflight 合并并发的相同查询。

## Mihomo YAML 默认值

YAML 配置中 `dns` 段写了 `nameserver`（Mihomo 写法）时：

- `ipv6` 未写则为 `false`，与 Mihomo 相同；JSON 配置与 sing-box 写法（`servers`）未写时为 `true`。
- `nameserver-policy`、`proxy-server-nameserver-policy` 按书写顺序匹配，与 Mihomo 的有序映射一致：连续的域名通配组成一段，段内取最具体者；`geosite:`、`rule-set:` 逐条检查；先命中者胜出。

## Geo 数据

`nameserver-policy`、`proxy-server-nameserver-policy`、`fake-ip-filter`、DNS 规则中的 `geosite:` 与 `fallback-filter` 的 `geosite`、`geoip-code` 并入路由表的 `GeoSlot`：启动时按引用加载 `geosite.dat`、`geoip.dat` 或 `Country.mmdb`（`geodata-mode` 决定 GeoIP 来源），Geo 文件刷新换入后立即按新数据匹配。`rule-set:` 引用读路由规则集，同样随刷新生效。

## 验证

- 单元测试：`crates/dns/src/pipeline_tests.rs`（回环权威服务器，覆盖策略、fallback、Fake-IP 过滤、缓存与乐观刷新、规则集、截断转 TCP、ECS、引导解析、出站拨号、监听、DoH、DoQ、`rcode://`）、`wire.rs`、`cache.rs`、`matcher.rs`、`hosts.rs`、`server.rs`；`crates/routing` 的 `mihomo_ip_rules_request_resolution_unless_no_resolve`；`crates/egress/tests/dns_pipeline.rs`；`egress` 单元测试 `nameserver_policy_geosite_reads_the_route_geo_slot`；`config` 的 `mihomo_yaml_keeps_policy_order_and_ipv6_default`。
- 与 Mihomo 差分：`tools/dns_diff_mihomo.py --kerlico <二进制> --mihomo <二进制>` 用同一份 `dns:` 配置启动两者，比较 14 类查询（主组、策略组、ipcidr 与 domain fallback、NXDOMAIN fallback、hosts 精确与通配、Fake-IP、fake-ip-filter、TXT 透传、`ipv6: false`，以及 `rule-set:` 与域名通配谁先写谁先命中的两种顺序）的应答来源。2026-11-07 在 `perf-01` 对 Mihomo v1.19.33 运行，14/14 一致。
- 未验证：DoT 与 DoH3 没有测试；DoH 与 DoQ 只对本地自签服务器测试；`respect-rules` 与 `#出站` 只在单元测试中用替身拨号器验证，未经真实代理出站。
