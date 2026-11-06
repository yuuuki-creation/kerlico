# DNS

由 `tools/capability_matrix.py build` 生成，不要手改。

## action

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `action` | 要执行的动作。 |  | 有 |  | 部分 | 未测 | 取值：`evaluate`、`predefined`、`reject`、`respond`、`route`、`route-options`<br>约束：自 sing-box 1.11.0 起<br>约束：默认使用 `route`。 |
| `answer` | 用于作为回答响应的文本 DNS 记录列表。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.12.0 起 |
| `client-subnet` | 默认情况下，将带有指定 IP 前缀的 `edns0-subnet` OPT 附加记录附加到每个查询。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.11.0 起<br>约束：自 sing-box 1.14.0 起 |
| `disable-cache` | 在此查询中禁用缓存。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.11.0 起<br>约束：自 sing-box 1.14.0 起 |
| `disable-optimistic-cache` | 在此查询中禁用乐观 DNS 缓存。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `evaluate` | evaluate 向指定服务器发查询并保存响应，供后续规则用 match_response 匹配，不终止规则评估 |  | 有 |  | 未实现 | 未测 | 取值：`evaluate`<br>约束：自 sing-box 1.14.0 起 |
| `extra` | 用于作为额外记录响应的文本 DNS 记录列表。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.12.0 起 |
| `method` | - `default`: 返回 REFUSED。 |  | 有 |  | 已实现 | 通过 | 取值：`default`、`drop`<br>约束：自 sing-box 1.11.0 起<br>约束：默认使用 `default`。 |
| `no-drop` | 如果未启用，则 30 秒内触发 50 次后，`method` 将被暂时覆盖为 `drop`。 |  | 有 |  | 已实现 | 通过 | 约束：当 `method` 设为 `drop` 时不可用。<br>约束：自 sing-box 1.11.0 起 |
| `ns` | 用于作为名称服务器响应的文本 DNS 记录列表。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.12.0 起 |
| `predefined` | `predefined` 以预定义的 DNS 记录响应。 |  | 有 |  | 未实现 | 未测 | 取值：`predefined`<br>约束：自 sing-box 1.12.0 起 |
| `race` | 仅可用于 `route`、`respond`、`reject` 和 `predefined` 动作。 |  | 有 |  | 未实现 | 未测 | 约束：与 `speculative` 冲突。<br>约束：自 sing-box 1.14.0 起<br>约束：需要 `match_response`（对 logical 规则，位于子规则中）。<br>约束：默认情况下，规则逐条按顺序匹配：带 `match_response` 的规则等待其引用的响应，在它被判定之前不会匹配任何后续规则。 |
| `rcode` | 响应码。 |  | 有 |  | 未实现 | 未测 | 取值：`FORMERR`、`NOERROR`、`NOTIMP`、`NXDOMAIN`、`REFUSED`、`SERVFAIL`<br>约束：自 sing-box 1.12.0 起<br>约束：默认使用 `NOERROR`。 |
| `reject` | `reject` 拒绝 DNS 请求。 |  | 有 |  | 已实现 | 通过 | 取值：`reject` |
| `remove-client-subnet` | 移除查询中的 `edns0-subnet` OPT 附加记录，并抑制 `dns.client_subnet`。 |  | 有 |  | 未实现 | 未测 | 约束：与 `client_subnet` 冲突。<br>约束：自 sing-box 1.14.0 起 |
| `respond` | `respond` 会终止规则评估，并直接返回前序 `evaluate` 动作保存的已评估的响应。 |  | 有 |  | 未实现 | 未测 | 取值：`respond`<br>约束：自 sing-box 1.14.0 起 |
| `rewrite-ttl` | 重写 DNS 回应中的 TTL。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.11.0 起<br>约束：自 sing-box 1.14.0 起 |
| `route` | `route` 继承了将 DNS 请求 路由到指定服务器的经典规则动作。 |  | 有 |  | 部分 | 未测 | 取值：`route` |
| `route-options` | `route-options` 为路由设置选项。 |  | 有 |  | 未实现 | 未测 | 取值：`route-options` |
| `server` | 目标 DNS 服务器的标签。 |  | 有 |  | 部分 | 未测 | 约束：必填<br>约束：自 sing-box 1.11.0 起<br>约束：自 sing-box 1.14.0 起 |
| `speculative` | 与 `race` 冲突。 |  | 有 |  | 未实现 | 未测 | 约束：启用 `speculative` 后，查询在规则匹配时立即发出、与未判定的竞态规则并行；其响应仅在所有竞态规则均未匹配后才被使用。<br>约束：没有前序竞态规则时无效果。<br>约束：自 sing-box 1.14.0 起<br>约束：默认情况下，查询决不与未判定的竞态规则并行发出：已匹配的 `evaluate` 动作扣住其查询，规则匹配在此处停止，直到所有竞态规则均未匹配。<br>约束：默认情况下，查询决不与未判定的竞态规则并行发出：已匹配的 `route` 动作扣住其查询，直到所有竞态规则均未匹配后才发送。 |
| `strategy` | 为此查询设置域名策略。 |  | 废弃 |  | 不适用 | 未测 | 取值：`ipv4_only`、`ipv6_only`、`prefer_ipv4`、`prefer_ipv6`<br>约束：`strategy` 已在 sing-box 1.14.0 废弃，且将在 sing-box 1.16.0 中被移除。<br>约束：自 sing-box 1.12.0 起 |
| `tag` | 已评估响应的标签。 |  | 有 |  | 未实现 | 未测 | 约束：带标签的响应仅能通过 `match_response` 以标签引用；<br>约束：自 sing-box 1.14.0 起 |
| `timeout` | 覆盖匹配查询的 DNS 查询超时时间。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |

## config

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `cache-capacity` | LRU 缓存容量。 |  | 有 |  | 未实现 | 未测 | 约束：小于 1024 的值将被忽略。<br>约束：自 sing-box 1.11.0 起 |
| `client-subnet` | 默认情况下，将带有指定 IP 前缀的 `edns0-subnet` OPT 附加记录附加到每个查询。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.9.0 起 |
| `disable-cache` | 禁用 DNS 缓存。 |  | 有 |  | 未实现 | 未测 | 约束：与 `optimistic` 冲突。 |
| `disable-expire` | 禁用 DNS 缓存过期。 |  | 有 |  | 未实现 | 未测 | 约束：与 `optimistic` 冲突。 |
| `fakeip` | 旧版 FakeIP 配置对象 |  | 已移除 |  | 不适用 | 未测 |  |
| `final` | 默认 DNS 服务器的标签。 |  | 有 |  | 部分 | 未测 | 约束：默认使用第一个服务器。 |
| `independent-cache` | 使每个 DNS 服务器的缓存独立，以满足特殊目的。 |  | 废弃 |  | 不适用 | 未测 | 约束：`independent_cache` 已在 sing-box 1.14.0 废弃，且将在 sing-box 1.16.0 中被移除，参阅迁移指南。 |
| `optimistic` | 启用乐观 DNS 缓存。 |  | 有 |  | 未实现 | 未测 | 约束：与 `disable_cache` 和 `disable_expire` 冲突。<br>约束：当设置为 `true` 时，使用默认超时 `3d`。<br>约束：自 sing-box 1.14.0 起 |
| `optimistic-enabled` | 启用乐观 DNS 缓存。 |  | 有 |  | 未实现 | 未测 |  |
| `optimistic-timeout` | 过期缓存条目可被乐观提供的最长时间。 |  | 有 |  | 未实现 | 未测 | 约束：默认使用 `3d`。 |
| `reverse-mapping` | 在响应 DNS 查询后存储 IP 地址的反向映射以为路由目的提供域名。 |  | 有 |  | 已实现 | 通过 |  |
| `rules` | 规则列表 |  | 有 |  | 部分 | 未测 |  |
| `servers` | DNS 服务器列表 |  | 有 |  | 部分 | 通过 |  |
| `strategy` | 默认解析域名策略。 |  | 有 |  | 部分 | 通过 | 取值：`ipv4_only`、`ipv6_only`、`prefer_ipv4`、`prefer_ipv6` |
| `timeout` | 每次 DNS 查询的默认超时时间。 |  | 有 |  | 已实现 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：默认使用 `10s`。 |

## dns

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `client-ip` | ECS IP |  |  | 有 | 未实现 | 未测 | 约束：IPv4 /24、IPv6 /96 发送 |
| `disable-cache` | 禁用缓存，默认 false |  |  | 有 | 未实现 | 未测 |  |
| `disable-fallback` | 禁用 fallback，默认 false |  |  | 有 | 未实现 | 未测 |  |
| `disable-fallback-if-match` | 命中优先列表时禁用 fallback |  |  | 有 | 未实现 | 未测 |  |
| `enable-parallel-query` | 并行查询：动态分组、组内竞速、组间回退 |  |  | 有 | 未实现 | 未测 | 约束：相邻且 clientIP、skipFallback、queryStrategy、tag、domains、expectedIPs、unexpectedIPs 完全相同为一组 |
| `hosts` | 静态映射 |  |  | 有 | 部分 | 通过 | 取值：`"a.com":"#3"`、`"a.com":"b.com"`、`"baidu.com":"127.0.0.1"`、`"dns.google":["8.8.8.8","8.8.4.4"]`<br>约束：#数字 请求失败；DNS 出站返回对应 rcode<br>约束：单域名递归，最大深度 5<br>约束：同时有 IP 和域名时只返回 IP<br>约束：多个域名视为失败<br>约束：无前缀默认 full: |
| `query-strategy` | 查询类型，默认 UseIP |  |  | 有 | 部分 | 通过 | 取值：`UseIP`、`UseIPv4`、`UseIPv6`、`UseSystem`<br>约束：UseSystem 检查默认网关，图形环境实时、命令行一次<br>约束：子项冲突时空响应 |
| `script` | Lua DNS 脚本路径 |  |  | 有 | 未实现 | 未测 | 约束：不能与 disableFallback、disableFallbackIfMatch、enableParallelQuery、server 的 domains、skipFallback、finalQuery 同用（source:infra/conf/dns.go） |
| `serve-expired-ttl` | 乐观缓存有效期秒，默认 0 永不过期 |  |  | 有 | 未实现 | 未测 |  |
| `serve-stale` | 乐观缓存，默认 false |  |  | 有 | 未实现 | 未测 |  |
| `servers` | 服务器列表，字符串或对象 |  |  | 有 | 部分 | 通过 |  |
| `tag` | 内置 DNS 查询的 inboundTag |  |  | 有 | 未实现 | 未测 | 约束：localhost、fakedns、TCPL、DOHL、DOQL 除外 |
| `use-system-hosts` | 附加系统 hosts |  |  | 有 | 部分 | 通过 |  |

## fakedns

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `fakedns` | FakeDNS 虚构解析以取回域名 |  |  | 有 | 已实现 | 通过 | 取值：`fakedns`<br>约束：FakeIP 未还原将无法连接<br>约束：可能污染本地 DNS |
| `combo` | FakeDNS 组合 |  |  | 有 | 已实现 | 通过 | pool：`both`、`ipv4`、`ipv6`<br>order：`blacklist other domains`、`first`、`whitelist domains`<br>sniffing：`fakedns`、`fakedns+others`、`metadataOnly`<br>entry：`dns outbound`、`tproxy`、`tun`、`tunnel`<br>约束：metadataOnly 时 destOverride 仅 fakedns<br>约束：与分流共存时要给 fakedns 相同 domains<br>约束：客户端入站需 sniffing destOverride 含 fakedns<br>约束：必须把查询路由到 FakeDNS 才生效 |
| `array-form` | fakedns 可写成多池数组，同时返回多池 FakeIP |  |  | 有 | 未实现 | 未测 |  |
| `auto-init` | 未配置时按 queryStrategy 初始化 |  |  | 有 | 未实现 | 未测 | 取值：`UseIP: 198.18.0.0/15+2001:2::/48 各 32768`、`UseIPv4: 198.18.0.0/15 65535`、`UseIPv6: 2001:2::/48 65535` |
| `ip-pool` | FakeIP 地址段 |  |  | 有 | 已实现 | 通过 |  |
| `pool-size` | 映射上限，默认 65535，LRU 淘汰 |  |  | 有 | 已实现 | 通过 | 约束：必须不大于地址总数 |

## flow

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `pipeline` | 先 Hosts，再按 domains 列表 1 + fallback 列表 2 依次查询 |  |  | 有 | 部分 | 通过 | 约束：disableFallback 跳过列表 2<br>约束：disableFallbackIfMatch 列表 1 非空时跳过<br>约束：expectedIPs/unexpectedIPs 过滤为空时试下一个<br>约束：finalQuery 截断后续<br>约束：skipFallback 不进列表 2<br>约束：配 script 时交给 Lua |
| `query-types` | 内置 DNS 只支持 A 和 AAAA，CNAME 重复查询 |  |  | 有 | 已实现 | 通过 | 约束：其他查询不进内置 DNS |

## global

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `cache-algorithm` | DNS 缓存算法，默认 lru | 有 |  |  | 未实现 | 未测 | 取值：`arc`、`lru` |
| `cache-max-size` | DNS 缓存最大容量（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `default-nameserver` | 解析 DNS 服务器域名用的 DNS | 有 |  |  | 未实现 | 未测 | 取值：`纯 IP 上游`<br>约束：必须为 IP，可为加密 DNS |
| `direct-nameserver` | direct 出口域名解析的 DNS | 有 |  |  | 部分 | 通过 | 取值：`上游列表`<br>约束：不填时遵循 nameserver-policy、nameserver、fallback |
| `direct-nameserver-follow-policy` | direct-nameserver 是否遵循 nameserver-policy，默认否 | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true`<br>约束：仅 direct-nameserver 不为空时生效 |
| `enable` | 启用 DNS 模块，false 用系统 DNS | 有 |  |  | 部分 | 未测 | 取值：`false`、`true` |
| `enhanced-mode` | DNS 处理模式，默认 redir-host | 有 |  |  | 已实现 | 通过 | 取值：`fake-ip`、`redir-host` |
| `fake-ip-filter` | fakeip 过滤，支持域名通配与 rule-set:、geosite: 引入 | 有 |  |  | 部分 | 未测 | 取值：`geosite:x`、`rule-set:x`、`规则语法`、`通配域名`<br>约束：fake-ip-filter-mode 为 rule 时改用规则写法，目标为 fake-ip 或 real-ip<br>约束：规则模式 RuleSet behavior 须为 domain 或 classical；classical 仅域名类规则生效<br>约束：规则模式支持 GEOSITE、RuleSet、DOMAIN*、MATCH |
| `fake-ip-filter-mode` | fakeip 过滤模式，默认 blacklist | 有 |  |  | 未实现 | 未测 | 取值：`blacklist`、`rule`、`whitelist` |
| `fake-ip-range` | fakeip IPv4 段，tun 默认 IPv4 地址参考此值 | 有 |  |  | 已实现 | 通过 | 取值：`CIDR` |
| `fake-ip-range6` | fakeip IPv6 段 | 有 |  |  | 已实现 | 通过 | 取值：`CIDR` |
| `fake-ip-ttl` | fakeip 查询返回的 TTL | 有 |  |  | 已实现 | 未测 | 取值：`整数` |
| `fallback` | 后备解析服务器；配置后默认启用 fallback-filter，geoip-code 为 cn | 有 |  |  | 未实现 | 未测 | 取值：`上游列表` |
| `fallback-filter-domain` | 命中域名直接用 fallback | 有 |  |  | 未实现 | 未测 | 取值：`通配域名` |
| `fallback-filter-geoip` | 启用 geoip 判断 | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `fallback-filter-geoip-code` | 国家缩写，默认 CN；其他国家结果视为污染 | 有 |  |  | 未实现 | 未测 | 取值：`国家代码` |
| `fallback-filter-geosite` | 命中域名只用 fallback | 废弃 |  |  | 不适用 | 未测 | 取值：`geosite 集合`<br>约束：字段已废弃，改用 nameserver-policy |
| `fallback-filter-ipcidr` | 命中网段的结果视为污染 | 有 |  |  | 未实现 | 未测 | 取值：`CIDR 列表` |
| `fallback-lazy-query` | 默认 false；true 时先判断 nameserver 结果再发起 fallback | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `ipv6` | 是否解析 IPv6，false 时 AAAA 返回空 | 有 |  |  | 部分 | 通过 | 取值：`false`、`true` |
| `ipv6-timeout` | 内部双栈并发时等待 AAAA 的时间，单位 ms，默认 100 | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `listen` | DNS 服务监听，支持 udp、tcp | 有 |  |  | 未实现 | 未测 | 取值：`host:port` |
| `listen-routing-mark` | DNS 监听 socket 的 routing-mark（文档未写） | 有 |  |  | 未实现 | 未测 | 取值：`整数` |
| `nameserver` | 默认解析服务器 | 有 |  |  | 部分 | 通过 | 取值：`上游列表` |
| `nameserver-policy` | 指定域名查询的解析服务器，优先于 nameserver、fallback | 有 |  |  | 部分 | 未测 | 取值：`geosite:`、`rule-set:`、`域名通配`<br>约束：值支持字符串或数组 |
| `prefer-h3` | DoH 优先 HTTP/3 | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true`<br>约束：强烈不建议与 respect-rules 一起用 |
| `proxy-server-nameserver` | 仅解析代理节点域名的 DNS | 有 |  |  | 未实现 | 未测 | 取值：`上游列表`<br>约束：不填时遵循 nameserver-policy、nameserver、fallback |
| `proxy-server-nameserver-policy` | 节点域名解析策略，格式同 nameserver-policy | 有 |  |  | 未实现 | 未测 | 取值：`映射`<br>约束：仅 proxy-server-nameserver 不为空时生效 |
| `respect-rules` | DNS 连接遵守路由规则 | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true`<br>约束：强烈不建议和 prefer-h3 一起使用<br>约束：需配置 proxy-server-nameserver |
| `use-hosts` | 回应配置中的 hosts，默认 true | 有 |  |  | 部分 | 通过 | 取值：`false`、`true` |
| `use-system-hosts` | 查询系统 hosts，默认 true | 有 |  |  | 部分 | 通过 | 取值：`false`、`true` |

## hijack

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `ip-to-domain` | 经 DNS 劫持进入 DNS 模块，使 TUN、Redirect、TProxy 入站流量把 IP 映射回域名 | 有 |  |  | 已实现 | 未测 |  |

## hosts

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `lan` | 值 lan 加入本机所有网卡地址 | 有 |  |  | 未实现 | 未测 | 取值：`lan` |
| `mapping` | hosts 映射，键支持域名通配，值支持字符串或数组 | 有 |  |  | 部分 | 通过 | 取值：`IP`、`IP 数组`、`域名重定向`<br>约束：域名重定向不支持数组<br>约束：完整域名优先于通配：foo.example.com > *.example.com > .example.com |
| `predefined-format` | hosts 服务器 predefined 取单 IP 字符串或 IP 列表；path 默认系统 hosts 文件 |  | 有 |  | 部分 | 通过 | 约束：/etc/hosts 为默认路径，Windows 用 C:\Windows\System32\Drivers\etc\hosts |

## legacy

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `rcode-server` | 旧版 rcode:// 服务器的取值 |  | 已移除 |  | 不适用 | 未测 | 取值：`format_error`、`name_error`、`not_implemented`、`refused`、`server_failure`、`success`<br>约束：用 predefined 动作替代 |

## legacy-fakeip

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `enabled` | 启用 FakeIP 服务。 |  | 已移除 |  | 不适用 | 未测 |  |
| `inet4-range` | 用于 FakeIP 的 IPv4 地址范围。 |  | 已移除 |  | 不适用 | 未测 |  |
| `inet6-range` | 用于 FakeIP 的 IPv6 地址范围。 |  | 已移除 |  | 不适用 | 未测 |  |

## param

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `disable-ipv4` | 丢弃 A 回应 | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `disable-ipv6` | 丢弃 AAAA 回应 | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `disable-qtype-int` | 丢弃指定类型回应 | 有 |  |  | 未实现 | 未测 | 取值：`disable-qtype-65=true` |
| `ecs` | 指定查询 subnet | 有 |  |  | 未实现 | 未测 | 取值：`CIDR` |
| `ecs-override` | 强制覆盖查询 subnet | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `h3` | 强制 HTTP/3 建立 DoH | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true`<br>约束：与 prefer-h3 不冲突<br>约束：需服务器支持 HTTP/3 |
| `name-cert-verify` | 仅修改证书 DNSName 校验目标，不改 SNI | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `proxy-or-interface` | #<名称> 指定代理或接口；优先代理，名称不存在则视作接口 | 有 |  |  | 未实现 | 未测 | 取值：`#en0`、`#proxy`<br>约束：经代理查询应配 proxy-server-nameserver 防鸡蛋问题<br>约束：附加参数用于发向公网地址的 DNS 服务器 |
| `rules` | #RULES 遵守路由规则，等同 respect-rules | 有 |  |  | 未实现 | 未测 | 取值：`#RULES` |
| `skip-cert-verify` | 跳过 TLS 证书验证 | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |

## query-options

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | DNS 查询策略、缓存、ECS、TTL 和超时组合 |  | 有 |  | 部分 | 通过 | strategy：`ipv4_only`、`ipv6_only`、`prefer_ipv4`、`prefer_ipv6`<br>cache：`default`、`disable_cache`、`disable_expire`、`optimistic`<br>cache_scope：`independent_cache(deprecated)`、`shared`<br>ecs：`dns.client_subnet`、`off`、`remove_client_subnet`、`rule client_subnet`<br>ttl：`rewrite_ttl`、`upstream`<br>timeout：`action timeout`、`default-10s`、`dns.timeout`<br>reverse_mapping：`off`、`on`<br>约束：cache_capacity 小于 1024 被忽略<br>约束：disable_cache、disable_expire 与 optimistic 冲突<br>约束：dns.timeout 可被规则 timeout 或 domain_resolver.timeout 覆盖<br>约束：optimistic 为 true 时超时默认 3d<br>约束：rule.client_subnet 覆盖 dns.client_subnet；remove_client_subnet 与 client_subnet 冲突 |

## resolve

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `flow` | 解析流程：规则判定域名或 IP，经 nameserver-policy、nameserver 与 fallback 并发、fallback-filter、direct-nameserver 重新解析 | 有 |  |  | 部分 | 通过 | 约束：direct-nameserver 重新解析自 v1.19.10 也用于 UDP；Tun 入站 UDP 仅限 Fakeip 模式 |

## rule

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | DNS 规则的类型、动作和响应匹配组合 |  | 有 |  | 部分 | 未测 | rule_type：`default`、`logical`<br>logical_mode：`and`、`or`<br>action：`evaluate`、`predefined`、`reject`、`respond`、`route`、`route-options`<br>response_match：`match_response:tag`、`match_response:true`、`off`<br>response_field：`ip_accept_any`、`ip_cidr`、`ip_is_private`、`response_answer`、`response_extra`、`response_ns`、`response_rcode`<br>race：`off`、`on`<br>speculative：`off`、`on`<br>约束：evaluate、respond 只允许顶层规则，respond 必须在 evaluate 之后<br>约束：ip_version、query_type 与旧版地址过滤字段、strategy 动作选项、rule_set_ip_cidr_accept_empty 在同一 DNS 配置不兼容，启动报错<br>约束：race 只用于 route、respond、reject、predefined，需要 match_response，与 speculative 冲突<br>约束：匹配逻辑同路由规则，地址项还含 ip_accept_any<br>约束：响应匹配字段需要 match_response 和前置 evaluate |
| `action` | 参阅 规则动作。 |  | 有 |  | 部分 | 未测 | 取值：`evaluate`、`predefined`、`reject`、`respond`、`route`、`route-options`<br>约束：必填 |
| `auth-user` | 认证用户名，参阅入站设置。 |  | 有 |  | 未实现 | 未测 |  |
| `clash-mode` | 匹配 Clash 模式。 |  | 有 |  | 未实现 | 未测 |  |
| `client-subnet` | 已移动到 DNS 规则动作. |  | 废弃 |  | 不适用 | 未测 |  |
| `default-interface-address` | 匹配默认接口地址。 |  | 有 |  | 未实现 | 未测 | 约束：仅支持 Linux、Windows 和 macOS.<br>约束：自 sing-box 1.13.0 起 |
| `disable-cache` | 已移动到 DNS 规则动作. |  | 废弃 |  | 不适用 | 未测 |  |
| `dns-search-domain` | 匹配指定 DNS 服务器的搜索域。 |  | 有 |  | 未实现 | 未测 | 取值：`dhcp`、`local`、`openconnect`、`openvpn`、`resolved`、`tailscale`<br>约束：自 sing-box 1.15.0 起 |
| `dns-server-address` | 匹配指定 DNS 服务器的服务器地址。 |  | 有 |  | 未实现 | 未测 | 取值：`dhcp`、`local`、`openconnect`、`openvpn`、`resolved`、`tailscale`<br>约束：自 sing-box 1.15.0 起 |
| `domain` | 匹配完整域名。 |  | 有 |  | 部分 | 未测 |  |
| `domain-keyword` | 匹配域名关键字。 |  | 有 |  | 部分 | 未测 |  |
| `domain-regex` | 匹配域名正则表达式。 |  | 有 |  | 部分 | 未测 |  |
| `domain-suffix` | 匹配域名后缀。 |  | 有 |  | 部分 | 未测 |  |
| `geoip` | 与查询响应匹配 GeoIP。 |  | 已移除 |  | 不适用 | 未测 | 约束：GeoIP 已在 sing-box 1.8.0 废弃且在 sing-box 1.12.0 中被移除，参阅 迁移指南。 |
| `geosite` | 匹配 Geosite。 |  | 已移除 |  | 不适用 | 未测 | 约束：GeoSite 已在 sing-box 1.8.0 废弃且在 sing-box 1.12.0 中被移除，参阅 迁移指南。 |
| `inbound` | 入站 标签. |  | 有 |  | 未实现 | 未测 |  |
| `interface-address` | 匹配接口地址。 |  | 有 |  | 未实现 | 未测 | 约束：仅支持 Linux、Windows 和 macOS.<br>约束：自 sing-box 1.13.0 起 |
| `invert` | 反选匹配结果。 |  | 有 |  | 部分 | 未测 |  |
| `ip-accept-any` | 当 DNS 查询响应包含至少一个地址时匹配。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.12.0 起 |
| `ip-cidr` | 与查询响应匹配 IP CIDR。 |  | 有 |  | 未实现 | 未测 | 约束：不带 match_response 时属于旧版地址过滤字段，已废弃，1.16.0 移除<br>约束：作为旧版地址筛选字段已废弃。<br>约束：自 sing-box 1.9.0 起 |
| `ip-is-private` | 与查询响应匹配非公开 IP。 |  | 有 |  | 未实现 | 未测 | 约束：不带 match_response 时属于旧版地址过滤字段，已废弃，1.16.0 移除<br>约束：作为旧版地址筛选字段已废弃。<br>约束：自 sing-box 1.9.0 起 |
| `ip-version` | 4 (A DNS 查询) 或 6 (AAAA DNS 查询)。 |  | 有 |  | 未实现 | 未测 | 取值：`4`、`6`<br>约束：在 DNS 规则中设置此字段后，该 DNS 规则在同一 DNS 配置中不能与旧版地址筛选字段 (DNS 规则)、旧版 DNS 规则动作 `strategy` 选项，或旧版 `rule_set_ip_cidr_accept_empty` DNS 规则项共存。<br>约束：默认不限制。 |
| `logical-mode` | `and` 或 `or` |  | 有 |  | 未实现 | 未测 | 取值：`and`、`or`<br>约束：必填 |
| `logical-rules` | 包括的规则。 |  | 有 |  | 未实现 | 未测 | 约束：必填 |
| `logical-type` | 逻辑规则类型，固定为 logical |  | 有 |  | 未实现 | 未测 | 取值：`logical` |
| `match-response` | 启用响应匹配。 |  | 有 |  | 未实现 | 未测 | 约束：启用后，此规则将匹配已评估的响应（由前序 `evaluate` 动作设置），而不仅是匹配原始查询。<br>约束：响应匹配字段（`response_rcode`、`response_answer`、`response_ns`、`response_extra`）需要此选项。<br>约束：当与 `evaluate` 或响应匹配字段一起使用时，`ip_cidr`、`ip_is_private` 和 `ip_accept_any` 也需要此选项。<br>约束：自 sing-box 1.14.0 起 |
| `network` | `tcp` 或 `udp`。 |  | 有 |  | 未实现 | 未测 | 取值：`tcp`、`udp` |
| `network-interface-address` | 匹配网络接口（可用值同 `network_type`）地址。 |  | 有 |  | 未实现 | 未测 | 约束：仅在 Android 与 Apple 平台图形客户端中支持。<br>约束：自 sing-box 1.13.0 起 |
| `network-is-constrained` | 匹配如果网络在低数据模式下。 |  | 有 |  | 未实现 | 未测 | 约束：仅在 Apple 平台图形客户端中支持。<br>约束：自 sing-box 1.11.0 起 |
| `network-is-expensive` | 匹配如果网络被视为计费 (在 Android) 或被视为昂贵，像蜂窝网络或个人热点 (在 Apple 平台)。 |  | 有 |  | 未实现 | 未测 | 约束：仅在 Android 与 Apple 平台图形客户端中支持。<br>约束：自 sing-box 1.11.0 起 |
| `network-type` | 匹配网络类型。 |  | 有 |  | 未实现 | 未测 | 取值：`cellular`、`ethernet`、`other`、`wifi`<br>约束：仅在 Android 与 Apple 平台图形客户端中支持。<br>约束：自 sing-box 1.11.0 起 |
| `outbound` | 匹配出站。 |  | 废弃 |  | 不适用 | 未测 | 约束：`outbound` 规则项已废弃且将在 sing-box 1.14.0 中被移除，参阅 迁移指南。 |
| `package-name` | 匹配 Android 应用包名。 |  | 有 |  | 未实现 | 未测 |  |
| `package-name-regex` | 使用正则表达式匹配 Android 应用包名。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `port` | 匹配端口。 |  | 有 |  | 未实现 | 未测 |  |
| `port-range` | 匹配端口范围。 |  | 有 |  | 未实现 | 未测 |  |
| `preferred-by` | 匹配指定 DNS 服务器的首选域名。 |  | 有 |  | 未实现 | 未测 | 取值：`hosts`、`local`、`mdns`、`openconnect`、`resolved`、`tailscale`<br>约束：自 sing-box 1.14.0 起 |
| `process-name` | 匹配进程名称。 |  | 有 |  | 未实现 | 未测 | 约束：仅支持 Linux、Windows 和 macOS. |
| `process-path` | 匹配进程路径。 |  | 有 |  | 未实现 | 未测 | 约束：仅支持 Linux、Windows 和 macOS. |
| `process-path-regex` | 使用正则表达式匹配进程路径。 |  | 有 |  | 未实现 | 未测 | 约束：仅支持 Linux、Windows 和 macOS.<br>约束：自 sing-box 1.10.0 起 |
| `protocol` | 探测到的协议, 参阅 协议探测。 |  | 有 |  | 未实现 | 未测 | 取值：`bittorrent`、`dns`、`dtls`、`http`、`ntp`、`quic`、`rdp`、`ssh`、`stun`、`tls` |
| `query-client-subnet` | 匹配查询中的 `edns0-subnet` OPT 附加记录（EDNS 客户端子网）。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `query-dnssec` | 匹配设置了 DNSSEC OK (`DO`) 位的查询。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `query-type` | DNS 查询类型。 |  | 有 |  | 部分 | 未测 | 约束：取值为整数或类型名字符串，如 A、HTTPS、32768<br>约束：在 DNS 规则中设置此字段后，该 DNS 规则在同一 DNS 配置中不能与旧版地址筛选字段 (DNS 规则)、旧版 DNS 规则动作 `strategy` 选项，或旧版 `rule_set_ip_cidr_accept_empty` DNS 规则项共存。 |
| `response-answer` | 匹配 DNS 应答记录。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `response-extra` | 匹配 DNS 额外记录。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `response-ns` | 匹配 DNS 名称服务器记录。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `response-rcode` | 匹配 DNS 响应码。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `rewrite-ttl` | 已移动到 DNS 规则动作. |  | 废弃 |  | 不适用 | 未测 |  |
| `rule-set` | 匹配规则集。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.8.0 起 |
| `rule-set-ip-cidr-accept-empty` | 使规则集中的 `ip_cidr` 规则接受空查询响应。 |  | 废弃 |  | 不适用 | 未测 | 约束：`rule_set_ip_cidr_accept_empty` 已废弃且将在 sing-box 1.16.0 中被移除，参阅迁移指南。<br>约束：自 sing-box 1.10.0 起 |
| `rule-set-ip-cidr-match-source` | 使规则集中的 `ip_cidr` 规则匹配源 IP。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.10.0 起 |
| `rule-set-ipcidr-match-source` | 使规则集中的 `ip_cidr` 规则匹配源 IP。 |  | 已移除 |  | 不适用 | 未测 | 约束：`rule_set_ipcidr_match_source` 已重命名为 `rule_set_ip_cidr_match_source` 且将在 sing-box 1.11.0 中被移除。<br>约束：自 sing-box 1.9.0 起 |
| `server` | 已移动到 DNS 规则动作. |  | 废弃 |  | 不适用 | 未测 |  |
| `source-geoip` | 匹配源 GeoIP。 |  | 已移除 |  | 不适用 | 未测 | 约束：GeoIP 已在 sing-box 1.8.0 废弃且在 sing-box 1.12.0 中被移除，参阅 迁移指南。 |
| `source-hostname` | 匹配源设备从 DHCP 租约获取的主机名。 |  | 有 |  | 未实现 | 未测 | 约束：仅支持 Linux、macOS，或在 Android 和 macOS 图形客户端中支持。<br>约束：自 sing-box 1.14.0 起 |
| `source-ip-cidr` | 匹配源 IP CIDR。 |  | 有 |  | 未实现 | 未测 |  |
| `source-ip-is-private` | 匹配非公开源 IP。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.8.0 起 |
| `source-mac-address` | 匹配源设备 MAC 地址。 |  | 有 |  | 未实现 | 未测 | 约束：仅支持 Linux、macOS，或在 Android 和 macOS 图形客户端中支持。<br>约束：自 sing-box 1.14.0 起 |
| `source-port` | 匹配源端口。 |  | 有 |  | 未实现 | 未测 |  |
| `source-port-range` | 匹配源端口范围。 |  | 有 |  | 未实现 | 未测 |  |
| `user` | 匹配用户名。 |  | 有 |  | 未实现 | 未测 | 约束：仅支持 Linux。 |
| `user-id` | 匹配用户 ID。 |  | 有 |  | 未实现 | 未测 | 约束：仅支持 Linux。 |
| `wifi-bssid` | 匹配 WiFi BSSID。 |  | 有 |  | 未实现 | 未测 | 约束：仅在 Android 与 Apple 平台图形客户端和 Linux 中支持。 |
| `wifi-ssid` | 匹配 WiFi SSID。 |  | 有 |  | 未实现 | 未测 | 约束：仅在 Android 与 Apple 平台图形客户端和 Linux 中支持。 |

## server

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | DNS 上游类型和拨号方式组合 |  | 有 |  | 部分 | 通过 | type：`dhcp`、`fakeip`、`h3`、`hosts`、`https`、`local`、`mdns`、`openconnect`、`openvpn`、`quic`、`resolved`、`tailscale`、`tcp`、`tls`、`udp`<br>dial：`bind_interface`、`detour`、`direct-default`、`domain_resolver`<br>tls_config：`h3`、`https`、`quic`、`tls`<br>server_name_kind：`domain`、`ip`<br>约束：dhcp 需要 with_dhcp；quic、h3 需要 with_quic<br>约束：fakeip 配 inet4_range、inet6_range；缓存见 store_fakeip<br>约束：server 用域名时必须配 domain_resolver<br>约束：tailscale、openconnect、openvpn 的 endpoint 必填，resolved 的 service 必填<br>约束：新格式默认走空 direct 拨号，不再默认走默认出站 |
| `address` | 服务器地址，形式同 upstream |  |  | 有 | 部分 | 通过 |  |
| `client-ip` | 覆盖全局同名配置 |  |  | 有 | 未实现 | 未测 |  |
| `disable-cache` | 覆盖全局同名配置 |  |  | 有 | 未实现 | 未测 |  |
| `domains` | 优先用此服务器的域名 |  |  | 有 | 部分 | 未测 | 约束：格式同路由 domain |
| `expect-ips` | expectedIPs 旧名 |  |  | 有 | 不适用 | 未测 | 约束：docs/config/fakedns.md 示例仍在用 |
| `expected-ips` | 校验返回 IP，只保留列表内 |  |  | 有 | 未实现 | 未测 | 取值：`*`、`geoip:cn`<br>约束：含 * 时过滤后为空仍返回原 IP |
| `final-query` | 最终尝试，不触发 fallback |  |  | 有 | 未实现 | 未测 |  |
| `id` | 服务器标识，供 Lua serverObj.ID |  |  | 有 | 未实现 | 未测 |  |
| `port` | 端口，默认 53 |  |  | 有 | 已实现 | 通过 | 约束：DoH、DoHL、DoQL 无效 |
| `query-strategy` | 子项策略，继承全局 |  |  | 有 | 未实现 | 未测 | 取值：`UseIP`、`UseIPv4`、`UseIPv6`、`UseSystem`<br>约束：受全局约束 |
| `serve-expired-ttl` | 覆盖全局同名配置 |  |  | 有 | 未实现 | 未测 |  |
| `serve-stale` | 覆盖全局同名配置 |  |  | 有 | 未实现 | 未测 |  |
| `skip-fallback` | fallback 时跳过 |  |  | 有 | 未实现 | 未测 |  |
| `tag` | 覆盖全局同名配置 |  |  | 有 | 未实现 | 未测 |  |
| `timeout-ms` | 超时，默认 4000 |  |  | 有 | 未实现 | 未测 | 约束：对 localhost 无效 |
| `unexpected-ips` | 去掉列表内 IP |  |  | 有 | 未实现 | 未测 | 取值：`*`、`geoip:cloudflare` |

## server-common

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `tag` | DNS 服务器的标签。 |  | 有 |  | 已实现 | 通过 |  |
| `type` | DNS 服务器的类型。 |  | 有 |  | 部分 | 通过 | 取值：`dhcp`、`fakeip`、`h3`、`hosts`、`https`、`local`、`mdns`、`openconnect`、`openvpn`、`quic`、`resolved`、`tailscale`、`tcp`、`tls`、`udp` |

## server-dhcp

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | DHCP 取得的 DNS 上游 |  | 有 |  | 未实现 | 未测 | 取值：`dhcp`<br>约束：需要 with_dhcp 构建标签 |
| `interface` | 要监听的网络接口名称。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.12.0 起<br>约束：默认使用默认接口。 |

## server-fakeip

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | FakeIP 上游 |  | 有 |  | 已实现 | 通过 | 取值：`fakeip` |
| `inet4-range` | FakeIP 的 IPv4 地址范围。 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.12.0 起 |
| `inet6-range` | FakeIP 的 IPv6 地址范围。 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.12.0 起 |

## server-hosts

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | hosts 文件和预定义记录 上游 |  | 有 |  | 部分 | 通过 | 取值：`hosts` |
| `path` | hosts 文件路径列表。 |  | 有 |  | 未实现 | 未测 | 约束：在 Windows 上默认使用 `C:\Windows\System32\Drivers\etc\hosts`。<br>约束：自 sing-box 1.12.0 起<br>约束：默认使用 `/etc/hosts`。 |
| `predefined` | 预定义的 hosts。 |  | 有 |  | 部分 | 通过 | 约束：自 sing-box 1.12.0 起 |

## server-http3

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | DoH3 上游 |  | 有 |  | 未实现 | 未测 | 取值：`h3`<br>约束：需要 with_quic 构建标签 |
| `headers` | 发送到 DNS 服务器的额外标头。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.12.0 起 |
| `path` | DNS 服务器的路径。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.12.0 起<br>约束：默认使用 `/dns-query`。 |
| `server` | DNS 服务器的地址。 |  | 有 |  | 未实现 | 未测 | 约束：如果使用域名，还必须设置 `domain_resolver` 来解析 IP 地址。<br>约束：必填<br>约束：自 sing-box 1.12.0 起 |
| `server-port` | DNS 服务器的端口。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.12.0 起<br>约束：默认使用 `443`。 |
| `tls` | TLS 配置，参阅 TLS。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.12.0 起 |

## server-https

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | DoH 上游 |  | 有 |  | 部分 | 未测 | 取值：`https` |
| `headers` | 发送到 DNS 服务器的额外标头。 |  | 有 |  | 部分 | 未测 | 约束：自 sing-box 1.12.0 起 |
| `path` | DNS 服务器的路径。 |  | 有 |  | 部分 | 未测 | 约束：自 sing-box 1.12.0 起<br>约束：默认使用 `/dns-query`。 |
| `server` | DNS 服务器的地址。 |  | 有 |  | 部分 | 未测 | 约束：如果使用域名，还必须设置 `domain_resolver` 来解析 IP 地址。<br>约束：必填<br>约束：自 sing-box 1.12.0 起 |
| `server-port` | DNS 服务器的端口。 |  | 有 |  | 部分 | 未测 | 约束：自 sing-box 1.12.0 起<br>约束：默认使用 `443`。 |
| `tls` | TLS 配置，参阅 TLS。 |  | 有 |  | 部分 | 未测 | 约束：自 sing-box 1.12.0 起 |

## server-legacy

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | 旧版 DNS 服务器地址格式 |  | 已移除 |  | 不适用 | 未测 | 约束：1.12.0 废弃，1.14.0 移除；配置后启动报错（source:option/dns.go） |
| `address` | DNS 服务器的地址。 |  | 已移除 |  | 不适用 | 未测 | 取值：`dhcp://`、`fakeip`、`h3://`、`https://`、`local`、`quic://`、`rcode://`、`tcp://`、`tls://`、`udp://`<br>约束：为了确保 Android 系统 DNS 生效，而不是 Go 的内置默认解析器，请在编译时启用 CGO。<br>约束：必填 |
| `address-resolver` | 用于解析本 DNS 服务器的域名的另一个 DNS 服务器的标签。 |  | 已移除 |  | 不适用 | 未测 | 约束：如果服务器地址包括域名则必须 |
| `address-strategy` | 用于解析本 DNS 服务器的域名的策略。 |  | 已移除 |  | 不适用 | 未测 | 取值：`ipv4_only`、`ipv6_only`、`prefer_ipv4`、`prefer_ipv6`<br>约束：默认使用 `dns.strategy`。 |
| `client-subnet` | 默认情况下，将带有指定 IP 前缀的 `edns0-subnet` OPT 附加记录附加到每个查询。 |  | 已移除 |  | 不适用 | 未测 | 约束：自 sing-box 1.9.0 起 |
| `detour` | 用于连接到 DNS 服务器的出站的标签。 |  | 已移除 |  | 不适用 | 未测 | 约束：如果为空，将使用默认出站。 |
| `strategy` | 默认解析策略。 |  | 已移除 |  | 不适用 | 未测 | 取值：`ipv4_only`、`ipv6_only`、`prefer_ipv4`、`prefer_ipv6` |
| `tag` | DNS 服务器的标签。 |  | 已移除 |  | 不适用 | 未测 |  |

## server-local

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | 系统 DNS 上游 |  | 有 |  | 部分 | 通过 | 取值：`local` |
| `neighbor-domain` | 用于从邻居解析器而非上游回答 A/AAAA 查询的域后缀列表。 |  | 有 |  | 未实现 | 未测 | 约束：仅匹配后缀之前的主机名部分不包含点的查询；<br>约束：每一项必须以 `.` 开头。<br>约束：自 sing-box 1.14.0 起 |
| `prefer-go` | 启用后，`local` DNS 服务器将尽可能通过拨号自身来解析 DNS。 |  | 有 |  | 未实现 | 未测 | 约束：在运行 Android 10 以下版本的设备上，此接口只能解析 A/AAAA 请求。<br>约束：自 sing-box 1.13.0 起 |

## server-mdns

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | mDNS 上游 |  | 有 |  | 未实现 | 未测 | 取值：`mdns` |
| `interface` | 用于发送 mDNS 查询的网络接口名称列表。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |

## server-openconnect

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | OpenConnect 推送 DNS 上游 |  | 有 |  | 未实现 | 未测 | 取值：`openconnect` |
| `accept-default-resolvers` | 接受 VPN 服务器推送的通用解析器，用于未匹配的查询。 |  | 有 |  | 未实现 | 未测 | 约束：启用时，仅当服务器要求所有 DNS 通过隧道，或未提供分流 DNS 规则及后缀时，通用解析器才会作为默认解析器。<br>约束：自 sing-box 1.14.0 起 |
| `accept-search-domain` | 启用且存在推送的搜索域时，单标签查询（例如 `intranet`）会依次附加各个搜索域进行重试，直到其中一个解析成功。 |  | 有 |  | 未实现 | 未测 | 约束：如果所有搜索域扩展均返回 `NXDOMAIN`，原始未限定名称将按普通默认解析器行为处理。<br>约束：自 sing-box 1.14.0 起 |
| `endpoint` | OpenConnect 端点 的标签。 |  | 有 |  | 未实现 | 未测 | 约束：必填<br>约束：自 sing-box 1.14.0 起 |

## server-openvpn

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | OpenVPN 推送 DNS 上游 |  | 有 |  | 未实现 | 未测 | 取值：`openvpn` |
| `accept-default-resolvers` | 对未匹配推送的 `resolve-domains`、`DOMAIN-ROUTE` 或搜索域后缀的查询使用推送解析器。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `accept-search-domain` | 启用且存在推送的搜索域时，单标签查询（例如 `intranet`）会依次附加各个搜索域重试，直到其中一个解析成功。 |  | 有 |  | 未实现 | 未测 | 约束：不存在搜索域时，原始单标签查询按普通默认解析器规则处理。<br>约束：自 sing-box 1.14.0 起 |
| `endpoint` | OpenVPN 客户端端点 的标签。 |  | 有 |  | 未实现 | 未测 | 约束：不支持 `dnssec yes`。<br>约束：必填<br>约束：自 sing-box 1.14.0 起 |

## server-quic

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | DoQ 上游 |  | 有 |  | 未实现 | 未测 | 取值：`quic`<br>约束：需要 with_quic 构建标签 |
| `server` | DNS 服务器的地址。 |  | 有 |  | 未实现 | 未测 | 约束：如果使用域名，还必须设置 `domain_resolver` 来解析 IP 地址。<br>约束：必填<br>约束：自 sing-box 1.12.0 起 |
| `server-port` | DNS 服务器的端口。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.12.0 起<br>约束：默认使用 `853`。 |
| `tls` | TLS 配置，参阅 TLS。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.12.0 起 |

## server-resolved

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | systemd-resolved 服务提供的 DNS 上游 |  | 有 |  | 未实现 | 未测 | 取值：`resolved` |
| `accept-default-resolvers` | 指示是否除了匹配域名外，还应接受默认 DNS 解析器以进行回退查询。 |  | 有 |  | 未实现 | 未测 | 约束：具体来说，默认 DNS 解析器是设置了 `SetLinkDefaultRoute` 或 `SetLinkDomains ~.` 的 DNS 服务器。<br>约束：自 sing-box 1.12.0 起 |
| `attempts` | resolved 服务器重试次数，文档未列 |  | 有 |  | 未实现 | 未测 |  |
| `rotate` | resolved 服务器轮换上游，文档未列 |  | 有 |  | 未实现 | 未测 |  |
| `service` | Resolved 服务 的标签。 |  | 有 |  | 未实现 | 未测 | 约束：必填<br>约束：自 sing-box 1.12.0 起 |

## server-tailscale

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | Tailscale MagicDNS 上游 |  | 有 |  | 未实现 | 未测 | 取值：`tailscale` |
| `accept-default-resolvers` | 指示是否除了 MagicDNS 外，还应接受默认 DNS 解析器以进行回退查询。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.12.0 起 |
| `accept-search-domain` | 启用后，单标签查询（例如 `my-device`）将依次附加 Tailscale 搜索域进行重试，直到其中一个解析成功。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `endpoint` | Tailscale 端点 的标签。 |  | 有 |  | 未实现 | 未测 | 约束：必填<br>约束：自 sing-box 1.12.0 起 |

## server-tcp

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | DNS over TCP 上游 |  | 有 |  | 已实现 | 通过 | 取值：`tcp` |
| `server` | DNS 服务器的地址。 |  | 有 |  | 部分 | 通过 | 约束：如果使用域名，还必须设置 `domain_resolver` 来解析 IP 地址。<br>约束：必填<br>约束：自 sing-box 1.12.0 起 |
| `server-port` | DNS 服务器的端口。 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.12.0 起<br>约束：默认使用 `53`。 |

## server-tls

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | DoT 上游 |  | 有 |  | 已实现 | 通过 | 取值：`tls` |
| `server` | DNS 服务器的地址。 |  | 有 |  | 部分 | 通过 | 约束：如果使用域名，还必须设置 `domain_resolver` 来解析 IP 地址。<br>约束：必填<br>约束：自 sing-box 1.12.0 起 |
| `server-port` | DNS 服务器的端口。 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.12.0 起<br>约束：默认使用 `853`。 |
| `tls` | TLS 配置，参阅 TLS。 |  | 有 |  | 部分 | 通过 | 约束：自 sing-box 1.12.0 起 |

## server-udp

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | DNS over UDP 上游 |  | 有 |  | 已实现 | 通过 | 取值：`udp` |
| `server` | DNS 服务器的地址。 |  | 有 |  | 部分 | 通过 | 约束：如果使用域名，还必须设置 `domain_resolver` 来解析 IP 地址。<br>约束：必填<br>约束：自 sing-box 1.12.0 起 |
| `server-port` | DNS 服务器的端口。 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.12.0 起<br>约束：默认使用 `53`。 |

## upstream

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `dhcp` | DHCP 上游 | 有 |  |  | 未实现 | 未测 | 取值：`dhcp://en0`、`dhcp://system`<br>约束：dhcp://system 仅限 cmfa |
| `doh` | DNS over HTTPS | 有 |  |  | 部分 | 未测 | 取值：`https://doh.pub/dns-query` |
| `doh3` | HTTP/3 的 DoH，由 h3 附加参数或 prefer-h3 开启 | 有 |  |  | 未实现 | 未测 | 取值：`https://host/dns-query#h3=true` |
| `doq` | DNS over QUIC | 有 |  |  | 未实现 | 未测 | 取值：`quic://dns.adguard.com:784` |
| `dot` | DNS over TLS | 有 |  |  | 已实现 | 通过 | 取值：`tls://1.1.1.1` |
| `easytier` | 解析 EasyTier 出站 overlay 的 A/PTR 记录 | 有 |  |  | 未实现 | 未测 | 取值：`et://easytier`<br>约束：建议放在 nameserver-policy |
| `rcode` | 直接返回指定 rcode | 有 |  |  | 未实现 | 未测 | 取值：`rcode://format_error`、`rcode://name_error`、`rcode://not_implemented`、`rcode://refused`、`rcode://server_failure`、`rcode://success` |
| `system` | 系统 DNS | 有 |  |  | 部分 | 通过 | 取值：`system`、`system://` |
| `tailscale` | 用指定 Tailscale 出站的 DNS 配置查询 | 有 |  |  | 未实现 | 未测 | 取值：`ts://tailscale`<br>约束：source:config/config.go 同时接受 tailscale:// 协议名 |
| `tcp` | TCP DNS | 有 |  | 有 | 已实现 | 通过 | 取值：`tcp://8.8.8.8`、`tcp://8.8.8.8:53`<br>约束：默认 53 |
| `udp` | UDP DNS | 有 |  | 有 | 已实现 | 通过 | 取值：`223.5.5.5`、`8.8.8.8`、`8.8.8.8:53`、`udp://223.5.5.5`<br>约束：默认 53 |
| `combo` | DNS 上游类型与附加参数的维度 | 有 |  | 有 | 部分 | 通过 | scheme：`dhcp`、`et`、`https`、`quic`、`rcode`、`system`、`tcp`、`tls`、`ts`、`udp`<br>section：`default-nameserver`、`direct-nameserver`、`fallback`、`nameserver`、`nameserver-policy`、`proxy-server-nameserver`、`proxy-server-nameserver-policy`<br>param：`#RULES`、`#interface`、`#proxy`、`disable-ipv4`、`disable-ipv6`、`disable-qtype-<int>`、`ecs`、`ecs-override`、`h3`、`name-cert-verify`、`skip-cert-verify`<br>enhanced-mode：`fake-ip`、`redir-host`<br>约束：default-nameserver 必须为 IP<br>约束：dhcp://system 仅限 cmfa<br>约束：et:// 仅解析 overlay A/PTR<br>约束：h3 仅对 DoH<br>约束：respect-rules 需 proxy-server-nameserver<br>upstream：`fakedns`、`h2c`、`h2c+local`、`https`、`https+local`、`localhost`、`quic+local`、`tcp`、`tcp+local`、`udp`<br>route：`local`、`routing`<br>query_strategy：`UseIP`、`UseIPv4`、`UseIPv6`、`UseSystem`<br>fallback：`default`、`disableFallback`、`disableFallbackIfMatch`、`finalQuery`、`parallel`、`skipFallback`<br>filter：`expectedIPs`、`none`、`unexpectedIPs`<br>ecs：`clientIp`、`off`<br>cache：`default`、`disableCache`、`serveStale`<br>约束：+local 不进路由；其他进路由，tag 可匹配 inboundTag<br>约束：FakeDNS 需 sniffing fakedns<br>约束：port 对 DoH、DoHL、DoQL 无效<br>约束：serveStale 受 disableCache 约束<br>约束：全局 queryStrategy 优先，子项冲突得空响应<br>约束：文档未列 DoT、DHCP、远程 quic://<br>约束：非 local 请求跳过 IPIfNonMatch、IPOnDemand 解析 |
| `fakedns` | FakeDNS |  |  | 有 | 已实现 | 通过 | 取值：`fakedns` |
| `h2c` | DoH 明文 h2c |  |  | 有 | 未实现 | 未测 | 取值：`h2c://dns.google/dns-query`<br>约束：需 Freedom+streamSettings TLS 包装 |
| `h2c-local` | h2c 本地模式，文档未写 |  |  | 有 | 未实现 | 未测 | 取值：`h2c+local://` |
| `https` | DoH，遵循路由 |  |  | 有 | 未实现 | 未测 | 取值：`https://1.1.1.1/dns-query`、`https://a.b.c.d:8443/my-dns-query`、`https://dns.google/dns-query` |
| `https-local` | DoH 本地模式 |  |  | 有 | 未实现 | 未测 | 取值：`https+local://dns.google/dns-query` |
| `localhost` | 本机 DNS |  |  | 有 | 部分 | 通过 | 取值：`localhost`<br>约束：disableCache 和 timeoutMs 对其无效<br>约束：请求不受 Xray 控制 |
| `quic-local` | DoQ 本地模式 |  |  | 有 | 未实现 | 未测 | 取值：`quic+local://dns.adguard.com`<br>约束：只有 local 形式<br>约束：默认 853 |
| `tcp-local` | TCP 本地模式，直走 Freedom |  |  | 有 | 已实现 | 通过 | 取值：`tcp+local://8.8.8.8:53`<br>约束：默认 53 |
