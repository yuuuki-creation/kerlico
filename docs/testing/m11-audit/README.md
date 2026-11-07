# M11 已实现项审计（2026-11-06）

能力总表中标为“已实现”或“部分实现”的 2,080 项，逐项对照代码重新判定。逐项结果在 [audit.jsonl](audit.jsonl)，每行字段为 `key`、`claim`（原标注）、`verdict`、`test`（断言该行为的测试，`none` 表示没有）、`evidence`（代码位置）、`fix`。

| 判定 | 项数 | 含义 |
| --- | --- | --- |
| `real` | 1,438 | 运行时行为与标注一致；其中 195 项没有断言该行为的测试 |
| `overclaimed` | 262 | 能用，但比标注或说明窄 |
| `stub` | 335 | 配置能解析，运行时效果是常量、占位、被忽略或只写日志 |
| `missing` | 45 | 没有对应代码 |

审计只读代码，没有运行。原 `results/*.jsonl` 的证据多为“单元与集成测试（tools/worker_gate.sh）”，不指向具体测试；M11 起 `pass` 必须写明测试名或互通脚本用例。

## 修复单元

按影响排序。S 小于 1 天，M 为 1 至 3 天，L 大于 3 天。

### 安全与静默错误（先做）

| 单元 | 问题 | 规模 | 状态 |
| --- | --- | --- | --- |
| OpenVPN 默认账号 | 未配用户时自动加入代码内置的固定账号口令；口令按字节比较 | S | 已修复 |
| OpenVPN 客户端证书 | `with_no_client_auth()`，`ca`、`crl`、指纹、EKU 等全部不生效；缺证书静默改用自签；所有客户端分到同一地址 `10.8.0.2` | M | 已修复 |
| 路由未实现条件 | `in_port`、`in_type`、`dscp`、`uid` 不参与匹配，带这些条件的规则匹配全部流量 | S | 已改为编译期拒绝；真实匹配待做 |
| SIP003 插件降级 | 未实现的插件或选项静默改为明文 TCP | S | 已修复：未实现的插件与参数编译期拒绝，v2ray-plugin WebSocket 与 obfs http 改为真实实现；未与真实插件互通 |
| 密钥生成 | `mldsa65`、`mlkem768`、`vlessenc` 输出 SHA-256 填充，不是真实密钥 | S | 已修复：真实 ML-KEM-768、ML-DSA-65；Hash32 改为 BLAKE3，未与 Xray 源码核对 |
| `cache.db` 覆盖 | 选中节点持久化与 Fake-IP 持久化写同一默认路径 | S | 已修复：单一持有者分区写入；旧格式 Fake-IP 记录不再读取 |

### 已发布功能的空壳

| 单元 | 问题 | 规模 | 状态 |
| --- | --- | --- | --- |
| 健康检查与测速 | 测速记录常量 12/15 ms；没有后台健康检查；url-test、fallback、least-ping 无真实数据 | L | 已修复：经出站发 HEAD 实测，按 `interval` 后台检查 |
| 配置热重载 | `SIGHUP`、`PUT/PATCH /configs`、`/restart` 只校验不应用 | L | 已修复：`SIGHUP`、`PUT /configs`、`/restart`；`PATCH /configs` 改 `mode`、`log-level` 就地生效，改端口、`allow-lan`、`tun` 时重建引擎 |
| HTTP 下载器 | http 订阅、远程规则集、Geo 自动更新只读本地文件 | L | 已修复：经出站下载、ETag、失败沿用缓存、运行中刷新；订阅成员变化时重建引擎；Geo 文件下载后运行中无重启替换 |
| 连接表与控制面数据 | `/connections` 恒空，`/dns/query` 固定地址，`/memory` 常量，`/rules` 占位 | M | 已修复：`/connections` 列出真实流量并可断开，`interrupt-exist-connections` 生效，`/rules`（含逐规则 `hitCount`/`hitAt`/`missCount`/`missAt`）、`/memory`、`/dns/query`、`/cache/dns/flush` 全部使用运行时真实数据 |
| OpenVPN 服务端 | 客户端证书、地址池、推送、NCP、换钥、tls-crypt-v2 缺失 | M | 已修复：官方客户端 10 个互通用例通过；`static_key` 模式改为拒绝；出站 tls-crypt-v2 的 WKc 长度读错位置已改正 |
| Mihomo YAML 直通 | 只改名 `name`/`type`，其余按原生格式解析 | M | 已修复：按类型映射字段，顶层、订阅成员与分享链接共用；订阅 `override` 先于字段映射应用；完整正则 `filter` 与中文/emoji/括号名称支持 |
| 能力总表复核 | 已修复单元涉及的键按当前代码复核并写入 `annotations/*.jsonl` 与 `results/*.jsonl` | — | 已完成 |
| DNS 管线 | 本地出网解析只用 hosts 与第一个 UDP/TCP/DoT 上游；DNS 规则、DoH、Fake-IP 只作用于劫持的报文；无 DoQ、乐观缓存、ECS；`dns.listen` 不监听；`detour` 不生效 | L | 已修复：全入口统一管线，支持 UDP/TCP/DoT/DoH/DoQ、乐观缓存、ECS、`fallback-filter`、`dns.listen` 与 `detour` |
| 规则集与 Geo 格式 | `.srs`/`.mrs` 是私有格式，真实文件返回空集；运行时 GeoIP/GeoSite 是内置小表 | L | 已修复：运行时与 CLI 直接读写标准 `.srs`（v1–v4）、`.mrs`（v1）及真实 `geoip.dat`、`geosite.dat`、`country.mmdb`、`ASN.mmdb` |
| 路由解析 IP | `resolved_ips` 恒为空，`resolve` 动作后 IP/GeoIP 规则不匹配域名目标 | M | 已修复：`resolve` 动作及未标 `no-resolve` 的 IP/GeoIP/ASN 规则通过统一 DNS 管线解析域名并匹配 `resolved_ips` |
| 日志管线与 WebSocket | 日志级别与输出不生效；控制面没有 WebSocket 端点；顶层 `mode` 不影响路由 | M | 已修复：进程日志管线（级别、文件输出、时间戳）驱动 `/logs`；`/traffic`、`/memory`、`/logs`、`/connections` WebSocket 推送；`mode` 与 `GLOBAL` 组生效；metacubexd 与 Mihomo v1.19.33 同配置对照通过 |
| sing-mux 线格式 | h2mux 不是 HTTP/2，yamux 不处理窗口更新，padding 与上游不同；只有自测 | L | 已修复：`h2mux`、`smux`、`yamux` 与分帧 padding 与 `sagernet/sing-mux` 双向互通，SS2022 接入 `sing-mux` |
| 拨号选项覆盖 | `detour`、`routing_mark`、TFO 等只在 ss、trojan、vless、vmess 的 TCP 路径生效 | M | 已修复：全部出站与 DNS 上游套接字统一经 `DialerOptions` 工厂创建，覆盖 `detour`、`routing_mark`、`interface_name`、TFO、uTLS `client-fingerprint` 与 `skip-cert-verify` |
| TUN 自动化 | `strict-route`、`auto-redirect`、出口防回环、IPv6 默认路由未生效 | L | 已修复：按 `sing-tun` 布局安装 IPv4/IPv6 路由表、`strict-route`、`auto-redirect`（nftables）、`auto-detect-interface` 与逐出站 `routing-mark` 防回环放行 |
| TProxy UDP 与入站嗅探 | TProxy UDP 未取原始目标地址；嗅探未覆盖全部入站 | M | 已修复：TProxy UDP 用 `IP_RECVORIGDSTADDR`/`IPV6_RECVORIGDSTADDR` 取原始目标并支持 IPv6；全部入站共用调度器嗅探阶段（8 协议 + 多包 QUIC 重组 + `geoip:`/`geosite:`/`rule-set:` 跳过名单） |
| Hysteria2 | 上行带宽丢弃，无 Brutal；masquerade `proxy` 不访问上游 | M | 已修复：`Hysteria-CC-RX` 双向协商，Brutal 为每连接 Quinn 控制器，`ignore_client_bandwidth`；`proxy` 为真实反向代理，支持 `rewrite_host`、`insecure` |
| 其余待做 | ACME 协议签发、服务端 ECH 解密、VLESS Reverse 注册隧道、内置 NTP 后台循环、`tools` 子命令联网探测、MASQUE 服务端地址池、EasyTier `secure-mode`、XHTTP 服务端字段、全局信任库、用户标签等 | S–L | 待做 |

## 处理规则

- 每个单元要么做成真实实现并带断言行为的测试，要么把能力总表降为真实状态（`partial` 或 `no`）并改写说明。
- 修复在 worker 上验证后合入；能力总表的 `results` 按测试名回填。
- 已发布标签不改写；更正写入新版本发行说明。
