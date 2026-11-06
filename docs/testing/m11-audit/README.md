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
| OpenVPN 客户端证书 | `with_no_client_auth()`，`ca`、`crl`、指纹、EKU 等全部不生效；缺证书静默改用自签；所有客户端分到同一地址 `10.8.0.2` | M | 待做 |
| 路由未实现条件 | `in_port`、`in_type`、`dscp`、`uid` 不参与匹配，带这些条件的规则匹配全部流量 | S | 已改为编译期拒绝；真实匹配待做 |
| SIP003 插件降级 | 未实现的插件或选项静默改为明文 TCP | S | 已修复：未实现的插件与参数编译期拒绝，v2ray-plugin WebSocket 与 obfs http 改为真实实现；未与真实插件互通 |
| 密钥生成 | `mldsa65`、`mlkem768`、`vlessenc` 输出 SHA-256 填充，不是真实密钥 | S | 已修复：真实 ML-KEM-768、ML-DSA-65；Hash32 改为 BLAKE3，未与 Xray 源码核对 |
| `cache.db` 覆盖 | 选中节点持久化与 Fake-IP 持久化写同一默认路径 | S | 已修复：单一持有者分区写入；旧格式 Fake-IP 记录不再读取 |

### 已发布功能的空壳

| 单元 | 问题 | 规模 | 状态 |
| --- | --- | --- | --- |
| 健康检查与测速 | 测速记录常量 12/15 ms；没有后台健康检查；url-test、fallback、least-ping 无真实数据 | L | 已修复：经出站发 HEAD 实测，按 `interval` 后台检查；HTTPS 探测未对真实 TLS 服务验证 |
| 配置热重载 | `SIGHUP`、`PUT/PATCH /configs`、`/restart` 只校验不应用 | L | 已修复 `SIGHUP`、`PUT /configs`、`/restart`；`PATCH /configs` 仍只记日志 |
| HTTP 下载器 | http 订阅、远程规则集、Geo 自动更新只读本地文件 | L | 已修复：经出站下载、ETag、失败沿用缓存、运行中刷新；订阅成员变化时重建引擎；Geo 文件下载后运行时仍用内置表；HTTPS 与 gzip 未对真实服务验证 |
| 连接表 | 见下 | M | 已修复：`/connections` 列出真实流量并可断开，`interrupt-exist-connections` 生效，`/rules`、`/memory`、`/dns/query` 用真实数据；无 WebSocket 推送 |
| OpenVPN 服务端 | 见下 | M | 已修复：客户端证书、地址池、推送、NCP、换钥、tls-crypt-v2，官方客户端 10 个互通用例通过；`static_key` 模式改为拒绝；出站 tls-crypt-v2 的 WKc 长度读错位置已改正 |
| Mihomo YAML 直通 | 见下 | M | 进行中 |
| DNS 管线 | 本地出网解析只用 hosts 与第一个 UDP/TCP/DoT 上游；DNS 规则、DoH、Fake-IP 只作用于劫持的报文；无 DoQ、乐观缓存、ECS；`dns.listen` 不监听；`detour` 不生效 | L | 待做 |
| 规则集与 Geo 格式 | `.srs`/`.mrs` 是私有格式，真实文件返回空集；运行时 GeoIP/GeoSite 是内置小表 | L | 待做 |
| 路由解析 IP | `resolved_ips` 恒为空，`resolve` 动作后 IP/GeoIP 规则不匹配域名目标 | M | 待做 |
| 连接表 | `register_active_connection` 无调用者，`/connections` 恒空，断开与 `interrupt-exist-connections` 无效 | M | 待做 |
| 日志管线与 WebSocket | 日志级别与输出不生效；控制面没有 WebSocket 端点 | M | 待做 |
| 控制面伪数据 | `/dns/query` 返回固定地址，`/memory` 常量，`/rules` 占位，`tools` 子命令输出固定 JSON | M | 待做 |
| 环境变量与 NTP | 环境变量收集后丢弃；NTP 校准无调用者 | M | 待做 |
| ACME | 生成自签证书，不走 ACME 协议 | L | 待做 |
| 服务端 ECH | 只检查 `ech_key` 非空 | L | 待做 |
| Mihomo YAML 直通 | 只改名 `name`/`type`，选项按 kerlico 原生格式解析，例如 ss 需要 `method` 而 Mihomo 写 `cipher` | M | 待做 |
| sing-mux 线格式 | h2mux 不是 HTTP/2，yamux 不处理窗口更新，padding 与上游不同；只有自测 | L | 待做 |
| 拨号选项覆盖 | `detour`、`routing_mark`、TFO 等只在 ss、trojan、vless、vmess 的 TCP 路径生效 | M | 待做 |
| TUN 自动化 | `strict-route`、`auto-redirect`、出口防回环、IPv6 默认路由未生效 | L | 待做 |
| TProxy UDP | 未取原始目标地址 | M | 待做 |
| VLESS Reverse | 出站不向服务端注册隧道 | M | 待做 |
| Hysteria2 | 上行带宽丢弃，无 Brutal；masquerade `proxy` 不访问上游 | M | 待做 |
| OpenVPN 服务端字段 | 多数字段解析后不读，`PUSH_REPLY` 为固定字符串 | M | 待做 |
| 其余 | MASQUE 服务端地址池、EasyTier `secure-mode`、XHTTP 服务端字段、全局信任库、嗅探覆盖入站、用户标签等 | S–M | 待做 |

## 处理规则

- 每个单元要么做成真实实现并带断言行为的测试，要么把能力总表降为真实状态（`partial` 或 `no`）并改写说明。
- 修复在 worker 上验证后合入；能力总表的 `results` 按测试名回填。
- 已发布标签不改写；更正写入新版本发行说明。
