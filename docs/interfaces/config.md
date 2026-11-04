# 配置与命令行接口

更新日期：2026-11-02（Asia/Shanghai）

当前源码使用 **配置版本 2（v2）**，同时支持标准 JSON、带单行/多行注释与尾随逗号的 JSONC，以及支持锚点（`&anchor`）、引用（`*alias`）与合并键（`<<:`）的 YAML。旧版 v1 配置迁移方式见 [配置 v2 迁移指南](../config-v2-migration.md)。

## 根配置结构

| 字段 | 约束说明 |
| --- | --- |
| `version` | 必填，固定为 `2`（v1 直接拒绝） |
| `epoch` | 默认 `1`，非零正整数，标识配置代次 |
| `accounts` | 管理账户数组，`user_id` 与 `username` 分别全局唯一 |
| `outbounds` | 命名出站数组（`tag` / `type` / `options`）；支持直接声明内联 `selector` 与 `urltest` 策略组出站 |
| `proxy_groups` | 策略组数组（`select`、`url-test`、`fallback`、`load-balance`、`balancer`），支持 `proxies`、`use`、`filter`/`exclude-filter`/`exclude-type`、`tolerance`、`lazy`、`expected-status`、`hash-key`、`fallback-tag` 与 `store-selected` |
| `proxy_providers` | 外部与内联代理提供者映射（`file`、`http`、`inline`），支持 JSON/YAML/Base64/URI 订阅解析、`header`、`size-limit`、`etag-support` 与整组健康检查 |
| `inbounds` | 回环固定目标转发入口，默认空 |
| `nodes` | 服务端协议节点（需配置真实鉴别成员 `members`），默认空 |
| `local_inbounds` | 协议工厂显式允许的本地回环入口，默认空 |
| `limits` | 全局超时、会话与账本记录上限，省略字段使用默认值 |
| `routes` | 路由规则数组，默认空，见下文 |
| `device` | 设备级 WARP 补齐，默认关闭，见下文 |
| `dns` | 网站域名解析的上游与 hosts，默认用系统解析器，见 [DNS](dns.md) |
| `control` | HTTP 控制接口，默认关闭，见[控制接口](control.md) |
| `telemetry` | SQLite 统计历史，默认关闭，见[统计历史](history.md) |
| `log` / `log_level` | 全局日志级别（`trace`/`debug`/`info`/`warning`/`error`/`fatal`/`panic`/`silent`）、访问与错误日志路径、时间戳及结构化开关 |
| `certificate` | 根级附加信任证书配置（`certificate_path`），默认空 |
| `certificate_providers` | 命名证书提供者数组（支持 `acme` 及 Cloudflare DNS-01 质询配置），默认空 |
| `route` / `rule_providers` | 扩展路由对象（含 `rules`、`rule_set`、`balancers`、`final`、`auto_detect_interface`、`default_interface`、`default_mark`）与外部/内联规则集提供者映射 |
| `sniffer` / `fakedns` / `tun` / `cache_file` / `profile` / `experimental` | 全局首包协议嗅探、顶层 FakeDNS 池、顶层 TUN 入口、选中节点（`store-selected`）与 Fake-IP 缓存持久化配置 |
| `geodata_mode` / `geodata_loader` / `geosite_matcher` / `geo_auto_update` / `geo_update_interval` / `geox_url` / `etag_support` | GeoIP / GeoSite 数据库加载模式、自动更新与 HTTP ETag 缓存配置 |
| `interface_name` / `routing_mark` / `disable_keep_alive` / `keep_alive_idle` / `keep_alive_interval` | 全局默认出站绑定网卡与套接字选项，可被单条出站 `dialer` / `sockopt` 覆盖 |

- **标签与校验**：`tag` 为 1–64 个 ASCII 字母、数字、`-` 或 `_`；出站拥有独立标签命名空间，所有入站（`inbounds` / `nodes` / `local_inbounds`）共用另一命名空间。未知字段、缺失类型、无效引用或能力不匹配在编译期直接拒绝。
- **管理账户（`accounts`）**：包含持久非零 UUID `user_id`、1–128 字符唯一 `username`、Argon2id v19 PHC 摘要 `password_hash`（参数范围：`m` 19456–262144，`t` 2–10，`p` 1–8）与可选 `enabled`。
- **协议节点（`nodes`）**：包含 `tag`、`type`、`listen`、`outbound`、`options`、`members` 及可选 `mode`、`max_sessions`：
  - `members` 每项包含 `user_id`、`native_credential` 及可选 `credential_epoch`（默认 `1`）、`enabled`；单节点最多 1024 个成员。跨节点复用认证或保护秘密在编译期拒绝。
  - `mode` 取 `ipv4-only`、`ipv6-only` 或 `dual-stack`（默认），仅约束本节点负责目标选择的 `Local` 出站路径（双栈默认 IPv4 优先）；`Remote` 代理出站保留原始目标域名或 IP 透传。

## 路由规则（`routes`）

每条规则含 `outbound` 与至少一个条件，按配置顺序匹配，首条命中生效。未命中时使用节点或入口绑定的 `outbound`。

| 字段 | 匹配 |
| --- | --- |
| `domain` | 目标域名完全相同 |
| `domain_suffix` | 目标域名等于该后缀，或是它的子域名 |
| `domain_keyword` | 目标域名包含该文本 |
| `ip_cidr` | 目标是字面 IP 且落在网段内 |
| `port` | 目标端口 |
| `network` | `tcp` 或 `udp` |
| `node` | 入站标签 |
| `user` | 管理账户 `user_id` |

同一字段内任一值命中即可；`domain*` 与 `ip_cidr` 都描述目标地址，任一命中即满足；其余字段须同时满足。

路由不查询 DNS，域名目标不会匹配 `ip_cidr`。多目标 UDP 关联建立时没有单一目标，固定走节点绑定的出站；TCP 与固定目标 UDP 按规则选择。规则选中的出站缺少对应能力时，该连接返回不支持错误。

以下规则永远不会按预期命中，`kerlico check` 直接拒绝：`node` 不是任何入站的标签，`user` 不在 `accounts` 内，`ip_cidr` 前缀为空（`10.0.0.0/`）或是 IPv4-mapped 网段（`::ffff:10.0.0.0/104`），`domain_keyword` 含非 ASCII 字符（目标域名已是 punycode）。

```json
"routes": [
  {"outbound": "block", "domain_suffix": ["ads.example"]},
  {"outbound": "direct", "ip_cidr": ["10.0.0.0/8"]},
  {"outbound": "direct", "user": ["00000000-0000-4000-8000-000000000001"], "port": [443]}
]
```

## 设备 WARP（`device`）

配置后，`dual-stack` 节点走 `direct` 出站且本机缺原生 IPv4 或 IPv6 时，缺失的地址族经 Cloudflare WARP 出网。单栈节点和 `Remote` 出站不受影响。未配置时只用原生地址族。

| 字段 | 约束说明 |
| --- | --- |
| `state_directory` | 必填，绝对路径。最终目录 `0700`，祖先目录不可被其他账户写入 |
| `registration` | `create-once`（默认）：状态为空时向 Cloudflare 注册一次。`existing-only`：只用已有身份，缺失或不匹配时启动失败 |

`direct` 出站可设 `"options": {"interface": "eth0"}` 绑定接口（仅 Linux）。绑定后该出站不使用 WARP。

同一 `state_directory` 只能被一个进程使用。需要 `warp` feature（默认启用）。详见[设备所有者](device-runtime.md)。

## 固定目标入口与全局限制（`limits`）

固定转发入口（`inbounds`）包含 `tag`、`type`（`tcp-forward` 或 `udp-forward`）、`listen`（必须为回环地址，端口 `0` 表示系统动态分配）、`target.host`/`port`、`outbound` 及可选 `mode`、`require_remote_eof`（默认 `false`；设为 `true` 时要求该入口实际使用的出站具备 `tcp_eof` 能力：以 `target`、TCP 和本入口为条件按序匹配 `routes`，首条命中的规则决定出站，未命中时使用 `outbound`）。

| `limits` 字段 | 默认值 | 有效范围与说明 |
| --- | --- | --- |
| `connect_timeout_ms` | `10000` | `1`–`300000`，建立链总期限 |
| `idle_timeout_ms` | `60000` | `1`–`86400000`，业务转发空闲超时 |
| `drain_timeout_ms` | `5000` | `1`–`300000`，关闭阶段排空预算 |
| `max_sessions` | `128` | `1`–`65536`，全局并发会话与附加逻辑流配额 |
| `udp_queue_packets` | `32` | `1`–`4096`，每来源固定 UDP 转发排队包数上限 |
| `max_datagram_size` | `65535` | `1`–`65535`，数据报缓冲区上限 |
| `max_flow_records` | `65536` | `max_sessions`–`1048576`，内存账本保留的 `FlowRecord` 上限 |

当内存账本记录达到 `max_flow_records` 上限时，优先淘汰已结束的记录（其累计流量保留在运行期汇总中）；若全部槽位均被活跃流占满，则拒绝新业务流。

## 命令行接口（CLI）

| 命令 | 行为说明 |
| --- | --- |
| `kerlico modules` | 按 `outbound/<kind>` 与 `inbound/<kind>` 列出当前构建实际注册的模块 |
| `kerlico check -c <file>` | 校验配置文件（上限 1 MiB）并编译装配计划，不绑定端口、不拨号或创建状态目录 |
| `kerlico run -c <file>` | 启动唯一共享出站服务并绑定全部入站入口；收到 `Ctrl-C` 或 Unix `SIGTERM` 时停止准入并有限排空，收到 Unix `SIGHUP` 时校验并记录配置热重载 |
| `kerlico account-new --prefix <name>` | 从标准输入读取 12–1024 字节管理密码，输出带 `<prefix>_<uuid>` 用户名与 Argon2id 摘要的账户 JSON |
| `kerlico history --kind <usage\|flows\|bandwidth\|events>` | 只读查询统计历史，输出 JSON，见[统计历史](history.md) |
| `kerlico generate <target>` | 生成 `uuid`、`rand`/`rand-base64`/`rand-hex`、`reality-keypair`/`vless-x25519`、`wg-keypair`、`ech-keypair`、`tls-keypair`（含 `--months`）、`vless-mlkem768`、`mldsa65`、`vlessenc` 与 `sudoku-keypair` |
| `kerlico tls <cert\|hash>` | 生成自签名 TLS 证书与私钥 PEM，或计算证书 SHA-256 指纹 |
| `kerlico xray <target>` | 兼容 Xray CLI 的 `uuid`、`x25519`、`wg`、`tls`、`mldsa65`、`mlkem768` 与 `vlessenc` 生成子命令 |

默认构建注册全部 **30 个协议模块**，另有基础出站 `direct`、`reject`：

- 同时注册 `inbound` 与 `outbound`（20 个）：`anytls`、`http`、`hysteria1`、`hysteria2`、`mieru`、`naive`、`shadowquic`、`shadowsocks`、`shadowsocksr`、`shadowtls`、`snell`、`socks`、`ss2022`、`sudoku`、`trojan`、`trusttunnel`、`tuic`、`vless`、`vmess`、`wireguard`。
- 仅注册 `outbound`（9 个）：`easytier`、`gost-relay`、`masque`、`openconnect`、`openvpn`、`ssh`、`tailscale`、`tor`、`zerotier`。
- 仅注册 `inbound`（1 个）：`tun`。
