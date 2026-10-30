# sing-box 技术调研

## 调研基线与项目定位是什么？

### 核心结论

sing-box 值得参考的是可组合的代理与网络平台：协议、路由、DNS、系统网络接入、生命周期和客户端桥接有明确的接口层。本文以已发布的 `v1.14.4` 固定源码为基线，在线文档只用于交叉核对；这些材料不能直接代表本项目已确定的架构。[项目说明](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/README.md)、[核心装配](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/box.go)

### 来源与事实

| 项目 | 本次核验结果 | 依据 |
|---|---|---|
| 调研日期 | 2026-10-30，Asia/Shanghai；这是本地记录日期 | 本次调研元数据 |
| 官方项目 | `SagerNet/sing-box`；官方说明为通用代理平台 | [README](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/README.md) |
| 已核验稳定发行 | `v1.14.4`，GitHub release 的 `published_at` 为 `2026-10-24T01:04:25Z`，`prerelease=false` | [发行页](https://github.com/SagerNet/sing-box/releases/tag/v1.14.4)、[latest release API](https://api.github.com/repos/SagerNet/sing-box/releases/latest) |
| 固定源码 | `c005f35300ce76427dc285481ec5695f5b179cd2`；实际浅克隆 HEAD 与 tag ref API 一致 | [commit](https://github.com/SagerNet/sing-box/commit/c005f35300ce76427dc285481ec5695f5b179cd2)、[tag ref API](https://api.github.com/repos/SagerNet/sing-box/git/ref/tags/v1.14.4) |
| 默认分支 | 本次仓库 API 返回 `testing`；本文没有把默认分支当成稳定发行 | [仓库 API](https://api.github.com/repos/SagerNet/sing-box) |
| 语言与工具链 | Go；固定快照的 `go.mod` 声明 `go 1.25.5` | [go.mod](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/go.mod) |
| 许可证原文 | GPL 第 3 版或之后版本，并附有未经同意不得使用该应用名称或暗示关联的文字；GitHub API 的 SPDX 字段为 `NOASSERTION`，不能仅用一个纯 GPL 标签概括全部文字 | [LICENSE](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/LICENSE)、[仓库 API](https://api.github.com/repos/SagerNet/sing-box) |

- 在线迁移页已经包含 `1.15.0 / Migrate TUN stack`，固定 `v1.14.4` 的迁移文档从 `1.14.0` 开始。因此本文关于栈、配置和接口的判断优先取自同一固定 SHA，不能把在线新增迁移当成 `v1.14.4` 行为。[在线迁移页](https://sing-box.sagernet.org/migration/)、[固定版本迁移文档](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/docs/migration.md)

### 分析与启发

- 本项目可以讨论其模块边界；若后续希望直接复用实现，需要把主仓库与依赖的许可文字、名称限制分别列入复用评估。这是研究事项，并非法律结论。

### 未验证项

- 本次没有审计全部第三方依赖许可，也没有对任一发行二进制进行功能与构建标记验证。

## 核心怎样装配，TCP 与 UDP 怎样经过系统？

### 核心结论

控制面的入口是配置解码、注册表和 `Box` 装配，常规数据面则是入站形成连接元数据，路由执行动作，出站建连，连接管理器负责双向传输。TCP 与 UDP 分别建模；另外还存在 TUN 流预匹配与包级转发路径，不能把所有数据都画成同一条字节流。[Box](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/box.go)、[路由](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/route/route.go)、[流预匹配接口](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/adapter/router.go)

### 来源与事实

- **启动与配置：** `cmd/sing-box/main.go` 执行 CLI；`cmd_run.go` 从文件、标准输入和配置目录读取 JSON，排序并合并配置，建立可取消 context，执行 `box.New` 与 `Start`。`Box.New` 装配入站、出站、endpoint、服务、证书、DNS transport、DNS router、网络与连接管理器等组件。[main.go](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/cmd/sing-box/main.go)、[cmd_run.go](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/cmd/sing-box/cmd_run.go)、[box.go](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/box.go)
- **注册表与生命周期：** `include/registry.go` 将协议构造器和对应选项注册到各类 registry。生命周期有 initialize、start、post-start、started 四阶段；`Scope` 持有子 scope、取消 context 和清理函数，关闭时逆序清理。它比单纯的“模块有一个 Start/Close”更具体。[registry.go](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/include/registry.go)、[lifecycle.go](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/adapter/lifecycle.go)
- **共享元数据：** `adapter.InboundContext` 包含源地址、目的地址、入站类型、用户、网络类型、协议和域名、进程、原始目的地址、DNS 响应、FakeIP 标记、出站链及规则匹配缓存。`Outbound` 提供类型、标签、网络能力、依赖和 `Dialer`，元数据还承载 UDP 超时及映射选项。[inbound.go](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/adapter/inbound.go)、[outbound.go](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/adapter/outbound.go)
- **常规 TCP：** TUN 的 `NewConnectionEx` 填充元数据并交给 `RouteConnectionEx`；路由匹配规则，处理 DNS 劫持、拒绝或出站选择，展开 selector 等出站链，回放嗅探已读取的缓存，调用出站 handler 或 `ConnectionManager.NewConnection`。后者执行拨号、握手成功报告和两个方向的数据复制。[TUN 入站](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/protocol/tun/inbound.go)、[route.go](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/route/route.go)、[conn.go](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/route/conn.go)
- **常规 UDP：** 入站交付 packet connection；路由使用 `RoutePacketConnectionEx`，同样保留嗅探读走的数据包。FakeIP 流会安装对应 NAT 包装；连接管理器依 `UDPConnect` 等选项选择 UDP dial 或 `ListenPacket`，维护报文复制与超时。UDP 不是把 TCP 接口的 network 字段改个值便完成。[UDP 路由](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/route/route.go)、[UDP 转发](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/route/conn.go)
- **预匹配例外：** `JudgeFlow` 根据首包、网络和源目的地址调用 `PreMatch`，可返回 flow、reject、drop、bypass、hijack DNS 等动作；满足 `tun.Port` 能力的出站可进入流级路径。仅用常规 TCP/UDP 连接路径解释 endpoint 与 TUN 的所有流量是不完整的。[adapter/router.go](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/adapter/router.go)

### 分析与启发

- Rust 设计讨论可以分别评估连接、报文会话、原始 IP 流三个层级，并对取消、超时、半关闭、缓存释放和清理顺序定义责任。
- Go 的大元数据结构和运行时服务查询可以帮助识别真实需求，但 Rust 是否使用 trait、枚举、依赖注入或 RAII，应另行比较，不宜逐行翻译。

### 未验证项

- 本次未逐项审计每个协议的握手和所有错误清理分支，也未证明预匹配路径在所有平台和出站上等价可用。

## TUN、平台适配、协议和依赖的边界在哪里？

### 核心结论

TUN 入站并不独自实现完整网络栈，它调用单独的 `sing-tun` 依赖并可由平台回调提供接口。协议能力还受编译标记约束；“源码中有目录”和“某发行包在某平台可用”需要分别核验。[TUN 入站](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/protocol/tun/inbound.go)、[依赖清单](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/go.mod)

### 来源与事实

- **TUN 与栈：** 入站通过 `sing-tun.New` 或平台 `OpenInterface` 打开接口，再调用 `sing-tun.NewStack`。固定依赖的完整提交为 `040db71fcd33196f1d15708b91eb61e9dc6ab8dd`。其 `system` 使用系统栈进行 L3→L4 转换；`gvisor` 使用虚拟栈；`mixed` 是 system TCP 与 gVisor UDP。真实默认选择还受 `IncludeAllNetworks` 与 GSO 影响：前者要求 gVisor 路径，具备 gVisor 且未启用 GSO 才默认 mixed，否则 system；不能只照搬文档中的简化默认说明。[入站装配](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/protocol/tun/inbound.go)、[固定版本 TUN 文档](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/docs/configuration/inbound/tun.md)、[依赖实际选择逻辑](https://github.com/SagerNet/sing-tun/blob/040db71fcd33196f1d15708b91eb61e9dc6ab8dd/stack.go)
- **操作系统边界：** 自动路由、nftables auto_redirect、UID 和接口规则均有独立平台条件。文档限定 auto_redirect 为 Linux 且依赖 auto_route，并特别说明 Android 上只具备简化 IPv4 TCP 转发；部分大量路由配置不适用于 Android/Apple 图形客户端。不能据此声称所有平台有相同透明代理能力。[平台限制](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/docs/configuration/inbound/tun.md)
- **客户端嵌入：** `experimental/libbox/PlatformInterface` 向宿主请求 OpenTun、socket 接口控制、连接归属查询、默认接口监听、DNS 清理和 NetworkExtension 状态等。VPN 权限、系统扩展与应用生命周期因此要和宿主一起理解，不能算作纯核心库自动获得的能力。[platform.go](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/experimental/libbox/platform.go)
- **协议与 endpoint：** 注册表包含 SOCKS、HTTP/mixed、Shadowsocks、VMess、VLESS、Trojan、ShadowTLS、AnyTLS、Snell、SSH/Tor 出站等不同角色。Hysteria/Hysteria2/TUIC 与 QUIC DNS transport 由 `with_quic` 文件注册；WireGuard、OpenConnect、OpenVPN、Tailscale 使用 endpoint 注册表及独立标记。WireGuard 旧 outbound 在本快照明确报错，要求迁移 endpoint，不能与新模型混列为可用出站。[注册表](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/include/registry.go)、[QUIC 注册](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/include/quic.go)、[WireGuard 标记](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/include/wireguard.go)
- **基础库生态：** `go.mod` 显示 `sing`、`sing-tun`、`sing-quic`、`sing-mux`、`sing-vmess`、`sing-shadowsocks` 等独立依赖，以及经项目修改的 gVisor、QUIC、WireGuard 与 Tailscale 相关模块。Rust 重做同类行为时要单独评估这些库承担的工作量，不能只估算 sing-box 仓库的胶水代码。[go.mod](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/go.mod)

### 分析与启发

- 可讨论将“平台网络权限与接口”“IP 流转换”“代理协议”“控制接口”分开评估，并先定义目标平台的能力矩阵。
- 此处协议表用于识别模型差异，不是本项目 MVP 清单；也没有证据说明完整复刻这些能力是当前目标。

### 未验证项

- 未对平台权限、驱动分发、休眠唤醒、网络切换、MTU 和 UDP NAT 行为进行实机验证。
- 未验证全部协议与外部实现互通，也没有性能或内存基准，不能据此排列三个项目的速度。

## DNS、路由和规则集有哪些值得追踪的演进？

### 核心结论

sing-box 把规则条件与动作分开，同时将 DNS 视为独立的可编排子系统。研究时必须带版本号：1.11 的动作迁移、1.12 的 DNS server 格式和 1.14 的 DNS 响应匹配改变了配置含义。[固定迁移文档](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/docs/migration.md)

### 来源与事实

- **路由动作：** 常规路由可顺序执行 `sniff`、`resolve`、`route-options` 等非终结动作，再由 route/reject/hijack-dns 等动作结束选择。嗅探消费的 TCP 缓存或 UDP 首包会回放给后续处理，避免探测破坏数据流。[路由实现](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/route/route.go)、[规则动作文档](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/docs/configuration/route/rule_action.md)
- **DNS 与 FakeIP：** DNS transport registry 包含 UDP/TCP/TLS/HTTPS、hosts/local/mDNS、FakeIP，以及受标记控制的 QUIC/HTTP3 等 transport。FakeIP 已是 `type: fakeip` 的 DNS server；路由准备阶段查询 FakeIP store，将 IP 还原域名并保留原目的地址，缺少映射会返回错误。DNS 反向映射是另一条可选机制，不等于 FakeIP。[DNS transport 注册](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/include/registry.go)、[FakeIP server](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/docs/configuration/dns/server/fakeip.md)、[恢复逻辑](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/route/route.go)
- **1.11/1.12 迁移：** 旧 block/DNS special outbound、旧入站嗅探与解析字段逐渐迁移为规则动作；DNS server 改为显式类型结构，拨号域名解析也迁移到 domain resolver。TUN 构造器在本快照直接拒绝已经移除的旧入站字段。[迁移说明](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/docs/migration.md)、[TUN 选项校验](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/protocol/tun/inbound.go)
- **1.14 DNS 变化：** 新增 `evaluate` 获取响应、`match_response` 显式匹配响应，以及 `race`/`speculative` 等调度语义。文档明确某些旧地址过滤与新规则特性混用会在启动时拒绝；`independent_cache` 被弃用，`store_rdrc` 建议迁移到持久化完整 DNS 缓存的 `store_dns`。这些是本次固定版本已核验的事实，不是泛指所有历史版本。[迁移文档](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/docs/migration.md)、[DNS 动作文档](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/docs/configuration/dns/rule_action.md)、[DNS router](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/dns/router.go)
- **规则集：** 支持 inline、本地文件和远端来源，文件有 source/JSON 与 binary/SRS 形式；本地修改可重载，远端有更新周期、缓存和初始文件。1.14 还增加显式 `http_client`；规则下载自身经过什么网络路径也属于配置语义。[rule-set 文档](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/docs/configuration/rule-set/index.md)

### 分析与启发

- Rust 候选设计可以先明确 DNS 查询、拨号解析、FakeIP 映射和数据路由的边界，再讨论它们共享哪些规则条件。
- 若引入多阶段规则、并行 DNS 与持久缓存，需要同步设计确定性、取消语义、缓存归属、配置迁移和错误提示，不能只做配置字段映射。

### 未验证项

- 本次未完整形式化 DNS race 的竞争与回退语义，也未审计 SRS 编译器与所有规则匹配数据结构。

## 运行控制、验证与后续阅读怎样安排？

### 核心结论

可动态切换选路、规则集更新、兼容 API、完整配置重载是不同能力。源码与测试最值得学习的是这些状态变化怎样影响已有连接，而不是仅看控制接口名称。[selector](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/protocol/group/selector.go)、[CLI reload](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/cmd/sing-box/cmd_run.go)

### 来源与事实

- **组与健康检查：** selector 持有一组已注册出站，切换时可保存选择并按配置中断连接；URLTest 有探测间隔、容差、空闲超时、探测历史，并分别按网络选择出站。它们是出站组，不应自动等同于任意订阅 provider 系统。[selector.go](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/protocol/group/selector.go)、[urltest.go](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/protocol/group/urltest.go)
- **配置重载边界：** CLI 收到 SIGHUP 先执行配置检查，然后取消并关闭旧 `Box`、重新读取合并配置、创建新实例；这不是无连接中断的原地替换。固定快照的 Clash API `PUT /configs` 只返回成功空响应，`PATCH /configs` 只实际切换 mode，不能写成“支持完整 Clash 配置热更新”。[cmd_run.go](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/cmd/sing-box/cmd_run.go)、[clashapi/configs.go](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/experimental/clashapi/configs.go)
- **观测与控制：** 日志、连接 tracker、Clash API 和可选 V2Ray 流量统计存在各自接口。1.14 的 `service/api` 又提供原生 gRPC/gRPC-Web 控制观测服务；它不能与兼容 API 混为一个承诺完全等价的接口。`with_clash_api`、`with_v2ray_api` 等构建条件需要核验，默认发行标记清单并不包含所有可选项。[原生 API 文档](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/docs/configuration/service/api.md)、[原生 API 实现](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/service/api/server.go)、[V2Ray API](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/docs/configuration/experimental/v2ray-api.md)、[默认标记](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/release/DEFAULT_BUILD_TAGS_OTHERS)
- **验证组织：** 仓库有同包测试，也有独立 `test/go.mod` 指回父模块的互通/集成测试。`test/box_test.go` 使用 goleak，并包含 TCP/UDP 回环、大数据和依赖外部网络的测试辅助逻辑；CI 在 Linux、Windows、macOS 上执行带标记测试。这个结构表明可以分别观察组件正确性、互通、资源泄漏与平台行为，不能据目录存在就声称它们全部通过。[test/go.mod](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/test/go.mod)、[test/box_test.go](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/test/box_test.go)、[CI](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/.github/workflows/test.yml)

建议后续按以下顺序阅读；所有链接都固定到本次基线，构成主要来源索引：

| 顺序 | 源码入口 | 阅读目的 |
|---|---|---|
| 1 | [box.go](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/box.go)、[registry.go](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/include/registry.go) | 组件依赖、实例装配与注册边界 |
| 2 | [adapter](https://github.com/SagerNet/sing-box/tree/c005f35300ce76427dc285481ec5695f5b179cd2/adapter) | 元数据、流/报文接口、生命周期和 Scope |
| 3 | [route/route.go](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/route/route.go)、[route/conn.go](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/route/conn.go) | 路由动作、缓存回放、建连与转发 |
| 4 | [protocol/tun/inbound.go](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/protocol/tun/inbound.go)、[libbox/platform.go](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/experimental/libbox/platform.go) | 系统接入与宿主职责 |
| 5 | [dns/router.go](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/dns/router.go)、[migration.md](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/docs/migration.md) | DNS 编排与兼容性成本 |
| 6 | [protocol/group](https://github.com/SagerNet/sing-box/tree/c005f35300ce76427dc285481ec5695f5b179cd2/protocol/group)、[test](https://github.com/SagerNet/sing-box/tree/c005f35300ce76427dc285481ec5695f5b179cd2/test) | 动态选路与验证思路 |

### 分析与启发

- 对本项目的候选启发是：把控制接口、配置重载、规则资源更新和活跃连接策略分别定义，再决定需要哪种兼容层。
- 下一轮讨论可以围绕“TCP/UDP/原始包的抽象边界、平台宿主职责、DNS 与路由的交互、配置升级策略”形成明确待决问题；这些尚未转化为实现或架构决策。

### 未验证项

- 本次只阅读官方网页、固定源码和固定依赖；未构建、运行核心、执行上游测试或改动系统网络。
- 仍需确认本项目的首批平台、客户端/服务端范围、首批协议、配置兼容目标、API 兼容需求，以及重载时已有连接应继续还是终止。
