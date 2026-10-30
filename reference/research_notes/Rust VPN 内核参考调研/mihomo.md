# mihomo 调研

## 1. 调研对象、版本与来源边界

### 核心结论

mihomo 最值得本项目研究的是连接元数据、规则路由、节点策略组、资源更新与客户端控制接口如何组成一个可运维的代理内核。本次以已核验的稳定标签源码为主体；以下分析是参考材料，不是本项目已确认的功能或技术选型。[固定版本 README](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/README.md)

### 来源与事实

| 项目 | 本次核验结果 | 依据 |
| --- | --- | --- |
| 调研记录日期 | 2026-10-30，Asia/Shanghai；这是本次记录日期，不代表文档发布日 | 本次任务上下文 |
| 官方入口 | MetaCubeX/mihomo；README 指向 wiki.metacubex.one | [固定 README](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/README.md) |
| 主体快照 | `v1.19.33` → `3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8`；调研时 `Meta` 分支也指向此 SHA | [tag 引用 API](https://api.github.com/repos/MetaCubeX/mihomo/git/ref/tags/v1.19.33)、[tag commit API](https://api.github.com/repos/MetaCubeX/mihomo/commits/v1.19.33)、[Meta commit API](https://api.github.com/repos/MetaCubeX/mihomo/commits/Meta) |
| 最新 release 观察 | `/releases/latest` 返回 `v1.19.33`，`published_at` 为 `2026-10-21T16:56:13Z`；“最新”仅描述本次请求结果 | [release API](https://api.github.com/repos/MetaCubeX/mihomo/releases/latest)、[版本页面](https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.33) |
| 语言与模块 | Go；`module github.com/metacubex/mihomo`，`go 1.20` | [固定 go.mod](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/go.mod) |
| 本体许可证 | 同一 SHA 的 LICENSE 为 GNU GPL version 3 文本，README 标为 GPL-3.0；README 另有下游命名声明 | [固定 LICENSE](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/LICENSE)、[固定 README](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/README.md) |

来源异常须保留：本次仓库首页、repo REST 元数据与默认 `HEAD` 返回了 Python/Pydantic 同名项目的信息，默认 `main`/HEAD 为 `008b91bfe8c0e2daca0ab69061efd9ea1ad71bd2`；但稳定 tag、`Meta` 引用及固定源码 tree 返回的是 Go 内核。故不使用首页语言统计、默认分支或首页 MIT 标签为本报告的 Go 快照定性，也不据此推测上游发生了什么。[repo API](https://api.github.com/repos/MetaCubeX/mihomo)、[HEAD commit API](https://api.github.com/repos/MetaCubeX/mihomo/commits/HEAD)、[已核验源码树](https://api.github.com/repos/MetaCubeX/mihomo/git/trees/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8?recursive=1)

### 分析与启发

- 后续比较或复核应沿用固定 tag/SHA，避免把不同分支、同名内容或滚动文档混成一个版本。许可证名称只是源码观察；借鉴设计、复制代码、链接依赖是不同问题，具体复用方式尚未确定。

### 未验证项

- 未解释首页与分支快照不一致的原因；不能断言是上游迁移、缓存、元数据故障或其他原因。
- 未逐项审阅全部依赖许可证，不能把本体 GPL-3.0 标签直接套用到所有依赖。

## 2. 架构、元数据与 TCP／UDP 数据路径

### 核心结论

核心抽象是：入站把连接或数据包与统一元数据交给 `Tunnel`；路由选择一个代理适配器，适配器分别提供流连接和包连接。`Tunnel` 名称在这里表示流量调度入口，不等同于 OS 的 TUN 网卡。[Tunnel 接口](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/constant/tunnel.go)、[适配器接口](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/constant/adapters.go)

### 来源与事实

建议按以下顺序阅读，先看控制流程与接口，再进入协议细节：

| 阅读顺序 | 固定源码位置 | 主要问题 |
| --- | --- | --- |
| 1 | [main.go](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/main.go)、[hub/hub.go](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/hub/hub.go) | 参数、配置来源、启动入口、信号触发重载 |
| 2 | [config/config.go](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/config/config.go)、[hub/executor/executor.go](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/hub/executor/executor.go) | YAML 原始配置如何解析为运行对象、如何应用 |
| 3 | [constant/metadata.go](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/constant/metadata.go)、[constant/adapters.go](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/constant/adapters.go) | 地址、域名、嗅探信息、流／包接口及回写约定 |
| 4 | [listener/sing/sing.go](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/listener/sing/sing.go)、[listener/sing_tun/server.go](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/listener/sing_tun/server.go) | 外部库／TUN 输出如何转换成 mihomo 入站语义 |
| 5 | [tunnel/tunnel.go](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/tunnel/tunnel.go)、[tunnel/connection.go](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/tunnel/connection.go) | 匹配、拨号、UDP 会话、超时、回写与释放 |

- **启动链路**：`hub.Parse` 先解析配置，再施加控制接口等覆盖选项，最后应用；`ApplyConfig` 更新运行组件。原始 YAML 与解析后的配置对象有明确转换步骤，解析规则、代理、监听器、DNS 各有独立函数。[hub 入口](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/hub/hub.go)、[配置解析](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/config/config.go)
- **元数据**：`Metadata` 除源／目的 IP、端口、网络类型，还包含入站名称和用户、`Host`、`SniffHost`、DNS 模式、进程与 UID、特殊代理／子规则、链路观测所需信息。`RuleHost` 区分嗅探域名与原始 Host，`Pure` 处理 DNS 映射后的拨号地址语义。[元数据定义](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/constant/metadata.go)
- **TCP 路径**：入站交付流与元数据 → 地址规范化、DNS 映射恢复与可选嗅探 → `resolveMetadata` 选择出站／策略组 → `DialContext` → 统计包装与双向中继 → 关闭连接。协议层无需各自重写规则调度。[调度实现](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/tunnel/tunnel.go)、[中继实现](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/tunnel/connection.go)
- **UDP 路径**：包适配器有会话 key；入口按 key 散列到有界工作队列，满时丢包。NAT 表为 key 建立 sender，首包准备阶段完成嗅探／路由并创建 `ListenPacketContext`；后续由 sender 顺序处理包，并用回写代理返回入站。该层不应被简化描述成“每个目的地址一个 TCP 式连接”。[UDP 调度](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/tunnel/tunnel.go)、[包适配器 key 与接口](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/constant/adapters.go)
- **包所有权**：`UDPPacket.Drop` 是用毕释放／回收约定；sender 处理后调用 Drop，关闭时还要清空队列。入站回写目标可更新；目标 NAT 映射要支持把响应地址恢复到客户端认识的原始地址。这里同时包含内存生命周期和地址语义。[sender 与 NAT 恢复](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/tunnel/connection.go)、[回写代理](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/component/nat/proxy.go)

### 分析与启发

- Rust 中可讨论独立的连接元数据、流接口、数据报接口与包所有权模型；直接把 Go 的全局变量、锁和 goroutine 逐一翻译过去，没有充分设计依据。
- UDP 会话 key、队列容量、首包等待、DNS 解析阻塞和超时释放，应先形成明确语义，再谈异步运行时或缓冲池选型。

### 未验证项

- 未运行流量、抓包或故障注入；上述是静态源码路径，不证明所有协议的相同语义与实际兼容性。
- 未完整审计 UDP key 在各入站下的隔离方式及所有并发竞态；不可直接声称适合任意多租户环境。

## 3. TUN、DNS、路由和协议能力

### 核心结论

mihomo 将 OS 接流、DNS 增强、路由决策和协议出站组合起来，但 TUN 协议栈与多种协议依赖独立库。对 Rust 项目而言，应该拆开评估这些边界，而不是把“支持 TUN”视作完整跨平台 VPN 能力的单一开关。[TUN 集成](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/listener/sing_tun/server.go)、[依赖表](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/go.mod)

### 来源与事实

| 主题 | 已核验事实与边界 | 来源 |
| --- | --- | --- |
| TUN 栈 | 当前固定源码包括 `system`、`gvisor`、`mixed`、`mips`；配置默认 `Mips`。不能套用只列前三种的旧资料。`with_gvisor` 是明确构建标签 | [栈枚举](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/constant/tun.go)、[默认配置](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/config/config.go)、[标签文件](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/constant/features/with_gvisor.go) |
| TUN 库边界 | Listener 调用 `metacubex/sing-tun` 创建网卡与 Stack；`go.mod` 锁定 `sing-tun v0.4.28`，并列有 mipstack、gvisor。网卡、栈、监视器、自动重定向分别持有资源并关闭 | [集成及 Close](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/listener/sing_tun/server.go)、[依赖版本](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/go.mod) |
| 平台限制 | `auto-redirect` 的本体编译分支仅在 Linux 开启；官网还列出各 OS 的 DNS 劫持、接口命名、路由和防火墙限制。因此未据 CLI 构建能力推断移动端系统 VPN 集成已经解决 | [Linux 开关](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/listener/sing_tun/redirect_linux.go)、[其他平台开关](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/listener/sing_tun/redirect_stub.go)、[滚动 TUN 文档](https://wiki.metacubex.one/config/inbound/tun/) |
| DNS | 有内置 DNS server、hosts、中间件、缓存、按域名策略、fallback；解析配置支持 UDP/TCP、TLS、HTTP(S)、QUIC、system/DHCP 等上游类型。Fake-IP 维护 IP→域名映射，TUN 的 DNS 劫持路径直接交给内部 resolver | [DNS resolver](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/dns/resolver.go)、[DNS middleware](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/dns/middleware.go)、[TUN DNS](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/listener/sing_tun/dns.go) |
| Fake-IP 状态 | Enhancer 提供逆向查询、缓存迁移、flush 与持久化接口；重载时可从旧 enhancer 迁移池状态，退出时保存。DNS 映射的生存期与连接路径相互关联 | [enhancer](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/dns/enhancer.go)、[应用与关闭](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/hub/executor/executor.go) |
| 规则与规则集 | 有域名、IP、进程、网络／端口等匹配与逻辑规则；规则集 provider 支持 file/http/inline，下载与匹配策略分开。路由还区分不支持 UDP 的适配器、Pass 和 Rematch 等分支，不能概括为无条件的首匹配返回 | [规则目录树](https://api.github.com/repos/MetaCubeX/mihomo/git/trees/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8?recursive=1)、[provider 解析](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/rules/provider/parse.go)、[路由 match](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/tunnel/tunnel.go) |
| 策略组和节点更新 | 源码有 selector、urltest、fallback、loadbalance；provider 负责节点集合和版本，健康检查有周期／惰性触发、超时和并发限制。节点来源、选择策略、可用性观测具有不同职责 | [策略组目录](https://github.com/MetaCubeX/mihomo/tree/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outboundgroup)、[provider](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/provider/provider.go)、[healthcheck](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/provider/healthcheck.go) |
| 入站 | 解析器覆盖 HTTP、SOCKS、mixed、redir、tproxy、tun、固定 tunnel，以及 Shadowsocks、VMess、VLESS、Trojan、Hysteria2、TUIC、AnyTLS 等协议监听器 | [listener 解析器](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/listener/parse.go) |
| 出站 | 解析器覆盖 direct/reject/dns、HTTP/SOCKS、Shadowsocks/SSR、VMess/VLESS、Trojan、Snell、Hysteria/Hysteria2、TUIC、WireGuard、SSH、AnyTLS 等；该快照还列有 OpenVPN、MASQUE、Tailscale、ZeroTier、EasyTier 等。列出配置分支只说明源码存在，不等于逐项验证稳定性、平台可用性或默认构建包含全部能力 | [adapter 解析器](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/parser.go)、[feature 与 stub 文件目录](https://api.github.com/repos/MetaCubeX/mihomo/git/trees/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8?recursive=1) |

### 分析与启发

- 值得借鉴的是 DNS 自身的上游引导解析、代理服务器解析与业务域名解析分工，以及域名／真实 IP／Fake-IP 不同身份的显式表达。Rust 版本是否兼容现有 YAML 语义仍待讨论。
- TUN 接流与 WireGuard/OpenVPN 等出站是不同层面的能力；客户端产品还需要 OS 权限、系统路由、DNS 接管与退出恢复，不能从协议名清单推出产品完成度。

### 未验证项

- 未审计 sing-tun 内部所有平台实现、iOS Network Extension 或 Android VPN Service 的接入方案。
- 未开展协议互通测试；不构成完整功能矩阵或与其他两个项目的协议等价证明。
- 官网是滚动文档，配置字段的版本归属应优先用固定源码复核；本次未保存官网的固定文档仓库 commit。

## 4. 生命周期、控制接口与工程验证

### 核心结论

这里的工程复杂度不止于转发：配置应用会按阶段暂停和恢复入口，节点／规则资源有独立更新流程，API 暴露运行状态；这些行为应当在 Rust 设计阶段单独讨论。[配置 executor](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/hub/executor/executor.go)、[控制接口](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/hub/route/server.go)

### 来源与事实

- `ApplyConfig` 用 mutex 串行执行，经过 `OnSuspend`、组件更新、`OnInnerLoading`、provider 加载，再 `OnRunning`；普通外部流量和内部资源加载流量在状态判断上有区分。源码可以说明更新顺序，不能据此宣称“零中断、事务式热重载”。[executor](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/hub/executor/executor.go)、[Tunnel 状态判断](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/tunnel/tunnel.go)
- REST 控制面包括运行配置、节点、策略组、provider、规则、连接，以及日志、流量和内存观测；配置 API 可 patch 或加载新配置。HTTP/TLS、Unix socket、Windows pipe 有不同监听实现；独立 Web 面板是另一项目，不属于转发链路本体。[路由 server](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/hub/route/server.go)、[配置 API](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/hub/route/configs.go)、[API 滚动文档](https://wiki.metacubex.one/api/)
- 已读的 CI 在 Linux、Windows、macOS 多架构与多个 Go 版本上执行普通和 `with_gvisor` 两组测试。但它设置 `SKIP_INTEROP_TEST=1`，且 macOS 先删除 `listener/inbound/*_test.go`；因此不能把矩阵覆盖等同于所有入站互通测试都已运行。[固定 CI](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/.github/workflows/test.yml)
- 源码树中有 Fake-IP 池、域名 trie、IPCIDR、规则逻辑、sniffer、连接缓冲、入站与协议互通相关测试，适合作为设计阅读材料。本次只检查了文件布局及 CI 配置，未运行测试，也未核验每项 CI 结果。[固定源码树](https://api.github.com/repos/MetaCubeX/mihomo/git/trees/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8?recursive=1)

### 分析与启发

- 本项目可以先明确“配置校验失败”“应用一半失败”“旧连接继续存活”“监听端口冲突”“退出恢复系统网络”各自的行为，再选择配置快照与资源管理方案。
- 控制面需要同时观察决策原因、节点链路、会话生存期和丢包情况；只记录总吞吐无法解释路由与 DNS 问题。

### 未验证项

- 未验证重载时各类旧连接是否保留，亦未证明失败时能完整回滚。
- 未实测平台权限、网络切换、DNS 泄漏、内存占用、吞吐、尾延迟或移动端电量。

## 5. 对 Rust 内核的候选启发与待决问题

### 核心结论

优先学习其职责拆分和异常路径，再决定本项目需要多少生态兼容能力。以下均为研究推论，不改变仓库目前“讨论与结构维护”的阶段。

### 来源与事实

支撑这些推论的直接材料是：元数据与适配器接口、独立 TUN 集成、DNS enhancer、provider 及 executor；它们分别呈现了地址语义、OS 边界、映射状态、资源更新和应用顺序。[接口](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/constant/adapters.go)、[TUN](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/listener/sing_tun/server.go)、[DNS](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/dns/enhancer.go)、[provider](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/provider/provider.go)、[executor](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/hub/executor/executor.go)

### 分析与启发

1. **元数据先行**：讨论域名、真实目的地址、嗅探结果与 Fake-IP 的区分，避免把一个可变字符串同时承担身份和拨号目标。
2. **数据报单独建模**：显式讨论包边界、目标地址、回写来源、NAT key、缓冲所有权、有界队列和丢包策略，不能直接复用 TCP 生命周期。
3. **平台适配独立**：把 TUN 设备、用户态网络栈、路由／DNS 修改、出口防回环与协议传输看成不同问题；尚不决定采用哪个 Rust 库或是否需要 FFI。
4. **资源和策略分离**：节点发现／下载、健康度观测、选择策略、规则资源更新可分别讨论，避免 provider 与转发流程互相牵制。
5. **兼容性单独估价**：是否兼容 Clash/Mihomo 配置、API、订阅和规则集，是产品范围选择，不应自然演变成“完整复刻”。

### 未验证项

本项目仍需明确：首批 OS；主要服务客户端还是网关／服务端；MVP 是否必须 TUN 与 Fake-IP；首批 TCP/UDP 协议；配置与 API 兼容目标；动态规则／订阅是否首批需要；重载一致性；许可证与依赖复用策略。完成这些讨论前，不据本调研建立实现模块或选定运行时。
