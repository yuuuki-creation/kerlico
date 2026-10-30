# 用三个项目厘清 Rust VPN 内核设计问题

**本轮的阅读判断是：用 mihomo 研究策略与资源管理，用 sing-box 研究组件装配和平台边界，用 Xray 研究统一分发及协议、传输、安全层的组合。**这三种视角互相补充，尚不足以替本项目选定架构。它们共同暴露的关键问题包括连接目标如何演进、TCP 与 UDP 如何分别管理、DNS 如何参与路由，以及系统网络资源由谁持有。Xray 本次快照已经包含原生 TUN，不能沿用“必须外接 tun2socks”的旧分类；控制接口的存在也不能直接解释为无损热重载。本轮仅研究官方文档和固定源码，没有构建、运行、互通测试、基准测试或系统网络实机验证，仓库继续保持讨论阶段。详细证据分别见 [mihomo](../research_notes/Rust%20VPN%20内核参考调研/mihomo.md)、[sing-box](../research_notes/Rust%20VPN%20内核参考调研/sing-box.md)、[Xray-core](../research_notes/Rust%20VPN%20内核参考调研/xray.md) 独立记录。

## 固定源码才能比较版本与能力

调研日期为 **2026-10-30，Asia/Shanghai**。下面是本轮核验的发行标签及源码，而非对未来 latest/default branch 状态的承诺；三份固定源码均为 Go 项目。语言和模块依据分别为 [mihomo go.mod](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/go.mod)、[sing-box go.mod](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/go.mod)、[Xray go.mod](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/go.mod)。

| 项目 | 已核验发行 | 固定提交 | 本体许可证观察 |
| --- | --- | --- | --- |
| mihomo | [v1.19.33](https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.33) | `3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8` | [LICENSE](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/LICENSE) 为 GPL v3；README 标 GPL-3.0，另有下游命名声明 |
| sing-box | [v1.14.4](https://github.com/SagerNet/sing-box/releases/tag/v1.14.4) | `c005f35300ce76427dc285481ec5695f5b179cd2` | [LICENSE](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/LICENSE) 含 GPL v3-or-later 及名称/关联限制；本次 GitHub SPDX 为 `NOASSERTION` |
| Xray-core | [v26.10.29](https://github.com/XTLS/Xray-core/releases/tag/v26.10.29) | `0afec66085a85191e9dd2a4a6646c7c9a94688d1` | 根 [LICENSE](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/LICENSE) 为 MPL-2.0 |

**来源不一致是本轮证据的一部分。**mihomo 首页、repo 元数据与默认 HEAD 返回 Python/Pydantic 同名项目信息，`main`/HEAD 为 `008b91bfe8c0e2daca0ab69061efd9ea1ad71bd2`，而稳定 tag 与 `Meta` 返回表中的 Go 内核。本报告只据固定 Go 快照判断架构和许可证，不推测异常原因。sing-box 在线迁移文档已出现 1.15 内容，而本轮基线是 1.14.4；其标签内文档优先于滚动网站。这些许可证记录仅描述对应源码，没有完成全部依赖审阅，也没有决定本项目是否复制代码或链接上游库。([mihomo 来源核验](../research_notes/Rust%20VPN%20内核参考调研/mihomo.md)、[sing-box 固定迁移文档](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/docs/migration.md))

## 三个项目的阅读价值落在不同边界

下表是架构对照，不是完整协议矩阵或项目排名。每个单元格描述固定快照的组织方式；构建标记、平台权限、客户端宿主和依赖版本仍会改变可用能力。

| 维度 | mihomo | sing-box | Xray-core |
| --- | --- | --- | --- |
| 装配与生命周期 | 配置解析后由 executor 按阶段应用到运行组件 | registry 与 `Box` 装配，分阶段生命周期，`Scope` 逆序清理 | 外部配置转换为内部配置，以工厂和 Feature 依赖组装 Instance |
| TCP / UDP | 流拨号与包监听接口分开；UDP 有会话 key、队列、NAT 和回写 | connection / packet connection 分开；另有 TUN 预匹配与包级路径 | Dispatcher/Link 统一分发；Buffer 仍保留 UDP 包边界和逐包目标 |
| TUN 与平台 | 通过 `metacubex/sing-tun` 集成；系统接流与出站协议分层 | 通过 `sing-tun` 和宿主平台回调；endpoint 另有模型 | 本仓库原生 TUN、OS 后端与轻量栈；移动端仍需宿主提供接口 |
| DNS 与规则 | DNS enhancer、Fake-IP、规则及资源 provider 与调度衔接 | 条件与动作分开；DNS router/transport 和 FakeIP store 独立组织 | DNS/FakeDNS 与 Dispatcher、Router 交互，解析策略影响 IP 规则 |
| 选择策略与资源 | selector/urltest/fallback/loadbalance；provider 与健康检查分别负责节点和观测 | selector/URLTest 选择已注册出站；不能等同于任意订阅 provider | router balancer 与 observatory 协作；不能据此推断相同订阅模型 |
| 配置与控制 | REST 配置/节点/连接等 API；应用过程包含暂停和恢复阶段 | SIGHUP 关闭旧 Box 后重建；兼容 API 与原生 API 职责不同 | gRPC 操作组件、规则及统计；不等于整份配置事务切换 |
| 协议与传输 | adapter/解析器组织多类协议，库依赖承担部分实现 | 类型注册与 build tag 控制能力，协议与 endpoint 角色要区分 | `proxy`、stream transport、安全配置、mux 分层，合法组合受校验 |
| 观测与验证 | 连接/日志/流量/内存接口；CI 存在互通跳过与平台排除 | tracker、API、统计与独立集成测试模块 | Stats/Routing/Handler 服务及协议场景、TUN 测试 |

装配与数据接口的主要依据是 [mihomo adapters](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/constant/adapters.go)、[mihomo executor](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/hub/executor/executor.go)、[sing-box Box](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/box.go)、[sing-box lifecycle](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/adapter/lifecycle.go)、[Xray Instance](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/core/xray.go) 和 [Xray Link](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/transport/link.go)。组选路、API、协议注册及测试的逐项出处见 [mihomo 记录](../research_notes/Rust%20VPN%20内核参考调研/mihomo.md)、[sing-box 记录](../research_notes/Rust%20VPN%20内核参考调研/sing-box.md) 和 [Xray 记录](../research_notes/Rust%20VPN%20内核参考调研/xray.md)。

TUN 比较尤其需要带版本。mihomo 固定源码列出 `system/gvisor/mixed/mips`，配置默认 `Mips`；sing-box 的实际默认栈受 gVisor 构建条件、GSO 与 `IncludeAllNetworks` 等因素影响；Xray 的该入口调用本仓库 `NewStack`，不能仅因依赖表存在 gVisor 就认定 TUN 使用 gVisor。Xray 的 `udp_fullcone.go` 只证明入口以源地址端口建立映射并保留逐包目的地，**不能证明任意出站和远端 NAT 端到端都具有 Full-cone 语义**。([mihomo 栈与默认配置](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/config/config.go)、[sing-tun 固定依赖选择逻辑](https://github.com/SagerNet/sing-tun/blob/040db71fcd33196f1d15708b91eb61e9dc6ab8dd/stack.go)、[Xray 栈接入](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/tun/handler.go)、[Xray UDP 映射](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/tun/udp_fullcone.go#L34))

平台支持也要拆开读。TUN 设备、用户态栈、路由/DNS 操作、防回环和移动端权限各有边界。sing-box 的 `PlatformInterface` 向宿主索取 OpenTun 等服务；Xray Android/iOS 接受 App 创建的 FD。Xray 滚动网页仍称 FreeBSD 需手工路由，但固定源码已有自动路由函数，本轮没有实机裁决其运行效果。([sing-box 宿主接口](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/experimental/libbox/platform.go)、[Xray Android](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/tun/tun_android.go#L24)、[Xray Darwin](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/tun/tun_darwin.go#L147)、[FreeBSD 源码](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/tun/tun_freebsd.go#L638)、[滚动 TUN 网页](https://xtls.github.io/config/inbounds/tun.html))

## 共同数据路径保留流与数据报的区别

下图是研究归纳，用来组织讨论，**不是三个项目共有的字面 API，也不是本项目已批准的架构**。DNS、嗅探、路由在不同项目中有重入、多阶段和旁路，图中只保留主要关系；sing-box 的 TUN 预匹配/包级路径也不能被普通连接路径完全覆盖。依据是 [mihomo 调度](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/tunnel/tunnel.go)、[sing-box 路由](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/route/route.go)、[sing-box 预匹配接口](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/adapter/router.go) 和 [Xray Dispatcher](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/app/dispatcher/default.go)。

```mermaid
flowchart LR
    A[代理监听器或 TUN 适配] --> B[目标与会话元数据]
    B --> C[嗅探与路由决策]
    D[DNS 与 Fake IP 映射] <--> C
    C --> E[出站选择与拨号]
    E --> F[TCP 流或 UDP 数据报转发]
    F --> G[回写 关闭与状态回收]
```

元数据并非一个始终不变的目的地址。mihomo 区分 Host 与 SniffHost；sing-box 保留原始目的地址和 FakeIP 状态；Xray 区分 OriginalTarget、Target、RouteTarget。它们都提示：原始身份、规则匹配依据和实际拨号目标需要可追踪。UDP 还要保留每个数据报的边界、目标和回写信息，首包探测读走的内容必须得到处理。([mihomo Metadata](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/constant/metadata.go)、[sing-box InboundContext](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/adapter/inbound.go)、[Xray session](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/common/session/session.go))

运行状态的变化同样属于数据路径。mihomo 的 executor 有暂停、内部加载与恢复阶段，不能据此承诺原子回滚；sing-box CLI 的 SIGHUP 是关闭旧实例再创建新实例，而固定快照 Clash `PUT /configs` 仅返回成功空响应、PATCH 只切换 mode；Xray API 的组件操作也不能推出整份配置无损替换。**规则更新、节点选择、监听器替换和旧连接处理必须分别定义。**([mihomo executor](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/hub/executor/executor.go)、[sing-box CLI](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/cmd/sing-box/cmd_run.go)、[sing-box configs API](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/experimental/clashapi/configs.go)、[Xray HandlerService](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/app/proxyman/command/command.proto))

## Rust 设计先讨论语义与资源责任

以下是基于上述事实提出的**候选问题**，不是已确认模块、依赖或实施任务。研究价值在于把 Go 实现中隐含的约定转成可讨论的责任，而不是逐行翻译 goroutine、反射和全局状态。

| 讨论对象 | 需要明确的语义 |
| --- | --- |
| 元数据所有权与阶段变更 | 谁能修改嗅探域名、路由目标、拨号地址；原始信息如何保留；异步任务看到哪个版本 |
| 流与数据报 | TCP 半关闭、双向复制与 UDP 多目标/逐包地址分别怎样表达；是否还需要原始 IP 流层级 |
| 缓冲与 UDP 会话 | 包交接后谁释放；NAT key 如何隔离入站/用户；超时、回写映射和关闭排队包由谁负责 |
| 取消与背压 | 上下行错误如何取消另一侧；首包等待与 DNS 超时如何终止；队列满是丢包、等待还是拒绝 |
| 平台宿主边界 | 设备 FD、栈、路由/DNS、防回环、网络切换及退出恢复分别由内核还是宿主持有 |
| 组件与生命周期 | 注册、校验、依赖排序、部分启动失败及逆序清理怎样组织；是否要求同进程多实例隔离 |
| DNS 与路由顺序 | bootstrap、代理服务器解析和业务解析是否分开；Fake-IP 恢复、嗅探、IP 规则、缓存如何配合 |
| 配置替换 | 校验与应用是否分离；失败如何恢复；旧连接使用旧快照还是立即中断；映射与选择状态怎样延续 |

这些问题各有取舍。例如统一接口有利于组合，过度统一会隐藏数据报目标和关闭语义；集中元数据便于匹配，也会扩大可变状态；自有网络栈带来控制能力，同时需要承担协议正确性和平台维护。Rust 的所有权与类型表达能用于刻画这些边界，但本轮没有证据选定 runtime、trait 组织、缓冲池、网络栈、FFI 或配置格式。性能、内存、电量、协议互通和异常恢复仍需在产品范围明确后单独验证。

## 下一轮阅读围绕尚未确认的产品范围

优先追数据流，再研究扩展能力。mihomo 可从 [Metadata](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/constant/metadata.go) 与 [adapters](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/constant/adapters.go) 进入 [tunnel](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/tunnel/tunnel.go)，再读 provider、DNS enhancer 和 executor，重点回答策略、资源与会话的关系。sing-box 可先读 [Box](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/box.go) 与 [registry](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/include/registry.go)，沿 route/conn 跟踪转发，再读 TUN、libbox 平台接口及迁移文档，重点回答平台依赖与生命周期的关系。Xray 可从 [core/xray.go](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/core/xray.go) 进入 [Dispatcher](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/app/dispatcher/default.go) 与 [outbound Handler](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/app/proxyman/outbound/handler.go)，之后对照协议/stream 配置与 TUN，重点回答层之间的契约。

下一轮讨论需要先确定首批 OS、客户端还是网关/服务端、是否首批必须 TUN、VPN 权限和 FD 的拥有者、首批 TCP/UDP 协议，以及配置/API/规则集兼容到哪一层。还要明确配置切换对现有会话的预期。目标若是终端代理式 VPN，与透明承载任意 IP 包的隧道会产生不同边界；在这些范围确定前，不从参考项目的完整功能清单推导本项目必须全部实现，也不建立实现目录或选定具体库。
