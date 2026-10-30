# Xray-core 调研

## 1. 调研对象、版本与证据边界

### 核心结论

Xray-core 适合重点研究协议、传输与安全层的组织方式，以及入站到出站之间的统一分发接口。本次已经核实原生 TUN 入口存在，不能沿用“Xray 只能配合外置 tun2socks”的历史判断。[源码入口](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/tun/handler.go)

### 来源与事实

| 项目 | 本次核查结果 | 一手来源 |
| --- | --- | --- |
| 调研日期 | 2026-10-30，Asia/Shanghai | 本次访问记录 |
| 官方仓库 / 文档 | `XTLS/Xray-core` / Project X | [仓库](https://github.com/XTLS/Xray-core)、[文档](https://xtls.github.io/) |
| 阅读快照 | `main` 与 `v26.10.29` 均解析到 `0afec66085a85191e9dd2a4a6646c7c9a94688d1` | [HEAD API](https://api.github.com/repos/XTLS/Xray-core/commits/HEAD)、[tag API](https://api.github.com/repos/XTLS/Xray-core/commits/v26.10.29)、[固定提交](https://github.com/XTLS/Xray-core/commit/0afec66085a85191e9dd2a4a6646c7c9a94688d1) |
| 本次观察的正式 release | `v26.10.29`，`prerelease=false`，发布于 2026-10-29 08:43:27 UTC | [release](https://github.com/XTLS/Xray-core/releases/tag/v26.10.29)、[release API](https://api.github.com/repos/XTLS/Xray-core/releases/latest) |
| 语言 / module | Go；`github.com/xtls/xray-core`；快照 `go.mod` 声明 Go 1.27 | [go.mod](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/go.mod) |
| 根许可证 | MPL-2.0；本次没有复制上游代码，也没有确定代码复用方式 | [LICENSE](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/LICENSE) |

### 分析与启发

- 以上是本次访问得到的版本快照，不承诺滚动链接在未来仍返回同一版本。后续讨论优先引用固定提交链接。
- “源码存在”与“目标系统已验证可用”需要分别记录；本次只做文档和静态源码阅读，没有构建、运行、抓包或性能测试。

### 未验证项

- 官方文档是滚动网站，本次没有固定文档仓库提交。涉及源码与文档不一致的内容在下文单列。
- 未逐项审查依赖和子目录许可证；未来如讨论直接复用，需要针对具体材料再核查。

## 2. 源码结构与实例生命周期

### 核心结论

Xray 把接口放在 `features/`，实现放在 `app/`，通过配置对象工厂和依赖解析组装实例。协议位于 `proxy/`，网络传输位于 `transport/`；配置的外部形式与内部运行对象之间存在明确转换层。[Feature 接口](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/features/feature.go)、[实例组装](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/core/xray.go)

### 来源与事实

- `main/run.go` 处理配置文件、配置目录及启动选项，经 `core.LoadConfig` 和 `core.New` 得到实例，再调用 `Start()`，退出时 `Close()`；JSON、YAML、TOML 等格式通过各自注册入口接入。[启动路径](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/main/run.go)、[格式注册](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/core/config.go)
- `infra/conf/` 负责把用户配置 `Build` 为内部 protobuf 配置；`core/config.proto` 定义实例及入出站配置，`common.RegisterConfig` 把配置类型关联到构造器。[配置构建](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/xray.go)、[内部配置](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/core/config.proto)、[工厂](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/common/type.go)
- `core/xray.go` 维护 Feature 集合、待解析依赖与运行状态；`RequireFeatures` 使用反射匹配依赖回调。`main/distro/all/all.go` 通过导入注册内置组件，不是运行时加载任意动态插件。[依赖解析](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/core/xray.go)、[组件集合](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/main/distro/all/all.go)
- `common/` 承担缓冲区、会话、地址、计时和多路复用等基础设施；`testing/` 提供测试服务端、mock 和协议场景。[common](https://github.com/XTLS/Xray-core/tree/0afec66085a85191e9dd2a4a6646c7c9a94688d1/common)、[testing](https://github.com/XTLS/Xray-core/tree/0afec66085a85191e9dd2a4a6646c7c9a94688d1/testing)

### 分析与启发

- Rust 可以借鉴“配置解析与校验 → 显式组装 → 启停管理”的边界，是否使用动态 trait 对象、枚举或泛型仍待讨论；没有必要照搬反射式依赖注入。
- `Instance` 并不自动意味着完全隔离：源码注释限制同时运行的 Server 实例，且初始化系统 dialer。若我们要求同进程多实例，需要专门评估全局状态。[相关源码](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/core/xray.go#L23)

### 未验证项

- 尚未逐项审查构造失败、部分启动失败及退出时的资源回收语义；不能据组件接口推断完整事务保证。

## 3. TCP、UDP 与会话元数据如何流动

### 核心结论

核心路径可以概括为：输入适配 → 协议解码/目标提取 → Dispatcher → 路由选择 → 出站 Handler → 协议与网络拨号。TCP 和 UDP 共用分发框架，但 UDP 依靠数据包边界及逐包地址元数据表达，不能当作普通字节流处理。[分发实现](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/app/dispatcher/default.go)、[UDP buffer 元数据](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/common/buf/buffer.go)

### 来源与事实

- 普通 TCP 入站的 `tcpWorker` 接受连接、填充 session，再调用 `proxy.Inbound.Process`。入站协议负责解出目标并调用 `routing.Dispatcher.Dispatch` 或 `DispatchLink`；Dispatcher 返回或接受 `transport.Link`。[worker](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/app/proxyman/inbound/worker.go#L61)、[协议接口](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/proxy.go)、[分发接口](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/features/routing/dispatcher.go)
- Dispatcher 可进行 sniffing、保留首包数据，调用 Router `PickRoute`，取得出站 tag 后交给出站管理器；无命中使用默认出站，但指定的出站 tag 不存在时不会悄悄回落到默认出站。[分发与出站选择](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/app/dispatcher/default.go#L434)
- 出站 Handler 管理协议对象、stream settings、计数器及可选 mux/XUDP，再调用具体出站协议的 `Process`；协议通过 dialer 接到实际网络或指定链路。[出站管理](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/app/proxyman/outbound/handler.go)
- `Link` 由 `buf.Reader` / `buf.Writer` 构成；`buf.Buffer.UDP` 可携带逐包目标。UDP dispatcher 建立受控生命周期的链路，并把返回数据包装为带地址的数据包。[Link](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/transport/link.go)、[Buffer](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/common/buf/buffer.go)、[UDP dispatcher](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/transport/internet/udp/dispatcher.go)
- session 显式区分入站来源、用户、tag，以及出站 `OriginalTarget`、`Target`、`RouteTarget`；sniffing 可以仅影响路由，或覆盖实际目标。[会话定义](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/common/session/session.go)、[覆盖逻辑](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/app/dispatcher/default.go#L324)

### 分析与启发

- 候选设计应单独表达原始 IP、请求域名、嗅探域名、路由目标与实际拨号目标，避免一次覆盖导致信息丢失。
- Rust 所有权模型可以用于明确 buffer 何时交接、何时释放，以及取消/半关闭后谁负责结束上下行任务；接口统一不应抹去数据报语义。

### 未验证项

- 未逐个协议验证 UDP、XUDP 和多目标复用的兼容组合，也未测试背压、长时间空闲和半关闭行为。

## 4. 原生 TUN 的真实边界与平台差异

### 核心结论

固定快照已包含 TUN OS 适配、自有 TCP/IP 栈和连接分发接入。它主要把原始 IP 流量转换成可代理的 TCP/UDP 连接；移动端的 VPN 权限、接口创建与流量导入仍由外部 App 负责。[TUN Handler](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/tun/handler.go)、[平台说明](https://xtls.github.io/config/inbounds/tun.html)

### 来源与事实

- `Handler.Start` 先调用 `NewTun`，再调用本仓库 `NewStack`；`HandleConnection` 把栈产生的连接转为 session 和 Link，最后进入统一 Dispatcher。`Network()` 返回空集合，说明它通过接口接收包，不通过普通监听端口接流量。[创建与接入](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/tun/handler.go#L123)、[连接分发](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/tun/handler.go#L213)
- `stack.go`、`packet.go`、`tcp_lightweight.go` 实现包解析、TCP 状态及重传等逻辑。这一入口实际调用自有 `NewStack`，不能因为 `go.mod` 中出现 gVisor 就推断此 TUN 使用 gVisor。[栈](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/tun/stack.go#L95)、[TCP](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/tun/tcp_lightweight.go)、[包解析](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/tun/packet.go)
- UDP 入口在 `udp_fullcone.go` 以源地址端口为连接映射键，并把每个目的地放入 `Buffer.UDP`；队列有容量限制，满时丢弃。这里只能确认入口实现的 Full-cone 机制，不能由此证明任意代理出站或远端 NAT 都具有相同语义。[映射与队列](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/tun/udp_fullcone.go#L34)

| 平台 | 固定源码中的边界 | 证据 |
| --- | --- | --- |
| Linux | 可创建 `/dev/net/tun` 接口，也支持校验并接入外部 FD；系统路由和 DNS 操作受权限及系统环境约束 | [Linux 实现](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/tun/tun_linux.go#L201) |
| Windows | Wintun 后端；接口、系统路由和防回环配置具有平台实现 | [Windows 实现](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/tun/tun_windows.go#L59) |
| macOS | 未传入 FD 时创建 utun；Darwin 路径也支持外部 FD | [Darwin 实现](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/tun/tun_darwin.go#L147) |
| FreeBSD | 存在原生后端与自动路由函数；出站防回环使用 escape FIB，其前置条件包括 `net.fibs >= 2` | [后端](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/tun/tun_freebsd.go#L27)、[路由实现](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/tun/tun_freebsd.go#L628) |
| Android | App 通过 VpnService 创建接口并传 FD；内核复制描述符接入，不能替代 App 获得 VPN 权限 | [Android 接入](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/tun/tun_android.go#L24)、[官方说明](https://xtls.github.io/config/inbounds/tun.html) |
| iOS | 外部 NetworkExtension 提供 FD，Darwin 实现复制该 FD；接口与流量导入依赖 App | [Darwin FD 分支](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/tun/tun_darwin.go#L147)、[官方说明](https://xtls.github.io/config/inbounds/tun.html) |

- 系统侧 DNS 接管并非所有平台统一行为：Linux 的相关模式依赖 systemd-resolved / `resolvectl`，FreeBSD 使用 `resolvconf`；`autoOutboundsInterface` 用于避免出站重入 TUN。[固定 README](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/tun/README.md)、[Handler 控制器](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/tun/handler.go#L130)
- 发现文档滞后：滚动 TUN 网页仍称 FreeBSD 自动路由须手动配置，但此 SHA 的 `Start` 已调用 `setSystemRoutes`。另，README 的 ICMP 描述偏简化，`stack.go` 除本地 Echo 回复还处理部分不可达和 MTU 错误；不能把它概括成通用原始 IP 转发。[网页](https://xtls.github.io/config/inbounds/tun.html)、[FreeBSD 源码](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/tun/tun_freebsd.go#L638)、[ICMP 实现](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/tun/stack.go#L554)

### 分析与启发

- TUN 设备、用户态协议栈、流量分发、系统路由/DNS、移动端宿主权限应分开讨论。一个 `tun` 开关不足以描述跨平台完成度。
- 自研轻量栈是可研究的实现路线，其协议正确性和维护成本需要独立评估，不能据源码存在就决定照搬或推断性能优于成熟栈。

### 未验证项

- 所有平台结论均来自源码和文档，没有执行系统网络修改或实机验证。移动端应用封装、驱动部署、断网恢复、睡眠唤醒和系统升级兼容仍待后续专题。

## 5. 协议、传输与安全层如何组合

### 核心结论

Xray 的协议配置和 `streamSettings` 分层清楚，但实际组合存在校验约束，并不是任意协议、传输和安全层的笛卡尔积。[协议配置加载器](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/xray.go)、[stream 配置](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/transport_internet.go)

### 来源与事实

- 当前配置注册项包含 SOCKS/HTTP、Shadowsocks、VLESS、VMess、Trojan、WireGuard、Hysteria、MASQUE 等；direct/freedom、block/blackhole、DNS 等也是出站类型。这里只确认该快照的注册与实现存在，不宣称各协议角色和选项完全对等。[注册表](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/xray.go#L27)
- `transport/internet/` 下实现 TCP/RAW、WebSocket、gRPC、HTTPUpgrade、KCP、XHTTP（内部路径 `splithttp`）等；TLS、REALITY 由相应 stream 安全配置接入。REALITY 可用 transport 组合在构建阶段受到检查。[配置转换](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/transport_internet.go)、[安全配置](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/transport_security.go)
- Vision/XTLS 相关处理并非一个普通独立“出站协议”名称；连接状态、padding 和直接复制处理分布在协议公共逻辑及 VLESS 路径中。mux/XUDP 的连接复用则由出站 Handler 管理。[公共协议逻辑](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/proxy.go)、[VLESS 出站](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/vless/outbound/outbound.go)、[复用管理](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/app/proxyman/outbound/handler.go)

### 分析与启发

- Rust 候选架构可分开表达协议编解码、传输、安全握手和复用，并集中校验合法组合；名称分层比“全部做成 outbound trait”更有助于避免概念混杂。

### 未验证项

- 未完成每个协议版本、加密扩展、指纹、回落机制、移动端互操作矩阵；本报告不能作为协议兼容承诺。

## 6. DNS、FakeDNS、路由与动态控制

### 核心结论

DNS 不只是独立查询工具，它参与路由决策、远端连接建立和 FakeDNS 地址恢复。动态 API 提供组件与规则操作；这与整份配置无损热重载是不同的保证。[路由实现](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/app/router/router.go)、[API 配置](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/api.go)

### 来源与事实

- DNS 包含本地解析、UDP/TCP、DoH、DoQ 等 server 实现，以及缓存、静态 hosts 和按域名选择上游的机制；本地与经 Dispatcher 的模式具有不同出站路径。[server 构造](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/app/dns/nameserver.go)、[DNS 主实现](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/app/dns/dns.go)
- FakeDNS 维护地址与域名映射；Dispatcher 结合 fake-IP 识别和 sniffing 决定恢复目标。Router 的 `IPOnDemand` / `IPIfNonMatch` 会影响何时解析域名以匹配 IP 规则，并使用 `SkipDNSResolve` 避免特定递归解析。[FakeDNS](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/app/dns/fakedns/fakedns.go)、[分发器](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/app/dispatcher/default.go)、[路由解析策略](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/app/router/router.go#L201)
- 路由按规则顺序选择；balancer 支持 random、roundrobin、leastping、leastload 等策略，部分策略依赖 observatory 观测结果。geodata 和规则加载在配置/应用层有独立结构。[策略配置](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/router_strategy.go)、[balancer](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/app/router/balancing.go)、[geodata 配置](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/geodata.go)
- gRPC HandlerService 暴露入出站增删、列举、用户管理等操作；RoutingService 支持规则及路由观测相关操作，StatsService 提供流量和系统统计。存在这些操作不能推出所有状态可以事务式切换。[HandlerService](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/app/proxyman/command/command.proto)、[RoutingService](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/app/router/command/command.proto)、[StatsService](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/app/stats/command/command.proto)

### 分析与启发

- 我们应先定义 DNS 查询、DNS 上游 bootstrap、代理服务器域名解析与普通业务路由之间的依赖关系，再讨论 Fake-IP 策略。
- “变更新连接策略”“替换监听器”“保留旧连接”“持久化选择状态”需要分开定义，不能用一个热重载标签代替。

### 未验证项

- 未验证各 DNS 模式的泄漏边界，也未验证规则热更新对已建立连接和缓存的完整影响。

## 7. 工程验证、依赖与建议阅读顺序

### 核心结论

该项目具有配置单元测试、协议场景测试和 OS 相关 TUN 测试。最值得借鉴的是用连接行为和真实边界验证抽象，而不是仅检查配置能否反序列化。[场景测试](https://github.com/XTLS/Xray-core/tree/0afec66085a85191e9dd2a4a6646c7c9a94688d1/testing/scenarios)、[TUN 测试](https://github.com/XTLS/Xray-core/tree/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/tun)

### 来源与事实

- CI 包含格式与 protobuf 一致性检查，测试矩阵覆盖 Windows、Ubuntu、macOS，并运行 `go test`；这是工作流定义，本次没有核查每次实际运行结果。[工作流](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/.github/workflows/test.yml)
- `go.mod` 明列 protobuf/gRPC、REALITY、uTLS、QUIC、Wintun、WireGuard、netlink 等依赖；原生内核能力包含本仓库代码与外部库共同承担的部分。[依赖清单](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/go.mod)
- TUN 测试包含 FD 生命周期、栈行为、UDP 队列及平台 DNS/路由等文件；协议场景覆盖 VLESS、VMess、Shadowsocks、DNS、传输等。[TUN 目录](https://github.com/XTLS/Xray-core/tree/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/tun)、[场景目录](https://github.com/XTLS/Xray-core/tree/0afec66085a85191e9dd2a4a6646c7c9a94688d1/testing/scenarios)

### 分析与启发

建议阅读顺序：先 `main/run.go → infra/conf/xray.go → core/xray.go` 建立组装模型，再读 `proxy/proxy.go → features/routing/dispatcher.go → app/dispatcher/default.go → app/proxyman/outbound/handler.go` 追数据流；之后独立阅读 `proxy/tun/handler.go → stack.go → udp_fullcone.go → OS 后端`，最后对照协议与测试。上述路径的固定链接已在前文提供。

### 未验证项

- 本次未执行上游测试或基准测试，没有性能排名、覆盖率或安全审计结论。

## 8. 留给本项目的讨论问题

### 核心结论

以下只是从调研提出的候选问题，不是已确认设计，也不授权开始实现。

### 来源与事实

- 讨论依据分别是统一 Dispatcher、显式会话目标、平台化 TUN 与 API 组件操作；对应事实见前文固定源码。[Dispatcher](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/features/routing/dispatcher.go)、[会话](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/common/session/session.go)、[TUN](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/tun/handler.go)

### 分析与启发

1. 产品首先是代理内核、TUN 驱动的终端 VPN，还是需要透明搬运任意 IP 包的隧道？三者的数据语义不同。
2. 首批目标系统是否包含移动端？VPN 权限和设备 FD 的所有权由谁承担？
3. UDP 是否要求多目标、Full-cone、QUIC 业务和统一超时语义？怎样证明这些语义跨出站成立？
4. 是否需要嵌入式库与同进程多实例？全局 DNS/dialer/路由控制如何隔离？
5. 协议兼容优先到什么层级：基本握手、传输组合、指纹，还是完整配置兼容？
6. 配置更新需要怎样的失败回滚与旧连接保留规则？

### 未验证项

- 上述问题均需结合 mihomo、sing-box 调研与用户的产品范围讨论后决定；本报告没有选择 Rust runtime、协议栈、模块目录或具体依赖。
