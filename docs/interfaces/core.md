# 核心接口

更新日期：2026-11-07（Asia/Shanghai）

本文描述 `kerlico-core`、`kerlico-net`、`kerlico-egress` 与 `kerlico-engine` 当前源码实现的运行装配、拨号选项与链式代理、通用复用与 UoT、身份鉴别、业务流完成权（`FlowOpen`）、唯一业务计量与生命周期契约。

## 运行装配

- **`Registry::prepare(Config)`**：校验 JSON v2 配置、编译原生凭据与证书资产，返回不可克隆的 `PreparedConfig`。`OutboundFactory::compile` 在 `with_compile_dialer` 注入的 `DialerOptions` 上下文中执行，返回 `OutboundPlan`（含 `Capabilities`、`TargetPolicy` 与一次性启动闭包），此阶段不创建运行后端、监听器或网络任务。
- **`Engine::bind(PreparedConfig)`**：消费装配计划，构造唯一 `EgressRuntime`、共享 `DetourTable` 与私有 `Dispatcher`。每个命名出站计划调用一次 `start(ServiceContext)`，并登记到 `DetourTable` 供链式拨号（`detour` / `dialer-proxy` / `proxySettings`）解析上游出站，随后绑定全部入站监听器。节点支持 `accept_proxy_protocol` 在外层监听器剥离 PROXY protocol v1/v2 头并更新观测来源与本地地址。

## 出站套接字工厂

出站的全部载体套接字经 `kerlico_core::DialerOptions` 创建（`crates/core-api/src/dialer.rs`）。出站在 `OutboundFactory::compile` 中调用一次 `current_compile_dialer()` 取得选项并保存，运行期按保存的选项建套接字。`crates/core-api/tests/socket_factory_lint.rs` 扫描生产代码，出站直接调用 `TcpStream::connect`、`UdpSocket::bind`、`TcpSocket::new_v4/v6` 或 `socket2::Socket::new` 时测试失败；入站监听、本机回环与用户态协议栈在该测试的 `ALLOWED` 表中逐项写明原因。

| 方法 | 用途 |
| --- | --- |
| `connect(&Destination) -> BoxStream` | 到代理端点的 TCP。配置 `detour` 时经上游出站的 `connect_tcp`；否则解析域名，按 RFC 8305 交错地址族，以 `fallback_delay`（默认 300ms）为间隔竞速 |
| `connect_addr(SocketAddr) -> TcpStream` / `tcp_socket(SocketAddr)` | 字面地址的操作系统 TCP，不处理 `detour` |
| `udp_peer(&Destination) -> UdpPeer` | 固定对端 UDP（QUIC、WireGuard、SS UDP 等）。配置 `detour` 时 `peer` 是本机回环中继，中继经上游出站的 `connect_udp` 固定目标通道转发，服务端域名交给上游解析；`relay` 句柄丢弃即停止中继 |
| `udp_socket` / `udp_socket_for` / `udp_socket_dual` | 多对端 UDP，不处理 `detour` |

每个套接字施加 `routing_mark`（Linux `SO_MARK`）、出口网卡（Linux `SO_BINDTODEVICE`，macOS `IP_BOUND_IF`）、`inet4_bind_address` / `inet6_bind_address`、`tcp_fast_open`（Linux `TCP_FASTOPEN_CONNECT`）、`mptcp`（Linux `IPPROTO_MPTCP`，内核不支持时改用普通 TCP，与 Go 相同）与 Keep-Alive。选项施加失败时返回错误。当前平台不支持的选项在配置加载阶段拒绝（`DialerOptions::validate_platform`）。`auto_detect_interface` 每次建套接字时读取 `/proc/net/route` 与 `/proc/net/ipv6_route` 的默认路由网卡，结果缓存 1 秒，跳过本配置的 TUN 网卡。

`OutboundFactory::supports_detour()` 默认 `false`；全部载体套接字都经 `connect` / `udp_peer` 建立的出站覆盖为 `true`。为 `false` 的出站配置 `detour` 时加载失败。下列组合同样在加载阶段拒绝 `detour`：

| 出站 | 原因 |
| --- | --- |
| Tailscale、ZeroTier | 多对端 UDP（DERP、直连打洞、根服务器），无法用固定目标中继表示 |
| EasyTier | 上游连接管理器按 URL 自建套接字，没有注入点；同时拒绝 `routing_mark`、出口网卡、源地址等任何拨号选项 |
| Hysteria、Hysteria2、TUIC 的端口跳跃 | 中继只转发到固定服务端端口 |
| VLESS / Trojan / VMess 的 XHTTP HTTP/3 | QUIC 套接字由传输库同步创建，无法接入中继；不带 `detour` 时经工厂建套接字 |
| WireGuard 显式 `bind` | 显式绑定的套接字直连对端 |

WARP 设备（`kerlico-device`）的能力探测、注册与 UDP 载体使用全局默认拨号选项（`PreparedConfig::global_dialer`）。DNS 直连上游（UDP、TCP、DoT、DoH HTTP/2 与 HTTP/3、DoQ、系统上游）同样经全局默认选项建套接字（`EgressPlan::global_dialer` 经 `DnsDialer::sockets` 传入）；`#出站`、`RULES` 与 `respect-rules` 上游经对应出站拨号，套接字带该出站的选项。代理服务器域名经 `kerlico_core::lookup_host` 走 DNS 管线后再由工厂连接。`dns.listen` 是入站监听，不经工厂。本地出网（`Local`）对多个候选地址同样按 RFC 8305 竞速，间隔取直连出站的 `fallback_delay`（`Outbound::fallback_delay`）。

测试：`kerlico-core` 的 `dialer-probe` 特性记录工厂套接字从内核读回的标记与 TFO 状态。`apps/kerlico/tests/dialer_marks.rs` 对每个 Mihomo 样例出站注入唯一标记，启动并连接一次后断言出现带该标记的套接字；`tools/dialer_netns_e2e.py` 在临时网络命名空间中验证 `ip rule fwmark` 按标记选路，以及 Hysteria2、WireGuard 经 SOCKS5 出站 `detour` 的 UDP 承载。

## 身份与访问

| 类型 / 接口 | 契约说明 |
| --- | --- |
| `UserId` | 持久管理 UUID，与协议线格式 UUID、用户名及密码分离 |
| `CredentialIssuer` | 配置编译期建立的节点凭据签发者，绑定配置代次、成员凭据代次与单次运行实例 |
| `CredentialSet<C>` | 原生候选凭据与不透明成员槽；验证必须唯一命中一行，歧义直接拒绝 |
| `Verified<T>` | 同一次真实线格式鉴别命中的成员与已解码握手状态，内部字段私有 |
| `IngressBinding` | 节点的鉴别入口；不含直接拨号方法 |
| `IngressBinding::authenticated` | 校验签发者、节点、运行实例与代次后，返回 `PeerSession` 与已解码状态 |
| `IngressBinding::local` | 仅显式 `Local` 入口可调用，签发 `Source::Local`，不生成管理用户 |
| `PeerSession` | 唯一业务访问句柄，绑定可信来源、客户端观测地址及节点取消域 |
| `OriginalTarget` | 分别保存经过校验的目标与安全原始表示 |
| `CredentialManifest` | 将 `Authentication` 成员槽与外层 `Protection` 秘密分离，编译期拦截跨入口秘密复用 |

- **准入停止（`IngressBinding::stop_admission`）**：不可逆且幂等，停止该绑定创建新 `PeerSession` 以及新 TCP 流、固定 UDP 流与多目标 UDP 关联。`local`、`authenticated` 与 `Dispatcher` 路由均复核同一准入状态；先于关闭通过准入的并发操作继续在原节点关闭预算内收尾，关闭后发起的建立请求直接拒绝且不创建新账本。
- **UDP 关联准入单位**：准入检查作用于 `UdpAssociation` 的创建；已接纳关联的 `send_to` 在原出站、限额、取消域与排空截止时间约束下仍可访问多个目标（保持 Full Cone 语义）。

## 数据通道、完成权与计量

### 1. `FlowOpen` 与唯一完成权

`PeerSession` 与 `SessionDispatcher` 的 `connect_tcp` / `connect_udp` / `associate_udp`（及接收 `OriginalTarget` 的 `open_tcp` / `open_udp`）分别返回 `FlowOpen<TcpFlow>`、`FlowOpen<FixedUdpFlow>` 与 `FlowOpen<UdpAssociation>`：

| 业务通道类型 | `into_parts()` 拆分结果 |
| --- | --- |
| `TcpFlow` | `TcpFlowIo`、`FlowCompletion` |
| `FixedUdpFlow` | `FixedUdpSender`、`FixedUdpReceiver`、`FlowCompletion` |
| `UdpAssociation` | `AssociationSender`、`AssociationReceiver`、`FlowCompletion` |

- **惰性准入与建账**：`Dispatcher` 通过 `FlowOpen::deferred` 在首次 `poll` 时执行准入检查、选路与 `FlowLease` 建账；尚未 `poll` 即被丢弃或调用 `finish` 的操作不启动后端且不生成记录。
- **终因报告顺序**：进入 `Opening` 后，`FlowOpen`（成功后移交 `FlowCompletion`）持有该流唯一完成权。`finish(self, outcome)` 先执行报告回调再释放建立 Future：
  - TCP 双向正常 EOF 使用 `DuplexEof`，协议定义的整会话正常结束使用 `ProtocolEnd`，超时/取消/错误使用 `Failed(FlowFailure)`；
  - 处于 `Opening` 阶段且尚无已知失败时，`ProtocolEnd` 复核请求、Peer、节点与命名服务四个取消域，任一域已取消则记录 `Cancelled`；
  - 未显式报告即 Drop 使用 `ClosedByCaller` 兜底，panic 展开使用 `Failed(FlowFailure::Failed)` 兜底；
  - 首次观察到的失败原因固定后不被后续清理取消覆盖，待所有 I/O 半部与完成权释放后提交最终记录。
- **转发辅助函数**：`relay_tcp(front, TcpFlow, idle, cancel)` 持有完成权执行双向转发；父载体持有完成权时子任务可使用 `relay_tcp_io(front, &mut TcpFlowIo, idle, cancel)`；`relay_streams` 仅用于底层载体或测试。

### 2. 目标绑定元数据（`TargetBind`）

底层 `Outbound::connect_tcp` 与 `DeviceNetwork::connect_tcp` 返回 `OpenedTcp { stream, info }`：

- `TcpConnectInfo` 记录 `TargetBind::Known { endpoint, evidence }`（`LocalSocket` 或 `PeerReported`，如本地直连 Socket 绑定或上游 SOCKS `BND` 报告）或 `TargetBind::Unknown`。
- 无可靠线格式证据的远端代理保持 `Unknown`，不用代理端点或监听地址代填，也不触发额外本地 DNS。

### 3. 唯一业务计量与取消唤醒

- **单次计量包装**：`Dispatcher` 仅包装一次业务 I/O。TCP 按成功读交付与成功写的实际字节数累加；UDP 按成功发送或交付的完整数据报累加（零字节空包仅增加包数）。载体握手、TLS 与复用控制帧不计入业务流量。
- **读写独立取消等待器**：TCP 业务流与物理 `PeerIo` 分别为读、写方向维护取消等待器；取消后返回携带 `Error::Cancelled` 的不可重试 `ConnectionAborted`，确保 `write_all` 与 `read_exact` 立即退出而不因 `Interrupted` 循环重试。
- **错误还原**：`FlowFailure::from_io_error` 精确识别错误源中的 `Error::Cancelled` 与 `Error::Timeout`，普通系统 `ConnectionAborted` / `TimedOut` 保持为 I/O 失败。
- **内存态查询（`Engine::telemetry`）**：`usage()` 从同一账本投影 Engine、管理用户、节点与命名出站四维用量；`records(after, limit)` 返回最多 4096 条进程内保留记录。

## 预算、任务与确定性回收

- **`ConnectContext` 与 `ResourceKey`**：`ConnectContext` 持有请求取消、超时、绝对建立 deadline、`ResourceKey`（命名出站 + 来源成员/Local + 凭据代次）以及 Peer/节点/服务取消域；`with_timeout` 仅能收紧预算，不可延长原 deadline。
- **物理连接租约（`PeerLease`）**：共享全局与节点两层并发配额及 Peer 取消域；物理 I/O、`PeerSession` 与 `Dispatcher` 流租约共同持有引用，HTTP 升级 handler 返回不会提前取消底层 I/O 或归还配额，最后一个引用释放时归还一次配额。
- **节点任务（`NodeTasks`）**：按 `NodeId` 追踪节点派生任务，独立于单个 Peer 取消；任务 panic 仅取消所属节点，不影响其他节点或命名出站。
- **命名服务回收（`ServiceContext` / `EgressRuntime`）**：
  - `Engine` 关闭时先停止入站准入并并行排空各节点，随后关闭 `EgressRuntime` 下的命名服务。
  - 首次进入关闭时固定绝对 `deadline`，中途丢弃等待 Future 不会丢失后台 `JoinSet`，重试时继续等待同一批任务。
  - `NodeEvent::ForcedCleanup` 仅在外层 handler 与实际节点派生任务均完成 `join` 且清理无失败后计入公开统计。
