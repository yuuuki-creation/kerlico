# 核心接口

更新日期：2026-11-02（Asia/Shanghai）

本文描述 `kerlico-core`、`kerlico-egress` 与 `kerlico-engine` 当前源码实现的运行装配、身份鉴别、业务流完成权（`FlowOpen`）、唯一业务计量与生命周期契约。

## 运行装配

- **`Registry::prepare(Config)`**：校验 JSON v2 配置、编译原生凭据与证书资产，返回不可克隆的 `PreparedConfig`。`OutboundFactory::compile` 返回 `OutboundPlan`（含 `Capabilities`、`TargetPolicy` 与一次性启动闭包），此阶段不创建运行后端、监听器或网络任务。
- **`Engine::bind(PreparedConfig)`**：消费装配计划，构造唯一 `EgressRuntime` 与私有 `Dispatcher`。每个命名出站计划调用一次 `start(ServiceContext)`，随后绑定全部入站监听器。节点仅保存入站协议、监听器与配额，不各自持有 `Outbound`；本地固定转发同样接入唯一 `Dispatcher`。

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
