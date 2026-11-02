# 运行、配置更新与资源生命周期

更新日期：2026-11-02（Asia/Shanghai）

本文定义 `Engine` 与共享服务的启动、排空、取消、任务回收及未来在线更新的资源生命周期规则。当前源码的生命周期实现细节见 [核心接口](interfaces/core.md) 与 [节点与共享目标访问](interfaces/node-egress.md)。

## 启动、运行与排空阶段

| 阶段 | 核心行为 | 失败或退出处理 |
| --- | --- | --- |
| 1. 编译校验 (`Registry::prepare`) | 解析 JSON v2 配置、校验账户与跨节点凭据隔离、编译各出站计划（`OutboundPlan`） | 纯内存校验，不绑定端口、不启动后台任务或修改网络 |
| 2. 绑定与启动 (`Engine::bind`) | 构造唯一 `EgressRuntime` / `Dispatcher`，启动各命名出站服务，绑定全部入站监听器 | 任一步骤失败时，按逆序主动退休（`retire`）已启动的命名出站服务并汇总清理报告 |
| 3. 运行接纳 (`Engine::run`) | 打开入站准入，接纳客户端连接与会话，由 `NodeTasks` 与 `ServiceContext` 跟踪派生任务 | 监听停止信号（`Ctrl-C` / `SIGTERM`）或外部 `CancellationToken` |
| 4. 停止准入 (`Quiescing`) | 调用各绑定 `IngressBinding::stop_admission()`，停止接纳新连接与新逻辑流 | 已通过准入的活跃会话进入有限排空阶段 |
| 5. 并行排空 (`Draining`) | 各节点在首次关闭固定的绝对截止时间（`drain_timeout_ms`）内并行排空活跃会话 | 达到协作阶段上限后对残留节点任务发出 `abort` 并等待真实 `join` |
| 6. 服务回收 (`Stopping`) | 节点排空完成后关闭 `EgressRuntime` 下的命名出站服务，由独立回收线程推进任务 `join` | 返回包含超时、panic 与强制回收计数的 `ShutdownReport` |

## 资源所有权与生命周期隔离

| 资源对象 | 唯一所有者 | 使用方持有方式 | 释放与回收条件 |
| --- | --- | --- | --- |
| TCP / UDP 监听 Socket | `Engine` 节点运行任务 | 入站循环独占，派生连接持有 `PeerLease` | 收到停止信号后立即停止 `accept` |
| 节点派生任务 (`NodeTasks`) | `Engine`（按 `NodeId` 独立持有） | 入站协议通过 `InboundContext.tasks.spawn_tracked` 登记 | 节点停止准入后，在固定绝对期限内协作排空、强制 `abort` 并完成 `join` |
| 全局 `Dispatcher` 与命名出站表 | `Engine` 装配的 `EgressRuntime` | 各节点通过 `IngressBinding` / `PeerSession` 共享引用 | 所有节点完成排空后统一关闭 |
| 命名服务后台任务 (`ServiceContext`) | 对应命名出站服务与独立回收线程 | 出站实现通过 `spawn` / `spawn_blocking_tracked` 登记 | `retire(deadline)` 触发后，由服务回收线程推进 80% 期限 `abort` 与最终 `join` |
| 运行期业务计量 (`Telemetry`) | `Dispatcher` | 每条业务流持有唯一 `FlowLease` / `FlowCompletion` | 最后 I/O 半部与完成权释放时提交终态记录 |
| 设备级出口 (`DeviceLease` / 规划 WARP) | 设备资源层 | `Dispatcher` 与底层连接器借用引用 | 原生接口与规划中的设备级共享 WARP 不随单节点或单 `Engine` 退出而关闭 |

## 分层取消域与确定性回收

1. **四级取消域分离**：
   - **请求级（`ConnectContext.cancel`）**：仅取消单次建立或单条逻辑流。
   - **物理连接级（`PeerLease`）**：共享全局与节点两层并发配额，仅在最后一个关联引用（含升级后的异步流）释放时取消并归还配额。
   - **节点级（`NodeId` 取消根）**：取消所属节点的监听与会话，不影响其他节点或共享命名出站。
   - **命名服务级（`ServiceContext`）**：由 `EgressRuntime` 管理；通过 `ServiceContext::fail(ServiceFailure)` 固定首个致命原因（如 Tor bootstrap 超时或协议过时），后续请求读取同一首因。
2. **防中断与防死锁回收**：
   - `NodeTasks` 与 `ServiceContext` 在首次进入关闭时固定绝对 `deadline`；若外部调用方中途丢弃等待 Future，后台真实 `JoinSet` 与回收线程不会丢失，后续通过 `ServiceRetirement::wait()` 重试仍继续等待同一批任务并保持原定截止时间。
   - 任务 `JoinError` 中的用户 panic 对象在释放内部锁之后再执行析构与唤醒，并设有双重 unwind 保护边界，防止析构重入或二次 panic 导致回收线程死锁或提前终止。

## 在线配置更新规划（未来扩展）

当前版本采用完整进程启动与停止；未来支持在线配置更新时按配置代次（`ConfigGeneration`）分级开放：

- **新老会话代次隔离**：入站在接纳会话时固定配置代次；已有 TCP 连接与活跃 UDP 关联保持原代次的已选出站，不因规则更新中途切换代理。
- **未支持变更显式返回 `RequiresRestart`**：涉及监听端口、底层设备或不支持热替换的资源变更时，在准备阶段明确返回需要重启，不执行半生效修改。

## 关联文档与借鉴依据

- **细化文档**：[核心接口](interfaces/core.md) · [节点与共享目标访问](interfaces/node-egress.md) · [核心契约](core-contracts.md)
- **上游借鉴**：关联 [借鉴映射](../reference/design-map.md) 的 `REF-003`（分阶段装配）、`REF-006`（映射状态）、`REF-007`（更新边界）与 `REF-008`（平台资源）。
