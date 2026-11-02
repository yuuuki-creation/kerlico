# 节点与共享目标访问接口

更新日期：2026-11-02（Asia/Shanghai）

本文描述节点工厂装配、凭据隔离清单、`Local`/`Remote` 三类数据路径以及命名出站服务终因与独立回收线程（`ServiceRetirement`）的实现契约。

## 装配与凭据隔离

- **`NodeFactory::build(NodeBuildContext)`**：
  - `options` 包含协议共享载体、安全参数与限制；`native_credentials` 按节点 `members` 顺序提供各成员原生认证材料。
  - `credentials(rows)` 要求候选数量与成员数一致，并绑定同一节点 `CredentialIssuer`。组合协议（如 ShadowTLS）通过 `with_options` 保持同一签发者，外层保护秘密不替代内层用户鉴别。
- **`InboundProtocol` 与鉴权边界**：
  - 提供 `credential_manifest`、监听能力声明及 `handle` / `handle_udp` / `handle_virtual`。
  - 入站在完成真实协议线格式鉴别取得 `Verified<T>` 后，调用 `IngressBinding::authenticated` 获得 `PeerSession`；鉴权前无法发起目标拨号。
  - `Local` 入口仅通过 `IngressBinding::local` 创建 `Source::Local`，不生成管理用户，也不作为远端节点的无认证旁路。
- **`CredentialManifest` 隔离校验**：
  - 显式区分成员认证槽（`Authentication { slot }`）与外层保护材料（`Protection`）。
  - 配置编译期要求每个成员具有有效认证行，并在全部入口间查重认证域与保护域，拒绝跨节点秘密复用。

## 三类数据路径与 `Local` / `Remote` 分支

所有入站取得的 `PeerSession` 共享同一个 `Dispatcher`：

1. **`TargetPolicy::Local`（本节点负责目标策略）**：
   - 仅在 `Local` 路径调用本地网站 `Resolver`。单栈模式（`ipv4-only` / `ipv6-only`）仅保留同族候选并在字面 IP 不兼容时直接拒绝；双栈模式（`dual-stack`）默认 IPv4 优先。
   - TCP 在发送业务数据前按剩余总预算依次尝试候选地址；固定 UDP 选择首个匹配目标；多目标 UDP 关联首次访问某目标时解析并缓存绑定（每关联上限 256 个目标，达上限时明确拒绝）。
2. **`TargetPolicy::Remote`（远端代理负责目标策略）**：
   - 将原始域名或字面 IP 与端口交由所选代理编码，本地网站 `Resolver` 调用次数为 0（代理载体自身的端点解析由底层连接器独立完成）。
   - 远端建立或转发失败直接结束当前尝试，不切换网站地址族、不换代理、不回退本地直连；未知远端目标绑定在 `FlowRecord` 中保持 `TargetBind::Unknown`。
3. **UDP 通道拆分语义**：
   - 业务层 `FixedUdpFlow` 与 `UdpAssociation` 拆分为独立收发半部与唯一 `FlowCompletion`。
   - 固定 UDP 接收器的 `peer_addr` 反映业务目标地址；多目标关联回包携带真实业务来源，空负载作为完整 0 字节数据报传递。

## 载体计量、命名服务终因与回收收据

### 1. 载体字节计量（`CarrierUsage`）

- `ServiceContext` 与 `IngressBinding` 提供 `record_carrier(sent_bytes, received_bytes)` 与 `carrier_usage()`，分别按命名出站或入站节点累计已确认的底层载体字节（使用饱和加法，溢出不回绕）。
- 载体流量与 `Dispatcher` 的唯一用户业务账本分开统计，不相互累加（当前 `protocol-wireguard` 已接入上报 Socket 确认的 UDP 载荷字节）。

### 2. 命名服务首因固定（`ServiceFailure`）

- `ServiceContext::fail(ServiceFailure)` 先固定该命名出站服务的首个致命失败原因，再触发服务级取消；后续失败或正常关闭不覆盖首因。
- `ServiceFailure` 仅包含可复制的公共错误类别与静态说明（不含动态上游文本或敏感信息），通过 `ServiceStatus::failure` 提供只读查询。
- 当 `FlowLease` 仍处于 `Opening` 时，终因归因同时检查请求、Peer、节点与所选命名服务状态：正常请求/Peer/节点取消记为 `Cancelled`；命名服务超时记为 `Timeout`，服务协议失效记为 `Failed`。

### 3. 独立回收线程与退休收据（`ServiceRetirement`）

- **按需创建回收线程**：命名服务在首次登记后台任务（`spawn` 或 `spawn_blocking_tracked`）前按需创建独立回收线程；零任务服务不创建线程。
- **固定关闭期限与两阶段中止**：`retire(deadline)` 同步固定首次关闭截止时间并停止新任务登记，由回收线程独立推进协作取消、在首次期限 80% 处发出强制 `abort` 并等待真实 `join`。`shutdown(deadline)` 仅约束当次调用的等待时间，中途丢弃等待 Future 不会中断后台回收，重试也不会延长首次期限。
- **`ServiceRetirement` 收据**：`Engine::service_retirements()` 与 `EgressRuntime::service_retirements()` 提供独立收据；`wait()` 等待全部登记任务与回收线程完成 `join` 后返回最终 `ShutdownReport`，`is_finished()` 仅在真实 `join` 完成后返回 `true`。
- **Unwind 与重入保护**：任务 `JoinError` 持有的用户 panic 对象在释放注册表内部锁之后析构，并带有两层受限 unwind 保护边界：若原 panic 对象析构时再次 panic，尝试析构新 panic 对象；若第二次析构仍 panic，则将该对象隔离保留在服务注册表中不再析构，收据保持未完成且 `shutdown` 返回非 clean 报告，确保回收线程不因恶意或缺陷析构而崩溃，其他任务继续正常 `join`。
