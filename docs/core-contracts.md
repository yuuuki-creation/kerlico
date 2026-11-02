# 核心类型、接口与依赖契约

更新日期：2026-11-02（Asia/Shanghai）

本文定义 `kerlico` 跨模块交互的核心标识、阶段元数据、服务契约与所有权规则。当前源码的公开类型与签名见 [核心接口](interfaces/core.md) 与 [节点与共享目标访问](interfaces/node-egress.md)。

## 装配与转发分离

- **装配期（Compile / Prepare / Bind）**：配置解析、工厂注册、凭据隔离检查、依赖校验与服务计划生成在启动阶段一次性完成（`Registry::prepare` → `Engine::bind`）。
- **转发期（Run）**：连接建立与数据转发直接使用已绑定的服务句柄（`IngressBinding`、`PeerSession`、`Dispatcher`），热路径不重复查找协议名称或解析 JSON 配置。

`core-api` 仅定义跨 crate 的最小公共契约，具体协议握手、传输状态与缓存留在各自 crate 内部。

## 核心标识与作用域

| 标识 / 类型 | 含义与隔离规则 |
| --- | --- |
| `NodeId` | 服务端入站节点或本地入口的唯一标识；IPv4 与 IPv6 节点分别建立 |
| `OutId` | 命名出站实例的唯一标识；每个命名出站在单个 `Engine` 运行期内只构造一次 |
| `UserId` | 管理域内持久唯一的用户 UUID，与可改用户名及协议线格式凭据（`native_credential`）分离 |
| `CredentialIssuer` / `Verified<T>` | 节点配置编译期绑定的凭据签发者与真实线格式鉴别结果；防止网络自报身份伪造可信用户 |
| `CredentialManifest` | 将认证域（`Authentication`）与外层保护域（`Protection`）显式分离，拒绝跨节点复用秘密 |
| `PeerSession` | 入站完成鉴别后取得的唯一业务访问句柄，绑定可信来源（`UserId` 或 `Local`）、观测地址与节点取消域 |
| `ResourceKey` | 包含命名出站实例、来源成员（或 `Local`）与凭据代次；共享出站连接池与会话票据按此键分区 |
| `FlowId` / `FlowLease` | 一次 TCP 流、固定 UDP 通道或多目标 UDP 关联的唯一计量与生命周期租约 |

## 目标信息按阶段保留

会话各阶段传递明确的目标类型，避免用单个可变字段覆盖原始请求：

| 阶段信息 | 产生位置 | 用途与边界 |
| --- | --- | --- |
| 原始请求目标 (`OriginalTarget`) | 入站协议解码 | 保留经过校验的目标域名/IP、端口及安全原始表示，作为远端透传与访问记录的基准 |
| 映射恢复 / 嗅探观察（规划） | Fake-IP 恢复 / 嗅探器 | 记录恢复域名或嗅探到的 TLS/HTTP 域名，与原始入口目标分开保存 |
| 路由与策略分支 (`TargetPolicy`) | `Dispatcher` / `routing` | 区分 `Local`（按节点 `FamilyMode` 本地解析选路）与 `Remote`（保留原目标透传给远端代理） |
| 实际目标绑定 (`TargetBind`) | `net` / 出站连接器 | 记录 `Known`（本地直连 Socket 绑定或 SOCKS `BND` 报告）或 `Unknown`，不反向覆盖 `OriginalTarget` |

## 跨模块核心契约

| 契约 | 提供方 / 调用方 | 职责边界 |
| --- | --- | --- |
| `OutboundFactory` / `NodeFactory` | 各协议 crate / `config` | 解码协议私有 `options` 与 `native_credential`，声明 `Capabilities`、`TargetPolicy` 与 `CredentialManifest` |
| `IngressBinding` | `egress` / 入站节点 | 提供 `authenticated(Verified)` 与 `local()` 签发 `PeerSession`；支持幂等 `stop_admission()` 停止新准入 |
| `SessionDispatcher` / `PeerSession` | `egress` / 入站协议 | 提供 `connect_tcp`、`connect_udp`、`associate_udp`，返回带唯一完成权的 `FlowOpen<T>` |
| `Outbound` | 各协议或 `net` / `egress` | 根据 `ConnectContext` 建立底层流或数据报通道；不直接决定入站节点身份 |
| `ServiceContext` / `NodeTasks` | `core-api` / 出站服务与节点 | 分别追踪命名出站后台任务与节点派生任务，管理首因失败记录与带截止时间的协作/强制回收 |
| `Telemetry` | `egress` / `engine` | 在逻辑业务通道唯一计量上传/下载字节，维护有界 `FlowRecord` 并按 Engine/用户/节点/出站四维投影 |
| `Router` / `Resolver` / `Platform` | 规划模块 / `egress`、`net` | 规则匹配、独立 DNS/Fake-IP 解析与宿主平台设备/防回环保护接口 |

## 能力声明（`Capabilities`）

协议模块通过 `Capabilities` 显式声明所支持的数据语义，配置编译期据此拦截不兼容组合：

- **流与半关闭**：是否支持 TCP 出站及远端写关闭传播（`tcp_eof`，供 `require_remote_eof` 校验）。
- **数据报模型**：区分固定单目标 UDP（`FixedUdpFlow`）与同 Socket 多目标 UDP 关联（`UdpAssociation`）。

## 所有权、取消与错误处理

- **完成权与计量唯一性**：`FlowOpen` 与拆分后的 `FlowCompletion` 持有该业务流唯一的结束报告权（`DuplexEof`、`ProtocolEnd`、`Failed(FlowFailure)`），先固定真实首次终因，待 I/O 半部释放后提交终态。
- **读写独立取消唤醒**：TCP 业务流与物理 Peer I/O 的读写半部分别保存取消等待器，取消后返回携带 `Error::Cancelled` 的 `ConnectionAborted`，防止 `write_all` / `read_exact` 陷入重试循环。
- **分层取消域**：请求级、Peer 级、节点级与命名出站服务级取消域相互独立；单次请求超时或单节点排空不会终止共享命名出站服务。

## 关联文档与借鉴依据

- **细化文档**：[实现核心接口](interfaces/core.md) · [数据路径](data-paths.md) · [运行与配置生命周期](runtime-lifecycle.md)
- **上游借鉴**：关联 [借鉴映射](../reference/design-map.md) 的 `REF-001`（目标演进）、`REF-002`（流/包语义）、`REF-003`（工厂与装配）与 `REF-005`（能力分层）。
