# TUIC v4/v5 双端接口

2026-11-02共享运行迁移已编写，尚未编译、格式检查或测试。本文保留的历史通过记录只对应原输入，不代表当前整树已验收。

配置模式为`version:2`。节点的`members`引用管理账户`user_id`，分别保存`credential_epoch`与`native_credential`。管理用户名、管理密码摘要和协议凭据互不代用。节点工厂接收`NodeBuildContext`，鉴权前只持`IngressBinding`，鉴权后使用`PeerSession`访问共享Dispatcher。

v4每条成员凭据为`{"token":"synthetic-token"}`，v5为`{"uuid":"00000000-0000-4000-8000-000000000001","password":"synthetic-password"}`。节点options不再接受token/tokens/uuid/password/users。真实v4认证摘要或v5 TLS exporter命中成员，连接内TCP流与UDP关联沿用该可信用户。

出站工厂通过`compile`校验配置与资产，返回一次性`OutboundPlan`；`start(ServiceContext)`才创建命名运行实例。一个Engine内每条命名出站只有一个实例，池按`ConnectContext.resource_key()`的服务、成员和凭据代次分区。持久任务登记到ServiceContext，shutdown停止并等待自身资源；单个请求或节点不关闭共享出站。使用TLS的共享出站不跨成员复用恢复票据。

成员池的外层表只在查找或取得 bucket 时短暂加锁。DNS、载体拨号和协议协商只持对应成员 bucket 的锁；其他成员可同时建立载体。关闭时先从表和 bucket 移出资源，再等待清理，不跨 await 持有全局池锁。bucket 只保存池状态，不创建第二个完整出站实例。

QUIC 的 NEW_TOKEN 缓存与 TLS 恢复票据分开处理。每次建立新 QUIC 连接都在克隆的 ClientConfig 上设置独立 TokenMemoryCache，避免缓存随配置 Arc 跨成员共享；当前也不跨重连复用 NEW_TOKEN，不修改上游 token 算法。

QUIC 入站的节点任务所有者登记原生驱动，使用独立子取消域。节点停止接入后先回收自己的连接，再关闭端点并在原 drain_timeout 总预算内排空；末段预算留给强制取消和实际 join。自然排空到期后，若全部登记任务已完成强制回收，记录 NodeEvent::ForcedCleanup 并返回成功；它不计为 Failed 或数据包 Dropped。强制后仍未完成或任务异常退出才返回错误。节点通知取消不会提前丢弃 QUIC 驱动，也不会取消共享出站服务。

QUIC 鉴权使用已接受连接的 remote_address 记录实际可观察来源；该字段不参与 ResourceKey，也不取客户端请求自报地址。TCP 来源继续沿用接入层的 socket 地址。

本模块代理出站声明`TargetPolicy::Remote`，保留网站原目标、端口和负载。本机只解析代理接入端点，网站解析由远端负责；协议无法表达的目标明确拒绝。TCP连接与UDP关联建立后固定所选出站，不在失败后跨代理或直连重放。


日期：2026-10-31。状态：本轮限定双端已通过远端包级检查、真实互通与生命周期矩阵，精确范围见[验证记录](../testing/tuic.md)。客户端和节点工厂均注册为 `tuic`，按角色分别验收。

## 客户端

```json
{
  "version": 5,
  "server": {"host": "127.0.0.1", "port": 10443},
  "uuid": "00000000-0000-4000-8000-000000000001",
  "password": "synthetic-password",
  "tls": {"server_name": "node.invalid", "ca_pem": "PEM 内容", "alpn": ["h3"]},
  "udp_relay_mode": "native",
  "congestion_control": "cubic",
  "idle_timeout_secs": 60,
  "heartbeat_interval_secs": 10
}
```

v4 使用 `"version":4,"token":"synthetic-token"`，不得同时配置 UUID/password；v5 使用 UUID/password，拒绝 token。`version` 缺省为 5。v4 token 在认证前按固定规范计算 BLAKE3，v5 token 使用当前 TLS exporter 派生，label 为 UUID 原始字节、context 为密码原始字节。

TLS 必须配置服务端名称，始终验证证书；不提供 insecure、关闭 SNI 或伪装指纹开关。ALPN 默认 `h3`，可按对端显式选择，必须非空且每项不超过 255 字节。空闲时间 5–3600 秒，心跳大于 0 且小于空闲时间。QUIC 连接按出站实例复用，没有逻辑业务且空闲超过 30 秒时，在心跳检查时关闭 QUIC 连接；端点缓存随连接实例或出站回收。不会跨节点复用带身份的连接池。

`udp_relay_mode` 只接受 `native` 或 `quic`，分别使用 QUIC datagram 和单向流；不是 sing-box 的 UDP-over-stream/UoT 扩展。`congestion_control` 只接受当前固定 quinn 实际提供的 `cubic`、`newreno`、`bbr`，没有性能等同结论。

v4 TCP 在建立预算内等待 `04 ff REP` 成功确认；v5 没有协议成功响应，发送请求后返回不证明目标已接纳。TCP 的 FIN 关闭写方向并继续读取反向数据。

## 服务端节点

```json
{
  "version": 5,
  "tls": {"certificate_file": "node.crt", "private_key_file": "node.key", "alpn": ["h3"]},
  "congestion_control": "cubic"
}
```

v4/v5凭据分别放入外层members[].native_credential，不能混用两版本字段。用户数 1–256，节点内重复身份拒绝；v5 跨节点重复 UUID 即使密码不同也拒绝，v4 按 token 指纹拒绝跨节点共享。证书/密钥可用内存 PEM 或文件，分别互斥，单文件不超过 1 MiB。

节点仅绑定 QUIC UDP 载体，TCP/UDP 是内部业务能力，不绑定 TCP 监听。IPv4 与 IPv6 节点配置和凭据独立。TLS 及 TUIC 认证完成前不创建网站连接或 UDP 关联；提前到达的业务命令在有限预算内等待认证。

节点通过统一 `PeerSession` 访问目标，强制要求出口支持 `DatagramAssociation`；配置准备阶段拒绝缺少该能力的代理，不用逐目标固定通道冒充 Full Cone。一个关联使用统一出口的同一个 socket 跨目标、跨地址族发送，并保留未先联系来源的数据报。域名解析和 IPv4 优先由 egress 处理，节点地址族不约束网站地址族。TUIC出站实现该关联契约；本轮每个业务连接选择一个命名出站。

## UDP 与生命周期

本模块单包上限为 65507 字节，空包合法；节点另遵守引擎 `max_datagram_size`。固定目标 `connect_udp` 是多目标关联的适配，按目标端口及字面 IP 检查来源，域名由对端统一解析。

v4 native 不含分片格式，超过实际 QUIC datagram MTU 时整包拒绝；v4 quic 使用单向流保留大包。v5 native 可按协议分片，重组完成后才交给出口，不将分片当作独立业务 UDP 包；quic 模式可直接承载整包。v5 分片首片必须带地址，后续片必须是 None；拒绝越界、冲突片和累计超长，支持乱序和一致重复片。每连接待重组最多 64 包、2 MiB，重组窗口 5 秒。

每个客户端 QUIC 连接最多同时保留 128 个 UDP 关联；关联、流、输入任务和队列有明确上限。逻辑关联另持有节点及全局预算。解关联取消相应出口资源。关闭节点停止新业务并按引擎预算取消、回收；读写错误不回退到另一身份或直连。一次发送被取消后写端失效，必须丢弃关联，不重试可能发出一部分的报文。

## 未提供范围

0-RTT、UDP-over-stream/UoT、ECH、客户端指纹、额外 QUIC 扩展、热重载和其他系统/架构尚未交付，未知字段拒绝。v4 与 v5、native 与 quic、客户端与服务端必须分别登记验证，不能按一个成功场景勾选全部组合。

## 完成权与绑定元数据

本轮完成权迁移源码与回归已编写，尚未运行新输入。底层 `Outbound::connect_tcp` 返回 `OpenedTcp`，本协议没有可证实的目标连接绑定字段，明确返回 `TcpConnectInfo::unknown()`。代理端点和载体本地地址不代填业务绑定。底层 UDP 通道保持原接口，唯一业务计量仍由 Dispatcher 包装。

入站从 `PeerSession` 取得 `TcpFlow`、`FixedUdpFlow` 或 `UdpAssociation`。自定义会话拆出 typed I/O 和唯一完成权，先报告正常协议结束、超时、取消或错误，再释放 I/O。TCP 的单向 EOF 不提前结束反向数据；零长度 UDP 包不作为 EOF。完成权只固定终因，最后计量 I/O 租约释放后才生成稳定终态，不重复累计流量。父级载体保留已建立流的完成权，关闭后拒绝新登记，旧代次结果不能关闭新流。

节点的原生 QUIC 驱动与派生入站任务登记到 `InboundContext.tasks` 的 `NodeTasks`。局部任务句柄释放只撤销所属任务，真实 JoinHandle 仍由 Engine 持有。外层 handler 被强制中止后，Engine 继续在同一关闭截止时间内等待实际节点任务；一个 peer 不能关闭节点任务所有者或共享出站。局部 `NodeEvent::ForcedCleanup` 只登记强制回收事实，Engine 确认 handler 与实际节点任务全部退出后才增加公开计数。超出预算仍保留未完成事实，不能记录为关闭成功。

子任务的完成权票据意外释放时，先从父表唯一移出，再在锁外报告终因：正在展开的 panic 为 Failed，已观察取消为 Cancelled，其余为 ClosedByCaller。显式完成或父级关闭已消费的票据不再次报告，后续正常父级 END 不能覆盖子流失败；已知计时器和协议错误仍显式报告。
