# AnyTLS 实际接口

当前源码更新于2026-11-02，已编写共享运行与配置 v2 迁移，尚未执行本轮编译、格式、测试或互通。下文既有通过结果只属于各自历史输入，不能作为本轮验收。

节点通过 `NodeFactory::build(&NodeBuildContext)` 编译。每个 `members[]` 绑定管理 user_id、credential_epoch 和 native_credential；协议凭据与管理用户名、密码分开。原生凭据格式为 `{"password":"协议密码"}`。

认证前只持 `IngressBinding`。真实协议校验成功后交接 `CredentialSet` 的槽与同次解码状态，经 `authenticated` 得到 `PeerSession`。每次 TCP 或 UDP 建立均由共享 Dispatcher 创建独立流归属；复用载体不会把成员或流标识混合。旧指纹接口已替换为 `CredentialManifest`，分别登记 Authentication 与 Protection。

出站使用 `OutboundFactory::compile(&Value) -> OutboundPlan`。编译完成字段、凭据与资产校验；Engine 只消费一次 `start(ServiceContext)`，构造唯一命名运行实例。此模块使用 Remote 策略，保留网站原域名/IP、端口和负载，只解析代理载体端点。远端失败不在本机更换代理、换族或回退直连。

`ConnectContext` 必须通过构造方法建立，嵌套阶段使用 `with_timeout` 收紧原期限。共享连接与票据按 `resource_key()` 的运行实例、成员与凭据代次分区。持久任务归命名服务，单个入站或请求取消不会关闭共享服务。显式 `shutdown` 停止并等待本实例任务；历史包级验证尚未覆盖新关闭路径。


状态：已实现，并在 perf-03 完成包级检查、原生双端与固定 sing-box 双向互通；组合边界见[验证记录](../testing/anytls.md)。对应总表 P-15。

根程序已装配本模块，可用 `cargo build -p kerlico --no-default-features --features anytls` 单独启用两端；`anytls` 是 `protocol-anytls` 的功能别名。

`kerlico-anytls` 导出 `AnyTlsFactory` 与 `AnyTlsNodeFactory`，两者注册名均为 `anytls`。依赖现有核心、配置与底层 TLS 连接器；业务目标仅经注入的 `PeerSession`，不在协议中解析或选择网站出口地址族。节点预算关闭后拒绝新逻辑流，已有流仍在排空预算内继续收发。

出站 options：

```json
{"server":{"host":"proxy.invalid","port":443},"password":"独立口令","tls":{"server_name":"proxy.invalid","ca_pem":null},"idle_session_timeout_ms":30000,"max_sessions":64}
```

节点 options：

```json
{"tls":{"certificate_file":"server.pem","private_key_file":"server.key"}}
```

TLS 必选。节点也接受 `certificate_pem` / `private_key_pem` 内联内容，各自与文件字段互斥。默认公共根证书可追加出站 `ca_pem`；不提供跳过证书校验。节点可指定 `padding_scheme`，默认采用固定规范的方案。未知字段拒绝。

每个命名出站只有一个运行实例，连接池和 padding 协商状态在该实例内部按可信来源分区。外层表只短暂加锁取得成员桶，网络等待只持本成员桶的锁；共享 Semaphore 统一限制命名实例的总会话数。忙会话不外借给其他应用流；闲置会话按顺序复用，逻辑流 ID 单调递增。节点接受同会话多个并发流，受流数和核心 `StreamBudget` 限制。节点凭据指纹用于装配阶段拒绝不同节点重复口令；节点用户表、认证连接和目标通道不跨节点共享。

实现 SHA-256 口令握手、v2 settings、SYN/PSH/FIN、SYNACK、心跳回应、padding 协商与丢弃。TCP 业务地址用 SOCKS 地址编码。UoT v2 使用保留域名，出站使用固定目标 connect 模式；节点同时解码固定目标与逐包地址模式，后者最多建立 32 个目标通道。数据报保留空包及包边界，帧最大 65535 字节，另受运行时限额与实际出口限制；原生双端已验证 65507 字节，对固定 sing-box 的互通只验证至 12000 字节。

`Capabilities` 为 TCP=true、UDP=true、tcp_eof=false；AnyTLS FIN 结束整个逻辑流，不能保证最终目标的 TCP 半关闭。ECH/uTLS/REALITY、ShadowTLS/Restls/JLS、通用 V2Ray transport、通用 mux、UoT v1 和主动心跳探测不在本轮接口内。认证失败直接拒绝，不回退到其他节点、用户表或伪装目标。

客户端逻辑流的 `shutdown` 禁用后续写入，并等待先前接纳字节的 PSH 在实际载体完成 `write_all` 和 `flush`，同时保留反向读取。后续写入返回 `BrokenPipe`。它不会发送 AnyTLS FIN 或承诺目标收到 EOF。服务端逻辑流 `shutdown` 先等待前序数据，再等待 FIN 的实际载体提交。完整关闭仍由对端 FIN 或调用方释放流对象触发。

## 完成权与节点任务契约

2026-11-02 本轮首轮编码，尚未构建、格式检查或运行验证。

业务入口返回 `TcpFlow`、`FixedUdpFlow` 或 `UdpAssociation`，拆分后唯一 `FlowCompletion` 留在实际会话 owner。字节与数据报仍只由 Dispatcher 计量，完成权只报告原因；最后 I/O、半部及完成权租约释放后才提交终态。底层出站 TCP 返回 `OpenedTcp`，本模块没有绑定证据时明确返回 `Unknown`，不以代理载体地址代填。

每条逻辑流独立持完成权。会话关闭原因和逻辑 FIN 通过该会话自己的通知传给业务 owner，FIN 表示整条逻辑流结束，不能当成普通 TCP 单向 EOF。多目标 UoT 的 Entry 持完成权，接收任务只持 typed 半部；父原因先固定再清理。客户端任务仍归命名 ServiceContext，服务端全部桥与逻辑任务归 NodeTasks，不借用测试服务宿主。

## 本轮审阅修复，待 worker 验证

UoT 每个目标的回包带私有 receipt。逻辑流的 `flush` 等待该流全部已接纳字节实际写入并 flush，包括仍在 duplex、桥尚未读出的字节。PSH 的私有队列项持有原逻辑流的独立交付状态与累计末位置，只有物理 writer 成功后才能推进确认。状态不按流 ID 回查，迟到帧不能确认另一条逻辑流。累计字节数检查溢出，不通过饱和或回绕制造成功。

父任务收到这一物理 flush 结果后才发出逐包 receipt，接收任务随后才能读取下一包或 EOF。每个目标的私有交接状态为 Receiving、Pending、Ended(FlowOutcome) 或 Closed，覆盖回包已接纳、尚未进入反馈队列的窗口。它不持有完成权，也不写入 `ConnectContext`。目标观测独立终因后，先固定 Ended，再等待有界 End 通知入队。独立 Timeout 在等待 receipt 期间发生、且 End 因队列满尚未入队时，仍保留该原因。

父退出先在各目标原状态锁下关闭交接并取得状态，再关闭和释放反馈接收端。已固定 Ended 的目标使用其独立终因，其余目标使用父原因；Pending 仍使正常父 EOF 或 FIN 转为失败。父 close 与目标 ended 由同一锁确定先后，父先关闭时，后续目标清理 Cancelled 不能反向覆盖父原因。目标完整记录仍由父持有的唯一 `FlowCompletion` 报告，并等待剩余 I/O 租约释放。

Session 先发布实际载体或逻辑流的终止原因，再唤醒等待物理 flush 的写侧。读取继续使用 duplex 自己的唤醒，桥对 FIN 的确认另用 oneshot，不覆盖应用写侧的唤醒。代次、32 项反馈队列、64 项物理帧队列、65536 字节 duplex、16 KiB PSH 分片及原多目标上限不变。这里的确认仅表示载体 `AsyncWrite` 已接纳并 flush，不表示 TCP ACK 或远端应用收到。

服务端实际读写与桥任务继续登记到原 `NodeTasks`，客户端继续归命名 `ServiceContext`。`Session::close` 发布原因并请求关闭，不能单凭它或局部句柄已结束声明资源回收。节点所有者仍须等待实际任务，Engine 的最终等待职责不变。

本节实现与新增回归已写入独立修复树，未运行构建、格式、静态检查、单元或互通测试。历史结果不适用于本轮输入，不能据此登记验收通过。
