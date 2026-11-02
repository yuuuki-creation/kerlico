# AnyTLS 双端接口

更新日期：2026-11-02（Asia/Shanghai）。对应总表 P-15，验证记录见 [AnyTLS 测试记录](../testing/anytls.md)。本模块采用配置 v2 与全局共享 `Dispatcher`（`TargetPolicy::Remote`），节点成员凭据 `members[].native_credential` 格式为 `{"password": "<协议密码>"}`。

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

## 完成权、节点任务与 UoT 回执契约

- 每条逻辑流独立持有 `FlowCompletion`；AnyTLS `FIN` 表示整条逻辑流结束，通过会话通知传给业务 owner。客户端任务归命名 `ServiceContext`，服务端全部桥与逻辑任务归 `NodeTasks`。
- **UoT 物理写确认回执**：每个目标的回包带私有 receipt。逻辑流的 `flush` 等待该流全部已接纳字节在物理载体完成 `write_all` 与 `flush`（PSH 队列项按原逻辑流独立持有交付状态与累计末位置，检查溢出且不按流 ID 回查）。父任务收到物理 flush 结果后才发出逐包 receipt，接收任务随后读取下一包或 EOF。
- **目标交接状态与父退出**：每个目标维护 `Receiving`、`Pending`、`Ended(FlowOutcome)` 或 `Closed` 状态。父退出先在各目标状态锁下关闭交接并读取状态，已固定 `Ended` 的目标保留其独立终因（如等待 receipt 期间发生的独立 `Timeout`），其余目标采用父原因（`Pending` 使正常父 EOF/FIN 转为失败），避免后续清理 `Cancelled` 反向覆盖父原因。
