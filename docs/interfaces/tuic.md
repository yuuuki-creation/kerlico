# TUIC v4/v5 双端接口

`TuicFactory`、`TuicNodeFactory` 均注册为 `tuic`（研究见 [tuic.md](../../reference/research_notes/tuic.md)，验证记录见 [tuic.md](../testing/tuic.md)）。

- **节点成员凭据**：v4 每条 `members[].native_credential` 为 `{"token": "synthetic-token"}`，v5 为 `{"uuid": "00000000-0000-4000-8000-000000000001", "password": "synthetic-password"}`。真实 v4 认证摘要或 v5 TLS exporter 命中成员后，连接内 TCP 流与 UDP 关联沿用该可信用户；鉴权使用已接受 QUIC 连接的 `remote_address` 记录可观察来源。
- **成员池与 QUIC 缓存**：成员池外层表只在查找或取得 bucket 时短暂加锁，DNS、载体拨号和协议协商只持对应成员 bucket 锁；每次建立新 QUIC 连接都在克隆的 `ClientConfig` 上设置独立 `TokenMemoryCache`，避免 `NEW_TOKEN` 缓存跨成员共享。
- **QUIC 节点排空**：QUIC 入站原生驱动登记到 `NodeTasks` 并使用独立子取消域。停止接入后先回收连接，再关闭端点并在 `drain_timeout` 内排空（末段留给强制取消和 join；全部强制回收完成记录 `NodeEvent::ForcedCleanup`）。

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

底层 `Outbound::connect_tcp` 返回 `OpenedTcp`，本协议没有可证实的目标连接绑定字段，明确返回 `TcpConnectInfo::unknown()`。代理端点和载体本地地址不代填业务绑定。底层 UDP 通道保持原接口，唯一业务计量仍由 Dispatcher 包装。

入站从 `PeerSession` 取得 `TcpFlow`、`FixedUdpFlow` 或 `UdpAssociation`。自定义会话拆出 typed I/O 和唯一完成权，先报告正常协议结束、超时、取消或错误，再释放 I/O。TCP 的单向 EOF 不提前结束反向数据；零长度 UDP 包不作为 EOF。完成权只固定终因，最后计量 I/O 租约释放后才生成稳定终态，不重复累计流量。父级载体保留已建立流的完成权，关闭后拒绝新登记，旧代次结果不能关闭新流。

节点的原生 QUIC 驱动与派生入站任务登记到 `InboundContext.tasks` 的 `NodeTasks`。局部任务句柄释放只撤销所属任务，真实 JoinHandle 仍由 Engine 持有。外层 handler 被强制中止后，Engine 继续在同一关闭截止时间内等待实际节点任务；一个 peer 不能关闭节点任务所有者或共享出站。局部 `NodeEvent::ForcedCleanup` 只登记强制回收事实，Engine 确认 handler 与实际节点任务全部退出后才增加公开计数。超出预算仍保留未完成事实，不能记录为关闭成功。

子任务的完成权票据意外释放时，先从父表唯一移出，再在锁外报告终因：正在展开的 panic 为 Failed，已观察取消为 Cancelled，其余为 ClosedByCaller。显式完成或父级关闭已消费的票据不再次报告，后续正常父级 END 不能覆盖子流失败；已知计时器和协议错误仍显式报告。
