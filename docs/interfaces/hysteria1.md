# Hysteria v1 双端接口

2026-11-02共享运行迁移已编写，尚未编译、格式检查或测试。本文保留的历史通过记录只对应原输入，不代表当前整树已验收。

配置模式为`version:2`。节点的`members`引用管理账户`user_id`，分别保存`credential_epoch`与`native_credential`。管理用户名、管理密码摘要和协议凭据互不代用。节点工厂接收`NodeBuildContext`，鉴权前只持`IngressBinding`，鉴权后使用`PeerSession`访问共享Dispatcher。

每条成员凭据为`{"auth_str":"synthetic-password"}`或`{"auth":"base64编码的原生凭据"}`，两字段互斥。节点options不再接受auth/auth_str/users。实际ClientHello认证字节的命中行决定PeerSession；混淆key仅登记Protection。

出站工厂通过`compile`校验配置与资产，返回一次性`OutboundPlan`；`start(ServiceContext)`才创建命名运行实例。一个Engine内每条命名出站只有一个实例，池按`ConnectContext.resource_key()`的服务、成员和凭据代次分区。持久任务登记到ServiceContext，shutdown停止并等待自身资源；单个请求或节点不关闭共享出站。使用TLS的共享出站不跨成员复用恢复票据。

成员池的外层表只在查找或取得 bucket 时短暂加锁。DNS、载体拨号和协议协商只持对应成员 bucket 的锁；其他成员可同时建立载体。关闭时先从表和 bucket 移出资源，再等待清理，不跨 await 持有全局池锁。bucket 只保存池状态，不创建第二个完整出站实例。

QUIC 的 NEW_TOKEN 缓存与 TLS 恢复票据分开处理。每次建立新 QUIC 连接都在克隆的 ClientConfig 上设置独立 TokenMemoryCache，避免缓存随配置 Arc 跨成员共享；当前也不跨重连复用 NEW_TOKEN，不修改上游 token 算法。

QUIC 入站的节点任务所有者登记原生驱动，使用独立子取消域。节点停止接入后先回收自己的连接，再关闭端点并在原 drain_timeout 总预算内排空；末段预算留给强制取消和实际 join。自然排空到期后，若全部登记任务已完成强制回收，记录 NodeEvent::ForcedCleanup 并返回成功；它不计为 Failed 或数据包 Dropped。强制后仍未完成或任务异常退出才返回错误。节点通知取消不会提前丢弃 QUIC 驱动，也不会取消共享出站服务。

QUIC 鉴权使用已接受连接的 remote_address 记录实际可观察来源；该字段不参与 ResourceKey，也不取客户端请求自报地址。TCP 来源继续沿用接入层的 socket 地址。

新增节点 Runtime 测试代码覆盖强制回收后驱动和连接任务已释放、监听端口可重新绑定、父取消域保留及驱动 panic 不被报告为正常清理；这些新测试尚未执行。

本模块代理出站声明`TargetPolicy::Remote`，保留网站原目标、端口和负载。本机只解析代理接入端点，网站解析由远端负责；协议无法表达的目标明确拒绝。TCP连接与UDP关联建立后固定所选出站，不在失败后跨代理或直连重放。


更新日期：2026-10-31。状态：限定范围已在 perf-02 通过 16 项自端测试、严格检查，以及官方 v1.3.5 的 24 组和 sing-box 1.14.4 的 12 组真实双向矩阵；UDP 对端边界见测试记录，其他分支不继承结果。

`Hysteria1Factory`、`Hysteria1NodeFactory` 分别注册 `hysteria1` 出站与节点。线协议版本固定为 0x03；它与 Hysteria2 的 HTTP/3 鉴权和请求分离。节点物理监听为 QUIC/UDP，不能从 `supports_tcp=false` 推断没有 TCP 业务能力。

## 配置

出站必填 `server: {host,port}`、一项认证、`up_bps`/`down_bps` 和 `tls`；节点options必填`tls`，认证来自members。单项认证二选一：`auth_str` 按 UTF-8 字节使用，`auth` 按标准 base64 解码；同时提供时拒绝。节点members最多256项，每项native_credential只填auth_str或auth，解码后不得重复。认证字节非空、上限 4096。

| 参数 | 行为 |
| --- | --- |
| transport | udp（默认）或 wechat-video，均使用 UDP socket |
| obfs | 可选 xplus 密码；省略或空字符串表示不启用，上限 4096 UTF-8 字节 |
| udp | 默认 true；false 关闭逻辑 UDP 能力与 DATAGRAM 协商，物理载体仍是 QUIC/UDP |
| up_bps/down_bps | 字节/秒。客户端为 16384–10^12；节点可为 0（默认，跟随对端提示）或同范围正数 |
| limits.congestion_control | cubic（默认）、newreno、bbr，保留各自拥塞控制并按协商发送速率约束 pacer；没有 Brutal |
| limits.max_streams | 默认 64，范围 1–1024；有效节点上限还受引擎预算约束 |
| limits.udp_queue_packets | 每会话接收队列默认 32，范围 1–256 |
| limits.udp_queue_bytes | 每连接队列总负载默认 4 MiB，范围 64 KiB–16 MiB |
| limits.idle_timeout_ms | 默认 30000，范围 100–86400000；节点与引擎空闲预算取小值；客户端缓存无活动持有者时回收 |

TLS 客户端为 `tls: {server_name, ca_pem?, alpn?}`；节点为 `tls: {certificate_pem, private_key_pem, alpn?}`，或使用分别与内联互斥的 `certificate_file`/`private_key_file`。文件各不超过 1 MiB，默认 ALPN 为 `["hysteria"]`，不提供跳过证书校验或禁用 TLS 的选项。

```json
{
  "server": {"host": "127.0.0.1", "port": 14443},
  "auth_str": "hysteria1-test-only-node-token",
  "up_bps": 10000000,
  "down_bps": 10000000,
  "transport": "wechat-video",
  "obfs": "xplus-test-only-key",
  "tls": {"server_name": "proxy.example.invalid", "ca_pem": "<测试 CA PEM>"}
}
```

未知字段、Fake-TCP、端口列表/跳跃或 brutal 控制器明确拒绝，不静默回退。没有实现入口硬限速、PMTUD 优化、GSO/GRO/ECN、外部认证、ACME、TUN 或透明接入，不能据普通 QUIC 功能推定这些分支已支持。

## 协议与生命周期

- 客户端收到鉴权成功后才打开业务流。TCP 收到成功响应后才返回，表示网站侧 TCP 已建立，不等于目标应用已响应。自端保留独立 FIN，但旧官方转发器不能保证反向排空，因此通用出站 `tcp_eof=false`，不让 require_remote_eof 配置误通过；目标先发数据与自端 FIN 分别验收。
- 每条 QUIC 连接的标准控制器有独立协商速率状态；服务端发送/接收各按对应方向提示取小值。此行为不是 Brutal，也不构成吞吐或丢包性能保证。
- 节点按实际解码认证字节生成指纹，避免字符串/base64 别名绕过跨节点隔离；鉴权失败关闭当前连接，不尝试其他节点。
- UDP 每会话只创建一次 `PeerSession::associate_udp`，同一 socket 访问多个目标，域名解析与 IPv4 优先由统一出口负责。提示地址不限制后续逐包目标；关联能力不足在配置阶段拒绝。
- UDP hold stream 结束时立即回收关联、路由与分片状态。节点会话号单调分配不复用，客户端拒绝重复活动会话号，异步清理回调核对代次。
- 单包负载上限为 65507，并同时受节点 `max_datagram_size` 限制；请求和目标回包都校验。零负载是合法包，不表示关闭。超限或队列满整包丢弃，不截短后发送。
- 分片按连接内会话/消息/代次组装，目标与数量必须一致；重复相同分片不重复计数，冲突丢弃整组。组装最多 128 组、4 MiB、10 秒；完整/冲突消息的近期记录有固定上限。缺片到期不交付。发送按连接串行提交每包全部分片，分片消息号耗尽后至少等待旧窗口过期。
- 载体、逻辑流与 UDP 会话分别取得预算；节点排空期禁止新连接/逻辑流，已有业务按预算结束。自身 socket 句柄随所有者显式关闭，不依赖 QUIC 关闭计时器释放端口。

本项目自端 UDP 已验至 12000 字节，固定官方 CLI 至 4096、固定 sing-box 转发路径至 8192；超限截短仅记负例，外部零包未验。

固定版本与已知对端差异见[调研](../../reference/research_notes/hysteria1.md)，真实结果见[测试记录](../testing/hysteria1.md)。

## 完成权与绑定元数据

本轮完成权迁移源码与回归已编写，尚未运行新输入。底层 `Outbound::connect_tcp` 返回 `OpenedTcp`，本协议没有可证实的目标连接绑定字段，明确返回 `TcpConnectInfo::unknown()`。代理端点和载体本地地址不代填业务绑定。底层 UDP 通道保持原接口，唯一业务计量仍由 Dispatcher 包装。

入站从 `PeerSession` 取得 `TcpFlow`、`FixedUdpFlow` 或 `UdpAssociation`。自定义会话拆出 typed I/O 和唯一完成权，先报告正常协议结束、超时、取消或错误，再释放 I/O。TCP 的单向 EOF 不提前结束反向数据；零长度 UDP 包不作为 EOF。完成权只固定终因，最后计量 I/O 租约释放后才生成稳定终态，不重复累计流量。父级载体保留已建立流的完成权，关闭后拒绝新登记，旧代次结果不能关闭新流。

节点的原生 QUIC 驱动与派生入站任务登记到 `InboundContext.tasks` 的 `NodeTasks`。局部任务句柄释放只撤销所属任务，真实 JoinHandle 仍由 Engine 持有。外层 handler 被强制中止后，Engine 继续在同一关闭截止时间内等待实际节点任务；一个 peer 不能关闭节点任务所有者或共享出站。局部 `NodeEvent::ForcedCleanup` 只登记强制回收事实，Engine 确认 handler 与实际节点任务全部退出后才增加公开计数。超出预算仍保留未完成事实，不能记录为关闭成功。

子任务的完成权票据意外释放时，先从父表唯一移出，再在锁外报告终因：正在展开的 panic 为 Failed，已观察取消为 Cancelled，其余为 ClosedByCaller。显式完成或父级关闭已消费的票据不再次报告，后续正常父级 END 不能覆盖子流失败；已知计时器和协议错误仍显式报告。
