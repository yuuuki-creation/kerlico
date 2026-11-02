# ShadowQUIC 双端接口

2026-11-02共享运行迁移已编写，尚未编译、格式检查或测试。本文保留的历史通过记录只对应原输入，不代表当前整树已验收。

配置模式为`version:2`。节点的`members`引用管理账户`user_id`，分别保存`credential_epoch`与`native_credential`。管理用户名、管理密码摘要和协议凭据互不代用。节点工厂接收`NodeBuildContext`，鉴权前只持`IngressBinding`，鉴权后使用`PeerSession`访问共享Dispatcher。

每条成员凭据为`{"username":"node-user","password":"synthetic-password"}`，节点options不再接受username/password/users。只有JLS库完成真实认证后返回的chosen user可以映射CredentialSlot。

出站工厂通过`compile`校验配置与资产，返回一次性`OutboundPlan`；`start(ServiceContext)`才创建命名运行实例。一个Engine内每条命名出站只有一个实例，池按`ConnectContext.resource_key()`的服务、成员和凭据代次分区。持久任务登记到ServiceContext，shutdown停止并等待自身资源；单个请求或节点不关闭共享出站。使用TLS的共享出站不跨成员复用恢复票据。

成员池的外层表只在查找或取得 bucket 时短暂加锁。DNS、载体拨号和协议协商只持对应成员 bucket 的锁；其他成员可同时建立载体。关闭时先从表和 bucket 移出资源，再等待清理，不跨 await 持有全局池锁。bucket 只保存池状态，不创建第二个完整出站实例。

QUIC 的 NEW_TOKEN 缓存与 TLS 恢复票据分开处理。每次建立新 QUIC 连接都在克隆的 ClientConfig 上设置独立 TokenMemoryCache，避免缓存随配置 Arc 跨成员共享；当前也不跨重连复用 NEW_TOKEN，不修改上游 token 算法。

QUIC 入站的节点任务所有者登记原生驱动，使用独立子取消域。节点停止接入后先回收自己的连接，再关闭端点并在原 drain_timeout 总预算内排空；末段预算留给强制取消和实际 join。自然排空到期后，若全部登记任务已完成强制回收，记录 NodeEvent::ForcedCleanup 并返回成功；它不计为 Failed 或数据包 Dropped。强制后仍未完成或任务异常退出才返回错误。节点通知取消不会提前丢弃 QUIC 驱动，也不会取消共享出站服务。

QUIC 鉴权使用已接受连接的 remote_address 记录实际可观察来源；该字段不参与 ResourceKey，也不取客户端请求自报地址。TCP 来源继续沿用接入层的 socket 地址。

新增节点 Runtime 测试代码覆盖强制回收后驱动和连接任务已释放、监听端口可重新绑定、父取消域保留及驱动 panic 不被报告为正常清理；这些新测试尚未执行。

本模块代理出站声明`TargetPolicy::Remote`，保留网站原目标、端口和负载。本机只解析代理接入端点，网站解析由远端负责；协议无法表达的目标明确拒绝。TCP连接与UDP关联建立后固定所选出站，不在失败后跨代理或直连重放。


日期：2026-10-31。工厂类型为 `shadowquic`。QUIC v1 双端已通过固定 Mihomo 的 TCP、两种 UDP 模式与真实上游回退；v2 已通过 Rust 双端、固定向量及单列受控 Go 参照的完整负载互通、实际密钥更新与参数负例。原固定 Mihomo v2 缺少标准强制版本信息，实际互通被拒绝，不能登记为原资产兼容。详见 `docs/testing/shadowquic.md`。

## 客户端

```json
{
  "server": {"host": "127.0.0.1", "port": 10443},
  "username": "node-user",
  "password": "synthetic-password",
  "server_name": "cover.invalid",
  "alpn": ["h3"],
  "quic_version": "v1",
  "udp_mode": "datagram",
  "congestion_control": "cubic",
  "idle_timeout_secs": 60
}
```

JLS 在 TLS 握手中完成双向认证，必须取得 `is_jls=true` 才能暴露业务流；普通 TLS/证书成功不等于认证成功。传输使用独立包名的 quinn-jls/rustls-jls，未修改其他协议的全局 TLS/QUIC 实现。

`quic_version` 接受 `v1`、`v2`，缺省为 v1；`udp_mode` 接受 `datagram`、`stream`，缺省为 datagram。它们分别对应原生 QUIC datagram 与可靠单向流，不机械套用 TUIC 分片。`congestion_control` 为 `cubic`、`newreno`、`bbr` 的真实控制器，不提供仅改变名字的 BBR3/Brutal 选项，也没有性能结论。

用户名 1–256 字节，密码 1–4096 字节，server_name 必须是会发送 SNI 的 DNS 名称，服务器接入 IP 仍由 server.host 配置；ALPN 非空，每项不超过 255 字节。载体域名有界解析并优先取 IPv4 的首个候选，握手失败不尝试另一地址或另一身份。连接池按出站实例隔离；没有逻辑业务且闲置 30 秒后关闭 QUIC 连接，端点缓存随实例或出站回收。

TCP 无应用层成功回应，发送请求并返回不证明目标已经接纳。FIN 只关闭写方向，继续接收反向数据。QUIC v1/v2 使用受认证版本信息；客户端仅声明选定版本，不做自动跨版本回退或握手内兼容切换。TLS 恢复与 0-RTT 禁用，不跨版本/节点复用票据。

## 服务端节点

```json
{
  "upstream": {"host": "127.0.0.1", "port": 11443},
  "server_name": "cover.invalid",
  "alpn": ["h3"],
  "quic_versions": ["v1", "v2"],
  "congestion_control": "cubic",
  "upstream_rate_bps": 16000000
}
```

服务端用户名和密码只从外层members读取。用户数 1–256，节点内重复用户名拒绝；跨节点重复用户名即使密码不同也拒绝。IPv4/IPv6 接入节点分别配置，不隐式共享凭据。节点只绑定 UDP 载体，内部 TCP/UDP 业务不依赖 TCP 监听。

服务器使用本地生成的临时证书承载握手，身份由 JLS secret 验证；不把它当作 PKI 或安全审计结论。`upstream` 是显式配置的普通 QUIC 传输上游，`server_name` 用于 JLS 名称校验；格式检查不拨号、不监听、不隐式解析域名。运行时在建立预算内解析传输上游，再构造端点。

未通过 JLS 的普通 QUIC 只能回退到上述传输上游，不能因此访问任意网站或改用另一代理节点。回退最多 64 个来源且不超过节点配置上限，同时持有全局和节点资源许可；每来源两包、共 128 KiB 接收缓冲，两个方向另各有最多 32 包/256 KiB 的发送队列；闲置不超过节点空闲预算且最高 30 秒，定时清理。`upstream_rate_bps` 为每来源回退速率，范围 8000–8000000000 bit/s，带一个完整 UDP 包的有限 burst。后台初次转发与 QUIC 驱动归属节点作用域，退出时统一取消。

通过 JLS 的 CONNECT、两类 UDP 关联经 `PeerSession` 访问目标。节点要求出口提供 `DatagramAssociation`，准备阶段拒绝缺少该能力的代理，不降级为逐目标固定通道。本地路径的域名解析和IPv4优先由共享调度器承担，远端路径保留原目标；节点、传输上游和网站的地址族互不绑定。

## UDP、资源与错误边界

一个关联控制流登记多个地址与全连接唯一的 16 位 ID；datagram 只携带 ID 和负载，可靠单向流以 ID 开头并连续携带长度前缀包。双方命名空间独立，重复 ID 不得跨关联覆盖；关闭控制流释放两方向映射和相关单向流。已退役 ID 在同一连接内不重新登记，避免延迟包误入新关联。

Full Cone 关联跨目标/跨地址族保持同一出口 socket，并接收未先联系来源的包。客户端同时提供 `associate_udp` 和固定目标 `connect_udp`；后者按目标来源过滤。空包合法；本模块最大 UDP 负载 65507 字节，节点另遵守 `max_datagram_size`。datagram 超实际 MTU 时整包拒绝，不透明拆包；stream 模式用于大包。

每连接最多 4096 个活动 ID、每关联最多 256 个目标，可靠单向流最多 128；节点预算可能进一步收紧。新关联及服务器的可靠载体各持有资源许可。先于控制映射到达的包缓存最多 128 个 ID、每 ID 16 包、总计 256 KiB，5 秒后清理；未知可靠流最多等待映射 5 秒。半帧读取状态不会因其他后台事件重建；发送中取消后写端失效，必须丢弃关联，不能重试部分帧。

验证范围按角色、版本、模式与地址族分别登记；v2 的原固定 Mihomo 互通仍未通过，受控参照不等于原资产兼容。BIND、应用层 AUTHENTICATE、远程用户管理、Brutal/BBR3、0-RTT、ECH、指纹、热重载和其他平台没有交付；未知字段拒绝。连接统计扩展只返回当前连接计数，不开放用户管理权限。

## 完成权与绑定元数据

本轮完成权迁移源码与回归已编写，尚未运行新输入。底层 `Outbound::connect_tcp` 返回 `OpenedTcp`，本协议没有可证实的目标连接绑定字段，明确返回 `TcpConnectInfo::unknown()`。代理端点和载体本地地址不代填业务绑定。底层 UDP 通道保持原接口，唯一业务计量仍由 Dispatcher 包装。

入站从 `PeerSession` 取得 `TcpFlow`、`FixedUdpFlow` 或 `UdpAssociation`。自定义会话拆出 typed I/O 和唯一完成权，先报告正常协议结束、超时、取消或错误，再释放 I/O。TCP 的单向 EOF 不提前结束反向数据；零长度 UDP 包不作为 EOF。完成权只固定终因，最后计量 I/O 租约释放后才生成稳定终态，不重复累计流量。父级载体保留已建立流的完成权，关闭后拒绝新登记，旧代次结果不能关闭新流。

节点的原生 QUIC 驱动与派生入站任务登记到 `InboundContext.tasks` 的 `NodeTasks`。局部任务句柄释放只撤销所属任务，真实 JoinHandle 仍由 Engine 持有。外层 handler 被强制中止后，Engine 继续在同一关闭截止时间内等待实际节点任务；一个 peer 不能关闭节点任务所有者或共享出站。局部 `NodeEvent::ForcedCleanup` 只登记强制回收事实，Engine 确认 handler 与实际节点任务全部退出后才增加公开计数。超出预算仍保留未完成事实，不能记录为关闭成功。

子任务的完成权票据意外释放时，先从父表唯一移出，再在锁外报告终因：正在展开的 panic 为 Failed，已观察取消为 Cancelled，其余为 ClosedByCaller。显式完成或父级关闭已消费的票据不再次报告，后续正常父级 END 不能覆盖子流失败；已知计时器和协议错误仍显式报告。
