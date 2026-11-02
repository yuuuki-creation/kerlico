# Naive 实际接口

2026-11-02共享运行迁移已编写，尚未编译、格式检查或测试。本文保留的历史通过记录只对应原输入，不代表当前整树已验收。

配置模式为`version:2`。节点的`members`引用管理账户`user_id`，分别保存`credential_epoch`与`native_credential`。管理用户名、管理密码摘要和协议凭据互不代用。节点工厂接收`NodeBuildContext`，鉴权前只持`IngressBinding`，鉴权后使用`PeerSession`访问共享Dispatcher。

每条成员凭据为`{"username":"node-user","password":"synthetic-password"}`，节点options不再接受users。H1/H2/H3每个CONNECT按真实Basic命中行创建peer，UoT与普通TCP分别建立逻辑访问。

出站工厂通过`compile`校验配置与资产，返回一次性`OutboundPlan`；`start(ServiceContext)`才创建命名运行实例。一个Engine内每条命名出站只有一个实例，池按`ConnectContext.resource_key()`的服务、成员和凭据代次分区。持久任务登记到ServiceContext，shutdown停止并等待自身资源；单个请求或节点不关闭共享出站。使用TLS的共享出站不跨成员复用恢复票据。

成员池的外层表只在查找或取得 bucket 时短暂加锁。DNS、载体拨号和协议协商只持对应成员 bucket 的锁；其他成员可同时建立载体。关闭时先从表和 bucket 移出资源，再等待清理，不跨 await 持有全局池锁。bucket 只保存池状态，不创建第二个完整出站实例。

本轮补齐全部桥任务所有权，源码与回归已编写，尚未执行。H1真实TCP桥、H2和H3逻辑流桥、双端padding桥都必须接收真实运行所有者。出站桥直接登记到命名服务，后端保留对应 `ServiceTask` 并在 shutdown 取消和等待；HTTP会话driver及QUIC原生driver仍属于同一 `ServiceContext`。保留的业务流句柄不阻止shutdown取出并关闭QUIC端点，也不能在关闭后登记新桥。

TCP入站为每条已接受连接持有本地任务集合，H1和H2的HTTP桥与padding桥均由该集合等待退出。H3入站桥与QUIC原生driver归节点任务所有者；请求处理即使异常返回，任务仍在节点集合中。HTTP处理结束后统一取消、排空和等待所属桥，不使用测试服务标识伪造生产宿主。请求取消不向上取消服务或其他节点。

QUIC 入站的节点任务所有者登记原生驱动，使用独立子取消域。节点停止接入后先回收自己的连接，再关闭端点并在原 drain_timeout 总预算内排空；末段预算留给强制取消和实际 join。自然排空到期后，若全部登记任务已完成强制回收，记录 NodeEvent::ForcedCleanup 并返回成功；它不计为 Failed 或数据包 Dropped。强制后仍未完成或任务异常退出才返回错误。节点通知取消不会提前丢弃 QUIC 驱动，也不会取消共享出站服务。

QUIC 鉴权使用已接受连接的 remote_address 记录实际可观察来源；该字段不参与 ResourceKey，也不取客户端请求自报地址。TCP 来源继续沿用接入层的 socket 地址。

新增 concurrent_members 测试代码通过真实 HTTP Basic 入站与 Naive H2 出站，挂起成员 A 的连接器，再验证同命名出站内成员 B 转发及 A 取消后的 B 存量流。该测试尚未执行。

本模块代理出站声明`TargetPolicy::Remote`，保留网站原目标、端口和负载。本机只解析代理接入端点，网站解析由远端负责；协议无法表达的目标明确拒绝。TCP连接与UDP关联建立后固定所选出站，不在失败后跨代理或直连重放。


状态：2026-10-31，**限定双端与组合已验收并冻结，供1.0.0整树发行复验使用**。perf-03通过26项Rust、严格Clippy/fmt、限定CLI构建、156/156配置的900条常规检查及同进程双端28条检查；原参考包长与EOF限制另列。P-21；研究和完整范围见[详细研究](../../reference/research_notes/naive.md)，冻结及真实结果见[测试记录](../testing/naive.md)。本模块结果不代表1.0.0整树或发行产物已验收。

`kerlico-naive` 导出 `NaiveFactory`、`NaiveNodeFactory`，两端注册名 `naive`；根程序的可选功能为 `protocol-naive`。工厂只解析配置、构造状态，不拨号或绑定端口。业务目标只通过注入 `PeerSession`，逐包多目标只用 `DatagramAssociation`。

出站示例：

```json
{
  "server":{"host":"proxy.invalid","port":443},
  "username":"node-user",
  "password":"本节点独立口令",
  "tls":{"server_name":"proxy.invalid","ca_pem":null},
  "transport":"h2",
  "udp_over_tcp":{"enabled":true,"version":2},
  "max_sessions":4,
  "max_streams":128,
  "idle_session_timeout_ms":60000,
  "congestion_control":"cubic"
}
```

节点 options：

```json
{
  "tls":{"certificate_file":"server.pem","private_key_file":"server.key"},
  "transports":["h1","h2","h3"],
  "udp_over_tcp":true,
  "congestion_control":"cubic"
}
```

`transport` 为 `h1`、`h2` 或 `h3`，默认 `h2`；节点默认三种，列表不得重复或为空。H1/H2使用TCP监听，H3使用UDP监听；同时启用时使用节点同一个配置端口的两类socket。TLS必选；H1/H2协商固定ALPN（无ALPN的H1接入也可识别），服务端优先H2；H3固定QUICv1与h3、禁用0-RTT。节点也接受 `certificate_pem` / `private_key_pem`，分别与相应文件字段互斥。出站可追加CA，默认仍启用公共根与名称校验，不提供跳过校验。

节点放在外层 `nodes`，回环Naive节点也保留TLS和凭据；本模块未注册无认证的 `local_inbounds` 模式。节点用户表须有1..256项，用户名在表内不得重复。外层 `nodes[].max_sessions` 和 `limits` 提供服务端预算；出站的 `max_sessions`、`max_streams`、`idle_session_timeout_ms` 不是节点options字段。`udp_over_tcp` 在节点是布尔值，在出站是带 `enabled` / `version` 的对象。

`congestion_control` 仅H3支持 `cubic` 或 `reno`；其他载体不接受非默认值。没有BBR、QUICv2、gQUIC、ECH、REALITY、uTLS、浏览器指纹、明文HTTP/h2c或其他通用transport/mux开关，未知字段拒绝。

标准TLS校验外，模块固定NaiveProxy v154.0.8037.49-5的109项SPKI拒绝值，包含该版本新增的八项中间证书值。检查叶及对端提供中间链，不用自有解析替代WebPKI；不是动态更新或Chrome全部证书政策。源码仅保留拒绝证书测试资产的来源、876字节大小、DER及SPKI摘要；证书未取得明确再分发许可，不随源码或产物分发。worker准备工具以正常TLS下载固定原始DER到私有目录，测试仅从 `KERLICO_TEST_ASSETS_DIR/naive/blocked-intermediate.der` 读取并校验，缺失明确失败且不联网。生产拒绝集和产品TLS不依赖该文件。

认证为每个CONNECT的Basic。用户名非空、不含冒号；用户名和密码均不含控制符，密码非空，总字节数不超过1024。秘密查重沿用现有HTTP的 `http` 域与 `SHA256(b"kerlico/http\0" + canonical Basic header)`，因此HTTP与Naive节点也不能复用同一整组凭据。TLS、版本、padding不创建新身份域。不同节点各持用户表和连接资源；认证失败直接拒绝。

前八个记录按方向独立填充，此后为原流。出站只请求padding类型1；节点处理当前 `padding-type-request` 与旧式Padding头，并明确回复1；不降级为无填充普通代理。帧中payload最大65535，padding最大255；大写入分块，解码支持零payload帧、短读、合帧与第九帧切换。HTTP DATA/TLS/QUIC读取边界不改变padding状态。

H2/H3按出站实例持有有界会话池和真实并发请求流。`max_sessions`1..128、`max_streams`1..1024、空闲会话预算100..86400000毫秒；H1每会话只有一个CONNECT，使用同一物理会话上限。服务端每个物理连接和额外逻辑请求受核心预算；停止接新流后，存量请求受排空预算。flush确认先前数据已交给编码器与载体发送层，shutdown等待编码器完成写端关闭；取消或错误关闭相应流，不重放业务数据，也不回退其他身份。GOAWAY或物理连接失败向调用方报错，旧会话退出后下次调用可新建，不自动重发CONNECT。H3接入域名解析后优先IPv4，当前只尝试首个解析地址。

`max_streams` 是H2/H3每会话的请求流上限，H1始终受协议的一流限制。静态UDP入口的本地流可能一直保留到空闲超时，物理会话上限须容纳仍活跃的H1 UDP关联；不能将多个物理H1连接称为复用。

UoT默认关闭。出站启用时版本只能1或2，默认2；固定UDP和多目标关联分别有接口。v1保留域名 `sp.udp-over-tcp.arpa`，v2为 `sp.v2.udp-over-tcp.arpa`；不允许普通 `connect_tcp` 将这两个目标当网站访问。v2支持connect固定目标与逐包模式，v1逐包模式。原sing客户端保留域名CONNECT使用端口0，节点仅对这两个域名接受并映射内部占位1；普通网站端口0拒绝，原生出站保留域名使用占位1。网站UDP包保留空包、包边界和来源；上限同时受u16帧、运行时和真实IP UDP限制。多目标使用同一远端关联socket，不按目标拆成多个固定通道。节点启用UoT时声明要求出口具备关联能力，配置准备阶段拒绝不满足的出口。

当前 `Capabilities` 为TCP=true、UDP取决于UoT、tcp_eof=false；原生实现写端EOF映射到载体写端结束并继续读，但最终目标EOF的声明要等真实对端独立验收。不能由H2/H3有END_STREAM/FIN推定所有参照的半关闭行为。

`NaiveFactory::compile_with_connector(options, Arc<dyn StreamConnector>)` 只允许H1/H2；该连接器先建立代理接入字节流，Naive再在其上校验自己的TLS。H3显式拒绝此构造，不忽略注入后直连。节点网站地址族由统一目标访问服务选择，接入IPv4/IPv6不限制目标网站族。

固定forwardproxy的H1分支尽管发Padding响应头，却使用无填充流；本模块H1按sing-box的padded线格式实现，两者组合不兼容，不提供首包猜测/无填充回退。固定Caddy的H2/H3只提供TCP，不识别UoT；原官方Naive客户端的Chrome网络栈、preamble与指纹行为也不属于本模块能力。

1.0.0接口核对范围：工厂名、JSON字段与默认值、严格未知字段拒绝、Basic真实凭据域、两类UDP接口、监听与业务数据能力、EOF准入和连接器限制均与实现对齐。软件版本由workspace统一继承；外层配置 `version:2` 是项目配置模式版本，UoT的1/2是线协议版本，均不随软件发布号改写。

## 完成权与绑定元数据

本轮完成权迁移源码与回归已编写，尚未运行新输入。底层 `Outbound::connect_tcp` 返回 `OpenedTcp`，本协议没有可证实的目标连接绑定字段，明确返回 `TcpConnectInfo::unknown()`。代理端点和载体本地地址不代填业务绑定。底层 UDP 通道保持原接口，唯一业务计量仍由 Dispatcher 包装。

入站从 `PeerSession` 取得 `TcpFlow`、`FixedUdpFlow` 或 `UdpAssociation`。自定义会话拆出 typed I/O 和唯一完成权，先报告正常协议结束、超时、取消或错误，再释放 I/O。TCP 的单向 EOF 不提前结束反向数据；零长度 UDP 包不作为 EOF。完成权只固定终因，最后计量 I/O 租约释放后才生成稳定终态，不重复累计流量。父级载体保留已建立流的完成权，关闭后拒绝新登记，旧代次结果不能关闭新流。

节点的原生 QUIC 驱动与派生入站任务登记到 `InboundContext.tasks` 的 `NodeTasks`。局部任务句柄释放只撤销所属任务，真实 JoinHandle 仍由 Engine 持有。外层 handler 被强制中止后，Engine 继续在同一关闭截止时间内等待实际节点任务；一个 peer 不能关闭节点任务所有者或共享出站。局部 `NodeEvent::ForcedCleanup` 只登记强制回收事实，Engine 确认 handler 与实际节点任务全部退出后才增加公开计数。超出预算仍保留未完成事实，不能记录为关闭成功。

子任务的完成权票据意外释放时，先从父表唯一移出，再在锁外报告终因：正在展开的 panic 为 Failed，已观察取消为 Cancelled，其余为 ClosedByCaller。显式完成或父级关闭已消费的票据不再次报告，后续正常父级 END 不能覆盖子流失败；已知计时器和协议错误仍显式报告。
