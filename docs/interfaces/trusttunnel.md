# TrustTunnel 双端接口

配置模式为`version:2`。节点的`members`引用管理账户`user_id`，分别保存`credential_epoch`与`native_credential`。管理用户名、管理密码摘要和协议凭据互不代用。节点工厂接收`NodeBuildContext`，鉴权前只持`IngressBinding`，鉴权后使用`PeerSession`访问共享Dispatcher。

每条成员凭据为`{"username":"node-user","password":"synthetic-password"}`，节点options不再接受users。H1/H2/H3每个CONNECT按实际Basic命中行创建peer；_udp2的各目标flow继承该用户。密码隔离条目只登记Protection。

出站工厂通过`compile`校验配置与资产，返回一次性`OutboundPlan`；`start(ServiceContext)`才创建命名运行实例。一个Engine内每条命名出站只有一个实例，池按`ConnectContext.resource_key()`的服务、成员和凭据代次分区。持久任务登记到ServiceContext，shutdown停止并等待自身资源；单个请求或节点不关闭共享出站。使用TLS的共享出站不跨成员复用恢复票据。

成员池的外层表只在查找或取得 bucket 时短暂加锁。DNS、载体拨号和协议协商只持对应成员 bucket 的锁；其他成员可同时建立载体。关闭时先从表和 bucket 移出资源，再等待清理，不跨 await 持有全局池锁。bucket 只保存池状态，不创建第二个完整出站实例。

QUIC 入站的节点任务所有者登记原生驱动，使用独立子取消域。普通节点排空首次观察到逻辑预算关闭时固定 `drain_timeout` 总截止时间，H3 连接与物理 QUIC 所有者共用该时间。前 80% 允许既有请求协作完成，后 20% 留给关闭载体、强制取消和 join。已接纳业务全部结束时保留各自正常终因；协作期限到达仍有请求时，父级先为仍活跃业务固定 Timeout，再清理。局部清理在原总期限内完成才返回 `Error::Timeout`，超期或任务异常另报清理错误。外部 Engine 仍保留 NodeTasks 的真实 join 权，必须确认实际任务退出，不能据包装任务退出声明已回收。`NodeEvent::ForcedCleanup` 不替代业务 FlowRecord 的 Timeout，也不单独表示公开关闭成功。节点通知取消优先于排空计时，也不会取消共享出站服务。

QUIC 鉴权使用已接受连接的 remote_address 记录实际可观察来源；该字段不参与 ResourceKey，也不取客户端请求自报地址。TCP 来源继续沿用接入层的 socket 地址。

本模块代理出站声明`TargetPolicy::Remote`，保留网站原目标、端口和负载。本机只解析代理接入端点，网站解析由远端负责；协议无法表达的目标明确拒绝。TCP连接与UDP关联建立后固定所选出站，不在失败后跨代理或直连重放。


2026-11-01历史快照曾由Egress预解析网站域名。本轮已按[0010远端原目标透传](../decisions/0010-node-egress-modes-and-warp.md)改写调用边界，不支持的原目标类型明确拒绝；当前代码尚未复验，旧结果不证明新路径通过，共享调度器、节点模式和设备WARP也不据此登记验收。

日期：2026-10-31。对应总表 P-18。**原验证已停止，协议尚未交付完成。最后已验是perf-02 r12的20项Rust、格式、选定包/专用CLI严格Clippy与构建；当前本地H2连接窗口及新增回归未同步/未编译/未测。** 不能据本文扩大互通通过范围；实际状态见[测试记录](../testing/trusttunnel.md)，固定证据见[研究](../../reference/research_notes/trusttunnel.md)。

包 `kerlico-trusttunnel` 导出 `TrustTunnelFactory` 和 `TrustTunnelNodeFactory`，两者 kind 均为 `trusttunnel`。构造只验证配置、读取指定证书文件及构建协议对象，不创建监听或拨号。主程序的根依赖、feature 和注册由公共集成任务维护。

## 本轮接口范围

| 载体 | 安全 | 客户端/节点业务 | 物理节点入口 |
| --- | --- | --- | --- |
| `h1` | TLS1.2、TLS1.3 | TCP、固定目标UDP | TCP，每条CONNECT一连接 |
| `h2`，默认 | TLS1.2、TLS1.3，ALPN `h2` | TCP、固定目标UDP | TCP，HTTP/2多流 |
| `h3` | QUICv1、TLS1.3，ALPN `h3` | TCP、固定目标UDP | UDP，HTTP/3多流 |

不提供明文载体、h2c、任意WS/gRPC包装、自动H3/H2竞速、ECH/指纹/ClientRandom鉴权密钥、订阅或系统VPN管理。未知选项直接拒绝。普通CONNECT保留目标authority；`_udp2`、`_check`、`_icmp` 为独立控制authority。extended CONNECT 不是本轮业务路径。

客户端 `capabilities={tcp:true,tcp_eof:false,udp:<配置>}`；H2/H3自端实现单向EOF，但外部H1/Mihomo等关闭边界尚不能保证，通用能力保守登记false。原始FIN、自端大负载、真实对端FIN分别留证，不能用正常回写代替半关闭验收。`supports_udp_association=false`，不提供Full Cone；节点也不要求统一出口支持多目标关联。

H1读取到头尾即止，CONNECT成功后直接承载字节，不套chunked层；客户端实际请求头不超过官方的1024字节限制。H1节点最多32项头部；H2/H3头部总预算16384字节。H2流初始窗口131072字节。H3禁用QUIC DATAGRAM，UDP只在可靠HTTP DATA里传输。两端禁用0-RTT；普通会话票据保持TLS库默认，不用关闭票据来隐藏问题。

## 出站配置

```json
{
  "server": {"host": "127.0.0.1", "port": 8443},
  "transport": "h2",
  "auth": {"username": "test", "password": "独立测试秘密"},
  "tls": {
    "server_name": "tt.example.invalid",
    "ca_pem": "PEM字符串",
    "version": "auto"
  },
  "udp": true,
  "app_name": "kerlico",
  "limits": {
    "max_connections": 4,
    "max_streams": 64,
    "max_udp_flows": 64,
    "idle_timeout_ms": 30000,
    "health_check_ms": 10000
  }
}
```

`server` 为代理节点接入地址，不是网站目标；网站目标继续传给 `connect_tcp/connect_udp`。TLS校验证书和名称；`ca_pem` 缺省只用内置公共根，指定时只信任指定CA。可选 `certificate_pem`、`private_key_pem` 必须同时提供，用于mTLS客户端证书，仍必须提供Basic。没有跳过校验开关。`version` 为 `auto/tls12/tls13`，H3拒绝tls12。

用户名和密码非空、不含控制字符，用户名不能含冒号，密码允许冒号；两者UTF-8字节总长不超过512。AppName最多255字节UTF-8，不含控制字符，仅为非认证元数据。客户端固定发出规范Base64 Basic，不把Base64当加密。

`max_connections` 为1–32，`max_streams`、`max_udp_flows` 为1–1024；两项时间为100–86400000毫秒。H1物理并发取 `max_connections` 与总逻辑上限的共同约束。H2/H3单连接流上限按总流数除以池大小向上取整，所有连接再共同受总逻辑上限约束；满额立即 `ResourceLimit`。出站`max_udp_flows`还限制本实例的固定UDP通道总数，发送/接收半通道全部释放后归还额度；节点同名字段限制单个HTTP流的四元组数量。出站对象独享池和TLS会话材料，不跨节点、认证或信任配置共用。

H2/H3空闲且无活动业务的物理连接自动关闭；后续重新建立新连接。在空闲达到健康检查间隔但尚未回收时，复用前先发认证 `_check`，不访问网站。GOAWAY、连接关闭和认证失败不重放已发送业务，不切换其他节点或直连。池锁只覆盖选择/建立/健康检查，业务流继续独立受流控驱动。

## 节点配置

```json
{
  "tag": "node4",
  "type": "trusttunnel",
  "listen": "127.0.0.1:8443",
  "outbound": "direct",
  "members": [{"user_id":"00000000-0000-4000-8000-000000000001","credential_epoch":1,"native_credential":{"username":"test","password":"本节点独立秘密"}}],
  "options": {
    "transport": "h2",
    "tls": {
      "certificate_file": "server.pem",
      "private_key_file": "server-key.pem",
      "version": "auto"
    },
    "udp": true
  }
}
```

证书和私钥各自选择 `*_pem` 或 `*_file` 一种，大小各不超过1MiB；不接受两种重复来源。可选 `client_ca_pem` 使节点强制验证客户端证书；Basic仍必需。用户表1–256项，拒绝重复完整认证和表内重复密码秘密。

节点 `limits` 只接受 `max_streams`、`max_udp_flows`、`idle_timeout_ms`，默认值和范围同出站；物理会话数由NodeSpec/Engine预算负责。出站池的 `max_connections`、`health_check_ms` 在节点侧拒绝，避免接受不生效的配置。

每条CONNECT独立鉴权，拒绝重复 `proxy-authorization`，按所有用户的固定长度摘要做常量时间比较。完成鉴权和目标解码后才通过注入的 `PeerSession` 访问目标。本项目节点等待TCP目标连接成功才发200；普通外部200仅表示代理受理，不能外推最终目标连接已建立。

鉴权指纹来自真实完整Basic，保持 `trusttunnel` 认证域；同时提供与原生HTTP代理一致的 `http` 摘要，因为H1 TCP CONNECT可用同一整组Basic凭据互相认证，不能因配置类型不同绕过查重。额外秘密隔离指纹用 `trusttunnel-password` 域，拒绝两个TrustTunnel节点换用户名重用同一密码。额外秘密只用于查重，不授予节点鉴权资格；证书公共信息、SNI、AppName或虚拟源地址不代替秘密认证。

## 数据、资源和错误

UDP每个Core固定通道独占一个 `_udp2` HTTP流，H2/H3仍可复用底层物理连接。服务端允许一个HTTP流容纳多个四元组，各自 `PeerSession::connect_udp`，每个flow独立预算和空闲期限。客户端声明的source仅作回包关联，不是本机bind地址或身份；回包source取自统一出口 `DatagramReceiver::peer_addr`，缺少实际业务来源时明确拒绝，不用代理载体地址补位。

UDP域名由Engine统一Egress先解析、默认IPv4优先；直接调用裸出站的域名UDP明确 `Unsupported`。TCP域名保留到目标统一出口。UDP空包是完整数据报；完整流EOF才返回None。最大业务包65507字节，并遵守节点Core更小限制。收到攻击者声明的超限u32长度时直接拒绝，不分配该长度；每flow发送队列8包，共享回包队列8包，均有界。

线格式把IPv4填入最后4字节、前12字节补零；按规范将 `::1` 特判为IPv6。IPv4 `0.0.0.1` 与部分 `::/96` IPv6不能无歧义往返，发送时拒绝。固定官方端的 `::1`、尾部零包和包长差异见研究，不以自端正确编解码外推对端。

认证失败407并停止该认证载体；TCP目标访问失败502；排空/预算不足503；非法请求400；关闭UDP或认证后的 `_icmp` 返回501。ICMP无能力开关，不调用原始套接字、不借UDP接口承接Echo。后续需要独立统一ICMP契约。`_check`只认证并返回200/EOF，不能创建网站目标。

Engine持有物理会话租约；H2/H3每CONNECT再取逻辑流预算，UDP每flow再取统一预算。排空关闭预算后不接受新网站目标；已有活动业务按统一取消/截止时间退出。TCP和UDP都带取消与双向活动空闲预算；异常分帧/部分发送取消后丢弃整个通道，不能重放剩余片段。

## 当前停止边界

参考端整体兼容未验收：官方回环旁路记录已作废并保留；官方H2 65000字节回写及H3/IPv6节点setup仍有失败，IPv6私有目标条件不足。Mihomo证书路径/信任夹具失败，固定上行unknown source 0:0又与当前Node的source port0拒绝条件冲突，均未修复或复验。

本地`client.rs`的2MiB H2连接窗口和`io.rs`的新atomic credit回归只是待验证增量，不能据代码意图写成已经解决。只读交接保存的源码/锁/二进制和各矩阵终态见测试记录；未启动后续验证。

## 完成权与绑定元数据

底层 `Outbound::connect_tcp` 返回 `OpenedTcp`，本协议没有可证实的目标连接绑定字段，明确返回 `TcpConnectInfo::unknown()`。代理端点和载体本地地址不代填业务绑定。底层 UDP 通道保持原接口，唯一业务计量仍由 Dispatcher 包装。

入站从 `PeerSession` 取得 `TcpFlow`、`FixedUdpFlow` 或 `UdpAssociation`。自定义会话拆出 typed I/O 和唯一完成权，先报告正常协议结束、超时、取消或错误，再释放 I/O。TCP 的单向 EOF 不提前结束反向数据；零长度 UDP 包不作为 EOF。完成权只固定终因，最后计量 I/O 租约释放后才生成稳定终态，不重复累计流量。父级载体保留已建立流的完成权，关闭后拒绝新登记，旧代次结果不能关闭新流。

节点的原生 QUIC 驱动与派生入站任务登记到 `InboundContext.tasks` 的 `NodeTasks`。局部任务句柄释放只撤销所属任务，真实 JoinHandle 仍由 Engine 持有。外层 handler 被强制中止后，Engine 继续在同一关闭截止时间内等待实际节点任务；一个 peer 不能关闭节点任务所有者或共享出站。局部 `NodeEvent::ForcedCleanup` 只登记强制回收事实，Engine 确认 handler 与实际节点任务全部退出后才增加公开计数。超出预算仍保留未完成事实，不能记录为关闭成功。

## 固定参考的 H2 无 ALPN 兼容

客户端 `tls.h2_allow_missing_alpn` 默认 `false`。只有配置中显式指定 `transport: "h2"` 才能设为 `true`；H1、H3或省略 transport 时设为 true 均在配置编译阶段拒绝。客户端始终发送 `h2` ALPN，并验证证书链与服务端名称。兼容选项只接受验证成功的 TLS 没有返回 ALPN，错误的非空 ALPN 仍拒绝，随后只执行 HTTP/2，不降级、不重试代理。

该选项用于固定 Mihomo 的先验 HTTP/2 over TLS 行为，不表示标准 HTTP/2 允许省略 ALPN。互通工具仅在本项目客户端到固定 Mihomo 的 H2 方向设置，并在结果输入单列 `mihomo_h2_alpn_mode`。真实 TLS1.2、TLS1.3严格与兼容回归、错误 ALPN、证书、名称和认证负例已编写，未执行本轮验证。

UDP `_udp2` 的父级表按目标与代次保留完成权。回复写任务报错直接成为失败原因，父级空闲超时先固定 Timeout 再取消子任务。下行包等待写任务确认，回包仍在队列中时不提前提交该子流终态。未知业务来源继续拒绝，不记录代理载体地址。

子任务的完成权票据意外释放时，先从父表唯一移出，再在锁外报告终因：正在展开的 panic 为 Failed，已观察取消为 Cancelled，其余为 ClosedByCaller。显式完成或父级关闭已消费的票据不再次报告，后续正常父级 END 不能覆盖子流失败；已知计时器和协议错误仍显式报告。

## 本轮审阅修复，待 worker 验证

H2 与 H3 的请求结果区分独立请求结束、鉴权拒绝和任务所有者失败。鉴权拒绝返回父级 `Error::Rejected`，父 FlowSet 先为仍活跃业务固定 Failed，再关闭载体并中止、回收请求任务。错误鉴权不创建业务账本，不能把拒绝触发的并发业务中断记为 ProtocolEnd。

私有 `RequestFailure::AuthenticationRejected` 仅由实际 Basic 凭据校验失败产生。407 发送失败也保留该判定，不能把已知认证拒绝改成普通请求结束。合法凭据通过校验后，目标策略返回的 `Error::Rejected` 属于独立操作失败，当前 CONNECT 返回 502，同载体的其他业务继续运行；该错误不代表凭据失效。H1 映射回原公共错误类型，H2/H3 仅按私有来源状态执行认证载体关闭，未增加公共错误码。

普通排空的结果同样区分请求全部结束与仍有请求超时。H2 在关闭前继续驱动物理连接，H3 的 accept None 仅停止接纳新的请求，不作为已有业务完成的依据；请求 JoinSet 为空才算协作完成。节点停止接入不打断既有 TCP 或 UDP 的最后一次收发。父 FlowSet 先固定终因，最后 I/O 租约释放后才生成最终用量和稳定记录。较早已固定的鉴权拒绝、真实载体失败或正常完成不被后续 Timeout 覆盖。

TT 私有原生运行时使用 `shutdown_at` 接收绝对截止时间，原来接收 Duration 并重建期限的接口已移除。外层 QUIC 在取消子域前关闭各独立连接的 FlowSet；登记仅保存弱引用，不合并连接或用户的业务账本。真实 NodeTasks 报告由外部所有者读取；Engine 自己更早固定的关闭期限和取消保持优先。`handle_udp` 本身也是同一 NodeTasks 的任务，运行时内部不能关闭或等待整个所有者，以免自等。单个 H3 peer 也不关闭整个节点任务所有者。

本节实现与新增回归已写入独立修复树，未运行构建、格式、静态检查、单元或互通测试。历史结果不适用于本轮输入，不能据此登记验收通过。

## H3 准入拒绝与解析前所有权修订，待 worker 验证

H3 在逻辑预算不足或已关闭时，对尚未接纳的请求发送 `H3_REQUEST_REJECTED` reset 和 STOP_SENDING。该分支不解析请求头、不鉴权、不建立目标业务，也不关闭已有请求的载体。直接丢弃未发送响应的请求可能产生响应头前 EOF，固定客户端会把它解释为连接级错误。

固定 h3 的请求结束归属从 `RequestResolver` 创建时开始。解析成功后，同一个 `Arc<RequestEnd>` 移交给 `RequestStream`；解析前拒绝、错误或释放都会归还排空账项。拆分的发送和接收半流继续共享这份归属，最后一个持有者释放后只结算一次。该调整不改变公开函数签名、错误码或现有字段的可移动性，补丁范围见 [h3 补丁记录](../../third_party/h3/PATCHES.md)。

H2 的目标拒绝用例已在原失败输入中完成 502、后续业务往返和合法控制请求，但服务端收尾返回 Protocol。本轮仅增加测试构建中的准确底层诊断，正式错误映射未变。
