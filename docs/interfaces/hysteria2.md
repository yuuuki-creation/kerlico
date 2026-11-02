# Hysteria2 双端接口

2026-11-02共享运行迁移已编写，尚未编译、格式检查或测试。本文保留的历史通过记录只对应原输入，不代表当前整树已验收。

配置模式为`version:2`。节点的`members`引用管理账户`user_id`，分别保存`credential_epoch`与`native_credential`。管理用户名、管理密码摘要和协议凭据互不代用。节点工厂接收`NodeBuildContext`，鉴权前只持`IngressBinding`，鉴权后使用`PeerSession`访问共享Dispatcher。

每条成员凭据为`{"auth":"synthetic-password"}`，节点options不再保存auth。H3认证请求的实际命中行创建连接peer，已认证连接不接受改换成员；Salamander秘密只登记Protection。

出站工厂通过`compile`校验配置与资产，返回一次性`OutboundPlan`；`start(ServiceContext)`才创建命名运行实例。一个Engine内每条命名出站只有一个实例，池按`ConnectContext.resource_key()`的服务、成员和凭据代次分区。持久任务登记到ServiceContext，shutdown停止并等待自身资源；单个请求或节点不关闭共享出站。使用TLS的共享出站不跨成员复用恢复票据。

成员池的外层表只在查找或取得 bucket 时短暂加锁。DNS、载体拨号和协议协商只持对应成员 bucket 的锁；其他成员可同时建立载体。关闭时先从表和 bucket 移出资源，再等待清理，不跨 await 持有全局池锁。bucket 只保存池状态，不创建第二个完整出站实例。

QUIC 的 NEW_TOKEN 缓存与 TLS 恢复票据分开处理。每次建立新 QUIC 连接都在克隆的 ClientConfig 上设置独立 TokenMemoryCache，避免缓存随配置 Arc 跨成员共享；当前也不跨重连复用 NEW_TOKEN，不修改上游 token 算法。

QUIC 入站的节点任务所有者登记原生驱动，使用独立子取消域。节点停止接入后先回收自己的连接，再关闭端点并在原 drain_timeout 总预算内排空；末段预算留给强制取消和实际 join。自然排空到期后，若全部登记任务已完成强制回收，记录 NodeEvent::ForcedCleanup 并返回成功；它不计为 Failed 或数据包 Dropped。强制后仍未完成或任务异常退出才返回错误。节点通知取消不会提前丢弃 QUIC 驱动，也不会取消共享出站服务。

QUIC 鉴权使用已接受连接的 remote_address 记录实际可观察来源；该字段不参与 ResourceKey，也不取客户端请求自报地址。TCP 来源继续沿用接入层的 socket 地址。

本模块代理出站声明`TargetPolicy::Remote`，保留网站原目标、端口和负载。本机只解析代理接入端点，网站解析由远端负责；协议无法表达的目标明确拒绝。TCP连接与UDP关联建立后固定所选出站，不在失败后跨代理或直连重放。


日期：2026-10-31。状态：本轮范围已实现，通过 worker 的 8 项 Rust 测试和 544 项正式 CLI 检查；完整角色、组合和限制以验证记录为准。

`kerlico-hysteria2` 导出 `Hysteria2Factory`、`Hysteria2NodeFactory` 以及后端类型`Hysteria2Outbound`、`Hysteria2Node`。运行出站由OutboundPlan.start创建。类型均为 `hysteria2`。同一可执行程序按角色装配，入站与出站分别记录结果。

## 首轮完整范围

- QUIC v1、TLS 1.3、ALPN h3，双端 HTTP/3 鉴权；无认证或错误认证请求返回静态 404 页面。
- 原生 TCP 业务流，目标成功响应后返回流，保留写端 FIN 和反向排空。
- 原生 QUIC UDP datagram，固定目标与同一 Session ID 的多目标关联，支持空包、分片、乱序重组、冲突/缺片/超时丢弃与实际来源地址回写。
- 普通 QUIC 与 Salamander 两种载体；自适应 BBR、NewReno 两种拥塞配置。
- 独立 IPv4/IPv6 节点凭据、节点/全局资源预算、统一目标访问、空闲回收、取消与退出。

具体结果见[验证记录](../testing/hysteria2.md)。Hysteria v1、Gecko、Brutal 固定速率、端口跳跃、Realm、noise、ECH、指纹模仿、外部认证与反向伪装代理尚未实现，不提供无效开关。

## 配置

客户端 options：

```json
{
  "server": {"host":"127.0.0.1","port":8443},
  "auth":"synthetic-node-secret",
  "tls": {"server_name":"localhost","ca_pem":"PEM 内容"},
  "salamander_password":null,
  "limits": {"congestion":"bbr"}
}
```

节点 options：

```json
{
  "tls": {"certificate_file":"certificate.pem","private_key_file":"private-key.pem"},
  "udp":true,
  "salamander_password":null,
  "limits": {"congestion":"bbr"}
}
```

同一节点的客户端与服务端 auth 必须一致，IPv4/IPv6 不同节点分别设置独立 auth。节点 TLS 每种材料分别选择 `_pem` 或 `_file`，不得同时填写；单份材料最多 1 MiB。客户端不设 ca_pem 时信任内置公共根；不接受 insecure 跳过验证。auth 必须为非空、至多 4096 字节的合法 HTTP 字段值，拒绝首尾空白。Salamander 密码为可选的 4–4096 字节字符串，必须双端一致，它不替代 auth。

`limits` 默认值：max_streams=64、udp_queue_packets=16、udp_queue_bytes=4194304、idle_timeout_ms=30000、congestion=bbr。允许 max_streams 1–1024、UDP 队列 1–64 包、队列字节 65536–16777216、空闲时间 100–86400000 毫秒。congestion 仅接受 bbr 或 reno；实际使用 Quinn 对应控制器，不宣称与官方 BBR/Brutal 实现性能相同。

客户端 auth 请求通告接收速率 0；服务端返回 auto，采用自适应控制。客户端接收对端的 0/auto；收到非零固定速率会明确拒绝，避免接受但忽略尚未实现的协商限制。

## 节点、服务和生命周期

物理监听只使用 UDP/QUIC，TCP 业务通过 QUIC stream 承载；不建立同端口 TCP listener。UDP 业务可以关闭，此时物理 QUIC 仍通过 UDP 工作。开启 UDP 业务时，节点要求出口实现 `DatagramAssociation`，配置准备阶段通过 `requires_udp_association` 校验；不得静默退回多个固定目标 socket。

每个节点只保存本节点 auth 指纹与载体配置，注册表拒绝同协议跨节点复用 auth。节点经鉴权、解码后，TCP 使用 `PeerSession::connect_tcp`，UDP 使用 `PeerSession::associate_udp`。后者保留同一会话的出口 socket 与实际来源；节点、载体和目标的 IPv4/IPv6 不互相限制。

HTTP/3 与 TCPRequest 由唯一 bidirectional stream 接纳器按首个 varint 分流。普通请求和鉴权前的特殊类型交 HTTP/3 处理；0x401 只有在连接已鉴权后进入代理处理器。各 stream 的前缀字节保留，不靠两个 accept_bi 消费者竞争连接。

一个 QUIC carrier、每个新 HTTP/代理 stream 和 UDP 关联分别受共享预算约束；控制 stream 另有 QUIC 数量/窗口限制。UDP 队列同时受包数和字节数约束，分片最多 255 片，每会话只保留一个未完成包，5 秒后失效；有效回收还受业务空闲时间限制。最大业务包 65507 字节，零长度包不等于关闭。关闭新预算后拒绝新会话，既有业务可以在 engine 的排空期限内运行；强制取消后关闭 endpoint 并回收任务。

客户端连接池按出站实例保存，不跨节点共享带身份的资源。TCP 返回前完成认证、请求发送及成功响应；UDP 返回前确认对端支持 datagram。鉴权失败不会重试其他节点或凭据。错误文本不包含远端响应正文、认证值或原始 QUIC close reason。

## 完成权与绑定元数据

本轮完成权迁移源码与回归已编写，尚未运行新输入。底层 `Outbound::connect_tcp` 返回 `OpenedTcp`，本协议没有可证实的目标连接绑定字段，明确返回 `TcpConnectInfo::unknown()`。代理端点和载体本地地址不代填业务绑定。底层 UDP 通道保持原接口，唯一业务计量仍由 Dispatcher 包装。

入站从 `PeerSession` 取得 `TcpFlow`、`FixedUdpFlow` 或 `UdpAssociation`。自定义会话拆出 typed I/O 和唯一完成权，先报告正常协议结束、超时、取消或错误，再释放 I/O。TCP 的单向 EOF 不提前结束反向数据；零长度 UDP 包不作为 EOF。完成权只固定终因，最后计量 I/O 租约释放后才生成稳定终态，不重复累计流量。父级载体保留已建立流的完成权，关闭后拒绝新登记，旧代次结果不能关闭新流。

节点的原生 QUIC 驱动与派生入站任务登记到 `InboundContext.tasks` 的 `NodeTasks`。局部任务句柄释放只撤销所属任务，真实 JoinHandle 仍由 Engine 持有。外层 handler 被强制中止后，Engine 继续在同一关闭截止时间内等待实际节点任务；一个 peer 不能关闭节点任务所有者或共享出站。局部 `NodeEvent::ForcedCleanup` 只登记强制回收事实，Engine 确认 handler 与实际节点任务全部退出后才增加公开计数。超出预算仍保留未完成事实，不能记录为关闭成功。

子任务的完成权票据意外释放时，先从父表唯一移出，再在锁外报告终因：正在展开的 panic 为 Failed，已观察取消为 Cancelled，其余为 ClosedByCaller。显式完成或父级关闭已消费的票据不再次报告，后续正常父级 END 不能覆盖子流失败；已知计时器和协议错误仍显式报告。

## 本轮审阅修复，待 worker 验证

H3 `accept()` 首次返回 None 仅表示控制请求结束。服务端以这次返回为新准入关闭点，停止新原生 TCP 准入和新 UDP session，并固定一次 `drain_timeout` 截止时间。底层解析 GOAWAY 早于这个边界，不能将二者视为同一时刻。H3 对象保持到排空结束，继续驱动控制帧及原分流器。

唯一分流器继续持有并轮询此前已接纳的类型识别 future。`TCP_ID=0x401` 的两个 varint 字节只到达一个时，原 `StreamLease` 仍属该 future，既不丢弃也不重新申请配额。识别完成后，TCP 进入原队列继续读取请求头和连接目标；仍未识别的流、已接纳队列和实际 NodeTask 均计入排空。全部待识别流结束后才关闭队列的新发送，已排队项仍继续处理。未识别流没有业务目标，不为它创建虚假 FlowRecord。

排空期间每轮至多拒绝 64 个之后到达的真实 QUIC 双向流，再轮询旧识别 future。新流直接 reset 和 stop_sending，不进入 sniffer 集合或申请配额。旧识别 future 数下降才产生排空进展，空集合保持 Pending 并等待真实 I/O 唤醒，不能形成立即 None 循环。旧 UDP 关联仍可访问新目标；原截止时间不会因新流、UDP 活动或旧流完成识别而延长。

排空时，`H3Control` 每次 poll 新建一个 `accept()` future，只轮询一次后释放，不再次 poll 已完成的 future。固定 H3 先推进控制读取及原有 SETTINGS、GOAWAY 校验，再推进同一个分流器。重复 None 转为 Pending，保留已注册的控制流、QUIC 接纳与旧 sniffer waker，只有实际待识别集合缩减才向外报告进展。首次准入关闭点、原截止时间和旧任务归属不变。

旧 sniffer 在排空期间识别为非 TCP 时直接拒绝，保留原排空语义，不改变 H3 最后接纳 ID。相同关闭上界由固定 H3 跳过重复 GOAWAY。若 `accept()` 返回尚未处理的 HTTP resolver，包装只对该实际流执行 reset 与 stop_sending，随后由已有 RequestEnd 退账，不创建新请求任务。

独立 control stream RESET 即使没有先关闭整个 QUIC，也由固定 H3 解析为 `H3_CLOSED_CRITICAL_STREAM`。连接循环随后以 Failed 关闭已有业务完成权并回收资源，不等待原排空期限后将该错误登记为 Timeout。节点取消和首次 deadline 的既有优先级保持不变。

当前私有 `H3Control` 集中访问 `h3.inner.conn` 和 resolver 的 `frame_stream.stream`。这依赖固定供应源码 `third_party/h3/src/server/connection.rs`、`third_party/h3/src/connection.rs` 与 `third_party/h3/src/server/request.rs` 的实际公开字段及已有 RequestEnd RAII，不承诺稳定上游 API。需要额外 feature 的 `poll_accept_request_stream` 没有启用或使用，本轮不修改 h3 feature 或供应源码。

只有待识别流、队列和实际任务同时排空才正常结束。超时、节点取消与 QUIC 失败先固定对应父终因，再关闭和回收；取消与 QUIC 失败优先于排空成功，原节点取消及 Engine 外部截止时间仍优先。

本次控制流修复与两项新增真实 QUIC 回归已写入独立修复树，未运行构建、格式、静态检查、单元或互通测试。此前 r25 的 19 项库测试通过只属于原冻结输入，其中包括 11 项原生 GOAWAY 回归；该结果不覆盖本次修复、夹具和供应 H3 后续变化，不能据此登记当前输入验收通过。
