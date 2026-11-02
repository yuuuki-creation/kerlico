# Mieru 双端接口

2026-11-02共享运行迁移已编写，尚未编译、格式检查或测试。本文保留的历史通过记录只对应原输入，不代表当前整树已验收。

配置模式为`version:2`。节点的`members`引用管理账户`user_id`，分别保存`credential_epoch`与`native_credential`。管理用户名、管理密码摘要和协议凭据互不代用。节点工厂接收`NodeBuildContext`，鉴权前只持`IngressBinding`，鉴权后使用`PeerSession`访问共享Dispatcher。

TCP节点的每条成员凭据为`{"username":"node-user","password":"synthetic-password"}`，节点options不再接受username/password/users。命中身份来自首次成功解密的实际Key，不能只凭nonce中的用户hint授予身份。旧不安全UDP仅用Local，编码材料保留在options并登记Protection。

出站工厂通过`compile`校验配置与资产，返回一次性`OutboundPlan`；`start(ServiceContext)`才创建命名运行实例。一个Engine内每条命名出站只有一个实例，池按`ConnectContext.resource_key()`的服务、成员和凭据代次分区。持久任务登记到ServiceContext，shutdown停止并等待自身资源；单个请求或节点不关闭共享出站。使用TLS的共享出站不跨成员复用恢复票据。

成员池的外层表只在查找或取得 bucket 时短暂加锁。DNS、载体拨号和协议协商只持对应成员 bucket 的锁；其他成员可同时建立载体。关闭时先从表和 bucket 移出资源，再等待清理，不跨 await 持有全局池锁。bucket 只保存池状态，不创建第二个完整出站实例。

Mieru UnsafeUDP 本地兼容模式在收到真实 recv_from 来源后才建立 Local peer，每条逻辑会话固定此来源；TCP 继续使用接入层来源。兼容模式不会把报文中的用户提示当成已鉴权身份。

本轮逻辑流终止不再持续返回可重试的`Interrupted`。明确请求取消使用独立私有原因，并通过`ConnectionAborted`及`Error::Cancelled`来源返回；普通泵错误、队列关闭和释放路径仍按失败处理，不能只按`ConnectionAborted`种类归为取消。该原因值不进入线格式，也不改变认证或容量。原始出站流的`read_exact`、`write_all`取消回归与未分类失败回归已编写，尚待海外worker执行。

本轮后续修订把`abort_cancel`限定为逻辑泵和队列的机制性清理信号。每条入站逻辑会话用真正peer取消域派生自己的目标请求token，relay保留peer取消语义。`run_session`私有所有者持有TCP流或UDP关联的唯一完成权，先报告实际结果，再取消该逻辑请求token回收后端派生资源。普通内部终止先固定Failed，明确空闲期限记Timeout，请求、peer、节点或共享服务的真实取消仍记Cancelled；清理Drop不改写已知Timeout。TCP与旧本地UDP载体的明确idle原因使用同一私有超时值。

建立期使用`FlowOpen`承接同一个完成权。私有`PendingTarget`在目标尚未返回时也能读取Life的首次原因，并在真正建链future被销毁前调用`finish`。其后RequestCleanup才取消本逻辑请求child token。成功返回时完成权随typed flow进入既有SessionTarget，不另开账本。TCP、固定UDP、多目标UDP的公共建立方法保持原名称和await用法，可信构造边界见[核心接口](core.md)。该Pending补漏已编写，尚未运行本输入。

正常对端整会话关闭仍可终止反向剩余数据，不新增半关闭保证。明确`peer_close`与仅因资源析构产生的`finished`分别记录；前者在没有失败或真实取消时按ProtocolEnd完成，后者不能单凭finished推导成功。新增真实入站回归使用生产首帧解密、凭据匹配与PeerSession签发路径，通过既有driver的abort命令触发reason 2，检查真实TCP目标和UDP关联的FlowRecord、单次计量、已交付尾部及原许可。代码与回归均已编写，尚未在本输入执行。

目标仍Pending时的正常Frame 4/5同样报告ProtocolEnd。没有已知失败且真实取消域均未取消时，记录可为Opening阶段、Completed终因且业务量为零，不表示网站目标已连接。命名服务已因后台任务失败而取消时，真实FlowLease在Opening阶段固定Cancelled，即使建立future未再次poll；已交付流及已固定终因不被此规则改写。

仅由普通Entry析构发出的finished仍使用ClosedByCaller或真实取消、已知失败兜底。Pending回归在真实Direct后端已持有回环socket时触发内部abort、peer/node取消、idle、建立期限和协议关闭，并检查较早独立失败/超时不会被后续清理改写。新增服务失败回归使用绑定同一命名服务的真实后台panic，确认服务token已取消且当前FlowOpen未再次poll，再经加密载体发送合法Frame 4或5。测试轮询门只延迟指定逻辑会话的PendingTarget，保留原waker，终因和资源回收仍由生产driver与唯一完成权处理。普通系统ConnectionAborted或TimedOut仍归Failed。这些回归已编写、尚未运行，使用TCP载体内的TCP与UDP关联，不代替旧本地UDP载体的线格式验证。

本模块代理出站声明`TargetPolicy::Remote`，保留网站原目标、端口和负载。本机只解析代理接入端点，网站解析由远端负责；协议无法表达的目标明确拒绝。TCP连接与UDP关联建立后固定所选出站，不在失败后跨代理或直连重放。


2026-11-01历史快照曾由Egress预解析网站域名，并限制固定UDP只接受IP。本轮已按[0010远端原目标透传](../decisions/0010-node-egress-modes-and-warp.md)改写调用边界；当前代码尚未复验，旧结果不证明新路径通过，共享调度器、节点模式和设备WARP也不据此登记验收。

日期：2026-10-31。状态：原生双端、21 项 Rust 测试、config 3 项回归、严格 Clippy/格式/CLI 通过；两版官方 API 与原 Mihomo 的限定矩阵已验，包长和本地 UDP 风险分别记录于 `docs/testing/mieru.md`。类型名 `mieru`，导出 `MieruFactory` / `MieruNodeFactory`。调研及已复现的原 UDP 密码学限制见 `reference/research_notes/mieru.md`。

## 客户端出站

```json
{
  "server": {"host": "127.0.0.1", "port": 10443},
  "username": "node-user",
  "password": "synthetic-password",
  "transport": "tcp",
  "multiplexing": true,
  "no_wait": false,
  "max_sessions": 128,
  "idle_timeout_secs": 60,
  "mtu": 1400,
  "traffic": {"low_entropy_mode": 0, "mask_rotation": 0, "max_padding": 32}
}
```

默认载体为 TCP；它使用 Mieru 自身的 XChaCha20-Poly1305、时间密钥、分段与逻辑会话，不附加 WS/TLS/QUIC 等其他协议载体。可传输 TCP 及 Full Cone UDP 包隧道。`tcp_eof=false`：官方关闭语义是完整会话关闭，不能独立关闭写方向并继续等待新反向数据；需要 `require_remote_eof` 的固定入口在准备阶段拒绝。

用户名按 UTF-8 字节计为 1–64，密码为 1–4096 字节，两者拒绝 NUL。大小写与其他字符按原字节参与密钥派生。没有代理载体的 SNI、证书或 TLS 恢复配置。TCP 的服务器域名有界解析，优先 IPv4 首个候选，握手失败不自动换地址、凭据或另一节点。本地目标由共享调度器解析，远端目标保持原域名。

`multiplexing=true` 在实例独立的物理载体内复用逻辑会话；false 每会话使用独立载体。`no_wait=true` 延迟到首次应用写入才发请求，并提前返回流；接入 TCP 成功不代表凭据或目标已通过，错误通过后续读/flush 返回，先读会等待首次写入。初始握手仍受预算约束，不提供无限闲置的未认证连接或 0-RTT 票据。

客户端 `max_sessions` 范围 1–128，空闲秒数 1–600，MTU 576–1500；MTU 只用于 UDP 兼容载体的发段上限，不把 TCP 限为该长度。每实例最多保留 128 个物理载体，创建超过 120 秒的载体不再增加新逻辑会话，已有会话继续使用原选定密钥。没有跨实例/节点共享密码连接池。

## TCP 服务端节点

`nodes` 条目采用如下 `options`：

```json
{
  "transport": "tcp",
  "user_hint_required": true,
  "traffic": {"low_entropy_mode": 0, "mask_rotation": 0, "max_padding": 32}
}
```

TCP节点只从外层members读取用户名和密码；用户数 1–256，同节点不允许重复用户名。物理 TCP 与额外逻辑会话分别占用全局/节点预算。每次新会话先校验完整段、方向、时间、ID 和负载，再经 `PeerSession` 处理精简 SOCKS 请求。TCP 目标实际建立后才发送成功回应；UDP Associate 使用 `DatagramAssociation`，缺少 Full Cone 能力的出口在准备阶段拒绝，不隐式降级或绕过出口。

鉴权与配置隔离分开：TCP 鉴权集合包含基于真实 `SHA256(password || 00 || username)` 基础秘密的指纹；隔离集合同时包含 `mieru` 基础秘密域与 `mieru-user` 用户名域。因此同名不同密码会按身份规则拒绝，相同实际凭据跨载体也会拒绝；不同身份的基础秘密因用户名参与而分别派生。IPv4/IPv6 节点分别配置身份与地址，不能把用户名指纹说成时间密钥或秘密指纹。

TCP 首 nonce 的内存重放表最多 16384 条，保留 360 秒；完整解密及合法首次打开之后才记录，未到期容量满时拒绝新增。重启不保留该内存表。实际元数据接受当前分钟前后各 1 分钟，客户端/服务端需要相符的系统时钟。时间密钥更新不等于已实现前向保密或密码学审计。

## 仅本机的旧 UDP 载体

原协议在一个 UDP 段中对元数据和负载复用同一 key/nonce，已由两个固定官方版本的独立探针复现已知明文异或关系。故公网 UDP 载体**未支持**；密码字段和成功互通不构成可靠鉴权保证。

本地兼容用途必须使用 `local_inbounds`，例如：

```json
{
  "tag": "local-compatibility",
  "type": "mieru",
  "listen": "127.0.0.1:11443",
  "outbound": "direct",
  "options": {
    "username": "local-user",
    "password": "different-synthetic-password",
    "transport": "udp",
    "unsafe_udp_compatibility": true
  }
}
```

该模式返回空鉴权集合、强制回环，并仍以隔离集合阻止复用其他 Mieru TCP/UDP 条目的秘密或用户名。即使 `nodes` 监听回环，也不能放入其中。出站同样要求显式标志及服务器为 IP 字面量回环；`localhost`、其他域名、非回环、IPv4-mapped IPv6 均拒绝。运行时再次核对 socket。TCP 带不安全 UDP 标志或一条配置混用两载体均拒绝；不修改官方 nonce/key 规则伪造兼容。此去重针对同一配置内的接入条目，不能检查其他进程或手填出站的秘密；本地兼容模式仍须使用独立于公网的凭据。

本地模式保留完整 UDP 线格式、会话、累积 ACK、有限窗口、乱序和重复抑制、RTO/快速重传与关闭回应墓碑。发送窗口为有界加性增大/乘性减小，没有提供名为 CUBIC/BBR 的无效开关，也没有性能结论。每次重传重新生成该段 nonce；这不修复同段内的既有复用问题。

## 数据与资源边界

UDP Associate 每包携带目标/来源，域名经统一出口解析并默认优先 IPv4；同一关联保持一个出口 socket、支持跨目标/地址族和未先联系来源。固定 UDP 通道只接受统一出口已经解析的 IP 目标，并过滤其他来源；多目标或域名使用关联接口，不在客户端私自解析网站地址。

UDP 负载最多 65507 字节，另受节点上限及“地址+负载”不超过 65535 字节限制；长域名可能降低可容纳负载。空 UDP 包合法，包隧道有独立长度/标记，不以空包表示 EOF。读取或写入在半帧处取消后，该方向失效，不得继续拼接新包或重试半帧。

每载体活动逻辑会话最多 128，累计 ID 最多 8192，不复用已退役 ID；预算可能进一步收紧。每逻辑待交付原字节上限 256 KiB，另有 32 KiB 双工缓冲与固定复制槽。TCP 待发队列最多 512 段/8 MiB，串行写端有界；慢逻辑流超过限额只关闭相应会话，不重置其他流的 nonce。帧首字节到达后按建立预算读完整帧，热队列也执行期限与回收。

UDP 兼容模式乱序缓冲最多 128 段、向对端通告的接收窗口最多 32 段，待发/未 ACK 最多 512 段；每段发送次数上限 20，RTO 100 ms–3 秒、退避最高 5 秒，ACK 与关闭控制不受数据零窗口阻塞。关闭墓碑最多 8192、360 秒，不持有网站 socket 或逻辑预算。源地址与身份固定，不做跨地址迁移。模块仅为自己持有的 UDP socket 请求 2 MiB 接收缓冲，受系统上限限制，不修改全局 sysctl；通告窗口保留内核 skb 与共享载体余量。

`traffic.low_entropy_mode` 为 0/1/2/3/4，分别关闭或使用 32/40/48/56 模式；`mask_rotation` 为 0、右旋 1–15 或左旋 16 的 1–15 倍，mode=0 时只能为 0。四种模式及填充均为流量编码，不是额外加密。未知字段、旧 v2、端口范围/漫游、任意固定 nonce、管理面、热重载、指纹和其他载体均没有交付。

## 完成权与绑定元数据

本轮完成权迁移源码与回归已编写，尚未运行新输入。底层 `Outbound::connect_tcp` 返回 `OpenedTcp`，本协议没有可证实的目标连接绑定字段，明确返回 `TcpConnectInfo::unknown()`。代理端点和载体本地地址不代填业务绑定。底层 UDP 通道保持原接口，唯一业务计量仍由 Dispatcher 包装。

入站从 `PeerSession` 取得 `TcpFlow`、`FixedUdpFlow` 或 `UdpAssociation`。自定义会话拆出 typed I/O 和唯一完成权，先报告正常协议结束、超时、取消或错误，再释放 I/O。TCP 的单向 EOF 不提前结束反向数据；零长度 UDP 包不作为 EOF。完成权只固定终因，最后计量 I/O 租约释放后才生成稳定终态，不重复累计流量。每个Mieru逻辑会话保留自己的完成权，成功应答失败与双向传输结束分别报告；完成权不绑定整个复用载体。

TCP 与回环 UDP 服务端 Scope 使用本节点 NodeTasks 登记实际泵和会话任务，客户端 Scope 使用命名出站 ServiceContext。服务端外层 handler 被中止后，Engine 仍能等待内部真实任务。单 peer 仅停止自己的 Scope，不关闭 NodeTasks；关闭后的登记直接停止该 Scope，不退回独立 spawn。此补漏及 socket 回归仅已编写，尚未运行。
