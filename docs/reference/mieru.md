# mieru

这篇是 mieru 的决定。段、元数据、密钥和 UDP 封装的字段以官方仓库 [enfein/mieru](https://github.com/enfein/mieru) 的 `docs/protocol.md` 为准。这里不复制那份字段表。代码还没全部跟上的地方，单独标成「代码未跟上」。

## 线协议

TCP 和 UDP 两种传输都要有。加密算法是 XChaCha20-Poly1305。密钥由用户名、密码和系统时间生成。服务端最多试三个时间盐。两端时钟差不能大于 4 分钟。nonce 是 24 字节。生成步骤以官方协议文档为准。

UDP 客户端载体固定对端。发送使用已连接套接字，接收仍校验来源。

共享实现用 `chacha20::hchacha::<U10>` 从密钥和 nonce 的前 16 字节派生子密钥，再由 `ring` 执行 ChaCha20-Poly1305，内部 nonce 为四个零字节和原 nonce 的后 8 字节。线上仍是同一套 XChaCha20-Poly1305 密文、16 字节标签和 24 字节 nonce。每个方向只缓存自己当前 nonce 前缀对应的子密钥；前缀变化会重新派生，两个方向和不同账号不共用缓存。测试以原 RustCrypto 实现逐字节对照，并覆盖 nonce 向前缀进位。

每个段都有 32 字节元数据。会话元数据、数据元数据和低熵扩展都要识别。协议类型从 2 到 11。低熵模式是 0、1、2、3、4，对应关闭以及官方的 `LOW_ENTROPY_MODE_32`、`LOW_ENTROPY_MODE_40`、`LOW_ENTROPY_MODE_48`、`LOW_ENTROPY_MODE_56`。

填充、序号、未确认序号、窗口和分片按官方文档做流控。UDP 按序号重排，并拒绝重放。TCP 单片最大 32768 字节。`LOW_ENTROPY_MODE_32` 的单片最大是 32764 字节。UDP 段必须放进一个数据报。MTU 取值是 1280 到 1400，默认 1400。两端使用同一个值。

多路复用是一条底层连接上的多个会话。服务端接受任意个数。客户端级别是 `MULTIPLEXING_OFF`、`MULTIPLEXING_LOW`、`MULTIPLEXING_MIDDLE`、`MULTIPLEXING_HIGH`。默认 `MULTIPLEXING_LOW`。`OFF` 时一条底层连接只有一个会话。各级别打开新连接的概率以官方客户端为准。

握手模式是 `HANDSHAKE_STANDARD` 和 `HANDSHAKE_NO_WAIT`。默认 `HANDSHAKE_STANDARD`。`HANDSHAKE_NO_WAIT` 允许首包带上应用数据。时序以官方客户端为准。

## 请求

认证之后的请求是 SOCKS5。`CONNECT` 和 `UDP ASSOCIATE` 都要有。`UDP ASSOCIATE` 的每个数据报先封装成 `0x00`、2 字节大端长度、数据、`0xff`，再作为段的载荷。TCP 和 UDP 两种传输使用同一套封装。

服务端为每个 `CONNECT` 交出一个 TCP `Handoff`，为 `UDP ASSOCIATE` 中每个目标各交出一个 UDP `Handoff`。同一 UDP 关联的交接共享会话标记，并携带对端地址。服务端仍逐目标分流，选择相同原生出口或支持共享关联的落地时复用同一出站 UDP 关联。回包头优先用实际回复源，包括未发送过的地址或端口。协议 crate 不拨号，也不选择出口。

## 监听和账号

节点的 `listen` 决定地址族。一个节点仍然只听一个族。`settings` 里的 `transport` 取值是 `TCP` 或 `UDP`，缺省是 `TCP`。

只使用节点上的端口时，听这一个端口。`settings` 里写了 `portRange` 时，听这一段连续端口。节点上的端口必须落在这段之内，否则配置错误。端口小于 1025 或大于 65535 时拒绝。`portRange` 的两端是十进制，中间一个连字符。

`mtu` 只对 UDP 生效。缺省 1400。小于 1280 或大于 1400 时拒绝。

用户的 `username` 和 `password` 放在该用户的 `Settings` 里。缺省用户名是邮箱。多个用户共用这个节点。

## 客户端入口

mieru 客户端不实现数据包平面。它导出 `CLIENT = ClientEntry::ProxyWithDatagramLanding`，客户端叶子在它前面运行本机 SOCKS5 和 HTTP 代理，官方把这个入口叫做 HTTP / HTTPS 代理。同一入站 UDP 会话的目标选中 mieru 落地时，复用同一条上游 `UDP ASSOCIATE`。命令行、文档语法、本机端口和 LAN 绑定，以及 SOCKS5 与 HTTP 的行为，见 `docs/reference/crates.md` 的「客户端叶子和本机入口」。

`multiplexing`、`handshakeMode` 和 `mtu` 使用上面的名字和取值。服务端地址、传输、单个端口或 `portRange` 也在客户端的 `Settings` 里。

`land` 和 `open_stream` 打开一条到目标的会话，走同一套段。TCP 和未标记共享会话的 UDP 落地仍调用 `land`。

独立客户端和落地的 TCP/UDP 载体均由出站打开。独立客户端通过出站使用系统解析器，落地通过服务端运行时使用配置的 DNS。端口范围的每个可选对端保留解析出的地址及作用域。

## 不进入这份实现的部分

官方 mita 的 DNS 和它自己的 RPC 不实现。解析、嗅探、FakeDNS、分流、拨号和用户计数以 `docs/reference/server.md` 为准。官方客户端给命令行改配置用的 RPC 不实现。

## 客户端配置与 API

客户端、服务端及可选落地分别使用以下构建命令，全部在 worker 执行：

```sh
cargo build -p kerlico-client --no-default-features --features mieru
cargo build -p kerlico-server --no-default-features --features mieru,landing-mieru
```

启用 `mieru` feature 后，从客户端叶子启动代理。文档写了 `"protocol": "mieru"` 时，`kerlico-client client.json` 走同一路径。

```text
kerlico-client --mieru-proxy client.json
```

```json
{
  "protocol": "mieru",
  "peer": "127.0.0.1:30000",
  "settings": {
    "username": "test-user",
    "password": "test-password",
    "transport": "TCP",
    "mtu": 1400,
    "multiplexing": "MULTIPLEXING_LOW",
    "handshakeMode": "HANDSHAKE_STANDARD",
    "lowEntropyMode": "LOW_ENTROPY_MODE_OFF",
    "socks5Port": 1080,
    "httpProxyPort": 8080,
    "socks5ListenLAN": false,
    "httpProxyListenLAN": false
  }
}
```

示例仅用合成账号。除叶子取走的四个本机入口键，`settings` 只接受 `username`、`password`、`transport`、`portRange`、`mtu`、`multiplexing`、`handshakeMode` 和 `lowEntropyMode`。未知键、非法枚举、空账号或密码都拒绝，不输出原始配置。`portRange` 使用上文约束。`lowEntropyMode` 接受上文五个名字，也接受 0 到 4。值按通用规则先转成文本，所以数字形式的 `username` 当作文本接受，不再按 JSON 类型拒绝。`protocol`、`peer` 与 `address`、`port` 的规则见 `crates.md`。

`kerlico-mieru-client::Client::new(host, port, settings)` 创建一个可克隆客户端，它实现客户端叶子的 `Upstream`。`open_stream(host, port)` 打开 TCP 目标，`associate()` 打开 UDP 关联。`close()` 幂等取消所有克隆共享的会话。

代理、`land` 和兼容的 `open_stream` 函数使用同一客户端实现。无状态落地按节点地址、账号和完整设置隔离缓存，最多 64 个配置。条目距上次调用超过 60 秒，且没有活跃会话或调用者时清退，每 5 秒检查一次。缓存满且全部活跃时返回 `Again`，不会合并不同账号的池。统一出口的 UDP 会话另外按节点和用户隔离。

本机入口由客户端叶子的 `Proxy::start` 绑定。生成菜单仍是协议名单的唯一来源。

四种复用级别的因子分别为 0、1、2、3。池有 N 条可调度底层连接时，新建概率为 `1/(N*因子+1)`；`OFF` 始终新建。服务端只接收会话，不选择级别。标准握手在打开会话前确认远端应答；`NO_WAIT` 返回惰性会话，首次应用写入发送请求及可用首批数据。读操作等待首次写入，不替调用者启动握手；关闭未写入会话不发送请求。UDP 关联使用标准握手。

UDP 底层的会话建立确认独立于 SOCKS 应答。客户端后续的 DATA、ACK 和心跳等待按序的 `OPEN_RESPONSE`；期间 `OPEN_REQUEST` 按规则重传，关闭消息不受该等待约束。普通 ACK 不能替代这一确认。`NO_WAIT` 不取消该 UDP 传输要求。等待有握手期限，关闭客户端会唤醒等待中的写入。TCP 由底层保证顺序，不增加这次等待。

一条 SOCKS5 UDP 关联对应一个 `Assoc`，数据报按原样带目标发出，空包也发送。

## 资源和线协议边界

接收和落地测试验证报文边界。macOS 的夹具发送符合默认内核限制的 UDP 载荷，Linux 的接收测试仍覆盖 32,000 和 65,000 字节，落地测试覆盖 32,768 字节。

`Conn::read_for` 与 `Assoc::recv_for` 超时只表示暂时没有数据，不能解释为 EOF；关联接收超时保留尚未读齐的封装。`close` 和 Drop 释放会话并唤醒等待者。服务端节点拥有监听和 `ServerHandle`；节点释放时显式关闭所有句柄。`serve_tcp`、`serve_udp` 的返回句柄保持兼容的显式关闭语义，丢弃句柄本身不停止服务，生产节点必须持有它。

UDP 的一次读写是一整个数据报，包括零长度。缓冲不足时报错，不能拆成下一包；嗅探预读也保留这个语义。出站复制区分零字节报文和 EOF。TCP 则继续使用字节流。mieru 线协议没有独立的写半关闭消息，本机 TCP EOF 后保留反向响应，直到对端关闭、取消或空闲期限，不新增私有 FIN 扩展。

UDP 接收先按来源地址找活跃会话的密钥，每把不同密钥最多验证一次元数据。验证后只在同一来源、同一密钥下查会话 ID，再验证载荷；同一个包的两次验证共用派生结果。新会话仍按账号和时间盐验证，重放检查保持覆盖不同来源。

普通 UDP 载荷在接收槽内原地认证解密，派发持有认证时找到的会话。顺序到达的明文直接追加到该会话的 Pipe，乱序段才复制到重排队列。低熵模式解码后的缓冲可直接交给重排队列。

重放缓存检查当前和上一代记录，轮换时复用哈希表。IPv4 来源直接编码地址和端口。每代单独保存遇到的 IPv6 来源，包括端口、作用域和流标签。检查重复包时，用首次收到该包的那一代核对完整来源。

Linux UDP 接收一次最多取出 16 个已经排队的数据报，保留每个包的来源和边界；只等待第一个包，不等待凑满批次。处理期间新到达的包继续以非阻塞读取取出，但同一通知批次总计仍不超过 16 包；当前没有可取的包就结束，不额外等待。每个包仍独立认证和重排，同一批次的数据交付按会话合并读取通知，处理完就唤醒，不跨接收等待延迟通知。握手和关闭立即通知。其他系统或系统不支持批量接收时沿用单包读取；接收超时和关闭检查保持原有边界。

服务端 UDP 监听按创建顺序轮流分配到单线程 Tokio 执行器，首次使用某个执行器时才创建线程。线程数以进程可用的 CPU 数为上限，设置正整数 `TOKIO_WORKER_THREADS` 可进一步收紧。每个监听的接收、发送背压、维护定时器和原生 TCP 流转发都在同一个执行器上运行。

就绪后的批量接收从第一包起也不阻塞，同一次就绪内连续取完已经可读的数据，仍在每个至多 16 包的批次末通知读者。批次末尾的非阻塞系统调用返回 EAGAIN 时，接收任务同时清除这次可读通知并唤醒已经收到数据的会话。一次执行累计达到 128 包或 256 KiB 后，在批次边界让出工作线程，避免繁忙监听独占执行器。TCP 会话交给出站的 `AsyncTcp` 借出从 Pipe 换走的队列，读取通知和发送窗口使用任务唤醒，不再为每条 TCP 流建立阻塞复制线程。UDP 关联和同步调用继续使用同一个会话状态机与有界 Pipe。

原生异步写入只在窗口和发送队列都有空间后接受一段完整 PDU，每次部分写入至多一个 UDP 载荷片段，分片字段为 0；返回 Pending 不消耗序号或保存未完成的分片组。加密后的 UDP 数据报遇到套接字背压时由监听器按序暂存，总计至多 2 MiB，恢复后发送原数据报，不重新生成 nonce。重传仍按原规则生成新 nonce。`flush` 和写半边结束等待本流已经接受的数据报完成套接字发送，不等待其他流后来排入的数据。队列耗尽时异步写者等待容量，控制消息和同步调用报告暂不可写；关闭监听唤醒全部任务并释放队列。mieru 没有写半关闭，出口读到 EOF 后仍保留反向响应直到对端关闭、取消或空闲期限。

UDP 累计 ACK 只移除已经确认的序号区间，序号回绕时拆成两个区间。未确认段、拥塞恢复和对端通告窗口在同一把会话锁下更新。重复收到同一个累计 ACK 时，如果已没有待确认段，只更新对端通告的窗口。可用额度改变会唤醒发送方，新段进入重传表后重新处理累计 ACK。

UDP 数据确认在至多 1 ms 的窗口内合并，握手确认和关闭沿用原顺序。每条底层连接的维护线程按最近的确认或重传期限唤醒；空闲时最多每 100 ms 维护一次，不为每个 ACK 扫描全部未确认段。应用读空一个曾关闭接收窗口的队列时，也安排窗口更新，避免双方都等对方再发数据。

重传期限随未重传报文的 RTT 样本更新，计入 RTT 波动和确认延迟；初始期限仍为 3 秒，退避上限 10 秒。同一缺口收到三次累计确认时提前重传一次，仍沿用原序号和载荷，UDP nonce 重新生成。一次丢包恢复只缩小一次拥塞窗口，最低保留 16 段；恢复完成后先慢启动到阈值，随后按确认推进拥塞避免。重复确认、乱序和重传不改变接收顺序或认证规则。

密钥的时间盐与元数据时间戳是两个检查：固定官方实现的元数据只接受当前分钟前后 1 分钟，不能把密钥文档中的时钟差描述直接当成整个连接的容忍范围。

TCP 接收由每条底层连接的 128 KiB 读缓冲保留预读字节，一次读取可以带进几段。元数据和载荷在读缓冲内原地解密，跳过填充只推进位置，读到半段后发生 socket 超时仍继续收齐。顺序到达的数据段从读缓冲直接追加进会话的 Pipe，其余段走通用派发。服务端出站复制读 TCP 会话时，用一个空队列整体换走 Pipe 里的字节，直接写往出口，不再复制进复制循环的缓冲。

TCP 发送时，每条底层连接有一个可复用的 wire 缓冲，它同时是段顺序锁。一次应用写入的各段依次加密进这个缓冲，最多 128 KiB 一起发送；两次发送之间放开锁，同一底层的其他会话可以轮流发送。上一次 16 KiB 以上的发送等了对端超过 5 ms 时，底层标为慢，之后逐段发送，直到一次大发送不再等待。载荷复制进 wire 缓冲后就地加密；低熵开启时保持原有扩展体和标签布局。已加密的段一定发出：TCP nonce 递增与线上的段顺序一致，不变。

填充长度和填充字节使用每线程 1 KiB 的系统随机字节缓存，长度分布保持原样。该缓存不用于生成 nonce。TCP 保留 `TCP_NODELAY`，不再每次读取前设置 `TCP_QUICKACK`，ACK 由内核按连接状态调度。mieru 自身的 UDP ACK 和重传规则不受这一 TCP 调整影响。

两种底层的顺序段直接交付载荷，只有乱序段保存在重排表。乱序字节数随插入和移出更新，重复段不重复计入预算，序号按 u32 回绕。Pipe 仍使用有界字节队列，本轮没有引入全局数据块池或改变窗口上限。出站复制换走的队列在写完出口前不计入 Pipe 上限，因此一个会话在 Pipe 之外最多还有一份不超过上限的队列；原来复制循环的缓冲也不计入这一上限。会话的条件变量只在有线程等待时通知。

TCP 会话的 Pipe 达到 2 MiB 上限时，底层接收线程等待应用读取腾出空间，让 TCP 自身施加背压。等待不增加队列上限，关闭会话会立即唤醒；持续 300 秒仍无足够空间则关闭会话。同一底层的其他会话会受这次等待影响。UDP 接收不进入这个等待，继续按协议的窗口与重传规则处理。

## 当前实现与验证状态

固定配置的一分钟服务端性能观测、基于 `df2e347` 的源码核验，以及首批缓冲与派发优化，见[性能记录与优化候选](mieru-performance.md)。各批实施和测量分别登记，下述表格保留首次功能互通验收的结果。

2026-11-10：本机入口移到客户端叶子后，在 `perf-02` 用固定源码构建的官方对端重跑，`--full` 45/45，`--quick --node-host ::1` 17/17，命令行未改。

2026-11-09：上述 mieru 范围已完成实现，并在 `perf-02` 的独立工作目录完成本轮验收。构建、格式、静态检查和测试全部在 worker 执行。本地只编辑、同步和管理 Git，VLESS 源码未改动。

| 检查 | 实际结果 |
| --- | --- |
| Rust 回归 | 60 项通过。协议共享 23、客户端模块 9、客户端生命周期 2、公共类型 2、服务端单元 12、TCP 落地 1、节点及 UDP 落地 5、既有 mieru 集成 6。 |
| 格式与严格检查 | 修改的 Rust 文件格式检查通过，两端及三个 mieru 包的所有目标通过 `Clippy -D warnings`。 |
| 可执行文件 | mieru 客户端、mieru 服务端及 `landing-mieru` 构建通过。 |
| 依赖裁剪 | 客户端仅 WireGuard、服务端仅 OpenVPN 分别构建通过。运行时依赖图没有引入另一端协议，加入错误角色的负面对照会被检查拒绝。未启用 mieru 时，专用 CLI 返回明确错误。 |
| Rustdoc | 两个叶子和 mieru 角色包的 `cargo doc --no-deps` 在 `RUSTDOCFLAGS="-D warnings"` 下通过。 |
| IPv4 节点官方互通 | 22 行配置双向各通过，共 44 项，另有 1 项配置负面检查，合计 45/45。 |
| IPv6 节点官方互通 | 明确标记为 smoke 的 8 行配置双向通过，另有 1 项配置负面检查，合计 17/17。节点实际监听 `::1`，客户端使用 `[::1]:port`。 |
| 资源与隔离 | 20 次重复关闭及原端口重启通过，线程和文件描述符未增长。真实 LAN 地址的监听与 SOCKS 协商、IPv6-only 监听、端口范围失败回滚、UDP 空包与 32 KiB 落地、节点及用户出口缓存隔离均有通过记录。 |

原有 `official_go_client_uses_this_server` 忽略项依赖另一份外部探针，没有计入上述 60 项。本轮官方互通由仓库中的 Go API 对端及 Python 驱动实际执行。参照端真实拨 TCP 和 UDP 目标，逐字节比对，保留应用包边界。目标包含 IPv4、IPv6 和域名；本机 HTTP 包含普通请求、请求体、chunked、跨目标 keepalive、CONNECT 及预读数据。

IPv4 节点使用下表的五因素两两覆盖，覆盖 86 个因素对。表中两列结果分别是官方客户端到 kerlico 服务端、kerlico 客户端到官方服务端。复用列省略 `MULTIPLEXING_`，握手列省略 `HANDSHAKE_`。

| 编号 | 底层 | 复用 | 握手 | 低熵模式 | MTU | 官方到 kerlico | kerlico 到官方 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | TCP | OFF | STANDARD | 0 | 1280 | 通过 | 通过 |
| 2 | TCP | LOW | NO_WAIT | 1 | 1400 | 通过 | 通过 |
| 3 | UDP | MIDDLE | STANDARD | 2 | 1400 | 通过 | 通过 |
| 4 | UDP | HIGH | NO_WAIT | 3 | 1280 | 通过 | 通过 |
| 5 | TCP | MIDDLE | NO_WAIT | 4 | 1280 | 通过 | 通过 |
| 6 | TCP | HIGH | STANDARD | 3 | 1400 | 通过 | 通过 |
| 7 | UDP | OFF | STANDARD | 4 | 1400 | 通过 | 通过 |
| 8 | UDP | LOW | STANDARD | 1 | 1280 | 通过 | 通过 |
| 9 | TCP | OFF | NO_WAIT | 2 | 1280 | 通过 | 通过 |
| 10 | UDP | LOW | NO_WAIT | 0 | 1400 | 通过 | 通过 |
| 11 | TCP | OFF | STANDARD | 1 | 1280 | 通过 | 通过 |
| 12 | TCP | OFF | STANDARD | 3 | 1280 | 通过 | 通过 |
| 13 | TCP | LOW | STANDARD | 2 | 1280 | 通过 | 通过 |
| 14 | TCP | LOW | STANDARD | 3 | 1280 | 通过 | 通过 |
| 15 | TCP | LOW | STANDARD | 4 | 1280 | 通过 | 通过 |
| 16 | TCP | MIDDLE | STANDARD | 0 | 1280 | 通过 | 通过 |
| 17 | TCP | MIDDLE | STANDARD | 1 | 1280 | 通过 | 通过 |
| 18 | TCP | MIDDLE | STANDARD | 3 | 1280 | 通过 | 通过 |
| 19 | TCP | HIGH | STANDARD | 0 | 1280 | 通过 | 通过 |
| 20 | TCP | HIGH | STANDARD | 1 | 1280 | 通过 | 通过 |
| 21 | TCP | HIGH | STANDARD | 2 | 1280 | 通过 | 通过 |
| 22 | TCP | HIGH | STANDARD | 4 | 1280 | 通过 | 通过 |

IPv6 节点 smoke 的 8 行由 `tools/verify_mieru.py --quick --node-host ::1` 生成，覆盖两种底层、四级复用、两种握手和五种低熵模式。该结果单独登记，不替代 IPv4 的两两矩阵。完整 160 行笛卡尔组合、其他上游版本、Mihomo 原生 CLI、真实外网和长期压力没有在本轮验收。

2026-11-15 在 perf-03 用当前程序和同一个官方对端执行 `--full --node-host ::1`。与 IPv4 相同的 22 行配置双向通过，另有一项配置负面验证，合计 45/45。UDP 底层另用第 02 行（MIDDLE、STANDARD、低熵 2、MTU 1400）双向长跑。独立网络命名空间给承载数据报注入 20 ms 延迟（2 ms 抖动）和 0.5% 随机丢包，实际丢了 151 个底层包。两个方向各在同一关联校验至少 90 秒，分别正确收回 694、518 个应用数据报，包含空包、多目标和 32 KB 分片。此结果是受控链路损伤验证，不是公网吞吐测量。worker 原始日志在 `/srv/build/kerlico-compat-20261115/`。

初轮失败及修订证据继续保留在私有日志中。UDP 回显夹具的 8192 字节截断由独立直连反例确认，修订后 32000 字节完整返回。过短的 2 秒回显期限由目标 `TimeoutError` 和逐流字节记录确认，现与有效流预算统一为 25 秒。Go 对端改为并发关闭已拥有的连接后，再停止 API；3 秒退出上限和字节断言均保留。IPv4 与 IPv6 的活跃 LISTEN 负面对照仍会拒绝重绑，关闭后重绑通过。

UDP 连发检查要求三个包按发送顺序回来，这是 mieru 应有的语义：UDP 关联经 `PacketOverStreamTunnel` 走一条会话，UDP 底层按序号重排后才交付（官方 `pkg/protocol/session.go` 的 `moveRecvBufToRecvQueue`），两端每个方向只有一个复制循环（客户端 `pkg/socks5/copy.go` 的 `BidiCopyUDP`，服务端 `pkg/socks5/udp.go` 的 `RunUDPAssociateLoop`）。2026-11-10 偶发的 `02-rust-to-official` 顺序失败出在回显夹具：原来的 `ThreadingUDPServer` 每包一个线程，按序收到后由线程调度决定回包先后。perf-02 上对失败行（UDP、MIDDLE、STANDARD、低熵 2、MTU 1400）只重复连发：不经代理直连原夹具 20000 次失败 16 次；同一夹具下官方客户端到官方服务端 2000 次失败 4 次，Kerlico 客户端到官方服务端 2000 次失败 6 次。插桩记录显示每次都是夹具按 a、b、c 收到、回包乱序，三个包都到达。夹具改为收包线程内逐包回发后，直连 20000 次、官方对官方 2000 次、Kerlico 对官方 2000 次都没有失败；四个忙循环占满 CPU 时，Kerlico 对官方与官方对官方各 1000 次也没有失败。

为通过当前路径的严格检查，共享出站和路由函数改用具名上下文，DNS 辅助函数移到测试模块之前，WARP 依赖仅调整两处错误构造写法。`kerlico-server::Server` 和既有 `land` 接口的签名保持兼容。

官方源码固定为 [`1367cf2d2dd81c5f27d455be7cea691d7948c420`](https://github.com/enfein/mieru/tree/1367cf2d2dd81c5f27d455be7cea691d7948c420)。协议字段以该版本 [`docs/protocol.md`](https://github.com/enfein/mieru/blob/1367cf2d2dd81c5f27d455be7cea691d7948c420/docs/protocol.md) 为准；复用概率见 `pkg/protocol/mux.go` 和 `pkg/appctl/appctlcommon/client.go`，懒握手见 `apis/internal/early_conn.go`。验收工具见 [worker 使用说明](../../tools/mieru_peer/README.md)。原有指向外部探针的忽略测试不代替本轮官方双向验收。
