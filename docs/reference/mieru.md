# mieru

这篇是 mieru 的决定。段、元数据、密钥和 UDP 封装的字段以官方仓库 [enfein/mieru](https://github.com/enfein/mieru) 的 `docs/protocol.md` 为准。这里不复制那份字段表。代码还没全部跟上的地方，单独标成「代码未跟上」。

## 线协议

TCP 和 UDP 两种传输都要有。加密算法是 XChaCha20-Poly1305。密钥由用户名、密码和系统时间生成。服务端最多试三个时间盐。两端时钟差不能大于 4 分钟。nonce 是 24 字节。生成步骤以官方协议文档为准。

每个段都有 32 字节元数据。会话元数据、数据元数据和低熵扩展都要识别。协议类型从 2 到 11。低熵模式是 0、1、2、3、4，对应关闭以及官方的 `LOW_ENTROPY_MODE_32`、`LOW_ENTROPY_MODE_40`、`LOW_ENTROPY_MODE_48`、`LOW_ENTROPY_MODE_56`。

填充、序号、未确认序号、窗口和分片按官方文档做流控。UDP 按序号重排，并拒绝重放。TCP 单片最大 32768 字节。`LOW_ENTROPY_MODE_32` 的单片最大是 32764 字节。UDP 段必须放进一个数据报。MTU 取值是 1280 到 1400，默认 1400。两端使用同一个值。

多路复用是一条底层连接上的多个会话。服务端接受任意个数。客户端级别是 `MULTIPLEXING_OFF`、`MULTIPLEXING_LOW`、`MULTIPLEXING_MIDDLE`、`MULTIPLEXING_HIGH`。默认 `MULTIPLEXING_LOW`。`OFF` 时一条底层连接只有一个会话。各级别打开新连接的概率以官方客户端为准。

握手模式是 `HANDSHAKE_STANDARD` 和 `HANDSHAKE_NO_WAIT`。默认 `HANDSHAKE_STANDARD`。`HANDSHAKE_NO_WAIT` 允许首包带上应用数据。时序以官方客户端为准。

## 请求

认证之后的请求是 SOCKS5。`CONNECT` 和 `UDP ASSOCIATE` 都要有。`UDP ASSOCIATE` 的每个数据报先封装成 `0x00`、2 字节大端长度、数据、`0xff`，再作为段的载荷。TCP 和 UDP 两种传输使用同一套封装。

服务端把每个会话交成一个 `Handoff`。`CONNECT` 的传输是 TCP。`UDP ASSOCIATE` 的传输是 UDP，并写上对端地址，供服务端的 UDP 会话表使用。协议 crate 不拨号，也不选择出口。

## 监听和账号

节点的 `listen` 决定地址族。一个节点仍然只听一个族。`settings` 里的 `transport` 取值是 `TCP` 或 `UDP`，缺省是 `TCP`。

只使用节点上的端口时，听这一个端口。`settings` 里写了 `portRange` 时，听这一段连续端口。节点上的端口必须落在这段之内，否则配置错误。端口小于 1025 或大于 65535 时拒绝。`portRange` 的两端是十进制，中间一个连字符。

`mtu` 只对 UDP 生效。缺省 1400。小于 1280 或大于 1400 时拒绝。

用户的 `username` 和 `password` 放在该用户的 `Settings` 里。缺省用户名是邮箱。多个用户共用这个节点。

## 客户端入口

mieru 客户端不实现数据包平面。`connect` 不是这条协议的入口。

客户端对本机提供 SOCKS5 和 HTTP 代理。SOCKS5 包含 `CONNECT` 和 `UDP ASSOCIATE`。HTTP 代理接受普通 HTTP 请求和 `CONNECT`。官方把这个入口叫做 HTTP / HTTPS 代理。两个监听端口不能相同。`socks5ListenLAN` 或 `httpProxyListenLAN` 为真时，绑定该机的局域网地址。否则只绑定环回。端口取值是 1025 到 65535。

`multiplexing`、`handshakeMode` 和 `mtu` 使用上面的名字和取值。服务端地址、传输、单个端口或 `portRange` 也在客户端的 `Settings` 里。

`land` 和 `open_stream` 打开一条到目标的会话，走同一套段。落地仍然调用 `land`。

## 不进入这份实现的部分

官方 mita 的 DNS 和它自己的 RPC 不实现。解析、嗅探、FakeDNS、分流、拨号和用户计数以 `docs/reference/server.md` 为准。官方客户端给命令行改配置用的 RPC 不实现。

## 客户端配置与 API

客户端、服务端及可选落地分别使用以下构建命令，全部在 worker 执行：

```sh
cargo build -p kerlico-client --no-default-features --features mieru
cargo build -p kerlico-server --no-default-features --features mieru,landing-mieru
```

启用 `mieru` feature 后，从客户端叶子启动代理：

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

示例仅用合成账号。`protocol` 可以省略；提供时必须为 `mieru`。也可以省略 `peer`，改在 `settings` 写 `address`、`port`；同时提供时必须一致。`peer` 的 IPv6 使用 `[::1]:30000` 形式。未知键、错误类型、非法枚举、空账号或密码都拒绝，不输出原始配置。`portRange` 使用上文约束。`lowEntropyMode` 接受上文五个名字，也接受 0 到 4。两个本机端口默认分别为 1080、8080，不能相同。

本机默认只绑定 `127.0.0.1`。LAN 开关为真时，枚举实际接口上的 IPv4 私网/链路本地地址、IPv6 ULA/链路本地地址，逐一绑定；IPv6 设置 `IPV6_V6ONLY`，链路本地携带接口作用域。没有合适地址时拒绝，不扩大到公网 wildcard。所有端口成功绑定后才开始接入；失败释放先前绑定的端口。

`kerlico-mieru-client::Client::new(host, port, settings)` 创建一个可克隆客户端。`open_stream(host, port)` 打开 TCP 目标，`associate()` 打开 UDP 关联。`close()` 幂等取消所有克隆共享的会话。

代理、`land` 和兼容的 `open_stream` 函数使用同一客户端实现。无状态落地按节点地址、账号和完整设置隔离缓存，最多 64 个配置。条目距上次调用超过 60 秒，且没有活跃会话或调用者时清退，每 5 秒检查一次。缓存满且全部活跃时返回 `Again`，不会合并不同账号的池。统一出口的 UDP 会话另外按节点和用户隔离。

`Proxy::start(client, settings)` 绑定两个本机入口。返回句柄提供 `socks5_addrs()`、`http_addrs()`、`wait()` 和 `close()`，释放句柄会停止监听并等待受控任务。`run_proxy(document)` 解析 CLI 传入的配置。通用数据包接口 `connect` 返回 `OpenError::Settings`，mieru 使用代理或会话入口。现有生成菜单仍是协议名单的唯一来源。

四种复用级别的因子分别为 0、1、2、3。池有 N 条可调度底层连接时，新建概率为 `1/(N*因子+1)`；`OFF` 始终新建。服务端只接收会话，不选择级别。标准握手在打开会话前确认远端应答；`NO_WAIT` 返回惰性会话，首次应用写入发送请求及可用首批数据。读操作等待首次写入，不替调用者启动握手；关闭未写入会话不发送请求。UDP 关联使用标准握手。

SOCKS5 UDP 关联受 TCP 控制连接生命周期约束；验证请求声明及实际来源，端口为 0 时固定第一个合法 UDP 来源。拒绝分片注入，回复保留实际目标头。普通 HTTP 按每个请求的目标建会话，支持 Content-Length、chunked 和同一本机连接上的跨目标请求；CONNECT 保留预读隧道数据。头部、行长度和消息边界受限，冲突长度、非法地址和不支持的升级/期望控制明确拒绝。

## 资源和线协议边界

`Conn::read_for` 与 `Assoc::recv_for` 超时只表示暂时没有数据，不能解释为 EOF；关联接收超时保留尚未读齐的封装。`close` 和 Drop 释放会话并唤醒等待者。服务端节点拥有监听和 `ServerHandle`；节点释放时显式关闭所有句柄。`serve_tcp`、`serve_udp` 的返回句柄保持兼容的显式关闭语义，丢弃句柄本身不停止服务，生产节点必须持有它。

UDP 的一次读写是一整个数据报，包括零长度。缓冲不足时报错，不能拆成下一包；嗅探预读也保留这个语义。出站复制区分零字节报文和 EOF。TCP 则继续使用字节流。mieru 线协议没有独立的写半关闭消息，本机 TCP EOF 后保留反向响应，直到对端关闭、取消或空闲期限，不新增私有 FIN 扩展。

密钥的时间盐与元数据时间戳是两个检查：固定官方实现的元数据只接受当前分钟前后 1 分钟，不能把密钥文档中的时钟差描述直接当成整个连接的容忍范围。

## 当前实现与验证状态

固定配置的一分钟服务端性能观测见[性能记录](mieru-performance.md)，与下述功能互通验收分别登记。

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

初轮失败及修订证据继续保留在私有日志中。UDP 回显夹具的 8192 字节截断由独立直连反例确认，修订后 32000 字节完整返回。过短的 2 秒回显期限由目标 `TimeoutError` 和逐流字节记录确认，现与有效流预算统一为 25 秒。Go 对端改为并发关闭已拥有的连接后，再停止 API；3 秒退出上限和字节断言均保留。IPv4 与 IPv6 的活跃 LISTEN 负面对照仍会拒绝重绑，关闭后重绑通过。

为通过当前路径的严格检查，共享出站和路由函数改用具名上下文，DNS 辅助函数移到测试模块之前，WARP 依赖仅调整两处错误构造写法。`kerlico-server::Server` 和既有 `land` 接口的签名保持兼容。

官方源码固定为 [`1367cf2d2dd81c5f27d455be7cea691d7948c420`](https://github.com/enfein/mieru/tree/1367cf2d2dd81c5f27d455be7cea691d7948c420)。协议字段以该版本 [`docs/protocol.md`](https://github.com/enfein/mieru/blob/1367cf2d2dd81c5f27d455be7cea691d7948c420/docs/protocol.md) 为准；复用概率见 `pkg/protocol/mux.go` 和 `pkg/appctl/appctlcommon/client.go`，懒握手见 `apis/internal/early_conn.go`。验收工具见 [worker 使用说明](../../tools/mieru_peer/README.md)。原有指向外部探针的忽略测试不代替本轮官方双向验收。
