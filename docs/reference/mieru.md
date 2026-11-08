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

## 代码未跟上

服务端已经按上面的决定收官方客户端。TCP 和 UDP 传输、填充、窗口、乱序重排、低熵类型 10 和 11、`HANDSHAKE_NO_WAIT`、多会话、`UDP ASSOCIATE`、`portRange` 和 MTU 都在这条路径上。

客户端对本机的 SOCKS5 和 HTTP 代理入口还没有做。四种复用级别是客户端打开新连接的概率，服务端不选择级别，只接受任意个数的会话。
