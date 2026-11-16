# Hysteria 2

线协议以 [Hysteria 2 规范](https://hy2.app/docs/developers/Protocol/) 为准。用 [官方 v2.14.0](https://github.com/HyNetworks/hysteria/releases/tag/app/v2.14.0) 作双向互通对端。

`protocols/hy2/shared` 持有 HTTP/3 认证字段、QUIC varint、TCP 请求和响应、UDP 数据报及分片。VLESS 的 `network: hysteria` 使用同一套认证和流类型，流上的请求是 VLESS，UDP 仍由 VLESS 承载。独立 Hy2 则用 TCP 请求里的地址或每个 UDP 数据报的地址决定目标。

UDP 分片按会话和包号区分。每片的地址和总片数必须一致；重复片不增加收到的数量；超时或超出内存上限的包被丢弃，只有收齐才交付。零长度 UDP 数据报保留。每条会话内的目标仍由入站节点的规则选出口。

客户端叶子和服务端入站使用 `hy2` feature；服务端落地使用 `landing-hy2`。客户端的 `peer` 写 `host:port` 或 `[IPv6]:port`，`settings.password` 必填；上游 `userpass` 模式的 `password` 写成 `用户名:密码`。`serverName` 指定证书名称；`tls` 接受共享 TLS 字段，例如 `pinnedPeerCertSha256`。域名解析出多个地址时，客户端错开尝试 QUIC 认证，使用先成功的地址。客户端的 SOCKS5/HTTP 入口属于客户端叶子。具有同一运行时、对端和设置的落地 TCP/UDP 流复用同一个已经认证的 QUIC 连接。

服务端按普通节点配置，`protocol` 写 `hy2`，账号用 `users: [{"email":"用户标识","password":"凭据"}]`。证书与私钥用 `certificate` / `privateKey` 或 `certificateFile` / `privateKeyFile`；也可以通过 `tls.certificates` 配置。`udp` 默认为 `true`。`udpIdleTimeout` 为秒数，默认 60。`masquerade` 可配置 `string`、`file` 或 `proxy`；默认 HTTP/3 404。代理源站连接由服务端出站模块打开。

两端可以设置 `sendRate`、`receiveRate`（字节每秒）。服务端的 `receiveRate: "auto"` 要求两端使用常规拥塞控制。`quicParams` 复用 QUIC 窗口、控制器、Chrome 指纹和 MTU 选项。Hy2 从 QUIC 的 1200 字节 UDP 载荷起步，再按路径探测放大，避免低 MTU 隧道丢掉握手包。`obfs` 可写 `{"type":"salamander","password":"..."}` 或 `{"type":"gecko","password":"..."}`；Gecko 另接受 `minPacketSize` 和 `maxPacketSize`，默认为 512 和 1200。客户端可用 `hopPorts` 指定一个逗号分隔的端口列表或范围，`hopInterval` 写秒数或 `最小-最大`，默认 30 秒。服务器或外层网络需要让这些端口转发到同一个 Hy2 监听套接字。

Linux worker 上用 `tools/verify_hy2.py` 运行官方自对照、两个互通方向、落地和协议选项。已通过 13 组验收，覆盖 SOCKS5 和 HTTP CONNECT、TCP/UDP、两个 UDP 目标、UDP 分片、错误密码、TCP 拒绝、UDP 禁用、Salamander、Gecko、配置的 Brutal 速率、TCP 半关闭、通过域名连到只听 IPv6 的官方服务端，以及保留原 TCP 流的本地和远端端口跳跃。

这里实现 Hysteria 2 的线协议，使用 Kerlico 自己的节点和客户端配置。官方应用的 Realm 发现、Mimic Fake TCP 和 ACME 自动签证书不属于这个线协议入口。
