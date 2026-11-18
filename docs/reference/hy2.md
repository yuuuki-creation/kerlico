# Hysteria 2

线协议以 [Hysteria 2 规范](https://hy2.app/docs/developers/Protocol/) 为准。用 [官方 v2.14.0](https://github.com/HyNetworks/hysteria/releases/tag/app/v2.14.0) 作双向互通对端。

`protocols/hy2/shared` 持有 HTTP/3 认证字段、QUIC varint、TCP 请求和响应、UDP 数据报及分片。VLESS 的 `network: hysteria` 使用同一套认证和流类型，流上的请求是 VLESS，UDP 仍由 VLESS 承载。独立 Hy2 则用 TCP 请求里的地址或每个 UDP 数据报的地址决定目标。

TCP 流有数据或发送窗口可用时直接读取或提交；暂时无法读写时，Quinn 唤醒原来的读写线程继续同一次操作。同步读写的期限由各自的等待线程计时，取消仍可结束等待。QUIC 网络收发、握手和连接定时器仍由 Tokio 驱动。

TCP 入站选中原生出口时，在报告拨号结果后把原来的 Quinn 接收和发送流移交给统一出站。转发任务与 QUIC 连接驱动使用同一个既有执行器，直接等待流和原生套接字就绪，稳态路径不再经过同步条件变量及两条阻塞复制线程。其他出口和客户端同步调用仍使用上段的等待接口。背压、半关闭、字节计数和双向共同空闲期限由统一出站负责。

UDP 分片按会话和包号区分。每片的地址和总片数必须一致；重复片不增加收到的数量；超时或超出内存上限的包被丢弃，只有收齐才交付。零长度 UDP 数据报保留。同一 QUIC 连接内，同一个 UDP 会话里的各目标独立选出口；选中原生出口的目标共享 UDP 端口，选中支持共享 UDP 的落地则共享一条落地关联。回复带数据报的实际来源。

客户端叶子和服务端入站使用 `hy2` feature；服务端落地使用 `landing-hy2`。客户端的 `peer` 写 `host:port` 或 `[IPv6]:port`，`settings.password` 必填；上游 `userpass` 模式的 `password` 写成 `用户名:密码`。`serverName` 指定证书名称；`tls` 接受共享 TLS 字段，例如 `pinnedPeerCertSha256`。域名解析出多个地址时，客户端错开尝试 QUIC 认证，使用先成功的地址。客户端的 SOCKS5/HTTP 入口属于客户端叶子。具有同一运行时、对端和设置的落地 TCP/UDP 流复用同一个已经认证的 QUIC 连接。若入站把多个目标标在同一个 UDP 会话上，Hy2 落地会用同一个 Hy2 会话 ID 发送这些数据报。

服务端按普通节点配置，`protocol` 写 `hy2`，账号用 `users: [{"email":"用户标识","password":"凭据"}]`。证书与私钥用 `certificate` / `privateKey` 或 `certificateFile` / `privateKeyFile`；也可以通过 `tls.certificates` 配置。`udp` 默认为 `true`。`udpIdleTimeout` 为秒数，默认 60。`masquerade` 可配置 `string`、`file` 或 `proxy`；默认 HTTP/3 404。代理源站连接由服务端出站模块打开。

两端可以设置 `sendRate`、`receiveRate`（字节每秒）。服务端的 `receiveRate: "auto"` 要求两端使用常规拥塞控制。`quicParams` 复用 QUIC 窗口、控制器、Chrome 指纹和 MTU 选项。Hy2 从 QUIC 的 1200 字节 UDP 载荷起步，再按路径探测放大，避免低 MTU 隧道丢掉握手包。`obfs` 可写 `{"type":"salamander","password":"..."}` 或 `{"type":"gecko","password":"..."}`；Gecko 另接受 `minPacketSize` 和 `maxPacketSize`，默认为 512 和 1200。客户端可用 `hopPorts` 指定一个逗号分隔的端口列表或范围，`hopInterval` 写秒数或 `最小-最大`，默认 30 秒。服务器或外层网络需要让这些端口转发到同一个 Hy2 监听套接字。

Linux worker 上用 `tools/verify_hy2.py` 运行官方自对照、两个互通方向、落地和协议选项。已通过 13 组验收，覆盖 SOCKS5 和 HTTP CONNECT、TCP/UDP、同一 UDP 会话访问两个目标时的源端口复用、从不同端口返回回复、UDP 分片、错误密码、TCP 拒绝、UDP 禁用、Salamander、Gecko、配置的 Brutal 速率、TCP 半关闭、通过域名连到只听 IPv6 的官方服务端，以及保留原 TCP 流的本地和远端端口跳跃。

这里实现 Hysteria 2 的线协议，使用 Kerlico 自己的节点和客户端配置。官方应用的 Realm 发现、Mimic Fake TCP 和 ACME 自动签证书不属于这个线协议入口。

## 500 Mbps 服务端 CPU 对照

2026-11-18 在 perf-01 的隔离 veth 内网对照 Kerlico 和官方 Hysteria。两个服务端都固定在核 1–2，共用同一客户端和源站。每轮用 8 条持久 TCP 流预热 5 秒，再计量 30 秒，核对 1,875,000,000 字节有效载荷。三轮中的第二轮交换运行顺序。12 个窗口均在 500 Mbps 的 1% 以内，最大发送迟到小于 1 秒。

| 方向 | Kerlico 进程 CPU 中位数 | Hysteria 进程 CPU 中位数 | 三轮配对降幅 |
| --- | ---: | ---: | --- |
| 上行 | 20.87% | 41.20% | 49.35%、47.96%、49.91% |
| 下行 | 17.67% | 28.27% | 39.11%、37.35%、34.32% |

CPU 占用取服务端进程的用户态与内核态时间，一核满载为 100%。Kerlico 服务端 SHA-256 为 `13ae6e69bcc9ade8f7cccecc4cff18f07a0f538fbc3e34a05e59a4d7a3abdcaf`，Hysteria 为 `fc25edff9948708cb00a4ff01f3bccde677660aca050133bb1ad46c6860362d2`，共同客户端为 `22bdea591247fed9ec049e75f2461c61fbe9b144152a16ee940ea9d153b37c2a`。
