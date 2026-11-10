# VLESS

目标是在本仓库的节点、`Handoff` 和出站边界内替代 Xray 的全部合法 VLESS 组合，包括通用传输层的高级功能。当前对照固定为 Xray **26.10.31，a4a3dff**，只读源码位于 `reference/.upstream/xray-core-v26.10.31`。不能用一次短消息、自身两端互通或编译成功代替与官方二进制的验证。尚未完成的部分列在最后，不能据此缩小目标。

## 层次和账号

链路按套接字及 finalmask、TLS/REALITY、传输、VLESS Encryption、VLESS 请求、Vision、Mux/数据报的顺序组合。协议服务端完成握手后交出 `Handoff`，目标拨号仍由 `crates/outbound` 执行。分流、DNS、嗅探和 FakeDNS 使用 `server.md` 的规则。

版本字节是 0。请求依次带 UUID、addons、命令、端口、地址；响应带版本和 addons。addons 是 protobuf，字段 1 是 flow，字段 2 是 seed，未知字段按 protobuf 规则跳过。命令为 TCP(1)、UDP(2)、Mux(3)、Reverse(4)。Mux 和 Reverse 的请求在命令之后结束，没有目标字段。服务端与 Xray 的入站一样，不在读完请求后立即写响应，而是把响应和第一批下行字节放在同一次写入里：TCP 和 UDP 的首个回复、Vision 的首个填充帧、Mux 的首帧或门户的控制帧，交出原始套接字之前也先写出。流结束前没有下行字节时不发送响应。

UUID 可以写标准形式或 1 至 30 字节的自定义字符串。自定义 ID 按 Xray 的 UUID v5 映射；`我爱🍉老师1314` 对应 `5783a3e7-e373-51cd-8642-c83782b807c5`。认证比较时清零字节 6、7，保留线上的原始 UUID 给 Vision。路由字节不创建全局路由。

用户键是邮箱。用户设置为 `id`、`flow`、可选 `reverse`。空的用户 flow 继承节点 flow。重复添加同一邮箱替换旧 UUID；不同邮箱不能占用同一认证 UUID。删除或替换账号立即禁止旧反向连接接收新会话，握手注册也检查账号代际。

节点必须写 `decryption`，关闭时为 `none`；落地必须写 `encryption`。`network` 默认 `tcp`，`security` 默认 `none`。没有 Encryption 的明文链路限私网，或显式声明 `trusted: true`。该规则不取消节点自身的出站规则。

## 组合

| 传输 | 传输安全 | 形态 |
| --- | --- | --- |
| `raw` / `tcp` | none、TLS、REALITY | 字节流；可配置 RAW HTTP authenticator |
| `mkcp` / `kcp` | none、TLS | UDP 上的可靠字节流；TLS 在 KCP 流内 |
| `ws` / `websocket` | none、TLS | HTTP/1.1 Upgrade 后的 WebSocket 二进制帧 |
| `httpupgrade` | none、TLS | HTTP/1.1 101 后的原始字节流 |
| `grpc` | none、TLS、REALITY | HTTP/2 gun Tun / TunMulti，含自定义方法路径 |
| `xhttp` / `splithttp` | none、TLS、REALITY | H1、H2、H3，packet-up、stream-up、stream-one、auto |
| `hysteria` | TLS | Hysteria v2 的认证 QUIC 字节流；VLESS 自己封装 UDP |
| `xdrive` | 存储服务的 HTTP/TLS | local、template、S3、Google Drive；必须 Encryption、空 flow、普通连接使用 Mux |

XHTTP 的 none 使用 H1，TLS 可选 H1/H2/H3，REALITY 使用 H2。服务端也接受 H2 prior knowledge。Hysteria 必须 `version: 2` 且两端 `auth` 相同。Hysteria 的 HTTP/3 服务端在认证回答和伪装的 string、file、404 回答之前，按 RFC 9114 第 4.1 节用 H3_NO_ERROR 停止请求流；伪装代理把请求体交给 hyper，hyper 不再读时 h3-quinn 可能还有读取在进行，无法停止，这时由 quinn 以错误码 0 停止。HTTP/3 客户端收到对端的 STOP_SENDING 时把请求当作已结束，照常读取响应。XDrive 的 TLS 配置用于存储服务，并非用户流的额外 TLS 层。

Xray 26 已删除独立 `http` / `h2` / `h3` / `quic` 和 `security: xtls`，禁止 VLESS + MASQUE；它们不计入正例。Kerlico 保留的 `network: http` 是旧 HTTP/2 字节流接口，不代表当前 Xray 还有这项传输。

VLESS Encryption 可以叠在上述任一合法载体上，不限于 RAW/none。Vision 要求它紧邻的安全层为 TLS 1.3、REALITY 或 VLESS Encryption；普通 TLS 外再包 WS、gRPC、XHTTP 或 Hysteria 时，需要内层 Encryption 才能用 Vision。mKCP + TLS 1.3 可直接用 Vision。XDrive 禁止 Vision，包括单独用户指定非空 flow。

入站 flow 只允许空值和 `xtls-rprx-vision`。落地另外接受 `xtls-rprx-vision-udp443`，线上仍写前一个字符串，只改变 UDP/443 的许可：不进 Mux 连接池的 Vision UDP/443 没有这个后缀就拒绝，进池的 UDP/443 只看 `xudpProxyUDP443`，与 Xray 一致。Vision UDP 自动改用 XUDP，不能发送带 Vision flow 的独立 UDP 命令。启用 Mux 连接池时 Vision 的 TCP 落地直接拒绝，因为 Xray 服务端会断开承载 TCP 的 Vision Mux 连接。Vision 用户可接收空 flow 的独立 UDP 和 id-0 XUDP，不能借空 flow 发普通 TCP；该账号的 Mux 始终只承载 UDP。

## 传输设置

节点、用户和落地的 `Settings` 接受字符串、数字、布尔值、数组及对象；结构值序列化为 JSON 后由协议解释。协议设置不等于直接加载整份 Xray 配置。

TLS 的 `certificate` / `key` 接受 PEM，也可用 `certificateFile` / `keyFile`。客户端 `serverName` 用于 SNI 和名称验证，`pinnedPeerCertSha256` 是 DER 证书 SHA-256，支持逗号分隔和十六进制冒号分隔。叶证书 pin 精确验证；CA pin 还验证链和名称。`allowInsecure` 只关闭证书信任校验，不关闭握手签名校验。`alpn` 接受 JSON 数组或逗号分隔值。`minVersion` / `maxVersion` 的 1.0、1.1、1.2、1.3 在两个方向都与 Xray 互通，由 `xray_advanced_tls_bidirectional` 证明。TLS 1.3 服务端在客户端已为服务端接受的组发了 key share 时，取其中服务端顺序最靠前的一个，不发 HelloRetryRequest；服务端接受的组是 `curvePreferences`（Xray 和 BoringSSL 的组名，不分大小写），不写时按 Go 的默认取 X25519MLKEM768、X25519、P-256、P-384、P-521。Go 1.27 遇到客户端列出却没给 key share 的后量子组时仍会为它重试，而 Xray 的 uTLS 客户端（如 `randomized` 指纹）无法为 X25519MLKEM768 重试，所以这里不跟 Go。

REALITY 使用服务端 `privateKey`、客户端 `publicKey`，客户端 `shortId`，服务端 `shortIds` 数组或单个 `shortId`。服务端 `serverNames`、`minClientVer`、`maxClientVer`、毫秒单位的 `maxTimeDiff` 限制认证。`mldsa65Seed` / `mldsa65Verify` 增加 ML-DSA-65 验证。支持 X25519 和 X25519MLKEM768，严格验证证书结构、CertificateVerify、Finished 和协商套件。H2 载体接受 Xray REALITY 未发送 ALPN 的握手，明确协商其他协议则拒绝。`target`（旧名 `dest`）写 `host:port`、`[IPv6]:port` 或本机端口；裸端口按 `127.0.0.1:端口` 处理，不经服务端 DNS 解析 `localhost`。以 `/` 开头是 Unix 套接字路径，以 `@` 开头是 Linux 抽象套接字，`@@` 开头按 Xray 用零补满 `sun_path`。未认证的连接，包括读不出 ClientHello 的字节，按原样交给 target：TCP target 仍通过 `Handoff` 交出，节点规则和出口照常生效；Unix target 没有出口可选，协议经运行时上下文的 `connect_unix` 连接并在协议内双向转发，一侧 EOF 后对另一侧半关闭；两个方向都 300 秒没有字节时转发结束，与 `server.md` 的 TCP 空闲规则相同。`xver` 为 0、1、2，按 Xray 使用的 go-proxyproto 写 PROXY 头：两端都是 IPv4 才写 IPv4，否则两端都写 IPv6。`limitFallbackUpload` / `limitFallbackDownload` 是 `{afterBytes, bytesPerSec, burstBytesPerSec}`，键名不区分大小写，只限未认证回落：上传计探测方发往 target 的字节，下载计 target 发回的字节，target 第一次读到的数据不计量；`bytesPerSec` 为 0 或不写即不限。认证成功的握手也像 Xray 一样先连 target：经运行时上下文直连（TCP 用原生套接字，Unix 用 `connect_unix`），发送 PROXY 头和客户端的原始 ClientHello，读取 target 的 ServerHello、CCS 和加密握手记录，沿用它的套件、密钥组、ServerHello 和各记录长度。连接 target 和读完这些记录共用一个 10 秒期限，target 连接失败、超过期限或返回的结构不能套用时，改用合成的握手记录，不中断认证连接。

WS 和 HTTPUpgrade 的 `path` 默认 `/`、`host` 可选，路径比较排除查询串。WS 服务端按帧方向检查掩码，处理 Ping/Pong/Close 和分片，保留 HTTP 升级后的预读字节。`?ed=N` 的 WebSocket 早期数据通过 `Sec-WebSocket-Protocol` 携带。RAW HTTP 用 `header: {"type":"http","request":{...},"response":{...}}` 指定首个请求/响应伪装。WS/HTTPUpgrade 用 `headers` 对象指定自定义头。WebSocket 客户端在第一笔真实写入时发送升级请求，早期数据放进请求头。HTTPUpgrade 客户端与 Xray 的拨号器一样在建连时发送请求；`ed` 大于 0 时不等 101 就写首批数据，否则读到 101 后再写。两种情况下 Encryption 握手都走同一条路径。WS、HTTPUpgrade、XHTTP、gRPC 服务端共用同一条 `sockopt.trustedXForwardedFor` 规则：请求同时带 `X-Forwarded-For` 和列表中任一标记头时，才以前者的第一个 IP（端口 0）作为 `Handoff` 来源；缺少标记头、第一个值不是 IP 或列表为空时保留 TCP 对端。

gRPC 同一条 HTTP/2 连接可以并发承载 Tun 和 TunMulti。每个 RPC 独立完成 VLESS 握手并交出 Handoff。`serviceName` 支持 Xray 的 `/service/method|multi-method` 写法和转义。H2 保留 HPACK 状态，按连接和流分别处理窗口、END_STREAM、RST 和 GOAWAY。收到响应头之前允许先写应用数据。RPC 结束时先交付已接收的数据，服务端发送 gRPC trailers 和 END_STREAM，连接继续处理控制帧和其他 RPC。落地按对端和配置复用连接，GOAWAY 或断开后在下一次开流时重连。 客户端可用 `authority` 覆盖 HTTP/2 authority，用 `user_agent` 选择 chrome、edge、firefox、golang 或自定义值。`initial_windows_size` 指定接收流窗口。`idle_timeout` 和 `health_check_timeout` 以秒为单位控制 PING 探测与超时，`permit_without_stream` 允许客户端在没有 RPC 时探测。服务端按 `sockopt.trustedXForwardedFor` 恢复会话来源，规则见 WS 与 HTTPUpgrade 段。

XHTTP 的 `auto` 通常选择 packet-up；REALITY 下选择 stream-one，有独立 `downloadSettings` 时选择 stream-up。`downloadSettings` 可单独指定地址、端口、安全、路径及 HTTP 版本。支持配置上传方法、headers、padding 位置、会话 ID/序号的 path/query/header/cookie 位置、header/cookie 上传载荷、上传分块限额及间隔、缓冲包数量、stream-up 保活。上传必须消费响应；packet-up 要求 HTTP 200。H1 流式请求使用 `Connection: close` 以启用 Xray 的全双工处理。

XHTTP 服务端的 `h2Params` 只作用于 H2 入口（h2c、TLS H2、REALITY H2），不作用于 H3。客户端配置里的 h2Params 既不生效也不校验。键名按 Go `http.HTTP2Config` 字段匹配，不区分大小写，未知键忽略，重复键后者生效，类型错误、小数、字符串数字或非空 `CountError` 会拒绝配置。`MaxConcurrentStreams`、`MaxReadFrameSize`、`MaxDecoderHeaderTableSize`、`MaxReceiveBufferPerStream` 写入 SETTINGS 并被强制执行，`MaxReceiveBufferPerConnection` 决定连接窗口和首个 WINDOW_UPDATE；`SendPingTimeout`、`PingTimeout`、`WriteByteTimeout` 以纳秒计，分别控制空闲探测、探测应答期限和写停滞断开；`PermitProhibitedCipherSuites` 为假时，协商到 RFC 7540 禁用套件的 TLS 1.2 连接以 INADEQUATE_SECURITY 拒绝，低于 TLS 1.2 无论如何都拒绝。零值或越界值取 Kerlico 默认值（128 流、16 MiB 窗口、16 KiB 帧、4096 字节 HPACK 表），Go 的默认值是 250 流和 1 MiB 窗口。`MaxEncoderHeaderTableSize` 只校验类型，Kerlico 的 HPACK 编码器不使用动态表。H2 客户端遇到对端流数已满时在同一份 XMUX 连接下另开 TCP 连接，不等待。

XHTTP 客户端的 `hMaxRequestTimes` 与 Xray 同样记账：下载 GET、stream-up 上传和 stream-one 请求直接扣减，不换连接；packet-up 的 POST 扣减后预算已尽才换连接，换到的新连接不记这次 POST。packet-up 的 VLESS 请求头和第一笔数据最多等 100 毫秒后合并成一个 POST，启用 Encryption 时不合并。H1 的 XMUX 连接数不与 Xray 对齐，Go 的 H1 上传连接池会不确定地多开连接。

mKCP 处理绝对接收窗口、累积确认、丢包重传、乱序、重复数据重新确认和关闭前的数据排空。空闲时每 3 秒发 PING，30 秒无对端活动才过期。`header` 支持 none、original、srtp、utp、wechat、dtls、wireguard、dns，`domain` 是 DNS 名，`seed` 启用 AES-GCM。旧 original 包装使用 FNV-1a 和错位异或。

通用 finalmask 的类型与 Xray 注册的类型相同（`infra/conf/transport_finalmask.go`）。TCP 有 `header-custom`、`filter`、`fragment`、`xmc`、`sudoku`；UDP 有 `header-custom`、`filter`、`mkcp-legacy`、`noise`、`realm`、`salamander`、`sudoku`、`udphop`、`xdns`、`xicmp`。其他类型名拒绝配置。

`sockopt` 的键按 Go `encoding/json` 匹配，不区分大小写，未知键忽略，`null` 保持默认值，类型错误仍然拒绝配置。

`acceptProxyProtocol: true` 在 TCP 载体握手之前消费 PROXY v1/v2，普通非 PROXY 连接仍可使用；解析后的来源用于 UDP Handoff，目的地址用于 fallback PROXY 头。该选项只应配置在实际接收 PROXY 头的入口上。

XDrive 使用 `xdriveSettings` 对象；local 也接受 `service: local` 和 `remoteFolder`。HTTP 后端支持 OAuth、模板预签名 PUT、S3 SigV4/会话令牌/path-style/virtual-host，以及 Google Drive 的 multipart、分段对象和环形槽位。`storageAddress` / `storagePort` 是显式存储连接覆盖；不会用 VLESS 逻辑监听地址替代云服务地址。

## VLESS Encryption、Vision 和复用

Encryption 的模式是 `mlkem768x25519plus.native`、`xorpub`、`random`。服务端后接票据有效期和私钥，客户端后接 `1rtt` 或 `0rtt` 及公钥。按 Xray 语法支持有效期区间、长度/间隔 padding，以及 X25519 和 ML-KEM 密钥链。拒绝低阶公钥，0-RTT 校验票据和重放，冷启动仍做 1-RTT。random 在取消内层 AEAD 后保留记录头掩码。

Vision 只保留一条实现路径。END 结束填充；DIRECT 在最后一块填充和对应安全记录排空后移除紧邻的安全层，不跳过外层传输。内层真实 TLS 的大记录不能提前切换。分开的读写半边共享 Vision 状态，阻塞读取不占用写侧。

独立 UDP 使用两字节大端长度，Mux UDP 载荷本身就是一份数据报，不再重复套长度。XUDP 使用 id 0，KEEP 帧携带的不同目标分别产生 Handoff，回复保留目标元数据。XUDP 的 NEW 帧在地址后可带 8 字节 GlobalID，全零等于没有。服务端节点按用户和 GlobalID 记录会话。另一个载体送来同一用户、同一 GlobalID 的 NEW 帧时，原会话的各个目标改用新载体和新会话 id，不产生新的 Handoff，出站 UDP 流和套接字继续使用，远端看到的源端口不变。原载体若还开着，会先收到该会话的 END。带 GlobalID 的会话在载体关闭或收到 END 后脱离载体，这段时间的回复直接丢弃，60 秒内没有载体接回就结束。新的 NEW 帧只查自己的键，过期的会话当场换新；其余过期条目最多每分钟清理一次，与 Xray 的 `XUDPManager` 每分钟扫一遍相同。Xray 的表只按 GlobalID 查找，范围是整个进程。同一客户端重连时用户不变，所以多按用户区分不影响互通。没有 GlobalID 的会话随载体关闭。TCP 大写入拆成最多 65535 字节的 Mux 帧。队列有界，关闭发送 END，已收数据先于 EOF 交给调用方。

写到线上的数据报不超过 Xray 在同一种封装里写出的大小。超限的数据报直接丢弃，不报错，流和承载都继续。规则只写在 `UdpFraming` 一处。Xray 的缓冲区是 8192 字节（`common/buf/buffer.go` 的 `buf.Size`）。独立 UDP 两个方向最多 8190 字节，对应 `MultiLengthPacketWriter` 的 `length+2 > buf.Size`（`proxy/vless/encoding/addons.go`）。Xray 的读端把更长的数据报按 8192 字节拆成几个数据报。客户端独占一条承载的 XUDP 会话最多 7526 字节，对应 `xudp.PacketWriter` 的 `length+666 > buf.Size`（`common/xudp/xudp.go`）。其余 Mux 包帧最多 8192 字节，包括连接池会话、服务端对 XUDP 和 Mux 的回复，以及反向桥和门户的会话。Xray 的 Mux 读端遇到更长的包帧会断开整条 Mux 连接，连同上面所有 TCP 会话（`common/mux/reader.go`）。XUDP 读端同样结束这条连接（`out of bound`）。Xray 自己不会写出这种帧，因为它每次读 UDP 只装满一个缓冲区，更长的数据报只留前 8192 字节。这样截短的数据报在 Mux 包帧里照样发出，Xray 服务端的 XUDP 回复也是如此；客户端的 XUDP 写端和两个方向的独立 UDP 再按上面的规则把它丢弃。Kerlico 读到的是完整数据报，超限就整个丢弃，不发截短的内容。门户的第一个数据报超限时，会话用不带数据的 NEW 帧打开。

空数据报是有效数据报，见 `server.md`。服务端在 Mux 和 XUDP 会话上写空数据报返回 `Ok(0)`，流继续；独立 UDP 两端都写出长度为零的数据报。客户端的 Mux 和 XUDP 会话跳过空数据报，与 Xray 的写端相同。Xray 服务端不转发源站的空回复。Xray 客户端收到 Kerlico 服务端的空数据报时连接照常，三种承载都不把它交给应用。

`vless_xray_udp_size` 对照官方 Xray 检查这些上限。Mux、XUDP 和独立 UDP 各有三行：Xray 对照、Xray 客户端连 Kerlico 服务端、Kerlico 客户端连 Xray 服务端；另有 Xray 门户分别连 Xray 桥和 Kerlico 桥两行。每行开一条 TCP 流和一条 UDP 流。客户端先写一个正好到上限的数据报、超限的数据报和一个短数据报；再请源站回同样大小的数据报、一个空数据报和一个短数据报。两次的短数据报都必须是下一个收到的，TCP 流随后照常往返，承载数不变。2026-11-10 在 perf-01 上 11 行全部通过。

落地的 UDP 承载按 Xray 的 VLESS 出站选择。Xray 的 cone 默认开启（`core/xray.go` 只在环境变量 `xray.cone.disabled` 为 `true` 时关闭），Kerlico 不提供关闭开关。因此不走 Mux 连接池时，Vision UDP 和空 flow 发往 53、443 以外端口的 UDP 都用 Mux 命令下的单会话 XUDP（Xray 的 `v1.mux.cool:666`），会话结束即关闭这条连接；空 flow 发往 53 和 443 端口的 UDP 保持独立 UDP 命令。`land_udp` 返回 `UdpSession`：XUDP 或 Mux 会话里每个数据报可以指定不同目标，回复带来源地址；独立 UDP 命令只能到达第一个目标，发往其他目标会报错。

落地 `mux` 写 `true`、`false` 或 Xray 的对象 `{"enabled", "concurrency", "xudpConcurrency", "xudpProxyUDP443"}`，`true` 等于 `{"enabled": true}`。启用后 `land` 把会话放进按对端和完整设置共享的 Mux 连接（Xray 的 `v1.mux.cool:9527`），会话 id 从 1 递增。`concurrency` 是每条连接同时承载的会话数，默认 8，负值让 TCP 不走连接池。`xudpConcurrency` 为 0 时 UDP 与 TCP 共用连接，为正时 UDP 使用自己的连接池和这个并发数，为负时 UDP 不进池。`xudpProxyUDP443` 默认 `reject`，拒绝 UDP/443；`allow` 让它进池；`skip` 让它绕过连接池，按上一段处理。每条连接累计分配 128 个会话后不再接新会话，这些会话全部结束即关闭；没有会话满 16 秒的连接关闭；已关闭的连接在下次打开会话时换新。没有连接能接新会话时，新连接先进连接池再拨号，这期间打开的会话也分到这条连接，等同一次拨号，拨号失败时一起失败，不会排在前一次拨号的超时后面，与 Xray 的 `IncrementalWorkerPicker` 相同。连接组随运行时归属失效，最多保留最近使用的 32 组。TCP 会话 100 毫秒内没有首包时先发不带数据的 NEW，目标先发数据的协议也能建立连接。每条 Mux 连接都有自己的写线程，落地的连接池、反向桥、服务端的 Mux 入站和门户共用 `kerlico_vless::MuxUplink` 这一份实现。写线程按顺序写出各会话的帧；还有超过 64 KiB 没写出时，会话的写入最多等 200 毫秒，与 Xray 写进 64 KiB 管道时阻塞相同。END 不等待；排队超过 128 KiB 说明对端已不再读取，这条连接随即关闭。写超时截断的帧由写线程接着写完，不依赖读方向空闲，读线程也不替写方向等待。XDrive 总是使用 Mux，拒绝负的并发值和 `skip`。gRPC 流可共享底层连接。落地不发送 GlobalID，客户端入口发送，见「客户端入口」。HTTP/1 分块编码保存 wire 位置和待确认的应用长度，短写、WouldBlock、flush 和最后的零长度块共用这一份状态。

## 反向连接和回落

账号 `reverse` 可以是标签字符串或 `{"tag":"bridge"}`。该账号拒绝正向请求。反向握手后服务端先登记这个门户，再发送 UDP 控制会话到 `reverse:0`，之后按 Xray 节拍发送 ACTIVE；桥收到控制会话时，`open_reverse` 已经能找到这个门户。协议标签不创建全局路由表或新的 `OutboundChoice`。服务端可用 `landing: {"node":"节点名","reverse":"标签"}` 将这个节点的 Portal 作为既有 Landing 出口，检查 Portal 归属和账号代际。

服务端 `open_reverse(tag, host, port, tcp, payload)` 返回双向流。客户端 `reverse_bridge(host, port, settings)` 返回 `ReverseBridge`，`accept()` 给出各自包含 `Destination` 和 `InboundStream` 的 `ReverseFlow`，可以并发处理 TCP、UDP 和同一 XUDP 会话里的多个目的地。实际目标拨号仍归调用它的出站层。`load()` 给出 Xray 桥监控读的状态：活动会话数（含 Portal 的控制会话）、Draining 或 Closed。控制会话里 `Control.state` 不是 ACTIVE 时为 Draining；控制消息不是合法 protobuf 时关闭这条连接，和 Xray 相同。服务端配置的 `bridges` 把桥作为节点运行，每条 `ReverseFlow` 成为该节点的 `Handoff`，并按 Xray 的 2 秒检查、平均超过 16 个会话加开连接的规则维护连接，见 `server.md`「配置和运行时接口」。落地 `land` 只有显式 `reverse` 配置时才进入反向兼容入口；普通目标 `v1.rvs.cool` 不会触发反向模式。

`fallback` 为默认 `host:port`、`[IPv6]:port` 或本机端口。`fallbacks` 接受 Xray 的 JSON 数组，也接受分号分隔的 `name=...,alpn=...,path=...,dest=...,xver=...`。SNI 匹配最长子串，ALPN 和路径逐级使用默认值；h2 规则不能再带路径。`xver` 为 0、1、2。回落交出已读取的全部字节及可选 PROXY 头，正常出口选择仍生效。

回落在解开载体后判定，允许 none、TLS 和已认证 REALITY；未知 UUID 或不是 VLESS 的首包可回落，已认证用户的错误 flow 直接关闭。Encryption 与 VLESS fallback 互斥；REALITY 未认证时的 target 是独立的外层处理。

## 客户端入口

`kerlico-client` 在 VLESS 前面运行本机 SOCKS5 和 HTTP 代理，对应 Xray 的 socks、http 入站加 vless 出站。命令行、文档语法和四个本机入口键见 `crates.md` 的「客户端叶子和本机入口」。`settings` 里其余的键就是落地的 VLESS 设置，写法与落地相同。

```json
{
  "protocol": "vless",
  "peer": "203.0.113.5:443",
  "settings": {
    "id": "5783a3e7-e373-51cd-8642-c83782b807c5",
    "encryption": "none",
    "flow": "xtls-rprx-vision",
    "security": "reality",
    "serverName": "www.example.com",
    "publicKey": "<base64url 公钥>",
    "shortId": "12ab34cd",
    "socks5Port": 1080,
    "httpProxyPort": 8080
  }
}
```

启动时检查 `id`、`encryption`、`flow` 和 `mux`，不合法时在绑定端口之前退出。传输和安全层的组合在第一条流拨号时检查，不合法时这条流失败，SOCKS 应答 5，HTTP 应答 502。

每条 SOCKS `CONNECT` 和每个 HTTP 请求调用一次 `land`，与落地共用载体、Vision、Mux 连接池和全部传输。

一条 SOCKS UDP 关联按每个数据报自己的目标选择承载。规则与 `land_udp` 相同：

| 数据报 | 承载 |
| --- | --- |
| 启用 Mux 连接池，UDP/443 而 `xudpProxyUDP443` 为 `reject` | 丢弃 |
| 进入 Mux 连接池 | 关联唯一的 Mux UDP 会话，每个数据报带目标 |
| Vision 发往 443，flow 没有 `-udp443` | 丢弃 |
| 其余 Vision 数据报，以及空 flow 发往 53 和 443 以外的端口 | 关联唯一的单会话 XUDP（`v1.mux.cool:666`），每个数据报带目标 |
| 空 flow 发往 53 或 443 | 每个目标一条独立 UDP 命令连接，最多 64 条，空闲 60 秒关闭 |

Xray 一条关联只有一条链接，命令和 UDP/443 规则都只看第一个目标。第一个目标走独立 UDP 时，发往其他目标的数据报也送到第一个目标。第一个目标走 XUDP 或 Mux 时，之后发往 443 的数据报不再受 UDP/443 规则限制。Kerlico 对每个数据报单独判断，所以不会把数据报送错目标，UDP/443 的拒绝对整条关联都生效。关联只有一个目标时，两者的承载相同。

XUDP 和 Mux 会话的回复来源取自帧里的地址，独立 UDP 连接的回复来源是它的目标。空数据报丢弃，与 Xray 的 SOCKS 入站相同。承载打不开时丢弃这个数据报，下一个数据报重新打开，与 Xray 的 UDP 分发器相同。承载断开后，下一个数据报同样重新打开。

本机 SOCKS 入口在 Xray 里属于 cone 入站，所以 XUDP 和 Mux UDP 会话的 NEW 帧带 GlobalID。它与 Xray 的 `xudp.GetGlobalID` 算法相同：用进程启动时生成的 32 字节随机密钥做带密钥的 BLAKE3，输入是 `udp:<来源 IP>:<端口>`，IPv6 加方括号，取前 8 字节。同一个本机 UDP 套接字在重开的承载上带同一个 GlobalID。服务端无论是 Xray 还是 Kerlico，都把原会话接到新承载上，源站看到的源端口不变。

`tools/verify_vless_client.py` 在 worker 上运行真实的 `kerlico-client`，对官方 Xray 服务端覆盖 raw none、raw TLS、raw REALITY + Vision、ws TLS、gRPC REALITY、XHTTP TLS h2 和 Mux 七行。每行检查 SOCKS CONNECT 的载荷往返，一条关联内多个目标的 UDP 往返和回复来源，HTTP CONNECT，同一 HTTP 连接上两个目标的 keep-alive，以及错误 UUID 不能到达源站。明文行用分路器读出每个承载的 VLESS 命令字节。另有 GlobalID 续接检查：切断承载后再次发送，Xray 服务端和 Kerlico 服务端的源站都看到同一个源端口；不带 GlobalID 的独立 UDP 连接作为对照，源端口必须改变。每项都用 Xray 客户端再跑一遍作对照。2026-11-10 在 perf-02 上 18 项全部通过，其中 Xray 客户端的对照确认了上文两处承载差异。

## 验证和未完成项

真实流程回归在 `crates/server/tests/vless_flow.rs`，官方双向矩阵在 `vless_xray.rs` 和 `vless_support`。每个外部用例都比较实际载荷，并可先跑 Xray 到 Xray 对照。`XRAY` 必须指向固定版本；没有二进制时测试明确 ignored，不伪报通过。云端 API 用本地存储模拟验证协议，不能推断真实账号权限、配额和服务可用性。

```text
cargo test -p kerlico-vless -p kerlico-vless-client -p kerlico-vless-server --lib
cargo test -p kerlico-server --no-default-features --features vless,landing-vless --test vless_flow
XRAY=/path/to/xray VLESS_XRAY_CONTROL=1 cargo test -p kerlico-server --no-default-features --features vless,landing-vless --test vless_xray -- --ignored --nocapture
```

Windows 当前可用 GNU 工具链，加 `+stable-x86_64-pc-windows-gnu`。叶子隔离构建仍按 `crates.md` 分别执行，不能把上述互操作测试的 feature 联合用于隔离结论。

本地实现现已接入完整 finalmask 模块、运行时 DNS/出口回调、socket 配置、mKCP 与 QUIC 参数、TLS 指纹/ECH/证书轮换/OCSP，以及 XHTTP/XDrive/Hysteria 的高级传输选项。VPS 上的阶段性验证包括 15 项真实载体回归、210 项库测试、21 项 QUIC/Hysteria 官方对照；完整 Xray 矩阵曾在较早的整合快照通过 353/354 项。结果和证据见本地 `.audit/vless-completion.tsv`，这些数字不代表当前工作区最终快照已通过全部验收。

仍在收尾和复核的部分：

- REALITY 目标 TLS flight 重用、Unix target、fallback 速率限制与 spider 的服务端接线；现有基础模块已验证，prepared outbound handoff 尚未完成最终集成与矩阵验证。
- XHTTP server `h2Params` 的完整设置，以及 H1/H2/H3 下全部 XMUX 连接预算和关闭策略的最终复核。
- 出站 Mux 连接跨会话复用、XUDP GlobalID 跨 carrier、UDP/443 通用策略，以及服务端 reverse bridge 配置入口。
- socket 选项与所有出口/载体的最终互操作矩阵；XDrive 云服务当前通过本地协议模拟器验证，不推断实际账号或配额。
- 独立客户端叶子的 VLESS 报文 `DataPlane` 仍明确返回错误；当前可运行的是服务端入站、落地 `land` 和反向流 API。
- 最终完整官方矩阵、独立审查，以及 `crates.md` 要求的客户端 WireGuard 和服务端 OpenVPN 两条分离构建。

固定版本 Xray 的 HTTPUpgrade 服务端用带缓冲的读取解析请求头后返回原始连接，与请求头同一次读到的 VLESS 字节随之丢失（`transport/internet/httpupgrade/hub.go`）。明文早期数据下，请求之后越早写出数据越容易触发。Kerlico 客户端因此像 Xray 的拨号器那样在建连时发出请求，不再在首批数据时与请求连续写出。同一快照各重复 20 次：修正前 kerlico 到 Xray 失败 11 次，修正后 2 次；Xray 自对照两轮均为 0 次，此前完整矩阵中也出现过 1 次失败。TLS 记录把请求和数据分开，TLS 组合不受影响。剩余失败属于对端缺陷，不能把偶然通过计作已消除，也不使用 sleep 或补齐字节掩盖它。Xray 客户端连 Kerlico 服务端时的失败来自 Xray 客户端的缺陷：`ed` 大于 0 时，拨号器到第一次读取才解析 101，VLESS 响应解码的第一次读取只有 1 字节，随后清空缓冲，与 101 同时到达的响应字节随之丢失（`transport/internet/httpupgrade/dialer.go`、`proxy/vless/encoding/addons.go`）。Xray 服务端的响应随第一批下行数据写出，不会触发它；Kerlico 服务端改用同样的时机后，perf-01 上该行重复 200 次为 0 次失败，同一测试改回立即写响应时失败 21 次。
