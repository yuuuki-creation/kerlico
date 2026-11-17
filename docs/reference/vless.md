# VLESS

目标是在本仓库的节点、`Handoff` 和出站边界内替代 Xray 的全部合法 VLESS 组合，包括通用传输层的高级功能。当前对照固定为 Xray **26.10.31，a4a3dff**，只读源码位于 `reference/.upstream/xray-core-v26.10.31`。不能用一次短消息、自身两端互通或编译成功代替与官方二进制的验证。尚未完成的部分列在最后，不能据此缩小目标。

## 层次和账号

链路按套接字及 finalmask、TLS/REALITY、传输、VLESS Encryption、VLESS 请求、Vision、Mux/数据报的顺序组合。协议服务端完成握手后交出 `Handoff`，目标拨号仍由 `crates/outbound` 执行。分流、DNS、嗅探和 FakeDNS 使用 `server.md` 的规则。

版本字节是 0。请求依次带 UUID、addons、命令、端口、地址；响应带版本和 addons。addons 是 protobuf，字段 1 是 flow，字段 2 是 seed，未知字段按 protobuf 规则跳过。命令为 TCP(1)、UDP(2)、Mux(3)、Reverse(4)。Mux 和 Reverse 的请求在命令之后结束，没有目标字段。服务端与 Xray 的入站一样，不在读完请求后立即写响应，而是把响应和第一批下行字节放在同一次写入里：TCP 和 UDP 的首个回复、Vision 的首个填充帧、Mux 的首帧或门户的控制帧，交出原始套接字之前也先写出。流结束前没有下行字节时不发送响应。

普通 TCP 字节流的底层若是原生 TCP 或直接包在它上面的 TLS，选中原生出口后，可以把现有状态移交给统一出站的异步任务。预读字节和待发首响应随状态一起移交；TLS 继续使用原来的握手、记录认证和控制消息实现。原生套接字就绪通知推进读写，TLS 读取需要发送 KeyUpdate 等控制回复时等待可写，不等待新的应用下行字节。背压时保留原密文进度和重试明文，关闭写半边不丢掉反向读取。异步交接不重新解析请求、不重新握手、不重新拨号。具有额外帧、复用、掩码或 Vision 状态的流继续由其原载体驱动；REALITY/Vision 的内核转发规则保持在统一出站内。

原生异步读取会继续取走当前已经可读的明文，直到出口提供的缓冲用完或套接字暂不可读，再交给出口写入；不为每条 TLS 记录单独结束一次读取，也不等待凑满。已读到数据后才遇到的错误或 EOF 留到数据交付后处理，控制回复和反向半关闭保持原有顺序。

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

TLS 的 `certificate` / `key` 接受 PEM，也可用 `certificateFile` / `keyFile`。文件证书在新握手时按内容检测变化，即使大小和修改时间相同也能重载。只有证书和私钥能解析且相互匹配，才替换上一份有效身份；`oneTimeLoading` 只在配置创建时读取文件。客户端 `serverName` 用于 SNI 和名称验证，`pinnedPeerCertSha256` 是 DER 证书 SHA-256，支持逗号分隔和十六进制冒号分隔。叶证书 pin 精确验证；CA pin 还验证链和名称。`allowInsecure` 只关闭证书信任校验，不关闭握手签名校验。`alpn` 接受 JSON 数组或逗号分隔值。`minVersion` / `maxVersion` 的 1.0、1.1、1.2、1.3 在两个方向都与 Xray 互通，由 `xray_advanced_tls_bidirectional` 证明。TLS 1.3 服务端在客户端已为服务端接受的组发了 key share 时，取其中服务端顺序最靠前的一个，不发 HelloRetryRequest；服务端接受的组是 `curvePreferences`（Xray 和 BoringSSL 的组名，不分大小写），不写时按 Go 的默认取 X25519MLKEM768、X25519、P-256、P-384、P-521。Go 1.27 遇到客户端列出却没给 key share 的后量子组时仍会为它重试，而 Xray 的 uTLS 客户端（如 `randomized` 指纹）无法为 X25519MLKEM768 重试，所以这里不跟 Go。

REALITY 使用服务端 `privateKey`、客户端 `publicKey`，客户端 `shortId`，服务端 `shortIds` 数组或单个 `shortId`。服务端按 Xray 的 `xtls/reality` 选认证用的密钥：ClientHello 的 key_share 里必须先有一个 X25519MLKEM768 share，之后的第一个 X25519 share 用于认证，没有就用混合 share 里的 X25519 那一半；只有 X25519 share、X25519 在混合 share 之前或有两个混合 share 的 ClientHello 不算 REALITY 连接，按未认证交给 target。客户端照指纹原样发送 key_share，不替旧指纹补混合 share。服务端 `serverNames`、`minClientVer`、`maxClientVer`、毫秒单位的 `maxTimeDiff` 限制认证。`mldsa65Seed` / `mldsa65Verify` 增加 ML-DSA-65 验证。支持 X25519 和 X25519MLKEM768，严格验证证书结构、CertificateVerify、Finished 和协商套件。H2 载体接受 Xray REALITY 未发送 ALPN 的握手，明确协商其他协议则拒绝。`target`（旧名 `dest`）写 `host:port`、`[IPv6]:port` 或本机端口；裸端口按 `127.0.0.1:端口` 处理，不经服务端 DNS 解析 `localhost`。以 `/` 开头是 Unix 套接字路径，以 `@` 开头是 Linux 抽象套接字，`@@` 开头按 Xray 用零补满 `sun_path`。未认证的连接，包括读不出 ClientHello 的字节，按原样交给 target：TCP target 仍通过 `Handoff` 交出，节点规则和出口照常生效；Unix target 没有出口可选，协议经运行时上下文的 `connect_unix` 连接并在协议内双向转发（Xray 的 REALITY 层同样用 `net.Dialer` 直接连 target 并转发，这是 `AGENTS.md` 拨号规则的唯一例外），一侧 EOF 后对另一侧半关闭；两个方向都 300 秒没有字节时转发结束，与 `server.md` 的 TCP 空闲规则相同。`xver` 为 0、1、2，按 Xray 使用的 go-proxyproto 写 PROXY 头：两端都是 IPv4 才写 IPv4，否则两端都写 IPv6。`limitFallbackUpload` / `limitFallbackDownload` 是 `{afterBytes, bytesPerSec, burstBytesPerSec}`，键名不区分大小写，只限未认证回落：上传计探测方发往 target 的字节，下载计 target 发回的字节，target 第一次读到的数据不计量；`bytesPerSec` 为 0 或不写即不限。认证成功的握手也像 Xray 一样先连 target：经运行时上下文直连（TCP 用原生套接字，Unix 用 `connect_unix`），发送 PROXY 头和客户端的原始 ClientHello，读取 target 的 ServerHello、CCS 和加密握手记录，沿用它的套件、密钥组、ServerHello 和各记录长度。握手记录之后已经到达的一条记录（target 的 NewSessionTicket）也记下总长度，服务端在 Finished 之后发一条同样长度的记录，内容是空应用数据，用服务端应用密钥封装，序号从 0 起。target 的握手只有一条加密记录时（超过 512 字节，Xray 同样合并），没有这条记录。连接 target 和读完这些记录共用一个 10 秒期限。结果的处理与 xtls/reality 相同：连不上 target、target 中途断开或超过期限、ServerHello 之后的记录不合规，或无法按它的套件和密钥组套用时，直接关闭连接；target 的头几个字节不是合规的 ServerHello 时，把已读到的字节写给客户端，之后双向转发，上下行按 `limitFallback*` 限速，已读到的字节不计量。只有没有 `target`，或没有可拨号的运行时上下文时没有可模仿的对象，服务端才发合成的握手记录。

服务端在打开节点时就探测 target，与 Xray 随监听器启动一致。对每个 `serverNames` 和三种 ALPN 类别（不带 ALPN、`http/1.1`、`h2` 在前）各做两次真实的 TLS 1.3 握手，并像 Xray 的 TLS 客户端一样用系统根证书（或 `SSL_CERT_FILE`、`SSL_CERT_DIR` 指向的证书）验证 target 的证书链和服务器名，验证不过就什么也学不到：没有记录，也没有 ChangeCipherSpec 数目，认证连接不会为探测等待。一次在客户端 Finished 之后读 5 秒，记下 target 发来的应用数据记录的长度（OpenSSL 的 NewSessionTicket、HTTP/2 的 SETTINGS 等）；另一次在客户端 Finished 之前连发 ChangeCipherSpec，看 target 在 2、17、33 条之后是否 alert 或断开，得到它容忍的连续无效记录数 1、16、32 或不限。认证连接读完客户端 Finished 后，按记录长度逐条写空应用数据记录，序号接在上面那条之后；探测还没结束时最多等 35 秒，与 Xray 的第一批握手一样，探测失败就一条也不写。服务端到握手结束才断开与 target 的连接。读客户端 Finished 时容忍这个数目的 ChangeCipherSpec，多一条就发 unexpected_message alert 后关闭。读这一步的其他错误也按 xtls/reality 的记录层先发 alert 再关闭，alert 是致命级，用服务端应用密钥封装，序号接在已发的记录之后，整条 24 字节：无法认证的记录是 bad_record_mac，版本不对或 SSLv2 样的首字节是 protocol_version，记录超过 16640 字节是 record_overflow，畸形的 ChangeCipherSpec 是 decode_error，解密出来的内容类型不对、握手消息不是 Finished、握手消息把 ChangeCipherSpec 隔开是 unexpected_message，握手消息体超过 65536 字节是 internal_error，Finished 不符是 decrypt_error。读不到数据、对方 close_notify 不回 alert。握手完成后连续的空应用记录超过这个数目只关闭连接，不发 alert。探测还没有结果时这个数目取 32，与 OpenSSL 和 xtls/reality 的默认相同。

WS 和 HTTPUpgrade 的 `path` 默认 `/`、`host` 可选，路径比较排除查询串。WS 服务端按帧方向检查掩码，处理 Ping/Pong/Close 和分片，保留 HTTP 升级后的预读字节。`?ed=N` 的 WebSocket 早期数据通过 `Sec-WebSocket-Protocol` 携带。RAW HTTP 用 `header: {"type":"http","request":{...},"response":{...}}` 指定首个请求/响应伪装。WS/HTTPUpgrade 用 `headers` 对象指定自定义头。WebSocket 客户端在第一笔真实写入时发送升级请求，早期数据放进请求头。HTTPUpgrade 客户端在建连时发送请求。明文 HTTPUpgrade 总是等到 101 后再写首批数据，避免旧对端丢掉同一次读取中的首包；有 TLS 且 `ed` 大于 0 时仍提前写，升级请求和首包分别写入 TLS 记录。两种情况下 Encryption 握手都走同一条路径。WS、HTTPUpgrade、XHTTP、gRPC 服务端共用同一条 `sockopt.trustedXForwardedFor` 规则：请求同时带 `X-Forwarded-For` 和列表中任一标记头时，才以前者的第一个 IP（端口 0）作为 `Handoff` 来源；缺少标记头、第一个值不是 IP 或列表为空时保留 TCP 对端。

gRPC 同一条 HTTP/2 连接可以并发承载 Tun 和 TunMulti。每个 RPC 独立完成 VLESS 握手并交出 Handoff。`serviceName` 支持 Xray 的 `/service/method|multi-method` 写法和转义。H2 保留 HPACK 状态，按连接和流分别处理窗口、END_STREAM、RST 和 GOAWAY。收到响应头之前允许先写应用数据。RPC 结束时先交付已接收的数据，服务端发送 gRPC trailers 和 END_STREAM，连接继续处理控制帧和其他 RPC。落地按对端和配置复用连接，GOAWAY 或断开后在下一次开流时重连。 客户端可用 `authority` 覆盖 HTTP/2 authority，用 `user_agent` 选择 chrome、edge、firefox、golang 或自定义值。`initial_windows_size` 指定接收流窗口。`idle_timeout` 和 `health_check_timeout` 以秒为单位控制 PING 探测与超时，`permit_without_stream` 允许客户端在没有 RPC 时探测。服务端按 `sockopt.trustedXForwardedFor` 恢复会话来源，规则见 WS 与 HTTPUpgrade 段。

XHTTP 的 `auto` 通常选择 packet-up；REALITY 下选择 stream-one，有独立 `downloadSettings` 时选择 stream-up。`downloadSettings` 可单独指定地址、端口、安全、路径及 HTTP 版本。支持配置上传方法、headers、padding 位置、会话 ID/序号的 path/query/header/cookie 位置、header/cookie 上传载荷、上传分块限额及间隔、缓冲包数量、stream-up 保活。上传必须消费响应；packet-up 要求 HTTP 200。H1 流式请求使用 `Connection: close` 以启用 Xray 的全双工处理。

XHTTP 服务端的 `h2Params` 只作用于 H2 入口（h2c、TLS H2、REALITY H2），不作用于 H3。客户端配置里的 h2Params 既不生效也不校验。键名按 Go `http.HTTP2Config` 字段匹配，不区分大小写，未知键忽略，重复键后者生效，类型错误、小数、字符串数字或非空 `CountError` 会拒绝配置。`MaxConcurrentStreams`、`MaxReadFrameSize`、`MaxDecoderHeaderTableSize`、`MaxReceiveBufferPerStream` 写入 SETTINGS 并被强制执行，`MaxReceiveBufferPerConnection` 决定连接窗口和首个 WINDOW_UPDATE；`SendPingTimeout`、`PingTimeout`、`WriteByteTimeout` 以纳秒计，分别控制空闲探测、探测应答期限和写停滞断开；`PermitProhibitedCipherSuites` 为假时，协商到 RFC 7540 禁用套件的 TLS 1.2 连接以 INADEQUATE_SECURITY 拒绝，低于 TLS 1.2 无论如何都拒绝。零值或越界值取 Xray 的默认值：250 条并发流、1 MiB 的流窗口和连接窗口、1 MiB 的最大读帧、4096 字节 HPACK 表。SETTINGS 的发送顺序与固定版本 Xray 相同。`MaxEncoderHeaderTableSize` 只校验类型，Kerlico 的 HPACK 编码器不使用动态表。H2 客户端遇到对端流数已满时在同一份 XMUX 连接下另开 TCP 连接，不等待。

XHTTP 客户端的 `hMaxRequestTimes` 与 Xray 同样记账：下载 GET、stream-up 上传和 stream-one 请求直接扣减，不换连接；packet-up 的 POST 扣减后预算已尽才换连接，换到的新连接不记这次 POST。packet-up 的 VLESS 请求头和第一笔数据最多等 100 毫秒后合并成一个 POST，启用 Encryption 时不合并。H1 的 XMUX 连接数不与 Xray 对齐，Go 的 H1 上传连接池会不确定地多开连接。

mKCP 处理绝对接收窗口、累积确认、丢包重传、乱序、重复数据重新确认和关闭前的数据排空。空闲时每 3 秒发 PING，30 秒无对端活动才过期。`header` 支持 none、original、srtp、utp、wechat、dtls、wireguard、dns，`domain` 是 DNS 名，`seed` 启用 AES-GCM。旧 original 包装使用 FNV-1a 和错位异或。

通用 finalmask 的类型与 Xray 注册的类型相同（`infra/conf/transport_finalmask.go`）。TCP 有 `header-custom`、`filter`、`fragment`、`xmc`、`sudoku`；UDP 有 `header-custom`、`filter`、`mkcp-legacy`、`noise`、`realm`、`salamander`、`sudoku`、`udphop`、`xdns`、`xicmp`。其他类型名拒绝配置。

`sockopt` 的键按 Go `encoding/json` 匹配，不区分大小写，未知键忽略，`null` 保持默认值，类型错误仍然拒绝配置。

`acceptProxyProtocol: true` 在 TCP 载体握手之前消费 PROXY v1/v2，普通非 PROXY 连接仍可使用；解析后的来源用于 UDP Handoff，目的地址用于 fallback PROXY 头。该选项只应配置在实际接收 PROXY 头的入口上。

XDrive 使用 `xdriveSettings` 对象；local 也接受 `service: local` 和 `remoteFolder`。HTTP 后端支持 OAuth、模板预签名 PUT、S3 SigV4/会话令牌/path-style/virtual-host，以及 Google Drive 的 multipart、分段对象和环形槽位。`storageAddress` / `storagePort` 是显式存储连接覆盖；不会用 VLESS 逻辑监听地址替代云服务地址。

真云往返用例 `cloud_storage_round_trips` 只手动执行。将 `xdriveSettings` 对象保存在 Linux worker 上的私有文件中，用专用的测试前缀或文件夹，令 `XDRIVE_LIVE_SETTINGS` 指向该文件，执行 `cargo test -p kerlico-vless --lib cloud_storage_round_trips -- --ignored`。S3 的 `secrets` 依次为 access key、secret key、可选会话令牌；Drive 的三个值依次为 OAuth client ID、client secret、refresh token。`remoteFolder` 必须是测试专用，因为 XDrive 会写入和清理会话对象。

## 数据路径

TCP 握手预读在读半边先交付。独立 UDP 的待解帧和短写余量只在 UDP 流里保存，普通字节流和 Mux 不检查这两份缓存。TCP 预读排空后才允许交出原始读套接字。

REALITY 和 TLS 的记录层一次读取取回线路上已到达的全部字节，到齐的记录逐条解开；一次写入最多把四条满记录和不足一条的尾部封好后一并写出。记录的大小和内容不变。REALITY 的记录用 `ring` 就地加解密。TLS 状态每次只收一条完整记录，一次读取只交付一条记录的数据。REALITY 一次读取可以交付多条记录的数据，但只判定第一条：它后面的记录在调用方的缓冲里试着解开，解得开且是应用数据才算数，否则线路上的字节原样留到下一次读取再判定。这是因为 Vision 切换直连由上层在读到数据之后才决定，切换之后最后一条记录后面的字节不是记录。切换时，最后一条记录之后预读到的字节原样交付。

TLS 1.3 接收记录在共享 TLS 的预读缓冲中由 Rust 就地认证和解密；TLS 1.2 及以下由 BoringSSL 从当前记录取字节。普通读取仍逐条交付，原生异步普通 VLESS 可以借出多条已认证记录，由出口向量写出，部分写入只消费对应的前缀。TLS 写半部在没有待发密文时接管封好的缓冲；如果部分写入后还有待发字节，新记录排在它们之后。

VLESS Encryption 的记录层用 `ring` 就地加解密，密钥在会话建立时展开一次。读取同样一次取回已到达的全部字节，但和 Xray 一样每次只解开一条记录，交付完再解下一条，所以 Vision 在任何一条记录之后切换直连，后面预读到的字节都去掉头部掩码后原样交付；一次写入最多把八条 8 KiB 的满记录和不足一条的尾部封好后一并写出，记录的切分与逐条写出时相同。

HTTP/2 的接收窗口在消耗满四分之一时归还，与 grpc-go 相同。一条流等数据和等发送窗口各有自己的等待点，一帧只唤醒它所属的流。等发送窗口的流按用尽的先后取连接窗口，攒到要发的数据或半个窗口再发，1 毫秒内攒不到就有多少发多少；对端每次至少归还半个窗口，否则靠这 1 毫秒的期限继续前进。

gRPC 的每条 HTTP/2 连接有一个读线程和一个写线程。写数据的流在线路空闲时自己发出已排队的帧和自己的数据，线路忙时只把帧入队，由写线程按入队顺序发出。读数据的流和读线程只入队，不向线路写，所以不会被别的流的数据拖住。一次写入成帧的数据量，以及排队多少字节之后流要先等，取线路最近约十六分之一秒发出的量，范围是 16 KiB 到 128 KiB：线路慢时，共用连接的流只互相等几帧。HTTP 和 XHTTP 的 H2 连接没有这两个线程，同一时刻只有一条流在写，其他流等到自己的帧发出；只为控制帧而写的流在有流等待时让出。

gRPC 的一条消息到齐并校验之后才交付，载荷在原处解码。发送时消息前缀和数据直接成帧，不先拼成消息。落地的字节流读写直接用调用方的缓冲。

这些做法的测量在 [VLESS 性能记录](vless-performance.md)。

## VLESS Encryption、Vision 和复用

Encryption 的模式是 `mlkem768x25519plus.native`、`xorpub`、`random`。服务端后接票据有效期和私钥，客户端后接 `1rtt` 或 `0rtt` 及公钥。按 Xray 语法支持有效期区间、长度/间隔 padding，以及 X25519 和 ML-KEM 密钥链。拒绝低阶公钥，0-RTT 校验票据和重放，冷启动仍做 1-RTT。客户端在本机有 AES-GCM 硬件支持时整个会话用 AES-256-GCM，否则用 ChaCha20-Poly1305；判断条件在 x86-64 和 ARM64 上与 Xray 的 `HasAESGCMHardwareSupport` 相同，其他架构用 ChaCha20-Poly1305。服务端不看本机硬件，用能解开第一条记录的那一种。random 在取消内层 AEAD 后保留记录头掩码。

Vision 只保留一条实现路径。END 结束填充；DIRECT 在最后一块填充和对应安全记录排空后移除紧邻的安全层，不跳过外层传输。内层真实 TLS 的大记录不能提前切换。分开的读写半边共享 Vision 状态，阻塞读取不占用写侧。

Linux 的原生 REALITY/TCP 载体进入 Vision DIRECT 后，出站可以取得该方向的 TCP 句柄并使用内核转发。上行必须先读完握手预读、Vision 明文和 REALITY 预读；下行必须先发完 VLESS 响应、填充、DIRECT 指令及安全层待写记录。END 不会移除 REALITY 加密。仍需变换的外层载体不会交出原始句柄；不满足条件时继续原有字节流处理。

独立 UDP 使用两字节大端长度，Mux UDP 载荷本身就是一份数据报，不再重复套长度。XUDP 使用 id 0，KEEP 帧携带的不同目标分别产生 Handoff，回复保留目标元数据。XUDP 的 NEW 帧在地址后可带 8 字节 GlobalID，全零等于没有。服务端节点按用户和 GlobalID 记录会话。另一个载体送来同一用户、同一 GlobalID 的 NEW 帧时，原会话的各个目标改用新载体和新会话 id，不产生新的 Handoff，出站 UDP 流和套接字继续使用，远端看到的源端口不变。原载体若还开着，会先收到该会话的 END。带 GlobalID 的会话在载体关闭或收到 END 后脱离载体，这段时间的回复直接丢弃，60 秒内没有载体接回就结束。新的 NEW 帧只查自己的键，过期的会话当场换新；其余过期条目最多每分钟清理一次，与 Xray 的 `XUDPManager` 每分钟扫一遍相同。Xray 的表只按 GlobalID 查找，范围是整个进程。同一客户端重连时用户不变，所以多按用户区分不影响互通。没有 GlobalID 的会话随载体关闭。TCP 大写入拆成最多 65535 字节的 Mux 帧。队列有界，关闭发送 END，已收数据先于 EOF 交给调用方。

写到线上的数据报不超过 Xray 在同一种封装里写出的大小。超限的数据报直接丢弃，不报错，流和承载都继续。规则只写在 `UdpFraming` 一处。Xray 的缓冲区是 8192 字节（`common/buf/buffer.go` 的 `buf.Size`）。独立 UDP 两个方向最多 8190 字节，对应 `MultiLengthPacketWriter` 的 `length+2 > buf.Size`（`proxy/vless/encoding/addons.go`）。Xray 的读端把更长的数据报按 8192 字节拆成几个数据报。客户端独占一条承载的 XUDP 会话最多 7526 字节，对应 `xudp.PacketWriter` 的 `length+666 > buf.Size`（`common/xudp/xudp.go`）。其余 Mux 包帧最多 8192 字节，包括连接池会话、服务端对 XUDP 和 Mux 的回复，以及反向桥和门户的会话。Xray 的 Mux 读端遇到更长的包帧会断开整条 Mux 连接，连同上面所有 TCP 会话（`common/mux/reader.go`）。XUDP 读端同样结束这条连接（`out of bound`）。Xray 自己不会写出这种帧，因为它每次读 UDP 只装满一个缓冲区，更长的数据报只留前 8192 字节。这样截短的数据报在 Mux 包帧里照样发出，Xray 服务端的 XUDP 回复也是如此；客户端的 XUDP 写端和两个方向的独立 UDP 再按上面的规则把它丢弃。Kerlico 读到的是完整数据报，超限就整个丢弃，不发截短的内容。门户的第一个数据报超限时，会话用不带数据的 NEW 帧打开。

空数据报是有效数据报，见 `server.md`。服务端在 Mux 和 XUDP 会话上写空数据报返回 `Ok(0)`，流继续；独立 UDP 两端都写出长度为零的数据报。客户端的 Mux 和 XUDP 会话跳过空数据报，与 Xray 的写端相同。Xray 服务端不转发源站的空回复。Xray 客户端收到 Kerlico 服务端的空数据报时连接照常，三种承载都不把它交给应用。

`vless_xray_udp_size` 对照官方 Xray 检查这些上限。Mux、XUDP 和独立 UDP 各有三行：Xray 对照、Xray 客户端连 Kerlico 服务端、Kerlico 客户端连 Xray 服务端；另有 Xray 门户分别连 Xray 桥和 Kerlico 桥两行。每行开一条 TCP 流和一条 UDP 流。客户端先写一个正好到上限的数据报、超限的数据报和一个短数据报；再请源站回同样大小的数据报、一个空数据报和一个短数据报。两次的短数据报都必须是下一个收到的，TCP 流随后照常往返，承载数不变。2026-11-10 在 perf-01 上 11 行全部通过。

落地的 UDP 承载按 Xray 的 VLESS 出站选择。Xray 的 cone 默认开启（`core/xray.go` 只在环境变量 `xray.cone.disabled` 为 `true` 时关闭），Kerlico 不提供关闭开关。因此不走 Mux 连接池时，Vision UDP 和空 flow 发往 53、443 以外端口的 UDP 都用 Mux 命令下的单会话 XUDP（Xray 的 `v1.mux.cool:666`），会话结束即关闭这条连接；空 flow 发往 53 和 443 端口的 UDP 保持独立 UDP 命令。`land_udp` 返回 `UdpSession`：XUDP 或 Mux 会话里每个数据报可以指定不同目标，回复带来源地址；独立 UDP 命令只能到达第一个目标，发往其他目标会报错。

XUDP 或 Mux 入站的各 UDP 目标各交出一个 `Handoff`，带同一个数据报会话标记。分流仍逐目标检查。选中相同原生出口的各目标复用同一个套接字，回复帧写实际来源。VLESS 落地也读这个标记：同一入站会话里选择相同 XUDP 或 Mux 承载的目标共用上游会话，独立 UDP 命令仍按目标打开。VLESS 落地不会用入站的对端套接字计算 GlobalID；同一个套接字可能承载多条独立的认证会话。

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

真实流程回归在 `crates/server/tests/vless_flow.rs`，官方双向矩阵在 `vless_xray.rs` 和 `vless_support`。每个外部用例都比较实际载荷，并可先跑 Xray 到 Xray 对照。`XRAY` 必须指向固定版本；没有二进制时测试明确 ignored，不伪报通过。XDrive 的日常回归使用本地模拟器，另有独立 S3 兼容实现和真云的手动测试。

```text
cargo test -p kerlico-vless -p kerlico-vless-client -p kerlico-vless-server --lib
XRAY=/path/to/xray XRAY_BIN=/path/to/xray cargo test -p kerlico-vless -p kerlico-vless-client -p kerlico-vless-server --lib -- --ignored --test-threads=1 --skip cloud_storage_round_trips
cargo test -p kerlico-server --no-default-features --features vless,landing-vless --test vless_flow
XRAY=/path/to/xray VLESS_XRAY_CONTROL=1 cargo test -p kerlico-server --no-default-features --features vless,landing-vless --test vless_xray -- --ignored --nocapture
python3 tools/verify_vless_client.py --xray-bin /path/to/xray --client-bin <kerlico-client> --server-bin <kerlico-server>
```

库测试里有四个 ignored 测试对照 Xray：`xray_advanced_tls_bidirectional` 检查 TLS 1.0 至 1.3 和各指纹的双向握手，`xray_reality_browser_fingerprints` 检查 Kerlico 客户端用各指纹连 Xray 的 REALITY，另两个检查客户端和服务端的反向 API。`vless_xray` 有八个测试：完整矩阵、拒绝用例、XUDP 续接、反向桥、XUDP 多目标、UDP 大小、h2Params 和 REALITY target。REALITY target 还检查认证连接在握手记录之后收到的记录，与 decoy 发给真实客户端的 NewSessionTicket 同长，Xray 和 Kerlico 两个服务端都比较；两者通过 `SSL_CERT_FILE` 信任 decoy 的证书，否则探测验证不过，什么也学不到。它还重放一个客户端的 ClientHello，读完服务端的握手记录后发一条无法认证的记录，要求两个服务端都只回一条 24 字节的 alert 记录再关闭。`verify_vless_client.py` 的覆盖见「客户端入口」。

叶子隔离按 `crates.md` 分别构建四条命令：客户端只编 WireGuard、服务端只编 OpenVPN、客户端只编 VLESS、服务端只编 VLESS 加 `landing-vless`，再用 `cargo tree` 检查只编 WireGuard 和只编 OpenVPN 的依赖图。上面互操作测试的 feature 组合不能用作隔离结论。

2026-11-11 在 Linux worker 上对代码快照 `d631f25` 验收：库测试 194、31、44 项全部通过，四个 ignored 的 Xray 对照全部通过；`vless_flow` 19 项通过；官方矩阵连跑两遍都是 456/456，拒绝用例 15/15，h2Params 2/2，UDP 大小 11/11，反向桥 2/2，XUDP 续接 2/2，REALITY target 10/10；`verify_vless_client.py` 18/18；两个 TLS 对照各重复 20 次全部通过；库测试连跑 30 次、加满负载再跑 30 次都没有失败；三个 VLESS crate 的 clippy 没有告警，四条叶子构建和依赖检查通过。过程和证据记录在 `.audit/vless-completion.tsv`。

REALITY 认证之后的伪装（NewSessionTicket 同长记录、探测 target 得到的记录长度和 ChangeCipherSpec 数目、target 探测失败时的处理）补上之后，在 Linux worker 上对 90e7fd8 之上的改动验证：库测试 208、31、44 项通过，四个 ignored 的 Xray 对照通过，三个 crate 的 clippy 没有告警，`vless_flow` 19 项通过，四条叶子构建和依赖检查通过，REALITY target 10/10，其中两个服务端在 TCP 和三种 Unix target 上发出的握手后记录都与 decoy 的 NewSessionTicket 同长（184 字节）。官方矩阵两遍：一遍 456/456，一遍 455/456，失败的是 `httpupgrade-early-data/xray-control`，即上面说的 Xray 服务端缺陷，不涉及 Kerlico。读客户端 Finished 出错时先发 alert 补上之后再验证一遍：库测试 209、31、44 项通过，四个 ignored 的 Xray 对照通过，clippy 没有告警，`vless_flow` 19 项通过，叶子隔离通过，官方矩阵 456/456，拒绝用例 15/15，REALITY target 10/10；其中重放 ClientHello 后发无法认证的记录，Xray 和 Kerlico 两个服务端都只回一条 24 字节的 alert（`17 03 03 00 13`）再关闭。客户端入口没有重跑。

2026-11-12 数据路径的改动之后（REALITY、TLS 和 VLESS Encryption 记录层的成批读写，HTTP/2 的等待点、写线程和排队规则，gRPC 原处解码，Encryption 客户端按硬件选算法），在 Linux worker 上对 `a08c02c` 之上的工作区验证：库测试 218、31、44 项通过，四个 ignored 的 Xray 对照通过，三个 crate 的 clippy 没有告警，`vless_flow` 19 项通过，四条叶子构建和依赖检查通过。官方矩阵 455/456，失败的是 `httpupgrade-early-data/kerlico-to-xray`，Xray 服务端日志是 `invalid request version`，即下面说的 Xray 服务端缺陷；这一组另外重复 16 次全部通过。对写入排队最敏感的 `grpc-tls-sudoku` 重复 24 次全部通过。同一工作区还带着 mieru 对 `crates/shared` 和复制循环的改动。测量见 [VLESS 性能记录](vless-performance.md)。

已知差异和未完成项：

- REALITY 在等待目标探测完成的连接上应用探测得到的空记录上限，其余连接沿用 32。探测客户端在目标请求证书时回空证书。在等客户端 Finished 时，原生 TCP 和 Unix target 提前断开会中止握手。握手完成后连续空记录超限时，发送 TLS fatal alert，然后关闭。与 target 的 NewSessionTicket 同长的记录只在它已随握手记录到达时记下，到达是否赶得上取决于读取，Xray 也一样。
- Xray 客户端用 ios、edge、qq 和部分 `randomized` 指纹发出的 ClientHello 只有 X25519 share，连 Xray 和 Kerlico 的 REALITY 服务端都会失败；android 和 360 指纹只有 TLS 1.2，也不能用于 REALITY。这是 Xray 的规则，Kerlico 保持一致。
- TLS 1.3 服务端的组选择有意与 Go 不同，见上文 TLS 段。`curvePreferences` 支持 `SecP256r1MLKEM768` 和 `SecP384r1MLKEM1024`，两组均已与 Xray 双向验证。未识别的组名按 Xray 的方式忽略。
- XHTTP H1 已与 Xray 双向验证请求预算耗尽和限制复用后的载荷传输。物理 TCP 连接数取决于 HTTP 上传连接池，固定版本 Xray 自对照也会变化；因此只对 H2 做精确载体计数比较。
- 门户的第一个数据报超限时，会话用不带数据的 NEW 帧打开。已用 Xray 桥验证超限首包被跳过、后续数据报和回包照常传输。
- XDrive 在独立的 RustFS 1.0.0-alpha.89 上通过 S3 载荷往返；S3 上传为空时也发送 `Content-Length: 0`。没有 AWS S3 和 Google Drive 测试账号，两家的真云往返尚未验证。
- 固定版本 Xray 自对照仍可能在明文 HTTPUpgrade 早期数据下失败：它读完请求头后弃用缓冲，预读的 VLESS 字节被一起丢弃（`transport/internet/httpupgrade/hub.go`）。Kerlico 客户端等 101 后再发首包。Kerlico 服务端仍接收 Xray 客户端提前发送的数据，并把 VLESS 响应随第一批下行一起写，避开 Xray 客户端会丢掉和 101 一起到达的响应字节的问题。旧实现对 Xray 自对照的已知缺陷无法在 Kerlico 一侧更改。

2026-11-15 在 perf-01 上验证：证书文件的大小和修改时间固定不变时，重载回归在旧实现的 release 构建下失败，切换到按内容判断后通过；同一用例还检查了部分轮换、坏 PEM 和 `oneTimeLoading`。明文 HTTPUpgrade 的回归确认 `ed>0` 时也不在 101 前发送首包，且 Kerlico 客户端对固定 Xray 的明文和 TLS 两项用例通过。H2 服务端现在也会发送 SETTINGS 9（`SETTINGS_NO_RFC7540_PRIORITIES`，值为 1）；两组 `h2Params` 对照直接读取 h2c 和 TLS 的 SETTINGS，结果均与 Xray 一致。共享 TLS 拆分后以及加入 SETTINGS 9 后各重跑了一次 Xray 完整矩阵，都是 456/456。

2026-11-16 在 perf-01 验证：Xray 矩阵 456/456，REALITY target 10/10，h2c 和 TLS 的 `h2Params` 2/2，`vless_flow` 19/19，四项额外的库内 Xray 对照全部通过。`h2Params` 对照比较了默认与显式配置的 SETTINGS 值、发送顺序和首个连接窗口增量。

扩展后的 `h2Params` 字节级对照 6/6：还验证了禁用套件时的 `GOAWAY INADEQUATE_SECURITY`、显式允许时的 SETTINGS，以及原生 TCP 写停滞后启用 `WriteByteTimeout` 的断连、关闭此选项后的完整 8 MiB 传输。原矩阵复跑 456/456，新增两组 H1 XMUX 也分别通过官方自对照和两个互通方向，共 6/6。
