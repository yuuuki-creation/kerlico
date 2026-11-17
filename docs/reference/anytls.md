# AnyTLS

这篇是 AnyTLS 的决定。目标是替代参照实现里的 AnyTLS：同样的配置写法，同样的线上字节，更好的性能。

固定的 Xray 26.10.31（`reference/.upstream/xray-core-v26.10.31`）没有 AnyTLS 代理。本地可用的实现是 mihomo 1.19.33，只读源码在 `reference/.upstream/mihomo-v1.19.33`：`transport/anytls/`（客户端、会话、流、帧、填充）、`listener/anytls/server.go`、`adapter/outbound/anytls.go`、`listener/config/anytls.go`，UDP over TCP 来自它依赖的 `github.com/metacubex/sing` v0.5.8 的 `common/uot`。互通和性能都以 mihomo 1.19.33 为对端。下文说「mihomo」都指这个版本。

协议目录是 `protocols/anytls/{shared,client,server}`，包名 `kerlico-anytls`、`kerlico-anytls-client`、`kerlico-anytls-server`。叶子上的依赖键是 `anytls`，服务端另有 `landing-anytls`。入站交出 `Handoff`，不拨号；客户端 crate 导出 `CLIENT = ClientEntry::ProxyWithDatagramLanding` 和 `land`。

## 层次

一条连接依次是 TCP、传输安全层、认证、会话帧。普通 TLS 支持 TLS 1.3 和 TLS 1.2，显式配置的明文监听省略安全层。会话里有多条流。每条流先写目标地址，之后是 TCP 字节，或者是 UDP over TCP 的报文。

## 认证

客户端在 TLS 握手之后先发一条 TLS 记录：密码的 SHA-256（32 字节），2 字节大端的填充长度，然后是这么多个零字节。填充长度取填充方案第 0 包的第一个长度，默认方案是 30。服务端按 SHA-256 找用户，找不到就关闭连接，没有回落。

mihomo 服务端只看第一次读到的那条记录，密码、长度和填充必须都在里面。Kerlico 服务端按字节流读，分在几条记录里也接受。mihomo 的握手和认证没有期限；Kerlico 两者共用 10 秒，过期关闭连接。

## 帧

帧头是 1 字节命令、4 字节大端流号、2 字节大端长度，后面是数据。命令和 mihomo 相同。

| 命令 | 值 | 方向 | 行为 |
| --- | --- | --- | --- |
| waste | 0 | 客户端到服务端 | 填充，丢弃。 |
| SYN | 1 | 客户端到服务端 | 开一条流。服务端在收到设置之前收到 SYN，发 alert `client did not send its settings`，送出后关闭会话。客户端收到 SYN 时回 FIN，mihomo 客户端也是开了就关。 |
| PSH | 2 | 双向 | 流的数据。一帧最多 65535 字节，长度 0 的帧忽略。 |
| FIN | 3 | 双向 | 关闭这条流，两个方向一起关；AnyTLS 没有半关闭。收到 FIN 的一端不再回 FIN。 |
| settings | 4 | 客户端到服务端 | `v=2`、`client=<client-metadata>`、`padding-md5=<方案 MD5>`，每行一个 `键=值`。 |
| alert | 5 | 服务端到客户端 | 带数据时关闭会话。长度 0 的 alert 不处理，和 mihomo 一样。 |
| updatePaddingScheme | 6 | 服务端到客户端 | 新的填充方案原文。 |
| SYNACK | 7 | 服务端到客户端 | 流已打开；带数据时是错误文本，客户端以 `remote: 文本` 结束这条流。 |
| heartRequest | 8 | 双向 | 回一个同流号的 heartResponse。两端都不主动发。 |
| heartResponse | 9 | 双向 | 不处理。 |
| serverSettings | 10 | 服务端到客户端 | `v=2`。 |

settings 的三行顺序固定为上面的顺序。Go 按 map 遍历顺序写，每次不同；读的一方不看顺序，长度也相同。

服务端收到 settings 后，客户端的 `padding-md5` 和自己的方案不同就发 updatePaddingScheme；`v` 按 Go 的 `strconv.Atoi` 读到不小于 2 的数时，记下对端版本并回 serverSettings。客户端收到 serverSettings 时记下对端版本。

mihomo 不读 SYN、FIN、心跳以及不认识的命令后面的数据。对端真的在这些帧后面带了数据时，mihomo 会把它当作下一个帧头读错。Kerlico 按长度跳过这些数据。正常的对端不会发这种帧，所以和 mihomo 互通时看不出差别。

## 流头和 SYNACK

客户端开流后的第一段数据是 sing `SocksaddrSerializer` 格式的目标：1 是 IPv4、4 是 IPv6、3 是域名（1 字节长度），后面是 2 字节大端端口。服务端读完地址，对端版本不小于 2 时立刻回 SYNACK，然后才把流交出去，和 mihomo 一样不等出站拨号的结果。读不出的地址类型以 FIN 结束这条流。

客户端在同一会话里开第 2 条及以后的流、并且对端版本不小于 2 时，从发 SYN 起 3 秒内收不到任何 SYNACK，就关闭整个会话，和 mihomo 的 `synDone` 相同。

## 填充

填充方案是若干 `键=值` 行，`stop` 是不再填充的包号，数字键是包号，值是逗号分隔的列表：`a-b` 取 `[a, b)` 里的随机数（`a=b` 时就是 `a`，两端都要大于 0，先小后大可以颠倒），`c` 表示剩余数据为空时这一包到此为止。解析与 mihomo 的 `util.StringMapFromBytes`、`NewPaddingFactory` 和 `GenerateRecordPayloadSizes` 一致，包括后出现的同名键覆盖前者、`stop` 用 `Atoi` 读、负数 `stop` 回绕成 u32。默认方案与 mihomo 的 `DefaultPaddingScheme` 逐字节相同，MD5 是 `75cff2ad89aadf5e257059ee571ebe11`。

只有客户端填充。客户端每次写出（mihomo 的一次 `writeConn`）是一个包，包号从 1 起。包号小于 `stop` 时按列表切：剩余数据比这个长度长就写这么长的一条记录；剩余数据不长于它，就把剩余数据和一个 waste 帧拼成恰好这个长度（waste 帧的数据长度为负或零时只写剩余数据）；没有剩余数据时写一条只有 waste 帧的记录，长度是帧头加这个长度。列表用完还有数据，就再写一条。包号到 `stop` 后不再填充。会话的第一个包是 settings、SYN 和目标地址三帧，mihomo 先把前两帧缓存起来，写地址时一起发，Kerlico 也这样。

在 Go 里列表的每一项是一次 `conn.Write`，也就是一条 TLS 记录。Kerlico 让每一项成为一条记录，记录长度与 mihomo 客户端相同；不同的是几条记录可以放在同一次套接字写入里。认证记录和第一个包也和客户端的 TLS Finished 放在同一次写入里：Kerlico 客户端握手时把最后一组握手记录留到第一批 AnyTLS 字节一起发。

方案更新对已经在跑的会话也生效：客户端的每个包都读当前方案，与 mihomo 共享 `atomic.Pointer` 的效果相同。新方案解析失败时保留旧方案。

## UDP over TCP

UDP 走 sing 的 UoT。客户端开一条目标是 `sp.v2.udp-over-tcp.arpa:0` 的流，第一包前面带请求：1 字节 `isConnect` 和 SOCKS 格式的目标。之后的每个报文是 `uot.AddrParser` 格式的地址（0 是 IPv4、1 是 IPv6、2 是域名）、2 字节大端长度和数据；`isConnect` 为真时没有地址。服务端也接受旧的 `sp.udp-over-tcp.arpa`，那时没有请求，每个报文都带地址。

mihomo 客户端总是发 `isConnect` 为假，请求里的目标是第一个报文的目标。Kerlico 客户端也这样。mihomo 客户端先解析域名再发，Kerlico 客户端照本机应用给的目标发，可以是域名，服务端去解析。

Kerlico 服务端拆开 UoT 报文，为每个新目标交出一个 UDP `Handoff`，节点仍逐目标选出口。非连接模式下，同一条 UoT 流的目标共用会话标记；走同一原生出口时复用 UDP 源端口，走支持共享关联的落地时复用该关联。UoT 回包携带出站看到的真实来源，包括域名解析后的 IP 和另一个端口发来的回复。连接模式固定一个目标，回包不带地址。每个目标最多积压 256 KiB 未读报文，再多的丢弃。一个目标的出站结束后，同一目标的下一个报文会再次交出 `Handoff`。mihomo 在 UDP 会话空闲 5 分钟后会关这条流。

## TLS

普通连接由 rustls 的 unbuffered API 完成握手，再把两个方向的流量密钥交给 `kerlico-anytls` 的记录层。每个方向一个 ring AEAD，序号各自递增。TLS 1.3 由 rustls 计算新密钥，本端下一批将越过 2^23 条记录时先发送 KeyUpdate；普通写入按一条记录检查，借入载荷的写入按本次实际记录数检查。TLS 1.2 支持 AES-GCM 和 ChaCha20-Poly1305，不重协商，达到限额时结束会话。两种版本都检查记录认证。收到 close_notify 当作连接结束，其他 alert 是错误；会话结束时尽量发 close_notify。

普通 TLS 服务端按本端套件顺序选择双方都支持的算法，在 TLS 1.3 中优先选择 `TLS_AES_128_GCM_SHA256`。仍接受只提供 AES-256-GCM 或 ChaCha20-Poly1305 的对端；TLS 1.2 沿用原有套件列表和顺序，客户端的 ClientHello 套件顺序不变。此 TLS 1.3 优先级与固定 anytls-go v0.0.13 服务端在测试机上的实际协商一致。性能比较必须记录实际协商的套件，不能把不同 AES 密钥长度造成的成本全部归因于协议实现。

客户端配置了浏览器指纹、ECH 或单独的校验名称，或者服务端配置了 ECH 密钥时，用 [共享 TLS 引擎](crates.md) 的 BoringSSL 实现。收发仍走同一套 AnyTLS 会话帧、流调度和排队逻辑；共享引擎负责 TLS 记录与控制消息。AnyTLS 不依赖 VLESS crate，也不引入 QUIC。ECH 必须成功协商 TLS 1.3，拒绝时不退回明文 SNI。

根证书默认用 `webpki-roots`；mihomo 用系统证书加它自带的 CA 包。客户端不做会话恢复。服务端不提供 ALPN，和 mihomo 的监听器一样。

## 服务端

节点 `settings` 接受 mihomo 监听器的 `certificate` 和 `private-key`（PEM 文本或文件路径），以及可选 `padding-scheme` 和 `ech-key`（mihomo 的 `ECH KEYS` PEM 文本或文件路径）。`client-auth-type` 取 `request`、`require-any`、`verify-if-given` 或 `require-and-verify`。前两种只检查客户端对证书私钥的持有，后两种还要求以 `client-auth-cert` 配置的 CA 验证证书链。只配 CA 时按 `require-and-verify`。TLS 客户端证书验证之后仍要检查 AnyTLS 密码。

没有配置证书和其他安全层时，必须显式设置 `allow-insecure: true` 才允许明文监听。该模式直接读写 AnyTLS 认证和会话帧，不提供传输加密。证书和私钥同时配置时仍使用 TLS。明文和以下三种载体不使用普通 TLS 的 ECH 和客户端证书选项。一个节点至多启用一种载体。

| 载体 | 节点 `settings` |
| --- | --- |
| ShadowTLS | `shadow-tls` 写 `enable: true`、`version`（1、2、3）、`handshake: {"dest":"host:port"}`。v2 用 `password`，v3 用 `users: [{"name":"…","password":"…"}]`。v2 和 v3 可以按 SNI 指定 `handshake-for-server-name`；v3 接受 `strict-mode` 和 `wildcard-sni`（`off`、`authed` 或 `all`）。 |
| RestLS | `res-tls` 写 `enable: true`、`dest`、`password`，可加 `restls-script`、`min-record-len` 和 `rate-limit`。`dest` 省略端口时取 443；支持目标实际协商的 TLS 1.2 和 TLS 1.3，并支持两版握手续接。 |
| JLS | `jls-config` 写 `enable: true`、`dest: "host:port"`、`users: [{"username":"…","password":"…"}]`，可加 `sni`、`alpn`、`rate-limit`。默认 SNI 是 `dest` 的主机名。握手用临时证书，成功还需校验 AnyTLS 密码。 |

ShadowTLS 和 RestLS 的握手目标通过运行时向出站模块请求原生 TCP 载体。打开握手目标前就识别为回落时，把已读握手字节和目标交给节点的出口规则；已经和目标交换字节后，则在原连接上继续双向转发，不再拨一次。ShadowTLS v2 在切换前认证失败、v3 严格模式遇到非 TLS 1.3 目标时，也保留原连接。RestLS 的 `rate-limit` 作用于回落转发，单位为比特每秒，0 表示不限。

用户对象写 `email` 和 `password`，对应 mihomo `users` 里的名字和密码。两个邮箱不能用同一个密码，因为服务端按密码找用户；mihomo 的 map 里后写的覆盖先写的。删除用户后，这个用户已有会话里的新流不再交出。

## 客户端

客户端文档的 `protocol` 是 `anytls`，端点写 `peer`。`settings` 接受 mihomo `anytls` 代理的字段名：

| 键 | 含义 |
| --- | --- |
| `password` | 必填。 |
| `sni` | SNI 和校验证书用的名字，缺省是服务器地址。 |
| `alpn` | JSON 数组或逗号分隔。 |
| `skip-cert-verify` | 不校验证书链；握手签名照常校验。 |
| `fingerprint` | 证书 SHA-256，十六进制，可带冒号。匹配叶证书就接受；匹配链上的其他证书时以它为唯一根，再校验证书链和名字。浏览器名字报错，和 mihomo 相同。 |
| `client-fingerprint` | 共享 TLS 引擎支持的 ClientHello 预设，例如 `chrome`。 |
| `name-cert-verify` | 只替代证书的校验名称，SNI 仍由 `sni` 决定。 |
| `certificate`、`private-key` | 同时填写，用于 TLS 客户端认证。支持 PEM 文本或文件路径。 |
| `ech-opts` | `enable` 为真时启用。可提供 Base64 `config`；未提供时查 HTTPS 记录，查询名称默认是 SNI，可用 `query-server-name` 覆盖。服务端落地使用其配置的 DNS，独立客户端使用系统 DNS 配置。 |
| `shadow-tls-opts` | 对象 `{"version": 3, "password": "…"}`，版本 0 或省略按 v2。v1 只用于 TLS 1.2 的握手目标。 |
| `restls-opts` | 对象 `{"version-hint":"tls13","password":"…"}`。`version-hint` 可设为 `tls12`，需与目标实际协商的版本匹配；也可提供 `restls-script`。 |
| `jls-opts` | 对象 `{"username":"…","password":"…"}`。可配 `client-fingerprint`。 |
| `udp` | 缺省 `false`，和 mihomo 一样，为假时本机 SOCKS5 的 UDP ASSOCIATE 失败。 |
| `client-metadata` | settings 里 `client` 的值，缺省空。 |
| `idle-session-check-interval`、`idle-session-timeout` | 秒。不大于 5 时当作 30，和 mihomo 相同。 |
| `min-idle-session` | 清理时保留的空闲会话数。 |
| `disable-reuse` | 流结束后关闭会话，不放回空闲池。 |

三种载体选项互斥。其余键拒绝，含 mihomo 的通用拨号字段。

会话池和 mihomo 的 `session.Client` 一样：一个会话同时只给一条流用。开流时取最新的空闲会话，没有就新建；流结束（任一端关闭）时，会话还活着就放回空闲池并记下时间。每过 `idle-session-check-interval` 清理一次：从最新的空闲会话往旧的数，没超时的算活跃，超时的在活跃数不足 `min-idle-session` 时保留并重新计时，其余关闭。`close` 关闭全部会话。

本机 SOCKS5 和 HTTP 入口由客户端叶子提供，见 [编译单元](crates.md)。AnyTLS 把上游的主机名和端口交给服务端运行时，由出站模块打开原生 TCP 载体。落地的会话池按运行时、上游地址和设置分别缓存，最多 64 组；无活动且 60 秒没用到的组，以及运行时已销毁的组，在下次使用缓存时清退。入站标记为同一 UDP 会话的目标经 AnyTLS 落地时，在这个池里共用一条 UoT 流。

## 数据路径

普通 TLS 记录和明文会话使用共享的 Tokio 执行器。忙碌 TCP 流的转发任务直接取走整个接收状态，原地解密、解析，并借出属于它的多段载荷；消费完成或任务退出时归还状态。借出前可以继续读取当前已经就绪的数据，仍受 512 KiB 和 64 段上限约束，不等待后续数据凑批次。借用期间没有第二个任务读取或移动这块存储。其他流的数据使用原有有界队列；队列背压时保留已经认证的记录剩余位置，恢复后不重复解密。空闲任务只处理握手、无读者的会话和控制消息。没有开始读取的流不阻止空闲任务工作。

原生 TCP 出口把下行数据直接读入写者持有的 PSH/TLS 帧载荷区域，一批最多两个 65,535 字节 PSH 帧。帧头、TLS 头和标签不暴露给出口。提交后由会话唯一的发送密钥和序号原地封装，已初始化存储在批次间复用。普通异步写入也填充这些区域并使用同一封装接口。控制记录和应用批次进入同一有序发送队列；部分写入保留原密文。等待应用批次完成的写任务推进自己的批次，辅助任务只发送控制记录并通知应用写者套接字可写。调用者取消已经封装的写入时，有限的密文批次仍按序排空后再发送该流的 FIN，不能从 TLS 序列中删除一段而破坏其他流。

共享 TLS 引擎和其他库包装的载体沿用以下同步读权规则，帧解析、认证和队列边界与原生执行方式共用。

会话的接收端同一时间只由一个线程持有。持有者用一个大缓冲区读套接字（从 64 KiB 起，读满时加倍，最大 512 KiB），把已经到齐的每条记录在原地解开，再在解开的地方拆帧，PSH 的数据交给它所属的流。每条流有自己的条件变量，只有流的读者真的在等时才唤醒它。连续的帧属于同一条流时不再查流表。

流的读者在自己的队列为空、接收端又没人持有时，自己去读套接字。客户端一个会话只有一条流，所以本机入口的下行线程直接读 TLS 连接，不再经过另一个线程转手；服务端的出站上行线程也一样。会话自己的读线程按这条规则让路：

- 会话里没有在读的流（第一条流之前、上一条流刚结束、只有 UDP 的流）时，它马上读。一条流从任一端结束（关闭、FIN、丢弃句柄）时，如果它是最后一个在读的流，就立刻唤醒这个线程，所以复用的会话接下一条流不等任何计时器。
- 有流的读者正在 `read_for` 里时，由那个读者读，这个线程每 100 ms 看一次。
- 所有流的读者都离开了 `read_for`（在处理读到的数据）时，离开满 5 ms 它才去读；它只睡剩下的那段时间。

不属于任何读者的帧（新流的 SYN、心跳、和 TCP 流同在一个会话里的 UoT 报文）只在所有读者都离开 `read_for` 时才要等：读者离开前这个线程刚看过一次时，最多晚约 105 ms，否则最多晚 5 ms。读者通常只离开几微秒（把读到的数据写给应用或出口）；mihomo 客户端一个会话只有一条流，所以只有出口或应用写不动时才会碰到这个上限，这时 mihomo 的读循环也停在那条流的管道上。复查间隔改成 20 ms 时上限约 25 ms，但每个会话每秒多 50 次唤醒：300 个每 100 ms 往返一次 64 字节的会话，服务端和客户端的 CPU 各从约 18% 升到约 23%（见下文），所以取 100 ms。

它一次读最多等 200 ms（`SO_RCVTIMEO`，每条连接只设一次），所以读者的等待期限最多晚 200 ms。同一会话的几条流同时在读时，没拿到接收端的读者等持有者交来数据，持有者放手时叫醒一个在等的读者接着读；等待每 20 ms 再试一次。

这条规则的第一版只看「100 ms 内有没有读者要过数据」，流结束时什么也不做。复用的会话因此在上一条流结束后的 100 到 200 ms 里没人读：`crates/server/tests/anytls_latency.rs` 在 perf-01 上测到，mihomo 客户端经 SOCKS5 连续开短连接（连上、发 64 字节、读回、关闭，下一条在关闭后隔一段时间再开，每个间隔 100 次，会话确实被复用），Kerlico 服务端的连上到回显 p50 在间隔 0、5、20、50 ms 时分别是 101、96、81、51 ms，改动之前的版本是 1.1、1.3、1.2、1.9 ms；间隔 150 和 400 ms 时两者相同。Kerlico 客户端库对 Kerlico 服务端一样。改成上面的规则后，mihomo 客户端在 0 到 400 ms 的各个间隔下，p50 回到 1.07 到 1.86 ms，和改动前的 1.08 到 2.15 ms 同量级。另一种情况，同一会话里一条流每 3 ms 往返一次、每 50 ms 新开一条流，新流从打开到第一次回显的 p50 在三个版本里都是 0.9 ms 左右：读者在 `read_for` 里时它本来就读得到新流的帧。共享 crate 的测试 `a_reused_session_answers_the_next_stream_at_once` 检查上一条流结束 10 ms 后开的新流在 50 ms 内收到回显；按第一版的规则，这个测试在 90 ms 以上失败。

在 perf-01 上，这一步把 Kerlico 客户端每 GiB 的 CPU 从 1.27 秒降到 1.12 秒，服务端从 1.30 降到 1.16：此前每读一块数据就有一次读线程到流读者的 futex 唤醒和两三次上下文切换。

流的接收队列最多积压 1 MiB。超过时持有接收端的线程等这条流被读走一些，整个会话随之停下；持有者正是这条流的读者时不等。mihomo 的管道没有积压，读线程每帧都等流的读者读走，所以这只是同一行为来得更晚。

流自己持有接收端时，解析器把属于它的 PSH 载荷记成接收存储中的范围，至多借出 64 段，由出口一次向量写入；这些载荷不先进入流队列，也不复制到通用转发缓冲。整个借用期间持有接收端，不能继续读取、移动或复用该缓冲，出口背压也暂停这个会话的读取。其他流已经排队的数据仍可独立读走。属于其他流、地址解析留下的载荷、超过本次读取容量或切片上限的尾部仍进入原有的有界队列，先排队的数据不会被后来的借用片段越过。普通读取和借用读取共享解析器及消费顺序；后续 TLS 认证失败时，先交付这一批已经认证的前缀，再结束会话。

写的一方直接把调用者的字节连同帧头复制进 TLS 记录，在发送缓冲里原地加密。几个写者共用一个发送缓冲：发现套接字空闲的写者把整个缓冲一次写出，其他写者把自己的字节加进缓冲后等着；写出的人写完自己的那批后，如果还有人在等，就把写的活交给最早的那个等待者，自己返回。所以一个线程至多替别人写一批。写入在套接字收下之后才返回，和 Go 的 `Write` 一样。

持有接收端的线程从不为此写套接字。它要发的帧（SYNACK、心跳回复、设置的回复、KeyUpdate）放进发送缓冲，没有人在写时交给会话的写辅助线程，这个线程在第一次需要时才创建。

发送缓冲里待写的字节有上限，约等于套接字最近十六分之一秒收走的量，限制在 16 KiB 到 128 KiB 之间。超过时写者按到达顺序排队。客户端填充期间一次写入就是一个包；之后长的写入按 65535 字节的整帧切成不超过上限的几段，每段排一次队，所以线上的帧和 mihomo 一样，只是不一定在同一次写入里。填充期之后记录按 16384 字节切；Go 的 TLS 会从约 1.2 KB 的记录开始逐步加大，这只在密文的记录长度上看得出。

## 验证

构建和测试在 Linux worker 上执行。

单元测试里的字节向量来自 Go：`tools/anytls_peer/vectors_test.go` 放进 mihomo 的 `transport/anytls/session` 包里运行，打印默认方案 MD5、认证记录、客户端一串写出（设置、SYN、地址、几种填充切法、第二个 SYN、超过 `stop` 的大写入、FIN）、只有填充的包、服务端的三种帧、两种地址格式、UoT 请求和报文。`kerlico-anytls` 的测试逐条对照这些写出：每次 Go 写出对应 Kerlico 的一条记录，内容逐字节相同。

2026-11-12 先在 perf-02 上得到下表的结果，所有命令都在工作区根目录执行。性能改动之后，最终的代码在 perf-01 上重跑：三个 crate 的测试 18、1、4 项，`anytls_flow` 7 项，`anytls_mihomo` 连跑两次都是 11/11，clippy 没有告警，两条叶子构建通过且依赖图里没有 anytls 的 crate；客户端叶子在 `anytls` 和 `mieru` 两种构建下的测试也都通过。

| 检查 | 命令 | 结果 |
| --- | --- | --- |
| 共享 crate、入站和客户端 crate 的测试 | `cargo test -p kerlico-anytls -p kerlico-anytls-server -p kerlico-anytls-client` | 18、1、4 项通过。共享 crate 的 18 项含上面的 Go 向量、地址、填充解析、队列，以及回环 TLS 上的会话：4 条流各 40 次 32 KiB 往返和 3 MiB 大传输、UoT 分目标与空包、服务端方案下发、错误密码。共享 crate 连跑 10 次没有失败。 |
| Kerlico 对 Kerlico | `cargo test -p kerlico-server --no-default-features --features anytls,landing-anytls --test anytls_flow` | 7 项通过，连跑 9 次没有失败。经真实服务端和出站：4 条流的 32 KiB 往返和各 8 MiB 传输；一个会话上 6 条流各 1 MiB；UoT 到两个目标、空包和 1400 字节；节点的 `padding-scheme` 下发到客户端；空闲会话复用和超时关闭；错误密码碰不到目标；`landing-anytls` 把一个节点的 TCP 和 UDP 交给另一个节点。 |
| 与 mihomo 互通 | `MIHOMO=… cargo test -p kerlico-server --no-default-features --features anytls,landing-anytls --test anytls_mihomo -- --ignored --test-threads=1` | 11 项，连跑 3 次都是 11/11。 |
| 一会话多流的压力 | 同上，只跑 `kerlico_session_multiplexes` 和 `mihomo_client_tcp`，另有两个忙循环占 CPU | 40 次全部通过。 |
| 静态检查 | `cargo clippy -p kerlico-anytls -p kerlico-anytls-server -p kerlico-anytls-client --all-targets -- -D warnings` | 没有告警。 |
| 叶子隔离 | `AGENTS.md` 的两条构建命令，以及两条命令的 `cargo tree --edges normal` | 构建通过，依赖图里没有 AnyTLS crate；只启用 `anytls` 时，两端只引入共享 crate 和本端角色。 |

`anytls_mihomo` 的 11 项：mihomo 客户端到 Kerlico 服务端有 4 条并发流的 32 KiB 往返加各 8 MiB、经 SOCKS5 的 UoT（两个目标、1400 字节、空包，回包来源逐个比对）、Kerlico 的填充方案下发（mihomo 日志里的 `Update padding succeed`，以及之后新会话的记录长度）、空闲会话复用和超时关闭（中间的 TCP 中继数连接）、错误密码；Kerlico 客户端到 mihomo 服务端有同样的五项，另加一个会话上 6 条流各 2 MiB。两个方向的填充项用同一个固定方案，新会话的前三条应用记录在两种客户端下都是 71、167、217 字节（认证 34+20、第 1 包 150、100 字节写入的第 2 包 200，各加 17 字节 TLS 开销），所以 mihomo 客户端和 Kerlico 客户端在线上的记录长度相同。没有 `MIHOMO`，或者版本不是 1.19.33，这些测试失败，不会算通过。

mihomo 在隧道开始运行之前就打开监听，这段时间里到达的流会被立刻关闭（`hub/executor/executor.go` 先 `updateListeners`，最后才 `tunnel.OnRunning`）。测试一开始偶尔失败就是这个原因：mihomo 服务端收到了 6 个 SYN 和地址，`NewConnection` 立刻返回并发 FIN。现在测试和性能工具都先等一条流真正走通再开始。

2026-11-15 整合到当前工作区后，在 perf-01 的独立构建目录复验：共享、客户端、服务端单元测试分别通过 19、5、1 项，端到端通过 7 项，对 mihomo 双向互通通过 11 项。三个 AnyTLS crate 的 Clippy 通过。客户端 WireGuard 和服务端 OpenVPN 分别构建并检查依赖图；另外检查了客户端 `anytls`、服务端 `anytls` 和服务端 `landing-anytls` 单独启用时的依赖图。共享本机入口回归 9 项、VLESS 流程 19 项、mieru 流程 6 项通过；mieru 的外部 Go 客户端用例本轮未执行。

补上 TLS 兼容项后在 perf-01 复验：共享、客户端、服务端单元测试分别通过 21、5、1 项，端到端 7 项，mihomo 互通 13 项。新增的两项 mihomo 对照分别验证两个方向的 ECH；Kerlico 当客户端时同时用 Chrome 指纹。标准 rustls 对端验证了 TLS 1.2 的 AES-GCM、ChaCha20-Poly1305 和客户端证书校验。DNS 测试验证了 ECH 查询名称和缓存，并分别验证了独立客户端和服务端落地在 UDP 应答截断后向同一上游用 TCP 重试。WireGuard 客户端与 OpenVPN 服务端的裁剪构建及依赖隔离再次通过。

2026-11-16 在 perf-01 复验：端到端 9/9，固定版本 mihomo 的互通和续接回归合计 19/19。明文用例检查启用后的载荷往返和错误密码拒绝；ShadowTLS v1、v2、v3、RestLS TLS 1.2、RestLS TLS 1.3 和 JLS 都在两个方向传输载荷。JLS 也检查 Chrome 指纹和初始认证失败时的回落。续接用例由握手目标分别确认 TLS 1.2、TLS 1.3 的第一次完整握手和第二次恢复握手。

性能用 `crates/server/tests/anytls_perf.rs`：`PERF_STREAMS` 条持久流各自写 32 KiB 再读回，另有一条每 10 ms 往返 64 字节的探测流。字节数是写出加读回，CPU 是 `/proc` 里 utime 加 stime。`PERF_RECORD_DIR` 让同一窗口里对两个隧道进程跑 `perf record` 和主要系统调用的 `perf stat`；做了剖析的窗口不当测量用。

下面的数字来自 perf-01（8 个 vCPU 的 Xeon，有 AES-NI 和 VAES），release 构建，8 条流，服务端绑 CPU 0-2，客户端 3-5，负载和回显源 6-7，每组 30 秒，热身 3 秒。每格是三轮的中位数，方括号是最小到最大。新旧二进制在同一时段里逐轮交替运行。

改动之前（协调方在 perf-01 上的一次三轮测量，`/srv/build/anytls-run/final.jsonl`）：

| 组合（客户端到服务端） | 吞吐 MiB/s | 服务端 CPU 秒/GiB | 客户端 CPU 秒/GiB | 探测 p50/p99 µs |
| --- | --- | --- | --- | --- |
| mihomo 到 mihomo | 1400 | 1.40 | 1.38 | 278/945 |
| Kerlico 到 Kerlico | 1566 | 1.41 | 1.46 | 240/434 |
| mihomo 到 Kerlico | 1567 | 1.31 | 1.33 | 242/768 |
| Kerlico 到 mihomo | 1413 | 1.50 | 1.42 | 293/761 |

改动之后，与改动前的二进制交替测量（`ab4.jsonl`），mihomo 对 mihomo 是同一时段的对照：

| 组合 | 版本 | 吞吐 MiB/s | 服务端 CPU 秒/GiB | 客户端 CPU 秒/GiB | 探测 p50/p99 µs |
| --- | --- | --- | --- | --- | --- |
| mihomo 到 mihomo | | 1357 [1300-1396] | 1.42 [1.38-1.48] | 1.43 [1.37-1.48] | 283/934 |
| Kerlico 到 mihomo | 改前 | 1395 [1371-1434] | 1.51 [1.48-1.55] | 1.46 [1.39-1.51] | 298/763 |
| Kerlico 到 mihomo | 改后 | 1625 [1576-1640] | 1.32 [1.30-1.35] | 1.16 [1.14-1.19] | 221/559 |
| mihomo 到 Kerlico | 改前 | 1539 [1489-1548] | 1.34 [1.31-1.38] | 1.37 [1.36-1.42] | 250/679 |
| mihomo 到 Kerlico | 改后 | 1589 [1540-1625] | 1.23 [1.20-1.25] | 1.35 [1.32-1.38] | 237/578 |
| Kerlico 到 Kerlico | 改前 | 1546 [1512-1555] | 1.45 [1.44-1.45] | 1.51 [1.48-1.53] | 251/456 |
| Kerlico 到 Kerlico | 改后 | 1816 [1783-1836] | 1.16 [1.16-1.19] | 1.15 [1.14-1.19] | 185/357 |

对着同一个 mihomo 服务端，Kerlico 客户端每 GiB 的 CPU 比 mihomo 客户端低约 19%（1.16 对 1.43）；对着同一个 mihomo 客户端，Kerlico 服务端低约 13%（1.23 对 1.42）。mihomo 服务端在 Kerlico 客户端对面也省了 CPU（1.51 降到 1.32），因为它收到的记录少了。

两步各自交替测量了三轮，都保留了：

1. 客户端叶子的本机入口每次复制从 16 KiB 改成 64 KiB（`ab1.jsonl`）。16 KiB 时一块 32 KiB 的数据要写两次，每次是一个 16391 字节的帧，即一条满记录加一条 7 字节的记录，下行也写回本机两次。Kerlico 客户端对 mihomo 服务端 1.42 [1.39-1.42] 降到 1.29 [1.26-1.31]。
2. 流的读者自己读套接字（见「数据路径」，`ab2.jsonl`）。客户端 1.27 [1.27-1.27] 降到 1.12 [1.12-1.15]，服务端在 mihomo 客户端对面 1.30 [1.26-1.31] 降到 1.16 [1.16-1.17]。

还试过一步，持有接收端的读者把自己流的字节直接解进调用者的缓冲区，省掉经过接收队列的那次复制（`ab3.jsonl`）。几组都好了 2% 到 3%，但三轮的范围互相重叠，算作噪声，没有保留。

每块 32 KiB（写出加读回 64 KiB）在 Kerlico 客户端上的系统调用，`perf stat` 计数除以块数：改前 futex 2.19、recvfrom 3.41、sendto 4.05、上下文切换 3.20；改后 futex 0.00、recvfrom 2.32、sendto 2.32、上下文切换 2.04。mihomo 客户端是 read 4.58、write 4.01、futex 0.65、上下文切换 0.93。剩下的两次上下文切换是每个方向的阻塞读各一次，Go 用 epoll 和 goroutine，没有这一项。`perf record` 的自身时间按类分，Kerlico 客户端改前：内核网络和系统调用 41%、复制（内核的用户态拷贝、清页、libc 的 memcpy）22%、AEAD 17%、唤醒和调度 15%、其他用户态 4%；改后：内核 32%、复制 32%、AEAD 22%、唤醒和调度 10%、其他 4%。按每 GiB 的 CPU 折算，AEAD 约 0.25 秒没有变，唤醒和调度从约 0.22 秒降到 0.12 秒，内核网络从约 0.60 秒降到 0.37 秒。

perf-02 上较早的测量每端只有一个核、CPU 型号也不同，当时 Kerlico 服务端的 CPU 看起来只有 mihomo 的三分之二；那组数字不代表多核上的差距，以 perf-01 的为准。

第一次测量时 Kerlico 客户端只有约 5 MiB/s：客户端叶子的本机 SOCKS5/HTTP 入口没有给接入的连接设 `TCP_NODELAY`，回给应用的第二段数据要等应用的延迟确认（Linux 上 40 ms）。这次在 `crates/client/src/proxy/mod.rs` 接入连接时设上了，这个入口对所有代理协议都是同一份；Go 的连接默认就是这样。

2026-11-15 整合到当前工作区后，同一台 perf-01、同样的绑核和 8 条流，各做一轮 30 秒对照：

| 组合（客户端到服务端） | 吞吐 MiB/s | 服务端 CPU 秒/GiB | 客户端 CPU 秒/GiB | 探针 P50 / P99 微秒 |
| --- | ---: | ---: | ---: | ---: |
| mihomo 到 mihomo | 1294 | 1.473 | 1.474 | 320 / 1074 |
| mihomo 到 Kerlico | 1375 | 1.241 | 1.446 | 346 / 2247 |
| Kerlico 到 mihomo | 1456 | 1.399 | 1.192 | 299 / 945 |

同对端下，Kerlico 服务端和客户端分别少用 15.8% 和 19.1% 的 CPU 秒/GiB。服务端组合在这一轮的持久流探针 P99 高于 mihomo 对照，不据此判断延迟改善。

短连接复测覆盖 0、5、20、50、150、400 ms 的流间隔，每个间隔各测 100 次，两种客户端共 1200 次；另测同会话里另一条流繁忙时的 100 次新流。全部拿到回显，分组 P50 为 1.0 至 2.2 ms，最慢一次 5.5 ms。又在同一时段按旧版、整合版、整合版、旧版的顺序，只换服务端，重测 0、5、20、50 ms 间隔和同会话的第二条流。各组两轮的 P50 持平或下降，P99 有升有降；两版最慢的一次都低于 5 ms。原始结果在 perf-01 的 `/srv/build/anytls-integration-20261115/`，分别是 `perf.jsonl`、`latency.jsonl` 和 `latency-{base,integrated}-{1,2}.jsonl`。

## 没有做的

- 一个会话同时承载多条流的客户端调度。客户端按 mihomo 的做法一流一会话；服务端接受任意多条流，互通测试里用共享 crate 直接在一个会话上开多条流。
- 主动心跳。两端都不主动发 heartRequest，和 mihomo 相同。
