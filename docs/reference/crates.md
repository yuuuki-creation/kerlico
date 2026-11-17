# 编译单元和协议目录

这篇只记仓库现在怎么划分，以及增加协议时要改哪几处。为什么这样分，见 `docs/explanation/shape.md`。

## 目录

```text
crates/shared          包 kerlico-shared。两端的领域类型。没有角色 feature。
crates/client          包 kerlico-client。客户端叶子。
crates/server          包 kerlico-server。服务端叶子。依赖 kerlico-outbound。
crates/outbound        包 kerlico-outbound。服务端以及 AnyTLS 独立客户端的拨号模块。
crates/manifest        包 kerlico-manifest。构建时核对协议目录和叶子依赖。
crates/tls             包 kerlico-tls。双方共用的传输 TLS、证书与 ClientHello 配置。
crates/wg              包 kerlico-wg。WireGuard 角色和 WARP 共用的用户态引擎。不安装本机默认路由。
protocols/<id>/shared  包 kerlico-<id>。这个协议两端共用的帧。
protocols/<id>/client  包 kerlico-<id>-client。只有客户端叶子可以依赖。
protocols/<id>/server  包 kerlico-<id>-server。只有服务端叶子可以依赖。
```

工作区显式成员是 `crates/shared`、`crates/client`、`crates/server`、`crates/outbound`、`crates/manifest`、`crates/tls` 和 `crates/wg`。协议目录不显式列入成员。

代码未跟上：2026-11-09 的 `cargo metadata --format-version 1 --no-deps` 显示协议的 path 依赖也被 Cargo 自动纳入工作区，共 15 个成员。本轮没有改变工作区划分；功能裁剪分别检查叶子的运行时依赖图，不用工作区包数推断角色隔离。

协议目录包括 `wireguard`、`openvpn`、`mieru`、`vless`、`anytls`、`hy2` 和 `ss2022`。OpenVPN 的协议体是 `unimplemented!`。各协议的配置见各自的参考文档。

本机 SOCKS5/HTTP 入口只在客户端叶子里有一份，见下文「客户端叶子和本机入口」。

mieru 共享 crate 的运行时加密依赖是 `chacha20` 和 `ring`，组合实现既有 XChaCha20-Poly1305；原 `chacha20poly1305` 留作测试对照依赖。该变化没有增加协议或角色 feature。`kerlico-shared::Traffic` 在建流时返回 `TrafficCounters`，注册和查询仍由服务端拥有，出站持有计数句柄。

mieru 共享 crate 在 Linux 上通过 `libc` 和 `socket2` 0.6 批量接收已有 UDP 数据报；这两个直接依赖只在 Linux 启用，不增加角色依赖。

mieru 共享 crate 使用 Tokio 驱动服务端 UDP 监听的就绪、发送队列和维护期限，并为其中的 TCP 会话交出 `AsyncTcp`。认证、重排、窗口和恢复仍由同一个共享状态机处理，拨号仍属于出站。

`kerlico-outbound` 在 Linux 上直接依赖 `libc`，用于已完成协议转换的原生 TCP 之间的内核复制；不引入任何协议或角色 crate。

`kerlico-shared::AsyncTcp` 使用 Tokio 的异步读写契约和已有执行器句柄，持有协议交出的明文读写两半；共享包不创建执行器、不拨号，也不依赖协议角色。统一出站可以把原生 TCP 转发移到这个执行器，见服务端文档。出站启用 Tokio 宏来同时推进两个方向和共同空闲期限。

共享的 `AsyncBufReadVectored` 扩展借用读取契约，允许协议一次交出几段认证缓冲；它使用标准库的 `IoSlice`，不引入协议依赖或另一份拨号实现。SS2022 使用其原有 bytes 依赖持有这些记录，出站决定如何写到目标。

同步 `InboundStream::read_from_user_vectored_to` 同样使用标准库 `IoSlice`，把一批借用数据交给现有出站复制循环；默认适配单段读取，不增加包依赖。AnyTLS 持有接收端期间借出原地认证的载荷，原生 TCP 出口完成向量写入后才释放借用。

AnyTLS 共享 crate 直接依赖 Tokio 的套接字就绪、任务和通知接口，让原生 TLS/明文会话的流持有接收状态并移交 `AsyncTcp`。接收端通过同一个向量借用契约交付数据，发送端通过 `AsyncWriteInput` 借出 PSH/TLS 载荷区域；拨号仍只在出站。socket2 0.5 仅作为该共享 crate 的测试依赖，用于构造实际套接字背压。

`AsyncWriteInput` 允许编码器借出最终帧内存中的载荷区域。共享契约只描述互不重叠的 `IoSliceMut` 和本次填充长度；读取目标套接字仍属于出站。普通异步写入和借出输入区域的写入都通过 `AsyncWriteHalf` 交接，不增加协议依赖。

VLESS 服务端直接依赖 Tokio 的套接字就绪与异步读写接口，使用 VLESS 共享包原有的 I/O 执行器移交已经建立的原生 TCP/TLS 字节流。测试用 socket2 构造单连接背压；它不增加运行时角色依赖。

VLESS、AnyTLS 和 Hy2 都依赖 `kerlico-tls`。VLESS 和 Hy2 会开启这个引擎的 `quic` feature。AnyTLS 在普通连接上保留 rustls 取密钥和按方向处理记录的路径，浏览器指纹、ECH 以及需要修改首个 ClientHello 的载体使用共享引擎。JLS 的默认握手使用 rustls-jls，见 [AnyTLS](anytls.md#tls)。

共享 TLS 的握手和发送记录仍由原生 TLS 引擎处理。TLS 1.3 完成握手并验证对端后，将接收方向的应用流量密钥和原生引擎实际的下一记录序号交给 Rust 接收层，使用 `ring` 在接收存储中认证和解密；`ring` 因此为普通依赖，`foreign-types` 用于原生连接和会话句柄。TLS 1.2 及以下继续使用原生记录层。接收密钥只在连接内存中交接，配置未指定 `masterKeyLog` 时不写密钥文件。KeyUpdate 的接收密钥更新由接收层处理，回复仍由原生发送层封装；新会话票据交还原生引擎校验后进入同一配置缓存。

共享 TLS 的接收存储按实际填满的底层读取增长；普通 `Read` 使用至多四条最大 TLS 记录的预读空间，每次仍只交出一条记录，让 Vision 可以在记录之后切换直连。原生异步 VLESS 的底层套接字已经转为非阻塞，可以在交出批次之前继续取回已就绪的密文，至多保存十六条最大记录，然后通过原有向量借用接口交付认证明文。统一出站写完多少才消费多少；批次交出后不再读取、移动或覆盖其中的存储。它不等待新数据凑批次，后续错误留到有效字节交付后报告。

`protocols/hy2/shared` 持有 Hysteria 2 的认证和帧格式。VLESS 的 `hysteria` 载体复用认证与流类型；VLESS 命令仍由 VLESS 解析。独立 Hy2 的当前范围见 [Hysteria 2](hy2.md)。

工作区固定的 Quinn 使用套接字报告的 GSO 能力组织发送批次；合并后的单次 UDP 提交至多 65,507 字节，一次驱动最多交付 128 个数据报或 256 KiB，随后让其他任务继续。密文缓冲按实际需要增长并复用，不为安静连接预留整批存储。套接字背压时保留原批次，恢复后计入本次驱动的预算，不重新生成包或推进密钥。MTU、拥塞控制和实际发包时机仍由原 QUIC 状态机决定，不等待额外数据凑批次。

`protocols/ss2022/shared` 使用 `shadowsocks` 1.25.0 和 `shadowsocks-crypto` 0.8.0。工作区固定这两个版本并加上 ChaCha12；[补丁说明](../../vendor/shadowsocks-crypto/KERLICO-PATCH.md) 记录改动和许可。

## 一次构建选一端和一组协议

feature 名字就是协议 id，也是叶子 `[dependencies]` 里那条可选依赖的键。叶子没有 `[features]` 表。

客户端只编 WireGuard。

```text
cargo build -p kerlico-client --no-default-features --features wireguard
```

服务端只编 OpenVPN。这是另一条命令。

```text
cargo build -p kerlico-server --no-default-features --features openvpn
```

WireGuard 客户端使用 `kerlico-outbound` 为整个隧道打开一个 UDP 载体，系统支持时在同一个端口收发 IPv4 和 IPv6，依赖图没有服务端协议 crate。检查时用 `cargo tree -p kerlico-client --no-default-features --features wireguard --edges normal,build`。

同一次命令如果写了 `-p kerlico-client -p kerlico-server --features wireguard`，两个叶子都有名为 `wireguard` 的 feature，服务端图里会出现 `kerlico-wireguard-server`。不对称的协议集合用两条命令。

## 增加一个协议

协议 id 是一段或多段小写字母和数字，段之间用一个连字符。

1. 建立 `protocols/<id>/shared`，包名 `kerlico-<id>`。这个包不依赖角色 crate。
2. 需要哪一端，就建立 `protocols/<id>/client` 或 `protocols/<id>/server`。包名是 `kerlico-<id>-client` 或 `kerlico-<id>-server`。
3. 角色 crate 依赖 `../shared` 和 `../../../crates/shared`。它不依赖另一端。
4. 在对应叶子的 `[dependencies]` 加一行。键等于协议 id。
5. 客户端 crate 导出 `pub const CLIENT: ClientEntry`。数据包隧道写 `ClientEntry::Tunnel(connect)`；能提供落地 UDP 关联的隧道使用 `PacketTunnel`，也可提供 TUN 设备入口。代理协议写 `ClientEntry::Proxy(upstream)`；落地能共享 UDP 关联时可用 `ClientEntry::ProxyWithDatagramLanding(upstream)`。生成的注册表引用这个常量，缺少它时构建失败。

客户端的这一行是这个形状。

```toml
wireguard = { package = "kerlico-wireguard-client", path = "../../protocols/wireguard/client", optional = true, features = ["tun-device"] }
```

服务端入站使用包名和路径里的 `server`，不启用 `tun-device`。

落地是服务端去拨另一个代理。它用的是该协议的客户端 crate，不是入站 crate。这一行只加在服务端叶子上。键是 `landing-` 加上协议 id。

```toml
landing-vless = { package = "kerlico-vless-client", path = "../../protocols/vless/client", optional = true }
```

入站协议的键仍然等于协议 id。客户端叶子不加 `landing-` 依赖。只编 OpenVPN 的那条命令不打开任何 `landing-` feature，依赖图里仍然没有客户端协议 crate。

`kerlico-manifest` 要求目录和这些行一致。下面几种写法会让构建失败。

- 叶子出现 `[features]` 表。
- 协议依赖使用 `dep:`。
- 协议依赖不是 `optional = true`。
- 包名、路径和协议 id 对不上。
- 客户端叶子点到服务端 crate。
- 服务端叶子点到客户端 crate，而这行的键不是 `landing-` 加上对应的协议 id。
- 协议的入站 crate 或客户端 crate 去依赖另一端。
- `protocols/<id>/shared` 缺失，或它依赖角色 crate。
- 协议源码里出现 `PROTOCOL_ID`。id 以目录名为准。

服务端叶子上的 `landing-<id>` 依赖指向该协议的客户端 crate，并且不进入入站菜单。出站模块调用该 crate 的 `land`。`landing-vless` 还让服务端叶子用该 crate 的 `reverse_bridge` 运行配置里的 `bridges` 节点，桥上的流仍由出站模块拨号。见 `docs/reference/server.md`。

AnyTLS 客户端 crate 用 `kerlico-outbound` 建立独立客户端的 TCP 连接并访问系统 DNS，作为落地时走服务端运行时的出口和 DNS。只有引入 AnyTLS 客户端 crate 的构建才为出站模块打开 `system-dns`。

## 客户端叶子和本机入口

客户端叶子的注册表把协议 id 对到该协议的 `CLIENT`。WireGuard 和 OpenVPN 提供数据包平面（`DataPlane`）。mieru、vless、anytls、hy2 和 ss2022 的 `ClientEntry::Proxy` 返回 `Arc<dyn Upstream>`。一个协议只能是数据包隧道或代理其中一种。

`Upstream`、`Stream` 和 `Association` 定义在 `kerlico-shared` 的 `proxy` 模块，因为协议的客户端 crate 也会作为 `landing-<id>` 编进服务端，不能依赖客户端叶子。`Upstream::open_stream(host, port)` 打开 TCP 流，`associate()` 打开一条 SOCKS5 UDP 关联，`close()` 幂等地取消它打开的全部流和关联。`Stream::read_for` 在等待期内没有数据时返回 `TimedOut`，结束时返回 `Ok(0)` 或 `UnexpectedEof`。`Association::send_to` 带本机应用的 UDP 来源，同一关联的来源不变。协议拒绝的单个数据报以 `Ok` 丢弃，只有关联已经结束才返回错误。`recv_for` 一次给出一个完整数据报及其来源。

SOCKS5 和 HTTP 前端在 `crates/client/src/proxy/`，只属于客户端叶子，所以服务端的 `landing-<id>` 构建不编入本机代理。前端用到的依赖里只有 `httparse` 是客户端叶子独有的。服务端叶子也依赖 `if-addrs`。`kerlico-shared`、`kerlico-outbound` 和 `kerlico-vless` 直接依赖 `socket2` 0.6，服务端叶子、`kerlico-mieru-server` 和 `kerlico-anytls-server` 直接依赖 `socket2` 0.5。

```text
kerlico-client                              # 列出本次构建的客户端协议
kerlico-client client.json                  # 按文档里的 protocol 启动
kerlico-client --tun wg-test client.json    # WireGuard 使用指定的 TUN 设备
kerlico-client --mieru-proxy client.json    # 同一路径，protocol 固定为 mieru，可以省略
```

客户端文档由 `kerlico_shared::Document::parse` 解析，是 JSON 对象 `{"protocol", "peer", "settings"}`，不接受其他顶层键。`protocol` 只在 `--mieru-proxy` 下可以省略，提供时必须是本次构建的协议，否则命令以非零状态退出并说明缺少哪个协议。端点写 `peer`，也可以省略 `peer`，改在 `settings` 写 `address` 和 `port`；同时提供时必须一致。`peer` 的 IPv6 写成 `[::1]:30000`。`settings` 的值按 `Settings::insert_json` 转换，规则与服务端配置相同：字符串原样保留，数字和布尔值变成 JSON 文本，数组和对象序列化为 JSON 文本，`null` 拒绝。

代理协议的 `settings` 还带四个本机入口键，由叶子取走，不交给协议。`socks5Port` 和 `httpProxyPort` 默认 1080 和 8080，取值 1025 到 65535，两者不能相同。`socks5ListenLAN` 和 `httpProxyListenLAN` 为 `true` 时绑定局域网地址，默认只绑定 `127.0.0.1`。其余键交给协议，协议自己拒绝它不认识的键或值。文档、本机入口键和协议在打开上游时能检查的设置，都在绑定端口之前检查。错误信息不输出配置原文。

LAN 开关为真时，枚举实际接口上的 IPv4 私网和链路本地地址，以及 IPv6 ULA 和链路本地地址，逐一绑定。IPv6 设置 `IPV6_V6ONLY`，链路本地地址携带接口作用域。没有合适地址时拒绝，不扩大到公网 wildcard。所有端口成功绑定后才开始接入，失败时释放先前绑定的端口。`Proxy::start(upstream, &LocalEntry)` 返回的句柄提供 `socks5_addrs()`、`http_addrs()`、`wait()` 和 `close()`；释放句柄会停止监听并等待受控任务。

SOCKS5 包含 `CONNECT` 和 `UDP ASSOCIATE`，只接受无认证方法。UDP 关联受 TCP 控制连接的生命周期约束，验证请求声明的地址和实际来源，端口为 0 时固定第一个合法 UDP 来源。拒绝分片注入，回复写出协议给的来源地址。HTTP 代理接受普通请求和 `CONNECT`。普通 HTTP 按每个请求的目标打开一条流，支持 Content-Length、chunked 和同一本机连接上的跨目标请求。CONNECT 保留预读的隧道数据。头部、行长度和消息边界有上限，冲突的长度、非法地址和不支持的升级或期望明确拒绝。本机 TCP 读到 EOF 后保留反向响应，直到对端关闭、取消或 300 秒空闲。接入的本机连接设置 `TCP_NODELAY`，否则分两次写回应用的数据要等应用的延迟确认。SOCKS5 和 HTTP CONNECT 的 TCP 转发每个方向一次复制最多 64 KiB：从本机一次读到的数据整段交给协议写一次，协议一次交出的数据整段写回本机。

## 引擎和协议是两个 crate

`crates/wg` 是唯一的 WireGuard 引擎。入站、客户端、落地和服务端默认带的 WARP 都使用它。仅客户端叶子启用 WireGuard 时加上 `tun-device`，落地使用用户态 TCP/UDP，不需要打开 TUN。只编客户端且不编 WireGuard 时，不依赖 `kerlico-wg`。

`crates/wg/vendor/boringtun` 固定 BoringTun 0.7.1，并加上在线更换预共享密钥和报告握手确认的接口。[补丁说明](../../crates/wg/vendor/boringtun/KERLICO-PATCH.md) 记录上游版本和改动。分发包含 WireGuard 或 WARP 的二进制时，应附上它的 [BSD 许可](../../crates/wg/vendor/boringtun/LICENSE.md)。
