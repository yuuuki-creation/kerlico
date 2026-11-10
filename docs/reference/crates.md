# 编译单元和协议目录

这篇只记仓库现在怎么划分，以及增加协议时要改哪几处。为什么这样分，见 `docs/explanation/shape.md`。

## 目录

```text
crates/shared          包 kerlico-shared。两端的领域类型。没有角色 feature。
crates/client          包 kerlico-client。客户端叶子。
crates/server          包 kerlico-server。服务端叶子。依赖 kerlico-outbound。
crates/outbound        包 kerlico-outbound。服务端唯一的拨号模块。
crates/manifest        包 kerlico-manifest。构建时核对协议目录和叶子依赖。
crates/wg              包 kerlico-wg。用户态 WireGuard，只给出站的 WARP 用。不安装本机默认路由。
protocols/<id>/shared  包 kerlico-<id>。这个协议两端共用的帧。
protocols/<id>/client  包 kerlico-<id>-client。只有客户端叶子可以依赖。
protocols/<id>/server  包 kerlico-<id>-server。只有服务端叶子可以依赖。
```

工作区成员是 `crates/shared`、`crates/client`、`crates/server`、`crates/outbound`、`crates/manifest` 和 `crates/wg`。协议目录不是工作区成员。

代码未跟上：2026-11-09 的 `cargo metadata --format-version 1 --no-deps` 显示协议的 path 依赖也被 Cargo 自动纳入工作区，共 15 个成员。本轮没有改变工作区划分；功能裁剪分别检查叶子的运行时依赖图，不用工作区包数推断角色隔离。

现在的协议目录是 `wireguard`、`openvpn`、`mieru` 和 `vless`。WireGuard 和 OpenVPN 的协议体是 `unimplemented!`。mieru 的决定在 `docs/reference/mieru.md`。vless 的决定在 `docs/reference/vless.md`。

本机 SOCKS5/HTTP 入口只在客户端叶子里有一份，见下文「客户端叶子和本机入口」。

mieru 共享 crate 的运行时加密依赖是 `chacha20` 和 `ring`，组合实现既有 XChaCha20-Poly1305；原 `chacha20poly1305` 留作测试对照依赖。该变化没有增加协议或角色 feature。`kerlico-shared::Traffic` 在建流时返回 `TrafficCounters`，注册和查询仍由服务端拥有，出站持有计数句柄。

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

2026-11-08 用 `cargo tree -p kerlico-client --no-default-features --features wireguard --edges normal` 看到的运行时依赖是 `kerlico-client`、`kerlico-shared`、`kerlico-wireguard-client` 和 `kerlico-wireguard`。图里没有 `kerlico-outbound`，也没有服务端协议 crate。

同一次命令如果写了 `-p kerlico-client -p kerlico-server --features wireguard`，两个叶子都有名为 `wireguard` 的 feature，服务端图里会出现 `kerlico-wireguard-server`。不对称的协议集合用两条命令。

## 增加一个协议

协议 id 是一段或多段小写字母和数字，段之间用一个连字符。

1. 建立 `protocols/<id>/shared`，包名 `kerlico-<id>`。这个包不依赖角色 crate。
2. 需要哪一端，就建立 `protocols/<id>/client` 或 `protocols/<id>/server`。包名是 `kerlico-<id>-client` 或 `kerlico-<id>-server`。
3. 角色 crate 依赖 `../shared` 和 `../../../crates/shared`。它不依赖另一端。
4. 在对应叶子的 `[dependencies]` 加一行。键等于协议 id。
5. 客户端 crate 导出 `pub const CLIENT: ClientEntry`。数据包隧道写 `ClientEntry::Tunnel(connect)`，代理协议写 `ClientEntry::Proxy(upstream)`。生成的注册表引用这个常量，缺少它时构建失败。

客户端的这一行是这个形状。

```toml
wireguard = { package = "kerlico-wireguard-client", path = "../../protocols/wireguard/client", optional = true }
```

服务端把包名和路径里的 `client` 换成 `server`。

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

## 客户端叶子和本机入口

客户端叶子的注册表把协议 id 对到该协议的 `CLIENT`。`ClientEntry::Tunnel` 是数据包平面（`DataPlane`），`ClientEntry::Proxy` 返回 `Arc<dyn Upstream>`。WireGuard 和 OpenVPN 是 `Tunnel`，mieru 和 vless 是 `Proxy`。一个协议只能是其中一种。

`Upstream`、`Stream` 和 `Association` 定义在 `kerlico-shared` 的 `proxy` 模块，因为协议的客户端 crate 也会作为 `landing-<id>` 编进服务端，不能依赖客户端叶子。`Upstream::open_stream(host, port)` 打开 TCP 流，`associate()` 打开一条 SOCKS5 UDP 关联，`close()` 幂等地取消它打开的全部流和关联。`Stream::read_for` 在等待期内没有数据时返回 `TimedOut`，结束时返回 `Ok(0)` 或 `UnexpectedEof`。`Association::send_to` 带本机应用的 UDP 来源，同一关联的来源不变。协议拒绝的单个数据报以 `Ok` 丢弃，只有关联已经结束才返回错误。`recv_for` 一次给出一个完整数据报及其来源。

SOCKS5 和 HTTP 前端在 `crates/client/src/proxy/`。只有客户端叶子依赖 `socket2`、`if-addrs` 和 `httparse`，所以服务端的 `landing-<id>` 构建不编入本机代理。

```text
kerlico-client                              # 列出本次构建的客户端协议
kerlico-client client.json                  # 按文档里的 protocol 启动
kerlico-client --mieru-proxy client.json    # 同一路径，protocol 固定为 mieru，可以省略
```

客户端文档由 `kerlico_shared::Document::parse` 解析，是 JSON 对象 `{"protocol", "peer", "settings"}`，不接受其他顶层键。`protocol` 只在 `--mieru-proxy` 下可以省略，提供时必须是本次构建的协议，否则命令以非零状态退出并说明缺少哪个协议。端点写 `peer`，也可以省略 `peer`，改在 `settings` 写 `address` 和 `port`；同时提供时必须一致。`peer` 的 IPv6 写成 `[::1]:30000`。`settings` 的值按 `Settings::insert_json` 转换，规则与服务端配置相同：字符串原样保留，数字和布尔值变成 JSON 文本，数组和对象序列化为 JSON 文本，`null` 拒绝。

代理协议的 `settings` 还带四个本机入口键，由叶子取走，不交给协议。`socks5Port` 和 `httpProxyPort` 默认 1080 和 8080，取值 1025 到 65535，两者不能相同。`socks5ListenLAN` 和 `httpProxyListenLAN` 为 `true` 时绑定局域网地址，默认只绑定 `127.0.0.1`。其余键交给协议，协议自己拒绝它不认识的键或值。文档、本机入口键和协议在打开上游时能检查的设置，都在绑定端口之前检查。错误信息不输出配置原文。

LAN 开关为真时，枚举实际接口上的 IPv4 私网和链路本地地址，以及 IPv6 ULA 和链路本地地址，逐一绑定。IPv6 设置 `IPV6_V6ONLY`，链路本地地址携带接口作用域。没有合适地址时拒绝，不扩大到公网 wildcard。所有端口成功绑定后才开始接入，失败时释放先前绑定的端口。`Proxy::start(upstream, &LocalEntry)` 返回的句柄提供 `socks5_addrs()`、`http_addrs()`、`wait()` 和 `close()`；释放句柄会停止监听并等待受控任务。

SOCKS5 包含 `CONNECT` 和 `UDP ASSOCIATE`，只接受无认证方法。UDP 关联受 TCP 控制连接的生命周期约束，验证请求声明的地址和实际来源，端口为 0 时固定第一个合法 UDP 来源。拒绝分片注入，回复写出协议给的来源地址。HTTP 代理接受普通请求和 `CONNECT`。普通 HTTP 按每个请求的目标打开一条流，支持 Content-Length、chunked 和同一本机连接上的跨目标请求。CONNECT 保留预读的隧道数据。头部、行长度和消息边界有上限，冲突的长度、非法地址和不支持的升级或期望明确拒绝。本机 TCP 读到 EOF 后保留反向响应，直到对端关闭、取消或 300 秒空闲。

## 引擎和协议是两个 crate

`crates/wg` 是以后唯一的 WireGuard 实现。`protocols/wireguard` 是可选的入站和客户端协议，将来依赖 `kerlico-wg`。`crates/outbound` 也会依赖 `kerlico-wg`，因为服务端默认带 WARP。只编客户端、且不编 WireGuard 协议时，不要依赖 `kerlico-wg`。
