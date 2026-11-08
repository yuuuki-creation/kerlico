# Kerlico

Do not read or use git branch `old`. The branch and everything on it are out of bounds.

不要读、不要用 `old` 分支。设计以本文件点名的文档为准。代码和文档不一致时，先改代码去跟上文档，不要把文档改回旧代码。出口的默认规则以 `docs/reference/server.md` 为准。

## 先读拥有这块的文档

改编译、crate 或协议目录之前，读 `docs/reference/crates.md`。

改服务端入站、出站、用户或计数之前，读 `docs/reference/server.md`。

改 mieru 的帧、握手或两端入口之前，读 `docs/reference/mieru.md`。

要解释为什么是这个形状，读 `docs/explanation/shape.md`。那篇不写操作步骤。

要上测试机，读 `docs/reference/workers.md`。连接资料在 `.private/machines/`，不要写进 git。

## 改动的规则

设计变了，就在同一次改动里更新拥有它的那一篇。不要另写一篇架构说明。

实现可以使用 crates.io 上的 Rust 包。语言保持 Rust。

一个行为只留一条路径。协议 crate 负责入站握手，并交出 `Handoff`。拨号只放在 `crates/outbound`。分流规则只挂在节点上，命中结果是 `OutboundChoice`。规则集与 Xray 的域名规则、`geosite.dat` 和 `geoip.dat` 使用同一套写法。不要按网址路径匹配，不要做一份全局路由表，也不要做 `outboundTag`。DNS、嗅探和 FakeDNS 属于服务端。落地用的客户端协议只通过服务端叶子上的 `landing-<id>` 依赖引进来。

WireGuard 引擎只放在 `crates/wg`，包名 `kerlico-wg`。不要把引擎写进 `protocols/wireguard`，也不要写进 `crates/outbound`。

服务端默认带上轻量 WARP。WARP 用这份 Rust 引擎，只给出站模块用。不要把整台机器的默认路由交给它。

增加协议时，按 `docs/reference/crates.md` 的目录和那一行依赖来加。`kerlico-manifest` 会对不上的清单让构建失败。不要再写一份协议名单。

## 验证

客户端只编 WireGuard。

```text
cargo build -p kerlico-client --no-default-features --features wireguard
```

服务端只编 OpenVPN。这是另一条命令。

```text
cargo build -p kerlico-server --no-default-features --features openvpn
```

两条命令的依赖图必须各自不含另一端的协议 crate。同一次命令同时构建两个叶子，并且使用同名 feature 时，两个叶子都会打开这个 feature。
