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

现在的协议目录是 `wireguard`、`openvpn` 和 `mieru`。WireGuard 和 OpenVPN 的协议体是 `unimplemented!`。mieru 的决定在 `docs/reference/mieru.md`。

mieru 的本机代理从 `kerlico-client --mieru-proxy <配置文件>` 启动，需要 `mieru` feature。监听、设置与生命周期由 mieru 客户端 crate 拥有；该专用操作入口不增加另一份协议菜单，也不改变其他协议的注册签名。

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

服务端叶子上的 `landing-<id>` 依赖指向该协议的客户端 crate，并且不进入入站菜单。出站模块调用该 crate 的 `land`。见 `docs/reference/server.md`。

## 引擎和协议是两个 crate

`crates/wg` 是以后唯一的 WireGuard 实现。`protocols/wireguard` 是可选的入站和客户端协议，将来依赖 `kerlico-wg`。`crates/outbound` 也会依赖 `kerlico-wg`，因为服务端默认带 WARP。只编客户端、且不编 WireGuard 协议时，不要依赖 `kerlico-wg`。
