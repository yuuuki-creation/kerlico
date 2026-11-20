# Kerlico

客户端本机 SOCKS5/HTTP 入口为 `kerlico-client <配置文件>`，按配置运行 [mieru](docs/reference/mieru.md)、[VLESS](docs/reference/vless.md)、[AnyTLS](docs/reference/anytls.md)、[Hysteria 2](docs/reference/hy2.md)、[Shadowsocks 2022](docs/reference/ss2022.md) 或 [SOCKS5](docs/reference/socks.md)。[WireGuard](docs/reference/wireguard.md) 客户端使用数据包 API 或 `kerlico-client --tun <接口名> <配置文件>`。客户端和服务端入站启用对应协议的 feature，服务端落地使用 `landing-<id>`。入口和编译规则见 [编译单元](docs/reference/crates.md)。

## 归档边界

既有代码与文档已全部移到分支 `old`，包括移动前工作区里尚未提交的改动。

分支 `old` 及其全部内容永不参考、永不使用。

## 内核布局

代理先读 `AGENTS.md`。编译和协议目录在 `docs/reference/crates.md`。服务端入站和出站在 `docs/reference/server.md`。mieru 在 `docs/reference/mieru.md`。取舍在 `docs/explanation/shape.md`。

```text
cargo build -p kerlico-client --no-default-features --features wireguard
cargo build -p kerlico-server --no-default-features --features openvpn
```
