# Kerlico

客户端本机 SOCKS5/HTTP 入口为 `kerlico-client <配置文件>`，按配置运行 [mieru](docs/reference/mieru.md)、[VLESS](docs/reference/vless.md)、[AnyTLS](docs/reference/anytls.md) 或 [Hysteria 2](docs/reference/hy2.md)。客户端和服务端入站需要启用对应协议的 feature，服务端落地使用 `landing-<id>`。mieru 仍可用 `kerlico-client --mieru-proxy <配置文件>`。入口和编译规则见 [编译单元](docs/reference/crates.md)。

## 归档边界

既有代码与文档已全部移到分支 `old`，包括移动前工作区里尚未提交的改动。

分支 `old` 及其全部内容永不参考、永不使用。

## 内核布局

代理先读 `AGENTS.md`。编译和协议目录在 `docs/reference/crates.md`。服务端入站和出站在 `docs/reference/server.md`。mieru 在 `docs/reference/mieru.md`。取舍在 `docs/explanation/shape.md`。

```text
cargo build -p kerlico-client --no-default-features --features wireguard
cargo build -p kerlico-server --no-default-features --features openvpn
```
