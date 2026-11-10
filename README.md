# Kerlico

当前 mieru 的客户端代理、服务端和落地接口已实现。配置、API 和本轮验收范围见 [mieru](docs/reference/mieru.md)。客户端本机代理入口为 `kerlico-client --mieru-proxy <配置文件>`，需要启用 `mieru` feature。

## 归档边界

既有代码与文档已全部移到分支 `old`，包括移动前工作区里尚未提交的改动。

分支 `old` 及其全部内容永不参考、永不使用。

## 内核布局

代理先读 `AGENTS.md`。编译和协议目录在 `docs/reference/crates.md`。服务端入站和出站在 `docs/reference/server.md`。mieru 在 `docs/reference/mieru.md`。取舍在 `docs/explanation/shape.md`。

```text
cargo build -p kerlico-client --no-default-features --features wireguard
cargo build -p kerlico-server --no-default-features --features openvpn
```
