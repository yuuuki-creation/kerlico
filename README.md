# 已归档

既有代码与文档已全部移到分支 `old`，包括移动前工作区里尚未提交的改动。

分支 `old` 及其全部内容永不参考、永不使用。

## English

The previous code and documentation are on branch `old`, including uncommitted work from the working tree at the time of the move.

Branch `old` and everything on it must never be referenced or used.

## 内核布局

代理先读 `AGENTS.md`。编译和协议目录在 `docs/reference/crates.md`。服务端入站和出站在 `docs/reference/server.md`。mieru 在 `docs/reference/mieru.md`。取舍在 `docs/explanation/shape.md`。

```text
cargo build -p kerlico-client --no-default-features --features wireguard
cargo build -p kerlico-server --no-default-features --features openvpn
```
