# 1.0.0 发行范围与质量门槛

更新日期：2026-11-02（Asia/Shanghai）

按“先发布源码、再执行海外整树构建与验证”的推进顺序，`v1.0.0` 源码版已先行发布（见 [1.0.0 发行说明](releases/1.0.0.md)）。本文记录 `1.0.0` 系列完整交付的质量验收门槛，作为发布后持续验证与补丁版本（`1.0.x`）收尾的标准。

## 协议与架构范围

1. **协议模块（23 个）**：
   - 双端协议（20 个）：VLESS、AnyTLS、SS2022、SOCKS、HTTP、Shadowsocks (AEAD/legacy)、Trojan、VMess、Snell、TUIC、Hysteria v1、Hysteria2、ShadowQUIC、Mieru、Naive、ShadowsocksR、ShadowTLS、TrustTunnel、Sudoku、WireGuard。
   - 仅出站协议（3 个）：SSH、Gost Relay、Tor。
   - 各协议具体支持的版本、传输组合与数据边界以 [协议总表](../reference/reports/三核心%20协议%20组合支持.md) 及 `docs/interfaces/` 为准。
2. **核心架构能力**：
   - 全局唯一共享出站调度器（`EgressRuntime` / `Dispatcher`），支持多命名远端出站；
   - 节点地址族模式（`ipv4-only` / `ipv6-only` / `dual-stack` 默认 IPv4 优先）、双栈缺族设备共享 CF WARP 自动补齐，以及远端代理原目标透传（[0009](decisions/0009-global-egress-dispatcher.md)、[0010](decisions/0010-node-egress-modes-and-warp.md)）；
   - 单节点多用户管理账户、唯一业务流量计量、采样带宽历史与访问记录持久化（[0011](decisions/0011-users-statistics-and-access-records.md)）。

## 完整交付验收门槛

| 验收维度 | 要求与标准 |
| --- | --- |
| 协议模块验证 | 每个模块完成包级测试、真实参考对端互通、异常报文/鉴权失败负例、包长/EOF 边界与资源回收测试；明确区分参考对端自身限制与本实现缺陷 |
| 公共 API 与文档一致 | `core-api`、`config`、`egress`、`engine` 的公开签名、Rustdoc、错误/取消契约与 `docs/interfaces/` 完全一致 |
| 配置与 CLI | JSON v2 校验、未知/非法配置拒绝、Cargo feature 裁剪行为、`modules`/`check`/`run`/`account-new` 命令与中英双语提示验证通过 |
| 整树构建与检查 | 同一源码快照在专用海外 worker（Linux `x86_64` / Rust `1.99.1`）通过全工作区测试、严格 Clippy、`cargo fmt --check`、Rustdoc、功能裁剪构建与多节点并发联合运行 |
| 许可证与源码合规 | 完成 `GPL-3.0-only` 声明及全部实际链接依赖的第三方许可证/署名通知核对（见 [许可说明](licensing.md)） |
| 匿名与隐私检查 | 通过 `.githooks/privacy-check` 完整历史与产物检查，确保无个人身份信息、主机路径或 `.private/` 凭证泄露 |
| 正式构建产物 | 上传与对应 Git 标签源码严格匹配的 Release 二进制及 SHA-256 校验摘要，完成启动冒烟与优雅退出验证 |
