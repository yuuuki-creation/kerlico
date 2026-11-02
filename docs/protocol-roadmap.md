# 协议开发阶段与工作流

更新日期：2026-11-02（Asia/Shanghai）

本文维护协议开发的阶段划分与标准工作流。各协议的具体支持范围、组合限制与任务编号统一维护在 [三核心协议与组合总表](../reference/reports/三核心%20协议%20组合支持.md)，当前完成度与测试状态见根 [STATUS.md](../STATUS.md)。

## 协议开发固定工作流

遵循 [0002](decisions/0002-support-catalog-before-implementation.md) 与 [0007](decisions/0007-protocol-development-cycle.md)，每个协议模块固定按以下四步推进：

1. **调研（Research）**：对照总表稳定编号，核实协议固定版本、规范、支持角色（客户端出站 / 服务端节点）、传输与安全组合、数据能力（TCP / 固定 UDP / 多目标关联 / TCP EOF）、依赖许可证及参考对端。
2. **完整首轮编写（Implementation）**：一次性完成本轮确认范围的全部协议代码、工厂注册与 `docs/interfaces/<protocol>.md` 接口文档，不采用“先写最小子集立即构建测试”的碎片化方式。
3. **远端测试（Verification）**：在专用海外 worker 运行包级测试、严格 Clippy 和一次真实对端互通（见 [0012](decisions/0012-simplified-delivery-and-verification.md)）。
4. **修改（Refinement）**：集中修复，复跑受影响 crate；与参考端的差异写进接口文档。

## 阶段划分与总表映射

| 阶段 | 交付范围 | 总表编号系列 | 当前进度 |
| --- | --- | --- | --- |
| 1. 支持目录调研 | 核验 mihomo、sing-box、Xray-core 的协议能力与组合边界 | `P` / `E` / `A` / `D` / `V` | 已完成 |
| 2. F0 核心框架与共享出站 | 装配入口、流/包契约、凭据隔离、全局共享 `Dispatcher`、多用户账本与优雅排空 | `K-F0` | 已实现 |
| 3. 本地接入协议 | 本地固定转发、SOCKS 4/4a/5 双端与 HTTP 代理双端 | `K-L` 系列 | 已完成并验证 |
| 4. 主力代理协议 | VLESS、VMess、Trojan、Shadowsocks、SS2022、SSR、AnyTLS、ShadowTLS、Snell、TUIC、Hysteria v1/v2、ShadowQUIC、Mieru、Naive、TrustTunnel、Sudoku、SSH、Gost Relay | `K-S` / `K-T` / `K-V` / `K-R` / `K-A` 系列 | 19 个协议模块已合入 |
| 5. 匿名网络与 IP 隧道端点 | Tor（TCP 出站）、WireGuard（原生双端），以及后续 OpenVPN、OpenConnect、EasyTier、Tailscale、ZeroTier、MASQUE | `K-E` / `K-B` 系列 | 已合入 |

## 开工前核对清单

| 检查项 | 必查内容 |
| --- | --- |
| 协议与角色边界 | 明确协议版本、入站/出站角色、原始目标透传（`Remote`）或本地选路（`Local`）策略 |
| 传输、安全与复用 | 允许的传输载体、TLS/REALITY/混淆组合、流复用与 UDP 封装格式 |
| 凭据与多用户隔离 | 原生认证材料结构（`native_credential`）、`CredentialManifest` 认证域与保护域划分 |
| 异常与生命周期验证 | 鉴权失败、畸形报文、连接/空闲超时、请求/节点取消、半关闭（EOF）与后台任务回收 |
