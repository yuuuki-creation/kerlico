# 协议开发阶段与工作流

更新日期：2026-11-04（Asia/Shanghai）

本文维护协议与核心能力开发的阶段划分与标准工作流。各协议的具体支持范围、组合限制与任务编号维护在 [三核心协议与组合总表](../reference/reports/三核心%20协议%20组合支持.md) 与 [能力总表](capability-matrix/README.md)，当前完成度、排期与测试状态见根 [STATUS.md](../STATUS.md)。

## 协议与能力开发固定工作流

遵循 [0002](decisions/0002-support-catalog-before-implementation.md) 与 [0007](decisions/0007-protocol-development-cycle.md)，每个协议或能力模块固定按以下四步推进：

1. **调研（Research）**：对照总表稳定编号与 `docs/capability-matrix/` 规范键，核实协议固定版本、规范、支持角色（客户端出站 / 服务端节点）、传输与安全组合、数据能力（TCP / 固定 UDP / 多目标关联 / TCP EOF）、依赖许可证及参考对端。
2. **完整首轮编写（Implementation）**：一次性完成本轮确认范围的全部代码、工厂注册、`docs/interfaces/` 接口文档与 `docs/capability-matrix/annotations/*.jsonl` 现状标注，不采用“先写最小子集立即构建测试”的碎片化方式。
3. **远端测试（Verification）**：在专用海外 worker 运行包级测试、严格 Clippy 和一次真实对端互通（见 [0012](decisions/0012-simplified-delivery-and-verification.md)），并将实测结论写入 `docs/capability-matrix/results/*.jsonl`，运行 `python3 tools/capability_matrix.py build` 与 `check --strict`。
4. **修改（Refinement）**：集中修复，复跑受影响 crate；与参考端的差异写进接口文档。

## 阶段划分与总表映射

| 阶段 | 交付范围 | 总表编号 / 矩阵范围 | 当前进度 |
| --- | --- | --- | --- |
| 1. 支持目录调研 | 核验 mihomo、sing-box、Xray-core 的协议能力与组合边界，生成 4,360 项能力总表 | `P` / `E` / `A` / `D` / `V`；`docs/capability-matrix/` | 已完成 |
| 2. F0 核心框架与共享出站 | 装配入口、流/包契约、凭据隔离、全局共享 `Dispatcher`、多用户账本与优雅排空 | `K-F0` | 已实现 |
| 3. 本地接入协议 | 本地固定转发、SOCKS 4/4a/5 双端与 HTTP 代理双端 | `K-L` 系列 | 已完成并验证 |
| 4. 主力代理协议 | VLESS、VMess、Trojan、Shadowsocks、SS2022、SSR、AnyTLS、ShadowTLS、Snell、TUIC、Hysteria v1/v2、ShadowQUIC、Mieru、Naive、TrustTunnel、Sudoku、SSH、Gost Relay | `K-S` / `K-T` / `K-V` / `K-R` / `K-A` 系列 | 19 个协议模块已合入 |
| 5. 匿名网络与 IP 隧道端点 | Tor（TCP 出站）、WireGuard（原生双端）、OpenVPN、OpenConnect、EasyTier、Tailscale、ZeroTier、MASQUE | `K-E` / `K-B` 系列 | 已合入 |
| 6. M0 基线回填与底盘修障 | 回填 1,105 项已实现/部分实现实测记录；修复 QUIC 空载关闭、VLESS 出站多目标 UDP、WireGuard 瞬时容错、EasyTier UDP、smoltcp 丢包恢复 | `results/*.jsonl`；`v1.3.3` | 待开始 |
| 7. M1 入站/出站角色与协议细项对齐 | `mixed`、`redirect`、`tproxy` 入站，入站 `fallback` 分流，MASQUE/OpenVPN 服务端入站，`vless-reverse`，`dns`/`loopback`/`rematch` 内部出站，SS2022 Relay 与 SS SIP003 插件 | `inbound`、`outbound`（`v1.4.0`） | 规划中 |
| 8. M2 传输、安全、多路复用与拨号对齐 | `dialer-proxy`/`detour` 链式拨号，`sing-mux`（`h2mux`/`smux`/`yamux`），`UoT` v1/v2，mKCP 与 V2Ray H2/QUIC 传输，Xray `finalmask`，ECH 双端，TLS 分片/伪装，内置 ACME 自动证书 | `transport`、`security`、`cert`、`mux`、`udp`、`dialer`（`v1.5.0`） | 规划中 |
| 9. M3 流量感知、DNS、路由规则集与 TUN 自动化 | TLS/HTTP/QUIC/BT 嗅探，Fake-IP 双栈池与持久化还原，DoH/DoQ、乐观缓存、ECS 与 DNS 规则动作，`rule-set`（`srs`/`mrs`/`dat`）与逻辑/进程规则，TUN `auto-route`/`auto-redirect` | `sniff`、`dns`、`route`、`ruleset`、`tun`、`cache`（`v1.6.0`） | 规划中 |
| 10. M4 策略组、订阅提供者、控制面 API 与 CLI 工具链 | `select`/`url-test`/`fallback`/`load-balance`/`observatory` 策略组，`proxy-providers` 订阅解析与覆写，完整 Clash RESTful/WS API 与外部面板，规则转换/密钥生成 CLI，内置 `ntp` | `group`、`provider`、`api`、`cli`、`config`、`ntp`（`v1.7.0`） | 规划中 |

## 三核心能力对齐推进顺序

1. **先做 M0（实测回填与底盘修障）**：消除总表中 1,105 项已实现或部分实现能力的“未测”统计缺口，同时收口 `v1.3.2` 已知的协议栈与关闭生命周期问题。
2. **并行推进 M1 与 M2 底座**：`M2` 的链式拨号（`dialer-proxy`/`detour`）、通用多路复用（`sing-mux`）和 `UoT` 是 `M1` 出站组合的底层依赖；`M1` 的 `mixed`、`redirect`、`tproxy` 入站是 `M3` 透明代理与嗅探的入口。
3. **打通 M3 数据面闭环**：在 `M1` 入站管线之上接入协议嗅探（`sniff`）与 Fake-IP（`dns` + `cache`），再合入外部规则集（`ruleset`）和 TUN 自动路由/自动重定向（`auto-route`/`auto-redirect`）。
4. **收口 M4 编排与控制面**：在全局共享 `Dispatcher` 的命名出站表上层构建策略组（`group`）与订阅提供者（`provider`），并通过完整 Clash API（`api`）对外提供状态查询、延迟测速、节点切换与热重载。

## 开工前核对清单

| 检查项 | 必查内容 |
| --- | --- |
| 协议与角色边界 | 明确协议版本、入站/出站角色、原始目标透传（`Remote`）或本地选路（`Local`）策略 |
| 传输、安全与复用 | 允许的传输载体、TLS/REALITY/ECH/混淆组合、流复用与 UDP 封装格式 |
| 凭据与多用户隔离 | 原生认证材料结构（`native_credential`）、`CredentialManifest` 认证域与保护域划分 |
| 异常与生命周期验证 | 鉴权失败、畸形报文、连接/空闲超时、请求/节点取消、半关闭（EOF）与后台任务回收 |
| 能力总表同步 | 对应 `docs/capability-matrix/annotations/*.jsonl` 键值更新、`results/*.jsonl` 实测证据登记与 `tools/capability_matrix.py check --strict` 校验 |
