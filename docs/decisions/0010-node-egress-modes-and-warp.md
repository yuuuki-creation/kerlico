# 0010 节点出站模式、设备共享 WARP 与远端透传

- **状态**：已确认（`Local`/`Remote` 分支与节点三种模式已合入主工作树；`kerlico-device` 已由 CLI 按 `device` 配置接入）
- **日期**：2026-11-01（2026-11-02 更新状态）

## 背景与确认要求

用户明确以下出站目标策略规则，作为对 [0009](0009-global-egress-dispatcher.md) 全局共享调度器的补充：

1. **节点地址族模式**：部署节点时指定 `ipv4-only`、`ipv6-only` 或 `dual-stack`（默认 IPv4 优先），约束由本节点负责目标策略的本地出网路径。
2. **双栈缺族自动配备共享 WARP**：当双栈节点所在设备缺少某一原生出站地址族时，自动配备 Cloudflare WARP 补齐对应地址族；同一台设备统一管理一套 WARP 的 IPv4/IPv6 逻辑出口，由全局共享调度器统一调用，不为每个节点重复部署。
3. **远端分流原目标透传**：分流至远端代理的请求保留原始业务目标（域名或字面 IP）、端口与业务负载，由远端代理自行解析网站域名并执行目标策略；远端失败时按协议返回错误或结束会话，本节点不换地址族、不换代理、也不回退本地直连或 WARP 重试。

## 决定与责任边界

### 1. 区分 `TargetPolicy::Local` 与 `TargetPolicy::Remote`

共享 `Dispatcher` 在处理目标地址前先根据所选出站的 `TargetPolicy` 划分分支：

- **`TargetPolicy::Local`（本节点负责目标策略）**：包括本地直连（`direct`）、设备管理的 WARP 出口以及三层 IP 隧道（如 `wireguard`）。该分支按入站节点的 `mode` 解析目标域名并筛选地址族：
  - `ipv4-only`：仅使用 IPv4 目标候选与设备 IPv4 出口，拒绝字面 IPv6 目标；
  - `ipv6-only`：仅使用 IPv6 目标候选与设备 IPv6 出口，拒绝字面 IPv4 目标；
  - `dual-stack`：允许 IPv4 与 IPv6，默认 IPv4 候选优先。
- **`TargetPolicy::Remote`（远端代理负责目标策略）**：包括 VLESS、Trojan、VMess、Hysteria2、Tor 等应用层代理出站。该分支将原始域名/IP 与端口直接交由代理协议编码，本地网站 `Resolver` 调用次数为 0（代理服务器自身的端点地址仍由底层连接器独立解析拨号）。

### 2. 设备级共享出口能力

| 设备原生出网能力 | 双栈节点（`dual-stack`）使用的逻辑出口 |
| --- | --- |
| 原生 IPv4 与 IPv6 均可用 | `Native4` + `Native6` |
| 仅原生 IPv4 可用 | `Native4` + 自动补齐的设备共享 `Warp6` |
| 仅原生 IPv6 可用 | 自动补齐的设备共享 `Warp4` + `Native6` |

- **生命周期与纯校验边界**：设备级 WARP 的准备属于运行部署阶段，配置纯校验（`Registry::prepare` / `kerlico check`）不安装软件或修改系统网络；单个节点或单个 `Engine` 退出仅释放自身连接与租约，不关闭设备共用 WARP 服务。

## 落地状态

- **已实现**：配置 v2 节点 `mode` 字段（`ipv4-only` / `ipv6-only` / `dual-stack`）、`TargetPolicy::Local` 与 `TargetPolicy::Remote` 分流、本地多目标 UDP 关联解析缓存（上限 256 目标）及远端原目标透传（见 [节点与共享目标访问接口](../interfaces/node-egress.md)）。
- **待实现**：跨进程共享设备（有多进程部署需求时再做）。
