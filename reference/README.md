# VPN 内核参考调研

更新日期：2026-11-02（Asia/Shanghai）

本目录保存 mihomo、sing-box 与 Xray-core 的固定版本源码调研、协议支持对照与借鉴映射。`kerlico` 的自身架构设计见 [docs/README.md](../docs/README.md)，实时开发与验证进度见 [STATUS.md](../STATUS.md)。

## 阅读入口

| 材料 | 内容范围 |
| --- | --- |
| [三核心协议与组合总表](reports/三核心%20协议%20组合支持.md) | 三个参考核心的协议范围、角色、传输/安全/flow/UDP 边界与 `kerlico` 任务编号（唯一主清单） |
| [借鉴映射 (design-map.md)](design-map.md) | 上游固定源码证据 → `kerlico` 设计方案 → 验证目标映射 |
| [横向调研报告](reports/Rust%20VPN%20内核参考调研.md) | 三核心架构对照、数据路径共性与 Rust 建模分析 |
| [mihomo 独立调研](research_notes/Rust%20VPN%20内核参考调研/mihomo.md) | 元数据、TCP/UDP 调度、策略组/provider、DNS、TUN 与控制 API |
| [sing-box 独立调研](research_notes/Rust%20VPN%20内核参考调研/sing-box.md) | 组件注册与生命周期、路由动作、DNS、TUN/宿主边界与配置结构 |
| [Xray-core 独立调研](research_notes/Rust%20VPN%20内核参考调研/xray.md) | Feature/Dispatcher、协议与传输分层、会话目标、TUN 与动态 API |
| [Xray 统计与访问记录调研](research_notes/xray-statistics-and-access.md) | `v26.10.31` 固定源码的日志、流量、在线状态与查询边界对照 |
| [Tor 实现与依赖报告](reports/tor-implementation-20261102.md) | `arti-client 0.47.0` 嵌入边界、局部补丁与第三方许可证说明 |
| [各协议专项研究笔记](research_notes/) | VLESS、AnyTLS、SS2022、VMess、Trojan、Hy1/Hy2、TUIC、ShadowQUIC、Mieru、Naive、TrustTunnel、Sudoku、WireGuard 等固定源码研究 |

## 核心参考基线

| 参考项目 | 固定发行标签 | 固定源码 SHA | 根目录许可证观察 |
| --- | --- | --- | --- |
| mihomo | [v1.19.33](https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.33) | `3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8` | `LICENSE` 为 GPL-3.0 文本，附下游命名声明（详见独立记录） |
| sing-box | [v1.14.4](https://github.com/SagerNet/sing-box/releases/tag/v1.14.4) | `c005f35300ce76427dc285481ec5695f5b179cd2` | `LICENSE` 为 GPLv3-or-later 文本，附名称/关联附加条款 |
| Xray-core | [v26.10.29](https://github.com/XTLS/Xray-core/releases/tag/v26.10.29) | `0afec66085a85191e9dd2a4a6646c7c9a94688d1` | `LICENSE` 为 MPL-2.0 |

## 资料维护规则

- **固定版本追溯**：所有上游代码引用均绑定具体发行标签与完整 commit SHA，避免因上游 `main` 分支或在线文档滚动更新导致证据失效。
- **只读缓存隔离**：按需下载的上游源码缓存在 `reference/.upstream/<project>/<sha>/`，由 `.gitignore` 排除，不纳入版本控制或 Cargo 构建。
