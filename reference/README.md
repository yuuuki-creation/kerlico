# VPN 内核参考调研

本目录记录 mihomo、sing-box、Xray-core 的官方文档与源码调研，用于讨论未来 Rust VPN 内核的需求和设计。**当前仍处于讨论与仓库结构维护阶段，调研结论不代表已经选定架构，也不授权开始实现。**

调研日期：**2026-10-30，Asia/Shanghai**。本轮只做静态源码和文档阅读，未构建或运行上游核心，未进行互通、性能或系统 VPN 实机测试。

## 阅读入口

| 材料 | 内容 |
| --- | --- |
| [三核心协议与组合总表](reports/三核心%20协议%20组合支持.md) | 协议范围、角色、传输/安全/flow/UDP 限制与后续稳定任务编号；唯一主清单 |
| [借鉴到本项目的映射](design-map.md) | 上游固定源码 → 本项目设计草案 → 待验证行为 |
| [横向调研报告](reports/Rust%20VPN%20内核参考调研.md) | 架构对照、共同数据路径、Rust 设计候选问题与阅读顺序 |
| [mihomo 独立记录](research_notes/Rust%20VPN%20内核参考调研/mihomo.md) | 元数据、TCP/UDP 调度、策略组/provider、DNS、TUN、配置应用与 API |
| [sing-box 独立记录](research_notes/Rust%20VPN%20内核参考调研/sing-box.md) | 注册与生命周期、路由动作、DNS 演进、TUN/宿主边界、配置与控制接口 |
| [Xray-core 独立记录](research_notes/Rust%20VPN%20内核参考调研/xray.md) | Feature/Dispatcher、协议与传输分层、会话目标、原生 TUN、动态 API |

## 本轮固定基线

以下版本是本次核验的正式发行快照，不保证滚动的 latest/default branch 链接以后仍返回相同内容。完整核验过程与来源见独立记录。

| 项目 | 发行标签 | 固定源码 SHA | 同一快照的许可证观察 |
| --- | --- | --- | --- |
| mihomo | [v1.19.33](https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.33) | `3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8` | [LICENSE](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/LICENSE) 为 GPL v3 文本；README 标 GPL-3.0，另有下游命名声明。仅针对该 Go 快照，来源异常见下文 |
| sing-box | [v1.14.4](https://github.com/SagerNet/sing-box/releases/tag/v1.14.4) | `c005f35300ce76427dc285481ec5695f5b179cd2` | [LICENSE](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/LICENSE) 含 GPL v3-or-later 文字及名称/关联限制；本次 GitHub SPDX 元数据为 `NOASSERTION`，不能省略附加文字 |
| Xray-core | [v26.10.29](https://github.com/XTLS/Xray-core/releases/tag/v26.10.29) | `0afec66085a85191e9dd2a4a6646c7c9a94688d1` | 根 [LICENSE](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/LICENSE) 为 MPL-2.0；未审计全部子目录与依赖 |

**来源边界：**本次 mihomo 首页、repo 元数据和默认 HEAD 返回 Python/Pydantic 同名项目信息，`main`/HEAD 为 `008b91bfe8c0e2daca0ab69061efd9ea1ad71bd2`；稳定 tag 与 `Meta` 返回上述 Go 内核快照。本轮没有解释该不一致的原因，架构和许可证判断均取固定 tag。sing-box 在线文档已包含 1.15 内容，本轮以 1.14.4 标签内源码和文档为主。Xray 滚动 TUN 文档与固定源码的 FreeBSD 自动路由描述存在差异。详见各独立记录，不能将这些来源混为同一版本。

## 后续维护约定

本目录保存上游证据与分析；本项目自己的设计放在 [docs](../docs/README.md)，项目进度放在 [STATUS.md](../STATUS.md)。具体维护方式见[文档与资料约定](../docs/repository-workflow.md)。

用户已按[0002 当前流程](../docs/decisions/0002-support-catalog-before-implementation.md)明确要求先集中形成支持总表；随后框架先行、逐项实现，开工前仍补齐具体规范/依赖与验证研究。原有整体架构记录保留，总表和新证据不覆盖历史报告。

更新资料时记录日期、发行标签和完整提交号；代码引用固定到 SHA，并单独标注滚动文档的版本与访问边界。保留来源不一致和未验证项，清楚区分**源码事实、研究推论、待决问题**。

“源码存在”“默认构建包含”“目标平台可用”“已实机验证”分别记录。协议清单不构成互通承诺，CI 定义不等于全部测试通过，控制 API 不等于无损配置热重载。本轮也未对三个项目进行性能排名。

继续遵守根目录 [AGENTS.md](../AGENTS.md)：用户明确要求开始实现之前，只维护讨论材料与仓库结构；不创建实现、测试、开发脚本或 Cargo 骨架。
