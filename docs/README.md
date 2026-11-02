# 架构设计导航

更新日期：2026-11-02（Asia/Shanghai）

本目录维护 `kerlico` 的目标架构、模块契约、数据路径与设计决策。当前源码的实际公开接口与配置契约见 [实现接口](interfaces/README.md)，实时开发与测试进度见根 [STATUS.md](../STATUS.md)。

## 阅读顺序

| 文档 | 内容范围 |
| --- | --- |
| [使用指南](usage.md) | 安装、命令、客户端与服务端配置、路由、WARP 与统计 |
| [实现接口](interfaces/README.md) | 当前核心 API、JSON v2 配置、各协议模块与 CLI 的实际契约 |
| [总体结构](architecture.md) | 单可执行文件交付、Cargo workspace 划分与编译依赖关系 |
| [双端与统一目标访问](node-egress.md) | 全局共享调度器、多远端出站、节点地址族模式、设备共享 WARP 与远端透传 |
| [多用户、流量与带宽](statistics-and-users.md) | 管理账户与协议凭据分离、唯一业务计量、带宽采样、在线状态与访问记录持久化设计 |
| [核心契约](core-contracts.md) | 跨模块标识、分阶段会话元数据、工厂注册与能力约束 |
| [数据路径](data-paths.md) | TCP、UDP、TUN 与 DNS 的阶段协作、首包嗅探与半关闭语义 |
| [运行与配置生命周期](runtime-lifecycle.md) | 启动阶段、配置代次、资源租约（lease）、在线更新分级与排空退出 |
| [协议模块与插拔](protocol-modules.md) | 协议 crate 内部结构、显式注册、Cargo feature 裁剪与扩展示范 |
| [协议阶段与路线](protocol-roadmap.md) | 框架范围与“调研 → 编写 → 测试 → 修改”开发工作流 |
| [协议与组合总表](../reference/reports/三核心%20协议%20组合支持.md) | mihomo、sing-box、Xray-core 协议与组合支持对照及任务编号 |
| [编译与测试安排](build-and-test.md) | 三台专用海外 worker 分工、本地私有凭证隔离与测试约束 |
| [强制匿名规则](anonymity.md) | Git 匿名作者身份、内容脱敏要求与提交/推送校验钩子 |
| [项目许可说明](licensing.md) | `GPL-3.0-only` 许可范围与第三方材料合规要求 |
| [文档与资料约定](repository-workflow.md) | `docs/`、`STATUS.md`、`decisions/` 与 `reference/` 的维护边界 |
| [决策目录](decisions/README.md) | 重要架构与流程决策的背景、取舍与确认状态 |
| [上游调研](../reference/README.md) | 三个参考核心的固定源码基线、研究笔记与[借鉴映射](../reference/design-map.md) |

## 阅读约定

- **目标设计与当前实现区分**：`docs/*.md` 描述完整目标架构；已落地的 Rust 类型、配置字段与已验证边界以 [interfaces/](interfaces/README.md) 和 [STATUS.md](../STATUS.md) 为准。
- **契约术语**：文中的英文类型或服务名用于表达架构职责边界，具体代码签名见 `crates/core-api`、`crates/config`、`crates/egress` 与 `crates/engine`。
