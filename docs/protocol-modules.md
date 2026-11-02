# 协议模块与插拔规划

更新日期：2026-11-02（Asia/Shanghai）

本文说明协议模块的独立 package 组织、工厂注册、Cargo features 编译裁剪以及新增/移除协议的工程边界。

- 协议范围与组合清单：[三核心协议与组合总表](../reference/reports/三核心%20协议%20组合支持.md)
- 开发流程约定：[协议开发阶段与工作流](protocol-roadmap.md) 及 [0007](decisions/0007-protocol-development-cycle.md)
- 当前已实现的 23 个协议契约：[实现接口目录](interfaces/README.md)

## 一个协议一个独立 Crate

每个协议在 `crates/protocol-<name>` 下作为独立库 package 维护，内部包含该协议的配置解码、握手鉴权、报文编解码、客户端出站（`OutboundFactory`）与服务端入站（`NodeFactory`）：

```text
crates/protocol-<name>/
├── Cargo.toml
├── src/
│   ├── lib.rs          # 导出 Factory 与必要的公共类型，隐藏内部实现细节
│   ├── config.rs       # 协议专属 options 与 native_credential 解码校验
│   ├── inbound.rs      # (按需) 服务端节点监听/鉴别，通过 PeerSession 访问 Dispatcher
│   ├── outbound.rs     # (按需) 客户端出站连接，实现 Outbound trait
│   └── codec.rs        # (按需) 协议帧、地址编码与加密封装
└── tests/              # 协议包级单元/集成与回归测试
```

- **角色按需实现**：支持双端的协议同时导出 `OutboundFactory` 与 `NodeFactory`；仅支持出站的协议（如 `protocol-ssh`、`protocol-gost-relay`、`protocol-tor`）只导出 `OutboundFactory`。
- **公共能力复用**：通用 Socket 拨号与基础 TLS 辅助由 `kerlico-net` 提供；协议特有的握手、混淆、QUIC/H3 封装或用户态栈留在协议 crate 内部。

## 协议与核心的交互契约

| 接口 | 协议模块职责 | 核心保障 |
| --- | --- | --- |
| `OutboundFactory::compile` | 校验协议 `options`，声明 `Capabilities` 与 `TargetPolicy`（应用层代理为 `Remote`，IP 隧道为 `Local`），返回一次性启动闭包 `OutboundPlan` | 每个命名出站在 `Engine::bind` 时仅启动一次，由 `Dispatcher` 全局持有 |
| `NodeFactory::build` | 校验节点 `options` 与各成员 `native_credential`，声明 `CredentialManifest`（分离认证秘密与外层保护秘密） | 编译期拦截跨节点秘密复用，为节点分配独立 `CredentialIssuer` |
| 入站鉴别与请求提交 | 完成真实协议线格式验证后调用 `IngressBinding::authenticated` 获取 `PeerSession`，再调用 `connect_tcp` / `connect_udp` / `associate_udp` | 鉴权前禁止拨号；所有业务流统一经过 `Dispatcher` 进行选路与唯一业务计量 |
| 后台任务管理 | 出站后台任务登记至 `ServiceContext`，入站节点派生任务登记至 `InboundContext.tasks`（`NodeTasks`） | 关闭时按固定截止时间执行协作排空、强制中止与确定性 `join` |

## 显式注册与 Cargo Features 裁剪

`apps/kerlico` 通过 Cargo features（如 `protocol-vless`、`protocol-trojan`、`protocol-wireguard` 等，详见 [apps/kerlico/Cargo.toml](../apps/kerlico/Cargo.toml)）控制参与编译的协议 crate，并在 [`apps/kerlico/src/main.rs`](../apps/kerlico/src/main.rs) 的 `registry()` 中显式注册：

| 构建与配置状态 | 运行时行为 |
| --- | --- |
| Feature 未启用（未编入二进制） | `kerlico modules` 不列出该类型；配置文件引用该类型时明确报错拒绝 |
| Feature 已启用，但配置未引用 | 工厂已注册，但不构造运行实例、不分配监听或后台线程 |
| Feature 已启用，且配置校验通过 | 编译计划并构造对应命名出站或入站节点实例 |

## 新增与移除协议的改动范围

- **新增协议**：
  1. 新建 `crates/protocol-<name>`，实现协议编解码、工厂与包级测试；
  2. 在根 `Cargo.toml` 与 `apps/kerlico/Cargo.toml` 添加依赖与 `protocol-<name>` feature；
  3. 在 `apps/kerlico/src/main.rs` 注册工厂，并同步编写 `docs/interfaces/<name>.md` 与 `docs/testing/<name>.md`。
  - 核心 `kerlico-engine` 与 `kerlico-egress` 无需按新协议名称增加分支。
- **裁剪或移除协议**：关闭对应 Cargo feature 或从 `apps/kerlico` 移除注册与可选依赖；若有配置引用被移除的协议，在 `Registry::prepare` 阶段即被拦截。

## 关联文档与借鉴依据

- **细化文档**：[总体结构](architecture.md) · [核心契约](core-contracts.md) · [配置与命令行接口](interfaces/config.md)
- **上游借鉴**：关联 [借鉴映射](../reference/design-map.md) 的 `REF-003`（显式装配与注册）与 `REF-005`（协议与传输能力分层）。
