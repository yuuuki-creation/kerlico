# kerlico

[English](README.en.md)

`kerlico` 是使用 Rust 开发的客户端与服务端一体代理内核，参考 mihomo、sing-box 与 Xray-core 设计，编译为单一可执行程序。

当前已发布 **[1.0.0 源码版](docs/releases/1.0.0.md)**，下一版本和完成计划见 [STATUS.md](STATUS.md)。

## 核心特性与当前范围

- **双端一体与模块化协议**：包含 23 个独立协议 crate（VLESS、VMess、Trojan、Shadowsocks、SS2022、SSR、AnyTLS、ShadowTLS、Snell、TUIC、Hysteria v1、Hysteria2、ShadowQUIC、Mieru、Naive、TrustTunnel、Sudoku、SOCKS、HTTP、SSH、Gost Relay、Tor、WireGuard），支持通过 Cargo features 按需编译。
- **独立节点与全局共享出站**：IPv4 与 IPv6 节点独立监听与鉴权，共用同一个出站调度器（`EgressRuntime`）。本地出网按节点 `ipv4-only`、`ipv6-only` 或 `dual-stack`（默认 IPv4 优先）选择目标地址；远端代理分流保留原始域名/IP 与端口透传。
- **多用户账户与业务计量**：管理账户（`AccountSpec`）与协议原生凭据（`native_credential`）映射分离，提供唯一业务流量计量、内存态会话记录（`Telemetry`）、可选 SQLite 用量/带宽/访问历史与只读 `history` 查询。
- **显式双语接口**：CLI 帮助、参数错误和运行诊断支持 `--lang zh-CN` / `--lang en`；模块标识与 JSON 字段保持稳定，见[语言接口](docs/interfaces/localization.md)。
- **待完成能力**：CF WARP 的 CLI 接入、规则路由、`dns`/`tun`/`control` 模块、DNS 与错误事件历史、完整双语使用文档，以及 6 个隧道/覆盖网络端点。

## 快速开始（配置 v2）

构建基线为 **Rust 1.99.1（Linux x86_64）**：

```sh
cargo build --locked --release -p kerlico
cargo run --locked -p kerlico -- modules
cargo run --locked -p kerlico -- check -c examples/config-v2-minimal.json
```

- 当前源码使用 **配置版本 2（JSON v2）**，旧版 v1 配置迁移说明见 [配置 v2 迁移指南](docs/config-v2-migration.md) 与 [配置接口](docs/interfaces/config.md)。
- 仓库内的示例配置均使用合成占位值；实际运行凭证请保存在被 Git 忽略的本地私有目录，通过 `kerlico run -c <path>` 加载。

## 许可证与匿名约定

自有代码采用 [GPL-3.0-only](LICENSE)，第三方依赖与内置补丁保留各自原许可（见 [许可说明](docs/licensing.md)）。项目提交固定使用匿名身份，规则见 [匿名提交约定](docs/anonymity.md)。

## 文档导航

| 入口 | 内容 |
| --- | --- |
| [项目状态 (STATUS.md)](STATUS.md) | 实时进度、测试结果汇总与待完成项 |
| [1.0.0 发行说明](docs/releases/1.0.0.md) | 1.0.0 源码版范围与已知边界 |
| [架构设计导航](docs/README.md) | 总体结构、核心契约、数据路径、生命周期与协议插拔 |
| [节点与共享出站设计](docs/node-egress.md) | 全局调度器、节点地址族模式、共享 WARP 与远端透传设计 |
| [多用户、流量与带宽设计](docs/statistics-and-users.md) | 账户模型、唯一计量边界、带宽采样与访问记录设计 |
| [实现接口文档](docs/interfaces/README.md) | 核心 API、JSON v2 配置及各协议模块的实际契约 |
| [协议与组合支持总表](reference/reports/三核心%20协议%20组合支持.md) | 三参考核心支持范围、组合限制与任务清单 |
| [参考项目调研](reference/README.md) | mihomo、sing-box、Xray-core 固定源码调研与借鉴映射 |
| [协作约定 (AGENTS.md)](AGENTS.md) | 开发工作流、匿名规则与测试环境约束 |
