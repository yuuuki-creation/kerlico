# kerlico

[English](README.en.md)

当前版本目标为**1.0.0源码先行发布**。按用户最新要求先发布，再在海外worker继续构建和测试。本次版本号不表示整树已验收；首次发布不提供旧快照二进制，实际状态见[发行说明](docs/releases/1.0.0.md)。

使用Rust开发客户端与服务端一体的VPN内核，参考mihomo、sing-box和Xray-core。同一个程序承担两种角色，独立节点共用一个出站调度器，远端分流保留原目标。节点地址族与设备共享WARP的目标边界见[设计](docs/node-egress.md)及[最新决策](docs/decisions/0010-node-egress-modes-and-warp.md)；自动WARP部署尚未实现。

本快照包含原21模块及新编写的Tor、WireGuard，共23个协议源码模块。Tor仅TCP出站，WireGuard双角色首轮尚未编译验证；源码存在不代表已可用。共享调度器、多用户身份和运行业务账本已迁移，自动WARP、持久统计、带宽历史及完整多语言仍未完成。具体范围见[项目状态](STATUS.md)、[接口](docs/interfaces/README.md)与[发行说明](docs/releases/1.0.0.md)。工具链目标为Rust 1.99.1、Linux x86_64，以下是发布后的构建命令，尚无该发行整树构建通过结论：

```sh
cargo build --locked --release -p kerlico
cargo run --locked -p kerlico -- modules
cargo run --locked -p kerlico -- check -c examples/local-forward-v2.json
```

示例中的服务器、目标域名和 UUID 都是合成占位值。实际连接配置放在被 Git 排除的本地私有目录，使用 `kerlico run -c` 指定；程序不读取任何内置真实凭证。

当前配置版本为2。旧例和历史记录尚未全部迁移，不应直接当作本版可运行配置；先参照[配置接口](docs/interfaces/config.md)。

自有代码采用[GPL-3.0-only](LICENSE)。第三方材料保留各自原许可，适用范围与发行准备见[许可说明](docs/licensing.md)。

| 入口 | 内容 |
| --- | --- |
| [项目状态](STATUS.md) | 当前进度、已明确要求、待决项、下一步与验证状态 |
| [架构设计导航](docs/README.md) | 总体结构、核心契约、数据路径、生命周期与协议模块 |
| [共享出站与节点模式](docs/node-egress.md) | 全局调度、多远端、设备WARP、地址族模式和原请求透传的目标结构 |
| [多用户、流量与带宽](docs/statistics-and-users.md) | 已确认需求及目标设计，含访问记录、在线信息与保存查询，尚未实现 |
| [实现接口](docs/interfaces/README.md) | 核心、配置、节点及各协议的真实接口和边界 |
| [扩展验证快照](docs/testing/vless-combinations.md) | 三协议装配、VLESS 双端与明确未完成项 |
| [VLESS 0.1 历史记录](docs/testing/vless-ordinary-flow.md) | 旧版普通流验证，不外推新代码 |
| [文档与资料约定](docs/repository-workflow.md) | docs、STATUS、决策和上游源码的存放与维护方式 |
| [匿名提交规则](docs/anonymity.md) | 固定匿名身份、提交内容要求、钩子与克隆后的启用 |
| [参考项目调研](reference/README.md) | 三个项目的固定源码研究、横向对照与借鉴映射 |
| [协议与组合总表](reference/reports/三核心%20协议%20组合支持.md) | 三核心支持范围、组合限制与 kerlico 后续任务的唯一主清单 |
| [协作约定](AGENTS.md) | 当前阶段及开始编写实现的边界 |

已发布 0.1 不包含 SOCKS/HTTP 代理入站、TUN、REALITY、Vision、XHTTP、Mux/XUDP 或 VLESS Encryption。本开发快照中的增量和架构目标不代表已验收能力；文档和提交说明使用简体中文，提交身份保持匿名。
