# kerlico

计划使用 Rust 开发客户端与服务端一体的 VPN 内核，参考 mihomo、sing-box 和 Xray-core。目标是同一个可执行程序按配置承担两种角色；节点凭据独立，统一目标访问模块默认优先 IPv4，详见[双端设计](docs/node-egress.md)。

本次保存三协议双端的开发快照。已验证结果与最新未复验增量分别见[项目状态](STATUS.md)和[VLESS 扩展记录](docs/testing/vless-combinations.md)，不作为完整验收的发行版。当前构建基线为 Rust 1.99.1、Linux x86_64。源码按功能和协议分开，以下构建与运行命令在专用 worker 执行：

```sh
cargo build --locked --release -p kerlico
cargo run --locked -p kerlico -- modules
cargo run --locked -p kerlico -- check -c examples/vless-tls.json
```

示例中的服务器、目标域名和 UUID 都是合成占位值。实际连接配置放在被 Git 排除的本地私有目录，使用 `kerlico run -c` 指定；程序不读取任何内置真实凭证。

| 入口 | 内容 |
| --- | --- |
| [项目状态](STATUS.md) | 当前进度、已明确要求、待决项、下一步与验证状态 |
| [架构设计导航](docs/README.md) | 总体结构、核心契约、数据路径、生命周期与协议模块 |
| [实现接口](docs/interfaces/README.md) | 核心、配置、节点与三种协议的真实接口和边界 |
| [扩展验证快照](docs/testing/vless-combinations.md) | 三协议装配、VLESS 双端与明确未完成项 |
| [VLESS 0.1 历史记录](docs/testing/vless-ordinary-flow.md) | 旧版普通流验证，不外推新代码 |
| [文档与资料约定](docs/repository-workflow.md) | docs、STATUS、决策和上游源码的存放与维护方式 |
| [匿名提交规则](docs/anonymity.md) | 固定匿名身份、提交内容要求、钩子与克隆后的启用 |
| [参考项目调研](reference/README.md) | 三个项目的固定源码研究、横向对照与借鉴映射 |
| [协议与组合总表](reference/reports/三核心%20协议%20组合支持.md) | 三核心支持范围、组合限制与 kerlico 后续任务的唯一主清单 |
| [协作约定](AGENTS.md) | 当前阶段及开始编写实现的边界 |

已发布 0.1 不包含 SOCKS/HTTP 代理入站、TUN、REALITY、Vision、XHTTP、Mux/XUDP 或 VLESS Encryption。本开发快照中的增量和架构目标不代表已验收能力；文档和提交说明使用简体中文，提交身份保持匿名。
