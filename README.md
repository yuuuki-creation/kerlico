# kerlico

计划使用 Rust 开发 VPN 内核，参考 mihomo、sing-box 和 Xray-core。

当前已进入**框架与 VLESS 实现阶段**。源码按功能和协议分开，程序构建为一个可执行文件。已实现回环 TCP/UDP 固定目标转发、基础直连/拒绝和普通 VLESS 出站；真实兼容范围见接口与测试记录。

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
| [实现接口](docs/interfaces/README.md) | 当前核心、配置与 VLESS 的真实接口和边界 |
| [VLESS 验证记录](docs/testing/vless-ordinary-flow.md) | 构建、最低版本、互通与明确限制 |
| [文档与资料约定](docs/repository-workflow.md) | docs、STATUS、决策和上游源码的存放与维护方式 |
| [匿名提交规则](docs/anonymity.md) | 固定匿名身份、提交内容要求、钩子与克隆后的启用 |
| [参考项目调研](reference/README.md) | 三个项目的固定源码研究、横向对照与借鉴映射 |
| [协作约定](AGENTS.md) | 当前阶段及开始编写实现的边界 |

当前不包含 SOCKS/HTTP 代理入站、TUN、REALITY、Vision、XHTTP、Mux/XUDP 或 VLESS Encryption。已实现的功能与未来规划分开记录；文档和提交说明使用简体中文，提交身份保持匿名。
