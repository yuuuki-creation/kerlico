# VLESS 扩展的依赖与来源

状态：开发中采用，待组合验证后发布。日期：2026-10-30。

协议与组合行为仍以总表固定的 mihomo、sing-box、Xray 为依据。为复用 Rust 中的密码和传输实现，本轮通过 Cargo Git 依赖使用下列库，除了下述旧接口兼容副本外，不复制其源码进入本项目，也不将其 README 声称的功能直接记为本项目验证结果。

| 依赖 | 固定来源 | 用途与许可证 |
| --- | --- | --- |
| xray-transport / xray-proxy / xray-routing / xray-vless-encryption | [固定提交](https://github.com/aimalygin/xray-rust/tree/9b06d37466492242a1827f9a16aa91ca4c1b00be) | 传输、安全、Vision 和 Encryption 原语；[MPL-2.0](https://github.com/aimalygin/xray-rust/blob/9b06d37466492242a1827f9a16aa91ca4c1b00be/LICENSE) |
| rust-reality | [固定提交](https://github.com/jacek4yang/rust-reality/tree/316003c5ad2ce9b443f0e9c4311478b7f7b61f9c) | 仅使用 REALITY 握手与 TLS 记录原语，不复用其整套服务端运行时；MIT/Apache-2.0，来源与许可证保留在固定依赖中 |
| rust-xhttp | [固定提交](https://github.com/jacek4yang/rust-xhttp/tree/8de99be3ed1b9446a23763d1b6c36976177eb124) | 仅使用服务端 Encryption 与 XHTTP 有界重排/下载原语；MPL-2.0；其路由、管理与程序入口不参与装配 |
| shaped-rustls | [固定提交](https://github.com/aimalygin/shaped-rustls/tree/3a131beaef0183b0cb61e5a9070a703b6be39ed3) | REALITY ClientHello 定制、混合密钥交换与证书验证；许可证以该版本原始文件为准 |
| quinn / quinn-proto / h3-quinn / blake3 补丁 | 上述 xray-rust 固定提交的 vendor 目录 | 保留上游 H3 与二进制上下文 KDF 行为；各自许可证、补丁来源和范围保留在原始依赖中 |

Cargo.lock 记录实际 Git revision 与注册表校验和。根清单固定 rustls 为补丁提供的 0.23.40，避免 Cargo 选择更高的未修改版本而丢失 REALITY 所需接口。当前构建基线为 Rust 1.99.1。原计划 1.96 已经在隔离容器实际尝试，但固定 rust-reality 2.2.0 及 rr-crypto/rr-linux/rr-session 明确要求 1.99；因此调整工作区清单，不再声称兼容 1.96。此前 1.88 的历史结果仅适用于 0.1。

依赖源码及其原始许可证可从表中固定链接获取，Cargo 也会下载相同来源。分发二进制时必须随发行说明保留这些来源和许可证入口；如修改依赖文件，应另行公开对应源码及修改说明。匿名提交要求不允许删除第三方原有的许可证或署名。

这些库是实现依赖，不提供本项目的路由、配置生命周期或验收结论。协议原语通过 VLESS 模块适配到 core-api；真实对端、异常、取消和并发隔离仍由本项目独立验证。

旧 ML-KEM 0.2 与新 REALITY 的 0.3 所需 KEM 接口无法由同一注册表来源同时解析。本轮增加 `third_party/ml-kem-legacy`，保留 ml-kem 0.2.3 原始算法源码与许可证，只将旧 KEM 依赖改到固定独立来源；变更与构建原因见[副本说明](../third_party/ml-kem-legacy/README.md)。
