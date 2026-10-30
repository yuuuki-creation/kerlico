# 0004 VLESS 剩余组合与远端验证

状态：已采用，依据用户授权完成剩余组合并自主选择实现。日期：2026-10-30。

用户要求完成 VLESS 剩余组合，编译和测试不在本地执行，并允许借鉴 mihomo 等项目。普通流 0.1 的历史结果保持原范围；新增组合独立验收。

按总表 `K-V2`、`K-V3`、`K-V4` 推进 REALITY、Vision、XUDP/Mux、XHTTP 各 HTTP 版本、mode 和独立下载、VLESS Encryption 与 XDRIVE。共享传输中的 WS、HTTPUpgrade、gRPC 等分别记录。上游明确拒绝的组合保留负例，不通过忽略配置伪装成支持。详细边界和来源见[开工调研](../../reference/research_notes/vless-combinations-implementation.md)。

继续使用自己的 core/config/engine 契约。协议层可以调用固定版本 Rust 传输、Vision 和 Encryption 原语；不启动外部代理进程，不把整个参考内核替换成本项目。当前采用的 Rust 依赖固定到提交，补丁同时固定，许可证与源码获取说明见[依赖记录](../vless-dependencies.md)。扩展前阶段曾选择 Rust 1.96；加入服务端 REALITY 后的实际依赖要求与 1.99.1 构建基线见末尾复核，旧版结果不外推。

所有编译、格式检查、Clippy、Rustdoc、单元/集成测试和真实参考端互通在授权 worker 执行。本地只编辑、阅读、同步及管理 Git，不运行内核二进制或测试。构建使用独立项目工作区、有限并发和固定输入摘要；不修改基础服务。

完成条件是每项合法组合有可构建的实际路径、明确配置和资源退出语义，并留下真实参考端验证证据。仅有依赖声明、配置可解析或自建对端测试不能标为完成。完整结果写入模块接口和测试记录，再同步总表及 STATUS。

2026-10-30 复核：加入服务端 REALITY 后，固定 rust-reality 2.2.0 及其 rr-* 包要求 Rust 1.99。隔离 Rust 1.96 容器已实际拒绝该依赖集合；当前工作区改用已在 worker 验证的 1.99.1，此前 1.96 为扩展前的阶段计划。
