# 0003 最小框架与普通 VLESS 首次实现

状态：已采用，依据用户授权在当前任务内自主决定。日期：2026-10-30。

## 任务依据

用户明确要求完成资料后 push，再开始 VLESS 相关模块，任务中不询问并自行作出决定，同时维护接口文档。资料已先匿名推送；本记录只确定当前实现范围，不将其他候选组合自动加入任务。

## 本轮选择

先交付实际可运行的框架，再接入普通 VLESS 出站。首条路径为回环固定目标 TCP/UDP 转发，不额外启动 SOCKS/HTTP 协议开发。JSON v1 外层和工厂独立解码，核心不依赖具体协议；程序通过可选 `protocol-vless` feature 注册模块。

采用 Tokio、tokio-rustls/rustls 与 ring；密码学由库提供，不自行编写。Cargo.lock 固定实际依赖，代码使用 Rust 2024，清单最低版本为 1.88。面向 Linux x86_64 测试机并保留本地 macOS arm64 验证，不承诺其他平台已通过。

首个 VLESS 范围为固定源码的 version=0、UUID、空 flow、TCP 承载与正常 TLS 校验，以及固定目标 UDP 分帧。REALITY、Vision、XHTTP、Mux/XUDP 和 Encryption 明确拒绝。接口和配置分别见[核心接口](../interfaces/core.md)、[配置](../interfaces/config.md)、[VLESS](../interfaces/vless.md)。

## 责任与限制

工厂契约放在 config 边界，核心保持与序列化格式分开。请求发送与响应确认分离，首次读取才处理响应头。远端 EOF 传播单独作为能力，不能因为有 TCP 字节流接口就承诺该语义。

测试使用三台授权 worker 的项目工作区，不改变既有 Runner、Docker、Mesh、SSH 或监控。缺少主机身份记录时，本轮依据登记地址执行首次信任（TOFU）并固定，之后严格校验；这不等于经过独立第三方来源的指纹认证。真实资料和原始日志仍仅存私有目录。

本轮结果以[验证记录](../testing/vless-ordinary-flow.md)为准；不能由自建对端测试或旧缓存输出代替真实上游互通。
