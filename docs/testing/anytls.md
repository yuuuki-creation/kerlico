# AnyTLS 验证记录

日期：2026-10-30。对应总表 P-15。所有构建、格式、静态检查和测试均在 perf-03 独立临时项目目录执行，`CARGO_BUILD_JOBS=1`；本地仅编辑、阅读和同步。没有修改 worker 基础服务。

## 环境与固定对端

- Linux x86_64；Rust/Cargo 1.99.1；任务前可用内存约 2.5 GiB，未运行性能压测。
- sing-box v1.14.4，程序报告 revision `c005f35300ce76427dc285481ec5695f5b179cd2`；官方 Linux amd64 归档中的程序 SHA-256 为 `1264361b5f8868c8768f7555d3e77e20118bf503c41ac08bb290a0d99056aa3a`。
- Rust 依赖实际解析包括 rustls 0.23.40（沿用工作区固定 shaped-rustls）、tokio-rustls 0.26.6、Tokio 1.54.1、md-5 0.10.6、subtle 2.6.1、sha2 0.10.9、rand 0.8.8。
- 原始日志保存在本地被忽略的 `.private/builds/anytls/`。包级集中任务 `final`、根集成任务 `app-final` 与真实对端复验 `oracle-final` 均返回 0；公开文档不保存连接参数、真实机器标识或系统网络信息。

## 已通过

执行 `cargo fmt -p kerlico-anytls --check`、`cargo test -p kerlico-anytls`、`cargo clippy -p kerlico-anytls --all-targets -- -D warnings`。后续根集成和客户端停写补充回归后，默认测试 4 个单元测试、6 个集成测试通过；真实对端测试默认 ignored，随后显式启用并通过，合计 11 个测试。

| 范围 | 真实检查与结果 |
| --- | --- |
| 帧与地址 | IPv4、IPv6、域名在 SOCKS/UoT 地址编码往返；帧长度、截断与无效类型拒绝 |
| padding | 默认方案、固定初始 padding、方案指纹与非法区间限额 |
| 会话 | 同载体两路逻辑流隔离、心跳回应、关闭与取消；原生节点三次 TCP 请求仅接受一个 TLS 连接，确认池复用 |
| 原生双端 | TLS TCP；UoT v2 固定目标，空包、普通包、65507 字节数据报回写 |
| 节点边界 | 分别建立 IPv4/IPv6 TLS 节点，使用不同口令；两节点均访问 IPv6 目标（包含 IPv4 接入→IPv6 目标），各自拒绝另一节点口令；已取消的拨号拒绝 |
| 配置与预算 | 空口令、重复口令、未知字段拒绝；独立凭据指纹；未完成的 UoT 请求头受超时和取消约束 |
| 停接入与收尾 | 关闭节点预算后拒绝新逻辑流，已有流继续收发；有限响应目标在 FIN 前的全部 256 KiB 回写保留 |
| kerlico 出站→sing-box 入站 | TLS TCP 三次 256 KiB 回写与连接复用；UoT v2 connect 模式空包、普通包、12000 字节；错误口令不能取得目标回写 |
| sing-box 出站→kerlico 入站 | SOCKS 经 AnyTLS 的三次 TCP 回写；SOCKS UDP 经 UoT v2 逐包地址模式的空包、普通包、12000 字节回写 |

真实对端测试入口为 `tests/dual.rs` 中的 `sing_box_both_roles_tcp_and_uot_v2`，仅在 worker 设置 `ANYTLS_SING_BOX` 为固定参考程序路径、`ANYTLS_TEST_DIR` 为该任务私有目录后执行：

```sh
cargo test -p kerlico-anytls --test dual sing_box_both_roles_tcp_and_uot_v2 -- --ignored --nocapture
```

## 修复与限制

初次真实 TCP 大块回写暴露输入队列满时提前 FIN。修改为有界队列背压后，重复验证 256 KiB 回写与全部包级用例通过；有界内存仍可能带来同载体流之间的阻塞，AnyTLS 没有额外逐流窗口协议。

对 sing-box 入站发送 60000 字节 UoT 数据报时，参考端报告 `UoT read: short buffer` 并关闭流。本记录将该固定对端的互通范围限制为 12000 字节；原生双端的 65507 字节成功不能外推到该对端。

未验证 mihomo 实际程序、其他操作系统/架构、Rust 1.96 最低版本、跨公网链路、吞吐、长期池压力、UoT v1 或老版本客户端。AnyTLS FIN 不提供最终 TCP 半关闭，因此 `tcp_eof=false`。根程序的 AnyTLS-only 装配已按下述范围验证；结果不外推默认功能集合、整个 workspace 或其他协议。

## 根程序集成验收

在 perf-03 按顺序构建并保存两种根二进制：

```sh
cargo build -p kerlico --no-default-features --features anytls
cargo build -p kerlico --no-default-features
```

没有构建默认功能集合，也没有执行 workspace 全量验证。AnyTLS 构建程序 SHA-256 为 `afff43c2fb73d93293a37920cfeb4c258e696b61c848919c95d110c792bfe548`。工具 `tools/interop_anytls_app.py` 的最终 `app-final` 结果为 `ok=true`，共 19 项检查：

- CLI 仅注册 AnyTLS 双端与基础 direct/reject；拒绝未编译的 VLESS、Shadowsocks 2022 配置。
- 同一个 AnyTLS 根程序同时运行 IPv4/IPv6 服务节点和客户端转发；两节点均经统一访问服务访问 IPv4/IPv6 TCP 目标，TCP 256 KiB 回写、UDP 12288 字节与空包回写成功。
- 两节点口令分别设置，配置拒绝重复口令，运行时各自拒绝另一节点口令；四路并发隔离成功。
- kerlico 客户端到固定 sing-box 服务端的 IPv4/IPv6 目标与 UoT v2 回写成功；固定 sing-box 客户端分别通过 IPv4/IPv6 kerlico 节点访问两种目标地址族成功。
- 无协议构建不注册 AnyTLS，并分别拒绝包含 AnyTLS 出站、节点的配置；根程序在排空预算内退出。

最初根集成夹具的自签证书被标为 CA、Python UDP echo 默认只接收 8192 字节，分别导致证书校验拒绝和夹具截断。修正为服务器叶证书及 65535 字节接收缓冲后完整复验通过。

## 客户端停写保留反向数据修复

默认三协议联合验收发现：应用发送完整请求后 `SHUT_WR`，AnyTLS 客户端把本地停写传给内部 DuplexStream，发送泵读到 EOF 后提前发送结束全流的 FIN，导致反向响应丢失。修复仅调整客户端逻辑流：`shutdown` 禁止后续写入并 flush，继续接收响应；服务端真实 EOF/FIN 路径不变，仍声明 `tcp_eof=false`。

新增 `client_shutdown_preserves_large_response_and_reuses_session` 回归：分别发送 128 KiB 和 256 KiB（超过单流输入队列容量）请求后停写，目标延迟响应；检查后续写返回 `BrokenPipe`、完整反向数据及 EOF，并确认两次请求只使用一个 TLS 连接，证明逻辑流结束后可回收复用。原有服务端有限响应、预算关闭和取消用例一并保留。

本轮仍仅在 perf-03 执行，开始时可用内存约 2.5 GiB，构建作业数为 1；仅同步本协议 crate，使用独立 `target-anytls-shutdown`，没有覆盖共享源码或根 Cargo.lock。修复前新增回归失败；移除临时诊断后该回归连续 11 次通过，全包连续 3 轮通过。最终 `shutdown-final` 先在该独立 target 清理本包产物，再重新构建：格式、4 个单元测试、6 个集成测试、Clippy 和显式启用的固定 sing-box 对端测试均通过，任务退出 0。原始日志为 `.private/builds/anytls/perf-03-shutdown-final.log`。

本轮没有重建默认功能根程序，修复后默认三协议联合验收由对应总任务另行记录。客户端停写不会将 EOF 传给最终目标；依赖目标收到 EOF 才响应的应用仍不在 `tcp_eof=false` 的保证范围内。
