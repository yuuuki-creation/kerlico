# TUIC 双端实现前调研

日期：2026-10-31。状态：本轮限定双端已编写并完成远端验证，具体快照和边界见[验证记录](../../docs/testing/tuic.md)。

## 固定证据

- [TUIC v5 规范固定点](https://github.com/tuic-protocol/tuic/blob/a299ef02d9f4ab5a0edbf58b9998f41bf768b332/SPEC.md)：认证为 UUID 与当前 TLS exporter 的 32 字节 token；label 为 UUID 原始字节，context 为原始密码。TCP 无确认响应；UDP 为 16 位 association/packet ID，支持分片和 native/quic 两模式；后续分片使用 None 地址。
- [mihomo v4 格式](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/transport/tuic/v4/protocol.go)：认证 token 为原始配置字符串的 BLAKE3；UDP association 为 32 位；无 v5 分片字段；TCP 返回 `04 ff REP`，成功值为 0。
- [mihomo v4/v5 出站选择](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/tuic.go)：token 选择 v4，UUID/password 选择 v5；原生 UDP、可靠流承载与 UoT 扩展分别处理，不能混作一个参数。
- [sing-quic v5 协议](https://github.com/SagerNet/sing-quic/blob/7e0a5869a5f49ed0a685143345dfda0448bbc708/tuic/protocol.go)、[认证与监听](https://github.com/SagerNet/sing-quic/blob/7e0a5869a5f49ed0a685143345dfda0448bbc708/tuic/service.go)、[分片](https://github.com/SagerNet/sing-quic/blob/7e0a5869a5f49ed0a685143345dfda0448bbc708/tuic/packet.go)：服务端需在认证完成后释放其他流；分片首包地址与后续地址区别必须保留。

## Rust 依赖选择与约束

历史 `tuic-quinn 0.1.0` 固定源码依赖 quinn 0.10，且为 GPL-3.0-or-later；本项目既有 quinn 0.11.9/Rustls 0.23.40 路径不直接兼容。本轮采用既有固定 quinn/rustls 原生实现，不启动 Go 子进程，不复制上述 GPL 实现代码。协议格式按规范和上游行为独立编写；实际采用既有固定 fork 的 quinn 0.11.9/quinn-proto 0.11.16（MIT OR Apache-2.0）、blake3 1.8.5（CC0-1.0 OR Apache-2.0 OR Apache-2.0 WITH LLVM-exception）及 subtle 2.6.1；不复制上述 GPL 协议实现源码，完整发行依赖许可仍由主任务统一核对。

QUIC TLS 最低版本为 1.3，ALPN 默认 `h3`，可显式配置匹配对端；客户端始终验证证书与名称。拥塞选项仅暴露现有 quinn 实际提供的 `cubic`、`newreno`、`bbr`，不把上游同名实现当作性能等同。0-RTT 握手、关闭 SNI、insecure、自定义指纹及 sing-box 的 UDP-over-stream/UoT 扩展单列，不能用虚假开关宣称支持。

## 已决定的架构与完整首轮范围

现有 `AccessService.connect_udp(target)` 为固定目标数据报接口；TUIC 规范的一个 association 对应一个 Full Cone socket，逐目标创建固定通道无法保持同一出口端口和任意来源收包语义。主任务已实现独立 `DatagramAssociation` 服务契约与 Direct/Egress 适配，TUIC 出站也提供该能力，节点在配置准备阶段要求出口声明该能力。协议模块不绕过统一访问服务创建网站 socket。

本轮完整交付：v4/v5 双端 TCP 与 Full Cone UDP；native/quic 两 relay；v5 分片、乱序重组与解关联；v4 native 超 MTU 明确拒绝，可靠流模式保留大包；独立节点多用户、TLS1.3、证书/SNI 验证、cubic/newreno/bbr、连接复用、认证等待、预算/空闲/取消/关闭与半关闭。0-RTT、UoT、指纹和其他扩展不在本轮，配置不预建无效开关。验收按版本、角色、relay、节点/目标地址族、分片/空包/大包、多目标同端口/未联系来源、错误凭据/证书、并发/取消/退出分别记录。
