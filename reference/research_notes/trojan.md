# Trojan 双端与载体调研

日期：2026-10-31。对应总表 P-09；状态：限定范围已有 perf-02 实测，结果见测试记录；下面的上游源码观察本身不代表本项目已验证。

## 依据与协议边界

- [Trojan 原始规范](https://github.com/trojan-gfw/trojan/blob/master/docs/protocol.md)：56 字节小写 SHA-224 十六进制认证值、CRLF、命令、SOCKS 地址、CRLF。命令 1 为 TCP，3 为 UDP；UDP 每帧带独立目标、16 位大端长度和 CRLF。零长度包与流结束不同。
- [Xray 固定协议实现](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/trojan/protocol.go)：TCP/UDP 共用认证头；包目标逐帧提供。其读取上限为 8192 字节，因此本项目较大帧不能外推对该版本兼容。
- [Xray 固定配置](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/trojan.go)：Trojan flow 已移除；普通 Trojan 不继承 VLESS Vision/Encryption。
- [sing-box 固定出站](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/protocol/trojan/outbound.go)：业务协议与 V2Ray 载体分层；TCP/UDP 两条路径，UDP 可按逐包目标绑定。mux 为额外层，不由普通 Trojan 继承。
- [mihomo 固定出站](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/trojan.go)：自身常用载体为 TCP、WS、gRPC，安全扩展和内容包装另有约束。

## 首轮完整范围

实现客户端与服务端 TCP CONNECT、UDP ASSOCIATE，IPv4/IPv6/域名地址，逐包多目标服务端、固定目标核心出站适配，RAW/TCP、WS、HTTPUpgrade、gRPC Tun/TunMulti。每类载体均实现 TLS 和仅允许回环的无安全模式。TLS 校验证书与名称，不提供 insecure 开关。服务端支持本节点多密码、跨节点凭据指纹校验、统一 AccessService、连接/空闲/取消预算和载体内逻辑流预算。

本轮不将 REALITY、XHTTP、mKCP、ShadowTLS/Restls/JLS、Shadowsocks 内容包装、通用 mux 或网站 fallback 记作已实现；这些仍留在总目标后续增量中。原始 Trojan 的网站 fallback 是独立能力；本轮认证失败关闭连接，不宣称具有原版的网站探测伪装行为。没有 flow/Encryption 配置，未知字段必须拒绝。

## 依赖、构建和许可证

不引入 Go/C++ 协议代码。SHA-224/常量时间比较分别采用已有 sha2/subtle；TLS 采用已有 rustls/tokio-rustls，HTTP 服务端采用已有 hyper/hyper-util，WS 采用 tokio-tungstenite，gRPC Hunk 使用 prost。客户端复用项目已固定的 xray-rust `9b06d37466492242a1827f9a16aa91ca4c1b00be` transport/routing，其根 Cargo.toml 声明 MPL-2.0；本轮不复制该依赖源码到可提交目录。固定 Xray 为 MPL-2.0，原始 Trojan 为 GPL-3.0，均仅作规范和行为对照。项目整体许可证尚待确定，不能从依赖许可证推导整体许可。

Rust 1.99.1/Linux x86_64 为当前验证基线。首轮源码、接口、配置和测试写齐后在 perf-02 专用项目工作区统一构建与验证；本地不运行编译、格式检查或测试。

## 验收矩阵

- RAW、WS、HTTPUpgrade、gRPC single/multi × TLS/回环明文 × 双向客户端/服务端 × TCP/UDP。
- IPv4/IPv6 接入与目标交叉、域名目标、零包与 17/4096/8192 字节包、UDP 多目标回写及上限。
- 错误密码、错误证书/名称、非法命令/地址/CRLF、截断帧、未知字段、重复凭据、跨节点串用、取消、半关闭、连接排空及端口复用。
- 固定 Xray/sing-box 对端分别记录；自端通过不替代外部互通。单条组合通过不外推所有载体。

## 固定 Xray UDP 边界的实测修正

首轮外部矩阵的 TCP、17/4096 字节 UDP 已进入成功路径，8192 字节包未回写。固定对端日志报告 `proxy/trojan: failed to write response > common/buf: buffer is full`。核对 [common/buf/buffer.go](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/common/buf/buffer.go) 的 `Size=8192` 与 `PacketWriter.writePacket` 后确认：写入缓冲包含地址、端口、长度和 CRLF，不能把读取端 `maxLength=8192` 当成双向有效负载上限。IPv4 头部 11 字节，推得有效上限 8181；IPv6 头部 23 字节，推得 8169。上述边界已在完整双向矩阵实测通过；RAW/明文双向另保留 8192 字节负载负例。8192 的失败保留为对端限制，不改写成兼容。
