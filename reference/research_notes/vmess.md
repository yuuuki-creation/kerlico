# VMess 双端实现前调研

日期：2026-10-31。状态：固定源码与规范已阅读，本轮限定范围已编写并远端验证；结果与剩余边界见[验证记录](../../docs/testing/vmess.md)。

## 证据与依赖

- [VMess 规范](https://www.v2fly.org/developer/protocols/vmess.html)给出 AEAD 请求、响应、KDF、分块、地址及选项定义；旧 MD5 认证已弃用。
- [固定 Xray 服务端](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/vmess/encoding/server.go)同时约束请求校验、会话重放和响应记录。服务端须在目标访问之前完成认证及结构检查。
- [固定 AuthID 实现](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/vmess/aead/authid.go)用 AES 块解密识别用户、校验 CRC 和 ±120 秒时间窗口，并拒绝重复 AuthID。
- [固定 Rust 客户端](https://github.com/aimalygin/xray-rust/tree/9b06d37466492242a1827f9a16aa91ca4c1b00be/crates/xray-proxy/src/vmess)只有 AEAD 客户端，不能代替双端实现。其响应认证长度使用请求 key/IV；本模块须以真实对端验收该细节。
- 当前传输依赖 `xray-transport` 为既有固定 MPL-2.0 依赖；本模块自有协议代码按公开格式实现，密码运算使用 RustCrypto `aes`、`aes-gcm`、`chacha20poly1305`、`md-5`、`sha2`、`sha3`，本轮 worker 实际检查的直接密码依赖为 aes 0.8.4、aes-gcm 0.10.3、chacha20poly1305 0.10.1、md-5 0.10.6、sha2 0.10.9、sha3 0.10.9，其包元数据均登记 MIT OR Apache-2.0（顺序可能相反）；完整传递依赖与最终发行仍由工作区统一核对。项目整体许可证仍待确定。

## 完整首轮范围

双端 AEAD 认证、AES-128-GCM/ChaCha20-Poly1305/auto、TCP 和固定目标 UDP；节点多用户和跨节点凭据指纹隔离；RAW、WS、HTTPUpgrade、gRPC 单/多消息模式，分别使用 none/TLS。节点鉴权后统一调用 `AccessService`；建立总预算、空闲预算、取消、半关闭、计数器耗尽、AuthID 与会话 key/IV 重放防护均纳入实现和验证。

元数据掩码、全局 padding、authenticated_length 分别建模，拒绝未知位；UDP 记录保持一个包，空包与终止记录无法区分，配置/接口明确拒绝空包，不伪造数据。单包上限按 65535 字节记录长度减 AEAD 标签与最大 padding 确定。

## 组合与未交付边界

VMess 载体与安全独立；本轮 WS/HTTPUpgrade 使用 H1，gRPC 使用 H2。none 不表示 VMess 业务无加密。拒绝 alterId、旧 MD5 认证、CFB/none/zero 内容加密、Vision、VLESS Encryption、未知传输或安全类型。REALITY、XHTTP、mKCP、旧 h2/http、QUIC transport、通用 Mux/XUDP 为后续范围，不由已有 VLESS 支持外推；不伪造空实现或开关。

## 验收矩阵

两个方向 × 两种实际 cipher × 四类载体 × none/TLS × TCP/UDP；gRPC 单/多模式单列。覆盖 IPv4/IPv6 接入与目标、域名、authenticated_length、错误 UUID/认证标签、过期时间、重放、无效字段、半关闭、取消与端口复用。自端测试只验实现回归；固定 Xray/sing-box 真实对端才证明相应互通。

固定格式向量取自上述 Rust 固定版本的 `tests/fixtures/v08/protocol-primitives.json` 中 VMess 子集，保存为本模块 `tests/fixtures/vmess-vectors.json`；上游标记为固定 Go 生成向量。本模块逐项对照 command key、KDF、AuthID、两 cipher 和两长度编码，padding 公共随机字节归零后比较。该数据证据与实际对端互通分别记录。

Xray 默认 cone 模式会把普通 UDP 端口转换为 command 3/XUDP；本轮 command 2 互通显式设置 `xray.cone.disabled=true`，依据固定 `core/xray.go` 与 `common/platform/platform.go`。该测试设置不表示已支持 XUDP。
