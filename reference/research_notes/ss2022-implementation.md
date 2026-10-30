# Shadowsocks 2022 实现研究

日期：2026-10-30。对应总表 P-04、K-S2。源码事实、采用范围与验证结果分开记录。

## 固定依据

| 来源 | 固定版本与用途 |
| --- | --- |
| mihomo | `3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8`：`adapter/outbound/shadowsocks.go` 使用 sing-shadowsocks2，`listener/sing_shadowsocks/server.go` 使用 shadowaead_2022 服务；原生 UDP 与插件流路径分开 |
| sing-box | `c005f35300ce76427dc285481ec5695f5b179cd2`：`protocol/shadowsocks/inbound.go` 按单用户、多用户、relay 分支构造；出站由 sing-shadowsocks2 创建方法；UoT/mux 是额外扩展 |
| Xray-core | `0afec66085a85191e9dd2a4a6646c7c9a94688d1`：`proxy/shadowsocks_2022/` 与 `infra/conf/shadowsocks.go`；ChaCha 多 key 明确拒绝，多用户/relay 不能由单用户结果外推 |
| Rust 原语 | `shadowsocks =1.25.0`，crate VCS SHA `ab388c7466d21f979430e33cc9ef10e22fb05955`，MIT，最低 Rust 1.91；关闭默认功能，只启用 `aead-cipher-2022`；依赖的 AEAD/BLAKE3 由该库实现 |
| 规范 | [SIP022](https://shadowsocks.org/doc/sip022.html)、[EIH](https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-2-shadowsocks-2022-extensible-identity-headers.md)，滚动规范于本日核查，固定依赖源码作为实际行为依据 |

固定源码入口：[mihomo 出站](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/shadowsocks.go)、[mihomo 入站](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/listener/sing_shadowsocks/server.go)、[sing-box 入站](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/protocol/shadowsocks/inbound.go)、[Xray 构造与合法限制](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/shadowsocks.go)、[Rust TCP 原语](https://github.com/shadowsocks/shadowsocks-rust/tree/ab388c7466d21f979430e33cc9ef10e22fb05955/crates/shadowsocks/src/relay/tcprelay)、[Rust UDP 原语](https://github.com/shadowsocks/shadowsocks-rust/tree/ab388c7466d21f979430e33cc9ef10e22fb05955/crates/shadowsocks/src/relay/udprelay)。

本轮实际解析到 `shadowsocks-crypto 0.8.0`（MIT）、`aws-lc-rs 1.18.1`（`ISC AND (Apache-2.0 OR ISC)`）、`aws-lc-sys 0.45.0`（包含 ISC、Apache-2.0、MIT、BSD-3-Clause、MIT-0 的组合表达式）。后两项不是只有 MIT；分发时应按实际依赖许可证保留相应声明。AWS-LC 为进程内原语，构建需要 C 工具链/CMake，不启动外部代理。这里记录已核查的元数据，不声称已完成全部依赖法律审计。BLAKE3 仍受根 workspace 的 `xray-rust` 固定 `9b06d37466492242a1827f9a16aa91ca4c1b00be` patch 控制，本模块没有再更改该选择。

上述 Go 源码只用于设计核对，不复制进入 Rust 模块。Rust 库直接链接进同一程序，不启动 ssserver/sslocal 等进程。许可证观察不替代完整依赖审计；最终解析版本由根 Cargo.lock 固定。

## 线格式与安全边界

- AES-128 使用 16 字节随机 PSK，AES-256 与 ChaCha20 使用 32 字节；配置必须提供标准 Base64 编码原始 key，不使用口令派生。
- TCP 使用每连接随机 salt、BLAKE3 会话子密钥、带类型/时间戳/长度的初始头和 AEAD 数据块。响应关联请求 salt。握手与分块由 `ProxyClientStream`、`ProxyServerStream` 处理，节点共享独立 `Context` 保存 TCP salt 回放状态。
- AES UDP 的 session ID/packet ID 独立头与主头、ChaCha UDP 的 XChaCha20-Poly1305 随机 nonce 模型不同；不自行替换为同一种线格式。直接调用 `relay::udprelay::crypto_io`。该层验证 AEAD、类型、时间戳和地址；调用方仍需实现 UDP 会话与滑动窗口，不能以解密成功替代回放校验。
- UDP 服务端按已认证 key 与 client session ID 建立会话，只有完整验证且未回放的数据报可更新最后源地址；同一会话可请求多个目标。会话/回放状态至少保留 60 秒。响应有独立随机 server session ID 和单调 packet ID。客户端允许多个 server session，按各自窗口拒绝重复/过旧包。
- TCP/UDP 均无前向保密。SS2022 自身 AEAD 提供本轮公网节点的传输保护，不额外要求 TLS。

## 本轮完整编码范围

三种方法：`2022-blake3-aes-128-gcm`、`2022-blake3-aes-256-gcm`、`2022-blake3-chacha20-poly1305`；各自客户端/服务端、TCP/原生 UDP。AES 额外支持终端 EIH 多用户服务端和最多八层 identity key 链客户端；用户 key 必须各不相同，不能等于本节点服务 key。ChaCha 拒绝 EIH、多用户及冒号 key 链。三算法都拒绝未知方法、口令、错误 key 长度、插件、UoT 与 relay 配置。relay 转发链、SIP003、UoT、通用 mux 不在本轮范围，不登记为已支持。

节点私有 Context、用户表、UDP session/replay 状态不跨节点共享。凭据指纹覆盖 service key 与全部 user key，用于装配阶段拒绝 IPv4/IPv6 节点复用。业务目标只进入 `AccessService`；此模块不自行解析/拨号业务目标，代理载体解析与目标 IPv4 优先策略分属不同职责。

## 验收范围

已在 perf-01 独立工作区执行格式、Clippy、单元/集成测试；三算法分别核对双端 TCP/UDP、空包、较大负载、IPv4/IPv6/域名目标、错误认证、跨节点拒绝、UDP 回放与网络地址迁移、取消和资源限制。固定 sing-box/Xray 对端已分别验证角色与多用户范围，最终 8 项 Rust 测试及 44 场景、88 项正向互通通过，之后另有 17 组正式 CLI 集成通过；Xray 8192 字节 UDP 失败边界保留。详细命令、负载与未覆盖项见[测试记录](../../docs/testing/ss2022.md)，不能将本节验收目标全部解释为已验证。
