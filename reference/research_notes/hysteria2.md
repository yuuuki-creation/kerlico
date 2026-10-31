# Hysteria2 双端实现前调研

日期：2026-10-31。状态：只读调研；尚未编写 Hysteria2 模块，尚未编译或互通。对应总表 P-12，不包含 Hysteria v1。

## 固定证据

官方仓库当前 release 查询为 [app/v2.13.0](https://github.com/HyNetworks/hysteria/releases/tag/app/v2.13.0)，标签解引用提交 `ca8fbd874fd6ca82413948de6dc5924405e103e1`。本次保存其只读源码，不能用此前 Rust 依赖测试使用的 v2.12.2 结果替代当前版本。

本项目已固定 Rust 依赖 `xray-rust 9b06d37466492242a1827f9a16aa91ca4c1b00be`。其 `xray-proxy` 导出 Hysteria2 TCP/UDP 编解码与有界重组器；`xray-transport` 导出 Hysteria2 客户端、TCP 流和 UDP session，仅有客户端运行实现。不能由客户端可用推定服务端已存在。

| 对象 | 固定入口 | 已查明事实 |
| --- | --- | --- |
| 官方协议 | [Protocol](https://hysteria.network/docs/developers/Protocol/) | QUIC/H3 鉴权、TCP stream、UDP datagram、Salamander、Gecko |
| 官方服务端 | [server.go](https://github.com/HyNetworks/hysteria/blob/ca8fbd874fd6ca82413948de6dc5924405e103e1/core/server/server.go) | H3 服务与自定义 stream dispatcher 并行；鉴权前不接纳代理流 |
| 官方线格式 | [proxy.go](https://github.com/HyNetworks/hysteria/blob/ca8fbd874fd6ca82413948de6dc5924405e103e1/core/internal/protocol/proxy.go) | TCP 地址/响应/填充上限分别 2048/2048/4096；UDP frame 1200，当前官方 UDP 业务缓冲 4096 |
| Rust 线格式 | [hysteria/mod.rs](https://github.com/aimalygin/xray-rust/blob/9b06d37466492242a1827f9a16aa91ca4c1b00be/crates/xray-proxy/src/hysteria/mod.rs) | 编解码不鉴权、不拨号；调用者负责完整生命周期 |
| Rust 客户端 | [client.rs](https://github.com/aimalygin/xray-rust/blob/9b06d37466492242a1827f9a16aa91ca4c1b00be/crates/xray-transport/src/hysteria/client.rs) | H3 auth、有限 session/队列、连接关闭清理；仅自适应拥塞配置 |
| Rust 载体 | [carrier.rs](https://github.com/aimalygin/xray-rust/blob/9b06d37466492242a1827f9a16aa91ca4c1b00be/crates/xray-transport/src/hysteria/carrier.rs) | Salamander、UDP hop、noise；没有 Gecko |
| 另一 Rust crate | [hysteria2 0.1.6](https://docs.rs/crate/hysteria2/0.1.6) | 客户端 TCP；本次源码未发现服务端/UDP session 实现，不适合作为双端完整适配 |

## 依赖与许可证

优先复用项目已固定的 `quinn 0.11.9`、`h3 0.0.8`、`h3-quinn 0.0.10`、`rustls 0.23.40` 及固定 xray 编解码，不另引入一套 QUIC。实际 Quinn/h3-quinn 受根 patch 控制，不能仅按 crates.io 版本判断 API 和行为。

`xray-rust` 声明 MPL-2.0，官方 Hysteria 的 root/core/extras 为 MIT 文本，另一 `hysteria2 0.1.6` 声明 MulanPSL-2.0。Quinn/h3 相关许可证按实际锁定来源归档；整体发行许可证仍需主任务审核。若拷贝或修改上游源码，必须保留其适用许可证义务，不能因项目匿名规则抹掉外部代码的必要声明。

官方 v2.13.0 core 要求 Go 1.26，采用固定 quic-go 派生版本；对端优先取得正式已发布二进制并保存摘要，避免在 worker 安装或替换默认 Go。项目 Rust 构建基线仍为 Linux x86_64、Rust 1.99.1。

## 核心语义与实现边界

鉴权采用 H3 `POST https://hysteria/auth`，凭据不得进入日志；成功状态为 233，UDP 开关及接收速率分别协商。错误认证应呈现普通 H3 页面或伪装响应，不应打开目标连接。认证前收到代理流不得进入 AccessService。

TCP 每业务流开独立 QUIC 双向 stream，先编码目标与 padding，等待明确成功响应，再暴露业务流；保留 FIN 和反向排空。UDP 使用 Session ID，跨流不同 session 隔离，支持多目标与分片；缺片/冲突/超时整包丢弃，零长度包保留。QUIC datagram 丢失不应转化为自动重放。分片状态、队列字节/包数及目标关联均需有界。

服务端需要同时处理 H3 标准请求与 Hysteria 自定义 TCP stream。直接启动两个 `accept_bi` 读取者会竞态；仅在首个 auth 后停掉 H3 driver 的 mock 方式不足以证明完整 H3 伪装行为。编码阶段应使用明确的分流适配层：统一接纳 bidirectional stream，读取并保留首个 QUIC varint，把 HTTP HEADERS 类型交 H3，把 0x401 仅在认证后交代理；错误类型执行协议规定的拒绝。该适配层尚未实现。

节点应通过 engine 提供的 UDP socket 运行 QUIC endpoint，并持有独立 auth、连接集合与取消域。每个 QUIC carrier 及新增逻辑 TCP/UDP 关联均取得节点/全局预算，目标访问统一交 AccessService。已有核心 UDP handler 的生命周期和 socket 转换需在编码前核对，不另绑定未受管理的端口。

## 混淆与拥塞

Salamander 是 QUIC 外层数据报混淆，双方密码独立于 auth；需正确处理 GRO/GSO、salt 与最大 datagram 长度。Gecko 另在 Salamander 内切分 long-header QUIC 包，短头直通，不能与业务 UDP 分片混为一谈。官方固定源码提供 Gecko，但当前固定 Rust 客户端不提供；需要自己实现双向包装与有界源地址/msgID 重组，或明确登记尚未实现，不能给空配置开关。

当前固定 Rust 客户端 auth 通告接收速率 0，使用自适应 BBR/Reno；读取服务器速率但不切换 Brutal。官方可按协商速率启用 Brutal，或由 ignoreClientBandwidth 使用已配置自适应控制器。不能把普通 QUIC pacing、限速或名为 bbr 的配置当成已实现 Brutal。完整带宽模式需要移植/实现对应拥塞控制并验证，未完成前应拒绝固定速率选项。

端口跳跃不是新协议；现有 Rust 客户端具备载体 hop，但服务端需显式管理多个监听端口和同一节点连接归属。不得为实现 hop 修改 worker 防火墙或系统转发。Realm、HTTP/外部认证、ECH、Chrome 指纹模仿等上游附加功能仍按任务逐项界定，不能从基本协议成功继承。

## 待编写与验收范围

首轮需一次写齐双端 QUIC/TLS/H3 鉴权、TCP/UDP 与分片、多目标、独立 IPv4/IPv6 节点凭据、统一出口、取消/空闲/排空、严格配置与接口文档。Salamander 双端、自适应拥塞和无混淆载体同批交付；Gecko、固定速率 Brutal、hop 的实现/限制必须各自明确，未实现部分继续留在未完成清单，不能把以上核心路径的完成称作全部 Hysteria2 组合已支持。

验收必须包括：双向官方 v2.13.0 及固定 sing-box/Xray 对端；两类节点/目标地址族；TCP 并发与双向 FIN；UDP 0/小包/分片/当前官方 4096 缓冲边界；错误认证/证书/SNI/混淆密码；鉴权前流、畸形 varint、分片冲突/重复/超时、限额/取消/同端口重启；普通 H3 请求与已认证 TCP 并行。当前所有项目均待实现和验证。

## 首轮编码前补充核验

进一步读取固定 Rust 源码发现，`HysteriaUdpSession::send` 与其 UDP wire `validate` 均显式拒绝空业务包。为保留核心数据报契约，本轮自行实现双端 H3/QUIC 装配和有界 UDP 编解码/重组，复用现有 Quinn/H3/rustls 栈，不直接把现成客户端包装成完整协议。原有库的能力观察仍保留，不能把本项目新源码记成已经验证。

首轮最终范围、配置与待验项见[接口](../../docs/interfaces/hysteria2.md)和[验证记录](../../docs/testing/hysteria2.md)。服务端 UDP 使用新 `DatagramAssociation` 契约，并在准备阶段检查出口能力；此为已经存在的公共接口，不另建目标访问路径。
