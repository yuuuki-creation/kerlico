# Hysteria v1 双端与传输调研

日期：2026-10-31。对应 P-11。状态：详细调研与首轮编码已完成；perf-02 的 r3 自端 16 项及严格检查通过，同一 CLI 的官方 24/24 与 sing-box 12/12 真实双向矩阵通过。结果限于本轮所列范围与包长。

## 版本与固定证据

本项是 Hysteria **v1 家族**，线协议版本字节为 **0x03**。Hysteria2 的 HTTP/3 鉴权、0x401 请求及其他字段不属于本项。

- [官方 v1 协议](https://v1.hysteria.network/docs/protocol/)：标准 QUIC/RFC 9000 与不可靠 DATAGRAM 扩展；全部多字节数为大端。
- 官方 v1.3.5 源码固定为 [`57c5164854d6cfe00bead730cce731da2babe406`](https://github.com/apernet/hysteria/tree/57c5164854d6cfe00bead730cce731da2babe406)，检查 core/cs 的协议、客户端、服务端、分片、stream，以及 UDP/WeChat-video 包装和 app 的配置/认证/转发。
- sing-box 固定 [`c005f35300ce76427dc285481ec5695f5b179cd2`](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/protocol/hysteria/outbound.go)，其 sing-quic 依赖为 [`7e0a5869a5f49ed0a685143345dfda0448bbc708`](https://github.com/SagerNet/sing-quic/tree/7e0a5869a5f49ed0a685143345dfda0448bbc708/hysteria)。该独立 hysteria 目录含双端、xplus、UDP 分片与拥塞实现；不以旁边的 hysteria2 目录代替。
- mihomo 固定 [`3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8`](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/hysteria.go) 只有本轮登记的客户端入口，另有 UDP/Fake-TCP/WeChat-video 条件；不能推定有对应服务端。

## 必须独立实现的契约

| 项目 | 线格式或语义 |
| --- | --- |
| 控制流 | 首个客户端双向流发送 version=3、两项 u64 BPS、u16 长度及不透明认证字节；服务端返回 OK、两项 u64 BPS、u16 消息长度及消息 |
| 鉴权 | 客户端必须等 OK=1 后才打开业务流；服务端鉴权完成前不能创建网站目标资源。字符串与 base64 认证归一为同一组字节，不能绕过跨节点重复凭据检查 |
| 速率方向 | 服务端发送上限与客户端接收提示取较小值，服务端接收提示与客户端发送值取较小值；客户端发送再与服务端接收提示取较小值。官方服务端 0 表示跟随客户端提示，客户端 0 为非法 |
| TCP 请求 | 独立双向流：类型 0、u16 主机长度、主机、u16 端口；服务端必须返回 OK/u32 UDP 会话号/u16 消息，TCP 成功后再转发业务 |
| UDP 请求 | 类型 1，目标仅可作为提示，允许空主机/零端口；服务端不能据提示限制该会话的其他目标。每会话使用独立业务 UDP socket、独立端口和唯一 u32 会话号 |
| UDP hold stream | 数据流必须保持打开；流结束即清理对应 UDP socket、分片状态和回写任务，不以 QUIC 连接仍存活推定 UDP 会话仍有效 |
| UDP 消息 | 会话号、u16 主机长度/主机、端口、u16 消息号、u8 分片号/分片数、u16 数据长度/数据；每包可换目标，零负载与会话结束不同 |
| 分片 | 超出实际 QUIC DATAGRAM 上限时整包分片或丢弃；全部分片完整后才转发。以会话号和消息号隔离，核对目标/数量，拒绝冲突，设置数量、总字节与超时上限；缺片不交付部分负载 |
| 多流复用 | 同一已鉴权 QUIC 连接上的多个 TCP/UDP 流独立限额与取消，认证、端点及连接池不跨节点共享 |

官方 v1.3.5 的分片接收器一次只保存一组消息状态，因此并发分片交错会影响该对端；本项目发送端会按连接串行提交单包全部分片，接收端仍独立按会话/消息组装，不仿照其单组缓存缺陷。

## 物理载体与混淆

- 普通 UDP 与 WeChat-video 都是 UDP socket，能够由 Rust/Quinn 实现双端。官方 [WeChat 包装](https://github.com/apernet/hysteria/blob/57c5164854d6cfe00bead730cce731da2babe406/core/pktconns/wechat/obfs.go) 是 13 字节头部加实际载荷；序号为大端 u32。它可与 xplus 组合，顺序为 WeChat 头、xplus 盐、被掩码的 QUIC 载荷。
- xplus 每个 UDP 数据报独立生成 16 字节盐，掩码为 SHA-256(key || salt)，循环 XOR 32 字节。它不是 Hysteria2 的 Salamander，也不提供额外身份认证；报文真实性仍由 QUIC/TLS 负责。错误或过短数据报丢弃，不回退到无混淆模式。
- GSO/GRO 不能把多包只加一份盐或头部。本轮套接字适配逐包收发，不启用 GSO/GRO/ECN；包装层仍按接收 stride 剥离各包，不把多包混成一个 QUIC 报文。套接字所有者退出时显式关闭自己的克隆句柄，避免 QUIC 驱动的关闭计时器推迟端口回收。
- 本轮固定 QUIC 路径 MTU 为 1200。最大 29 字节包装加 IPv6/UDP 头仍不超过 IPv6 最小 MTU；不把该选择当成吞吐最优或 PMTUD 已验证。

Fake-TCP 需要独立原始套接字实现与网络边界，不借普通 TCP socket 冒充，也不为测试改 worker 防火墙/RST 策略。端口跳跃依赖额外 socket/迁移/多端口接入，本轮不提供参数或静默忽略；两者留待独立任务。

## 拥塞与协商速率边界

固定 Quinn 来自 xray-rust `9b06d37466492242a1827f9a16aa91ca4c1b00be`，quinn-proto 0.11.16 的 Controller 有实际接入发送路径的 `pacing_rate()`，可以对每条连接独立更新协商发送速率，同时保留 Cubic、NewReno 或 BBR 的原始 ACK/丢包控制。

本轮选择上述三种**明确命名的标准控制器和协商速率 pacer**。每条控制器在创建时有独立速率状态；鉴权完成后只更新当前连接，不共享节点级可变速率。握手阶段保留标准控制器，避免提前应用未协商速率。

不提供 Brutal 开关，也不将此实现称作 Brutal。固定 [Brutal](https://github.com/SagerNet/sing-quic/blob/7e0a5869a5f49ed0a685143345dfda0448bbc708/hysteria/congestion/brutal.go) 按逐包 ACK/丢失计数计算滑动窗口与补偿；当前 Quinn 的 `on_congestion_event` 只给出聚合 lost_bytes。精确移植需要额外依赖接口/适配，未进行该变更；用 lost_bytes/MTU 近似不是等价实现。功能互通不证明丢包性能、吞吐或完整 Brutal 行为。

## 统一目标访问与生命周期

服务端 TCP 全部交给 `AccessService::connect_tcp`。每个 UDP 会话只建立一次 `AccessService::associate_udp`，由统一出口处理逐包域名解析、IPv4 优先与目标选择，不能在协议里自行拨号或每个目标另建 socket。配置阶段声明 requires_udp_association，出口不具备该能力时拒绝。

接入 IPv4/IPv6 节点持有不同认证字节，指纹按解码后的实际凭据生成；同证书、同混淆参数不意味着共享认证。QUIC 载体、逻辑流和 UDP 关联取得节点/全局预算，队列及分片存储有界。节点开始排空后拒绝新载体/逻辑流，已有业务在截止时间内退出，再强制取消并回收端点。UDP 请求和目标回包都执行节点包长策略。

## 首轮完整范围

1. `hysteria1` 独立 Rust 客户端与节点，固定 version=3，TLS 1.3、证书/名称校验与可配置 ALPN。
2. 普通 UDP/WeChat-video 两载体 × none/xplus 两混淆条件 × Cubic/NewReno/BBR 三种标准控制器，两角色分别验收。
3. 字符串/base64 认证与节点多凭据；TCP、固定目标 UDP 出站及多目标 UDP 关联；IPv4/IPv6/域名与跨族访问。
4. 完整 UDP 分片/重组，单包发送串行化、乱序/重复/冲突/缺片/超时/上限；会话关闭和过期后不接受旧会话数据。
5. 真实逻辑流并发、同 socket 多目标及回写地址、半关闭、目标先发数据、错误鉴权/证书/ALPN、取消、超时、排空、重绑。
6. TCP-only 是真实能力裁剪：关闭 DATAGRAM 协商和 UDP 接口；节点禁用 UDP 时拒绝请求，不预建不可用关联。

首轮代码、接口、测试与工具全部写齐后，在 perf-02 统一构建与验证。本地只编辑、阅读、同步与仓库管理。

## 依赖、许可和对端矩阵

Rust 仅复用已有 Quinn/rustls/Tokio/socket2/sha2/rand/bytes 等原语；额外直接引用当前已锁定的 quinn-proto 0.11.16 以适配控制器回调，并用 [subtle 2.6.1](https://github.com/dalek-cryptography/subtle/blob/2.6.1/Cargo.toml) 的常量时间比较核对认证字节；其许可为 BSD-3-Clause。QUIC/TLS 使用项目固定 git/锁文件，不引入 Hysteria2 或仅客户端协议库来代替 v1。官方 v1.3.5 本体声明 MIT，另明确 -tags gpl 构建的程序为 GPLv3；sing-quic 为 GPL-3.0-or-later；它们用于规范、固定行为和隔离参考对端，不把其 Go 源码复制进内核。Quinn 子包声明 MIT OR Apache-2.0；项目整体许可仍由总状态维护。

已完成的限定验证：

- 固定 sing-box 1.14.4：普通 UDP × none/xplus × 三控制器 × 双方向，共 12 组；一节点用 auth_str，另一节点用 base64 的认证字节。
- 固定官方 v1.3.5：普通 UDP/WeChat-video × none/xplus × 三控制器 × 双方向，共 24 组；不把仅客户端结果外推服务端。
- 自端额外执行 TCP-only、零包、多目标同 socket、多个 UDP 会话交错分片、会话关闭、取消、流/包长限额和端点退出；检查同连接创建并发与独立凭据。

已读源码的已知对端限制：官方 v1.3.5 的 app UDP relay 与服务端业务 UDP 回写均使用 4096 字节缓冲，且 app relay 的 `n>0` 条件不转发零包。因此官方 CLI 的大包/零包不能继承本项目或 sing-box 结果。正式矩阵按 4096 字节边界验收，另保留两方向三种目标各 8192→4096 字节负例。固定 sing-box 转发路径首轮 12000 字节只回 8192，正式正例按 8192 边界完成，另保留两方向三种目标各 12000→8192 的负例；内部截短来源未完全定位，不推定为所有构建或协议上限。不拼包掩盖截短，外部零包未验。

官方 v1.3.5 的 Pipe2Way/PipePairWithTimeout 只等待任一方向错误，随后调用方关闭两侧，不能保证 FIN 后反向排空。通用 Hysteria v1 出站因此保守登记 tcp_eof=false；自端节点仍实现并测试独立 FIN。真实对端普通载荷先收完再关闭，半关闭语义另外记录，不改写为兼容。

实际命令、失败修复、退出码、UDP 与 FIN 边界及同快照摘要见[测试记录](../../docs/testing/hysteria1.md)。标准控制器互通不等于 Brutal、吞吐或丢包性能已验。
