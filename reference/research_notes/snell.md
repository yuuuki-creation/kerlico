# Snell 版本、角色与 Rust 实现调研

日期：2026-10-31。对应 P-10。状态：详细调研与首轮完整范围；限定范围已通过 perf-02 的检查、独立向量和固定对端矩阵，具体结果以测试记录为准。

## 固定证据

- sing-box `c005f35300ce76427dc285481ec5695f5b179cd2` 的 [出站](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/protocol/snell/outbound.go) 只注册 v4/v6，[入站](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/protocol/snell/inbound.go) 只注册 v5/v6。
- 固定依赖为 [sing-snell bc5a12ac736f235b2de2926ecd2791cc925e6b8c](https://github.com/SagerNet/sing-snell/tree/bc5a12ac736f235b2de2926ecd2791cc925e6b8c)。检查了公共 crypto/request/address/obfs、v4 客户端、v5 服务端、v6 三种记录模式、盐与 profile 派生、复用及 UDP 路径。
- [sing-box Snell 文档](https://sing-box.sagernet.org/configuration/outbound/snell/) 明确：不实现 v5 的 QUIC Proxy Mode 时，v5 普通线格式与 v4 兼容，因此不另提供 v5 出站或 v4 入站。这个限定不等于完整 v5 QUIC 支持。
- [Surge 手册](https://manual.nssurge.com/policies/snell.html) 明确：v4/v5 的 obfs 为 HTTP，v6 由 PSK 派生整形且不接受 obfs；v6 三模式为 default/unshaped/unsafe-raw，PSK 为 12–255 字节。v6 仍处 beta，可能出现不兼容变化。

## 已厘清的线格式

| 项目 | 固定证据与实现要求 |
| --- | --- |
| 加密 | Argon2id：t=3、m=8 KiB、p=1、版本 0x13、生成 32 字节后取前 16；AES-128-GCM；nonce 为小端计数器，头与体分别消耗一次 |
| 通用头 | 记录头明文 7 字节：版本 4、两字节保留、16 位大端 padding 长度、16 位大端 payload 长度；空 payload 是半关闭，不是 UDP 零包 |
| v4/v5 | 每方向 16 字节随机盐；头和非空体分别带 16 字节标签，padding 与密文的偶数位置交错；写入大小及初始 padding 随突发窗口变化 |
| v6 default | BLAKE2b-256 与固定域分隔常量派生 profile；盐嵌入 PSK 决定的块与置换；每记录前缀参与头 AAD、padding 参与体 AAD；需完整处理前缀、padding、混排、序号和半关闭 |
| v6 unshaped | 独立方向盐及 AES-GCM；无前缀/padding；不能拿它冒充 default |
| v6 unsafe-raw | 明文记录，无盐与 AEAD；PSK 本身不提供认证或保密。项目只允许回环且显式 userkey 鉴权，不能把不同 PSK 误称为彼此隔离的认证 |
| 请求 | version=1、command、client-id 长度及内容；CONNECT=1、可复用 CONNECT=5、UDP=6、PING=0；CONNECT 目标始终是主机字符串加端口 |
| 回复 | tunnel=0、pong=1、error=2；真实服务端可能把 tunnel 回复延迟到目标首包，客户端不能在允许发送业务前阻塞等回复 |
| UDP | 一条记录就是一个数据报，不能以普通字节流合并记录；请求前有 command=1，目标可为域名或带标记的 IPv4/IPv6；响应只允许字面 IP 地址，无域名 |
| 复用 | CONNECT=5 的逻辑流半关闭后可在同一加密载体继续下一个请求；须保持盐与 nonce 状态，池按节点隔离、有容量和过期时间，异常/半帧/单向未排空的载体不可复用 |

## 统一目标访问契约

Snell 不能自行解析域名再绕过 `AccessService`。原有固定目标通道只有负载，不能编码合法的域名目标 UDP 回包。主任务已实现并在 worker 验证默认可选的 `DatagramReceiver::peer_addr() -> Option<Destination>`，由统一出口报告实际选择的业务字面目标；Snell 已通过该接口验证域名 UDP 的真实字面回写。协议只使用业务元数据，不能将代理载体地址当成网站来源。若接入的自定义通道不提供元数据且原目标也是域名，明确拒绝该 UDP 关联，不伪造响应地址。

## 首轮完整交付范围

- 出站 v4、节点 v5、v6 双端；这三个配置角色按各自真实上游对端验收，不把角色互相推定。
- TCP、UDP、IPv4/IPv6/域名；v4/v5 none/HTTP obfs；v6 default/unshaped/unsafe-raw 三模式；unsafe-raw 限制见上。
- 单 PSK 与显式 userkey 多用户；独立节点凭据指纹；首连接盐重放防护。
- TCP 独立半关闭；有界顺序连接复用池；节点逻辑流预算、取消、空闲和退出回收；全部目标经统一访问服务。
- 不包括 v1–v3、v5 QUIC Proxy Mode、外加 ShadowTLS/Restls/JLS 或未复核的 TLS obfs；没有空开关或静默版本回退。

## Rust 原语与来源许可

准备使用 ring 0.17.14（AES-GCM，包声明 ISC）、argon2 0.5.3（MIT OR Apache-2.0）、blake2 0.10.6（MIT OR Apache-2.0），以及项目既有 Tokio、rand、sha2、subtle。参数使用固定值，不将默认 KDF 参数误当成 Snell 参数。不运行 Go 子进程承载业务，Go 仅可作为 worker 隔离互通对端。

另发现 meow-proxy 0.22.0 包声明 MIT，具有公开 Rust v4/v6 codec，但其 v4 文件明确写明自 opensnell/mihomo 移植；上游链路含 GPL-3.0。此处只登记来源许可未厘清，不判断其许可有效性，也不把这些源码或依赖直接加入项目。固定 sing-snell 自身为 GPL-3.0-or-later；本轮将根据公开线格式、参数与行为独立编写 Rust 适配，不复制其 Go 源码。项目整体许可仍由总状态另行确定。

## 验收矩阵

1. v4 出站↔固定 sing-box v5 节点；固定 sing-box v4 出站↔本项目 v5 节点，各自 none/HTTP obfs × reuse 开/关 × TCP/UDP。
2. v6 双向 × 三模式 × reuse 开/关；unsafe-raw 使用显式 userkey，非法公监听或缺认证必须拒绝。
3. 单/多用户、错误 PSK/userkey、跨节点身份串用、重复凭据、盐重放、非法版本/记录/长度/标签/截断与 nonce 边界。
4. 两类接入节点、两类 TCP/UDP 目标及域名；UDP 零包与记录边界，按角色记录首包长度和增长窗口限制，不用拆包掩盖超限。
5. 目标先发数据、半关闭后反向回包、多次复用同物理连接、并发隔离、取消、空闲、活动排空和端口重绑。
6. 首轮源码、接口、工具和测试全部写完后，在 perf-02 统一构建、格式、Clippy、测试与真实对端；所有未运行条目保持待验。

单 PSK 服务端接受任意 client-id，不能只把“PSK + userkey”视为跨节点凭据指纹。实现统一登记加密节点的 PSK 范围，跨节点共享 PSK 即拒绝；unsafe-raw 则只按其实际 userkey 登记。

## 首轮远端测试补充的边界

固定 sing-box 的 v6 三模式双向、复用、单/多用户 20 组已取得首轮通过；v4/v5 的 16 组在 4096 字节 UDP 处失败。单独诊断确认：本项目客户端到 sing-box 节点只收到 1402 字节，sing-box 客户端到本项目节点只收到 1162 字节。

固定 sing-snell 的 v5 [serverPacketConn.WriterMTU](https://github.com/SagerNet/sing-snell/blob/bc5a12ac736f235b2de2926ecd2791cc925e6b8c/snellv5/packet.go) 为 `1421-19=1402`；v4 客户端为 `1421-259=1162`。固定 sing-box 依赖 sing `5dc452e537bf` 的 [NewReadWaitOptions/NewPacketBuffer](https://github.com/SagerNet/sing/blob/5dc452e537bf/common/network/direct.go) 依据 MTU 分配读取缓冲。数值与实测截短长度吻合；这不是本项目的记录层上限，不能靠接收后拼包恢复原始边界。最终完整 36 组矩阵已按这些对端边界通过正例，并独立保留 4096 字节截断负例；不将负例改写为大包兼容。

另确认 v5 的非复用服务端在上游 EOF 后会直接关闭 TCP，不一定发零块。实现已补充完整记录边界的物理 EOF 与帧内截断区分，同时禁止物理已关闭的载体进入复用池；该增量及对应回归已在 r6 通过，并用冻结 CLI 复跑全部 36 组。

收尾的 r7 另补齐目标 UDP 回包的节点包长校验，4 字节边界正/负例通过，并在同一新 CLI 上完成 snell-peer-r4 的最终 36/36 组复验；详细摘要见测试记录。
