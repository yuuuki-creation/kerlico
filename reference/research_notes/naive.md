# Naive（P-21）详细研究与完整首轮范围

日期：2026-10-31。状态：**限定范围已验收并冻结：perf-03原生26项、严格检查/构建、156/156配置的900条常规检查、同进程双端28条检查通过。** 原对端包长、空包、EOF限制与未支持项分列，详见[最终验证记录](../../docs/testing/naive.md)。本输入供1.0.0整树/发行复验使用，不将单模块结果外推整树。总表入口为[三核心协议组合支持](../reports/三核心%20协议%20组合支持.md) P-21；开发顺序遵守 [0007](../../docs/decisions/0007-protocol-development-cycle.md)。Mieru 的已验冻结目录和锁文件保持隔离。

1.0.0再分发审计后，证书测试资产改为仅保留来源元数据。原876字节DER未取得明确再分发许可，已移出源码，原始数据与r12证据仅私有保存。worker准备工具从固定官方HTTPS URL下载原始响应体，逐项校验大小、DER及SPKI摘要；测试通过 `KERLICO_TEST_ASSETS_DIR` 只读私有文件，不联网。该测试增量在perf-03新冻结 `native-assets-r1` 通过完整26项、严格Clippy、fmt、限定CLI及探针构建，另有6项资产控制通过；生产SPKI事实值拒绝集和TLS生产部分与r12相同，既有互通范围仍按r12记录。

## 1. 固定来源与实际依赖

以下版本由官方 GitHub release、tag 到 commit 解析及源码核对，时间点为本次研究。`latest` 只用于查到版本，复现使用完整 SHA；源码缓存只读，不在其中开发或构建。

| 来源 | 固定版本 / commit | 角色与许可 |
| --- | --- | --- |
| sing-box | v1.14.4；`c005f35300ce76427dc285481ec5695f5b179cd2` | Naive 入站原生 Go；出站需 `with_naive_outbound` 和 Cronet；GPL-3.0-or-later |
| 官方 NaiveProxy | v154.0.8037.49-5；`d04efe1ea4477c2db24a7d0e2f068b3bee931e45` | Chromium 网络栈客户端，也有 HTTP/SOCKS 本机接入；项目根和 Chromium 源码 BSD-3-Clause，第三方组件另有许可证 |
| 官方推荐 forwardproxy 分支 | v2.11.7-naive2；`e747854e78743dba85c039b38ed185fb11d93667` | Caddy 服务器插件；Apache-2.0 |
| sing-box 实际 cronet-go | `v0.0.0-20260912104727-0d28acc44093`；`0d28acc44093df24b2526dea3d6ffefd6b0a54f0` | GPL-3.0-or-later Go 包装器；不是最新 release 标签的自动替代 |
| 上项实际 Chromium/Naive 子模块 | SagerNet/naiveproxy `72a06c9fca0e2d228588c7f3074bf7efff3ff686` | Cronet 定制分支；与官方最新客户端分开固定 |
| 上项平台库模块 | cronet-go/lib/* `c10c03c318db` | sing-box go.mod 所锁预编译平台库来源；首次实际取用必须再保存完整 SHA、库摘要和构建信息 |
| sing-box 实际 sing | `5dc452e537bf75c5c51c54c8c4a4be1d19d85c4f` | UoT v1/v2、地址序列化；GPL-3.0-or-later |
| forwardproxy go.mod 声明 Caddy | v2.8.4；`7088605cc11c52c2777ab613dfc5c2a9816006e4` | Apache-2.0；其声明 quic-go v0.44.0 |
| 当前插件发布流程使用的 Caddy | v2.11.7；`72dd0fb067f6d7826c7f79907670ba4a713bfe37` | Apache-2.0；Go 1.26.0；必须应用同固定插件仓库随附的两项发布补丁 |

forwardproxy 调用 Caddy `IdleTimeoutsFromContext`，而插件 go.mod 仍声明旧 Caddy。固定[发布工作流](https://github.com/klzgrad/forwardproxy/blob/e747854e78743dba85c039b38ed185fb11d93667/.github/workflows/build.yml)先以 `CADDY_VERSION=v2.11.7` 取源码，再应用同仓库的 `caddy-sing-quic-bbrv1.patch` 与 `caddy-read-idle-timeout.patch`。前者改用 SagerNet QUIC 与 BBRv1，后者回移空闲期限覆盖 API。原插件与 stock Caddy v2.11.7 在 perf-03 实际因缺该 API 编译失败；按固定上游流程的复现构建已通过，但不是未修改 Caddy 或原二进制资产。Go padding 参照与 Caddy 各用独立模块，保存各自首次 resolver 及 `go version -m`，避免前者的 QUIC mod.12 覆盖服务端工作流声明的 mod.9。

Caddy 归档 SHA-256：`e86c49311c0c9f7e9b3b80527f0139e5739dfe28effeaa41c444dd743f0bbd7e`；上述两补丁依次为 `298a057cf1640718a14157bcd22a37575538adffba5189e7a7ecd54bffe7cb8e`、`02583f364374e9461cee9b954349b87e0390d600319beafcf52ebcc5e2947eab`。补丁只施于 worker 测试副本，原缓存不改，插件代码不改。

固定 sing-box codeload 归档 SHA-256：`1c4d2b3bf261a8d98e1b026be0bbcddbcb3f53bbca77eb15e8f25f7d4e602e59`。forwardproxy 固定 commit 归档：`a3b9c1f5fd50b9f1235263960bf810a3e9f0dc59715cb562b39a187fc5ed8015`。NaiveProxy 体积较大，本次按 API 完整树和固定 raw 路径取研究所需文件，逐文件摘要留只读缓存；不把局部源码当完整 Chromium 构建输入。

官方 Linux x64 客户端 release 资产 `naiveproxy-v154.0.8037.49-5-linux-x64.tar.xz` 的 GitHub release API digest 为 `sha256:80214dfea1767f6ecf63a3a79dc9f48b203460f51abc609357fff48dd5844c7d`。该归档已在 perf-03 按此 digest 校验，二进制为 `f86c52be454eebc9134aad476f3fe91fcf90df7200c3df262a4d0a3d2de85464`，限定TCP客户端组合通过；EOF限制另列。版本字符串不能独立证明来源。

主要固定证据：

- [sing-box 入站](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/protocol/naive/inbound.go)、[padding](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/protocol/naive/inbound_conn.go)、[HTTP/3 入站](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/protocol/naive/quic/inbound_init.go)、[出站](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/protocol/naive/outbound.go)、[go.mod](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/go.mod)。
- [Naive 协议标识](https://github.com/klzgrad/naiveproxy/blob/d04efe1ea4477c2db24a7d0e2f068b3bee931e45/src/net/tools/naive/naive_protocol.h)、[协商](https://github.com/klzgrad/naiveproxy/blob/d04efe1ea4477c2db24a7d0e2f068b3bee931e45/src/net/tools/naive/naive_proxy_delegate.cc)、[framer](https://github.com/klzgrad/naiveproxy/blob/d04efe1ea4477c2db24a7d0e2f068b3bee931e45/src/net/tools/naive/naive_padding_framer.cc)、[padding socket](https://github.com/klzgrad/naiveproxy/blob/d04efe1ea4477c2db24a7d0e2f068b3bee931e45/src/net/tools/naive/naive_padding_socket.cc)。
- [forwardproxy 认证、CONNECT、H1 与双流实现](https://github.com/klzgrad/forwardproxy/blob/e747854e78743dba85c039b38ed185fb11d93667/forwardproxy.go)、[其 go.mod](https://github.com/klzgrad/forwardproxy/blob/e747854e78743dba85c039b38ed185fb11d93667/go.mod)。
- [cronet-go 客户端](https://github.com/SagerNet/cronet-go/blob/0d28acc44093df24b2526dea3d6ffefd6b0a54f0/naive_client.go)、[padding](https://github.com/SagerNet/cronet-go/blob/0d28acc44093df24b2526dea3d6ffefd6b0a54f0/naive_conn.go)、[构建要求](https://github.com/SagerNet/cronet-go/blob/0d28acc44093df24b2526dea3d6ffefd6b0a54f0/README.md)。

## 2. 入站、出站与传输的真实边界

Naive 的代理业务是 CONNECT 双向字节流；HTTP/2、HTTP/3 提供一个物理连接中的多个独立请求流。它不是 V2Ray transport，也没有另外的通用 mux、TUIC 命令或 SOCKS UDP 原生扩展。

| 载体 | 固定 sing-box | 官方客户端 / forwardproxy | 本轮处理 |
| --- | --- | --- | --- |
| TCP + TLS + H2 | 入站原生；出站 Cronet | 官方主要路径；插件双流并按 Padding 处理 | 双端，包含真实并发复用 |
| UDP + QUIC + H3 | 入站 quic-go；出站 Cronet QUIC | `quic://` 代理使用 HTTP/3 CONNECT | 双端，QUIC v1、ALPN h3，包含真实并发复用 |
| TCP + TLS + H1 | sing-box 入站 hijack 后仍启用 Naive padding | 当前官方客户端有 H1 HTTPS 失败 TODO；固定插件 H1 明确不做流 padding | 实现 strict padded 双端；只按 sing-box H1 路径验收，不登记固定 Caddy H1 兼容 |
| 明文 HTTP / h2c | sing-box 入站可启用 | 官方可配置 HTTP 代理，不能据此视为安全公网节点 | 不提供；配置拒绝，不传明文口令 |
| QUIC v2、gQUIC、H3 datagram、MASQUE CONNECT-UDP | 不是本项既定线格式 | 不由 `quic` 名称推定 | 不提供，不以原生 UDP 载体宣称业务 UDP |

H1 差异有直接源码证据：固定 sing-box `ServeHTTP` 的 Hijacker 路径使用 `naiveConn`；固定 forwardproxy `serveHijack` 调用 `dualStream(..., false)`，即使响应带 Padding 也不启用流填充。后者与其 H2/H3 的 `dualStream(..., request.Padding != "")` 不同。本轮不添加“猜测首包是否填充”的自动回退；该官方插件 H1 组合保留为已知线格式不兼容，不能在真实对端表中勾通过。原始 HTTP 通用代理由 P-02 实现。

Cronet 的 `-connect-authority`、`-force-quic`、`-network-isolation-key` 是其包装器的内部控制字段。在固定子模块 [spdy_http_utils.cc](https://github.com/SagerNet/naiveproxy/blob/72a06c9fca0e2d228588c7f3074bf7efff3ff686/src/net/spdy/spdy_http_utils.cc) 中，`-connect-authority` 被转换成 `:authority` 并跳过正常字段输出；[bidirectional_stream.cc](https://github.com/SagerNet/naiveproxy/blob/72a06c9fca0e2d228588c7f3074bf7efff3ff686/src/net/http/bidirectional_stream.cc) 先移除另两项。因此 Rust 侧发送标准伪头，不把私有字段当线协议需求，也不利用它们容忍错误 H3 伪头。

### HTTP CONNECT 与共享 H3 原语

普通 CONNECT 的目标只在 `:authority`，不得携带 `:scheme`、`:path`、`:protocol`；见 [RFC 9114 §4.4](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.4)。H1 用 authority-form，IPv6 必须方括号；H2/H3 业务目标和 TLS SNI 是两件事，不能用节点 SNI 覆盖目标。

现有 h3 0.0.8 发布源码 `src/proto/headers.rs::Pseudo::request` 给普通 CONNECT 也补默认 scheme/path，固定插件将明确拒绝。主任务已安排共享 `third_party/h3` 最小受控修正：回移官方条件并修正 classic CONNECT 的实际伪头数量；Naive 使用该共享类型，不再复制 h3/h3-quinn。共享修正已在perf-01独立原语工作区通过16项headers/QPACK回归及默认/all-features lib检查，`src`集合SHA-256为`5f5e413390b41101b8d63e93dcd1ff099b5fbd2d6667e110571909757bd450e7`，`headers.rs`为`bfed028d619cbb5755f35a03357c69dab2cba3f0aa50cea004fe26e8d03723c3`。此后唯一性/顺序增量另在perf-01通过21项原语；最终headers摘要`484e98d6507cc5abc6a7d1d03a8a2e9e36a33ca32258e2170b1fcf583a852805`、src集合`bc8781bbbb1dae4552ac663d83b4a622e56e1e51bd5f5d4a87e3bdbcd0e9cc9b`。Naive r9纳入该新输入，并通过实际QUIC/QPACK负例；原16项和旧整树结果不外推。字段角色/trailer的完整HTTP/3规范覆盖未登记。

## 3. TLS、认证和 padding

公网两端 TLS 必选，H3 强制 TLS 1.3。出站校验服务器名称与可信链；不提供 `insecure`、跳过 SNI、REALITY、uTLS、Chrome 指纹名称或未经实现的 ECH 开关。TLS 接入层按本节点证书配置建立，不共享其他节点的认证表。

`Proxy-Authorization: Basic base64(username:password)` 是每个 CONNECT 的认证材料，TLS 才提供其传输保密。用户名非空且不含冒号/控制符，口令非空；限制总字节数及请求头大小。逐用户采用完整凭据的秘密指纹，沿用 HTTP 的真实认证域 `http`：`SHA256(b"kerlico/http\0" + canonical Basic header)`；TLS、载体和 padding 不新增身份域。这样现有 HTTP 节点与 Naive 节点也不能复用同一整组 Basic 凭据；不得拿用户名摘要代替实际秘密指纹。拒绝重复认证头、冲突目标头、错误密码、非 CONNECT 和非法 authority；失败不回退到其他节点或其他凭据。

官方最新客户端 v154.0.8037.49-5 为证书安全更新。[-4 到 -5 的固定差异](https://github.com/klzgrad/naiveproxy/compare/v154.0.8037.49-4...v154.0.8037.49-5) 只修改 `net/cert/cert_verify_proc_blocklist.inc`，追加八个已被入侵 eMudhra 中间证书的 SPKI 摘要。原生模块计划在标准 WebPKI 校验之外，对叶和对端提供的中间证书执行本次固定上游 SPKI 拒绝集；它只增加拒绝，不绕过名称/链/签名验证。解析使用已锁 `x509-parser` 0.18.1。该快照不是自动更新服务；也不宣称包含 Chrome 的全部根证书政策、CT、CRLSet、吊销获取和动态黑名单。

padding 规则：

1. 请求 Padding 值使用不能被 HPACK Huffman 有效缩短的字符，随机长 16..32；响应 30..62。固定 Go 服务端实际 `rand.Intn(32)+30` 为 30..61，二者都只承载长度扰动，不是认证标签。
2. 当前官方客户端发送 `padding-type-request: 1, 0`。类型 1 是前八个记录填充，类型 0 为原流。本轮安全 Naive 出站只请求类型 1，不降级成普通代理。入站接受明确请求包含 1，或旧式非空 Padding；未知/无共同类型拒绝，明确回应类型 1。对旧服务端兼容：缺少 `padding-type-reply` 但非空 Padding 时采用类型 1；无 Padding 或非法 reply 拒绝。
3. 每个方向各自计数前八帧。记录为 `u16be payload_len | u8 padding_len | payload | padding`；padding 长 0..255；payload 不超过65535，超长写入拆分。第九帧起是原始字节流。记录边界与 HTTP DATA、TLS record、QUIC stream 读取边界互不等同。
4. 解码跨短读保留完整状态；零 payload 的合法 padding 帧要消耗且继续，不能向调用方伪造 EOF。截断长度、payload、padding 分开报错；EOF 只在完整边界解释为流结束。
5. 官方的 H2 RST_STREAM 前附加带 padding 的 END_STREAM、HEADERS 排布、preamble GET、TLS ClientHello 和连接策略是另一些流量行为。本轮实现应用线格式和受限 header padding，不声称复现整套浏览器流量分类特征。

客户端先等待认证响应再发送业务数据，不使用基于缓存能力的 Fast Open；服务端可以按标准读取已缓冲的早到 DATA，但不接受 QUIC 0-RTT 认证重放。拒绝原生重试中重放业务字节。TLS 握手/认证超时、流数、头大小、缓冲、背压与取消均须有实际限额。

## 4. TCP、UDP 与 Full Cone

Naive 本体只提供 CONNECT 流。业务 UDP 是 sing 的 UoT 扩展；H3 的物理 UDP 监听并不自动提供网站 UDP。官方 forwardproxy 只把 CONNECT 目标作为真实 TCP 目的地，不认识 UoT 保留域名，不能在其上登记 UDP 支持。

固定证据：[UoT 协议](https://github.com/SagerNet/sing/blob/5dc452e537bf75c5c51c54c8c4a4be1d19d85c4f/common/uot/protocol.go)、[包编码](https://github.com/SagerNet/sing/blob/5dc452e537bf75c5c51c54c8c4a4be1d19d85c4f/common/uot/conn.go)、[客户端](https://github.com/SagerNet/sing/blob/5dc452e537bf75c5c51c54c8c4a4be1d19d85c4f/common/uot/client.go)、[sing-box 入站路由](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/common/uot/router.go)。

- v1 连接保留域名 `sp.udp-over-tcp.arpa`，无初始 request，每包带目标。
- v2 连接 `sp.v2.udp-over-tcp.arpa`，先发 `isConnect:u8` 与标准 SOCKS 地址；0 为逐包目标，1 为固定目标。固定sing客户端的保留域名authority带端口0（`RequestDestination`未设置Port、`metadata/addr.go::String`明确JoinHostPort）；本模块入站仅将这两个保留域名的0端口归一化到内部占位1，普通目标0仍拒绝。原生出站使用占位1，服务端按保留域名识别，不把它交给网站DNS。
- 逐包地址的族标记与 SOCKS 不同：IPv4=0、IPv6=1、域名=2；域名带 u8 长，地址后为 u16be 端口，再 `u16be length | payload`。v2 初始地址仍是 SOCKS 标记1/4/3，不能混用。
- 空包长度0必须保留；协议可编码65535字节，但实际 IP UDP 和运行时限额更低。原生验收目标0/17/1200/12000/65507；65535作为内存线格式向量和超限用例，不假装IP UDP能发送它。
- TCP 业务经 `AccessService::connect_tcp`。v2固定 UDP 经 `connect_udp`；v1/v2多目标 UDP 经同一个 `AccessService::associate_udp`，保持一个远端真实 socket 的 Full Cone 语义和真实响应来源。禁止以每目标一条固定通道冒充关联。
- Naive 出站同时提供 `connect_udp` 和 `associate_udp`。v1固定接口可在逐包线上写固定目标，并验证返回来源；v2固定使用connect模式。多目标默认v2，可显式选v1。入站有UoT时声明 `requires_udp_association`，让配置准备阶段拒绝不支持多目标的目标出口。
- 凭据、HTTP会话池、padding协商和UoT关联都按出站/节点实例隔离。IPv4/IPv6接入节点独立建身份，目标地址族交给统一访问服务，不从接入地址族推定网站地址族。

原生流会把写端 shutdown 映射为 H1 TCP/TLS 写 EOF、H2 END_STREAM 或 H3 FIN，并保留反向读取。是否能登记最终目标 `tcp_eof=true` 要由真实目标等待 EOF 后回复的独立测试决定；官方客户端、sing-box和插件实现差异必须单列，不能仅凭 HTTP 有 END_STREAM 推定真实对端全部通过。

## 5. Rust 原语、许可及接口需求

业务运行时全部 Rust；不链接 Cronet，不启动官方 Naive、Go或Caddy进程承载 kerlico 业务。这些程序只在测试工具中作为独立对端。

| 原语 | 固定基础 / 许可 | 用途 |
| --- | --- | --- |
| rustls / tokio-rustls | 项目已有 rustls=0.23.40 与固定 shaped-rustls patch；Apache-2.0 OR ISC OR MIT / MIT OR Apache-2.0 | 正常TLS链、名称和签名验证；自有证书配置 |
| h2 | 当前锁0.4.20；MIT | 直接控制H2 CONNECT、DATA背压、END_STREAM及复用 |
| http / bytes / tokio | 现有依赖；MIT OR Apache-2.0 / MIT / MIT | HTTP头、缓冲、异步I/O与取消 |
| h3 / h3-quinn | 0.0.8共享受控修正 / 0.0.10现有固定patch；MIT | 标准H3 CONNECT和请求流；不另引入重复类型 |
| quinn | 0.11.9及项目已有固定xray-rust patch；MIT OR Apache-2.0 | QUIC v1、流限额/空闲、客户端端点和服务端socket |
| x509-parser | =0.18.1；MIT OR Apache-2.0；crate SHA-256 `d43b0f71ce057da06bc0851b23ee24f3f86190b07203dd8f567d0b706a185202` | DER证书SPKI拒绝集校验，不替代WebPKI |
| sha2 / rand / base64 / socket2 / rustls-pemfile / webpki-roots | 现有Rust依赖；沿用各自已登记许可 | 凭据摘要、随机header/padding、Basic、socket、证书根 |
| rcgen | 现有测试依赖；MIT OR Apache-2.0 | 临时测试CA/证书；不安装系统根 |

实际包为 `kerlico-naive`，导出 `NaiveFactory` / `NaiveNodeFactory`，注册名 `naive`，根/app已完成双向接线。H1/H2提供 `build_with_connector`；H3明确拒绝该构造，默认QUIC端点仅负责代理接入地址，业务目标不自行拨号。

没有新增共享核心API：沿用 `Outbound`、`InboundProtocol`、`AccessService`、`DatagramAssociation`、`StreamBudget`、分域凭据指纹和物理socket元数据。h2与x509-parser为包内依赖；共享h3修正已按固定摘要纳入r12冻结构建。

## 6. 本轮完整首轮编码范围

以下各项须全部写齐生产代码、接口、Rust测试、独立对端工具，之后才在perf-03统一构建；不在H2最小路径写完后提前测试。

1. 独立协议模块、双端Factory、严格配置校验；H1 padded / H2 / H3三载体，TLS必选，按角色注册，节点用户凭据独立。
2. header与padding协商、8帧双向增量codec、完整边界错误、短写/大写拆分；不向网站泄漏代理认证头。
3. H2/H3真实并发复用与有界连接池；每流读写背压、取消、EOF、RST/STOP_SENDING、空闲、物理连接断开、过载、GOAWAY后新流策略；不重放已发送业务数据。
4. UoT v1/v2，固定与多目标、空包、大包、IPv4/IPv6/域名、真实 Full Cone、来源保留；与统一访问及限额契约一致。
5. TLS校验、固定SPKI拒绝集、多用户认证和跨节点秘密去重；配置拒绝无TLS、错误transport、未知字段/协商类型、未实现浏览器开关和无关联能力的出口。
6. Rust codec/双端/原始负例/资源回归测试；官方客户端资产获取校验工具、固定Caddy+插件服务器构建工具、sing-box双角色配置及互通驱动；示例仅测试身份和保留域名。
7. 接口文档及逐组合测试表同步写齐，未运行项标记待验；首次resolver锁/源码清单/二进制摘要私有保存，不覆盖Mieru或共享根锁。

不包含：明文HTTP/h2c、普通网页反向代理或Caddy probe-resistance整站伪装、官方preamble流量模型、Chrome TLS/HTTP指纹复现、ECH/REALITY/uTLS、QUICv2/0-RTT、gQUIC、MASQUE、原生UDP datagram和通用V2Ray/mux组合。以上都应配置拒绝或保持未支持，不能新增无效开关。

## 7. 独立对端、构建条件与验收矩阵

只在perf-03新的项目私有目录执行。先查看当时资源和作业，构建并发1，保留已有服务，不改系统证书、网络/sysctl或全局工具链。参考进程只绑定回环并使用临时身份。已有sing-box资产须检查真实build tags，不能从版本号推定含`with_naive_outbound`。

官方Naive客户端只在归档digest校验后使用。该固定版本的 [src/build.sh](https://github.com/klzgrad/naiveproxy/blob/d04efe1ea4477c2db24a7d0e2f068b3bee931e45/src/build.sh) 明确设置 `use_nss_certs=false`；其 [TrustStoreUnix](https://github.com/klzgrad/naiveproxy/blob/d04efe1ea4477c2db24a7d0e2f068b3bee931e45/src/net/cert/internal/system_trust_store.cc) 明确读取 `SSL_CERT_FILE` / `SSL_CERT_DIR`。实际测试只给该参考子进程设置项目CA文件与项目空证书目录，保留链、名称与签名校验，不改用户或系统信任库。XDG缓存/数据/配置和临时目录也指向本项工作区。先前按通用Chromium NSS分支创建的项目私有库不适用于该资产，其准备失败和证书-202结果保留；NSS辅助程序已从本项运行依赖移除。官方H1本机监听可作为独立padding参照，但不等于其H2/H3客户端验收。

forwardproxy 本项只作为TCP业务服务器；UoT独立对端使用固定sing-box入站/出站，必要时创建直接调用固定sing的测试peer。含Cronet的参考构建需Chromium工具链与平台静态库（Linux glibc最低2.31），单纯普通Go构建不足；已有资产若不含该功能，先记录再在项目目录固定相应参考，不能让它成为产品运行时。官方Chrome客户端的UDP功能不由SOCKS监听推定，未证实前不登记它的UoT。

| 验收层 | 覆盖内容 | 当前状态 |
| --- | --- | --- |
| 原生线格式向量 | padding第1/8/9帧、0/65535 payload、0/255 padding、碎片/合帧/截断；UoT地址/模式与mapped来源 | r12 lib 9项通过；不是独立密码算法向量 |
| 原生双端 | H1/H2/H3、两种接入族、TCP/固定UDP/Full Cone、两族及域名网站目标 | r12 dual 11项与coexist 28条通过 |
| H2/H3复用 | 单物理会话多个TCP/UoT流、邻流释放、实际限额、慢下载背压、空闲回收 | 原生24并发及真实CLI对应组通过 |
| 官方Naive客户端→Rust节点 | H2/H3真实TCP与12并发；H1另列源码限制 | 12/12配置通过；原客户端EOF 12项未通过 |
| Rust客户端→上游流程Caddy | H2/H3真实TCP、两族/域名、并发、EOF；H1已知不兼容 | 12/12配置及EOF通过，不登记UDP |
| sing-box双向 | 其入站H1/H2/H3、出站H2/H3；UoT v1/v2、逐包/固定与包长分别记录 | 60/60常规配置通过；14项代表包长/空包及24项原客户端EOF限制保留 |
| 地址与认证独立 | 同进程双族节点独立凭据、交叉凭据拒绝、同名不同秘密/整组复用、跨族网站 | Registry/原生及同进程CLI对应回归通过 |
| Full Cone包级 | 单socket跨目标/地址族同端口、未联系来源、包边界/来源/取消 | Go参照72配置对应语义组及原生通过 |
| 原始负例 | authority、重复认证、padding类型/截断、UoT bool/族/长度、H3重复/顺序 | 对应已写用例通过；不宣称穷尽HTTP所有异常角色/trailer |
| TLS负例 | 错误CA/名称、SPKI拒绝值、截断DER、正常临时链；强制TLS/禁用0-RTT | 原生对应TLS/解析控制组通过；SPKI是直接解析拒绝测试，不是持有被拒证书私钥的握手测试 |
| 生命周期 | 握手/慢头/初始UoT预算、写端EOF后回包、取消、退出/重启 | r12对应回归、156生命周期场景及coexist通过；原客户端EOF限制分列 |
| 限定工具链 | 包级test、严格Clippy、fmt、实际app feature构建；共享h3单列 | r12终态0；1.0.0整树/发行复验由主任务另做 |

真实对端对空包、最大包长、半关闭或并发的限制须保留原始失败和恢复控制包，按方向、载体和版本分别记录；不能用自端通过覆盖对端失败，也不能修改外部参照使其结果冒充原资产兼容。
