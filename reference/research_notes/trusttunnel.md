# TrustTunnel 双端、载体与统一出口调研

日期：2026-10-31。对应唯一总表P-18。**状态：按主任务风险中断要求停止原验证，已做只读交接，尚未完成交付。** 最后完整包级通过为perf-02 r12的20项Rust及选定包/CLI检查；本地H2连接credit和新增第21项回归仅已写，未同步/未编译/未测。真实矩阵有通过、失败及路由无效记录，见[测试交接](../../docs/testing/trusttunnel.md)。具体风险触发动作/原因未知；不恢复中断步骤，ShadowTLS也保持停止。

## 固定版本与目录证据

| 来源 | 固定对象 | 结论边界 |
| --- | --- | --- |
| [Mihomo 出站](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/trusttunnel.go)、[服务端](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/listener/trusttunnel/server.go) | 3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8 | 出站显式选择 H2/TLS 或 H3/QUIC；入站注册两类物理监听，有 Basic 用户表及通用 TLS/mTLS 配置 |
| [sing-box 注册表](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/include/registry.go)、[出站选项](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/option/outbound.go) | c005f35300ce76427dc285481ec5695f5b179cd2 | 未登记 TrustTunnel；不等于其通用 HTTP/SOCKS 类型已经实现本协议 |
| [Xray 配置](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/xray.go)、[总导入](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/main/distro/all/all.go) | 0afec66085a85191e9dd2a4a6646c7c9a94688d1 | 未登记 TrustTunnel，不据普通 CONNECT 能力补填 UDP/ICMP |
| [官方服务端稳定版](https://github.com/TrustTunnel/TrustTunnel/tree/fab5b8353a19332f935fa30869307d37d4a898d1) | v1.1.0，fab5b8353a19332f935fa30869307d37d4a898d1，2026-09-01 发布 | Rust endpoint，库包自身版本为0.1.0，二者不是同一个版本号 |
| [官方客户端稳定版](https://github.com/TrustTunnel/TrustTunnelClient/tree/c0990e174fc75b2e52acd15882c62e69a3022581) | v1.1.11，c0990e174fc75b2e52acd15882c62e69a3022581，2026-10-07 发布 | 业务客户端核心为 C++20，Rust CLI/设置层不是纯 Rust 协议库；官方 CLI 明确只有 http2/http3 上游选项 |

规范以官方稳定源码内 [PROTOCOL.md v1.0](https://github.com/TrustTunnel/TrustTunnel/blob/fab5b8353a19332f935fa30869307d37d4a898d1/PROTOCOL.md) 为基线，并与真实 codec 核对，不能只用 README 支持列表。

本次查询还固定服务端 HEAD 3826388ea092aad7f65b59617871f0e6278ac032（2026-10-30）、客户端 HEAD 73e52e0e668d73c1424b50443f394d93020e452a（2026-10-27）。发布列表最新服务端预发布为 v1.3.0-beta.2，客户端为 v1.3.0-rc.2；不将其称作稳定版。稳定到 HEAD 分别相差12和37个提交，PROTOCOL.md 未变。服务端主要变化包括订阅/配置与错误响应 Content-Length；客户端增加 ClientRandom auth-key 派生等功能，不静默加入本轮基础协议范围。

Mihomo v1.19.33的tag对象已核对为表中固定commit。其transport来源注释指向 sing-trusttunnel v0.1.1，已固定 879e22b30bc28dcbd1148b4395d437fbad1b76c7。该来源及 Mihomo 为 GPL-3.0-or-later；只作研究和隔离参考对端，不把其 Go 实现引入 Rust 内核。

## 真实角色与合法载体

| 载体 | 官方稳定服务端 | 官方稳定客户端 | 固定 Mihomo | 本轮计划 |
| --- | --- | --- | --- | --- |
| H1 / TLS1.2 或1.3 | 独立 Http1Codec，CONNECT 后原始双向字节；同一请求可承载 TCP、_udp2、_icmp | CLI无H1上游选项 | 客户端主动禁止 H1 回退；服务端允许 HTTP1 handler，但无 H1 专项互通证据 | 双端 TCP/固定目标UDP；每隧道独立TLS连接，不把H1叫多流复用 |
| H2 / TLS1.2 或1.3，ALPN=h2 | 支持 | 支持 | 入/出支持 | 双端 TCP/固定目标UDP，真实连接池/流限额 |
| H3 / QUIC v1 / TLS1.3，ALPN=h3 | quiche 实现 | ngtcp2 实现 | quic-go/http3 入/出 | Quinn+h3 实现双端 TCP/固定目标UDP |
| 明文 H1、h2c、任意 WS/gRPC 等 | 不是规范安全载体 | 不据此支持 | 底层有h2c样式配置是为强制H2，实际仍先TLS握手 | 不提供明文或任意传输组合 |

H1 不是仅健康检查：官方 [Http1Codec](https://github.com/TrustTunnel/TrustTunnel/blob/fab5b8353a19332f935fa30869307d37d4a898d1/lib/src/http1_codec.rs) 将 CONNECT 后数据直接交给隧道，响应带 Connection: close，没有每个 UDP 包再套 HTTP chunked 的要求。它只有一个活动 CONNECT，不能复用成 H2 那样的多流池。官方 H1 头部上限1024字节、最多32项；本项目客户端应在发送前检查实际编码长度，不能把长认证头或长目标在其他载体通过的结果外推到 H1。

Mihomo 的出站只使用 H2/H3。其入站启用 HTTP1 不足以证明原始 H1 CONNECT 的所有双向体/EOF 组合正确；仍须单列该角色结果。

### ICMP 的支持边界

[官方 ICMP codec](https://github.com/TrustTunnel/TrustTunnel/blob/fab5b8353a19332f935fa30869307d37d4a898d1/lib/src/http_icmp_codec.rs) 是 Echo 请求/响应摘要，不是任意 IP/ICMP 原样转发：请求23字节，含id、目的IP16、sequence、TTL/hop-limit、数据长度；服务端生成 Echo 数据；响应22字节，只回id、来源IP、type、code、sequence。

Mihomo 仅 transport 内置该编解码与 ListenICMP 方法。实际 listener 传入 `ICMPHandler:nil`，认证后的 `_icmp` 返回501，出站适配器也未接入实际 Ping 接口，不能登记它为完整 ICMP 双端。

官方 Linux [RawPacketStream](https://github.com/TrustTunnel/TrustTunnel/blob/fab5b8353a19332f935fa30869307d37d4a898d1/lib/src/icmp_forwarder.rs) 使用 SOCK_RAW 和原生过滤/收包代码；通常需要对应原始套接字权限。当前 Core 没有统一 ICMP 目标访问服务。**本轮按主任务确认返回501/Unsupported，不新增ICMP能力开关，不用UDP假装ICMP，不做原始套接字权限实验。** 后续若交付ICMP，先独立定义统一 Echo 请求/结果、配额、取消与权限边界，不在协议中直接 ping 网站。

## 握手、鉴权、证书与 EOF

- 每条业务流使用 CONNECT。TCP authority 为 `host:port`，IPv6 带方括号；特殊 authority 为 `_udp2`、`_icmp`、`_check`，不与普通主机名自动互换。客户端带 user-agent 和 `proxy-authorization: Basic base64(username:password)`，Base64本身不提供保密。
- 官方 RegistryBasedAuthenticator 对照规范编码后的完整凭据；Mihomo 解码 Basic 并按用户名/密码查表。实现应固定发出规范 Basic 形式，拒绝歧义用户名冒号/控制字符、重复认证头，密码允许冒号；配置必须有真实非空秘密，不能用用户名、客户端随机前缀、会话号或应用名伪造认证指纹。
- 鉴权成功和目标解码后才调用 AccessService。200 是 CONNECT 受理成功；Mihomo handler 在实际目标拨号前已写200，因此通用出站不能据外部200声称网站已建立。本项目节点计划在 TCP 目标访问成功后再200。非200均失败；407/鉴权错误关闭本凭据的会话，不能切换到另一节点或直连网站。
- 规范要求服务器证书校验、SNI及TLS1.2+；H3固定TLS1.3。本轮始终验证名称/CA，允许测试CA与常规证书链；不提供 skip-verification。客户端证书可选，节点可要求并验证mTLS，Basic仍是必需门槛。该TLS组合有Mihomo接线证据，官方稳定服务端 TLS accept 使用 with_no_client_auth，不能拿官方默认互通填mTLS验证。
- H2 END_STREAM 与 H3 FIN 可表达单向EOF，RESET/STOP_SENDING为异常结束。官方H1会在EOF通知时关闭传输，Mihomo通用httpConn.Close也同时关闭读写；**通用tcp_eof先保守false**，自端独立FIN和真实对端观察分别验证，不从TLS或HTTP版本名称直接推断。
- 本轮禁用0-RTT；官方与Mihomo服务端存在接收early-data路径，不据此提供业务重放保证。普通1-RTT票据与连接资源按节点/凭据隔离。ECDH/证书库正常工作不等于流量不可区分、抗封锁或性能已经证明。

官方另有 `<编码凭据>.<主域>` 的SNI认证路径，可能将秘密编码暴露于SNI；本轮只用每流Basic，不提供该可选路径。客户端HEAD的 auth-key 通过HKDF/AES派生ClientRandom，并依赖厂商补丁TLS API；所读稳定OSS服务端实际鉴权仍是Basic/SNI注册表，没有对应key校验入口，不把该字段当本项目节点鉴权资格。

## UDP：固定 flow，不冒充同 socket 多目标关联

上行：u32长度（不含自身）+ sourceIP16 + sourcePort2 + destinationIP16 + destinationPort2 + appLen1 + appName + payload；下行去掉应用名字段，其余方向反转。整数大端。UDP承载在可靠HTTP DATA/字节流中，**不是QUIC DATAGRAM，也不是通用UoT v2**。

官方按完整源/目的四元组跟踪、分配独立UDP socket，空闲默认120秒。客户端一个 `_udp2` 流可复用许多固定flow；这不保证换目标仍使用同一个外部socket。本轮实现 Core `connect_udp` 固定目标能力，`supports_udp_association=false`，不宣称 DatagramAssociation/Full Cone。每个固定flow经 `AccessService::connect_udp`，不在协议内创建网站UDP socket或DNS。

框架 Engine 已为转发与节点出口包装 Egress：域名目标按统一IPv4优先策略解析后把字面地址传给出站。UDP线格式只容纳IP；直接调用裸出站的域名UDP将明确拒绝，调用方应使用统一服务。TCP authority可保留域名交给节点统一出口，不自行解析网站。

资源键至少包含节点、认证身份、物理会话、HTTP流和四元组；客户端声明的source地址只是回包关联键，不是网站源地址、真实接入地址或绑定本机地址的授权。服务端回包来源取自统一固定通道的真实peer元数据，目的字段回填客户端虚拟源。Mihomo回包可能将客户端目的置零，计划每个Core固定通道独立HTTP `_udp2` 流，以免仅靠不可靠虚拟目的字段混用两个同目标通道；H2/H3物理载体仍复用。

### 已读源码差异，不能当作测试通过

1. 规范和Mihomo把 `::1` 特判为IPv6；官方稳定及当前HEAD的 get_fixed_size_ip 只检查前12字节为零，会把 `::1` 解为IPv4 0.0.0.1。本项目按规范保留IPv6 loopback，并明确拒绝无法无歧义往返的IPv4 0.0.0.1；官方UDP IPv6验收需已有非 `::/96` 项目测试地址，否则保留缺口，不能添加worker地址绕过权限范围。
2. 官方 `MAX_UDP_PAYLOAD_SIZE=65536-20-8`，接收判断还多次减去固定头与应用名。按该固定表达式，最大有效负载受 `65434-2×appName字节数` 约束；精确阈值仍是源码推导；r11已在选择的0/65434/65507采样观察限制，未测出实际最大值，不能把表达式登记为测量结果。本项目仍遵守Core包长限制与实际UDP最大负载，不复制错误计算。
3. 官方Decoder循环依赖输入非空，零payload落在片段末尾时可能等下一输入才发出；需要专门验证最后一条零包、零包后非零包，不把“非零已通”外推为空包。
4. AppName是最多255字节UTF-8元数据，不作鉴权或节点路由身份。长度先检查再编码；超长、无效UTF-8、坏u32长度、截断与超限整包处理，不申请攻击者声明的4GiB缓存。

## 连接池、恢复与身份资源

Mihomo默认maxConnections=8/minStreams=5，选择计数较小的transport；这个参数约束transport对象，不自动等于绝对物理socket硬上限。官方客户端有健康检查、重连、位置选择及可选直连旁路策略。本轮采用真实可计数的物理连接池，不照搬无限配置或失败直连。

计划：H1每隧道一条TLS，只有并发上限；H2/H3有界池及每连接逻辑流上限，空闲回收、GOAWAY排空、_check、取消和故障清理。池只属于具体出站实例，键含接入endpoint、TLS名称/信任/客户端证书、实际认证与载体；不按网站authority分池，也不跨节点共用认证会话/票据。

认证指纹按实际Basic字节生成，并通过 scoped_credential_fingerprints 保持trusttunnel原域；H1 TCP CONNECT与原生HTTP代理有相同Basic接受路径，另提供与原HTTP实现相同的http认证摘要，防止切换类型绕过整组凭据查重。额外用已验证的 credential_isolation_fingerprints 隔离TrustTunnel密码秘密，避免换用户名却跨IPv4/IPv6节点复用同一密码。额外秘密不授予鉴权资格，证书公共信息和伪装标识不替代Basic。节点的物理连接、逻辑CONNECT及UDP flow取得相应预算，控制流也有上限；排空时不再打开新网站目标，截止后取消并回收。

因传输断开而创建新会话不代表可重放旧CONNECT或已发送业务；不自动跨节点重试，不提供fail-open直连、TUN、系统路由/DNS接管、订阅、测速、反向网站代理、ACME或凭据自动更新。

## Rust 原语、依赖与许可证

本项目计划独立Rust双端，复用已有TLS/QUIC/HTTP原语；不把官方C++客户端FFI或外部核心子进程当内核。官方Rust Forwarder/TcpConnector等为pub(crate)，Core内选择自带Direct/SOCKS forwarder；直接嵌入未改库不能注入AccessService，不采用其直拨网站路径。

| 原语/来源 | 当前固定版本 | 许可与用途 |
| --- | --- | --- |
| h2 | 本项目锁0.4.20 | MIT；请求/流控/END_STREAM，需新增明确直接依赖 |
| h3 / h3-quinn | 0.0.8 / 0.0.10；后者沿用xray-rust 9b06d37466492242a1827f9a16aa91ca4c1b00be补丁 | MIT；真正H3 CONNECT，不以裸QUIC冒充 |
| Quinn / quinn-proto | 0.11.9 / 0.11.16，同一固定补丁 | MIT OR Apache-2.0；QUIC v1、标准控制器及有界流 |
| rustls | 本项目0.23.40，shaped-rustls 3a131beaef0183b0cb61e5a9070a703b6be39ed3 | 上游声明Apache-2.0 OR ISC OR MIT；证书/名称/mTLS |
| Tokio / socket2 | 当前锁1.54.1 / 0.6.5 | MIT / MIT OR Apache-2.0；异步I/O、载体socket所有权 |
| 官方稳定endpoint | lib 0.1.0；h2 0.3.27、quiche 0.24.9、boring 4.22.0、rustls 0.23.43、Tokio1.53.1锁定 | 官方Apache-2.0；quiche BSD-2-Clause、boring Apache-2.0；参考端，不引入双QUIC栈 |
| 官方稳定client | C++20；Conan dns-libs 2.10.2-6-gc68d7dde、native_libs_common8.1.54、nghttp2 1.56.0、厂商boring-2026-05-08 | 官方Apache-2.0；还有libevent、ngtcp2等原生依赖。ngtcp2是传递依赖，顶层recipe没有独立锁定版本；若重建参考端需补完整Conan闭包 |

官方两仓库工具链文件为Rust1.95；本项目仍按自身Rust1.99.1 worker基线。标准crate元数据许可已查，git补丁继续沿用项目既有固定来源，不把上游许可声明当项目最终许可结论。Mihomo及sing-trusttunnel的GPL来源只用于证据/参考对端，具体借鉴在实现阶段由主任务补design-map。

## 本轮完整交付范围与测试矩阵

主任务已确认：**H1/H2/H3双端TCP与固定UDP；_udp2只复用多个固定flow；ICMP501/Unsupported。** 本轮再明确含Basic多用户、服务器证书验证、可选mTLS、真实池/健康检查/预算与退出。先写齐所有实现、接口、测试和工具，再在新隔离worker项目工作区统一构建；不恢复ShadowTLS停止的实验。

| 传输/安全条件 | 客户端/节点TCP | 客户端/节点固定UDP | 独立参考条件 |
| --- | --- | --- | --- |
| H1/TLS1.2 | 均实现并自验 | 均实现并自验 | 本项目客户端可接官方H1节点；节点TCP可用标准认证HTTPS CONNECT客户端；节点UDP暂无官方CLI H1上游，规范wire peer须标明受控性质 |
| H1/TLS1.3 | 同上 | 同上 | 同上，不把H2客户端强制回退伪装H1 |
| H2/TLS1.2 | 均实现并自验 | 均实现并自验 | 官方稳定与固定Mihomo双向 |
| H2/TLS1.3 | 均实现并自验 | 均实现并自验 | 同上 |
| H3/QUICv1/TLS1.3 | 均实现并自验 | 均实现并自验 | 官方稳定quiche/ngtcp2与固定Mihomo，分别记方向 |
| 上述载体加mTLS | 自端另测，Basic仍必需 | 自端另测 | H2/H3可按Mihomo实际证书配置验证；官方默认不填该格；H1独立对端条件另记 |

基本实现矩阵为5条传输/安全路径×2数据类型×2角色=20格，mTLS另列，不用一个成功格覆盖全部。网络首轮计划每格覆盖两节点地址族、两网站地址族、独立凭据、证书/名称/ALPN失败、目标先发、跨窗口TCP大负载、即时EOF/半关闭、15字节拆分与多记录合并、UDP零包/包长/双通道隔离、并发、取消、空闲、活动排空与同端口重绑；默认票据条件保留，不以关票据取代默认。

### 独立对端与验证前提

- 官方客户端有SOCKS模式与UDP支持，后续只启用回环SOCKS，关闭TUN、系统路由/DNS修改和默认外部DNS使用；不运行安装脚本、SSH部署器或修改worker服务。其`core/src/vpn_fsm.cpp`在killswitch关闭时有`bypass_until_connected`，因此参考SOCKS配置保持Core killswitch开启。但固定client的`core/src/tunnel.cpp`又硬编码loopback为VPN_CA_FORCE_BYPASS，该分支不受此开关覆盖；r11节点方向回环成功已重分类无效，r12改用既有私有IPv4自有目标。没有可用ULA，官方客户端IPv6目标条件仍不足。已读Linux SOCKS路径不调用TUN/系统防火墙入口；Windows TUN另有系统封锁设置，不属于本轮实验。DNS显式指向任务自有回环拒绝夹具，不访问默认外部DNS。
- 官方endpoint本地配置显式启用所需H1/H2/H3、配置静态测试证书/独立Basic用户，并允许项目私有测试目标：默认allow_private_network_connections=false，会阻止回环测试，不能误判协议失败。
- Linux原始ICMP默认能力不作实验；参考endpoint配置禁用其ICMP路径，使用无特权TCP/UDP验证。第三方声明支持不等于本项目已接ICMP。
- 官方linux-x86_64稳定发布归档已下载到私有目录：v1.1.0 endpoint为10608905字节，SHA256为91c2ea3db7416a01b5258a4c047ec22890490bc55e1b194206031aa75144f0e7；v1.1.11 client为4234196字节，SHA256为00e0546a6b35840dbb92b741dff3da6732a74bf2d6c581e044bb4567c0d96825，均与固定发布API摘要一致。perf-02 `reference-r1`已按固定VERIFY_RELEASES.md在项目私有keyring核对密钥指纹/两个RSA签名，运行两个`--version`成功；没有修改全局keyring；随后已运行协议矩阵，结果和重分类见测试交接，不能用签名/版本成功代替互通。
- H1节点UDP、官方UDP ::1、零包最后记录与极限包长是已知证据/对端缺口，分别登记自端、规范向量或真实对端结果；不得预填“官方双端通过”。

## 未决项与开工约束

1. ICMP作为独立后续任务，需要统一Echo访问契约、真实来源元数据、预算/取消及授权权限，不阻塞已确认TCP/固定UDP首轮。
2. 通用DatagramAssociation/Full Cone本轮不提供，不增加假开关；如后续确有跨目标同socket需求，应另定协议语义/对端协商，不能靠客户端承诺改变官方四元组socket行为。
3. H1节点UDP可信独立peer条件与官方稳定IPv6 ::1缺陷的测试替代条件须保留缺口；不修改worker网络地址或静默修补官方对端来填绿。
4. 零包/包长采样已有r11限制观察，精确最大值及所有后续流失败原因没有定量定位；原序列和干净H1对照分别保留。当前停止，不把待验证推论写成修复结果。
5. 1.3预发布/HEAD的订阅、ClientRandom auth-key、伪装随机前缀、SNI凭据、ECH/指纹、自动H3/H2竞速和系统VPN策略不进入本轮；未知字段明确拒绝。
6. 进一步核对 h3 0.0.8 的 `src/proto/headers.rs::Pseudo::request` 发现，它会给普通 CONNECT 无条件增加 `:scheme=https` 和 `:path=/`；普通 CONNECT 应省略这两个字段。现有 Hysteria2 POST 路径不涉及此条件。公共任务已落实classic CONNECT修正及伪头唯一性/顺序回归，r12纳入新headers输入；不外推旧H3或其他协议的互通。

**最后已验：r12的20项Rust/格式/选定包与CLI严格Clippy及构建。当前本地H2两文件增量未编译；Mihomo证书夹具、虚拟source 0:0约束和官方65000字节/H3节点setup边界未解决。保持停止，协议未登记完成。** 本文记录范围与上游证据，不能替代[worker验收记录](../../docs/testing/trusttunnel.md)。

### 测试阶段已留证的新边界

- 官方client对回环的强制旁路，使r11对应节点方向数据记录不能证明TT鉴权；原始/重分类结果均保留。既有私有IPv4探针没有增加地址、路由或服务配置，IPv6条件不足继续未测。
- 固定官方`http_udp_codec.rs`的Dropping分支返回被丢弃前缀；边界包后出现后续流失败，无边界的H1干净对照通过。相关性有证据，但没有证明所有失败的唯一原因。
- 官方`http2_codec.rs`的DroppingSink要求当前credit足够整条记录；r12 H2四个65000字节回写超时。2MiB客户端连接窗口和atomic回归仅写在本地，尚未验证此解释。
- Mihomo有效listener日志拒绝Home/SAFE_PATHS之外证书路径，有效H3客户端日志显示unknown authority。其`packet.go`明确写unknown source 0:0，本项目当前Node拒绝source port0，形成约束冲突；未修、未实测定位。mTLS没有业务正例，不以拒绝/退出记录充作兼容。
