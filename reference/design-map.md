# 上游借鉴到本项目设计的映射

更新日期：2026-10-30。本文整理已有固定版本调研，未进行新一轮上游核验、构建或实测。固定基线、许可证观察与来源异常以 [reference/README.md](README.md)为入口。

REF-001–008 保留首轮**设计草案**，后续条目单独标明实现与验证状态；“借鉴”不表示复制代码，也不表示完全兼容其配置或行为。

## REF-001 元数据与目标演进

**问题：**原始目标、嗅探域名、规则匹配目标和拨号地址怎样保留，避免互相覆盖。

**证据：**[mihomo Metadata](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/constant/metadata.go)、[Xray session](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/common/session/session.go)。两者提供区分目标信息的参考，具体字段语义见独立调研。

**Rust 落点：**[核心契约](../docs/core-contracts.md)中的分阶段上下文；借鉴信息责任，不复制一个全局可变上下文。

**待验证：**嗅探只参与路由时不改变拨号目标；Fake-IP 恢复保留原始地址；并发任务不串改会话。

## REF-002 TCP 与 UDP 的不同语义

**问题：**如何统一调度，同时保留流半关闭、包边界、逐包地址和回写上下文。

**证据：**[mihomo adapters](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/constant/adapters.go)、[mihomo UDP/连接管理](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/tunnel/connection.go)、[Xray buffer](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/common/buf/buffer.go)。

**Rust 落点：**[数据路径](../docs/data-paths.md)中的流/包分离、UDP 关联/目标流/端点与缓冲所有权。这三个层级是本项目的建议表达，不声称上游具有完全相同的模型。

**待验证：**TCP 单向 EOF、首包不丢不重、UDP 多目标回写、并发建立合并、超时与有界队列回收。

## REF-003 工厂、装配与部分失败清理

**问题：**新增协议怎样尽量不改核心，模块启动到一半失败时怎样退出。

**证据：**[sing-box registry](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/include/registry.go)、[Box](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/box.go)、[lifecycle](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/adapter/lifecycle.go)。

**Rust 落点：**[协议模块](../docs/protocol-modules.md)的显式注册、私有配置构造计划，以及[生命周期](../docs/runtime-lifecycle.md)的依赖顺序与清理责任；不照搬 Go 注册实现。

**待验证：**第二个协议的改动范围、缺失能力的配置错误、依赖环检测、部分资源取得后的清理。

## REF-004 策略组、资源提供器与观测

**问题：**节点从哪里来、如何选择、是否健康，三件事怎样分开。

**证据：**[mihomo provider](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/provider/provider.go)、[sing-box selector](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/protocol/group/selector.go)。两者不是同一种订阅或 provider 模型，不能直接视为等价。

**Rust 落点：**[总体结构](../docs/architecture.md)的 policy 责任与[生命周期](../docs/runtime-lifecycle.md)的新会话选择视图；是否首批实现仍待产品范围决定。

**待验证：**候选更新失败保留有效视图、健康结果不过期串用、选择变化不自动重放已发送业务数据。

## REF-005 协议、传输与安全边界

**问题：**哪些能力可共用，哪些组合需要显式约束。

**证据：**[Xray 协议配置](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/xray.go)、[stream 配置](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/transport_internet.go)。

**Rust 落点：**[协议模块](../docs/protocol-modules.md)与 net 的复用边界。可复用连接/安全能力与协议握手分开；不能假定任意代理、传输与安全层都可组合。

**待验证：**支持组合有明确能力约束，不支持组合在建立前被拒绝，协议特有语义不因抽象而丢失。

## REF-006 DNS、Fake-IP 与状态使用期

**问题：**域名恢复和 DNS 路由怎样配合，映射何时可回收。

**证据：**[mihomo enhancer](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/dns/enhancer.go)、[sing-box 路由恢复](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/route/route.go)、[Xray 路由解析](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/app/router/router.go)。

**Rust 落点：**[DNS/Fake-IP 数据路径](../docs/data-paths.md)与[资源生命周期](../docs/runtime-lifecycle.md)。独立映射所有者、lease、缓存分区与宽限是本项目建议，不据这些链接声称已证明其正确性。

**待验证：**解析依赖环、跨代缓存、旧会话映射不被复用、池耗尽与状态迁移。

## REF-007 更新能力需要逐项定义

**问题：**哪些变化可发布新快照，哪些需要替换实例或重启。

**证据：**[mihomo executor](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/hub/executor/executor.go)、[sing-box CLI](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/cmd/sing-box/cmd_run.go)。调研发现不同的更新顺序和重建边界，不能合并描述为事务式无损重载。

**Rust 落点：**[配置代次与更新分类](../docs/runtime-lifecycle.md)。固定会话代次、独占资源检查与 RequiresRestart 是本项目的候选规则，不是直接移植来的保证。

**待验证：**更新失败、迟到任务、旧资源保活、连续更新容量和平台补偿失败。

## REF-008 TUN 核心与宿主边界

**问题：**设备、用户态栈、权限、防回环和系统网络设置分别归谁。

**证据：**[sing-box PlatformInterface](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/experimental/libbox/platform.go)、[Xray TUN 入口](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/tun/handler.go)。平台差异与源码/网页冲突见 [sing-box](research_notes/Rust%20VPN%20内核参考调研/sing-box.md)、[Xray](research_notes/Rust%20VPN%20内核参考调研/xray.md)独立记录。

**Rust 落点：**[总体结构](../docs/architecture.md)的 tun/platform 分层及[生命周期](../docs/runtime-lifecycle.md)的 FD 所有权。当前不选择上游某个栈，也不把 Go 栈当成已可直接复用的 Rust 组件。

**待验证：**首批目标 OS 的真实接流、FD 移交/复制/借用、MTU/IPv6、退出恢复与网络切换。

## 后续维护

已有条目保持稳定编号；发现证据有误时注明修正，不静默换成另一个上游版本。新版本调研另存记录，映射说明所用基线。用户明确确认某项选择后补上决策链接；实现与验证进展链接到 [STATUS.md](../STATUS.md)，不直接把整篇调研标成“已实现”。


## REF-009 双端节点与统一出口

**依据：**用户对独立 IPv4/IPv6 节点、独立凭据和统一目标访问的明确确认，见 [0005](../docs/decisions/0005-separate-nodes-unified-egress.md)、[0006](../docs/decisions/0006-unified-client-server-core.md)。注册与角色分离继续参考 REF-003。

**实现：**`core-api` 的 `InboundProtocol`/`AccessService`、配置层独立节点工厂、引擎按能力绑定 TCP/UDP/虚拟入口、`egress` 的系统解析与 IPv4 优先；[接口](../docs/interfaces/node-egress.md)。节点凭据、身份池和配额按实例隔离，网站地址族不跟随接入地址族。

**验证：**AnyTLS 与 SS2022 的正式 CLI 集成已覆盖单进程双角色、独立双栈节点和两类业务目标；VLESS 扩展仍按其测试快照登记。尚未据此实现 DNS/Fake-IP 或完整路由语言。

## REF-010 AnyTLS

**固定证据：**[sing-anytls](https://github.com/anytls/sing-anytls/tree/130d2e61b8895727bfed4942c535e91b246a9603)、[mihomo 出站](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/anytls.go)，详细文件与许可证见[研究记录](research_notes/anytls-implementation.md)。

**实现：**`crates/protocol-anytls` 自主 Rust 会话、TLS、认证、padding、连接池与 UoT v2；不运行或链接 Go 代理。节点端通过 `AccessService` 访问目标，原生池按实例隔离。[接口](../docs/interfaces/anytls.md)与[真实 sing-box 互通、19 项 CLI 集成结果](../docs/testing/anytls.md)分别维护；未执行 mihomo 程序互通。

## REF-011 Shadowsocks 2022

**固定证据：**[SIP022](https://shadowsocks.org/doc/sip022.html)、三个核心的单用户/EIH 分支，以及 `shadowsocks` 1.25.0 的 [固定 Rust 原语](https://github.com/shadowsocks/shadowsocks-rust/tree/ab388c7466d21f979430e33cc9ef10e22fb05955)。精确 Go 文件、依赖与许可证见[研究记录](research_notes/ss2022-implementation.md)。

**实现：**`crates/protocol-ss2022` 使用该库 TCP/UDP 密码原语，自己适配节点认证、回放窗口、UDP 多目标与地址迁移、配额和退出；三算法双端，AES 支持终端 EIH 多用户和客户端身份链。[接口](../docs/interfaces/ss2022.md)与[88 项互通、17 组 CLI 集成结果](../docs/testing/ss2022.md)独立登记。relay 服务端、插件、UoT 和通用 Mux 未实现。

## REF-012 VLESS 扩展

**固定证据：**Xray 请求、Vision、Encryption、Mux、XHTTP 与 XDRIVE 源码，以及 mihomo/sing-box 合法组合，见[本轮研究](research_notes/vless-combinations-implementation.md)。

**实现：**`crates/protocol-vless` 分离组合校验、载体、payload、服务端安全、HTTP/H3、Mux 和 XDRIVE；Rust 密码/传输原语与来源见[依赖记录](../docs/vless-dependencies.md)。不复用外部核心的配置、路由、管理端或程序入口。

**验证：**旧客户端快照 394 个 Xray 配置已通过，基础服务端普通流/Vision 分别通过 11/9 项；新扩展仍在统一远端验证，不能把上游支持或既有快照替代最终源码的验收。

## REF-013 SOCKS 与 HTTP 代理

**证据：**SOCKS 的 RFC 1928/1929、4/4a 线协议以及 HTTP 的 RFC 9110/9112/7617；固定三核心入口见总表 P-01/P-02，具体来源与边界见[SOCKS 研究](research_notes/socks.md)和[HTTP 研究](research_notes/http-proxy.md)。

**实现：**独立 `protocol-socks`、`protocol-http` 双端工厂；节点目标访问交给 AccessService。物理 TCP 地址由引擎注入，SOCKS UDP 按真实来源绑定；HTTP 普通请求使用 Hyper 流式解析并剥离代理认证与逐跳字段。

**验证：**SOCKS 11 项、HTTP 7 项包级回归通过；固定 sing-box 52 项检查通过，4 项参考入口零包限制单列。认证、来源、帧边界、排空和回收范围分别见[SOCKS](../docs/testing/socks.md)、[HTTP](../docs/testing/http-proxy.md)，不由联合节点测试继承全部对端能力。

## REF-014 Shadowsocks AEAD 与 legacy

**证据与实现：**总表 P-03/P-05、固定 Shadowsocks Rust 密码依赖及[详细研究](research_notes/shadowsocks.md)对应 `protocol-shadowsocks`，与 SS2022 独立注册；接口列出具体方法、允许旧式模式的显式边界、UDP 重放与节点预算。

**验证：**45 方法自端、9 项 Rust 和 312 项限定独立对端检查通过；旧式方法与大包边界见[测试](../docs/testing/shadowsocks.md)。none/plain 后续改为真实无认证本地入口，并经 24 项外部检查复验；流连接器增量另做包级回归。

## REF-015 Trojan 与 VMess

**证据与实现：**总表 P-09/P-07、固定 Xray 和 Rust 传输依赖，分别见[Trojan 研究](research_notes/trojan.md)、[VMess 研究](research_notes/vmess.md)。两者各自实现双端，载体不得由 VLESS 的通过状态继承；VMess 服务端另实现请求认证、记录边界与有界重放缓存。

**验证：**Trojan 11 项 Rust 与固定 Xray 20/20 组合通过；VMess 11 项 Rust、Xray 48/48 和 sing-box RAW 16/16 配置通过。角色、载体、大包和地址族边界分别见[Trojan](../docs/testing/trojan.md)、[VMess](../docs/testing/vmess.md)，不把旧算法或未验载体纳入结果。

## REF-016 Snell

**固定证据与实现：**P-10、固定 sing-snell 与其版本/角色区别，见[详细研究](research_notes/snell.md)。`protocol-snell` 独立实现 v4 出站/v5 节点、v6 三模式，保持记录边界、密码状态和顺序复用；域名 UDP 仅使用统一出口业务元数据。

**验证：**14 项 Rust、64 组独立 profile/KDF/记录向量与固定 sing-box 36/36 组合通过；原有大包截短、物理 EOF 和回包限额修正保留记录，见[测试](../docs/testing/snell.md)。不能继承 v5 QUIC 模式或其他版本方向。

## REF-017 TUIC

**固定证据与实现：**P-13、v4/v5 规范和固定 mihomo/sing-quic，见[详细研究](research_notes/tuic.md)。`protocol-tuic` 原生双端，单个 UDP association 通过统一服务保持一个出口 socket；没有用多个固定目标通道替代 Full Cone。

**验证：**9 项 Rust、mihomo 48/48、sing-box v5 24/24 配置及 8/8 生命周期场景通过；角色、包长、分片、认证和来源边界见[测试](../docs/testing/tuic.md)，没有性能等同结论。

## REF-018 Hysteria2

**固定证据与实现：**P-12、固定官方 v2.13.0 与三个参考核心，见[详细研究](research_notes/hysteria2.md)。`protocol-hysteria2` 使用唯一双向 stream 接纳器区分 HTTP/3 与原生 TCP，UDP 使用统一关联与有界分片，不把现有客户端依赖当作完整双端。

**验证：**8 项 Rust、自端 CLI 160 项及 sing-box/Xray/官方各 128 项通过，见[测试](../docs/testing/hysteria2.md)。标准自适应拥塞、Salamander 与已验证数据语义分别记录，不将其写作 Brutal、Gecko 或端口跳跃支持。

## REF-019 Hysteria v1

**固定证据与实现：**P-11、官方 v1.3.5 与固定 sing-box，见[研究](research_notes/hysteria1.md)。`protocol-hysteria1` 独立实现双端、认证、普通/WeChat-video 载体、xplus 和业务 UDP 关联，不继承 Hysteria2 的握手或支持结论。

**验证：**16 项 Rust、官方 24/24 与 sing-box 12/12 限定组合通过；实际大包截断、空包与 FIN 边界见[测试](../docs/testing/hysteria1.md)。标准控制器和协商 pacer 不称为 Brutal。

## REF-020 ShadowQUIC

**固定证据与实现：**P-14、固定 Mihomo/JLS、RFC9368/9369，见[研究](research_notes/shadowquic.md)。独立 Rust 双端使用受控 JLS 依赖、真实 QUIC 回退和有界来源映射，不用普通 QUIC 冒充 JLS。

**验证：**16 项 Rust、v1 原固定 Mihomo 24 配置通过；v2 受控 Go 参照 24 配置及标准负例通过。原固定 Mihomo 缺少版本参数的 24 项 v2 失败、参照两次标准修正分别保留，见[测试](../docs/testing/shadowquic.md)，不登记原资产 v2 兼容。

## REF-021 SSH

**固定证据与实现：**P-20、russh 0.64.1 和独立 OpenSSH，见[研究](research_notes/ssh.md)。`protocol-ssh` 仅提供原生 direct-tcpip 出站，使用显式认证和主机 SHA256 固定，连接取消实际关闭底层 TCP；不运行系统 SSH 承载业务。

**验证：**6 项 Rust、OpenSSH 原生 140 项及同进程 HTTP→SSH 200 项检查通过，见[测试](../docs/testing/ssh.md)。没有 SSH 服务端、UDP、Shell、SFTP 或隐式 agent/known_hosts。

## REF-022 Gost Relay

**固定证据与实现：**P-19、固定Mihomo出站、GOST v3.3.2/x v0.27.2/relay v0.7.0与SMUX v1，见[研究](research_notes/gost-relay.md)。`protocol-gost-relay` 原生CONNECT出站，经TCP/TLS和可选单流SMUX v1传递固定TCP/UDP，已知转发目标必须实际匹配，不忽略网站地址。

**验证：**15项Rust、固定官方64配置704条记录及28项原始FIN阶段通过，见[测试](../docs/testing/gost-relay.md)。参考JSON整数被忽略导致的首轮失败保留；官方零包丢弃和65507→32768截断由直接目标控制区分，不改内核截包或登记Full Cone。没有Relay服务端、BIND、多流池、SMUX v2或其他物理载体。

## REF-023 Sudoku

**固定证据与首轮范围：**P-17、Mihomo固定3f27ef39和官方v0.5.2.0，见[详细研究](research_notes/sudoku.md)。独立Go探针已在worker取得8组table/编码向量与10条early鉴权语义/控制记录，固定来源、锁和产物见tools/sudoku_reference_probe/SOURCE.json；探针使用原生参考包，不进入Rust业务路径。

**实现状态：**已停止保存快照；r4库49/49、预算/HTTP及协议11/12通过，Mux期限失败与r5诊断保留。最后两文件性能增量未经过任何验证，原生互通未开始。实际边界见[接口](../docs/interfaces/sudoku.md)与[测试](../docs/testing/sudoku.md)。UserHash不作为独立身份，旧快照不外推新源码。

## REF-024 Mieru

**固定证据与实现：**P-16、Mihomo固定3f27ef39及官方API v3.38.1/v3.39.0，见[研究](research_notes/mieru.md)。原生双端、复用及Full Cone通过统一出口；实际秘密与用户名身份分别隔离。原UDP线格式存在nonce复用风险，仅显式本机兼容，不向公网放开。

**验证：**21项模块Rust、3项配置测试、格式与严格Clippy；三个参考对端分别88配置176普通检查通过，空包/大包/退出和原Mihomo边界独立记录，见[测试](../docs/testing/mieru.md)。冻结快照和同一CLI摘要可追溯，未验当前全工作区或其他平台。

## REF-025 TrustTunnel

**固定证据与实现：**P-18、固定官方endpoint/client及Mihomo，见[研究](research_notes/trusttunnel.md)。H1/H2/H3 TLS双端与固定UDP、Basic多用户和可选mTLS已写；真实Basic指纹与HTTP同域，不用密码额外隔离域代替实际认证。共享h3补丁来源及独立原语边界见third_party/h3/PATCHES.md。

**验证状态：**新h3快照20项Rust及选定检查、自端CLI240记录通过；新增H2窗口兼容修正与外部矩阵仍待验，官方client回环强制旁路的成功不计互通，见[测试](../docs/testing/trusttunnel.md)。不登记Full Cone或ICMP支持。

## REF-026 Naive

**固定证据与实现：**P-21、固定sing-box/官方Naive/forwardproxy/Cronet，见[研究](research_notes/naive.md)。双端H1/H2/H3、应用padding、UoT和实际HTTP凭据域已写；应用协议和Chrome网络栈行为分开，不宣称根证书/CT/CRLSet/ECH/指纹等价。

**验证状态：**26项Rust/严格检查、156配置900常规及同进程28检查通过；证书资产迁移后26项/6资产控制复验通过，原资产0/65507/EOF边界单列，见[测试](../docs/testing/naive.md)。不外推整树或正式发行。
