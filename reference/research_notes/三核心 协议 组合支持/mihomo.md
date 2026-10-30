# mihomo 协议与组合支持证据

## 1. 基线与判断范围

### 核心结论

本轮固定正式版 `v1.19.33`，提交 `3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8`。出站解析器有 28 个类型入口，其中 24 个是远端代理或隧道类型，另 4 个是内部动作；Listener 解析器有 20 个入口，不能把透明接入、组合入口和转发入口都计作远端协议。

### 来源与事实

| 项目 | 本轮观察 |
| --- | --- |
| 日期 | 2026-10-30，Asia/Shanghai |
| 正式发行 | GitHub latest release 返回 `v1.19.33`，`prerelease=false`，发布时间 `2026-10-21T16:56:13Z`；[发行页](https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.33) |
| 固定提交 | release tag 的 commits API 解析为上述完整 SHA；[固定提交](https://github.com/MetaCubeX/mihomo/commit/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8) |
| 源码身份 | 固定源码为 Go，module 是 `github.com/metacubex/mihomo`；[go.mod](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/go.mod) |
| 出站完整入口 | [adapter/parser.go](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/parser.go) |
| Listener 完整入口 | [listener/parse.go](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/listener/parse.go) |
| 滚动文档 | [出站目录](https://wiki.metacubex.one/config/proxies/)、[入站目录](https://wiki.metacubex.one/config/inbound/)，本次访问；不视作固定发行版说明 |

这里的“有路径”仅表示在固定源码中找到解析、构造或处理分支。全表**未构建、未运行、未做协议互通**。方向和数据能力按未额外包裹通用 sing-mux 的实例描述；`udp` 配置开关、对端能力与构建条件仍会影响使用结果。注册项缺失写作“未登记”，不推断所有外部扩展都不存在。

### 分析与启发

支持清单应保留类型、方向、传输、安全、flow/包编码、构建条件和验证状态。不得把某个配置可被解码，或没有返回错误，直接记为组合可互通。

### 未验证项

前轮曾记录默认首页与 Go 固定标签身份不一致；本轮直接验证正式标签的 Go 源码，未重新调查默认首页变化原因。所有下列代码链接均固定同一 Go SHA，不依赖默认分支内容。

## 2. 远端协议、方向与数据能力

### 核心结论

固定源码覆盖的范围明显大于 SOCKS、HTTP、SS、VMess、VLESS、Trojan、Hysteria、TUIC 等常见名称；还应登记 ShadowQUIC、Sudoku、Gost Relay、MASQUE、TrustTunnel、OpenVPN 及覆盖网络类型。SSH 和普通 HTTP 出站自身没有 UDP 包处理路径。

### 来源与事实

“流/包”描述核心提供的代理视图，不表示底层使用相同的 TCP/UDP 载体。出站方向统一由上述 parser 核实；入站方向统一由 Listener parser 核实，各行再给具体实现位置。

| 类型 / 协议族 | 入站 | 出站 | 数据能力与主要界限 | 固定源码 |
| --- | --- | --- | --- | --- |
| SOCKS | `socks`，SOCKS4/5 分支 | `socks5` | 出站 TCP CONNECT、UDP ASSOCIATE；入站 UDP 为 SOCKS5 路径；SOCKS4a 细节未逐项核实 | [入站握手](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/listener/socks/tcp.go)、[出站](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/socks5.go) |
| HTTP 代理 | `http` | `http` | 流代理；出站 CONNECT，可选 TLS；没有独立 UDP override | [入站](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/listener/inbound/http.go)、[出站](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/http.go) |
| Shadowsocks | `shadowsocks` | `ss` | 流和原生包；出站另有 UOT v1/v2。入站区分 none、AEAD、2022 服务，其他 cipher 回落另一实现；不把同名选项等同于全部算法已互通 | [入站服务选择](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/listener/sing_shadowsocks/server.go)、[出站](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/shadowsocks.go) |
| ShadowsocksR | 未登记 | `ssr` | 流和包；构造器限制 none/受支持 stream cipher，拒绝把 AEAD cipher 当 SSR；另有独立 protocol 与 obfs 选择 | [实现](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/shadowsocksr.go) |
| VMess | `vmess` | `vmess` | 流和包；出站可使用普通包编码、packetaddr 或 XUDP；安全与传输见后表 | [入站](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/listener/inbound/vmess.go)、[出站](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/vmess.go) |
| VLESS | `vless` | `vless` | 流和包；支持 VLESS Encryption/decryption、Vision、packetaddr/XUDP，但这些有独立约束 | [入站](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/listener/inbound/vless.go)、[出站](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/vless.go) |
| Trojan | `trojan` | `trojan` | 流和协议包；另有 SS 包裹选项、mux；UDP 不是底层原生 UDP socket 直传 | [入站处理](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/listener/trojan/server.go)、[出站](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/trojan.go) |
| Snell | `snell` | `snell` | 入站接受 version 1–5；出站 v5 按 v4 向后兼容路径处理，v1/v2 开 UDP 会被拒绝，v3/v4 有包路径 | [入站校验](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/listener/inbound/snell.go)、[出站版本处理](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/snell.go#L245) |
| Hysteria v1 | 未登记 | `hysteria` | QUIC 逻辑流和包；含独立底层传输选项，不能继承 VLESS 的 network 选项集 | [实现](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/hysteria.go) |
| Hysteria2 | `hysteria2` | `hysteria2` | 流和包；salamander/gecko 混淆分支；另有独立 Realm 入口，不新增为一个线协议族 | [入站](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/listener/inbound/hysteria2.go)、[出站混淆校验](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/hysteria2.go#L149) |
| TUIC | `tuic`，v4/v5 配置 | `tuic` | QUIC 流和包；token 与 UUID/password 对应不同版本路径，UDP relay 与 UDP-over-stream 分开 | [入站](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/listener/inbound/tuic.go)、[出站](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/tuic.go) |
| ShadowQUIC | `shadowquic` | `shadowquic` | QUIC 流和包；自身握手与 QUIC 选项，不是 ShadowTLS 的别名 | [入站](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/listener/inbound/shadowquic.go)、[出站](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/shadowquic.go) |
| AnyTLS | `anytls` | `anytls` | 流；包通过 UOT v2 目标建立，不等于原生 UDP 载体；有自己的会话复用 | [入站](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/listener/inbound/anytls.go)、[出站 UOT](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/anytls.go#L61) |
| Mieru | `mieru` | `mieru` | 流和包；底层 transport 选择 TCP/UDP，逻辑包通过协议流封装与 UDP associate wrapper 处理 | [入站包处理](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/listener/mieru/server.go)、[出站](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/mieru.go) |
| Sudoku | `sudoku` | `sudoku` | 流和包；具有自己的 HTTP mask stream/poll/auto/ws 等模式 | [入站包处理](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/listener/sudoku/server.go)、[出站](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/sudoku.go) |
| TrustTunnel | `trusttunnel` | `trusttunnel` | 流和包；有 TLS、QUIC 开关和独立连接池 | [入站](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/listener/inbound/trusttunnel.go)、[出站](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/trusttunnel.go) |
| Gost Relay | 未登记 | `gost-relay` | 流和包处理方法均存在，不与策略组 relay 混淆 | [实现](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/gost_relay.go) |
| SSH | 未登记 | `ssh` | 流；Base 中明确 UDP=false，没有 SSH UDP 处理实现 | [实现](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/ssh.go) |
| WireGuard | 未登记为 Listener | `wireguard` | 经 L3 用户态栈提供流/包视图；gVisor/mips/auto 等栈模式有构建与配置限制 | [实现](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/wireguard.go) |
| MASQUE | 未登记 | `masque` | h2、h3 路径；`h3-l4proxy` 模式明确不支持 UDP，不能统一打勾 | [构造](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/masque.go#L158)、[包限制](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/masque.go#L493) |
| OpenVPN | 未登记 | `openvpn` | L3 栈上的流/包视图；真实底层 UDP 与 TCP 两条 PacketIO 路径 | [底层选择](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/openvpn.go#L373) |
| EasyTier | 未登记 | `easytier` | 覆盖网络上的流/包视图；`no_easytier` 构建会使用报错 stub | [实现](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/easytier.go)、[stub](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/easytier_stub.go) |
| Tailscale | 未登记 | `tailscale` | 覆盖网络上的流/包视图；要求 `with_gvisor` 且无 `no_tailscale` | [实现](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/tailscale.go)、[stub](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/tailscale_stub.go) |
| ZeroTier | 未登记 | `zerotier` | 覆盖网络上的流/包视图；`no_zerotier` 构建会报错 | [实现](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/zerotier.go)、[stub](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/zerotier_stub.go) |

### 分析与启发

上表的 24 个出站类型应进入上游联合候选集，但 L3 隧道/覆盖网络不应与普通流代理强行共用全部选项。协议名、载体、UDP 编码与独立策略组分开建模。

### 未验证项

未逐项核实所有 cipher 名称、每个上游实现对全部角色的对称支持、原生 IP 子协议、移动端后台行为或外部管理服务要求。构造方法存在不等于所有目标平台能编译或全部服务端均互通。

## 3. 传输、安全、flow 和 UDP 组合

### 核心结论

该快照的组合显著超出“VLESS + TCP/REALITY”：VMess 还有 mKCP/Mekya/TLSMirror；多个协议有 ShadowTLS/Restls/JLS 分支。与此同时，出站 WS、XHTTP HTTP/3、Vision 和入站外层包装各有不同边界，不能由统一字段生成自由笛卡尔积。

### 来源与事实

| 协议 / 方向 | 已确认的传输或封装路径 | 安全与补充选项 | 主要限制与证据 |
| --- | --- | --- | --- |
| VLESS 出站 | 默认 TCP、`ws`、`http`、`h2`、`grpc`、`xhttp` | TLS；选项含 REALITY、ShadowTLS、Restls、JLS；VLESS Encryption、Vision、XUDP/packetaddr | [网络分派](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/vless.go#L155)、[构造](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/vless.go#L462) |
| VLESS 入站 | 默认 TCP、`ws-path`、`grpc-service-name`、`xhttp-config` | 证书 TLS、REALITY、ShadowTLS、Restls、JLS、decryption、按用户 flow | 证书与其余安全模式互斥；没有安全模式/decryption 时须显式 allow-insecure；不能由出站 http/h2 推断有完全对称的入站选项。[服务构造](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/listener/sing_vless/server.go#L90) |
| VMess 出站 | 默认 TCP、`ws`、`http`、`h2`、`grpc`、`mekya`、`mkcp`/`kcp` | 内部 cipher；可加 TLS、REALITY、ShadowTLS、Restls、JLS、TLSMirror；packetaddr/XUDP | 外层特殊安全模式互斥并要求 TLS=true；mKCP 明确拒绝 ShadowTLS/Restls/JLS；未见 VMess XHTTP 专门分支。[构造与分派](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/vmess.go#L475) |
| VMess 入站 | 默认 TCP、WS、gRPC、Mekya、mKCP 配置 | 证书、REALITY、ShadowTLS、Restls、JLS、TLSMirror 互斥；内层 alterId 等配置 | mKCP 与前三种 TCP-only 安全模式不兼容；不把多种入口选项同时存在视为所有叠加模式已验证。[实现](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/listener/sing_vmess/server.go) |
| Trojan 出站 | 默认 TCP、WS、gRPC | 默认 TLS 类握手；REALITY、ShadowTLS、Restls、JLS 互斥；可再包 SS 内容 | 没有 VLESS/VMess 那套全部 network 分支，不继承 XHTTP/H2/Mekya 支持。[实现](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/trojan.go) |
| Trojan 入站 | 默认 TCP、WS、gRPC | 证书、REALITY、ShadowTLS、Restls、JLS、SS/allow-insecure 等条件 | 安全模式互斥；完全无任何允许条件会报错。[服务](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/listener/trojan/server.go#L86) |
| Shadowsocks 出站 | 无插件、simple-obfs、v2ray-plugin、gost-plugin、ShadowTLS、Restls、JLS、kcptun | 独立 cipher；插件是内置分支，不是任意外部可执行 SIP003 插件 | `obfs` 只接受 http/tls；kcptun 强制 UOT；其他插件具体 mode 按插件实现约束，不视作通用 VLESS transport。[插件构造](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/shadowsocks.go#L301) |
| Shadowsocks 入站 | 原始流/包；simple-obfs、ShadowTLS、Restls、JLS、kcptun 配置 | cipher 服务选择独立；S/R/J 互斥 | 入站未暴露出站同样的 v2ray-plugin/gost-plugin 字段；kcptun 接管相应 UDP listener，用流承载逻辑包。[配置](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/listener/inbound/shadowsocks.go)、[包装](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/listener/sing_shadowsocks/server.go) |
| Snell | 自身流/包；http/tls simple-obfs、ShadowTLS、Restls、JLS | obfs 版本/参数独立 | v1/v2 不能开启出站 UDP；v5 客户端选择映射 v4。[实现](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/snell.go) |
| AnyTLS | 自身连接/会话管理，不暴露任意 network 选择 | TLS 或 ShadowTLS/Restls/JLS 互斥；UDP 为 UOT v2 | 未见 REALITY 选项，不能因名称含 TLS 推断能接受全部 TLS 扩展。[选项和构造](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/anytls.go) |
| SOCKS5 / HTTP 出站 | 自身标准代理流，SOCKS5 另有 UDP associate | 可 TLS 包裹，证书校验参数 | 没有 VLESS 所有网络/REALITY 字段；HTTP 原生无 UDP。[SOCKS5](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/socks5.go)、[HTTP](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/http.go) |

#### VLESS 组合必须单列的限制

| 条目 | 固定源码可证明的结论 |
| --- | --- |
| TCP + TLS / REALITY | 默认 TCP 支路调用 `streamTLSConn`；REALITY 要求 TLS=true、有效公钥参数及可用 client-fingerprint；后两项分别见[REALITY 解析](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/reality.go)、[TLS 选择](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/transport/vmess/tls.go#L105) |
| gRPC + TLS / REALITY | gRPC 构造传入对应安全配置，使用 h2；不据此保证任意版本对端可用。[构造](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/vless.go#L565) |
| WS + REALITY 出站 | WS 分支仅特别传入 ShadowTLS/Restls/JLS；其他情况使用普通 WebSocket TLS 配置，没有传入 REALITY。全局参数被接受不能记为这个组合已支持。[分支](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/vless.go#L155) |
| WS + REALITY 入站 | 入站是外层安全 listener 后运行 HTTP/WS handler，有 REALITY builder 路径；与前行不对称，实际互通仍未测试。[服务](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/listener/sing_vless/server.go#L146) |
| XHTTP HTTP/1/2 | 调用与普通流相同的安全选择函数，包含 TLS/REALITY 等路径；XHTTP mode 有自身校验。[构造](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/vless.go#L614) |
| XHTTP HTTP/3 | 明确要求 TLS，并拒绝 REALITY、ShadowTLS、Restls、JLS 等非空特殊安全模式；上下行 transport 都有这项检查。[主方向](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/vless.go#L693)、[下载方向](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/vless.go#L884) |
| XHTTP 模式 | 有 auto、stream-up、stream-one、packet-up；stream-one 与 download-settings 在出站构造时明确不兼容。[下载配置校验](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/vless.go#L719)、[入站模式](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/listener/sing_vless/server.go#L200) |
| Vision | flow 识别 `xtls-rprx-vision` 前缀；真正建立 Vision 还需要可识别的 TLS 1.3 或 VLESS Encryption 连接。没有可识别连接会返回错误，不能因为构造器接受 flow 就把所有 transport + Vision 打勾。[flow 构造](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/vless.go#L462)、[运行路径前提](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/transport/vless/vision/vision.go#L27) |
| Vision 与 UDP | 入站普通 UDP command 在 Vision 下明确拒绝；Mux/XUDP 是另一条命令路径，不能概括为“Vision 绝无 UDP”或“所有 UDP 模式都可用”。[服务命令处理](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/listener/sing_vless/service.go#L136) |
| 包编码 | 出站默认倾向 XUDP；packetaddr/packet 设置会改变 XUDP 选择。它们是包封装语义，不是额外传输或安全协议。[选择](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/vless.go#L474) |
| 无 TLS 模式 | 入站无证书/特殊安全/decryption 且没有 allow-insecure 时拒绝；因此不能把 VLESS+TCP+none 作为无条件可用的默认承诺。[入站条件](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/listener/sing_vless/server.go#L265) |

VMess/VLESS 的 HTTPUpgrade 通过 WS 选项中的 `v2ray-http-upgrade` 等开关表达，不是其网络 switch 的独立 `httpupgrade` 分支。未知 network 名称会落入默认 TCP 分支，不能用“配置没有报错”来证明不存在的网络已经实现。[VMess WS 选项](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/vmess.go#L165)、[VLESS 分派](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/vless.go#L155)。

通用 `smux` 在出站 parser 构造之后包裹适配器；可为逻辑流/包增加 sing-mux 编码，only-tcp=true 时包仍交给底层。对端也必须理解相应复用，不能将 HTTP+smux 的逻辑包等同于普通 HTTP 原生 UDP。`smux`/`yamux`/`h2mux` 是文档列出的复用选择，不是 Xray mux.cool 的同义词。[包装入口](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/parser.go)、[包分派](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/singmux.go)、[文档](https://wiki.metacubex.one/config/proxies/)。

### 分析与启发

kerlico 应先选一个明确角色与最小组合，再逐行补齐传输/安全/flow/包编码，并以正负用例验证。共同参数应由能力约束控制，不采用“所有协议 × 所有传输 × 所有安全”的自动生成支持表。

### 未验证项

Vision 在每一种封装/Encryption 组合中的连接解包、所有 XHTTP split 模式、WS/REALITY 入站和其他核心的双向互通都未验证。mKCP、Mekya、TLSMirror 等存在构造与测试文件，但本轮没有执行测试；测试文件名称本身不作为互通通过证据。

## 4. 不应混入远端协议总数的能力

### 核心结论

系统接入、内部动作、策略与 DNS 传输需要保留清单，但应与远端代理协议分别统计。

### 来源与事实

| 分类 | 固定源码确认的项目 | 限制 / 来源 |
| --- | --- | --- |
| 系统与组合入口 | `mixed`、`redir`、`tproxy`、`tun`、`tunnel`、`hysteria2-realm` | Listener 共 20 type，扣除 14 个线协议族后为这 6 个入口；Realm 的具体转发语义仍待专项核查。[解析器](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/listener/parse.go) |
| 内部出站动作 | `direct`、`dns`、`reject`、`rematch` | 在出站 parser 中登记，但不是四种远端线协议。[解析器](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/parser.go) |
| 策略组 | select、url-test、fallback、load-balance、relay | relay 组不是 `gost-relay` 线协议；providers 是资源加载来源。[组解析](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outboundgroup/parser.go) |
| DNS | UDP、TCP、TLS、HTTP/HTTPS、QUIC；system、DHCP、Tailscale/EasyTier 名称空间、rcode | DoH 实现另有 HTTP/3 相关能力；不是所有项都代表远程 DNS wire transport。[URI 解析](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/config/config.go#L1203)、[DoH](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/dns/doh.go) |
| TUN / L3 栈 | system、gvisor、mixed、mips；WireGuard 另有 IP stack 选择 | gVisor 分支需构建能力；TProxy/redirect 的平台实现另有 build constraint。不能据类型存在声称所有 OS 可用。[TUN 配置](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/listener/parse.go)、[WireGuard 栈校验](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/wireguard.go#L150) |
| 特殊构建 | Tailscale、EasyTier、ZeroTier 可变；Hysteria fake-TCP 有平台/标签条件 | Tailscale 需 with_gvisor；no_easytier/no_zerotier 切换到 stub；fake-TCP 为 linux && !no_fake_tcp。[Tailscale stub](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/tailscale_stub.go)、[fake-TCP](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/transport/hysteria/conns/faketcp/tcp_linux.go) |

官网目录本次出现的 EasyTier、Tailscale、ZeroTier、OpenVPN、TrustTunnel、ShadowQUIC 等，在固定源码中都找到了对应登记路径；本轮未形成“官网有而固定源码完全没有”的肯定差异项。反向有 `gost-relay`、嵌套安全/传输等入口不直接出现在本次官网主菜单，说明菜单也不是完整解析器清单。[官网目录](https://wiki.metacubex.one/config/proxies/)、[固定 parser](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/parser.go)。

### 分析与启发

实现清单按协议/系统入口/传输安全/包与复用/DNS/策略分别编号，减少统计上的假覆盖。默认构建与特殊构建的清单分开，不用单个“支持”勾号隐藏 stub 条件。

### 未验证项

未完整枚举 overlay 服务控制面要求、DNS 每个 URL 附加参数、平台自动路由、所有条件构建的可编译性；这些需要后续选定任务与平台后补齐。

## 5. 覆盖清单与后续任务边界

### 核心结论

本笔记足以为联合表提供完整 parser 类型集及关键组合规则，不能充当性能、协议正确性或实际节点兼容证明。

### 来源与事实

本轮检查了两个完整解析入口、全部 24 个远端/隧道出站实现文件的角色与流/包入口、对应 Listener 声明，以及 VLESS/VMess/Trojan/SS 的关键传输安全构造。额外检查 Vision 的连接类型前提、sing-mux 包分派、Overlay 构建 stub、DNS URI 解析和五类组解析。逐项来源已在表中给出；重要原始入口为 [outbound parser](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/parser.go)、[inbound parser](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/listener/parse.go)。

### 分析与启发

候选开发拆分可为：基础 SOCKS/HTTP；SS 无插件与包路径；VLESS TCP+TLS；VLESS TCP+REALITY；Vision；XHTTP HTTP/1/2+TLS；XHTTP HTTP/1/2+REALITY；XHTTP HTTP/3+普通 TLS；之后再加入上下行分离、其他包编码和其他协议。每项仍需选定方向、对端版本与验收条件，不将此排序记为用户已经确认。

### 未验证项

- 未对每个协议的全部密码套件、旧格式别名和所有数值配置做穷举。
- 未逐行审计全部依赖实现；SS 方法创建等依赖的具体算法集以锁定依赖为准。
- 未构建、未运行任何上游程序或测试，没有连接本项目测试机器。
- 未读取本项目私有目录、机器凭证或用户身份资料；没有提交、推送或修改其他研究文件。
