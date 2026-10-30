# Xray-core 协议与组合支持核查

## 1. 本次依据哪个版本，结论到哪一层？

### 核心结论

固定基线仍为正式发行 `v26.10.29`，提交 `0afec66085a85191e9dd2a4a6646c7c9a94688d1`。本次核查注册、配置构建和关键运行分支，没有构建、运行或互通测试；“配置接受”不能读成“所有组合已实测”。[正式发行](https://github.com/XTLS/Xray-core/releases/tag/v26.10.29)、[固定提交](https://github.com/XTLS/Xray-core/commit/0afec66085a85191e9dd2a4a6646c7c9a94688d1)

### 来源与事实

| 项目 | 观察结果 | 来源 |
| --- | --- | --- |
| 访问日期 | 2026-10-30，Asia/Shanghai | 本次访问记录 |
| latest 正式 release | `v26.10.29`，`prerelease=false`，发布于 2026-10-29 08:43:27 UTC | [release API](https://api.github.com/repos/XTLS/Xray-core/releases/latest) |
| 标签解析 | `v26.10.29` 对应上述完整 SHA，下载的源码以该 SHA 固定 | [标签提交 API](https://api.github.com/repos/XTLS/Xray-core/commits/v26.10.29) |
| 标准发行注册 | `main/distro/all/all.go` 包含代理与传输注册导入；配置注册也通过其依赖引入相应实现 | [组件入口](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/main/distro/all/all.go) |
| 滚动文档 | 用于理解角色与交叉核对，不替代固定源码；本次传输页速查表没有列出源码已有的 XDRIVE | [滚动传输页](https://xtls.github.io/config/transport.html)、[源码传输注册](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/transport_internet.go#L18) |

### 分析与启发

后续总表应分别标注“有类型注册”“构建可接受”“存在相关运行处理”“已互通验证”。本次最后一项均为未验证。文档中的传输字段 `method` 与旧字段 `network` 都有源码入口，不能把一个字段的改名当成另一个核心的协议兼容要求。

### 未验证项

未检查所有发布二进制的实际内容或依赖裁剪，未运行测试。本文件不提供吞吐、安全强度或跨平台可用性排名。

## 2. 实际有哪些入站、出站和协议变体？

### 核心结论

配置表有 **13 个入站字符串、15 个出站字符串**，包括别名与特殊处理器。按远端协议族归并为 HTTP、SOCKS、Shadowsocks、VMess、VLESS、Trojan、WireGuard、Hysteria v2、MASQUE 共 9 类；TUN、Tunnel 与 direct/block/DNS/loopback 另列。[双注册表](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/xray.go#L27)

### 来源与事实

| 协议族 | 入站 | 出站 | 已核查的能力与限制 | 固定来源 |
| --- | --- | --- | --- | --- |
| HTTP | `http`；`socks/mixed` 处理器也可识别 HTTP | `http` | 出站建立 CONNECT 通道，代码区分 HTTP/1.1 与 H2；原生 UDP 请求明确报错。通用 mux 封装不能据此直接算作原生 UDP 支持 | [HTTP 客户端](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/http/client.go)、[HTTP 服务端](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/http/server.go) |
| SOCKS | `socks` 与 `mixed` 是同一配置/实现；接受 SOCKS4、4a、5，非 SOCKS 首字节交 HTTP；4/4a 仅 CONNECT，要求密码认证时拒绝 4 | `socks` 的客户端握手固定为 SOCKS5，没有 SOCKS4 出站选择字段 | TCP；SOCKS5 UDP Associate 另开数据报路径，受入站 UDP 开关与关联约束；不能把入口的 `Network()=TCP` 误读为无 UDP | [服务端识别](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/socks/server.go#L66)、[4/5 握手及客户端握手](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/socks/protocol.go)、[配置](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/socks.go) |
| Shadowsocks AEAD | `shadowsocks` | `shadowsocks` | TCP/UDP；可配置 AES-128-GCM、AES-256-GCM、ChaCha20-Poly1305、XChaCha20-Poly1305 及源码列出的别名；当前解析器不接受任意旧流密码名称 | [算法与配置分派](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/shadowsocks.go)、[客户端](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/shadowsocks/client.go) |
| Shadowsocks 2022 | 同一 `shadowsocks` 名称，按 method 转到 2022 实现；单用户、多用户、relay 三种构造 | 同一名称按 method 转到 2022 客户端 | TCP/UDP；`2022-blake3-aes-128-gcm`、`2022-blake3-aes-256-gcm`、`2022-blake3-chacha20-poly1305`。多用户/relay 只接受 AES 系；ChaCha 多 key 明确拒绝 | [配置分派与限制](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/shadowsocks.go#L109)、[方法表](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/shadowsocks_2022/cipher.go)、[出站限制](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/shadowsocks_2022/outbound.go#L37) |
| VMess | `vmess` | `vmess` | TCP/UDP 与 mux 请求路径存在；配置的 body security 明确映射 AES-128-GCM、ChaCha20-Poly1305、auto，其他字符串落到 AUTO。不能把旧资料中的 none/zero 当作本版本可明确选择的模式 | [配置映射](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/vmess.go#L25)、[客户端编码](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/vmess/encoding/client.go)、[出站命令](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/vmess/outbound/outbound.go) |
| VLESS | `vless` | `vless` | TCP/UDP/XUDP、可选 Vision 与 VLESS Encryption。加密为 `none` 或当前 `mlkem768x25519plus` 构造，带 native/xorpub/random 等选项；方向字段、flow 与传输有不同约束，见组合表 | [配置构建](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/vless.go)、[入站](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/vless/inbound/inbound.go)、[出站](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/vless/outbound/outbound.go) |
| Trojan | `trojan` | `trojan` | TCP 与协议封装 UDP 路径均存在；公共出站构建限制公网目的地不能裸用无安全传输的 Trojan | [入站](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/trojan/server.go)、[出站](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/trojan/client.go)、[安全前置检查](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/xray.go#L260) |
| WireGuard | `wireguard` 以 server 模式构造 | `wireguard` 以 client 模式构造 | IP 隧道后端；客户端对业务 TCP/UDP 分别拨入栈，服务端自行接入，不由普通端口 worker 提供业务流；不是可套任意 streamSettings 的普通代理编解码 | [方向配置](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/wireguard.go)、[客户端](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/wireguard/client.go#L245)、[服务端](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/wireguard/server.go#L224) |
| Hysteria v2 | 名称为 `hysteria`，`version` 必须为 2 | 同左 | 双向构造器要求 hysteria 传输；TCP 请求与 UDP datagram 路径存在，UDP 要求其专用 InterConn，不能用任意普通流替代 | [版本构建](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/hysteria.go)、[客户端](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/hysteria/client.go)、[服务端](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/hysteria/server.go) |
| MASQUE | `masque` | `masque` | 双向均要求自身 masque 传输与 TLS；实现 CONNECT-IP、内部地址/栈及业务 TCP/UDP，不能据一个通用 HTTP CONNECT 名称推断等价 | [配置](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/masque.go)、[客户端构造与 TCP/UDP](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/masque/client.go)、[服务端构造](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/masque/server.go#L123) |

该固定双注册表未发现 SSR、Trojan-Go、TUIC、AnyTLS、SSH、Snell、ShadowTLS、Mieru 或独立 Hysteria v1 入口；这里只限定标准配置入口，不能证明不存在外部派生版本。[完整注册表](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/xray.go#L27)

### 分析与启发

联合主表需要把“相同配置名称下的密码族/版本”拆清，把 SOCKS 入站和出站版本分开。HTTP 原生 UDP、SOCKS/SS 的原生数据报和另加 mux/XUDP 的数据报应是不同能力项。

### 未验证项

未进行任一密码族、角色或对端版本的互通；通用 mux 套在 HTTP、SS2022 等处理器上时的完整 UDP 语义不在本次静态检查中作保证。VMess 历史认证变体不凭旧文档登记为支持。

## 3. 传输、安全与协议附加能力怎样组合？

### 核心结论

固定构建器接受 9 类传输：RAW/TCP、XHTTP、mKCP、gRPC、WebSocket、HTTPUpgrade、Hysteria、MASQUE、XDRIVE。TLS、REALITY、协议内加密、Vision 和 mux 不属于同一个选择层；分别有构建或运行条件。[传输构建器](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/transport_internet.go)

### 来源与事实

| 传输配置名/别名 | 安全层与重要边界 | 固定依据 |
| --- | --- | --- |
| `raw` / `tcp` → 内部 `tcp` | 公共构建可选 none/TLS/REALITY；协议还可能要求外层安全或自身加密 | [名称与安全构建](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/transport_internet.go#L18) |
| `xhttp` / `splithttp` | none、TLS、REALITY 有代码路径；无 TLS/REALITY 时选 HTTP/1.1，REALITY 强制选 H2；TLS 根据 ALPN 选 H1.1/H2/H3 | [HTTP 版本选择](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/transport/internet/splithttp/dialer.go#L82) |
| `grpc` | 公共构建明确接受 none/TLS/REALITY；REALITY 与 gRPC 的完整端到端握手本次未实测 | [允许名单](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/transport_internet.go#L117) |
| `ws` / `websocket` | 公共构建可选 none/TLS；REALITY 明确不在允许名单 | [构建器](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/transport_internet.go#L117) |
| `httpupgrade` | 同上，REALITY 在构建阶段拒绝 | [构建器](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/transport_internet.go#L117) |
| `kcp` / `mkcp` → 内部 `mkcp` | 公共构建可选 none/TLS；REALITY 拒绝；旧 mKCP mask 与传输名称分开 | [传输构建](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/transport_internet.go)、[mask 注册](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/transport_finalmask.go#L78) |
| `hysteria` | 传输配置也要求 version=2；监听与拨号必须取得 TLS 配置。传输还可承载其他已匹配的流协议，但需配置认证或取得 validator；不能由名称推断裸流即可成为 Hysteria UDP | [配置](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/transport_method.go#L762)、[监听检查](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/transport/internet/hysteria/hub.go#L196)、[拨号检查](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/transport/internet/hysteria/dialer.go#L327) |
| `masque` | 只允许 masque 代理角色，且 TLS 必需；实际支持 H2/H3 路径，客户端由 ALPN 选择，服务端可按 ALPN 开启相应监听 | [角色限制](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/xray.go)、[拨号](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/transport/internet/masque/dialer.go#L150)、[监听](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/transport/internet/masque/hub.go#L47) |
| `xdrive` | 源码已有、滚动速查表未列的特殊存储承载；只允许 VLESS Encryption，flow 必须为空，客户端普通模式要求 Mux.Cool；REALITY 被共同允许名单拒绝 | [专用验证器](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/xray.go#L281)、[服务构造](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/transport_method.go#L987) |

补充约束：

- `method` 有值时覆盖 `network`；`rawSettings` 优先于旧 `tcpSettings`，`xhttpSettings` 优先于旧 `splithttpSettings`。`h2/h3/http` 旧独立传输和 `quic` 旧独立传输返回已移除错误；XHTTP 的 H3 不等于重新支持 `network=quic`。`security=xtls` 旧模式也明确移除。[别名与移除检查](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/transport_internet.go#L18)
- XHTTP mode 为 auto、packet-up、stream-up、stream-one。显式 stream-one 禁止 downloadSettings；自动模式在 REALITY 下默认 stream-one，存在独立下载设置时改为 stream-up；cookie/header 上行数据和 GET 上行被限制在 packet-up。[模式构建](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/transport_method.go#L316)、[模式选择](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/transport/internet/splithttp/dialer.go#L332)
- XDRIVE 服务枚举为 local、google-drive、template、s3；旧 `Google Drive` 名称会转换。它不是任意协议共有的网络封装，且有自身存储和 xmux 要求；Google Drive 的 H3 分支限制 UDP mask 仅 noise，并拒绝 brutal 类拥塞配置。[服务枚举](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/transport_method.go#L1015)、[附加限制](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/transport_internet.go)
- TLS 指纹/uTLS、ECH 等属于安全选项；REALITY 的客户端/服务端字段不同，并有指纹、密钥长度和服务名等校验。这里不复制具体配置材料，也不把这些选项当成独立代理协议。[TLS 与 REALITY 构建](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/transport_security.go)

### 分析与启发

总表可以把通用传输集作为一个引用集合，再列协议自身的例外，避免复制出数百个未经验证的排列。XHTTP 自身的 HTTP 版本、mode 与独立下载设置也形成组合，不能只写一行“支持 XHTTP”。

### 未验证项

公共 StreamConfig 接受某项，不足以证明每个代理、双方向、数据报与该项均互通；表中的“公共构建”有意保留该证据层级。未穷举全部指纹、padding、mask 数值、云存储服务和 HTTP 服务端行为。

## 4. VLESS 的正反组合矩阵是什么？

### 核心结论

REALITY 不是 TCP 的子协议；在该固定版本中，其允许名单包含 RAW、XHTTP、gRPC。Vision 又是 VLESS flow，直接 TLS/REALITY 模式与 VLESS Encryption 包装下的限制不同；不是给任意传输加一个 flow 字符串就可用。[公共安全允许名单](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/transport_internet.go#L117)、[Vision 出站路径](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/vless/outbound/outbound.go#L242)

### 来源与事实

表内“接受/有路径”均未经过互通实测。`Encryption=none` 指没有启用 VLESS 自身 Encryption，不是指外层 TLS/REALITY。

| VLESS 组合 | 固定源码判定与条件 | 证据 |
| --- | --- | --- |
| RAW + TLS，flow 空 | 构建接受；普通 VLESS 流路径存在 | [VLESS 构建](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/vless.go)、[传输构建](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/transport_internet.go) |
| RAW + TLS + Vision，Encryption=none | 双方 flow 必须相容；运行路径还检查外层 TLS 1.3 | [入站检查](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/vless/inbound/inbound.go#L550)、[出站检查](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/vless/outbound/outbound.go#L242) |
| RAW + REALITY + Vision，Encryption=none | 存在直接 REALITY 通道的 Vision 路径；仍需有效 REALITY 与双方 flow 配置 | [入站与 flow](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/vless/inbound/inbound.go#L550)、[安全构建](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/transport_security.go) |
| XHTTP + TLS，flow 空 | 构建与实际 XHTTP TLS 拨号路径存在；mode、HTTP 版本、下载设置仍分别约束 | [XHTTP 拨号](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/transport/internet/splithttp/dialer.go) |
| XHTTP + REALITY，flow 空 | 公共构建接受，拨号明确调用 REALITY；HTTP 版本选择为 H2，不是 H3 | [XHTTP 安全与版本](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/transport/internet/splithttp/dialer.go#L82) |
| gRPC + REALITY，flow 空 | 明确在构建允许名单；本次未逐行完成 gRPC 握手路径和端到端核验 | [允许名单](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/transport_internet.go#L117) |
| WebSocket / HTTPUpgrade / mKCP / XDRIVE + REALITY | 公共构建阶段拒绝 | [安全检查](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/transport_internet.go#L117) |
| XHTTP 等非直连安全流 + Vision，Encryption=none | flow 字段可以被解析，但 Vision 的运行分支要求直接 TLS/REALITY 或 Encryption CommonConn，不能因为前一步构建接受就登记支持 | [出站通道类型检查](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/vless/outbound/outbound.go#L249)、[入站通道类型检查](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/vless/inbound/inbound.go#L550) |
| 非 RAW 传输 + Vision + VLESS Encryption | 存在以 Encryption CommonConn 进入 Vision 的分支，因而不能绝对说“Vision 永远只支持 TCP”；穿透/复制行为与直接 RAW 不同，具体组合仍待互通 | [Encryption 包装及 Vision 分支](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/vless/outbound/outbound.go#L202) |
| RAW + none + Encryption=none，公网服务端 | 出站构建拒绝；私有 IP/域名等受信目标有例外；启用 VLESS Encryption 的分支也有例外 | [安全前置检查](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/xray.go#L245) |
| XDRIVE + VLESS Encryption，flow 空 | 专用检查要求 Encryption 非 none，普通客户端要求 mux enabled，相关并发不能为负、UDP443 策略不能 skip；反向模式有自己的 mux 例外 | [专用验证器](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/xray.go#L281) |
| XDRIVE + Vision / Encryption=none / 非 VLESS | 专用配置验证拒绝；不能由上一行非 RAW + Encryption 的一般分支推导 XDRIVE 也支持 Vision | [专用验证器](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/xray.go#L281) |
| VLESS + MASQUE 传输 | 配置构建拒绝，masque 传输只供 masque 代理角色 | [角色验证](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/xray.go) |

入站 flow 允许空或 `xtls-rprx-vision`；出站另允许 `xtls-rprx-vision-udp443`，客户端会将扩展选项归一为线上 Vision 标识。VLESS 入站使用顶层 decryption，而用户项不得带 encryption；出站 encryption 必须显式为 none 或满足其构造格式，不能静默留空。[入/出站构建](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/vless.go)

### 分析与启发

kerlico 的任务单位宜是协议、方向和一个明确组合；支持 RAW + REALITY + Vision 后，仍需独立任务验证 XHTTP + REALITY。公共组合校验与协议特有校验应同时存在。

### 未验证项

上表不穷举 VLESS Encryption 的所有选项与各服务端兼容版本。没有确认所有非 RAW + Encryption + Vision 组合能互通；XHTTP 独立下载也可能使上行、下行具有不同 HTTP/安全参数，需要单独测试。

## 5. UDP、flow 与复用有哪些不能省略的限制？

### 核心结论

业务是 UDP、底层是 UDP、协议有数据报命令、是否使用 XUDP 是不同问题。Vision 与普通 TCP mux 也不能当作独立开关任意叠加。[公共出站分发](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/app/proxyman/outbound/handler.go)

### 来源与事实

- VLESS Vision 客户端把业务 UDP 转为 XUDP/Mux 命令；默认 Vision 对业务 UDP/443 有拒绝分支，`-udp443` 扩展允许该端口。入站 Vision 拒绝直接 UDP 命令，并将其 mux 通道限制为 UDP，不能把普通承载 TCP 的 Mux.Cool 当成 Vision 的可用叠加。[客户端命令与端口分支](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/vless/outbound/outbound.go#L242)、[入站允许网络](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/vless/inbound/inbound.go#L550)
- 通用 mux 有 TCP 并发、XUDP 并发及 UDP443 reject/allow/skip 策略，三者分开构建；被配置启用不代表任意对端协议能正确解释其内部会话。[配置](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/xray.go#L112)、[运行分发](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/app/proxyman/outbound/handler.go#L117)
- SOCKS UDP Associate 后单独拨 UDP，SS/SS2022 的原生 UDP 同样采用 UDP 目的网络；原生数据报并不自动经过用户为 TCP 配置的 WS、TLS 或其他流传输。另加 XUDP 的情况要按 mux 路径另测。[SOCKS UDP 拨号](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/socks/client.go#L146)、[SS2022 目的网络](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/shadowsocks_2022/outbound.go#L81)
- XHTTP 的 xmux 是 HTTP 连接/请求复用机制，不能因名称相似与代理层 Mux.Cool 合并；XDRIVE、MASQUE 也各有自身连接共享对象。[XHTTP xmux 配置](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/transport_method.go#L266)、[MASQUE 客户端](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/masque/client.go#L96)

### 分析与启发

互通表必须分 TCP、UDP、UDP443、原生数据报、XUDP 和多目标回写。不能用“已实现 UDP=true”覆盖这些差异，也不能由入口 Full-cone 映射推定任意出站 NAT 行为。

### 未验证项

未逐一检查每个远端协议的通用 mux/XUDP 兼容性，也没有抓包证明底层端口、映射、重组和长时间关联的实际行为。

## 6. 系统入口、特殊出站及附属能力附录

### 核心结论

这些项目需要在联合清单中出现，但不计入远端代理协议数量。标准配置入口与独立网络栈也不能混作同一种 transport 插件。[完整注册表](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/xray.go#L27)

### 来源与事实

| 类别 | 固定快照中的项目 | 来源/边界 |
| --- | --- | --- |
| 透明/固定目标接入 | `tunnel` / `dokodemo-door` 为别名；TCP/UDP 按配置，透明目的恢复另受 OS/socket 约束 | [实现](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/dokodemo/dokodemo.go) |
| TUN 接入 | 原生 `tun`；平台后端与用户态栈转换 TCP/UDP；默认未支持平台后端返回错误 | [接入](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/tun/handler.go)、[不支持平台分支](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/tun/tun_default.go) |
| 基础出站 | `direct/freedom`、`block/blackhole`、`loopback`、`dns`；前两对是别名 | [注册表](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/xray.go)、[DNS 特殊出站](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/dns_proxy.go) |
| WireGuard 平台后端 | Linux 有 kernel TUN 分支，非 Linux 的 kernel TUN 构造明确未实现；不能据此否定其用户态栈路径 | [Linux](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/wireguard/tun_linux.go)、[非 Linux](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/wireguard/tun_default.go) |
| DNS 解析传输 | 系统 localhost、经典 UDP、TCP（经 Dispatcher/本地）、HTTPS DoH（经 Dispatcher/本地）、h2c（经 Dispatcher/本地）、QUIC 本地模式、FakeDNS | [创建分派](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/app/dns/nameserver.go) |
| 非协议选路与服务 | Router、balancer/observatory、日志/统计、控制 API 等属于功能组件；不是网络代理协议名 | [标准组件导入](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/main/distro/all/all.go) |
| TCP FinalMask | filter、header-custom、fragment、sudoku、xmc | [TCP mask 注册](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/transport_finalmask.go#L78) |
| UDP FinalMask | filter、header-custom、mkcp-legacy、noise、salamander、sudoku、xdns、xicmp、realm、udphop | [UDP mask 注册](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/transport_finalmask.go#L86) |

### 分析与启发

mask 的类型名不是同名远端协议的实现承诺，例如 UDP header 的 wireguard 选项不等于 WireGuard 隧道。DNS 各路径与普通代理传输的选择也不能互相推导。

### 未验证项

DNS 创建分派未发现独立 `tls://` DoT 入口，本轮不据其他核心的能力补填；是否还有特定间接构造需要后续任务核查。未逐个验证 mask 可用的载体、组合顺序和角色，清单仅确认对应类型注册。

## 7. 覆盖范围、剩余问题与 kerlico 的候选任务

### 核心结论

本次完成类型与主要组合约束清点，最有价值的是将条件和拒绝路径保留，而不是把整个选项排列标为支持。原始注册、构造、运行分支的证据已分别附在前述条目。

### 来源与事实

已检查的关键入口包括：

- 配置与发行：`infra/conf/xray.go` 的双注册表、Inbound/Outbound Build、公共安全前置检查、validateXDrive，以及 `main/distro/all/all.go`。[配置入口](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/xray.go)、[发行导入](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/main/distro/all/all.go)
- 协议配置：socks、http、shadowsocks、vmess、vless、trojan、wireguard、hysteria、masque 对应的 `infra/conf/*.go`；以及 SOCKS、HTTP、SS2022、VLESS、Hysteria、MASQUE 的关键处理器分支。[配置目录](https://github.com/XTLS/Xray-core/tree/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf)、[代理目录](https://github.com/XTLS/Xray-core/tree/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy)
- 传输：`transport_internet.go`、`transport_method.go`、`transport_security.go`、`transport_finalmask.go`；XHTTP HTTP 版本和 mode 选择，Hysteria/MASQUE 的 TLS 与角色检查。[传输配置目录](https://github.com/XTLS/Xray-core/tree/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf)、[传输实现目录](https://github.com/XTLS/Xray-core/tree/0afec66085a85191e9dd2a4a6646c7c9a94688d1/transport/internet)
- 公共出站 mux 与 DNS resolver 创建分派，TUN/部分 WireGuard 平台后端。[公共出站](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/app/proxyman/outbound/handler.go)、[DNS](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/app/dns/nameserver.go)

### 分析与启发

以下仅供综合报告拆分任务，全部处于待开发/待验证，不替用户确认范围：

1. 将 HTTP/SOCKS 入站与出站、SOCKS 版本、TCP/原生 UDP 分开记录。
2. Shadowsocks AEAD 与 2022 分任务；2022 单用户、多用户、relay 和 ChaCha 多 key 限制分别验收。
3. VLESS 先选择一个角色和一个最小安全组合，再分别安排 Vision、XUDP、Encryption 与其他传输。
4. XHTTP 以 HTTP 版本、mode、独立下载和安全组合拆任务，不用一个总开关宣称所有变体可用。
5. Hysteria v2、MASQUE 与 WireGuard 保留自身数据模型和必要安全/栈条件；XDRIVE 作为独立长尾承载需求评估。
6. 编译、互通和性能验证在明确的版本、方向、数据能力和组合范围内进行；不存在本次实测结论。

### 未验证项

未穷举所有标准外第三方客户端、未检查每个 OS 的实际二进制、未跑配置解析或协议测试。gRPC+REALITY、各协议通用 mux/XUDP、所有 Encryption/flow/上下行分离排列等仍需开发时在指定对端实测；主表应保留这些空白，不用“支持”二字抹平证据等级。
