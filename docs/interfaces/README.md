# 实现接口目录

更新日期：2026-11-02（Asia/Shanghai）

本目录维护当前源码已实现的 Rust 公共接口、JSON v2 配置契约与 23 个协议模块的实现边界。各模块的实时测试进度见根 [STATUS.md](../../STATUS.md)，跨进程设备共享、独立路由/DNS/TUN 等后续目标见 [架构设计导航](../README.md)。

## 核心与公共接口

| 文档 | 内容范围 |
| --- | --- |
| [核心接口 (core.md)](core.md) | 装配流程、身份鉴别、业务流完成权（`FlowOpen`）、唯一业务计量与服务回收契约 |
| [配置与命令行 (config.md)](config.md) | JSON v2 根结构、管理账户、节点成员、资源限制与 CLI 子命令 |
| [节点与共享目标访问 (node-egress.md)](node-egress.md) | 凭据隔离清单、`Local`/`Remote` 目标路径、载体计量与服务退休收据（`ServiceRetirement`） |
| [统计历史 (history.md)](history.md) | SQLite 用量、访问与带宽记录，关闭收据和只读 CLI 查询 |
| [TUN 入站 (tun.md)](tun.md) | 系统 TUN 接口、路由配置与限制 |
| [DNS (dns.md)](dns.md) | 上游与静态 hosts |
| [控制接口 (control.md)](control.md) | 只读 HTTP 端点 |
| [设备所有者 (device-runtime.md)](device-runtime.md) | 同进程共享 WARP、原生载体与业务路径、私有状态和生命周期 |
| [语言与诊断 (localization.md)](localization.md) | 显式语种、双语 CLI、稳定诊断码及目录覆盖边界 |
| [IP 隧道 (ip-tunnel.md)](ip-tunnel.md) · [HTTP 载体 (http-carrier.md)](http-carrier.md) | WireGuard 共用 IP 数据面与受管 HTTP DATA/QUIC 载体 |

## 协议模块接口（23 个）

| 文档 | 角色与能力范围 |
| --- | --- |
| [VLESS](vless.md) | 双端 TCP/UDP，支持 RAW/WS/HTTPUpgrade/gRPC/XHTTP、TLS/REALITY、Vision、Encryption 混合密钥链、ML-DSA-65 校验、Mux、XUDP 跨载体迁移、XDRIVE、packetaddr |
| [AnyTLS](anytls.md) | 原生 Rust TLS 双端、会话复用、padding 与 TCP/UoT v2 |
| [SS2022](ss2022.md) | 三算法双端 TCP/UDP、AES EIH 多用户与客户端身份链 |
| [SOCKS](socks.md) | SOCKS 4/4a/5 双端与 SOCKS5 UDP 关联 |
| [HTTP 代理](http-proxy.md) | HTTP CONNECT 双端、普通 HTTP 转发、Basic 认证与 TLS |
| [Shadowsocks](shadowsocks.md) | AEAD / legacy / none 双端 TCP/UDP |
| [Trojan](trojan.md) | 双端传输与 TCP/UDP |
| [VMess](vmess.md) | AEAD 双端 TCP/UDP 与防重放边界 |
| [Snell](snell.md) | v4 出站、v5 节点与 v6 双端 |
| [TUIC](tuic.md) | v4/v5 双端与同 Socket 多目标 UDP 关联 |
| [Hysteria v1](hysteria1.md) | 独立握手、QUIC 载体与双端多目标 UDP |
| [Hysteria2](hysteria2.md) | 原生 QUIC/H3 双端、UDP 关联与 Salamander 混淆 |
| [ShadowQUIC](shadowquic.md) | 原生 JLS/QUIC 双端（v1/v2）与有界回退 |
| [SSH](ssh.md) | 原生 `direct-tcpip` 客户端出站、固定主机公钥校验与显式认证 |
| [Gost Relay](gost-relay.md) | 原生 CONNECT 客户端出站、TCP/固定 UDP、TLS 与 SMUX v1 |
| [Mieru](mieru.md) | TCP 双端、流复用与 Full Cone UDP 隧道 |
| [ShadowsocksR (SSR)](shadowsocksr.md) | 独立 protocol / obfs / cipher 双端与真实鉴权边界 |
| [ShadowTLS](shadowtls.md) | 内层 AEAD 流包装双端与认证/保护分域凭据 |
| [TrustTunnel](trusttunnel.md) | TLS H1/H2/H3 双端与固定目标 UDP |
| [Naive](naive.md) | H1/H2/H3、padding 与 UoT 双端 |
| [Sudoku](sudoku.md) | 记录/表/流/UoT/多路复用与六类载体双端 |
| [Tor](tor.md) | 基于 `arti-client` 的原生客户端 TCP 出站、目录权限校验与电路隔离 |
| [WireGuard](wireguard.md) | 基于 Boringtun + smoltcp 的原生双端 TCP/UDP 隧道与多用户 peer 隔离 |
| [MASQUE](masque.md) | HTTP/3 CONNECT-IP 客户端出站，经用户态 IP 数据面提供 TCP/UDP |
| [OpenVPN](openvpn.md) | 原生 2.x 客户端出站：UDP/TCP、tls-auth/tls-crypt、AEAD P_DATA_V2、推送配置与换钥 |
| [OpenConnect](openconnect.md) | 原生 AnyConnect 客户端出站：XML 口令认证、TLS 上的 CSTP 隧道、DPD 与 keepalive（无 DTLS） |
| [Tailscale](tailscale.md) | pre-auth key 原生加入 tailnet 的客户端出站：TS2021 控制面、DERP、直连 UDP、出口节点与子网路由 |

## 集成与专项验证记录

- [2026-11-02 协议恢复与矩阵验证](../testing/protocol-restoration-20261102.md)
- [VLESS 扩展组合验证](../testing/vless-combinations.md)
- [首批八模块联合集成](../testing/protocol-batch-1.md) · [第二批十一模块联合集成](../testing/protocol-batch-2.md)
- [凭据隔离契约验证](../testing/credential-isolation-contract.md)
