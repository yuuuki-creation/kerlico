# 上游借鉴到本项目设计的映射

更新日期：2026-11-02（Asia/Shanghai）

本文关联 mihomo、sing-box 与 Xray-core 的固定版本源码证据与 `kerlico` 的架构设计、协议实现及验证记录。上游固定基线见 [reference/README.md](README.md)，实时验证进度见 [STATUS.md](../STATUS.md)。

## 核心架构借鉴（`REF-001` – `REF-009`）

| 编号 | 主题 | 上游固定源码依据 | 本项目设计落点与当前状态 |
| --- | --- | --- | --- |
| `REF-001` | 元数据与目标分阶段保留 | [mihomo Metadata](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/constant/metadata.go)、[Xray session](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/common/session/session.go) | [核心契约](../docs/core-contracts.md)：已实现 `OriginalTarget` 与 `TargetBind` 分离；嗅探与 Fake-IP 恢复为后续扩展 |
| `REF-002` | TCP 与 UDP 语义分离 | [mihomo adapters](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/constant/adapters.go)、[tunnel/connection](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/tunnel/connection.go)、[Xray buffer](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/common/buf/buffer.go) | [数据路径](../docs/data-paths.md)：已实现 `TcpFlow`（含 `tcp_eof`）、`FixedUdpFlow` 与同 Socket 多目标 `UdpAssociation` |
| `REF-003` | 显式工厂注册与失败清理 | [sing-box registry](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/include/registry.go)、[Box](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/box.go)、[lifecycle](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/adapter/lifecycle.go) | [协议模块](../docs/protocol-modules.md)、[生命周期](../docs/runtime-lifecycle.md)：已实现 `Registry::prepare`、`Engine::bind` 事务启动与逆序回收 |
| `REF-004` | 策略组、资源提供器与健康观测 | [mihomo provider](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/provider/provider.go)、[sing-box selector](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/protocol/group/selector.go) | [总体结构](../docs/architecture.md)：规划中的 `policy` 模块 |
| `REF-005` | 协议、传输与安全能力分层 | [Xray 协议配置](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/xray.go)、[transport_internet](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/transport_internet.go) | [协议模块](../docs/protocol-modules.md)：公共传输/连接器归 `kerlico-net`，协议专属握手与组合校验归各 `protocol-*` crate |
| `REF-006` | DNS、Fake-IP 与映射租约 | [mihomo enhancer](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/dns/enhancer.go)、[sing-box route](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/route/route.go)、[Xray router](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/app/router/router.go) | [数据路径](../docs/data-paths.md)：当前已实现 `Local` 节点模式解析与 `Remote` 原目标透传；独立 DNS/Fake-IP 为后续扩展 |
| `REF-007` | 配置代次与在线更新边界 | [mihomo executor](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/hub/executor/executor.go)、[sing-box cmd_run](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/cmd/sing-box/cmd_run.go) | [生命周期](../docs/runtime-lifecycle.md)：已实现配置 `epoch` 与凭据代次绑定；在线更新分级为后续扩展 |
| `REF-008` | TUN 与宿主平台边界 | [sing-box PlatformInterface](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/experimental/libbox/platform.go)、[Xray TUN](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/tun/handler.go) | [总体结构](../docs/architecture.md)：系统 TUN 入站归规划中的 `tun`/`platform`；用户态 `smoltcp` 已在 `protocol-wireguard` 落地 |
| `REF-009` | 独立节点、全局共享出站与透传 | [0005](../docs/decisions/0005-separate-nodes-unified-egress.md)、[0006](../docs/decisions/0006-unified-client-server-core.md)、[0009](../docs/decisions/0009-global-egress-dispatcher.md)、[0010](../docs/decisions/0010-node-egress-modes-and-warp.md) | [节点与统一出站](../docs/node-egress.md)、[接口](../docs/interfaces/node-egress.md)：唯一 `EgressRuntime`/`Dispatcher` 与 `Local`/`Remote` 分流已合入，设备共享 WARP 待实现 |

## 协议与统计模块映射（`REF-010` – `REF-029`）

| 编号 | 模块 | 研究笔记 | 接口文档 | 测试记录 |
| --- | --- | --- | --- | --- |
| `REF-010` | AnyTLS (`protocol-anytls`) | [研究](research_notes/anytls-implementation.md) | [接口](../docs/interfaces/anytls.md) | [测试](../docs/testing/anytls.md) |
| `REF-011` | Shadowsocks 2022 (`protocol-ss2022`) | [研究](research_notes/ss2022-implementation.md) | [接口](../docs/interfaces/ss2022.md) | [测试](../docs/testing/ss2022.md) |
| `REF-012` | VLESS 扩展组合 (`protocol-vless`) | [研究](research_notes/vless-combinations-implementation.md) | [接口](../docs/interfaces/vless.md) | [测试](../docs/testing/vless-combinations.md) |
| `REF-013` | SOCKS 与 HTTP (`protocol-socks` / `protocol-http`) | [SOCKS](research_notes/socks.md) · [HTTP](research_notes/http-proxy.md) | [SOCKS](../docs/interfaces/socks.md) · [HTTP](../docs/interfaces/http-proxy.md) | [SOCKS](../docs/testing/socks.md) · [HTTP](../docs/testing/http-proxy.md) |
| `REF-014` | Shadowsocks AEAD/legacy (`protocol-shadowsocks`) | [研究](research_notes/shadowsocks.md) | [接口](../docs/interfaces/shadowsocks.md) | [测试](../docs/testing/shadowsocks.md) |
| `REF-015` | Trojan 与 VMess (`protocol-trojan` / `protocol-vmess`) | [Trojan](research_notes/trojan.md) · [VMess](research_notes/vmess.md) | [Trojan](../docs/interfaces/trojan.md) · [VMess](../docs/interfaces/vmess.md) | [Trojan](../docs/testing/trojan.md) · [VMess](../docs/testing/vmess.md) |
| `REF-016` | Snell (`protocol-snell`) | [研究](research_notes/snell.md) | [接口](../docs/interfaces/snell.md) | [测试](../docs/testing/snell.md) |
| `REF-017` | TUIC (`protocol-tuic`) | [研究](research_notes/tuic.md) | [接口](../docs/interfaces/tuic.md) | [测试](../docs/testing/tuic.md) |
| `REF-018` | Hysteria2 (`protocol-hysteria2`) | [研究](research_notes/hysteria2.md) | [接口](../docs/interfaces/hysteria2.md) | [测试](../docs/testing/hysteria2.md) |
| `REF-019` | Hysteria v1 (`protocol-hysteria1`) | [研究](research_notes/hysteria1.md) | [接口](../docs/interfaces/hysteria1.md) | [测试](../docs/testing/hysteria1.md) |
| `REF-020` | ShadowQUIC (`protocol-shadowquic`) | [研究](research_notes/shadowquic.md) | [接口](../docs/interfaces/shadowquic.md) | [测试](../docs/testing/shadowquic.md) |
| `REF-021` | SSH (`protocol-ssh`) | [研究](research_notes/ssh.md) | [接口](../docs/interfaces/ssh.md) | [测试](../docs/testing/ssh.md) |
| `REF-022` | Gost Relay (`protocol-gost-relay`) | [研究](research_notes/gost-relay.md) | [接口](../docs/interfaces/gost-relay.md) | [测试](../docs/testing/gost-relay.md) |
| `REF-023` | Sudoku (`protocol-sudoku`) | [研究](research_notes/sudoku.md) | [接口](../docs/interfaces/sudoku.md) | [测试](../docs/testing/sudoku.md) |
| `REF-024` | Mieru (`protocol-mieru`) | [研究](research_notes/mieru.md) | [接口](../docs/interfaces/mieru.md) | [测试](../docs/testing/mieru.md) |
| `REF-025` | TrustTunnel (`protocol-trusttunnel`) | [研究](research_notes/trusttunnel.md) | [接口](../docs/interfaces/trusttunnel.md) | [测试](../docs/testing/trusttunnel.md) |
| `REF-026` | Naive (`protocol-naive`) | [研究](research_notes/naive.md) | [接口](../docs/interfaces/naive.md) | [测试](../docs/testing/naive.md) |
| `REF-027` | 多用户、流量带宽与访问记录 (`Telemetry`) | [研究](research_notes/xray-statistics-and-access.md) | [核心接口](../docs/interfaces/core.md) | [设计](../docs/statistics-and-users.md) · [0011](../docs/decisions/0011-users-statistics-and-access-records.md) |
| `REF-028` | ShadowsocksR 与 ShadowTLS (`protocol-shadowsocksr` / `protocol-shadowtls`) | [SSR](research_notes/shadowsocksr.md) · [ShadowTLS](research_notes/shadowtls.md) | [SSR](../docs/interfaces/shadowsocksr.md) · [ShadowTLS](../docs/interfaces/shadowtls.md) | [SSR](../docs/testing/shadowsocksr.md) · [ShadowTLS](../docs/testing/shadowtls.md) |
| `REF-029` | Tor 与 WireGuard (`protocol-tor` / `protocol-wireguard`) | [Tor](research_notes/tor.md) · [WireGuard](research_notes/wireguard-native.md) | [Tor](../docs/interfaces/tor.md) · [WireGuard](../docs/interfaces/wireguard.md) | [Tor](../docs/testing/tor.md) · [WireGuard](../docs/testing/wireguard.md) |
