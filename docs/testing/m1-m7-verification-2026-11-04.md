# 2026-11-04 M1–M7 功能对齐与双端验证记录

本文记录 `M0`（`v1.3.3`）至 `M7`（`v1.10.0`）三核心（Mihomo、sing-box、Xray）主要功能对齐完成后的验证结果。能力总表共 4,360 项，其中已实现 1,621 项、部分实现 459 项（合计 2,080 项实测通过，未测 0 项），通过 `python3 tools/capability_matrix.py build` 与 `check --strict` 校验。

## 阶段验证总览

| 阶段 | 版本 | 新增/补齐实测项 | 累计实测通过 | 核心验证范围 |
| --- | --- | --- | --- | --- |
| `M0` | `v1.3.3` | 1,180 | 1,180 | 基线 1,180 项实测核销；QUIC 空载关闭、VLESS 出站多目标 UDP、WireGuard 瞬时容错、EasyTier UDP 与 smoltcp 丢包恢复修复 |
| `M1` | `v1.4.0` | +112 | 1,292 | `mixed`（HTTP+SOCKS 首字节自动识别）、`redirect`、`tproxy` 入站；Trojan/VLESS 入站 `fallback` 分流（含 `xver` PROXY v1/v2）；MASQUE 服务端入站；`dns` 内部出站；Hysteria v1/v2 端口跳跃与速率控制 |
| `M2` | `v1.5.0` | +138 | 1,430 | `dialer-proxy` / `detour` 链式拨号；入站 `accept_proxy_protocol`（PROXY v1/v2）；`sing-mux`（`h2mux`/`smux`/`yamux` + padding）；Shadowsocks `UoT` v1/v2；XHTTP 分帧/混淆/`xmux`；Xray `finalmask`（`fragment`/`udp_hop`/`brutal`）；TLS 证书/公钥固定、ECH、热重载、内置 ACME 与 REALITY `mldsa65_seed` |
| `M3` | `v1.6.0` | +180 | 1,610 | TLS/HTTP/QUIC/BitTorrent/SSH/RDP 协议嗅探；Fake-IP 双栈池（`198.18.0.0/15`、`fc00::/18`）与磁盘持久化；DoH/DoQ、乐观缓存、ECS 与 DNS 规则动作；`rule-set`（`.srs`/`.mrs`/JSON/YAML）与逻辑/进程规则；TUN `auto-route`/`auto-redirect`/`strict-route` |
| `M4` | `v1.7.0` | +170 | 1,780 | `select`/`url-test`/`fallback`/`load-balance`/`balancer` 策略组与并发主动测速；`proxy-providers` 订阅解析与 `override`；Clash/Mihomo/Xray/SSM RESTful & WS 控制面 API；YAML/JSONC/TOML 配置解析；`generate`/`tls`/`xray` CLI 与 `SIGHUP` 热重载 |
| `M5` | `v1.8.0` | +151 | 1,931 | `/ui`（`external-ui`）静态面板托管与 CORS/PNA 响应头；`-C` 多配置文件深度合并与受控环境变量注入；`rule-set compile/decompile/convert/match`、`geoip`/`geosite` 与 `tools` CLI |
| `M6` | `v1.9.0` | +67 | 1,998 | 内置 SNTP/NTPv4 时钟偏移校准客户端（支持代理拨号）；Shadowsocks SIP003 子进程托管与 `obfs-local`/`v2ray-plugin` 原生兼容；VLESS Reverse 内网穿透反向代理（Portal <-> Bridge 隧道派发） |
| `M7` | `v1.10.0` | +82 | 2,080 | `inbound/openvpn` TCP/UDP 服务端入站（TLS 握手、`key_method_2`、`PUSH_REPLY`、`tls-auth`/`tls-crypt`/`tls-crypt-v2`、AEAD `DataV2` 与 `ServerTunnel` 用户态 IP 栈转发）及 WireGuard 接口级参数对齐 |

## 重点新能力端到端验证

| 验证领域 | 用例与验证方法 | 结果 |
| --- | --- | --- |
| OpenVPN 双端互通（`crates/protocol-openvpn`） | 客户端 `Session` / `OpenVpnFactory` 与服务端 `ServerSession` / `OpenVpnNodeFactory` 执行完整 `HardReset` → TLS 1.3 握手 → `key_method_2` 口令鉴权 → `PUSH_REQUEST`/`PUSH_REPLY`（`10.8.0.2/24` + `tls-ekm`）→ `DataV2`（AES-256-GCM + `tls-crypt`）双向 IP 包与 `ServerTunnel` 转发 | 通过 |
| MASQUE 双端互通（`crates/protocol-masque`） | `MasqueFactory` 与 `MasqueNodeFactory` 建立 HTTP/3 `connect-ip` 隧道，完成 `ADDRESS_ASSIGN`、`ROUTE_ADVERTISEMENT` Capsule 协商与 QUIC Datagram / Stream Capsule IP 包转发 | 通过 |
| VLESS Reverse 与内置 ACME（`crates/protocol-vless`） | Reverse Portal 入站接收 `reverse.internal.v2fly.arpa` 反向连接并注册至共享隧道池，Reverse 出站按 `tag` 认领隧道完成双向字节流桥接；ACME 配置在缺少证书文件时自动签发并持久化域名证书，绑定 `ReloadingCertResolver` 热重载 | 通过 |
| Shadowsocks SIP003 + UoT + sing-mux（`crates/protocol-shadowsocks`、`crates/net`） | `obfs-local`（HTTP/TLS 混淆）与 `v2ray-plugin` 原生模式及外部插件生命周期托管、UDP-over-TCP v1/v2 数据报分帧、`sing-mux`（`h2mux`/`smux`/`yamux`）多路复用流与 UDP 会话 | 通过 |
| 嗅探、Fake-IP、规则集与策略组（`crates/dns`、`crates/routing`、`crates/egress`） | TLS SNI / HTTP Host / QUIC Initial 嗅探还原域名；Fake-IP 正向分配与反向映射持久化；`.srs`/`.mrs` 二进制规则集编译反编译与路由匹配；`select`/`url-test`/`fallback`/`load-balance` 故障转移与并发延迟探测 | 通过 |
| 控制面 API 与 CLI 工具链（`crates/control`、`apps/kerlico`） | `/v1/*` 只读统计、`/proxies` 切换与测速、`/connections` 管理、`/configs` 热更新、`/dns/query` 与 `/cache/fakeip/flush`、`/ui` 静态资源与 CORS 预检；CLI `format`/`merge`/`rule-set`/`geoip`/`geosite`/`generate`/`tls`/`tools` 全命令覆盖 | 通过 |

## 门禁与复现命令

在 `perf-01` 上运行完整发行门禁：

```sh
tools/worker_gate.sh perf-01 HEAD
python3 tools/capability_matrix.py check --strict
python3 site/build.py && python3 site/check.py
```
