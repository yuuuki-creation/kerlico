# VLESS 剩余组合开工调研

日期：2026-10-30。状态：已复核主要装配边界，正在实现和逐项验证。支持范围仍以[总表](../reports/三核心%20协议%20组合支持.md)为唯一清单；本文记录实现依据与未知项，不另建完成状态。

## 组合与层次

固定基线继续为 Xray `0afec66085a85191e9dd2a4a6646c7c9a94688d1`、mihomo `3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8`、sing-box `c005f35300ce76427dc285481ec5695f5b179cd2`。角色首先延续当前客户端出站；总表中的入站观察不等于本项目已实现服务端。

装配顺序是物理连接、安全、传输包装、VLESS Encryption、VLESS 请求/响应、Vision、业务或包编码。Vision Direct 只能移除它所对应的保护层，不能无条件跳过 HTTP 等外层包装；Encryption 提供 CommonConn 后，部分非 RAW 传输也有 Vision 路径。

| 组合维度 | 已追到的条件 | 依据 |
| --- | --- | --- |
| REALITY | RAW、gRPC、XHTTP 是 Xray 允许的传输；WS/HTTPUpgrade/mKCP/XDRIVE 不可机械套用 | [公共构造](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/transport_internet.go) |
| Vision | 直接 TLS/REALITY 或 Encryption CommonConn；普通 UDP command 被拒绝，业务 UDP 使用 XUDP；标准 flow 默认拒绝 UDP/443 | [客户端](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/vless/outbound/outbound.go)、[服务端](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/vless/inbound/inbound.go) |
| XHTTP | none 选择 H1；REALITY 选择 H2；TLS 按 ALPN 选择 H1/H2/H3；auto、packet-up、stream-up、stream-one 分开 | [传输实现](https://github.com/XTLS/Xray-core/tree/0afec66085a85191e9dd2a4a6646c7c9a94688d1/transport/internet/splithttp) |
| 上下行分离 | stream-one 不能配置独立下载；两个方向保留各自 endpoint、身份与连接池 | [mihomo 出站](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/vless.go)、上述 XHTTP 实现 |
| Encryption | mlkem768x25519plus，native/xorpub/random，1rtt/0rtt、NFS 公钥链和 padding；不得把字符串识别当握手完成 | [固定实现](https://github.com/XTLS/Xray-core/tree/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/vless/encryption) |
| XDRIVE | 依赖 Encryption、空 flow 与 Mux.Cool；存储承载和 WAL/slot 生命周期须单独实现及验证 | [固定实现](https://github.com/XTLS/Xray-core/tree/0afec66085a85191e9dd2a4a6646c7c9a94688d1/transport/internet/xdrive)、总表 V-26/V-27 |
| packetaddr | 特殊目标名为 sp.packet-addr.v2fly.arpa；包内 IP 地址类型为 IPv4=1、IPv6=2，不同于 VLESS 地址编号；域名目标拒绝 | [固定 serializer](https://github.com/SagerNet/sing-vmess/blob/a0c58542bd9d99b00ea0c3cfacce6f03cf8a4017/packetaddr/packetaddr.go)、[包包装](https://github.com/SagerNet/sing-vmess/blob/a0c58542bd9d99b00ea0c3cfacce6f03cf8a4017/packetaddr/conn.go) |

## Rust 实现选择与后续验证

选用固定 Rust 原语依赖，来源与许可证见[依赖记录](../../docs/vless-dependencies.md)。这些依赖包含 REALITY、Vision、五类流承载和 Encryption，但不覆盖本项目全部剩余任务；例如 XDRIVE 仍需单独处理。不能因采用依赖而缩小总表范围或提前勾选组合。

REALITY 必须使用提供 ClientHello 定制接口的固定 rustls 补丁。首先在 worker 完成依赖构建；普通 rustls 即使版本号相近也不能替代这些接口。当前 REALITY 服务端的混合 key share 和最低客户端版本要求需要在真实对端测试中检查，不能只用过期的固定线格式向量。

每类组合都应覆盖实际 TCP 负载、业务 TLS 触发 Vision 转换、原生 UDP/XUDP/packetaddr 的对应模式、并发隔离、错误身份/证书/密钥、截断、取消、超时和有界退出。Encryption 还需冷热连接及失败后的 ticket 生命周期；独立下载需证明实际使用了两个方向配置。所有构建和测试在远端执行，结果保存输入摘要和脱敏记录。

新增复核：固定 Xray 的 [入站装配](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/app/proxyman/inbound/inbound.go) 对 XHTTP/splithttp 的 Mux 上下文设置 AllowedNetwork=UDP。真实 TCP Mux 被 `unexpected network TCP` 拒绝，因此本项目明确拒绝 XHTTP+TCP Mux 配置；TCP 使用 XHTTP 自身 XMUX，UDP Mux 独立验收。这不影响普通 XHTTP TCP。
