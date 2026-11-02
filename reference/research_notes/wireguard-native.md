# WireGuard 原生实现依据

记录日期为2026-11-02。本文记录E-01本轮研究与实现范围，构建和互通结果另见[测试记录](../../docs/testing/wireguard.md)。首轮源码未经过编译、格式或测试，不能据此登记已支持。

## 固定输入

| 输入 | 本轮固定版本与提交 | 许可与构建边界 |
| --- | --- | --- |
| Boringtun | `0.7.1`，`253f7afb2b3df9e952065d10bf2af19913cb176b` | `BSD-3-Clause`；库默认feature为空，不启用`device`、JNI、FFI；清单未声明MSRV |
| smoltcp | `0.14.0`，`cbfe05f835cfc75bf781addc1c0eb2e1a0df1ea3` | `0BSD`；Rust 1.91；只启用用户态IP/TCP所需feature |
| 官方wireguard-go参考peer | `0.0.20250522`，`f333402bd9cbe0f3eeb02507bd14e23d7d639280` | `MIT`；Go 1.23.1；参考peer使用上游内存netstack，不创建系统TUN |

2026-11-02实际查询官方Git标签。Boringtun的最新库标签是`boringtun-0.7.1`，smoltcp是`v0.14.0`，wireguard-go的最新发行标签是`0.0.20250522`。wireguard-go当日HEAD为`b3bc704ef0ee21a36298601a9e1e5ff90377ac52`，本轮参考peer固定发行标签，不能声称覆盖后续HEAD。

Boringtun 0.7.1修复32位平台nonce计数宽度，依赖`portable-atomic`。其直接依赖包括`ring 0.17`、`x25519-dalek 2.0.1`、`chacha20poly1305`、`blake2`、`hmac`、`rand_core`、`parking_lot`和Unix上的`nix 0.31`。实际解析版本以主任务集中生成的Cargo.lock为准，不能把上游锁直接充当本项目最终依赖锁。项目Rust 1.99.1声明高于smoltcp的已声明MSRV，Boringtun及传递依赖仍需worker真实构建。

所有上游缓存只供阅读，不纳入本项目构建。产品依赖正式crate，不调用外部Go程序。GPL-3.0-only只适用于项目自有代码；Boringtun的BSD通知、smoltcp的0BSD声明及参考工具的MIT/Apache依赖通知仍保留，最终发行由主任务核对真实链接闭包。

## 数据能力与安全边界

[Boringtun的Tunn](https://github.com/cloudflare/boringtun/blob/253f7afb2b3df9e952065d10bf2af19913cb176b/boringtun/src/noise/mod.rs)只完成WireGuard握手、加密与解密。`encapsulate`输入IP包，`decapsulate`产生网络包或解密IP包。`WriteToNetwork`后必须用空输入继续排空。它不提供TCP重传、UDP关联、目标解析或可信管理用户。

[握手匿名解析](https://github.com/cloudflare/boringtun/blob/253f7afb2b3df9e952065d10bf2af19913cb176b/boringtun/src/noise/handshake.rs)可从初始握手取得peer公钥，用于选择配置候选。只有同一候选的Tunn真正接受认证数据后，才能签发`Verified`及`PeerSession`。公钥解析本身不授予业务访问。每节点使用独立私钥、监听和凭据表，peer源IP还必须匹配该peer的AllowedIPs。

[定时器](https://github.com/cloudflare/boringtun/blob/253f7afb2b3df9e952065d10bf2af19913cb176b/boringtun/src/noise/timers.rs)实现120秒重协商、180秒会话拒绝边界、5秒握手重试和可选持久keepalive。[会话计数器](https://github.com/cloudflare/boringtun/blob/253f7afb2b3df9e952065d10bf2af19913cb176b/boringtun/src/noise/session.rs)使用64位发送计数器与1024项接收窗口拒绝重放。这些上游事实需要通过本项目驱动定时器的路径复验，不能只测一次握手。

[smoltcp的TCP实现](https://github.com/smoltcp-rs/smoltcp/blob/cbfe05f835cfc75bf781addc1c0eb2e1a0df1ea3/src/socket/tcp.rs)提供IPv4/IPv6、MSS、窗口缩放、乱序重组、重传、零窗口探测及FIN状态机。本轮启用Reno，关闭Nagle，按配置MTU切分TCP。它没有完整PLPMTU。本轮不承诺动态路径MTU发现；配置MTU必须适合外层链路。

[smoltcp feature清单](https://github.com/smoltcp-rs/smoltcp/blob/cbfe05f835cfc75bf781addc1c0eb2e1a0df1ea3/Cargo.toml)虽然列有`proto-ipv6-fragmentation`，其普通IPv6入口没有对应分片重组路径。本轮在WireGuard模块的有界IP层实现IPv4和IPv6的UDP分片与重组，不能将feature名称当作已验证数据能力。分片资源同时受数量、总字节及过期时间约束，重叠分片拒绝，不把不完整数据报交业务接口。

WireGuard本身只承载IP，不带应用域名。[官方协议说明](https://www.wireguard.com/protocol/)和三个参考核心的WireGuard实现均不改变这一点。出站因此登记`TargetPolicy::Local`，由共享Dispatcher先处理节点地址族和域名解析，再将字面IP交本模块。远端应用代理的原域名透传规则仍由其他出站执行。

## 本轮方案与范围

| 方案 | 与本项目约束的关系 | 决定 |
| --- | --- | --- |
| 系统WireGuard/TUN与内核路由 | 用户流绕过`PeerSession`计量，需要设备路由和权限 | 不采用 |
| Boringtun与原生用户态TCP/IP适配 | 可在一个Rust进程内维持可信peer、共享出站和逐流完成权 | 采用 |
| 外部wireguard-go与gVisor | 已有完整IP栈，但增加外部产品后台和跨进程资源所有权 | 只作官方参考peer |

主任务已确认完整首轮范围为双角色TCP、固定UDP及多目标UDP，覆盖内外IPv4/IPv6、PSK、keepalive、密钥轮换、重放、半关闭、空包、大包分片、多peer来源校验及取消。每条命名出站建立一个WireGuard运行实例；多个并列代理通过多个命名出站表达。入站peer按认证公钥绑定配置成员，不读取包内用户名作为身份。

ICMP本轮只包含本隧道接口自身的echo及协议必要差错。任意远端ICMP不在当前无端口flow契约内，明确不提供；不得伪造远端echo成功，不把控制包计为用户业务量。这一边界由主任务明确接受，不从sing-box的更广ICMP能力推定本项目已经实现。

参考项目分别核对[mihomo固定WireGuard出站](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/adapter/outbound/wireguard.go)、[sing-box固定endpoint](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/protocol/wireguard/endpoint.go)和[Xray固定配置](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/infra/conf/wireguard.go)。[Xray官方入站说明](https://xtls.github.io/en/config/inbounds/wireguard.html)明确其用户态TCP/UDP转换路径；本项目借鉴这一职责划分，使用自己的可信成员、typed flow和Rust资源模型。

本轮不包含系统TUN接管、内核WireGuard、设备WARP部署、AmneziaWG、非零reserved扩展、跨peer故障回退、任意IP协议转发或运行时密钥配置热更新。WireGuard会话密钥的协议内轮换仍在本轮范围。

## 中断恢复后的源码复核

恢复作者完整读取旧partial后，保留加密、客户端、IP分片和用户态栈实现，补齐服务端、回归、接口和固定官方peer工具。当前所有新增内容仍是已编写、待验证，没有运行本机或worker构建、格式、检查、测试及产品。

[固定smoltcp IPv6入口](https://github.com/smoltcp-rs/smoltcp/blob/cbfe05f835cfc75bf781addc1c0eb2e1a0df1ea3/src/iface/interface/ipv6.rs#L213-L236)在目标不属于本接口时直接丢弃，不能从`set_any_ip`名称推定IPv6任意目标已经可用。主任务因此明确接受模块内有界TCP端点映射。服务端按认证peer及原五元组保留原网站目标，重组后才改内部目的端点，输出恢复来源并重算完整伪首部校验和。控制差错在改写前根据原包生成，日志与业务meter不记录虚拟目的端点。

[固定TCP暂停SYNACK接口](https://github.com/smoltcp-rs/smoltcp/blob/cbfe05f835cfc75bf781addc1c0eb2e1a0df1ea3/src/socket/tcp.rs#L750-L758)使服务端可以等待共享Dispatcher的目标建立结果。源码先接收认证SYN并保留socket，目标成功后才允许SYNACK。失败、取消、正常FIN与TIME_WAIT分别回收映射，不能用UDP载体建立代替TCP目标成功。

[固定Boringtun数据确认](https://github.com/cloudflare/boringtun/blob/253f7afb2b3df9e952065d10bf2af19913cb176b/boringtun/src/noise/mod.rs#L318-L429)区分发起握手、响应和transport认证。本轮不在初始握手响应时签发业务身份。只有实际Tunn确认加密transport或验证握手响应后，才经原候选槽取得可信成员，错误PSK不因此获得业务能力。endpoint漫游也只在该认证结果后生效。

主任务接受`ServiceContext.record_carrier`与`IngressBinding.record_carrier`的独立计量契约，WireGuard源码在实际UDP收发成功处调用，公共实现由主任务统一集成。计量只含socket确认的UDP载荷字节，含拒绝包，不代表IP/UDP头或网卡总量，不分摊用户且不与业务载荷相加。

官方wireguard-go固定归档SHA256为`4483dde7778ad264f3822b0a436c733ac82404e4d0265df3b603352111490987`，原始`go.sum`SHA256为`1aa8ba6a11e01ea4554607a7dd5402132b6912e6d4704474986d3044cef1ff69`。[参考netstack](https://github.com/WireGuard/wireguard-go/blob/f333402bd9cbe0f3eeb02507bd14e23d7d639280/tun/netstack/tun.go)通过内存IP包接入官方device，使用固定gVisor `39ed1f5ac29c`依赖。[固定gonet适配](https://github.com/google/gvisor/blob/39ed1f5ac29c/pkg/tcpip/adapters/gonet/gonet.go)的UDP接口是`ReadFrom`与`WriteTo`，TCP提供`CloseWrite`。本轮工具按这些真实接口编写，尚待Go构建与实际互通核对。
