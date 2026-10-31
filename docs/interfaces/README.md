# 实现接口

更新日期：2026-10-31。核心基础接口沿用 0.1，协议扩展各自标明版本与验证状态；这里描述已经写入代码的契约，完整目标架构仍在其他设计文档中维护。

| 文档 | 范围 |
| --- | --- |
| [核心接口](core.md) | 地址、I/O、出站能力、建立预算、注册与运行退出 |
| [配置与命令行](config.md) | JSON 外层、固定目标入口、限制、功能裁剪和退出行为 |
| [节点与统一出口](node-egress.md) | 独立节点凭据、双角色、访问服务、IPv4 优先与资源预算 |
| [VLESS 接口](vless.md) | 双端、传输/安全、Encryption、Mux 与存储承载；扩展验证中 |
| [AnyTLS 接口](anytls.md) | TLS 双端、会话复用与 UoT v2 |
| [SS2022 接口](ss2022.md) | 三种算法、TCP/UDP 双端与 AES EIH |
| [SOCKS 接口](socks.md) | 4/4a/5 双端及 SOCKS5 UDP；限定范围已验 |
| [Shadowsocks 接口](shadowsocks.md) | AEAD/legacy/none 双端；限定范围已验 |
| [HTTP 代理接口](http-proxy.md) | CONNECT 双端、普通转发、Basic/TLS；限定范围已验 |
| [Trojan 接口](trojan.md) | 双端传输与 TCP/UDP；限定范围已验 |
| [VMess 接口](vmess.md) | AEAD 双端、记录与重放边界；限定范围已验 |
| [Snell 接口](snell.md) | v4 出站/v5 节点与 v6 双端；限定范围已验 |
| [TUIC 接口](tuic.md) | v4/v5 双端与同 socket 多目标关联；限定范围已验 |
| [Hysteria2 接口](hysteria2.md) | 原生 QUIC/H3 双端、UDP 关联与混淆；限定范围已验 |
| [SSH 接口](ssh.md) | 原生 direct-tcpip 出站、固定主机与显式认证；限定范围已验 |
| [ShadowQUIC 接口](shadowquic.md) | 原生 JLS/QUIC 与有界回退；原 Mihomo v1 与受控 v2 分别已验 |
| [Hysteria v1 接口](hysteria1.md) | 独立握手、QUIC 载体与多目标 UDP；限定范围已验 |
| [SSR 接口](shadowsocksr.md) | 独立 protocol/obfs/cipher 与真实鉴权边界；首轮已写待验证 |
| [ShadowTLS 接口](shadowtls.md) | 真实内层 AEAD 流包装与分域凭据；首轮已写待验证 |
| [Gost Relay 接口](gost-relay.md) | 原生 CONNECT 出站、TCP/固定 UDP、TLS/SMUX v1；限定范围已验 |
| [Mieru 接口](mieru.md) | TCP双端、真实复用与Full Cone；原UDP仅显式本机不安全兼容，限定范围已验 |
| [TrustTunnel 接口](trusttunnel.md) | TLS H1/H2/H3双端和固定UDP；已停止原验证，H2增量未编译，完整对端未验收 |
| [Naive 接口](naive.md) | H1/H2/H3、padding和UoT双端；限定快照已验，对端EOF/包长限制单列，不外推当前整树 |
| [Sudoku 首轮接口](sudoku.md) | 记录/表/流/UoT/真实复用和六载体双端；完整首轮写齐并接线，冻结验证中 |
| [扩展验证快照](../testing/vless-combinations.md) | 当前各快照通过范围、失败修正及最新未复验增量 |
| [首批协议集成](../testing/protocol-batch-1.md) | 八模块冻结快照、公共契约、功能裁剪与 81 项联合运行 |
| [十一模块集成](../testing/protocol-batch-2.md) | 139 项整树测试、功能裁剪与 111 项联合运行 |
| [凭据隔离契约验证](../testing/credential-isolation-contract.md) | 六包冻结快照的7项限定测试、格式与严格Clippy |
| [0.1 历史记录](../testing/vless-ordinary-flow.md) | 已发布旧版环境与边界 |

修改公共签名、配置字段、能力、错误或关闭行为时，同步对应接口文档与有意义的验证；不要只更新总表状态。接口状态、上游支持情况和未来候选组合分别记录。源码与文档不一致时先修正，不把文档愿景当作实现。

用户已确认客户端/服务端一体、节点凭据独立和统一目标访问方向，目标边界见[双端设计](../node-egress.md)。相应接口已落地，具体协议的角色与组合仍以各自接口、测试记录为准。
