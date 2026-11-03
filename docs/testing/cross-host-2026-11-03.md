# 2026-11-03 跨机矩阵

**更正。** 本文的 32 MiB `eof` 和 `stall` 多数是工具假象：`exchange` 和 `tcp_watch` 让发送线程和接收共用 socket 超时，Python `sendall` 的超时是整次调用的总时长，发送线程在 40 或 180 秒后被静默终止。复测结果见[隧道复测](#隧道复测)，工具已修。真实断流只有 WireGuard（已修）和 EasyTier udp（未解决）。

30 个协议模块都在 `perf-01`、`perf-02`、`perf-03` 上跨机跑过。小载荷、1 MiB 和 UDP 小包在 29 个模块通过；Sudoku 分离传输（stream、poll）在高延迟路径上 1 MiB 也会失败，WireGuard 的 IPv6 载体 1 MiB 失败。32 MiB 的失败集中在 Sudoku 分离传输、WireGuard 和用户态栈配 UDP 外层的隧道。这轮修掉 Mieru 和 HTTP QUIC socket 两个缺陷，并确认另外两个已在 `main` 修复的缺陷在 `v1.3.1` 上存在。

## 环境

**路径。** 三台的机器防火墙只放行 SSH 端口，公网 IPv4、IPv6 的高位端口在六个方向全部不通（`probe --network public` 实测，读 nftables 规则相符），不改防火墙走不通。所有用例走 Mesh 接口地址，这是真实跨机路径，但不是公网地址，经 Cloudflare 中转。接口 MTU 为 1300。

**直连基线。** 同一套收发代码走裸 Mesh：TCP 32 MiB 全双工回显 6.55–14.22 MiB/s。UDP 64、1200、1252 字节六个方向全通；1400 字节 IPv4 靠分片能通，IPv6 不通。另测的突发丢包在经过 `perf-03` 的方向为 4.6–35%（1000 pps，测量时矩阵是否同时在跑未核对）。下表吞吐只作参考，矩阵和其他任务同时占用 worker。

**排列。** P0：A=`perf-01`，B=`perf-02`，C=`perf-03`。P1：A=`perf-02`，B=`perf-03`，C=`perf-01`。P2：A=`perf-03`，B=`perf-01`，C=`perf-02`。

**二进制。**

| 名称 | 来源 | SHA-256 | 跑了什么 |
| --- | --- | --- | --- |
| `v1.3.1` | 发行版 | `1c9ab279…35c9` | 全部 62 个双端配置、9 个仅出站协议、TUN |
| 修复版 | `main`（`2df9317`）加本分支两个修复 | `76ea5035…0abf` | 下表“已复跑”的 34 个配置和 TUN |

`v1.3.1` 上已知有缺陷：Shadowsocks 与 SS2022 写重试截断、Snell 出站 IPv4 映射地址，以及本文修复的 Mieru 和 HTTP QUIC socket。仅出站协议没有用修复版重跑。

## 用例

- **双端 IPv4**（P0、P1、P2）：SOCKS 入口 TCP 64 字节、1 MiB、32 MiB（SHA-256 校验）；`udp-forward` 的 UDP 64、1200、1252、1400 字节；SOCKS5 UDP ASSOCIATE 64 字节；SIGTERM 后 5 秒排空内退出码为 0。
- **双端 IPv6**（P0、P1、P2）：TCP 64 字节、1 MiB；UDP 64、1200 字节；SOCKS5 UDP；退出。32 MiB 没测，为控制时长。
- 协议不声明 UDP 时不测 UDP。出站不提供多目标关联时 SOCKS5 UDP 返回命令不支持，记为不适用。
- 复跑用 180 秒无进展判定；`v1.3.1` 首轮的双端用例是 40 秒。

## 双端协议结果

通过/失败/不适用为最终结果，已复跑的配置取修复版结果。“首轮失败”是 `v1.3.1` 首轮的失败数。

| 协议 | 载体（均跑满上述用例） | 通过 | 失败 | 不适用 | 32 MiB MiB/s | 首轮失败 | 已复跑 | 失败项与分类 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| SOCKS | socks5-auth | 42 | 3 | 0 | 3.22–5.71 | 3 | 否 | UDP 1400：环境，封装后超 MTU，分片丢包 |
| HTTP | plain、tls | 42 | 0 | 0 | 2.95–7.81 | 0 | 否 | 协议无 UDP，未测 |
| Shadowsocks | aes-128-gcm、chacha20-ietf-poly1305 | 69 | 9 | 12 | 4.93–11.42 | 20 | 是 | UDP 1400、IPv6 UDP 1200：环境。首轮 TCP 尾部停滞是写重试截断，修复后 0 |
| SS2022 | aes-128-gcm、aes-256-gcm-eih、chacha20-poly1305 | 99 | 18 | 18 | 2.90–16.93 | 33 | 是 | 同上 |
| ShadowsocksR | auth_aes128_sha1 + tls1.2_ticket、auth_chain_a + plain | 81 | 9 | 0 | 3.40–9.77 | 9 | 否 | UDP 1400、IPv6 UDP 1200：环境 |
| Trojan | tcp、ws、httpupgrade、grpc（均 TLS） | 156 | 0 | 24 | 0.18–13.90 | 0 | 否 | 无 |
| VMess | tcp、tcp-tls、ws-tls、httpupgrade-tls、grpc-tls | 195 | 0 | 30 | 0.18–9.60 | 0 | 否 | 无 |
| VLESS | raw-tls、vision、xudp、mux、reality、encryption、ws、httpupgrade、grpc、xhttp-h2、xhttp-h3 | 428 | 1 | 66 | 0.16–13.41 | 5 | 仅 xhttp-h3 | xhttp-h3 退出码 1 |
| AnyTLS | tls | 39 | 0 | 6 | 4.76–8.44 | 0 | 否 | 无 |
| Snell | v6-default、v4 客户端对 v5 节点、v6-unshaped | 117 | 0 | 18 | 3.16–12.11 | 0 | 否 | 无 |
| TUIC | v5-native、v5-quic、v4-native、v4-quic | 167 | 13 | 0 | 0.78–4.16 | 31 | 是 | v4-native UDP 1252、1400 和 IPv6 1200：协议限制，v4 native 不分片。退出码 1 共 4 次 |
| Hysteria v1 | udp、wechat-video + xplus | 90 | 0 | 0 | 0.42–2.22 | 12 | 是 | 首轮 32 MiB eof 和退出码 1 未复现 |
| Hysteria2 | quic、salamander | 90 | 0 | 0 | 0.64–3.65 | 12 | 是 | 同上 |
| ShadowQUIC | v1-datagram、v1-stream | 79 | 11 | 0 | 0.24–1.98 | 25 | 是 | datagram UDP 1252、1400 和 IPv6 1200：协议限制，超 MTU 整包拒绝。退出码 1 共 2 次 |
| Mieru | tcp-mux、tcp-nomux | 90 | 0 | 0 | 5.98–16.77 | 9 | 是 | 首轮是实现缺陷，已修 |
| ShadowTLS | v1、v2、v3（内层 SS2022） | 63 | 0 | 0 | 6.65–17.07 | 12 | 是 | 首轮是内层写重试截断。节点只监听 TCP，UDP 未测 |
| TrustTunnel | h1、h2、h3（均 TLS） | 112 | 5 | 18 | 0.18–13.11 | 17 | 是 | h3 首轮是实现缺陷，已修；h3 退出码 1 共 4 次；h2 的 32 MiB eof 1 次，未定位 |
| Naive | h1、h2、h3（均 TLS） | 135 | 0 | 0 | 0.67–13.08 | 9 | 是 | 首轮 32 MiB 停滞未复现 |
| Sudoku | raw、legacy、ws-tls、raw-mux、stream-tls、poll-tls | 260 | 10 | 0 | 0.85–6.27 | 11 | 是 | stream-tls、poll-tls 的 10 项未解决，见下 |
| WireGuard | udp（隧道 MTU 1280） | 36 | 9 | 0 | 无通过 | 45 | 是 | IPv4 32 MiB 全失败，IPv6 1 MiB 和 UDP 1200 全失败，见下。首轮 45 项是工具配的 MTU 低于下限 |

## 仅出站协议结果（`v1.3.1`）

kerlico 客户端在 A，真实第三方对端在 B，回显目标在 C。全部做到跨机，下面写明为此加的转发。

| 协议 | 对端与实测配置 | 通过 | 失败 | 不适用 | 32 MiB MiB/s | 说明与未测 |
| --- | --- | --- | --- | --- | --- | --- |
| SSH | OpenSSH 容器。口令、公钥各 P0/P1/P2；口令另测 IPv6 P0 | 27 | 0 | 0 | 0.48–1.77 | 无 UDP |
| Gost Relay | 官方 gost。tcp、tls、mtcp、mtls 各 P0/P1/P2；tcp IPv6 P0；deferred P0 | 97 | 0 | 14 | 1.49–8.93 | 协议无多目标关联 |
| Tor | 真实 Tor 网络，A 轮换三台 | 12 | 0 | 0 | 未测 | check.torproject.org、官方 v3 onion、1.1 MiB 下载（摘要与直连一致）。目标只能是公网地址，回显用例和 32 MiB 不适用 |
| MASQUE | Xray 固定提交。Mesh 直连 P0；两端转发 P0/P2 | 15 | 3 | 0 | 无通过 | 直连隧道建立失败：kerlico 的 QUIC 路径 MTU 下限 1350 高于 Mesh。转发时 32 MiB eof，最长无进展 60 秒。P1 没测，Xray 只放了两台 |
| OpenVPN | Alpine 打包版容器。udp tls-crypt P0/P2；tcp tls-auth P0/P2；udp 无包装 P0 | 39 | 1 | 0 | 0.20–0.88 | udp tls-crypt P2 的 32 MiB eof。容器在桥接后，经用户态转发。P1 没测 |
| OpenConnect | ocserv 容器，P0/P1/P2 | 24 | 0 | 0 | 0.21–0.67 | 经用户态转发 |
| Tailscale | headscale 加官方出口节点。DERP P0/P2；直连 P0 | 26 | 0 | 0 | 0.05–0.99 | 官方客户端确认路径分别是 DERP 和直连。Mesh 地址落在 CGNAT 段被官方客户端拒绝，目标改走 B 上转发到 C，并设 `--netfilter-mode=off`。P1 没测 |
| EasyTier | 官方 easytier-core 容器。tcp 静态地址 P0/P2；udp 自动地址 P0 | 22 | 2 | 0 | 0.22–0.84 | udp 载体 1 MiB、32 MiB 失败，重跑相同；同机对照通过。tcp 全过 |
| ZeroTier | 1.14.2 root、控制器和成员。P0/P2 | 15 | 1 | 0 | 0.18 | P2 的 32 MiB eof。只配 `roots` 时经常拿不到网络配置，结果里显式配了 `peers`。P1 没测 |

这些协议的 IPv6 除 SSH、Gost 外没测：对端在无 IPv6 的桥接里或依赖 NAT，Tailscale 只走 IPv4。换钥、重连、错误口令没有跨机重测。

## TUN 结果（修复版）

netns 内的内核 TCP 和 UDP 进入 TUN，kerlico 留在主 netns，出站到 B 的节点，目标在 C。kerlico 在主 netns 创建接口后用 `ip link set netns` 移入，运行正常，主 netns 路由未动。P0/P1/P2，TCP 64 字节、1 MiB、32 MiB，UDP 64、1200 字节。

| 出站 | 通过 | 失败 | 32 MiB MiB/s | 说明 |
| --- | --- | --- | --- | --- |
| socks | 18 | 0 | 7.70–14.10 | 无 |
| ss2022（经 `routes`，只测 TCP） | 15 | 0 | 10.01–19.38 | `v1.3.1` 上 32 MiB 全部尾部停滞，修复后通过。`check` 拒绝 TUN 直接绑定无多目标关联的出站，所以走路由；停节点后 TCP 失败，证明确实走了该出站 |
| hysteria2 | 16 | 2 | 4.38 | P1、P2 的 32 MiB eof 约 10M。经 SOCKS 入口的 hysteria2 32 MiB 复跑全过，未定位 |

## 修复的缺陷

| 缺陷 | 根因 | 修复 | 验证 |
| --- | --- | --- | --- |
| Mieru TCP 全双工断流 | 载体读取没有背压，会话缓存超过 256 KiB 就被中止 | 缓存到一半停读，写超时改用空闲期限 | 回环 10/10 失败变矩阵 90 项全过；回归测试关闭修复后失败 |
| TrustTunnel H3 1 MiB 必断 | HTTP QUIC socket 包装缓存 GSO 段数。设备拒绝 GSO 后 quinn 继续组批，发出的包全部被丢弃，连接约 2 秒后静默，30 秒后空闲超时 | 段数改为读原生 socket | 跨机 10/10；抓包确认修复前无后续报文。MASQUE 共用此包装，未复测 |

Shadowsocks、SS2022 写重试截断由 `main` 修复（`01b3e23`）。本工具独立定位到同一根因：`copy_bidirectional` 在写 Pending 时继续读入，重试切片变长，写端按新长度确认，多出的明文被丢弃。修复版上该类失败为 0，ShadowTLS 和 TUN ss2022 同时恢复。这也解释 `STATUS.md` 记录的 SS2022 回显偶发差数十字节（推断，未用该脚本复核）。

## 隧道复测

结论：共享栈没有“大流量断流”这一个共同缺陷。这组失败分三类。

| 协议 | 原表结果 | 修复前复测 32 MiB（MiB/s） | 修复后复测 32 MiB（MiB/s） | 结论 |
| --- | --- | --- | --- | --- |
| WireGuard | 全失败 | P0 重置（218 KB，无进展 60 秒）；P1 通过 0.03；P2 通过 0.04 | P2 通过 0.05；A=`perf-01`、B=`perf-03` 未跑完 | 真实死锁，已修；另有工具假象和低吞吐 |
| MASQUE 转发 | `eof` | P0 通过 0.06；P2 1201 秒 `eof` | P0 通过 0.06；P2 未跑 | P0 是工具假象，P2 未定位 |
| OpenVPN udp tls-crypt | P2 `eof` | P0 通过 0.25；P2 通过 0.07 | P2 通过 0.07 | 工具假象 |
| ZeroTier | P2 `eof` | P2 通过 0.08 | P2 通过 0.06 | 工具假象 |
| EasyTier udp | 1 MiB、32 MiB 失败 | P0 失败：1 MiB `eof@54587`，32 MiB `eof@793292` | P0 失败，相同形态 | 真实断流，未解决 |
| TUN + hysteria2 | P1、P2 约 10M `eof` | P1 通过 0.85；P2 通过 0.91 | P2 通过 0.87 | 工具假象（`exchange` 40 秒限时，约 10M 对应当时 0.25 MiB/s，推断） |

修复前复测用修复版二进制（这些 crate 与 `main` 无差异）和不共用超时的探针，后三行用已修的矩阵工具。修复后的二进制在 `perf-01` 构建，glibc 高于 `perf-02`，所以只跑 A、B 都不是 `perf-02` 的排列。

**WireGuard 死锁（已修）。** 两端都是 smoltcp。重传超时把发送序号回退到最后一个 ACK，纯 ACK 沿用回退后的序号；对端已收过这段数据，判为窗口外并丢弃，段内 ACK 不处理。两端同时回退后互相忽略，退避到 32 秒，60 秒空闲超时断开。抓到的报文：一端发 `seq=4216147591 ack=3327619286`，另一端发 `seq=3327613913 ack=4216153224`，双方的序号都低于对方已确认的位置。可控复现：`tools/netem_lab.py`，3% 丢包、60 毫秒 RTT、8 MiB，修复前 6 次 3 次重置（同条件累计 16 次 8 次），修复后 6 次全过。对端是内核 TCP 的隧道不会进入这个状态。修复见 `third_party/smoltcp/PATCHES.md`。

**低吞吐（未改）。** 限制因素是丢包恢复，缓冲只在无丢包时起作用。同一 netem 下：

| 路径条件 | 内核 TCP | 默认 64 KiB 窗口 | 256 KiB 窗口、1024 包队列 |
| --- | --- | --- | --- |
| 无丢包，RTT 60 毫秒 | 12.07 | 0.94 | 1.90 |
| 无丢包，RTT 300 毫秒 | 未测 | 0.20 | 0.32 |
| 1% 丢包，RTT 60 毫秒 | 未测 | 0.14 | 0.14 |
| 3% 丢包，RTT 60 毫秒 | 4.56 | 0.05 | 未测 |

3% 丢包时拥塞窗口实测在 1–20 KB 之间，RTO 下限 1 秒，把下限改成 200 毫秒只到 0.07。smoltcp 发送端不用 SACK；全双工回显的重复 ACK 都带数据，不计入快速重传，多数丢包要等 RTO。把缓冲加到 256 KiB 而队列留 128 包时，慢启动首轮溢出，吞吐只有 1.07。这些数字没有改动默认值的依据，所以默认值没变。Mesh 上的 0.03–0.25 MiB/s 与这些数字量级相符；Mesh 丢包是否就是限制因素未单独测，属推断。单向流未测，预计好于回显。

**EasyTier udp（未解决）。** 隧道 MTU 固定 1360，加外层后超过 Mesh 的 1300。对端容器的 `tun0` 上，内核在 13、21.7、39.6 秒按退避重传同一个 1320 字节段；kerlico 的栈在第 5 秒后没再收到任何带数据的段，也没收到这些重传，短 ACK 正常到达。A 到 B 的满长段正常到达。抓到的另一现象：对端纯 ACK 的序号等于接收窗口右沿时，smoltcp 判为窗口外，ACK 不处理，内核接受这种段；这在头部空洞补不上时才持续，属次要。下一步在 B 的外层 UDP 和 A 的 Mesh 上同时抓满长载体包，分清丢在 EasyTier、转发还是 Mesh 分片。tcp 载体和同机对照都通过。

**MTU 判断。** 两项都是路径 MTU 不够，不是缺陷。WireGuard IPv6：1280（IPv6 最小 MTU）加 32 字节 WireGuard、8 字节 UDP、40 字节 IPv6 共 1360，高于 Mesh 的 1300，IPv6 中途不分片，IPv4 外层靠发送端分片才通。MASQUE：隧道 MTU 须不低于 1280，`QUIC_PATH_MTU` 1350 为此留出 QUIC 和 HTTP Datagram 开销（读代码），Mesh 的 1300 放不下，直连隧道建立失败，经转发时靠内核分片。

## 未解决

- **Sudoku stream-tls、poll-tls。** P1 的 1 MiB 必现 `stall@425984`，32 MiB 三种排列都在 240–480 秒后 eof。已观察：上传每个 POST 约 22 KB、耗时约 1 个 RTT（P1 约 300 毫秒），串行发送，所以高延迟下上传很慢；停滞时三台 socket 队列为空。下行为何 40 秒无进展没有定位。raw、legacy、ws-tls、raw-mux 全过。
- **EasyTier udp 载体。** 见[隧道复测](#隧道复测)。B 到 A 方向的满长 TCP 段到不了 kerlico，流停住，原因未定位。
- **MASQUE P2。** 复测 32 MiB 在 1201 秒 `eof@9763584`，此前最长无进展 5.7 秒，吞吐 0.01 MiB/s。约 20 分钟结束的原因未定位。
- **ZeroTier 只配 `roots`。** 约 11 次试验 2 次通（次数按运行记录回忆）。抓包见请求发出后控制器没有回配置。加 `peers` 后稳定。
- **QUIC 客户端 SIGTERM 退出码 1。** `shutdown.incomplete; cleanup_timed_out=true`，修复版复跑的 34 个配置中出现 11 次，都在 QUIC 客户端（xhttp-h3、TUIC v4、ShadowQUIC datagram、TrustTunnel h3），业务用例不受影响。首轮排空预算 1.5 秒时更频繁，5 秒时减少。可能是 `wait_idle` 的等待随路径 PTO 变长（推测，未验证）。
- **偶发。** TrustTunnel h2 32 MiB eof 一次；TUN hysteria2 见上。

首轮 Hysteria、TUIC、ShadowQUIC、Naive 的 32 MiB 失败在复跑中没有再现。复跑的 180 秒判定、并发 2（首轮 3）和 5 秒排空都不同，所以不能确定首轮是负载、判定阈值还是缺陷。

## 复现

用法见[编译、测试与专用 Worker 安排](../build-and-test.md)。各轮 JSON（已清洗）保存在 worker 的 xhost 目录 `results/` 和本机临时目录，不入库。
