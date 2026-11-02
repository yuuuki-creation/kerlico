# 第三方真实对端互通（2026-11-03）

结论：30 个协议模块都在海外 worker 上对接了第三方对端或真实系统。发现并修复 3 个 kerlico 缺陷（Shadowsocks 与 SS2022 的 TCP 截断、Snell 出站丢弃官方服务端的 IPv4 UDP 回包、Sudoku 分离传输复用已关闭的下载连接），其余失败归为对端差异、脚本问题或下面列出的未解决项。

被测二进制：`v1.3.1`（提交 `ad48e8f`，SHA-256 `1c9ab279…35c9`），标注“修复后”的行用本分支构建。运行入口是 `tools/peer_interop_matrix.py`，对端路径放在 worker 私有的 `peers.json`。

## 结果

用例数按脚本自己的记录口径：每行一个配置或一项检查，不同脚本的颗粒度不同。

| 协议 | 对端与版本 | 机器 | 用例 | 通过 | 失败 | 未测与说明 |
| --- | --- | --- | --- | --- | --- | --- |
| HTTP、SOCKS | sing-box 1.14.4 | perf-01 | 56 | 52 | 0 | 4 项 UDP 0 字节：sing-box 入口自身丢零包，脚本记为参考入口受限 |
| Shadowsocks | sing-box 1.14.4 | perf-03 | 96 | 84 | 12 | 12 项都是 UDP 0 字节，sing-box 入口丢零包，同 `docs/testing/shadowsocks.md`。修复后结果相同 |
| Shadowsocks | Xray 26.10.29 | perf-03 | 72 | 72 | 0 | UDP 取 3、4096 字节：Xray 缓冲 8192 |
| SS2022 | sing-box 1.14.4、Xray 26.10.29 | perf-01 | 40 | 40 | 0 | 另见下节停滞结论 |
| SS2022 | Xray 中继链 | perf-01 | 4 | 4 | 0 | |
| SS2022 | 正式 CLI（仅 SS2022 构建，修复后） | perf-01 | 17 | 17 | 0 | |
| ShadowsocksR | 固定 Python 参考 | perf-01 | 384 | 384 | 0 | |
| ShadowsocksR | Mihomo v1.19.33，仅服务端方向 | perf-01 | 192 | 163 | 29 | 见失败定位 |
| Snell | sing-box 1.14.4 | perf-03 | 36 | 36 | 0 | 客户端方向不测域名 UDP，见对端差异 |
| Snell | 官方 snell-server v4.1.1、v5.0.1、v6.0.0（修复后） | perf-03 | 5 | 5 | 0 | 只测出站，官方没有 Linux 客户端。`v1.3.1` 上 5 个配置的 IPv4 UDP 全部无回包 |
| Hysteria1 | 官方 v1.3.5 | perf-03 | 24 | 24 | 0 | |
| Hysteria1 | sing-box 1.14.4 | perf-03 | 12 | 12 | 0 | 客户端方向不测域名 UDP，见对端差异 |
| Hysteria2 | 官方 v2.13.0 | perf-03 | 129 | 129 | 0 | 首轮 1 项关闭超时，复跑通过 |
| Hysteria2 | sing-box 1.14.4 | perf-03 | 128 | 128 | 0 | |
| Hysteria2 | Xray 26.10.29 | perf-03 | 96 | 96 | 0 | |
| TUIC | Mihomo v1.19.33 | perf-03 | 96 | 96 | 0 | |
| TUIC | sing-box 1.14.4 | perf-03 | 48 | 48 | 0 | |
| ShadowQUIC | 受控 Go 参照 v2 | perf-03 | 72 | 72 | 0 | Mihomo v2 不互通是已知差异，未重跑 |
| ShadowQUIC | 版本协商负例 | perf-03 | 8 | 8 | 0 | |
| AnyTLS | sing-box 1.14.4 | perf-03 | 19 | 19 | 0 | |
| ShadowTLS | sing-box 1.14.4 | perf-03 | 108 | 108 | 0 | |
| ShadowTLS | 官方 0.2.25 外层加 sing-box 内层 | perf-03 | 108 | 108 | 0 | |
| Mieru | Mihomo v1.19.33 | perf-03 | 8 | 8 | 0 | 4 个配置 |
| VMess | Xray 26.10.29 | perf-03 | 96 | 96 | 0 | UDP 17、1200 字节 |
| VMess | sing-box 1.14.4 | perf-03 | 72 | 72 | 0 | 不测 gRPC multi 和 HTTPUpgrade 客户端，见对端差异 |
| VLESS | Xray 客户端矩阵 | perf-01 | 394 | 393 | 1 | `grpc-reality-multi-auto-vision-native-1rtt-udp` TCP 回写不一致一次，单独复跑 5/5 |
| VLESS | Xray 服务端矩阵 | perf-01 | 394 | 394 | 0 | |
| VLESS | Xray、sing-box 普通流，各 11 项 | perf-01 | 22 | 22 | 0 | |
| VLESS | packetaddr、上下行分离、XDrive | perf-01 | 43 | 43 | 0 | 分离的 4 个 H3 配置对 kerlico 自端，见观察项 |
| Trojan | Xray 26.10.29 | perf-01 | 20 | 20 | 0 | |
| Naive | 官方 naive 154.0.8037.49、sing-box 1.14.4、Caddy 插件、Go 参照 | perf-01 | 156 | 156 | 0 | 另有共存检查 1 项通过 |
| Sudoku | 官方 v0.5.2.0 | perf-01 | 11001 | 9312 | 2 | 494 配置。2 项失败：1 项大流提前 EOF 见未解决项，1 项并发小流截断见失败定位。另有 985 项进程观察、663 项入口上限、11 项参考边界。28 项 TLS 配置缺证书未跑，由下一行补测 |
| Sudoku | 官方 v0.5.2.0，TLS 套件 | perf-01 | 343 | 247 | 1 | 1 项对端启动退出（setup），未定位。另有 39 项入口上限、28 项进程观察、28 项参考边界 |
| Sudoku | Mihomo 1.10.0 固定构建 | perf-01 | 10895 | 7185 | 2057 | 见失败定位。另有 980 项进程观察、645 项入口上限，28 项 TLS 配置缺证书未跑 |
| Sudoku | Mihomo 1.10.0，TLS 套件 | perf-01 | 364 | 224 | 42 | 42 项都是 UDP 64000、65507 字节。另有 42 项入口上限、28 项进程观察、28 项参考边界 |
| WireGuard | wireguard-go 固定提交 | perf-01 | 1194 | 1194 | 0 | 入站与出站，含损伤与轮换 |
| TUN | Linux 内核（独立 netns） | perf-01 | 3 | 3 | 0 | 对端是内核，`crates/protocol-tun/tests/netns.rs` |
| SSH | OpenSSH（Debian 13 容器） | perf-01 | 140 | 140 | 0 | |
| Gost Relay | 官方 GOST 3.3.2 | perf-01 | 704 | 704 | 0 | 脚本修复后 |
| Tor | 公网 Tor 与官方 Arti onion | perf-01 | 5 | 5 | 0 | 字面 IPv4、IPv6 目标和建链中取消未测 |
| MASQUE | Xray 26.10.29 | perf-02 | 5 | 5 | 0 | |
| OpenVPN | OpenVPN 2.6.20、2.4.12 | perf-02 | 11 | 11 | 0 | |
| OpenConnect | ocserv（Debian bookworm 容器） | perf-02 | 11 | 11 | 0 | |
| Tailscale | 官方客户端 v1.92.3、Headscale 0.27.1 | perf-02 | 10 | 10 | 0 | DERP、直连与出口节点 |
| EasyTier | easytier-core 2.6.4 | perf-02 | 16 | 16 | 0 | |
| ZeroTier | zerotier 1.14.2 容器 | perf-02 | 1 | 1 | 0 | 脚本只给整体结论，含拒绝、根节点、洪泛三阶段 |
| TrustTunnel | 官方 endpoint v1.1.0、client v1.1.11 | perf-02 | 232 | 230 | 2 | 另 18 项未测；见失败定位 |
| TrustTunnel | Mihomo v1.19.33 | perf-02 | 258 | 251 | 7 | 另 54 项观察到上限、4 项未测；见失败定位 |

官方下载的对端没有发布摘要，这里记录实测值：snell-server v4.1.1 `8e029749…`、v5.0.1 `5b2e221f…`、v6.0.0 `27d8bead…`；hysteria v1.3.5 `41dc8bc3…`；shadow-tls 0.2.25 `a173f5f2…`。其余对端沿用既有测试记录核验过的二进制或按固定来源构建：sing-box `1264361b…`，Xray `e783b9d2…`，GOST `19b5d859…`，Mihomo v1.19.33 `817f50b3…`，wireguard-go 参照 `54c58b72…`。

## SS2022 回显停滞结论

是节点截断，也影响 Shadowsocks 的所有 AEAD 和流方法，以及两者的出站方向。

`third_party/shadowsocks` 的加密写端在底层写返回 Pending 后，下次调用返回本次传入切片的长度。`tokio::io::copy_bidirectional` 在写 Pending 后会先把更多数据读进同一缓冲，再用更长的切片重试，多出的明文被确认却没有加密发送。AEAD 不报错，连接只是停滞。补丁让写端记住已加密的长度，见 `third_party/shadowsocks/PATCHES.md`。

依据：

- `crates/protocol-shadowsocks/tests/write_retry.rs` 用可控的 Pending 复现，修复前失败，修复后通过。
- 未修复的示例对端在 1 MiB 与 4 MiB 负载下 220 个用例停滞 7 个。echo 计数显示收发都完整，差额只在节点回写方向。修复后 200 个用例没有 TCP 停滞。
- 原报告的 131072 字节下，本次未修复构建在 perf-01 的 300 个用例（含 debug 构建和绑定单核）一次也没有复现，所以原报告的发生率没有在这里重现。差额形态一致，归因属于推断。

## 脚本问题

| 脚本 | 问题 | 处理 |
| --- | --- | --- |
| `interop_hysteria1.py` | 两节点复用同一 obfs，被跨节点凭据检查拒绝 | 改用不同 obfs |
| `interop_gost_relay.py` | `localhost` UDP 由 GOST 解析到 `::1`，目标只听 IPv4；forward 模式用域名目标，kerlico 按设计不解析 | 补 IPv6 回显；forward 只用字面目标；改正 `docs/interfaces/gost-relay.md` |
| `interop_ss2022_cli.py` | 错误文案已更新，语言随环境变化 | 跟随文案，固定中文 |
| `interop_vless_split.py` | 排空预算 200ms 小于 H3 关闭耗时 | 放宽到 3 秒 |

## 对端差异

- **sing-box Snell 入站**：回写域名目标的 UDP 时报 `udp response source is not an ip`。sing-box 自身互连同样失败。
- **sing-box Hysteria1 入站**：UDP 会话请求不带目标时丢弃域名目标的数据报。官方 v1.3.5 客户端和 kerlico 都不带目标，官方客户端对照同样超时。
- **sing-box HTTPUpgrade 入站**：拒绝带 `Sec-WebSocket-Key` 的请求（`real websocket request received`）。Xray 与 kerlico 都发这个头，Xray 对照同样被拒。
- **sing-box gRPC**：没有 multi 模式（`bad path: /proxy/TunMulti`）。

## 失败定位

上面结果表是首轮数字。下表是对其中未定位失败的结论。

| 失败 | 结论 | 依据 | 处理 |
| --- | --- | --- | --- |
| Sudoku 接 Mihomo：61 项小负载 TCP 提前 EOF、1 项 UDP 0 字节超时 | 脚本竞态，对端启动窗口 | Mihomo 的 `ApplyConfig` 先开监听，`tunnel.OnRunning` 在其后；`handleTCPConn` 在这之前直接关闭连接，UDP 被丢弃，都不写日志。不经过 kerlico 时，100 次启动有 63 次出现早期关闭，共 128 条，首次成功后 0 条失败 | 脚本等运行状态，见下 |
| TrustTunnel 接 Mihomo：6 项 TLS 负例、1 项 H2 并发 | 同一竞态 | 负例或正向对照的请求落在窗口里，日志没有拨号错误，脚本判 `insufficient-evidence`；并发项是启动后的第一批连接 | 加门后两轮 258 通过、0 失败（首轮 251、7） |
| Sudoku 接 Mihomo：12 项停服重启 | 对端行为 | 同一 Mihomo 客户端接 Mihomo 节点与接 kerlico 节点，各 12 轮：活动流都 12 秒内不关闭（12/12、12/12）；重启后首个请求 EOF（7/12、11/12），后续 3 个请求全部通过（36/36、36/36）。`poll` 模式重启后等 2 秒再发，首个请求 8/8 通过。两个比例的差异原因未验证 | 与官方一样记 `reference_boundary`，换新客户端再测 |
| Sudoku 接 Mihomo：1971 项 UDP 大包 | 对端上限 | Mihomo 把数据报截断到 16384 字节（SOCKS 入口含 10 字节头），回包内容在截断处之前一致，16000 字节通过、32000 字节截断。Mihomo 双端同样截断，kerlico 双端到 65507 字节通过。截断位置的源码未读 | 超过 16384 字节记 `reference_boundary` |
| Sudoku 接官方：1 项并发小流截断（`mux=auto`） | **kerlico 缺陷，已修** | 官方的下载响应声明 `Connection: keep-alive`，写完 EOF 尾部就关闭。kerlico 把连接放回连接池，下一个请求约 100 微秒内复用它并收到 RST。抓包里失败流的 FIN 两次都发在刚结束的下载连接上，都收到 RST，上传任务失败后拆除整条流；新流的下载请求撞上时表现为 0 字节 EOF。kerlico 到官方 2/400 失败，官方双端、官方到 kerlico、kerlico 双端都是 0/400 | 下载请求带 `Connection: close`；回归测试 `finished_pull_connection_is_not_reused_for_next_request` 修复前失败。修复后 `poll`、`stream`、`auto` 各 400 条并发流全部通过，`poll` 专注 60 轮 960 条没有失败（修复前同样轮数 3 条） |
| TrustTunnel 接官方：2 项 H3 UDP 65000 字节 | 对端行为 | 首轮把方向写反了，实际是 kerlico 客户端接官方 endpoint。trace 日志显示 endpoint 收到目标回包后打出 `Datagram dropped`。官方双端同样 12000 字节通过、16000 字节起超时；官方客户端接 kerlico 节点到 65000 字节通过。丢弃条件的源码未读，官方 H1、H2 的 65000 字节通过 | 记 `observed-limit` |
| ShadowsocksR 接 Mihomo：25 至 29 项，都在 `random_head` 与 `tls1.2_ticket_*` | 对端发坏流 | 抓包比较上行原始字节。`random_head` 40 例失败 33 例，都含 10KB 以上的重复密文片段，上行字节数也偏离通过时的约 60KB；通过的 7 例没有重复。`tls1.2_ticket_*` 40 例失败 21 例，TLS 记录头都在流中途被破坏；通过的 19 例记录头完整。抓包时失败比例高于矩阵。Mihomo 内部根因未定位，kerlico 的拒绝是正确行为 | 不改 |
| VLESS 客户端矩阵 1 项偶发 | 未定位 | 本轮未查，复跑 5/5 | 无 |

`tools/mihomo_ready.py` 是这个竞态的修复：给 Mihomo 加一个走 DIRECT 的 SOCKS 入口，目标收到探测连接才算运行。探针不经过被测协议，不会掩盖被测路径上的失败。`interop_shadowsocksr.py` 早有同类探测。`interop_tuic.py`、`interop_mieru.py` 也用 Mihomo，尚未接入，本轮它们没有失败。

复跑结果（Sudoku 都不含 `rekey`）：

| 被测 | 对端 | 套件 | 结果 |
| --- | --- | --- | --- |
| `v1.3.1` | Mihomo 1.10.0 | lifecycle、carriers、tables、mux、credentials | 全部退出 0，失败 0 |
| `v1.3.1` | TrustTunnel Mihomo，官方 H3 客户端方向 | 全量、仅 H3 | Mihomo 两轮 258 通过、0 失败；官方 30 通过、0 失败、2 项观察到上限 |
| 修复后 | 官方 v0.5.2.0 | carriers、tables | 2880、4800 通过，失败 0 |
| 修复后 | Mihomo 1.10.0 | carriers、tables | carriers 失败 0；tables 收尾前跑完 5625 条记录，7 项失败都来自同一用例：端口分配把同一端口同时发给节点和 SOCKS 入口，日志是 `address already in use`。分配器已去重，这个套件没有重跑 |

修复后的 `rekey`、`lifecycle`、`mux` 全量没有跑完，这几项对修复后二进制未验证。TLS 下的 H1、H2 回环由 crate 测试和一次 kerlico 双端往返覆盖。`tools/sudoku_interop/README.md` 给的自签 CA 证书当叶子时，kerlico 客户端拒绝，`--peer self --suite tls` 全部失败，`v1.3.1` 相同；改用 CA 加叶子证书后 H1、H2 通过。

## 未解决项

- **Sudoku 互通 README 的测试证书**：见上段，示例命令还没有改成 CA 加叶子证书。
- **Sudoku mux 流提前 EOF**：`kerlico` 作客户端、`mux=on` 的 33MiB 流在约 18MiB 处结束，`rekey` 套件单独复跑 38 条大流失败 3 条，全量矩阵里官方 1 条、Mihomo 12 条（4 条提前 EOF、8 条连接重置）。Sudoku mux 没有流控，接收方队列超过每流 4MiB 就重置该流；官方源码 `muxMaxQueuedBytesPerStream` 同样是 4MiB 且同样重置，所以这是协议性质，读得慢的本地客户端会遇到（根因由读代码推断，未在失败现场抓到重置帧）。用户侧表现是流提前结束，没有明确错误。下一步可以考虑把重置报告为错误。
- **映射地址同类风险**：Snell 的 IPv4 映射来源问题只在 Snell 上修了。`protocol-hysteria2/src/udp.rs`、`protocol-shadowsocksr/src/udp.rs` 也按字面比较来源与目标，本次对端都没有触发，未验证双栈对端。

## 观察项

- **H3 上下行分离出站关闭约 2 秒**：`drain_timeout_ms` 小于它时进程退出码为 1（`cleanup_timed_out=true`），`v1.3.0` 相同。放宽预算后 4 个 H3 配置通过。用例时长差（5.1 秒对 3 秒）是这个数字的来源，没有单独计时。
- **写重试同类审计**：读完范围内其余 83 个 `poll_write` 实现，没有确认的同类缺陷。REALITY 与 XHTTP 服务端在写 Pending 后调用 flush 时会重复发送，`copy_bidirectional` 只在缓冲写空时 flush，转发路径不触发；其他调用方未逐一排查。SSR `credential_io.rs` 的败者候选写回路径未核实。

## 复现

每台 worker 上放好 `peers.json` 后运行：

```sh
python3 tools/peer_interop_matrix.py --machine perf-03 --kerlico <二进制> --peers peers.json --out runs/<批次>
python3 tools/peer_interop_matrix.py --machine perf-03 --kerlico <二进制> --peers peers.json --out runs/<批次> --summary
```

Tor 用 `tools/tor_interop/worker.py`，TUN 用 `crates/protocol-tun/tests/netns.rs` 头部的命令，这两项不在表内。
