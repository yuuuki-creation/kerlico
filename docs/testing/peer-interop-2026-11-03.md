# 第三方真实对端互通（2026-11-03）

结论：30 个协议模块都在海外 worker 上对接了第三方对端或真实系统。发现并修复 2 个 kerlico 缺陷（Shadowsocks 与 SS2022 的 TCP 截断、Snell 出站丢弃官方服务端的 IPv4 UDP 回包），其余失败归为对端差异、脚本漂移或下面列出的未解决项。

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
| ShadowsocksR | Mihomo v1.19.33，仅服务端方向 | perf-01 | 192 | 163 | 29 | 见未解决项 |
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
| Sudoku | 官方 v0.5.2.0 | perf-01 | 11001 | 9312 | 2 | 494 配置。2 项失败是 mux 流提前 EOF，见下。另有 985 项进程观察、663 项入口上限、11 项参考边界。28 项 TLS 配置缺证书未跑，由下一行补测 |
| Sudoku | 官方 v0.5.2.0，TLS 套件 | perf-01 | 343 | 247 | 1 | 1 项对端启动退出（setup），未定位。另有 39 项入口上限、28 项进程观察、28 项参考边界 |
| Sudoku | Mihomo 1.10.0 固定构建 | perf-01 | 10895 | 7185 | 2057 | 见未解决项。另有 980 项进程观察、645 项入口上限，28 项 TLS 配置缺证书未跑 |
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
| TrustTunnel | 官方 endpoint v1.1.0、client v1.1.11 | perf-02 | 232 | 230 | 2 | 另 18 项未测；见未解决项 |
| TrustTunnel | Mihomo v1.19.33 | perf-02 | 258 | 251 | 7 | 另 54 项观察到上限、4 项未测；见未解决项 |

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

## 未解决项

- **ShadowsocksR 接 Mihomo**：192 项失败 25 至 29 项，`v1.3.0`、`v1.3.1`、修复后构建都在这个范围，失败主要是客户端先发 59392 字节时的 `IncompleteReadError`，集中在 `random_head` 与 `tls1.2_ticket_*`。已知 Mihomo 这些混淆会发出坏 MAC 流（`docs/testing/shadowsocksr.md`），但既有记录是 191/192，这次的比例更高，没有抓包确认。Python 参考 384/384。
- **Sudoku 接 Mihomo**：1971 项是 UDP 64000、65507 字节内容不符，17 和 4096 字节全部通过，官方对端同样大小通过，推断是 Mihomo 的 UoT 上限，未单独验证。另有 61 项小负载 TCP 提前 EOF（`tables`、`carriers` 轴为主）、12 项停服重启和 1 项 UDP 0 字节超时，没有定位；12 条 33MiB 流见下条。
- **TrustTunnel 官方**：官方客户端到本节点方向的 H3 UDP 65000 字节失败 2 项（两个节点族），未定位。
- **TrustTunnel Mihomo**：6 项 TLS 负例缺少足够的拒绝证据（脚本判定 `insufficient-evidence`），1 项 H2 并发业务失败，首轮 9 项里的具体用例与复跑不同，未定位。
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
