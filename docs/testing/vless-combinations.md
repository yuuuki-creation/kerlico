# VLESS 扩展与三协议装配：开发快照验证记录

记录日期：2026-10-31。此前按用户要求保存、推送快照并停止，用户随后已要求多代理继续推进。本文保留旧快照并追加实际续验，区分已验证二进制与当前工作树，不作为发行验收声明。所有编译、格式、Clippy、Rust 测试和程序互通均在专用 worker 执行。

## 环境与范围

环境为 Linux x86_64，宿主 Rust/Cargo 1.99.1；固定对端为 Xray v26.10.29（`0afec66085a85191e9dd2a4a6646c7c9a94688d1`）与 sing-box v1.14.4。测试只使用项目隔离目录、合成身份/密钥和回环目标，未改动既有基础服务。实际机器资料、私有工作目录与原始输出不公开。

Rust 1.96 容器尝试因 `rust-reality` 2.2.0、`rr-crypto`、`rr-linux`、`rr-session` 要求 1.99 而失败，当前清单已改为 1.99.1。release 曾成功构建，但当时源码早于后续修正，不能当作本提交发行产物。

## 已通过的快照

| 作业/快照 | 实际结果 |
| --- | --- |
| `full-code-r10` | 完整工作区默认 Rust 测试合计 49 项通过，另有默认 ignored 的对端测试；格式、Clippy、程序构建通过 |
| `vision-frame-boundary-r12` | VLESS 包级 24 项通过，格式、Clippy、构建通过；新增带读前探测的 Direct 边界及分片回归 |
| `client-full-r12` / `server-full-r12` | 客户端、服务端各 394/394 配置通过 |
| `client-mlkem-r12` / `server-mlkem-r12` | 各 44/44 TCP 配置通过；含 36 项 Encryption 组合及 8 项未加密基线，密钥使用固定 Xray 生成的 ML-KEM-768 材料 |
| `client-vision-frame-stress-r12` | TCP+REALITY+Vision 的真实对端重复验证 30/30 通过 |
| `split-r12` | 10/10 场景：H1/H2 对固定 Xray；含 H3 的组合对 kerlico 自端；上传/下载使用不同 CA/SNI，上传 IPv4、下载 IPv6，覆盖两类目标、并发和错误下载 CA/SNI |
| `xdrive-oracle-r8` | 6/6 场景：local、HTTP template、S3 模拟服务各自双向；TCP 128 KiB、UDP、四路 Mux、存储请求鉴权和退出 |
| `combined-core-r2` | 默认三协议、六节点在同一程序运行，35 项检查通过，含两种目标地址族、TCP/UDP、错误凭据、并发、退出及同端口重启 |
| `mux-drain-r14` | VLESS 包级 27 项通过，格式、Clippy、构建通过；包含并发首次建连接、关闭时排空、XUDP 首包和保留端口标记等修正 |
| `packetaddr-r14` | 对固定 sing-box 的 4/4 场景通过：双方角色、IPv4/IPv6 节点各访问两类目标，负载为 17、4096、12000 字节 |
| `mux-resume-r1` | 恢复后客户端额外 Mux 矩阵 30/30 配置通过，包含 TCP+none 四路并发；X25519、固定 Xray、脚本默认 30 组合 |
| `combined-eight-r1` | 首批八模块、16 节点同一程序的 81 项联合检查通过，详见[集成记录](protocol-batch-1.md) |

完整矩阵工具见 `tools/interop_vless_matrix.py`、`tools/interop_vless_server.py`。维度包括 RAW、WS、HTTPUpgrade、gRPC 单/多 Hunk、XHTTP H1/H2/H3 各 mode、合法 none/TLS/REALITY、普通/Vision、Encryption 三模式与 1/0 RTT、原生 UDP/XUDP。客户端覆盖 64 KiB TCP、256 KiB 业务 TLS、重复连接、四路并发和退出；服务端还覆盖独立双地址族节点与跨节点凭据拒绝。这里的数量表示工具选出的具体配置，不代表所有字段取值的穷举。

## 二进制对应关系

| 使用快照 | SHA-256 |
| --- | --- |
| `r12` 完整矩阵、ML-KEM、Vision 重复及上下行分离 | `beba7d73be27b75f9775612e668627eb87b86a76174d0d2993a4c6490dc3c62c` |
| `r14` 包级修正与 packetaddr | `d8da5d8b46d788fd4e61e7cf3de9ce327e2de9da51b1e62f6b01de527e71c6f2` |
| XDRIVE `r8` | `6bb2364489f4c3359b4c5efbc77c59fd361686a227a56790f1d58a291caa7e6b` |
| 三协议联合 `r7` | `827e6ab438027a660e7cdf37c8945f444c88f1f32d02b1281afcb0b55dc881ae` |
| 首批冻结 `r4`，八模块联合与 Mux 续验 | `420b9ba395bdc4a8f9189cdac47d963e9b671e52752448e00e7ed43cd8e253d3` |

这些摘要指向当时实际运行的文件。不同快照之间的结果不能合并成“当前全部代码通过”。最终源码和发行产物摘要尚未固定；本轮不发布二进制。

## 失败与已完成修正

- 服务端 Encryption 旧 ML-KEM 0.2 与新版 REALITY 的 ML-KEM 0.3 使用不兼容 KEM 接口；兼容副本与固定独立来源见[依赖说明](../vless-dependencies.md)。算法源码未修改。
- Vision 最初误将随机值当作填充参数，造成过大填充；已改用固定规范参数，随机填充仍由原语产生。
- 早期完整矩阵客户端、服务端分别出现 393/394；REALITY+Vision 重复验证也失败。限制读取边界的诊断版 30/30 后，改为按 Vision 帧边界读取，独立回归、重复 30/30 与双向完整 394/394 通过。
- XDRIVE 客户端并发曾阻塞。Encryption 的读路径也会驱动 flush，单唤醒槽可能覆盖写路径唤醒；改为有界多等待者通知后 6/6 通过。参考 Xray Mux 的 END 终止全流，XDRIVE 互通按长度回写，不使用提前 EOF 作为成功条件。
- 固定 Xray 对 XHTTP 的 Mux 仅允许 UDP，TCP Mux 被 `unexpected network TCP` 拒绝；工厂已明确拒绝该组合，TCP 使用 XHTTP 自身 XMUX，UDP Mux 单独验证。
- 带非零 XUDP global ID 的 NEW 必须包含首个数据包；改为延迟到首次发送时完整编码，新增回归。
- Mux 接收队列瞬时填满不应直接丢掉 TCP 数据，已改为有界背压；并发建连接需在锁内复查可用流槽；写端结束不能抢先取消尚待交付的反向数据。相关回归在 `r14` 通过。
- sing-box 的 packetaddr 保留目标使用零端口；新节点解析器只对 UDP 保留域名允许该标记，普通目标仍拒绝零端口，并区分业务包长与地址封装长度。

## 原停点与恢复后的复验

额外 Mux 矩阵 `client-mux-frame-r12` 曾为 29/30，失败为 TCP+none 的并发复用。后续 `r14` 修正并通过包级回归；本次恢复后，使用上表首批冻结 r4 CLI 在 perf-01 执行 `tools/interop_vless_matrix.py --mux --workers 1`，固定 Xray 对端与 X25519 密钥，`mux-resume-r1` 已 **30/30 通过**。检查包含 TCP 首包/大负载/重复连接、普通 UDP、TLS 1.3 业务 256 KiB、四路并发和有界退出。按脚本条件，Vision/XHTTP 只启用 UDP Mux，其他允许路径启用 TCP/UDP Mux；不能把数量称为 30 项 TCP Mux 或服务端角色验收。

原停点保留的节点共享取消域、兄弟入口排空、HTTP 升级跟踪/空闲及 WS 缓冲增量已在恢复后的原树和首批冻结工作区纳入编译、格式、Clippy 与测试；首批 104 项及后补回归、81 项联合运行见[集成记录](protocol-batch-1.md)。后续协议仍在继续修改，不能据此声明当前所有源码已验收。

混合 NFS 链、ML-DSA 验签、真实云账户、Google Drive 槽环完整互通、长期/性能压力、其他系统或架构均未在本轮验收。XUDP 尚无跨物理载体全局 NAT 会话。不得由固定依赖源码支持推定本内核已完成这些验证。

原保存快照时的作业均已结束；恢复后的当前作业与状态以根 STATUS 为准。原始证据和续接索引在本地 `.private/builds/`，连接资料在 `.private/machines/`，均不得提交。
