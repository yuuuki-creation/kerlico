# mieru 性能记录与优化核验

本篇保留一分钟内网观测，并登记[源码核验与优化候选](#源码核验与优化候选)、[首批实施记录](#首批缓冲与派发优化)和[与 mita 的同参数验收](#与-mita-的同参数验收)。源码成本不代表已测得的性能收益。协议决定仍以 [mieru](mieru.md) 为准，派发、出口和计数归 [server](server.md) 所有。

日期：2026-11-09，Asia/Shanghai。这里比较服务端，双方使用同一个官方客户端 SDK。两侧各运行一次 60 秒，结果只说明本轮固定负载下的观测，稳定性能优劣尚不能判断。

## 条件

- `perf-03` 同一台 8 vCPU Linux worker，回环网络。服务端、共同客户端和回显目标分别固定使用 4、3、1 个逻辑 CPU。
- kerlico 使用 `b52ea3f` 的 Rust release 构建，Rust 1.99.1。对端是官方原生 `mita` 3.39.0，源码固定为 `1367cf2d2dd81c5f27d455be7cea691d7948c420`，使用 Go 1.25.3 默认优化构建。
- TCP、`MULTIPLEXING_LOW`、`HANDSHAKE_STANDARD`、低熵 OFF、MTU 1400。双方使用相同合成账号和原生 IPv4 出口。
- 8 条持久数据流，每次完整写入并读回 32768 字节。另有 1 条 64 字节延迟探针，每约 10 毫秒请求一次。
- 全部会话先建立并预热 5 秒，再正式计时 60 秒。吞吐只计区间内完整收到并逐字节校验正确的数据，握手、预热和计时后排空单独处理。
- 两个服务端均以相同无特权 UID 运行。配置、UDS、日志只写本次独立目录，已有服务和全局 mita 资料目录保持原状。

## 正式结果

kerlico 的窗口起于 14:43:35，mita 起于 14:44:47。CPU 百分比以单核为 100%，服务端上限为 400%。RSS、FD 和线程峰值每 0.2 秒采样一次。

| 指标 | kerlico mieru | 官方 mita |
| --- | ---: | ---: |
| 单向有效吞吐 | 3961.95 Mbps | 3562.02 Mbps |
| 收发有效载荷合计 | 7923.90 Mbps | 7124.03 Mbps |
| 完整校验的数据 | 27.674 GiB | 24.880 GiB |
| 每秒完成的 32 KiB 块 | 15113.63 | 13588.02 |
| 64 B 探针 RTT P50 | 0.320 ms | 0.304 ms |
| 64 B 探针 RTT P95 | 0.832 ms | 0.832 ms |
| 64 B 探针 RTT P99 | 1.728 ms | 1.728 ms |
| 数据块 RTT P50 / P95 / P99 | 0.448 / 1.024 / 1.984 ms | 0.512 / 1.152 / 2.304 ms |
| 服务端平均 CPU | 235.89% | 238.98% |
| 服务端采样峰值 CPU | 260.89% | 260.76% |
| 服务端平均 RSS | 7.39 MiB | 96.31 MiB |
| 服务端采样峰值 RSS | 7.39 MiB | 144.59 MiB |
| 服务端线程峰值 | 26 | 10 |
| 服务端 FD 峰值 | 28 | 20 |
| 实际底层 TCP 连接 | 3 | 4 |
| 客户端平均 CPU | 232.08% | 219.51% |
| 共同负载进程平均 RSS | 351.06 MiB | 310.60 MiB |
| 共同负载进程采样峰值 RSS | 546.94 MiB | 399.69 MiB |
| 回显目标平均 CPU | 59.58% | 50.40% |
| 错误 / 超时 / 错字节 | 0 / 0 / 0 | 0 / 0 / 0 |

本轮 kerlico 的有效吞吐高 11.23%，服务端 CPU 接近，RSS 更低，线程和 FD 更多。RTT 来自有界直方图，表中分位数是桶上界，桶宽约 6.25%。LOW 复用实际形成了不同的底层连接数；这两次单轮结果不能给出稳定差距或极限吞吐，当前源码瓶颈也没有通过独立剖析定位。

客户端列属于共同的官方 SDK 负载进程，不是 kerlico 客户端实现的性能结果。服务端 RSS 也不代表整个三进程路径的内存总量。

## 有效性与边界

5 秒直连基线为 15271.99 Mbps，回显目标单核接近满载。正式代理测量中，三种角色均未打满各自分配的 CPU。当前结果属于上述 8 流闭环负载，未测不同并发、UDP、其他复用或低熵组合，也未做至少五轮交替复测。

客户端完整回读量由逐流、逐秒和总量三份计数交叉核对，目标进程也记录了真实读写。正式窗口内各有 60 个回显样本，中间采样区间实际写回约 29.21 GB 和 26.28 GB。错误载荷反例会返回非零并记录错字节，伪造总量、伪造逐秒计数或缺少一侧结果均被独立核对拒绝。

资源采样窗口实际为 60.0015 秒和 60.0018 秒，负载自身 CPU 计数与 `/proc` 采样一致。未将不同 socket 系统调用的 `/proc/io` 计数用来比较有效吞吐。结束后，本次二进制遗留进程数为 0，全局 mita 资料目录仍不存在。

最初在 `perf-01` 的同条件观测为 1778.25 / 1520.40 Mbps，错误也为 0，但期间系统背景负载明显升高，原有虚拟化工作负载仍在运行。该组保留为环境记录，没有与本表合并。转到空闲 worker 后，直连基线正常退出与最后一次采样发生竞态，工具据此拒绝该轮；修订后仅在输出结果后保留进程 2 秒供采样收尾，60 秒的吞吐、RTT 和 CPU 计时口径不变。

## 复现与指纹

工具入口是 [`tools/mieru_bench/run_comparison.py`](../../tools/mieru_bench/run_comparison.py)，方法及参数见[负载工具说明](../../tools/mieru_bench/README.md)。构建与执行只在专用 worker，原始数据和私有运行目录继续保留在本地 `.private/` 及 worker，不进入 Git。

| 二进制 | SHA-256 |
| --- | --- |
| kerlico-server release | `622bd8f417358f042570eebab0317284276990d29dcd4bef8eae8870f008e362` |
| 官方 mita | `b5dc0455c180b2f8be9269456bf4f99ceee304bb9657f5d1092c2eed0b182f55` |
| 共同负载与回显工具 | `6cc4a5f75d69b775df3f36931647a5413f5755499dfa717a31e32524eadc94dd` |

## 源码核验与优化候选

核验日期：2026-11-09，Asia/Shanghai。源码基点为 `df2e347`，官方参照仍固定为 `1367cf2d2dd81c5f27d455be7cea691d7948c420`。本轮检查了调用链、资源上限、现有回归用例和官方实现，仅更新文档，没有实施优化、运行协议测试或压测。

本节保留该基点的分析，源码链接固定到当时的提交。后续已实现的部分在实施记录中列出，其余内容仍是候选。

以下相关源码和锁文件在性能观测基点 `b52ea3f` 与本次核验基点之间没有差异。复核命令如下，本轮退出码为 0，无差异输出：

```sh
git diff --exit-code b52ea3f df2e347 -- protocols/mieru crates/server/src/lib.rs crates/outbound/src crates/shared/src/lib.rs Cargo.lock
```

这使源码分析可以对应前述观测，但不会扩大观测范围。8 条持久数据流、一个探针和官方 SDK 客户端，仍不能代表短连接、UDP、kerlico 本机代理或万级连接的性能。

### 按负载选择候选

| 编号 | 适用负载 | 候选方案 | 修改范围 | 尚待确认的收益 |
| --- | --- | --- | --- | --- |
| P1 | TCP 持续传输 | 减少中间 Vec，原地加解密，顺序包直接交付 | mieru 共享引擎 | 分配、搬运和 CPU 占比，端到端吞吐 |
| P2 | 短连接、突发接入、多节点 | 批量公平派发，有界准入 | 服务端调度及 mieru 接入 | 新流处理速率、排队延迟和积压内存 |
| P3 | UDP 高复用、高包速率 | 按 peer 和不同密钥定位，增量清理 ACK | mieru 共享引擎 | 每包解密次数、查表成本和包速率 |
| P4 | UDP 丢包和乱序 | 自适应重传期限，按丢包周期更新窗口，合并 ACK | mieru 共享引擎 | 有效吞吐、长尾延迟、重复发送量 |
| P5 | 大量空闲流、慢出口 | 共享定时调度，跨层事件驱动，可取消写，按需缓冲 | shared、server、outbound 及 mieru 两端 | 每流内存、线程数和资源回收时间 |
| P6 | 慢消费者、UDP 多目标 | 总字节预算、数据块回收 | mieru 队列及服务端准入 | 峰值内存和不同会话间的资源公平性 |
| P7 | 多流持续复制 | 预注册计数句柄 | shared、server、outbound | 全局锁等待、字符串分配和吞吐 |
| P8 | 低熵流量或频繁建连 | 优化低熵位操作，缓存认证派生结果 | mieru 共享引擎及账号发布 | 相应模式的 CPU 或握手成本 |

这张表没有给出统一的收益排名。默认 TCP 的持续吞吐先看 P1 和 P7，新流处理先看 P2，UDP 先看 P3 和 P4，大量连接的资源成本先看 P5 和 P6。各项都没有经过优化前后对比，不能承诺倍数或 RSS 降幅。

### P1：TCP 缓冲与顺序交付

[`take_with_idle`](https://github.com/yuuuki-creation/kerlico/blob/df2e347/protocols/mieru/shared/src/engine.rs#L1824) 先把 socket 数据读进 64 KiB 临时缓冲，再追加到 `stash`。取出头部、填充和载荷时使用 `drain(..n).collect()`，产生返回 Vec；仍有后续字节时还需要整理 `stash`。[`open_with`](https://github.com/yuuuki-creation/kerlico/blob/df2e347/protocols/mieru/shared/src/crypto.rs#L116) 使用返回新 Vec 的解密接口。

[`dispatch`](https://github.com/yuuuki-creation/kerlico/blob/df2e347/protocols/mieru/shared/src/engine.rs#L1445) 对 TCP 数据也调用 `push_in`。[`push_in`](https://github.com/yuuuki-creation/kerlico/blob/df2e347/protocols/mieru/shared/src/engine.rs#L734) 每次遍历乱序表计算字节数；顺序包也先插入、移出 `BTreeMap`，再合并到输出 Vec。[`append`](https://github.com/yuuuki-creation/kerlico/blob/df2e347/protocols/mieru/shared/src/engine.rs#L659) 把这些字节复制到 Pipe，之后再复制到调用者的读缓冲。这里确认的是源码中的中间缓冲和复制操作，没有测量优化后分配器实际减少多少次分配。

候选方案采用带消费位置的接收缓冲，跳过填充时只推进位置。已认证载荷原地解密后以数据块所有权进入队列；`seq == next` 时直接交付，乱序包才进入重排表。乱序字节数随插入和删除更新。序号检查、重放检查、分片边界和关闭后已缓冲数据的读取语义仍然保留。数据块池受总容量限制，小切片不能长期占住一整块大缓冲。

发送端的 [`write_wire`](https://github.com/yuuuki-creation/kerlico/blob/df2e347/protocols/mieru/shared/src/engine.rs#L1095) 分别调用 `seal` 生成元数据和载荷 Vec，再拼接。已有的 [`seal_into`](https://github.com/yuuuki-creation/kerlico/blob/df2e347/protocols/mieru/shared/src/crypto.rs#L86) 可以直接把载荷追加并加密到预留好的最终缓冲。[RustCrypto 0.10.1](https://docs.rs/chacha20poly1305/0.10.1/chacha20poly1305/#in-place-usage-eliminates-alloc-requirement) 也提供原地解密接口。低熵关闭的路径可先消除中间载荷 Vec；低熵路径还需要保留扩展后的密文和独立标签布局。

TCP 每次元数据或载荷加密都有自己的 nonce 递增。单条底层连接的加密顺序与发送顺序必须一致，不能把现有 `Direction` 并行使用。现有 `InboundStream` 仍要求向调用者缓冲复制，本方案不声称端到端零拷贝。

### P2：新流派发与排队

[`Server::run`](https://github.com/yuuuki-creation/kerlico/blob/df2e347/crates/server/src/lib.rs#L339) 每次派发后固定等待 20 ms。[`dispatch_next_with`](https://github.com/yuuuki-creation/kerlico/blob/df2e347/crates/server/src/lib.rs#L387) 每次最多成功交付一个 Handoff，随后立即返回。因此该主循环连续派发的源码上限约为 `1 / 0.020 = 50` 条每秒，处理和调度开销只会降低该值。这个上限不适用于已经建立的流，也不适用于外部直接调用 `dispatch_next` 的循环。每轮从节点 0 开始扫描，还会使持续就绪的靠前节点占据派发机会。

mieru 的 [`ready_rx`](https://github.com/yuuuki-creation/kerlico/blob/df2e347/protocols/mieru/server/src/lib.rs#L187) 来自无界 channel。[`handshake`](https://github.com/yuuuki-creation/kerlico/blob/df2e347/protocols/mieru/shared/src/engine.rs#L1473) 先写 SOCKS 成功应答，再发送 Ready，排队项持有 Conn。因此协议握手成功和服务端开始拨号之间可以存在积压。无界指 channel 本身没有容量限制，不代表其他地方没有限制；当前 TCP 接入另有 1024 条底层连接检查，`dispatch` 另有每 Link 4096 个会话检查。这些数量检查不构成总字节预算，也不替代 `mieru.md` 的复用要求。

候选方案在一次唤醒后按批量或时间预算处理就绪流，轮转节点起点，仅在没有工作时等待通知。准入预算覆盖握手、Ready 和执行中的流。只把 channel 换成阻塞的有界队列，会把等待转移到握手线程；队列已满时的拒绝、关闭和公平策略需要与资源预算一起确定。

### P3：UDP 会话定位与累计确认

[`decrypt_known`](https://github.com/yuuuki-creation/kerlico/blob/df2e347/protocols/mieru/shared/src/engine.rs#L1754) 每个包先调用 `live_sessions`，扫描整个 UDP listener 的会话表、升级弱引用，再筛选 peer。随后逐会话解密元数据，解密成功仍要比较 session ID。同一 peer 的多个会话共享密钥时，这些会话也会重复执行同一次元数据解密。

候选索引先按 peer 取得不同的活跃密钥，每个密钥最多试一次，再按已认证元数据中的 `(peer, session ID)` 定位会话。对于已存在会话的合法包，若该 peer 只有一个活跃密钥、共有 M 个会话，现路径最坏尝试 M 次，候选路径只需一次。这是操作次数推导，不是吞吐倍数。索引还要核对目标会话所属的账号和密钥；活跃旧会话的密钥保留到会话结束，新会话仍经过当前账号与时间盐检查。

[`on_ack`](https://github.com/yuuuki-creation/kerlico/blob/df2e347/protocols/mieru/shared/src/engine.rs#L759) 每次用 `retain` 扫描整个 inflight 表。候选方案按累计确认范围移除已确认项，避免重复遍历未确认项。普通数值大小关系不足以处理 u32 序号回绕，替换后的数据结构仍须使用序号窗口内的先后关系。

### P4：UDP 重传、ACK 与窗口恢复

[`emit_fragment`](https://github.com/yuuuki-creation/kerlico/blob/df2e347/protocols/mieru/shared/src/engine.rs#L888) 把初始重传期限设为 3 秒。[`Sess::tick`](https://github.com/yuuuki-creation/kerlico/blob/df2e347/protocols/mieru/shared/src/engine.rs#L1145) 每轮扫描 inflight，到期后将间隔乘 1.5，最多 10 秒，并复制待重传载荷。同一批每个到期包分别把 `cwnd` 除以 2。若起始窗口为 16，期间没有 ACK 更新，四个包同时超时就会依次降到 8、4、2、1。这是窗口更新路径，不是任何一次实测吞吐的解释。当前 [`dispatch`](https://github.com/yuuuki-creation/kerlico/blob/df2e347/protocols/mieru/shared/src/engine.rs#L1450) 对每个收到的 UDP 数据段立即发送独立 ACK。

候选方案记录可判定的 RTT 样本和波动，调整重传期限，按丢包周期处理一次拥塞事件，并根据重复 ACK 提前重传。重传调度按最近截止时间唤醒，ACK 合并有独立的最迟发送时间。重传保留载荷可以共享所有权，避免到期扫描再次复制完整载荷。窗口重新可用时需要及时更新对端，不能只依赖空闲心跳。

固定官方版本的 [`RTTStats::RTO`](https://github.com/enfein/mieru/blob/1367cf2d2dd81c5f27d455be7cea691d7948c420/pkg/congestion/rtt.go#L83) 使用平滑 RTT 和偏差。[`runOutputOncePacket`](https://github.com/enfein/mieru/blob/1367cf2d2dd81c5f27d455be7cea691d7948c420/pkg/protocol/session.go#L798) 使用重复 ACK 提前重传，并在一批重传后处理一次拥塞事件。[`requestPacketAck`](https://github.com/enfein/mieru/blob/1367cf2d2dd81c5f27d455be7cea691d7948c420/pkg/protocol/session.go#L1018) 设置 1 ms 的 ACK 调度期限。这些是实现参照，不能把 1 ms 当成所有机器上的实际发送保证。

该方案只使用既有序号、ACK 和窗口字段。定时任务必须独立于读超时：已有 [`udp_retransmits_even_when_packets_keep_the_reader_busy`](https://github.com/yuuuki-creation/kerlico/blob/df2e347/protocols/mieru/shared/src/completion_tests.rs#L440) 覆盖接收繁忙时仍要重传。本轮只核对了用例，没有重新执行。

### P5：线程、固定缓冲与可取消写

服务端每个进入 [`bridge`](https://github.com/yuuuki-creation/kerlico/blob/df2e347/crates/outbound/src/copy.rs#L78) 的流使用当前 `drive` 线程处理下行，另外创建一个上行线程。[`pump_up`](https://github.com/yuuuki-creation/kerlico/blob/df2e347/crates/outbound/src/copy.rs#L108) 和 [`pump_down`](https://github.com/yuuuki-creation/kerlico/blob/df2e347/crates/outbound/src/copy.rs#L162) 各申请 64 KiB 缓冲。N 条双向复制均存活的流合计申请 `N × 128 KiB`；N 为 10,000 时是 1,310,720,000 字节，约 1.22 GiB。该数没有计入线程栈、协议队列或内核 socket，也不是 RSS。线程能否达到该规模仍受机器资源限制。

[`serve_tcp`](https://github.com/yuuuki-creation/kerlico/blob/df2e347/protocols/mieru/shared/src/engine.rs#L354) 每条底层连接另开 reader 和 timer；服务端 UDP 是每个监听 socket 一个 Link，不是每个 peer 各开这两个线程。[`start_timer`](https://github.com/yuuuki-creation/kerlico/blob/df2e347/protocols/mieru/shared/src/engine.rs#L594) 每 100 ms 调用 Link 维护，读超时还会再次触发维护。TCP 的 `Sess::tick` 立即返回，Link 仍枚举会话，`session_count` 又构造一次活跃会话列表。

局部候选是共享定时调度与增量活跃计数，仅处理到期重传、空闲和退役项。跨层候选是共享 Rust runtime，将每流线程改成可等待就绪事件的任务，并让 [`InboundStream`](https://github.com/yuuuki-creation/kerlico/blob/df2e347/crates/shared/src/lib.rs#L296) 和出口复制支持取消。缓冲按活跃操作借用，池的总容量有上限。将阻塞接口搬进每连接的 `spawn_blocking` 不能消除主要线程成本；UDP 缓冲仍须容纳完整数据报，包括空包。

原生 TCP 的 [`dial_native`](https://github.com/yuuuki-creation/kerlico/blob/df2e347/crates/outbound/src/native.rs#L103) 没有设置写超时，[`TcpWrite::write_pipe`](https://github.com/yuuuki-creation/kerlico/blob/df2e347/crates/outbound/src/native.rs#L336) 直接调用阻塞 `write_all`。下行退出后，`bridge` 设置停止标志再等待上行线程，停止标志不能打断已阻塞的写。因此当前代码不能保证这种流在 300 秒空闲后及时释放，实际滞留时间还取决于系统 TCP 行为。候选修复是可取消的非阻塞写，或过渡性的写期限与共享 socket 关闭。这里是既有空闲期限的实现缺口，不改变 [server.md](server.md) 的 300 秒要求。

mieru 底层自己的 [`write_all_timeout`](https://github.com/yuuuki-creation/kerlico/blob/df2e347/protocols/mieru/shared/src/engine.rs#L1871) 则有另一种限制：20 秒检查只在写超时错误分支执行，不能把它描述成严格的整段写期限。[`wire_lock`](https://github.com/yuuuki-creation/kerlico/blob/df2e347/protocols/mieru/shared/src/engine.rs#L1104) 覆盖加密和 socket 写，慢写期间同 Link 的其他发送也会等待。候选有序 writer 需要按会话公平调度、限制排队字节，并保持 TCP nonce 与实际发送顺序一致。

### P6：字节预算与慢消费者

[`PIPE_LIMIT`](https://github.com/yuuuki-creation/kerlico/blob/df2e347/protocols/mieru/shared/src/engine.rs#L17) 为 2 MiB，Pipe 与乱序表分别检查这一上限，不能称为整个会话合计最多 2 MiB。两者按需增长；Pipe 排空没有执行容量收缩。[`window`](https://github.com/yuuuki-creation/kerlico/blob/df2e347/protocols/mieru/shared/src/engine.rs#L725) 只根据 Pipe 的剩余空间通告接收窗口，没有扣除乱序表占用。

[`Leg::push`](https://github.com/yuuuki-creation/kerlico/blob/df2e347/protocols/mieru/shared/src/engine.rs#L1259) 每个 UDP 目标最多保留 64 个包，超出后丢弃，没有按字节限制。UDP 关联封装的长度字段最多 65535 字节，应用载荷还要扣 SOCKS 地址头，因此单目标队列可接近但小于 4 MiB。[`fanout`](https://github.com/yuuuki-creation/kerlico/blob/df2e347/protocols/mieru/shared/src/engine.rs#L1509) 可为不同目标继续创建 Leg，没有关联级的目标数和队列总字节检查。此处讨论应用 UDP 关联，同时适用于 TCP 与 UDP 两种底层；它和 MTU 限制的线协议 UDP 段不是同一种大小。

候选预算同时覆盖接收队列、乱序缓存、发送未确认载荷、Leg 和待派发项，并按会话、关联、用户或节点汇总。接收窗口需要考虑实际已占字节，预算还要为缺口重传和窗口恢复留出进展空间，避免乱序包占满后无法接收缺失包。数据块在低水位或空闲后归还，逐次读取后立即收缩会增加分配抖动。

TCP 的 [`wait_slot`](https://github.com/yuuuki-creation/kerlico/blob/df2e347/protocols/mieru/shared/src/engine.rs#L777) 直接返回，固定官方实现的 [`inputAck`](https://github.com/enfein/mieru/blob/1367cf2d2dd81c5f27d455be7cea691d7948c420/pkg/protocol/session.go#L1231) 也忽略 TCP ACK。不能直接套用 UDP 窗口实现每个 TCP 会话的背压。暂停共享 TCP 会影响同 Link 其他会话，超限处理需要兼顾协议互通与公平性。

### P7：流量计数

[`Stats`](https://github.com/yuuuki-creation/kerlico/blob/df2e347/crates/server/src/lib.rs#L78) 使用全局 `Mutex<BTreeMap<String, u64>>`。每个方向成功复制一个块后，用户、节点和出口分别构造计数名称并进入这把锁，共三次名称构造和三次加锁。这个次数按复制块计，不按 mieru 段或 socket 包计。

候选方案在建流时取得计数句柄，热路径直接更新原子计数，名称注册表留给管理和查询。`Traffic` 及其调用方需要一起适配。按用户跨节点合并、删除用户不清零、计数时点和 API 查询可见性保持原定义。若原子计数仍成为热点，再测量按工作线程分片的方案；只在连接结束时汇总会改变长连接的实时可见性。

### P8：低熵与认证派生

[`entropy::pdep`](https://github.com/yuuuki-creation/kerlico/blob/df2e347/protocols/mieru/shared/src/entropy.rs#L168) 和 `pext` 按 mask 的置位位数循环。候选包括等价的批量位运算，以及对合法常见 mask 和 rotation 的专用实现。接收端仍接受所有官方合法参数，保留填充一致性与标签校验。此项只影响低熵开启的流量，不能解释低熵关闭的既有观测，也不能通过关闭用户要求的模式充当实现优化。

[`keys_for`](https://github.com/yuuuki-creation/kerlico/blob/df2e347/protocols/mieru/shared/src/crypto.rs#L17) 一次计算三个时间盐的派生密钥，客户端只使用中间一个。`open_first` 先检查用户名 hint，匹配后才派生；已知会话数据通常不重新执行 PBKDF2。候选按账号版本和 120 秒时间桶缓存预哈希及派生结果，客户端仅派生所需密钥。账号变更使新会话认证缓存失效，活跃会话密钥的生命周期单独管理，不能扩大时间盐或元数据时间戳的接受范围。

## 后续验证范围

以下均为待执行的验证。现有 [`mieru_bench load`](../../tools/mieru_bench/main.go#L475) 接受 1 到 256 条 bulk 持久流，另外总有一条探针；代理配置固定为 TCP、LOW、STANDARD、低熵关闭。现有驱动不直接提供下表的短连接、UDP、慢读和万级连接负载。功能互通工具也不能代替这些性能负载。

| 目标 | 负载与对照 | 主要观测 |
| --- | --- | --- |
| P1、P7 | 1、8、128 条 TCP bulk 流，固定块大小和实际底层连接数或单独记录其差异 | 有效吞吐、CPU 时间或 cycles 每有效字节、分配次数和字节量、锁等待、探针 P99 |
| P2 | 新流持续到达与突发，两节点同时就绪 | 握手到首次有效响应的延迟、Ready 等待时间、派发速率、拒绝数、节点公平性 |
| P3 | 同 peer 不同会话数，另加相同总会话数但分散 peer 的对照 | 每包元数据解密次数、扫描项数、包速率、CPU、账号隔离 |
| P4 | 可控 RTT、随机与成批丢包、乱序、重复包及窗口归零恢复 | 有效吞吐、P99、重传量、cwnd 轨迹、ACK 数量、恢复时间 |
| P5、P6 | 1,000 与 10,000 条空闲或慢读流，UDP 多目标，资源不足时记录实际接入数 | heap 活跃量与保留量、RSS、线程、FD、内核 socket 内存、取消和空闲回收时间 |
| P8 | 低熵五种模式分别比较，认证区分冷缓存、热缓存及跨时间桶 | 编解码 CPU、有效吞吐、握手速率、缓存内存、密钥轮换与账号变更结果 |

构建、协议测试和压测仍只在专用 worker。后续对比至少交替运行五轮，报告中位数和范围；profile 单独运行，不把剖析开销混进正式成绩。服务器、负载端和目标同时采样，拒绝、超时、错字节与未完成操作单列，不能把资源拒绝算成吞吐提升。LOW 的随机连接数和负载生成器自身上限需要一起记录。

正确性覆盖继续包含官方双向互通、TCP 并发 nonce 顺序、u32 序号回绕、读超时后保留半帧、空 UDP 包和数据报边界、关闭后缓冲读取、取消唤醒、账号与节点隔离。防重放缓存需要继续识别跨 peer 重放，不能随 UDP 会话索引按 peer 拆开；依据见 [`replay::reject`](https://github.com/yuuuki-creation/kerlico/blob/df2e347/protocols/mieru/shared/src/replay.rs#L37)。

这些候选没有更改 [官方字段与 nonce 规则](https://github.com/enfein/mieru/blob/1367cf2d2dd81c5f27d455be7cea691d7948c420/docs/protocol.md)、复用概率、`Handoff` 或唯一出站拨号边界。具体准入额度、超限行为和跨层接口仍待设计；实施时在同一次改动更新拥有它们的 `mieru.md`、`server.md` 或 `crates.md`，本篇不替代这些决定。

## 首批缓冲与派发优化

日期：2026-11-09，Asia/Shanghai。基线为 `024745a`，对应前述源码核验后的文档提交。本批实现 P1 的缓冲与顺序交付部分，以及 P2 的公平派发部分。

| 改动 | 当前行为 | 本批边界 |
| --- | --- | --- |
| TCP 接收 | `BufReader` 保留预读数据，移除 `stash.drain().collect()`，载荷原地解密，填充使用栈缓冲 | Pipe 仍复制到调用者缓冲，没有实现块队列或全局池 |
| 段发送 | 预留最终 wire 缓冲，低熵关闭时直接追加加密元数据和载荷；UDP 也复用这一加密入口 | 保留全部低熵模式、nonce、标签及填充规则 |
| 顺序交付 | 顺序段不插入重排树，直接复用载荷 Vec；乱序字节数增量维护 | 窗口、接收预算和重传策略未改变 |
| 服务端派发 | 节点轮转，成功派发后继续，整轮无就绪流才等待 20 ms；空闲轮不复制路由上下文 | 有界准入和跨层异步化仍待实施，既有慢出口取消缺口仍在 |

全部构建和协议验证在 `perf-03` 的独立目录完成。两侧 release 使用独立 target 目录，编译器均为 Rust 1.99.1；官方工具使用 Go 1.25.5 和上述固定官方源码。

| 验证 | 结果 |
| --- | --- |
| Rust 测试 | 64 项通过，保留 1 项依赖外部探针的忽略测试。新增检查覆盖加密拼接与篡改拒绝、序号回绕、乱序预算释放和节点公平性；半段超时用例同时覆盖元数据式读取与载荷式读取。 |
| 格式和静态检查 | 四个修改的 Rust 文件通过 rustfmt 检查；服务端、客户端叶子及三个 mieru 包通过相关所有目标的 `Clippy -D warnings`。 |
| 构建与裁剪 | 两端 mieru release 构建通过。客户端仅 WireGuard、服务端仅 OpenVPN 分别构建通过，运行时依赖图不含另一端协议 crate。 |
| 官方互通 | IPv4 节点完整两两矩阵双向 44 项及配置负面 1 项通过，共 45 项。覆盖两种底层、四级复用、两种握手、五种低熵和两种 MTU。 |

性能对比使用 [`run_regression.py`](../../tools/mieru_bench/run_regression.py)，每侧五轮、每轮 20 秒，依次交替运行。沿用 8 条持久数据流和一条延迟探针，单独保留直连基线；不会把该结果当作新流派发速率测试。每轮交叉核对逐块、逐秒、总字节和目标真实工作，并执行错误总量、错误逐秒计数及缺失一侧的负面对照。

五轮全部完成，十次代理负载的错误、超时和错字节均为 0。五轮独立核对和三个负面对照均通过，运行结束后没有本次二进制的遗留进程。直连基线为 14219.16 Mbps。

| 指标 | 基线中位数及范围 | 优化版中位数及范围 |
| --- | --- | --- |
| 单向有效吞吐 | 4032.80 Mbps，3980.58 至 4167.63 | 4113.80 Mbps，3987.64 至 4188.55 |
| 服务端 CPU 秒数 / 单向校验 GiB | 5.028，5.003 至 5.097 | 4.812，4.766 至 4.902 |
| 服务端平均 RSS | 7.512 MiB，7.449 至 7.633 | 6.676 MiB，6.613 至 6.800 |
| 64 B 探针 P99 桶上界 | 1.792 ms，1.600 至 2.560 | 1.920 ms，1.472 至 2.560 |
| 每轮实际底层 TCP 连接 | 3、3、4、3、3 | 3、3、4、3、3 |
| 服务端线程峰值 | 26 至 28 | 26 至 28 |

本轮吞吐结论不确定。中位数增加 2.01%，前后范围重叠，最后一轮优化版略低于基线，延迟也没有确认改善。三种角色的平均 CPU 均未打满分配额度，尚未通过剖析定位限制吞吐的因素，因此不据此宣称稳定的吞吐提升。

固定负载下，每 GiB 服务端 CPU 时间的中位数减少 4.30%，平均 RSS 的中位数减少 11.13%。两者是本轮观测，不代表万级空闲连接或慢读场景，也不能与此前纯计算中的假设倍数混用。双方每轮实际底层连接数恰好相同，线程模型未改变。本批没有验证全局内存预算、UDP 高复用查找或弱网重传的收益。

| 本轮二进制 | SHA-256 |
| --- | --- |
| 基线 kerlico-server | `01fda9194afbb4363ff61777199dcedabaa378966672ef141363507d0c8b2a82` |
| 优化版 kerlico-server | `385b4bd47a137e04be56d2fce1e8f01bda0d2843731b6eb55f320710c6051214` |
| 共同官方 SDK 负载工具 | `2ff60ddda946f71c980d0d6f472ae94eaa24afa4628b01f8e56c33b1ae29af38` |

原始数据、测试日志和源码指纹保留在本地 `.private/mieru-optimization-20261109/` 及本次 worker 目录。四个修改的 Rust 文件已逐一比对 worker 构建输入与本地 SHA-256。

## 与 mita 的同参数验收

日期：2026-11-09，Asia/Shanghai。本轮主目标是服务端每 GiB 有效数据的 CPU 时间比固定版本 mita 至少低 30%，同时检查吞吐、P99、RSS 和错误。CPU 时间包含该服务端进程的用户态与内核态时间，分母为客户端完整收到并校验正确的单向 bulk GiB。

本轮增加了以下改动，全部保持线上 XChaCha20-Poly1305 算法和既有消息格式。

- 用 RustCrypto 的 HChaCha20 和 `ring` 的 ChaCha20-Poly1305 组合原算法，缓存每个方向当前 nonce 前缀对应的子密钥。原 RustCrypto AEAD 留作测试对照。
- 填充随机字节按线程批量从系统获取，nonce 仍单独生成；原生 TCP 读取超时只在建连时设置。
- 由内核调度 TCP ACK，移除每次读取前的 `TCP_QUICKACK` 调用。独立的 64 B 小包检查没有出现延迟 ACK 长停顿，前后吞吐及 P99 范围重叠，不能宣称小包延迟改善。
- 建流时取得用户、节点和出口的原子计数句柄，移除逐块的名称构造和注册表锁，保持计数时点与 API 可见性。

CPU 剖析定位到加密计算和内核收发成本；系统调用剖析确认了重复的随机数获取和套接字选项设置。剖析与正式计时分开，带跟踪开销的结果不进入下表。

### 条件与结果

双方在同一台 8 vCPU Linux amd64 worker `perf-03` 运行，仍按服务端 4 核、共同负载 3 核、回显目标 1 核分配。双方服务端以同一无特权 UID 运行，使用同一个官方 SDK 负载二进制。固定参数为 TCP、LOW、STANDARD、低熵关闭、MTU 1400、原生 IPv4 出口、8 条 32768 B 持久数据流和一条 64 B 探针。

mita 固定为 `1367cf2d2dd81c5f27d455be7cea691d7948c420`，使用 Go 1.25.5 和官方 release 参数 `CGO_ENABLED=0 go build -trimpath -ldflags="-s -w"`。Rust 使用 1.99.1 的默认 release 配置，没有增加 CPU 特定编译参数。双方先预热，随后每侧五轮、每轮 60 秒，按 mita、kerlico 的顺序交替运行。直连基线为 10850.98 Mbps。

下表变化按两侧中位数计算，括号内是五轮范围。

| 指标 | mita | kerlico | 中位数变化 |
| --- | --- | --- | --- |
| CPU 秒数 / 单向校验 GiB | 5.434（5.288 至 5.532） | 3.685（3.608 至 3.783） | 减少 32.19% |
| 单向有效吞吐 | 3918.75 Mbps（3680.41 至 4142.76） | 4548.43 Mbps（4166.10 至 4614.03） | 增加 16.07% |
| 服务端平均 RSS | 108.103 MiB（98.364 至 118.170） | 7.023 MiB（6.723 至 7.039） | 减少 93.50% |
| 64 B 探针 P99 桶上界 | 2.560 ms（1.600 至 2.944） | 2.176 ms（1.600 至 2.944） | 本轮减少 15.00%，范围重叠 |
| 服务端平均 CPU，单核为 100% | 247.88%（237.03% 至 255.59%） | 193.81%（182.36% 至 195.10%） | 固定时间内两侧完成的数据量不同，验收用 CPU/GiB |
| 服务端线程峰值 | 9 | 24 至 30 | kerlico 仍较多 |
| 服务端 FD 峰值 | 18 至 21 | 26 至 32 | kerlico 仍较多 |

每组配对的 CPU/GiB 都达到至少 30% 的下降，配对降幅中位数为 30.85%。LOW 复用会随机形成不同数量的底层连接，实际值逐轮列出；没有筛除连接数不同或结果较差的轮次。

| 轮次 | mita CPU 秒/GiB | kerlico CPU 秒/GiB | 配对下降 | mita 底层 TCP 数 | kerlico 底层 TCP 数 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 | 5.328 | 3.685 | 30.85% | 5 | 4 |
| 2 | 5.434 | 3.760 | 30.80% | 3 | 2 |
| 3 | 5.461 | 3.783 | 30.74% | 3 | 2 |
| 4 | 5.532 | 3.660 | 33.85% | 2 | 5 |
| 5 | 5.288 | 3.608 | 31.76% | 5 | 5 |

CPU 主目标在这组固定负载下通过。线程与 FD 尚未低于 mita，阻塞复制模型、全局内存预算和慢出口取消仍有后续工作。P99 的范围重叠，不据中位数宣布稳定的延迟改善。此结果不是极限吞吐，也不外推到 UDP、其他复用级别、万级连接或其他 CPU 架构。

### 正确性与拒绝错误结果

首次完整互通在 UDP、HIGH、NO_WAIT、低熵模式 3、MTU 1280 的一条并发流上出现提前关闭，因此未启动正式性能验收。随后增加的线协议回归稳定观察到客户端在 `OPEN_RESPONSE` 前发送类型 10 的 DATA，断言为 `Some(10)` 对 `None`。固定官方实现会推迟这一阶段的 DATA；未知会话的 DATA 可能触发对端关闭。

修复把 UDP 会话建立确认与 SOCKS 应答分开，建立阶段的普通 ACK 不再释放 DATA，关闭会唤醒等待写入，建立前也不发送 ACK 心跳。回归在修复前失败、修复后通过。原失败配置重复十次，双向共 20 项全部通过，再重新运行完整互通和正式性能对比。原失败 JSON 和日志保留，没有把重复运行当作忽略失败的理由。

| 验证 | 结果 |
| --- | --- |
| Rust 回归 | 68 项通过，1 项外部探针测试保持忽略。包含 156 组密钥、nonce、长度组合的 AEAD 对照，以及 nonce 前缀进位、计数实时可见性、跨节点合并和 UDP 建立前写入取消。 |
| 官方 IPv4 节点互通 | 两两矩阵双向 44 项和配置负面 1 项通过，共 45 项。 |
| 官方 IPv6 节点互通 | 8 行双向与配置负面共 17 项 smoke 通过，单独记录覆盖范围。 |
| 构建与检查 | 两端 release、严格 Clippy、修改的 Rust 文件格式，以及客户端仅 WireGuard 和服务端仅 OpenVPN 的独立构建及运行时依赖裁剪通过。 |
| 正式对比 | 十次代理负载的错误、超时和错字节均为 0。每轮核对逐块、逐秒、总量、采样时间窗及回显目标实际工作。 |
| 负面对照 | 错误总量、错误逐秒计数、缺少一侧、参数不一致和缺失参数均被拒绝。CPU 阈值的边界、超限、空样本及零 CPU 比值对照通过。 |

[`run_regression.py`](../../tools/mieru_bench/run_regression.py) 的 `cpu_30_percent_lower` 和 `all_pairs_cpu_30_percent_lower` 均为真。复现可加 `--require-cpu-reduction 30`，任一配对未达线时以状态码 2 退出；已完成的本轮数据也按这一判据重新核对通过。

| 本轮二进制 | SHA-256 |
| --- | --- |
| 固定版本 mita | `5cc6fff6be3f6998773ab31a2231854455182cca183be4a523f3fe77a99e5915` |
| kerlico-server | `693f17be47c14f2b61159a2ebc7fc6af7bbf53757ba24ead647e0fdd72fed443` |
| 共同官方 SDK 负载 | `2ff60ddda946f71c980d0d6f472ae94eaa24afa4628b01f8e56c33b1ae29af38` |

原始数据、失败与通过记录、剖析和源码指纹保留在 `.private/mieru-optimization-20261109/mita30/` 及本次 worker 目录，不进入 Git。
