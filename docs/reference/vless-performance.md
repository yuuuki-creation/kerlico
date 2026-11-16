# VLESS 性能记录

这篇记一组固定组合的内网压测：怎么测、改动前后的数、剖析看到了什么、改了哪里。协议行为和数据路径的规则以 [VLESS](vless.md) 为准，这里不重复。

日期：2026-11-11。数字只说明这台机器、这组负载下的观测。

## 怎么测

工具是 `crates/server/tests/vless_perf.rs`，用 release 构建，汇总脚本是 `tools/vless_perf/report.py`。构建和运行都在 worker 上。

```text
XRAY=/path/to/xray PERF_OUT=results.jsonl PERF_SECONDS=30 PERF_STREAMS=8 PERF_CASE==grpc-reality-tun \
  cargo test --release -p kerlico-server --no-default-features --features vless,landing-vless \
  --test vless_perf -- --ignored --nocapture
```

`PERF_CASE` 的 `=名字` 只选这一个用例，不带等号按子串选。`PERF_DIRECTION` 用同样的写法选方向。

- 机器：`perf-01`，8 vCPU（Xeon Platinum 8269CY），回环。隧道服务端固定在 CPU 0-2，隧道客户端在 3-5，负载和回显源在 6-7。
- 对端：Xray 26.10.31。每个用例测三个方向，每次只换一端：Xray 客户端加 Xray 服务端是对照，Xray 客户端加 Kerlico 服务端测服务端，Kerlico 客户端加 Xray 服务端测客户端。
- 负载：8 条持久流，每条写 32 KiB 再读回，循环；另有一条流每 10 毫秒往返 64 字节，取延迟。预热 3 秒，计时 30 秒。
- 吞吐按读回的字节算，是单向的数。CPU 秒每 GiB 是被测进程的用户态加内核态时间除以读回的 GiB。RSS 每 0.2 秒采样。

## grpc-reality-tun

VLESS 经 gRPC（Tun）和 REALITY。8 条流和探针共用一条 HTTP/2 连接。

三轮各 30 秒，表中是中位数，括号里是三轮的范围。改动前是 `a08c02c` 的一轮。

| 方向 | 被测进程 | 吞吐 Mbps | CPU 秒每 GiB | 探针 P50 / P99 微秒 | 平均 RSS MiB |
| --- | --- | ---: | ---: | ---: | ---: |
| Xray 对 Xray | Xray 服务端 | 1812（1799 至 1864） | 7.05（6.76 至 7.06） | 602 / 2003 | 105.6 |
| Xray 对 Xray | Xray 客户端 | 同上 | 7.50 | 同上 | 86.8 |
| Kerlico 服务端，改动前 | Kerlico | 1096 | 14.76 | 865 / 2893 | 19.0 |
| Kerlico 服务端，改动后 | Kerlico | 2018（1996 至 2020） | 5.06（4.91 至 5.11） | 325 / 2049 | 16.3 |
| Kerlico 客户端，改动前 | Kerlico | 1005 | 15.54 | 902 / 3676 | 23.1 |
| Kerlico 客户端，改动后 | Kerlico | 1928（1693 至 1962） | 6.00（5.92 至 6.52） | 532 / 2743 | 19.7 |

服务端每 GiB 的 CPU 时间降到改动前的 34%，比同一负载下的 Xray 服务端低 28%；吞吐是改动前的 1.84 倍，比 Xray 对照高 11%。客户端每 GiB 的 CPU 时间降到改动前的 39%，比 Xray 客户端低 20%。客户端这一行的吞吐范围下沿是一轮受机器扰动的结果，没有剔除。

Xray 客户端的 RSS 取自改动前那一轮对照。

## 剖析看到的

改动前，Kerlico 服务端的 CPU 时间约 35% 在 futex 唤醒和线程切换，约 15% 在 AES-GCM。

- 一条 HTTP/2 连接的所有流等同一个条件变量。每读到一帧就唤醒全部流的读线程和写线程，其中多数马上又睡下。
- 每 16 KiB 的 DATA 帧单独写一次线路，每次是一条满记录加一条 9 字节的记录，各一次 `sendto`。
- REALITY 的记录层每条记录读两次套接字，加解密各分配并拷贝两到三次，用的是没有汇编实现的 AES-GCM。
- 收到的帧先整段拷进暂存区，再逐帧拷出来，再拷进流的缓冲。gRPC 的读取每 8 KiB 进一次连接的锁，每次清零 16 KiB 的栈缓冲。
- 接收窗口每消耗 16 KiB 就归还一次，每次是一条小记录和一次写。
- 对端 grpc-go 的连接窗口是 64 KiB，每次归还 16 KiB。8 条流共用它，每次归还都把所有等窗口的流唤醒。

## 改了哪里

规则写在 [VLESS 的数据路径](vless.md#数据路径)。按层列出：

- REALITY 记录层：`ring` 就地加解密；读缓冲随流量长到四条记录，一次读取取回已到达的全部记录，调用方的缓冲放得下就一并交付；一次写入最多封四条满记录后一并写出。
- TLS 记录层：同样的读缓冲和成批写出。TLS 状态仍然每次只收一条完整记录。
- HTTP/2：帧在读到的缓冲里原地解析，只有跨两次读取的那一帧才拼接；每条流的读和写各有等待点，一帧只唤醒它所属的流；接收窗口消耗满四分之一再归还；等发送窗口的流按先后取连接窗口，攒够再发；gRPC 连接增加写线程，读线程和读数据的流不再向线路写；一次写入的量和排队的量按线路速率取。
- gRPC：消息在读缓冲里原处解码；发送时前缀和数据直接成帧。
- 客户端落地：字节流读写直接用调用方的缓冲，不再每次读 8 KiB 经两次拷贝，写入也不再先整段复制。

一次有缺陷的中间做法值得记下。写数据的流入队后不等待，由拿到线路的线程一直代发到队列为空。对照矩阵的 `grpc-tls-sudoku` 因此偶发超时：一条读数据的流顺手刷新时接下了其他流排队的数据，在慢线路上几秒内回不去读。现在的规则是读的一方从不写线路，写的一方只代发它拿到线路时已经排队的那一批，其余交给写线程；线路落后时，每条流等自己上一块发出再写下一块。

第二处缺陷在 REALITY 的读取。一次读取交付多条记录时，起初每一条都就地解开，解不开就记下错误留给下一次读取。Vision 切换直连之后，最后一条记录后面是内层 TLS 的原始记录，外形与 REALITY 的记录相同。它如果和带 DIRECT 的那条小记录在同一次读取里到齐，就会被当作记录去解：解密失败时 `ring` 把这段字节清零，直连流的开头就丢了。对照矩阵 456 行里出现过一次（`raw-reality-vision-inner-tls`，Xray 客户端对 Kerlico 服务端），单独重跑没有复现。现在一次读取只判定第一条记录，后面的记录先拷进调用方的缓冲再解，解得开且是应用数据才算数，线路上的字节不动。拷贝的次数和原来相同，重测没有变慢。单元测试覆盖了这个时序。

## 其他组合

改动涉及 REALITY、TLS 和 HTTP/2 三层，下面的组合各测一轮 30 秒，只测 Kerlico 的两个方向，用来确认没有变慢。改动前的数和 Xray 对照取自同一天、同一工具的 20 秒全量轮，其中一部分在另一台 worker 上测得，只能看量级。

| 组合 | 方向 | 改动前 Mbps / CPU | 改动后 Mbps / CPU | Xray 对照 Mbps / CPU |
| --- | --- | ---: | ---: | ---: |
| raw-reality-tcp | 服务端 | 3613 / 5.77 | 5790 / 2.92 | 3782 / 4.12 |
| raw-reality-tcp | 客户端 | 3796 / 5.56 | 5543 / 3.00 | 3782 / 4.20 |
| raw-tls-tcp | 服务端 | 3936 / 4.60 | 5464 / 3.47 | 4433 / 3.71 |
| raw-tls-tcp | 客户端 | 4338 / 4.35 | 5173 / 3.62 | 4433 / 3.74 |
| raw-reality-vision-inner-tls | 服务端 | 4099 / 2.42 | 4280 / 1.85 | 4047 / 3.14 |
| raw-reality-vision-inner-tls | 客户端 | 3940 / 3.88 | 4417 / 1.86 | 4047 / 3.42 |
| raw-reality-encryption | 服务端 | 2856 / 8.24 | 4563 / 3.94 | 3761 / 4.51 |
| raw-reality-encryption | 客户端 | 2511 / 9.10 | 4389 / 3.94 | 3761 / 4.60 |
| grpc-h2c-tun | 服务端 | 1246 / 13.45 | 2405 / 3.88 | 2276 / 7.02 |
| grpc-h2c-tun | 客户端 | 1170 / 14.27 | 2323 / 4.67 | 2276 / 7.53 |
| grpc-tls-tun | 服务端 | 923 / 18.61 | 1932 / 5.87 | 1881 / 8.66 |
| grpc-tls-tun | 客户端 | 912 / 18.82 | 1698 / 7.25 | 1881 / 9.13 |
| grpc-reality-tunmulti | 服务端 | 1121 / 14.42 | 2025 / 4.62 | 1890 / 6.75 |
| grpc-reality-tunmulti | 客户端 | 991 / 15.63 | 1987 / 5.36 | 1890 / 6.98 |
| xhttp-h2-reality-stream-one | 服务端 | 2339 / 8.34 | 2918 / 6.24 | 2450 / 7.19 |
| xhttp-h2-reality-stream-one | 客户端 | 1964 / 10.28 | 3435 / 4.50 | 2450 / 6.40 |

CPU 一列是被测那一端每 GiB 的 CPU 秒数。十六行都没有错误。`raw-reality-encryption` 两行的改动后和 Xray 对照是下一节最终代码上三轮 30 秒的中位数。REALITY 的读取改成只判定第一条记录之后，`grpc-reality-tun`、`raw-reality-tcp`、`raw-reality-vision-inner-tls` 和 `xhttp-h2-reality-stream-one` 各重测一轮，没有变慢：CPU 与表中的数相差不到 3%，只有 `xhttp-h2-reality-stream-one` 的服务端更低，是 3459 / 5.33。

## VLESS Encryption

VLESS Encryption 是后来单独改的，分两步。

第一步是记录层。改动前剖析 Kerlico 服务端，约 35% 的 CPU 时间在 RustCrypto 的 AES-GCM（GHASH 乘法和 AES-CTR），客户端约 33% 在 RustCrypto 的 ChaCha20-Poly1305；每条记录都重新展开一次密钥，加解密各分配并拷贝一次，读一条记录要两次读套接字，写一条 8 KiB 的记录就是一次写。现在用 `ring` 就地加解密，密钥只展开一次，读缓冲一次取回已到达的记录，一次写出最多八条记录。

第二步是客户端的算法。Xray 客户端在有 AES 硬件的机器上选 AES-256-GCM（`protocol.HasAESGCMHardwareSupport`），Kerlico 客户端原来总是选 ChaCha20-Poly1305，第一步之后它仍占客户端 CPU 的约 27%。现在客户端按同样的条件选，规则见 [VLESS](vless.md#vless-encryptionvision-和复用)。服务端一直是哪种能解开就用哪种，没有改。

前两列各测一轮 30 秒。后两列是最终代码上三轮 30 秒的中位数，Xray 对照来自同一批的 Xray 对 Xray。

| 组合 | 方向 | 改动前 Mbps / CPU | 只改记录层 Mbps / CPU | 最终 Mbps / CPU | Xray 对照 Mbps / CPU |
| --- | --- | ---: | ---: | ---: | ---: |
| raw-reality-encryption | 服务端 | 3787 / 5.98 | 4482 / 4.03 | 4563 / 3.94 | 3761 / 4.51 |
| raw-reality-encryption | 客户端 | 3283 / 6.74 | 3787 / 4.58 | 4389 / 3.94 | 3761 / 4.60 |
| raw-encryption-native-1rtt | 服务端 | 4089 / 5.35 | 5484 / 3.00 | 5425 / 2.96 | 4426 / 3.81 |
| raw-encryption-native-1rtt | 客户端 | 3663 / 6.01 | 4406 / 3.73 | 5294 / 2.99 | 4426 / 3.88 |
| raw-encryption-random-vision | 服务端 | 4003 / 2.72 | 3942 / 2.33 | 4104 / 2.28 | 3967 / 3.60 |
| raw-encryption-random-vision | 客户端 | 4005 / 2.94 | 4148 / 2.32 | 4155 / 2.37 | 3967 / 3.51 |
| ws-encryption | 服务端 | 3048 / 7.64 | 3618 / 5.95 | 3575 / 5.93 | 3419 / 4.77 |
| ws-encryption | 客户端 | 2854 / 8.27 | 3420 / 6.17 | 3825 / 5.54 | 3419 / 5.37 |

三轮的范围：`raw-reality-encryption` 服务端 3.87 至 3.96，客户端 3.91 至 4.34；`raw-encryption-native-1rtt` 服务端 2.94 至 3.01，客户端 2.99 至 3.36。二十四次运行都没有错误。

前三个组合两端每 GiB 的 CPU 都低于 Xray。`raw-encryption-random-vision` 切换直连之后不再加解密，算法的选择对它没有影响。`ws-encryption` 两端仍高于 Xray，服务端高 24%，多出来的在 WebSocket 层，这次没有动。

## 边界

- 一台机器，回环，没有丢包和时延。每组一到三轮，轮间波动约 3%。
- 只测了 TCP 载荷。UDP、Mux 和 XUDP 没有测。
- WebSocket、mKCP、XHTTP H3 和 Hysteria 的数据路径没有动。`ws-encryption` 的服务端仍比 Xray 多用 24% 的 CPU。
- 客户端选 ChaCha20-Poly1305 的那条路径只有单元测试覆盖：三台 worker 都有 AES 硬件，对照矩阵里客户端走的都是 AES-256-GCM。
- 慢线路上的排队规则靠对照矩阵里最慢的组合（`grpc-tls-sudoku`，debug 构建）验证，没有在真实的慢速链路上测延迟。
