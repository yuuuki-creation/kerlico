# mieru 固定配置负载工具

只回答“在这一组固定配置、相同负载和 VPS 内网路径下，两服务端的有效载荷指标有什么差别”。工具不会据单次结果宣称某实现普遍更快，也不会扫描配置组合。两边都使用同一官方 Client SDK，固定 TCP、MULTIPLEXING_LOW、HANDSHAKE_STANDARD、低熵 OFF、MTU 1400，以及合成账号 `test-user/test-password`。

模块参照官方 SHA `1367cf2d2dd81c5f27d455be7cea691d7948c420`。在独立 worker 副本核实该提交并执行本地 replace；`go.mod` 的版本只是模块定位，不足以证明编译来源。构建、格式、检查和执行都只在 worker，当前结果见[一分钟性能记录](../../docs/reference/mieru-performance.md)：

```sh
cd tools/mieru_bench
go mod edit -replace github.com/enfein/mieru/v3=../../reference/.upstream/mieru-20261109
go mod tidy
gofmt -w main.go
go build -o /private/runtime/directory/mieru-bench .
```

所有真实地址仅通过运行时 flags 提供，输出使用 `--label rust`、`--label official` 等别名，不写 endpoint 或账号。以下地址变量由私有编排注入，不要把包含真实地址的命令行、shell 历史或进程采样原文提交。

```sh
# 同一 echo 进程同时服务内网直连基线和代理后面的回环目标。
mieru-bench echo --listen "$BENCH_INTERNAL_ECHO" --listen "$BENCH_LOOPBACK_ECHO" > echo.jsonl

# 先观察链路和负载机上限；基线不算任一代理的成绩。
mieru-bench load --direct --target "$BENCH_INTERNAL_ECHO" --duration 5s --warmup 5s --label baseline > baseline.jsonl

# 两服务端分别调用同一条命令，只替换 peer 和结果别名。
mieru-bench load --peer "$BENCH_PROXY_PEER" --target "$BENCH_LOOPBACK_ECHO" \
  --duration 60s --warmup 5s --concurrency 8 --block-size 32768 --latency-size 64 \
  --label rust --start-at "$BENCH_START_UNIX_MS" > load.jsonl
```

省略 `--start-at` 时，所有九条会话先建立，再同时预热五秒；全部预热完成后输出 `ready`，约半秒后开始。指定该 flag 时必须留足连接与预热时间，否则非零退出，不会默默改期。资源采样应按 `ready.scheduled_start_unix_ns` 启动，并以 `start.start_unix_ns` 和最终 CPU 窗口记录核对实际边界。没有 stdin 屏障或隐藏的二次启动路径。标准握手全部发生在计时之前，计时区间不新建会话。

八条 bulk 持久流每次完整写入 32768 字节、完整读回并逐字节比对后才开始下一块。每条流有不同的确定性载荷，并在头八字节写入递增序号，避免重复旧数据被当成完成。另有一条 64 字节流，每约十毫秒执行一次同样的校验，用于延迟探针。没有无限队列，内存上界与并发数、块大小和秒数成正比。

`second` 记录在全部流结束后按时间桶输出，其中 ACK 字节只代表计时区间内已经读完并校验正确的应用 payload。`effective_one_way_mbps` 是 bulk ACK 字节乘八除以固定计时秒数，`effective_bidirectional_mbps` 是上述有效载荷的收发合计，即两倍；不包含探针、协议头或线上加密流量。warmup 和握手不计入吞吐。到期不再开始新块，允许已开始的块最多排空五秒；到期后才完成的校验单列 `late_*`，不计入吞吐、各秒完成次数或 timed RTT。失败、超时和错字节都计数且非零退出，不能把提前结束的流记为成功。

bulk 和 probe RTT 包含本进程完整写入、读回与字节验证的时间；每流使用固定大小的对数直方图，每个数量级十六档，p50/p95/p99 报告桶上界（约 6.25% 桶宽），不会保存无限样本。CPU 使用 `getrusage` 的计时区间增量，百分比以单核为 100%，所以多核可超过 100%；CPU 采样实际时间窗另列。自定义官方 common.Dialer 统计真实建立的 TCP underlay，总数与关闭前活跃数都输出；直接基线没有代理 underlay，值为零。

echo 不识别请求块边界，只回写实际读到的数据，记录每秒实际 read/write 字节、读调用、写批次、连接、关闭和错误计数。SIGTERM 关闭所有监听与拥有连接，等待接受循环和复制任务结束，再输出带实际开始、结束与持续时间的 final。load 同样回收全部会话并停止 SDK。echo 的计数包含预热、计时和排空，需用时间戳与客户端 timed ACK 核对，不能直接拿 echo 全生命周期字节替代 60 秒吞吐。

`run_comparison.py` 使用 `--hold-after-final 2s` 让负载进程在结果输出后短暂保留，供资源采样读取最后一个快照。该等待不计入吞吐、RTT 或 CPU 的计时窗口，避免直连基线正常退出与采样结束发生竞态。

执行前按 benchmark-checklist 核对机器负载、核数、release/生产参数及内网基线。应同时采集服务器、echo 和负载机的 CPU、RSS、FD 与网络指标，判断瓶颈是否在负载端。两边至少交替跑五次，报告中位数和范围；若本轮只各跑一次，应明确“一次固定配置观测”，没有重现性和瓶颈证据就不选性能赢家。先排除错误、错字节或未实际发生的工作，再比较指标。基线只用于合理性和链路上限校验，不可当成已识别瓶颈的证据。

`run_comparison.py` 在至少 8 个可用逻辑 CPU 的 Linux worker 上编排回环对比，把服务端、共同客户端和 echo 分为 4/3/1 核。它只管理自己启动的进程，并要求全局 mita 资料目录不存在。`sample_process.py` 读取指定进程的 `/proc`，关键进程退出会使本轮失败。`check_results.py` 独立核对逐秒计数、逐块字节、时间窗与目标工作，并含错误总量、错误逐秒计数和缺失一侧的负面对照。

```sh
python3 tools/mieru_bench/run_comparison.py \
	--kerlico-bin /private/runtime/directory/kerlico-server \
	--mita-bin /private/runtime/directory/mita \
	--bench-bin /private/runtime/directory/mieru-bench \
	--output /private/runtime/directory/new-result --duration 60
python3 tools/mieru_bench/check_results.py \
	/private/runtime/directory/new-result/comparison.json \
	--output /private/runtime/directory/new-result/independent-check.json
```
