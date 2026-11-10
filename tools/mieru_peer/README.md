# 官方 mieru 双向互通夹具

本工具使用官方 `apis/client`、`apis/server`、`apis/common`，不复制官方协议实现。固定参照 SHA 是 `1367cf2d2dd81c5f27d455be7cea691d7948c420`；`go.mod` 的 `v3.0.0` 只是模块定位，执行前必须在独立 worker 副本使用本地 replace 指向该 SHA。不要在上游缓存目录改源码，不要使用真实账号。

以下命令只在专用 worker 执行。当前实现和验收记录见 [mieru 接口文档](../../docs/reference/mieru.md)。

```sh
# 在 worker 仓库根执行；先由调度者核实上游只读目录的提交 SHA。
cd tools/mieru_peer
go mod edit -replace github.com/enfein/mieru/v3=../../reference/.upstream/mieru-20261109
go mod tidy
go build -o /tmp/kerlico-mieru-peer .
cd ../..
python3 tools/verify_mieru.py \
  --server-bin /absolute/path/to/kerlico-server \
  --client-bin /absolute/path/to/kerlico-client \
  --peer-bin /tmp/kerlico-mieru-peer \
  --output /private/run/directory/mieru-results.json
```

Go 模块变动和 `go.sum` 只在 worker 副本生成。输出内的 upstream_sha 是预期参照标识，不能单独证明依赖源码；必须同时留存 worker 对源码 SHA 和 replace 的核验记录。

默认是五个因素（TCP/UDP、四级复用、两种握手、低熵 0..4、MTU 1280/1400）的确定性两两覆盖，每行运行两个方向。`--full` 显式选择同一默认矩阵；`--quick` 为 8 行 smoke，JSON 会明确标注 smoke，不能当完整矩阵报告。每个方向有自己的总期限，默认每 case 90 秒、整套 2400 秒；更慢的 worker 可通过 `--case-timeout` 和 `--suite-timeout` 显式调整。IPv6 fixture 不能绑定会直接失败，没有静默跳过。

`--case-index 0` 只复现所选矩阵的第一行双向 case，JSON 明确标记 `coverage=partial`，不执行单独的配置负面 case，也不代表完整通过。UDP 失败同时留下包序号、预期与实际长度、目标、来源、内容前缀和原始错误；目标回显器接收上限显式设为 65535 字节，避免 `socketserver` 默认 8192 字节截断制造假失败。

`--node-host` 默认 `127.0.0.1`。传入 `--node-host ::1` 可以验证 IPv6 节点承载；Rust 服务端监听、官方对端地址、Rust 客户端远端地址、临时端口分配及退出后的绑定检查都会使用 IPv6，IPv6 检查设置 `IPV6_V6ONLY` 并实际执行 `bind+listen`。本机 SOCKS/HTTP 入口仍使用 `127.0.0.1`，独立目标夹具不变。`--quick --node-host ::1` 是 8 行双向加配置负面共 17 项 smoke，结果明确记录 `coverage=smoke` 与 `node_host=::1`，不能据此宣称完整两两矩阵通过。

`server` 子命令是真正的代理服务端：完成官方 API 要求的 SOCKS 应答，CONNECT 使用 TCP 拨目标，UDP ASSOCIATE 使用官方 PacketOverStreamTunnel 和 UDPAssociateWrapper，按包目标拨独立 UDP socket，再带真实源地址返回。不会把入站数据直接自行 echo。`probe` 通过官方 API 建立可复用客户端，8 条并发 TCP 流逐字节核对，UDP 包含空包、1 字节、MTU 边界、32KB 分片和多目标；所有目标由外部 Python fixture 提供。

```sh
/tmp/kerlico-mieru-peer server --listen 127.0.0.1 --port 46000 --transport UDP --mtu 1280 --low 4
/tmp/kerlico-mieru-peer probe --listen 127.0.0.1 --port 46000 --transport UDP \
  --mtu 1280 --low 4 --multiplexing MULTIPLEXING_HIGH --handshake HANDSHAKE_NO_WAIT \
  --tcp-targets 127.0.0.1:47000,[::1]:47001,localhost:47000 \
  --udp-targets 127.0.0.1:48000,127.0.0.1:48001,[::1]:48002 --timeout 25s
```

Python 驱动只使用合成账号 `test-user/test-password`。Rust 客户端使用 `--mieru-proxy client.json`。Rust 服务端测试配置只走原生环回目标；配置显式提供 `warp.secretKey="invalid"`，并在 case 目录放同样无效的 `warp.json`。这是为了使现有 `load_profile` 在解析阶段立即失败，避免 `warp.disabled` 未被识别后触发真实网络注册；并非宣称应用增加了 disabled 开关。

TCP 退出检查采用与生产监听相同的 `SO_REUSEADDR=true` 后 `bind+listen`，不使用 `SO_REUSEPORT`。它允许符合该策略的 TIME_WAIT 重启，但活跃 LISTEN 必须失败；失败证据保留端口、错误和 Linux socket 状态，不能把 TIME_WAIT 或任意绑定错误无条件算通过。worker 的独立坏控制保留“活跃 LISTEN 被拒绝”与“关闭后重绑成功”的成对记录。

有效流的 Python 收发、TCP 回显目标空闲预算与 Go 对端操作预算统一为 25 秒，case 总期限仍为 90 秒。原先回显目标只有 2 秒空闲预算，会在 UDP 底层合法重传前主动断开；worker 保留了每条失败流与对应目标 TimeoutError 的读写字节和耗时，修正预算不会减少负载或放宽内容断言。Go 服务停止时先取快照，并发关闭自己拥有的全部独立应用连接，等待关闭任务收敛后调用官方 Stop 并等待完成，不依赖 Stop 替夹具关闭现有连接，也不把官方每会话优雅关闭的等待时间串行累加。三秒退出上限保持不变，超时仍判失败并由 SIGQUIT 留下 Go 堆栈。

本机代理覆盖 SOCKS CONNECT 和 UDP ASSOCIATE、HTTP GET/POST/chunked/CONNECT、IPv4/IPv6/域名、同 HTTP keepalive 切换目标、CONNECT 预读字节、UDP 连发边界、控制连接关闭撤销关联。首行额外验证错误账号、UDP FRAG 和外来来源、非法 HTTP；独立 case 验证非法设置、重复/占用端口和第二次绑定失败的回滚。每次退出均清理所有子进程组，并检查端口可重绑；失败退出码为 1，JSON 和相对日志路径保留具体失败 case。中断也通过 finally 关闭所管理进程。

这套黑盒结果不能替代引擎内部的概率穷举、nonce 顺序、超时/取消、重放/乱序和 Arc/FD 资源验收。wire 成功只能证明这一矩阵的真实通信成功，不能证明四级复用的概率分布或进程内资源已完全回收。
