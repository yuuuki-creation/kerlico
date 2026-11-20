# SOCKS5

协议 id 为 `socks`。客户端和入站使用 `socks` feature，服务端落地使用 `landing-socks`。线协议按 [RFC 1928](https://www.rfc-editor.org/rfc/rfc1928) 和 [RFC 1929](https://www.rfc-editor.org/rfc/rfc1929) 实现。互通基线使用 [Xray-core v26.10.31](https://github.com/XTLS/Xray-core/releases/tag/v26.10.31)。

## 入站

在 `inbounds` 中添加一个 SOCKS5 节点。

```json
{
  "tag": "socks-in",
  "protocol": "socks",
  "listen": "127.0.0.1",
  "port": 1080,
  "outbound": "default",
  "settings": {
    "auth": "password",
    "users": [{"user": "demo", "pass": "change-me"}],
    "udp": true
  }
}
```

`auth` 默认 `noauth`，也可设为 `password`。密码认证时填写 `users`，也接受 Xray 的旧键 `accounts`。同时提供时使用 `accounts`。账号可填写 `email` 作为计数和管理键，省略时依账号顺序分配 `socks-user-1` 等标识。用户名和密码各为 1 到 255 字节。接受 `userLevel: 0`。

`CONNECT` 接受 IPv4、IPv6 和域名，保留客户端提前发送的载荷及 TCP 半关闭。原生出口、分流和计数沿用普通节点配置。`UDP ASSOCIATE` 通过 `udp: true` 开启。每条关联使用独立 UDP 端口，并在 TCP 控制连接结束时关闭。`ip` 可指定返回给客户端的中继 IP，地址族须与监听地址相同。关联核对 UDP 来源地址和端口，未声明端口时固定第一个有效来源。`BIND` 返回命令不支持，带分片号的数据报丢弃。监听入口接受 SOCKS5。

Linux 原生 TCP 在握手完成后使用统一出站的 `splice`。没有嗅探预读字节的连接由出站批量等待套接字就绪，各方向独立应对背压。UDP 按线上的目标地址复用已有转发流。原生 UDP 完成选路后，在入站执行器上直接交付借用的报文，回包的协议头和载荷经一次向量发送提交。两侧按套接字就绪处理至多 32 个报文，再检查关联状态或交还执行时间。握手和 UDP 关联各有独立的并发限额。

原生 UDP 的入站和出口收满一批后显式让出执行时间。待选路数据由入站执行器按序发送，随后在同一次交接中安装发送器。TCP 成功响应使用所选出口的绑定地址。原生 TCP 和 WARP 报告本端地址及端口，SOCKS 落地保留上游报告的绑定地址，未提供绑定信息的出口返回未指定地址。[RFC 1928 第 6 节](https://www.rfc-editor.org/rfc/rfc1928#section-6)

## 客户端和落地

客户端配置向服务端提供 `peer`，也可把 Xray SOCKS 出站的 `address`、`port`、`user`、`pass` 放在 `settings` 里。

```json
{
  "protocol": "socks",
  "peer": "127.0.0.1:1080",
  "settings": {"user": "demo", "pass": "change-me", "socks5Port": 1081}
}
```

落地按服务端的 `landing` 配置指定 SOCKS5 代理。

```json
{
  "protocol": "socks",
  "address": "127.0.0.1",
  "port": 1080,
  "settings": {"user": "demo", "pass": "change-me"}
}
```

省略 `user` 和 `pass` 使用无认证上游。TCP 请求保留目标域名，由上游解析。UDP 按上游返回的中继地址收发，入站标为同一关联的落地流可以共享一条 SOCKS5 UDP 关联。节点和出站选择见 [服务端参考](server.md)。

SOCKS TCP 落地的每次写入报告实际写入长度。出现背压时，统一出站从已写入的位置继续。

## 本机验证

`tools/verify_socks.py` 使用本机 IPv4 和 IPv6 目标，验证认证、TCP、UDP、Xray 双向互通和落地。先分别构建客户端和包含落地的服务端。

```sh
cargo build --locked --release -p kerlico-client --no-default-features --features socks
cargo build --locked --release -p kerlico-server --no-default-features --features socks,landing-socks
sudo bash tools/socks_bench/veth.sh python3 tools/verify_socks.py --xray "$(command -v xray)" \
  --server target/release/kerlico-server --client target/release/kerlico-client \
  --landing-server target/release/kerlico-server
```

Linux 压测使用 4 个可用 CPU 核和隔离的 veth 网络。两台代理使用同一个目标和流量夹具。每轮 8 条 TCP 流预热 5 秒，以 500 Mbps 持续发送并逐字节核对。主指标为服务端进程 CPU 时间，包括用户态和内核态。

```sh
rustc --edition 2021 -O tools/socks_bench/load.rs -o /tmp/kerlico-socks-load
sudo bash tools/socks_bench/veth.sh python3 tools/socks_bench/run.py \
  --server target/release/kerlico-server --xray "$(command -v xray)" \
  --load /tmp/kerlico-socks-load --veth --direction down --seconds 30 \
  /tmp/kerlico-socks-down kerlico xray xray kerlico kerlico xray
```

2026-11-20 在本机 ARM64 Linux 5.15 虚拟机验证水平触发的原生 TCP 路径。三组 30 秒下行配对的 6 个窗口各核对 1,875,000,000 字节，实测速率为 500.13–500.15 Mbps。

| 下行轮次 | Kerlico 进程 CPU 时间 | Xray-core 进程 CPU 时间 | 降幅 |
| --- | ---: | ---: | ---: |
| 第一轮 | 0.81 秒 | 1.28 秒 | 36.7% |
| 第二轮 | 0.82 秒 | 1.30 秒 | 36.9% |
| 第三轮 | 0.80 秒 | 1.22 秒 | 34.4% |

同步零拷贝路径的早期配对用 20 秒窗口，同一负载下上行平均进程 CPU 降低 61.4%，下行降低 14.7%。

最终构建的 20 秒上行检查中，Kerlico 使用 0.38 秒进程 CPU，Xray-core 使用 1.47 秒，降幅为 74.1%。同一构建通过 TCP 背压、半关闭、嗅探预读和双向 TCP、UDP 互通测试。本机分别让内核拒绝所有 `splice` 调用和仅拒绝从管道到目标的 `splice` 调用，均通过载荷校验。

UDP 对照使用 8 条关联，每秒发出 8,000 个带序号的 1,200 字节数据报，由同一个源站原样回送。客户端分别统计成功回包、重复和丢包，并核对每个成功回包的地址、长度和载荷。每个方向的目标有效载荷速率为 76.8 Mbps，预热期为 5 秒。

```sh
sudo bash tools/socks_bench/veth.sh python3 tools/socks_bench/run.py \
  --server target/release/kerlico-server --xray "$(command -v xray)" \
  --load /tmp/kerlico-socks-load --veth --udp --seconds 12 \
  "/tmp/kerlico-socks-udp" kerlico xray xray kerlico
```

两组 12 秒窗口中，每个实现共发出 192,000 个数据报。Kerlico 核对了 191,353 个成功回包，丢包率为 0.337%，平均进程 CPU 时间为 6.41 秒。Xray-core 核对了 191,925 个成功回包，丢包率为 0.039%，平均进程 CPU 时间为 4.88 秒。两端均无重复包。

同一夹具以 `--packets-per-second 26000 --seconds 8` 各跑两次，每个方向目标 249.6 Mbps。每个实现共发出 416,000 个数据报。Kerlico 核对了 415,989 个成功回包，丢包率为 0.003%，平均进程 CPU 时间为 4.215 秒。Xray-core 核对了 415,697 个成功回包，丢包率为 0.073%，平均进程 CPU 时间为 2.945 秒。两端均无重复包。

此处复测使用的 Kerlico 服务端 SHA-256 为 `16f3befef8e2673fdbc3afa05ea68bcd84e7f0a683f9ec645a33f8fde96d799b`，Xray-core 为 `5939649960deaf535bcd5f7ce0467a2b1d63b72a2758a6f42eade714ae8d5328`。

### 原生 UDP 直接转发复测

在本机 ARM64 Linux 5.15 虚拟机，将全功能构建与同机编译的 v1.16.4 及 Xray-core v26.10.31 交错运行。每个实现跑两轮，每轮预热 5 秒后计量 20 秒。两个负载分别为每秒 8,000 和 26,000 个报文，仍使用 8 条关联和 1,200 字节载荷。发包夹具保留目标包数，并限制虚拟机调度停顿后的补发速率。代理和测试端分别记录 Linux UDP 错误计数。

高档初测有一轮少收到 179 个回包，代理侧没有 UDP 错误，测试端接收队列记录了溢出。高档复测为三组测试的客户端和源站统一申请 4 MiB 的套接字接收缓冲，保留相同发包速率及代理配置。低档沿用操作系统默认的测试端缓冲。

```sh
rustc --edition 2021 -O tools/socks_bench/load.rs -o /tmp/kerlico-socks-load
sudo bash tools/socks_bench/veth.sh python3 tools/socks_bench/run.py \
  --server target/release/kerlico-server --baseline-server /path/to/v1.16.4/kerlico-server \
  --xray "$(command -v xray)" --load /tmp/kerlico-socks-load --veth --udp \
  --packets-per-second 26000 --seconds 20 --endpoint-udp-buffer 4194304 \
  /tmp/kerlico-socks-udp-26k baseline xray kerlico kerlico xray baseline
```

| 每方向有效吞吐 | 优化版进程 CPU 时间 | Xray-core 进程 CPU 时间 | v1.16.4 进程 CPU 时间 | 配对降幅（对比 Xray-core） |
| --- | ---: | ---: | ---: | ---: |
| 76.8 Mbps | 3.78、3.80 秒 | 7.90、7.71 秒 | 9.82、10.42 秒 | 52.2%、50.7% |
| 249.6 Mbps | 4.58、4.59 秒 | 7.24、6.96 秒 | 10.32、10.21 秒 | 36.7%、34.1% |

两档的所有计量窗口均达到目标吞吐，回包、地址和载荷全部核对通过。每个实现分别验收 320,000 和 1,040,000 个回包，丢包及重复包均为零。两侧命名空间的 UDP 错误、接收缓冲溢出和发送缓冲溢出计数无增加。

全功能优化版服务器 SHA-256 为 `51aafd4717416a5cd3f8819878d6b4efc976090ad470b387a62a6772b75a78f8`，同机 v1.16.4 为 `89d4010512056a765d02f10a918ae159dac22d67768c490bf5049104fe29a2b7`。

修正 UDP 批次调度和路由交接后，在本机 Linux 5.15 虚拟机上通过 Kerlico 与 Xray 的双向 SOCKS5 互通，并核对了 CONNECT 回报的 IPv4 和 IPv6 绑定地址。两档 UDP 负载各计量 5 秒，分别核对 40,000 和 130,000 个回包。两档均无丢包、重复包或内核 UDP 错误。
