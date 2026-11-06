# sing-mux 多路复用

更新日期：2026-11-07（Asia/Shanghai）

`kerlico-net::sing_mux` 实现 sagernet/sing-mux 的线格式，与 sing-box 1.14.4（sing-mux `caf09fe`）和 Mihomo v1.19.33（metacubex/sing-mux v0.3.12）双向互通。Shadowsocks、VMess、VLESS、Trojan 出站用 `multiplex` 启用客户端；这些协议以及 Hysteria2、TUIC、ShadowQUIC、Sudoku 节点用 `multiplex` 接纳复用流。客户端把载体拨到 `sp.mux.sing-box.arpa:444`，服务端见到该目标即进入 sing-mux 会话。

## 配置

出站 `multiplex`：

```json
{"enabled":true,"protocol":"h2mux","max_connections":4,"min_streams":4,"max_streams":0,"padding":false,"only_tcp":false,
 "brutal":{"enabled":false,"up_mbps":0,"down_mbps":0}}
```

| 字段 | 含义 |
| --- | --- |
| `protocol` | `h2mux`（缺省，别名 `h2`）、`smux`、`yamux` |
| `max_connections` / `min_streams` / `max_streams` | 会话选择规则同 sing-mux：取流数最少的会话；流数为 0 直接复用；设了 `max_connections` 时，会话数已达上限或该会话流数小于 `min_streams` 就复用；否则仅当设了 `max_streams` 且流数小于它时复用；其余情况新建载体。三者都不设时只复用空闲会话。取值不能为 0 |
| `padding` | 启用会话请求版本 1 与填充记录 |
| `only_tcp` | 为真时 UDP 不走复用 |
| `brutal` | 新会话先做 Brutal 带宽交换，`up_mbps`、`down_mbps` 须大于 0；所有新流固定复用第一个会话 |

节点 `multiplex`：`{"enabled":true,"padding":false}`。`padding: true` 拒绝未填充的客户端。节点的 `brutal.enabled: true` 在加载时报错：服务端 Brutal 要在载体 TCP 套接字上设置 `TCP_CONGESTION brutal`，kerlico 入站拿不到该套接字；客户端发起的 Brutal 交换收到拒绝响应 `brutal is not enabled by the server`。旧字段 `mux_option_padding` 仍可用。

Mihomo 订阅的 `smux` 映射到 `multiplex`：`protocol`、`max-connections`、`min-streams`、`max-streams`、`padding`、`only-tcp` 同名转换，`brutal-opts.enabled: true` 时 `up`、`down` 按 Mihomo 带宽写法（无单位为 Mbps）换算为 `up_mbps`、`down_mbps`。

## 线格式

- **会话请求**：无填充时 `00 | 协议`；有填充时 `01 | 协议 | 01 | u16 填充长度 | 256..767 字节随机数据`。协议编号 smux=0、yamux=1、h2mux=2。
- **填充记录**：请求之后每个方向前 16 次写入各自封装为 `u16 数据长度 | u16 填充长度 | 数据 | 填充`，之后直通。
- **smux**：xtaci/smux 帧 `版本 1 | 命令 | u16 LE 长度 | u32 LE 流 ID`，单帧上限 32 KiB，无保活。smux v1 没有逐流窗口，会话内未读数据超过 4 MiB 时暂停读载体。smux 没有半关闭：一端关闭写即发 FIN，对端收到后写入失败。
- **yamux**：hashicorp/yamux 帧 `版本 0 | 类型 | u16 标志 | u32 流 ID | u32 长度`，逐流初始窗口 256 KiB，读走一半窗口后发 WINDOW_UPDATE。服务端收到 SYN 立即回 ACK，避免触发对端 5 秒打开超时；回应对端 Ping；支持半关闭；本端释放未收到对端 FIN 的流 5 秒后发 RST。
- **h2mux**：`h2` crate 的 HTTP/2。每条流是一个 `CONNECT`（`:authority localhost`）请求，请求体为上行，`200` 响应体为下行；逐流窗口 4 MiB，连接窗口 16 MiB。客户端在响应头到达前即可写入，因为 Go 服务端在首个下行数据时才发出响应头。
- **流请求**：`u16 标志 | SOCKS 地址 | u16 端口`。标志 0 为 TCP，1 为固定目标 UDP（每包 `u16 长度 | 负载`），3 为逐包地址 UDP（每包 `SOCKS 地址 | 端口 | u16 长度 | 负载`）。
- **流响应**：成功为 `00`；失败为 `01 | uvarint 长度 | 错误文本`。kerlico 服务端拨号完成后立即写状态；客户端在首次读取时解析状态，因为 sing-mux 服务端在首个下行数据前才写状态。
- **Brutal 交换**：流目标为 `_BrutalBwExchange:0`，客户端写 `u64` 下行字节每秒，服务端回 `01 | u64 接收速率` 或 `00 | uvarint 长度 | 错误文本`。

`connect_udp` 用固定目标流，`associate_udp` 用逐包地址流。逐包地址流的流请求随首包写出，请求目标取首包目标，与 sing-mux `ListenPacket` 一致；sing-box 服务端按该目标路由整条 UDP 流，请求目标写成占位的 `sp.mux.sing-box.arpa:444` 时不转发任何包。

## 限制

- 客户端 Brutal 只完成带宽交换：载体是经协议封装的 `BoxStream`，kerlico 不在客户端载体套接字上设置 Brutal，与 sing-box 客户端设置失败时的行为相同（只影响上行拥塞控制）。
- 不发送 yamux 保活 Ping，也不发送 smux NOP。
- SS2022（`2022-*` 加密）出站不支持 `multiplex`。

## 验证

单元测试位于 `crates/net/src/sing_mux/`。真实对端矩阵用 `tools/interop_sing_mux.py`，见 [sing-mux 互通记录](../testing/sing-mux-2026-11-07.md)。
