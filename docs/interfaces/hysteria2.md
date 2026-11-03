# Hysteria2 双端接口

`kerlico-hysteria2` 导出 `Hysteria2Factory`、`Hysteria2NodeFactory` 以及后端类型 `Hysteria2Outbound`、`Hysteria2Node`，类型均为 `hysteria2`（研究见 [hysteria2.md](../../reference/research_notes/hysteria2.md)，验证记录见 [hysteria2.md](../testing/hysteria2.md)）。

- **节点成员凭据**：每条 `members[].native_credential` 为 `{"auth": "synthetic-password"}`。HTTP/3 认证请求的实际命中行创建连接 `PeerSession`，已认证连接不接受改换成员；Salamander 秘密只登记 `Protection`。
- **成员池与 QUIC 生命周期**：成员池按 `ConnectContext.resource_key()` 分区，外层表短暂加锁，拨号与协商只持对应成员 bucket 锁；每次新建 QUIC 连接设置独立 `TokenMemoryCache`。QUIC 入站原生驱动登记到 `NodeTasks` 并使用独立子取消域。

## 首轮完整范围

- QUIC v1、TLS 1.3、ALPN h3，双端 HTTP/3 鉴权；无认证或错误认证请求返回静态 404 页面。
- 原生 TCP 业务流，目标成功响应后返回流，保留写端 FIN 和反向排空。
- 原生 QUIC UDP datagram，固定目标与同一 Session ID 的多目标关联，支持空包、分片、乱序重组、冲突/缺片/超时丢弃与实际来源地址回写。
- 普通 QUIC 与 Salamander 两种载体；自适应 BBR、NewReno 两种拥塞配置。
- 独立 IPv4/IPv6 节点凭据、节点/全局资源预算、统一目标访问、空闲回收、取消与退出。

具体结果见[验证记录](../testing/hysteria2.md)。Hysteria v1、Gecko、Brutal 固定速率、端口跳跃、Realm、noise、ECH、指纹模仿、外部认证与反向伪装代理尚未实现，不提供无效开关。

## 配置

客户端 options：

```json
{
  "server": {"host":"127.0.0.1","port":8443},
  "auth":"synthetic-node-secret",
  "tls": {"server_name":"localhost","ca_pem":"PEM 内容"},
  "salamander_password":null,
  "limits": {"congestion":"bbr"},
  "finalmask": {"brutal_up":10000000,"brutal_down":50000000,"udp_hop":{"remote_ports":[8443,8444],"interval":30}},
  "multiplex": {"enabled":false,"padding":false}
}
```

节点 options：

```json
{
  "tls": {"certificate_file":"certificate.pem","private_key_file":"private-key.pem"},
  "udp":true,
  "salamander_password":null,
  "limits": {"congestion":"bbr"},
  "finalmask": {"brutal_up":10000000,"brutal_down":50000000,"udp_hop":{"remote_ports":[8443,8444],"interval":30}},
  "multiplex": {"enabled":false,"padding":false}
}
```

同一节点的客户端与服务端 auth 必须一致，IPv4/IPv6 不同节点分别设置独立 auth。节点 TLS 每种材料分别选择 `_pem` 或 `_file`，不得同时填写；单份材料最多 1 MiB。客户端不设 ca_pem 时信任内置公共根；不接受 insecure 跳过验证。auth 必须为非空、至多 4096 字节的合法 HTTP 字段值，拒绝首尾空白。Salamander 密码为可选的 4–4096 字节字符串，必须双端一致，它不替代 auth。

`limits` 默认值：max_streams=64、udp_queue_packets=16、udp_queue_bytes=4194304、idle_timeout_ms=30000、congestion=bbr。允许 max_streams 1–1024、UDP 队列 1–64 包、队列字节 65536–16777216、空闲时间 100–86400000 毫秒。congestion 仅接受 bbr 或 reno；实际使用 Quinn 对应控制器，不是官方 BBR/Brutal 实现。

客户端 auth 请求通告接收速率 0；服务端返回 auto，采用自适应控制。客户端接收对端的 0/auto；收到非零固定速率会明确拒绝，避免接受但忽略尚未实现的协商限制。

## 节点、服务和生命周期

物理监听只使用 UDP/QUIC，TCP 业务通过 QUIC stream 承载；不建立同端口 TCP listener。UDP 业务可以关闭，此时物理 QUIC 仍通过 UDP 工作。开启 UDP 业务时，节点要求出口实现 `DatagramAssociation`，配置准备阶段通过 `requires_udp_association` 校验；不得静默退回多个固定目标 socket。

每个节点只保存本节点 auth 指纹与载体配置，注册表拒绝同协议跨节点复用 auth。节点经鉴权、解码后，TCP 使用 `PeerSession::connect_tcp`，UDP 使用 `PeerSession::associate_udp`。后者保留同一会话的出口 socket 与实际来源；节点、载体和目标的 IPv4/IPv6 不互相限制。

HTTP/3 与 TCPRequest 由唯一 bidirectional stream 接纳器按首个 varint 分流。普通请求和鉴权前的特殊类型交 HTTP/3 处理；0x401 只有在连接已鉴权后进入代理处理器。各 stream 的前缀字节保留，不靠两个 accept_bi 消费者竞争连接。

一个 QUIC carrier、每个新 HTTP/代理 stream 和 UDP 关联分别受共享预算约束；控制 stream 另有 QUIC 数量/窗口限制。UDP 队列同时受包数和字节数约束，分片最多 255 片，每会话只保留一个未完成包，5 秒后失效；有效回收还受业务空闲时间限制。最大业务包 65507 字节，零长度包不等于关闭。关闭新预算后拒绝新会话，既有业务可以在 engine 的排空期限内运行；强制取消后关闭 endpoint 并回收任务。

客户端连接池按出站实例保存，不跨节点共享带身份的资源。TCP 返回前完成认证、请求发送及成功响应；UDP 返回前确认对端支持 datagram。鉴权失败不会重试其他节点或凭据。错误文本不包含远端响应正文、认证值或原始 QUIC close reason。

### 完成权与 H3 控制排空契约

- 底层 `Outbound::connect_tcp` 返回 `OpenedTcp` 与 `TcpConnectInfo::unknown()`。父级载体保留已建立流的完成权，子任务完成权票据意外释放时从父表唯一移出并在锁外报告终因。
- **H3 控制排空**：H3 `accept()` 首次返回 `None` 作为新准入关闭点，停止新原生 TCP 准入和新 UDP session，并固定一次 `drain_timeout` 截止时间。H3 对象保持到排空结束，继续驱动控制帧及唯一分流器。
- **待识别流与队列排空**：`TCP_ID = 0x401` 的两个 varint 字节只到达一个时，原 `StreamLease` 仍属该识别 future。识别完成后进入队列读取请求头和连接目标；全部待识别流结束后才关闭队列的新发送。排空期间每轮至多拒绝 64 个新到达的 QUIC 双向流（直接 `reset` + `stop_sending`），再轮询旧识别 future；旧 sniffer 识别为非 TCP 时直接拒绝。
- **H3Control 轮询与关键流关闭**：`H3Control` 每次 poll 新建 `accept()` future 并只轮询一次，重复 `None` 转为 `Pending`，只有待识别集合缩减才向外报告进展。若 `accept()` 返回未处理的 HTTP resolver，只对该流执行 `reset` 与 `stop_sending` 并由 `RequestEnd` 退账。独立 control stream `RESET` 由固定 `third_party/h3` 解析为 `H3_CLOSED_CRITICAL_STREAM`，连接循环随后以 `Failed` 关闭已有业务完成权并回收资源。
- 只有待识别流、队列和实际任务同时排空才正常结束；超时、节点取消与 QUIC 失败先固定对应父终因，再关闭和回收。
