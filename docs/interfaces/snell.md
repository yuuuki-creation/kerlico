# Snell 双端接口

`SnellFactory` 注册 `snell` 出站，`SnellNodeFactory` 注册 `snell` 节点（研究见 [snell.md](../../reference/research_notes/snell.md)，测试记录见 [snell.md](../testing/snell.md)）。角色范围为出站 v4、节点 v5、v6 双端；v4 客户端与 v5 节点采用普通兼容线格式，未实现 v5 QUIC Proxy Mode。v1–v3 与其他版本方向明确拒绝。

## 配置

- **出站必填**：`server: {host, port}`、`version`、`psk`；可选 `userkey`、`reuse`（默认 `false`）、`obfs_mode`（`none` / `http`，默认 `none`）、`obfs_host`、`obfs_uri`。
- **节点配置**：`options` 必填 `version`，可选同名 `mode` / `obfs` 选项；成员凭据 `members[].native_credential` 格式为 `{"psk": "协议 PSK", "userkey": "可选原生 userkey"}`（`unsafe-raw` 必须提供非空 `userkey`）。节点 `userkey` 不允许空或重复，最多 256 个，每个最多 255 UTF-8 字节。单 PSK 节点不将 `client-id` 当成额外身份凭据。

v6 专用 `mode` 为 default（默认）、unshaped、unsafe-raw；v6 拒绝 HTTP obfs 及其参数，PSK 必须为 12–255 字节。v4/v5 拒绝 mode。HTTP obfs 默认 host 为 `bing.com`、URI 为 `/`；它不是 WebSocket 或 TLS，HTTP 指纹未与原始发行程序比对。

unsafe-raw 没有加密或 PSK 鉴权，因此本项目要求显式 userkey，并限制回环 IP 字面量节点与代理服务器。其跨节点认证指纹只取实际 userkey，不以不同 PSK 伪造隔离。普通加密节点都登记 PSK 指纹，跨节点重复 PSK 即拒绝，防止单 PSK 节点接受另一个多用户节点的 client-id。userkey 列表仍按本节点鉴权。

```json
{
  "server": {"host": "127.0.0.1", "port": 17177},
  "version": 6,
  "psk": "snell-test-only-shared-key",
  "userkey": "node-test-only-user-key",
  "mode": "default",
  "reuse": true
}
```

## 流、数据报与资源

- TCP 请求发送后即可写业务；目标先发数据已覆盖。真实对端可能延迟 tunnel 回复到目标首包，首次读时再验证回复。错误不包含用户凭据或目标明文。
- 记录零块只表示该方向 EOF，另一方向继续读取；复用保持密码状态与 nonce，只把双向排空且无剩余帧的载体放回池。完整记录边界的物理 TCP EOF 可以结束普通业务，但该载体不得回池。同一命名运行实例按可信成员分别持池，容量 10、180 秒有效期，20 秒清理；发生错误或提前丢弃的连接直接回收，不在发送业务后透明重试。
- 可复用节点每个逻辑连接独立取得全局与节点 lease；引擎排空时禁止新逻辑流，已有流在预算内结束。UDP 目标关联分别持有预算、空闲计时和回写队列，随物理连接销毁。
- UDP 请求与目标回包都受节点 `max_datagram_size` 约束。每条记录对应一个包，允许零负载；不切分或截断数据报以掩盖长度限制。v4/v5 还受突发窗口动态记录上限约束，首批大包可能明确报资源限制；v6 包受 16 位记录长度和地址头占用限制。自端大包已验证至 8192 字节；固定 sing-box 的 v5 节点/ v4 客户端通用包路径实测分别受 1402/1162 字节 MTU 约束，超出会被该对端截短，不能据自端结果推定大包外部兼容。外部零包未覆盖。
- 网站目标全部通过 `PeerSession`。域名 UDP 回写必须使用通道的 `peer_addr()` 业务目标字面元数据；没有元数据时明确拒绝该关联，不能自行 DNS 或用载体地址替代。
- 加密模式在首请求通过认证后登记方向盐，节点缓存最多 8192 条、保存 300 秒；重复盐或达到容量时拒绝新连接。unsafe-raw 无盐，不能继承此防重放声明。

## 完成权与 UDP 回写确认契约

- 每次逻辑 CONNECT 使用独立 `TcpFlow`，成功应答失败先报告，顺序复用不会共用一个完成权；底层出站 `OpenedTcp` 返回 `TcpConnectInfo::unknown()`。
- UDP Entry 持完成权和发送半部，接收结果及回包带目标代次（32 项有界回复队列）；缺失或非法业务来源先报告失败。
- UDP 目标回包进入队列后，父任务在实际记录写入与 `flush` 成功后回传私有 receipt；接收任务等待确认后才读取下一包或 EOF。父退出只保留已确认交付后的独立 End，其余目标先固定父终因，再取消和回收。上传活动不丢弃正在等待的接收 future。
