# Trojan 双端接口

`TrojanFactory`、`TrojanNodeFactory` 分别注册 `trojan` 出站与节点（研究见 [trojan.md](../../reference/research_notes/trojan.md)，验证记录见 [trojan.md](../testing/trojan.md)）。客户端、服务端均提供 TCP CONNECT 与 UDP ASSOCIATE；UDP 通过流载体封装，不声明原生 UDP 监听。

## 配置

- **出站选项**：`server: {host, port}`、`password`、`transport`、`security` 与可选 `multiplex`（`sing-mux` 连接池，`h2mux` / `smux` / `yamux`，见 [sing-mux](sing-mux.md)）。
- **节点配置**：`options` 为 `transport`、必填 `security`、可选 `multiplex`、`mux_option_padding`、`fallbacks` 与 `fallback_for_alpn`，协议密码位于 `members[].native_credential`（格式 `{"password": "协议密码"}`）。密码非空、最长 4096 字节，节点最多 256 个且不能重复。

`transport` 默认为 `"tcp"`，也接受 `"raw"`；对象形式如下：

| type | 选项 |
| --- | --- |
| tcp/raw | 无 |
| ws | path（默认 `/`）、host、headers（二元数组列表）、early_data_bytes（默认 0，上限 65536） |
| httpupgrade | path（默认 `/`）、host、headers |
| grpc | service_name（默认空）、authority、multi_mode（客户端默认 false，服务端接受 Tun/TunMulti）、user_agent / grpc-user-agent |

TLS 出站使用 `security: {type: "tls", server_name, ca_pem}`；省略名称时使用 server.host。TLS 节点使用 `security: {type: "tls", certificate_pem, private_key_pem}`，也支持分别与内联互斥的 `certificate_file`/`private_key_file`。证书与密钥文件上限各 1 MiB。不提供跳过证书校验选项。`{type: "none"}` 仅允许回环节点与服务器；客户端未提供 security 时按该限制处理。

```json
{
  "server": {"host": "127.0.0.1", "port": 14443},
  "password": "仅供测试的独立节点密码",
  "security": {"type": "tls", "server_name": "proxy.example.invalid", "ca_pem": "<测试 CA PEM>"},
  "transport": {"type": "grpc", "service_name": "tunnel", "multi_mode": false}
}
```

## 行为与资源边界

- 鉴权值为 SHA-224 小写十六进制，服务端以常量时间原语比较候选密码；认证错误关闭当前连接。配置阶段返回带协议域的认证指纹，用于拒绝跨节点复用凭据。
- 所有合法目标经注入的 `PeerSession` 访问；节点地址族与目标地址族独立。RAW、HTTPUpgrade 和 gRPC 的 TCP 路径保留半关闭后的反向读取；WS 不提供独立写端 EOF，能力中明确关闭该标记。建立成功仅表示载体与请求已发送，Trojan 不存在目标已接纳的确认帧。
- UDP 出站适配固定目标契约；节点按逐帧目标建立独立 UDP 关联，每关联占用节点与全局逻辑流预算。关联、回写队列、HTTP 消息和 gRPC 帧均有界；目标关联和读取任务随物理连接退出销毁。
- 单包长度上限为 65535 字节并受引擎 `max_datagram_size` 约束；固定 Xray 的 8192 字节总写缓冲包含地址头，实测有效负载边界为 IPv4 8181、IPv6 8169 字节；8192 字节负载不能完整回写。不能将自端大包结果登记为该对端的外部兼容。
- WS/HTTPUpgrade 升级任务由当前物理连接持有；gRPC 请求各取得逻辑流 lease，连接退出等待已创建任务，取消或空闲期限结束时回收任务。
- flow、Encryption、REALITY、XHTTP、mKCP、通用 mux、网站 fallback 及额外安全包装未提供，未知选项拒绝。

## 完成权、UDP 回写确认与节点任务契约

- TCP 使用 `TcpFlow`；底层出站 `OpenedTcp` 返回 `TcpConnectInfo::unknown()`。
- 多目标 UDP 的每个 Entry 持有唯一完成权，接收任务只持 typed 接收半部；回包和结束事件带目标代次（32 项有界回复队列），父任务在实际载体 `write_all` 与 `flush` 成功后回传私有 receipt，接收任务等待确认后才读取下一包或 EOF。父退出只保留已确认交付后的独立 End，其余目标先固定父终因，再取消和回收。上传活动不会重建正在等待的接收 future。
- HTTP 升级及 gRPC 派生任务登记到 `NodeTasks`。HTTP/2 executor 将 Hyper 的真实 future 登记到 `NodeTasks`；节点拒绝接纳时释放该 future，不退回未登记的 Tokio 任务，也不把正常关闭拒绝升级为整个 Engine 故障。
