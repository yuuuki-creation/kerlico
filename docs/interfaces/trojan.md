# Trojan 双端接口

更新日期：2026-10-31。状态：限定双端范围已在 perf-02 构建并通过 Rust 测试及固定 Xray 双向矩阵；其他扩展不继承该结果。

`TrojanFactory`、`TrojanNodeFactory` 分别注册 `trojan` 出站与节点。客户端、服务端均提供 TCP CONNECT 与 UDP ASSOCIATE；UDP 通过流载体封装，不声明原生 UDP 监听。

## 配置

出站选项为 `server: {host, port}`、`password`、`transport` 和 `security`。节点选项为 `password` 或互斥的 `passwords` 列表、`transport` 和必填 `security`。密码非空、最长 4096 字节，节点最多 256 个且不能重复。

`transport` 默认为 `"tcp"`，也接受 `"raw"`；对象形式如下：

| type | 选项 |
| --- | --- |
| tcp/raw | 无 |
| ws | path（默认 `/`）、host、headers（二元数组列表）、early_data_bytes（默认 0，上限 65536） |
| httpupgrade | path（默认 `/`）、host、headers |
| grpc | service_name（默认空）、authority、multi_mode（客户端默认 false，服务端接受 Tun/TunMulti） |

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

- 鉴权值为 SHA-224 小写十六进制，服务端按常量时间比较所有本节点密码；认证错误关闭当前连接。配置阶段返回带协议域的认证指纹，用于拒绝跨节点复用凭据。
- 所有合法目标经注入的 `AccessService` 访问；节点地址族与目标地址族独立。RAW、HTTPUpgrade 和 gRPC 的 TCP 路径保留半关闭后的反向读取；WS 不提供独立写端 EOF，能力中明确关闭该标记。建立成功仅表示载体与请求已发送，Trojan 不存在目标已接纳的确认帧。
- UDP 出站适配固定目标契约；节点按逐帧目标建立独立 UDP 关联，每关联占用节点与全局逻辑流预算。关联、回写队列、HTTP 消息和 gRPC 帧均有界；目标关联和读取任务随物理连接退出销毁。
- 单包长度上限为 65535 字节并受引擎 `max_datagram_size` 约束；固定 Xray 的 8192 字节总写缓冲包含地址头，实测有效负载边界为 IPv4 8181、IPv6 8169 字节；8192 字节负载不能完整回写。不能将自端大包结果登记为该对端的外部兼容。
- WS/HTTPUpgrade 升级任务由当前物理连接持有；gRPC 请求各取得逻辑流 lease，连接退出等待已创建任务，取消或空闲期限结束时回收任务。
- flow、Encryption、REALITY、XHTTP、mKCP、通用 mux、网站 fallback 及额外安全包装未提供，未知选项拒绝。没有实现原版的网站 fallback，不宣称其探测伪装行为。

协议依据与后续组合见[调研](../../reference/research_notes/trojan.md)，真实验证结果见[测试记录](../testing/trojan.md)。
