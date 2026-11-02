# Trojan 双端接口

当前源码更新于2026-11-02，已编写共享运行与配置 v2 迁移，尚未执行本轮编译、格式、测试或互通。下文既有通过结果只属于各自历史输入，不能作为本轮验收。

节点通过 `NodeFactory::build(&NodeBuildContext)` 编译。每个 `members[]` 绑定管理 user_id、credential_epoch 和 native_credential；协议凭据与管理用户名、密码分开。原生凭据格式为 `{"password":"协议密码"}`。

认证前只持 `IngressBinding`。真实协议校验成功后交接 `CredentialSet` 的槽与同次解码状态，经 `authenticated` 得到 `PeerSession`。每次 TCP 或 UDP 建立均由共享 Dispatcher 创建独立流归属；复用载体不会把成员或流标识混合。旧指纹接口已替换为 `CredentialManifest`，分别登记 Authentication 与 Protection。

出站使用 `OutboundFactory::compile(&Value) -> OutboundPlan`。编译完成字段、凭据与资产校验；Engine 只消费一次 `start(ServiceContext)`，构造唯一命名运行实例。此模块使用 Remote 策略，保留网站原域名/IP、端口和负载，只解析代理载体端点。远端失败不在本机更换代理、换族或回退直连。

`ConnectContext` 必须通过构造方法建立，嵌套阶段使用 `with_timeout` 收紧原期限。共享连接与票据按 `resource_key()` 的运行实例、成员与凭据代次分区。持久任务归命名服务，单个入站或请求取消不会关闭共享服务。显式 `shutdown` 停止并等待本实例任务；历史包级验证尚未覆盖新关闭路径。


更新日期：2026-10-31。状态：限定双端范围已在 perf-02 构建并通过 Rust 测试及固定 Xray 双向矩阵；其他扩展不继承该结果。

`TrojanFactory`、`TrojanNodeFactory` 分别注册 `trojan` 出站与节点。客户端、服务端均提供 TCP CONNECT 与 UDP ASSOCIATE；UDP 通过流载体封装，不声明原生 UDP 监听。

## 配置

出站选项为 `server: {host, port}`、`password`、`transport` 和 `security`。节点 options 为 `transport` 和必填 `security`，密码位于 `members[].native_credential.password`。密码非空、最长 4096 字节，节点最多 256 个且不能重复。

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

- 鉴权值为 SHA-224 小写十六进制，服务端以常量时间原语比较候选密码；认证错误关闭当前连接。配置阶段返回带协议域的认证指纹，用于拒绝跨节点复用凭据。
- 所有合法目标经注入的 `PeerSession` 访问；节点地址族与目标地址族独立。RAW、HTTPUpgrade 和 gRPC 的 TCP 路径保留半关闭后的反向读取；WS 不提供独立写端 EOF，能力中明确关闭该标记。建立成功仅表示载体与请求已发送，Trojan 不存在目标已接纳的确认帧。
- UDP 出站适配固定目标契约；节点按逐帧目标建立独立 UDP 关联，每关联占用节点与全局逻辑流预算。关联、回写队列、HTTP 消息和 gRPC 帧均有界；目标关联和读取任务随物理连接退出销毁。
- 单包长度上限为 65535 字节并受引擎 `max_datagram_size` 约束；固定 Xray 的 8192 字节总写缓冲包含地址头，实测有效负载边界为 IPv4 8181、IPv6 8169 字节；8192 字节负载不能完整回写。不能将自端大包结果登记为该对端的外部兼容。
- WS/HTTPUpgrade 升级任务由当前物理连接持有；gRPC 请求各取得逻辑流 lease，连接退出等待已创建任务，取消或空闲期限结束时回收任务。
- flow、Encryption、REALITY、XHTTP、mKCP、通用 mux、网站 fallback 及额外安全包装未提供，未知选项拒绝。没有实现原版的网站 fallback，不宣称其探测伪装行为。

协议依据与后续组合见[调研](../../reference/research_notes/trojan.md)，真实验证结果见[测试记录](../testing/trojan.md)。

## 完成权与节点任务契约

2026-11-02 本轮首轮编码，尚未构建、格式检查或运行验证。

业务入口返回 `TcpFlow`、`FixedUdpFlow` 或 `UdpAssociation`，拆分后唯一 `FlowCompletion` 留在实际会话 owner。字节与数据报仍只由 Dispatcher 计量，完成权只报告原因；最后 I/O、半部及完成权租约释放后才提交终态。底层出站 TCP 返回 `OpenedTcp`，本模块没有绑定证据时明确返回 `Unknown`，不以代理载体地址代填。

TCP 使用 `TcpFlow`。多目标 UDP 的每个 Entry 持有唯一完成权，接收任务只持 typed 接收半部；回包和结束事件带目标代次，按队列顺序处理。父级退出先消费已到达的独立结果，再报告仍活跃目标的终因，之后取消并等待任务。上传活动不会重建正在等待的接收 future。HTTP 升级及 gRPC 派生任务登记到节点所有者。

HTTP/2 executor 也将 Hyper 的真实 future 登记到 `NodeTasks`；节点拒绝接纳时释放该 future，不退回未登记的 Tokio 任务，也不把正常关闭拒绝升级为整个 Engine 故障。

## 本轮审阅修复，待 worker 验证

UDP 目标回包先进入有界队列，父任务在实际载体 `write_all` 与 `flush` 成功后回传私有 receipt。接收任务等待确认后才读取下一包或 EOF，未交付回包不能生成正常 End。失去写入所有者时不再发送可覆盖父失败的取消 End。父退出只保留已确认交付后的独立 End，其余目标先固定父终因，再取消和回收。代次、32 项回复队列与原目标容量保持。

本节实现与新增回归已写入独立修复树，未运行构建、格式、静态检查、单元或互通测试。历史结果不适用于本轮输入，不能据此登记验收通过。
