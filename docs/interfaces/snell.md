# Snell 双端接口

当前源码更新于2026-11-02，已编写共享运行与配置 v2 迁移，尚未执行本轮编译、格式、测试或互通。下文既有通过结果只属于各自历史输入，不能作为本轮验收。

节点通过 `NodeFactory::build(&NodeBuildContext)` 编译。每个 `members[]` 绑定管理 user_id、credential_epoch 和 native_credential；协议凭据与管理用户名、密码分开。原生凭据格式为 `{"psk":"协议 PSK","userkey":"可选原生 userkey"}`。unsafe-raw 必须提供非空 userkey。

认证前只持 `IngressBinding`。真实协议校验成功后交接 `CredentialSet` 的槽与同次解码状态，经 `authenticated` 得到 `PeerSession`。每次 TCP 或 UDP 建立均由共享 Dispatcher 创建独立流归属；复用载体不会把成员或流标识混合。旧指纹接口已替换为 `CredentialManifest`，分别登记 Authentication 与 Protection。

出站使用 `OutboundFactory::compile(&Value) -> OutboundPlan`。编译完成字段、凭据与资产校验；Engine 只消费一次 `start(ServiceContext)`，构造唯一命名运行实例。此模块使用 Remote 策略，保留网站原域名/IP、端口和负载，只解析代理载体端点。远端失败不在本机更换代理、换族或回退直连。

`ConnectContext` 必须通过构造方法建立，嵌套阶段使用 `with_timeout` 收紧原期限。共享连接与票据按 `resource_key()` 的运行实例、成员与凭据代次分区。持久任务归命名服务，单个入站或请求取消不会关闭共享服务。显式 `shutdown` 停止并等待本实例任务；历史包级验证尚未覆盖新关闭路径。


更新日期：2026-10-31。状态：限定范围及 UDP 双向包长约束已在 perf-02 通过检查、独立向量和固定 sing-box 双向验收；其他角色和扩展不继承结果。

`SnellFactory` 注册 `snell` 出站，`SnellNodeFactory` 注册 `snell` 节点。角色范围为出站 v4、节点 v5、v6 双端；v4 客户端与 v5 节点采用普通兼容线格式，未实现 v5 QUIC Proxy Mode。v1–v3 与其他版本方向明确拒绝。

## 配置

出站必填 `server: {host,port}`、`version`、`psk`；可选 `userkey`、`reuse`（默认 false）、`obfs_mode`（none/http，默认 none）、`obfs_host`、`obfs_uri`。节点 options 必填 `version`，可选同名 mode/obfs 选项；成员凭据分别保存 psk 与可选 userkey。节点 userkey 不允许空或重复，最多 256 个，每个最多 255 UTF-8 字节。单 PSK 节点不将 client-id 当成额外身份凭据。

v6 专用 `mode` 为 default（默认）、unshaped、unsafe-raw；v6 拒绝 HTTP obfs 及其参数，PSK 必须为 12–255 字节。v4/v5 拒绝 mode。HTTP obfs 默认 host 为 `bing.com`、URI 为 `/`；它不是 WebSocket 或 TLS，不宣称与原始发行程序有完全相同的 HTTP 指纹。

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

原语、版本和依据见[调研](../../reference/research_notes/snell.md)，执行结果见[测试记录](../testing/snell.md)。

## 完成权与节点任务契约

2026-11-02 本轮首轮编码，尚未构建、格式检查或运行验证。

业务入口返回 `TcpFlow`、`FixedUdpFlow` 或 `UdpAssociation`，拆分后唯一 `FlowCompletion` 留在实际会话 owner。字节与数据报仍只由 Dispatcher 计量，完成权只报告原因；最后 I/O、半部及完成权租约释放后才提交终态。底层出站 TCP 返回 `OpenedTcp`，本模块没有绑定证据时明确返回 `Unknown`，不以代理载体地址代填。

每次逻辑 CONNECT 使用独立 `TcpFlow`，成功应答失败先报告，顺序复用不会共用一个完成权。UDP Entry 持完成权和发送半部，接收结果及回包带目标代次；缺失或非法业务来源先报告失败。父级终止先处理已完成结果，再固定活跃目标原因，最后取消并等待任务。上传活动不丢弃正在等待的接收 future。

## 本轮审阅修复，待 worker 验证

UDP 目标回包先进入有界队列，父任务在实际记录写入与 `flush` 成功后回传私有 receipt。接收任务等待确认后才读取下一包或 EOF，未交付回包不能生成正常 End。失去写入所有者时不再发送可覆盖父失败的取消 End。父退出只保留已确认交付后的独立 End，其余目标先固定父终因，再取消和回收。代次、32 项回复队列与原目标容量保持。

本节实现与新增回归已写入独立修复树，未运行构建、格式、静态检查、单元或互通测试。历史结果不适用于本轮输入，不能据此登记验收通过。
