# VMess AEAD 双端接口

当前源码更新于2026-11-02，已编写共享运行与配置 v2 迁移，尚未执行本轮编译、格式、测试或互通。下文既有通过结果只属于各自历史输入，不能作为本轮验收。

节点通过 `NodeFactory::build(&NodeBuildContext)` 编译。每个 `members[]` 绑定管理 user_id、credential_epoch 和 native_credential；协议凭据与管理用户名、密码分开。原生凭据格式为 `{"uuid":"协议 UUID"}`。

认证前只持 `IngressBinding`。真实协议校验成功后交接 `CredentialSet` 的槽与同次解码状态，经 `authenticated` 得到 `PeerSession`。每次 TCP 或 UDP 建立均由共享 Dispatcher 创建独立流归属；复用载体不会把成员或流标识混合。旧指纹接口已替换为 `CredentialManifest`，分别登记 Authentication 与 Protection。

出站使用 `OutboundFactory::compile(&Value) -> OutboundPlan`。编译完成字段、凭据与资产校验；Engine 只消费一次 `start(ServiceContext)`，构造唯一命名运行实例。此模块使用 Remote 策略，保留网站原域名/IP、端口和负载，只解析代理载体端点。远端失败不在本机更换代理、换族或回退直连。

`ConnectContext` 必须通过构造方法建立，嵌套阶段使用 `with_timeout` 收紧原期限。共享连接与票据按 `resource_key()` 的运行实例、成员与凭据代次分区。持久任务归命名服务，单个入站或请求取消不会关闭共享服务。显式 `shutdown` 停止并等待本实例任务；历史包级验证尚未覆盖新关闭路径。


日期：2026-10-31。状态：限定双端已通过远端包级检查及真实对端矩阵，精确范围见[验证记录](../testing/vmess.md)。工厂类型均为 `vmess`，客户端与服务端分别注册。

## 客户端

```json
{
  "server": {"host": "127.0.0.1", "port": 10443},
  "uuid": "00000000-0000-4000-8000-000000000001",
  "security": "aes-128-gcm",
  "tls": {"type": "tls", "server_name": "node.invalid", "ca_pem": "PEM 内容"},
  "transport": {"type": "tcp"},
  "chunk_masking": true,
  "global_padding": true,
  "authenticated_length": false,
  "no_termination_signal": false
}
```

`security` 接受 `auto`、`aes-128-gcm`、`chacha20-poly1305`；当前 `auto` 明确选择 AES-128-GCM。它是 VMess 内容算法，外层安全由 `tls` 配置，缺省为 `{"type":"none"}`。TLS 始终校验证书和名称，不提供 insecure 开关。未识别字段、非法 UUID、未知 cipher 和 padding 未启用 mask 均拒绝。

`transport` 缺省为 `{"type":"tcp"}`，另有 `{"type":"ws","path":"/proxy","host":"node.invalid"}`、`{"type":"httpupgrade","path":"/proxy"}`、`{"type":"grpc","service_name":"proxy","authority":"node.invalid","multi_mode":false}`。WS/HTTPUpgrade 使用 H1，gRPC 使用 H2。Xray 两方向已验证这些载体与 none/TLS、两种 cipher 的限定矩阵；sing-box 目前仅登记 RAW 真实互通。

建立预算覆盖载体建立与请求头发送。返回流时服务端响应头仍延迟校验，不能据此声称目标已接纳。每个会话有独立随机 key/IV 和计数器；耗尽后结束，禁止复用 nonce。

## 服务端

```json
{
  "security": {"type": "tls", "certificate_file": "node.crt", "private_key_file": "node.key"},
  "transport": {"type": "tcp"}
}
```

此示例是公共 options，协议 UUID 分别放入节点成员的 native_credential。用户数为 1–256，节点内重复 UUID 拒绝，跨同协议节点的凭据指纹由注册表拒绝。IPv4/IPv6 节点各自配置，不回退认证。TLS 证书与密钥可分别使用 `certificate_pem`、`private_key_pem` 内存值，内存与文件选项互斥，文件上限 1 MiB。

认证要求 AEAD 版本 1、合法 FNV1a、合法地址/端口与内容算法；AuthID 时差限 ±120 秒，AuthID 及用户/key/IV 会话身份分别防重放。节点有界缓存最多保留 65536 项，每项保留 300 秒；满额时拒绝新请求，不淘汰仍有效项。目标访问发生在认证之后，通过注入的 `PeerSession`；节点入口地址族不决定网站地址族。

## 数据能力与边界

TCP 默认支持写端终止记录和继续读取反向数据；开启 `no_termination_signal` 后不声明目标 EOF 能力。UDP 为 VMess command 2 的固定目标记录，不是物理 UDP 监听；每次 send/read 保留一个包，本模块上限 65456 字节；真实对端实测范围为 Xray 17/1200 字节、sing-box 17/1200/12000 字节，另测的 Xray 12000/65000 字节及 sing-box 65000 字节未通过整包互通。空包与终止记录无法区分，因此发送空包明确报错。服务端另遵守引擎 `max_datagram_size`。数据报发送中被取消后，该写端失效，不重新发送可能已经发出部分的记录。

本轮不提供旧 MD5/alterId、CFB/none/zero、Vision、VLESS Encryption、REALITY、XHTTP、mKCP、旧 h2/http、QUIC transport、Mux/XUDP，未知选项拒绝；这些仍属于尚未交付范围。节点协议只声明 TCP 监听，由载体承载流与包。

## 完成权与节点任务契约

2026-11-02 本轮首轮编码，尚未构建、格式检查或运行验证。

业务入口返回 `TcpFlow`、`FixedUdpFlow` 或 `UdpAssociation`，拆分后唯一 `FlowCompletion` 留在实际会话 owner。字节与数据报仍只由 Dispatcher 计量，完成权只报告原因；最后 I/O、半部及完成权租约释放后才提交终态。底层出站 TCP 返回 `OpenedTcp`，本模块没有绑定证据时明确返回 `Unknown`，不以代理载体地址代填。

TCP 直接传递 `TcpFlow`；command2 UDP 拆分 typed 半部，保留同时收发和非空数据报限制，完整会话结束、外层读写错误、空闲与取消分别报告。HTTP 派生任务登记到 `NodeTasks`，NodeTasks 不替代原物理 peer 的取消和额度。

HTTP/2 executor 将 Hyper 的真实 future 登记到同一节点所有者；节点停止接纳后释放该 future，不创建未登记的备用任务。原物理连接的取消与租约仍由各请求上下文保留。
