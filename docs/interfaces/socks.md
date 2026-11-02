# SOCKS 接口

2026-11-02共享运行迁移已编写，尚未编译、格式检查或测试。本文保留的历史通过记录只对应原输入，不代表当前整树已验收。

配置模式为`version:2`。节点的`members`引用管理账户`user_id`，分别保存`credential_epoch`与`native_credential`。管理用户名、管理密码摘要和协议凭据互不代用。节点工厂接收`NodeBuildContext`，鉴权前只持`IngressBinding`，鉴权后使用`PeerSession`访问共享Dispatcher。

SOCKS5的每条成员凭据为`{"username":"node-user","password":"synthetic-password"}`。`options`只保留`version`和`userid`。RFC1929命中行决定管理用户；SOCKS4/4a和无认证SOCKS5只用Local，不从userid生成用户。
出站工厂通过`compile`校验配置与资产，返回一次性`OutboundPlan`；`start(ServiceContext)`才创建命名运行实例。一个Engine内每条命名出站只有一个实例，池按`ConnectContext.resource_key()`的服务、成员和凭据代次分区。持久任务登记到ServiceContext，shutdown停止并等待自身资源；单个请求或节点不关闭共享出站。使用TLS的共享出站不跨成员复用恢复票据。

本模块代理出站声明`TargetPolicy::Remote`，保留网站原目标、端口和负载。本机只解析代理接入端点，网站解析由远端负责；协议无法表达的目标明确拒绝。TCP连接与UDP关联建立后固定所选出站，不在失败后跨代理或直连重放。


日期：2026-10-31。首轮代码已编写，尚未完成 worker 编译和互通验收。

`protocol-socks` 注册 `socks` 入站节点与出站。`version` 为字符串 `4`、`4a`、`5`，默认 `5`。三版本实现 CONNECT；5 另实现 UDP Associate，4/4a 不声明 UDP。BIND、GSSAPI、UDP 分片重组不支持。

出站选项：`server: {host, port}`、`version`、可选 `auth: {username, password}`、4/4a 的可选 `userid`。节点选项只含`version`与`userid`；认证取自外层members。未知字段、版本冲突、空或超过 255 字节的认证字段拒绝。配置与凭据不写入错误消息。节点接入后通过统一 PeerSession 访问目标，不直接创建目标连接。

SOCKS5 有认证时只协商用户名密码，没有认证时只协商无认证，禁止失败后降级。认证指纹参与同协议跨节点去重。`nodes` 中的服务端仍必须有独立认证；无认证 SOCKS5 与 SOCKS4/4a 使用单独的 `local_inbounds` 数组，字段与节点相同但必须回环监听，不能注册为公网节点。userid 不是安全认证。SOCKS5 用户名密码在线路上明文传输。

SOCKS4仅接受IPv4字面目标，域名和IPv6明确拒绝；4a将域名交给代理端解析。5 支持 IPv4、IPv6 与域名，解析交给目标访问服务。接入地址族不限制目标地址族。

SOCKS5 出站根据服务端实际返回的 UDP relay 地址绑定 socket，TCP 控制地址族不限制 relay 的地址族；域名 relay 优先控制连接的地址族，没有对应地址时允许另一族。独立 IPv4 控制/IPv6 relay 回归已在 worker 通过。控制关联及目标通道的空闲时间由成功业务读写推进，非法包不续期；持续单向发送保持原目标通道，更新活动计时不取消已开始的目标接收 future。

本轮将旧的逐目标固定通道改为真实多目标关联。SOCKS5出站提供固定UDP和DatagramAssociation，SOCKS4/4a均不提供UDP。入站TCP不要求所选出站具有关联能力；收到UDP_ASSOCIATE时才检查，只有固定UDP或没有UDP的出站返回命令不支持，不把多个固定通道当成关联。

SOCKS5 UDP 由 TCP 控制连接动态创建同地址族 UDP 端口，TCP 断开即回收关联。节点依赖 InboundContext 的物理 peer_addr/local_addr 以校验 UDP 来源 IP；指定端口时固定来源端口，否则固定首个合法包的来源端口。整个控制连接只建立一个业务 UdpAssociation并固定命名出站，多个目标沿用同一关联及可信成员；负载长度、空闲、取消和关闭受现有预算限制。非零 FRAG、错误来源和无效包整包丢弃。出站提供多目标DatagramAssociation；固定目标通道是其适配，控制连接关闭后接收返回None。UDP 载荷可以为空，封装总长不得超过 65507 字节。

CONNECT 绑定元数据和未知兼容回复见本轮契约；UDP Associate 回复实际绑定地址与端口。TCP 保留写端 EOF 与反向排空。握手与目标建立各自受 connect_timeout 限制，成功后的转发受 idle_timeout 和取消约束。

研究与验收矩阵见[研究记录](../../reference/research_notes/socks.md)，实际结果见[测试记录](../testing/socks.md)。

## 完成权与节点任务契约

2026-11-02 本轮首轮编码，尚未构建、格式检查或运行验证。

业务入口返回 `TcpFlow`、`FixedUdpFlow` 或 `UdpAssociation`，拆分后唯一 `FlowCompletion` 留在实际会话 owner。字节与数据报仍只由 Dispatcher 计量，完成权只报告原因；最后 I/O、半部及完成权租约释放后才提交终态。底层出站 TCP 返回 `OpenedTcp`，本模块没有绑定证据时明确返回 `Unknown`，不以代理载体地址代填。

CONNECT 从 `TcpFlow.info()` 取得 `TargetBind`。已知绑定保留 `LocalSocket` 或 `PeerReported` 证据；未知绑定仅在线格式使用有名称的兼容零回复，内部仍是 `Unknown`，不写成网站观察地址。SOCKS4 只编码可表示的 IPv4 绑定，其他情况保留兼容占位。SOCKS5 上游真实 IPv4、IPv6、域名 BND 原样保留，零端口或未指定 IP 归为未知。UDP ASSOCIATE 继续返回实际监听地址。成功回复写失败先报告失败；TCP 控制连接正常结束为关联 `ProtocolEnd`，空闲为 `Timeout`。
