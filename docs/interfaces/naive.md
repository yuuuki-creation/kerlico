# Naive 实际接口

状态：2026-10-31，**限定双端与组合已验收并冻结，供1.0.0整树发行复验使用**。perf-03通过26项Rust、严格Clippy/fmt、限定CLI构建、156/156配置的900条常规检查及同进程双端28条检查；原参考包长与EOF限制另列。P-21；研究和完整范围见[详细研究](../../reference/research_notes/naive.md)，冻结及真实结果见[测试记录](../testing/naive.md)。本模块结果不代表1.0.0整树或发行产物已验收。

`kerlico-naive` 导出 `NaiveFactory`、`NaiveNodeFactory`，两端注册名 `naive`；根程序的可选功能为 `protocol-naive`。工厂只解析配置、构造状态，不拨号或绑定端口。业务目标只通过注入 `AccessService`，逐包多目标只用 `DatagramAssociation`。

出站示例：

```json
{
  "server":{"host":"proxy.invalid","port":443},
  "username":"node-user",
  "password":"本节点独立口令",
  "tls":{"server_name":"proxy.invalid","ca_pem":null},
  "transport":"h2",
  "udp_over_tcp":{"enabled":true,"version":2},
  "max_sessions":4,
  "max_streams":128,
  "idle_session_timeout_ms":60000,
  "congestion_control":"cubic"
}
```

节点 options：

```json
{
  "users":[{"username":"node-user","password":"本节点独立口令"}],
  "tls":{"certificate_file":"server.pem","private_key_file":"server.key"},
  "transports":["h1","h2","h3"],
  "udp_over_tcp":true,
  "congestion_control":"cubic"
}
```

`transport` 为 `h1`、`h2` 或 `h3`，默认 `h2`；节点默认三种，列表不得重复或为空。H1/H2使用TCP监听，H3使用UDP监听；同时启用时使用节点同一个配置端口的两类socket。TLS必选；H1/H2协商固定ALPN（无ALPN的H1接入也可识别），服务端优先H2；H3固定QUICv1与h3、禁用0-RTT。节点也接受 `certificate_pem` / `private_key_pem`，分别与相应文件字段互斥。出站可追加CA，默认仍启用公共根与名称校验，不提供跳过校验。

节点放在外层 `nodes`，回环Naive节点也保留TLS和凭据；本模块未注册无认证的 `local_inbounds` 模式。节点用户表须有1..256项，用户名在表内不得重复。外层 `nodes[].max_sessions` 和 `limits` 提供服务端预算；出站的 `max_sessions`、`max_streams`、`idle_session_timeout_ms` 不是节点options字段。`udp_over_tcp` 在节点是布尔值，在出站是带 `enabled` / `version` 的对象。

`congestion_control` 仅H3支持 `cubic` 或 `reno`；其他载体不接受非默认值。没有BBR、QUICv2、gQUIC、ECH、REALITY、uTLS、浏览器指纹、明文HTTP/h2c或其他通用transport/mux开关，未知字段拒绝。

标准TLS校验外，模块固定NaiveProxy v154.0.8037.49-5的109项SPKI拒绝值，包含该版本新增的八项中间证书值。检查叶及对端提供中间链，不用自有解析替代WebPKI；不是动态更新或Chrome全部证书政策。源码仅保留拒绝证书测试资产的来源、876字节大小、DER及SPKI摘要；证书未取得明确再分发许可，不随源码或产物分发。worker准备工具以正常TLS下载固定原始DER到私有目录，测试仅从 `KERLICO_TEST_ASSETS_DIR/naive/blocked-intermediate.der` 读取并校验，缺失明确失败且不联网。生产拒绝集和产品TLS不依赖该文件。

认证为每个CONNECT的Basic。用户名非空、不含冒号；用户名和密码均不含控制符，密码非空，总字节数不超过1024。秘密查重沿用现有HTTP的 `http` 域与 `SHA256(b"kerlico/http\0" + canonical Basic header)`，因此HTTP与Naive节点也不能复用同一整组凭据。TLS、版本、padding不创建新身份域。不同节点各持用户表和连接资源；认证失败直接拒绝。

前八个记录按方向独立填充，此后为原流。出站只请求padding类型1；节点处理当前 `padding-type-request` 与旧式Padding头，并明确回复1；不降级为无填充普通代理。帧中payload最大65535，padding最大255；大写入分块，解码支持零payload帧、短读、合帧与第九帧切换。HTTP DATA/TLS/QUIC读取边界不改变padding状态。

H2/H3按出站实例持有有界会话池和真实并发请求流。`max_sessions`1..128、`max_streams`1..1024、空闲会话预算100..86400000毫秒；H1每会话只有一个CONNECT，使用同一物理会话上限。服务端每个物理连接和额外逻辑请求受核心预算；停止接新流后，存量请求受排空预算。flush确认先前数据已交给编码器与载体发送层，shutdown等待编码器完成写端关闭；取消或错误关闭相应流，不重放业务数据，也不回退其他身份。GOAWAY或物理连接失败向调用方报错，旧会话退出后下次调用可新建，不自动重发CONNECT。H3接入域名解析后优先IPv4，当前只尝试首个解析地址。

`max_streams` 是H2/H3每会话的请求流上限，H1始终受协议的一流限制。静态UDP入口的本地流可能一直保留到空闲超时，物理会话上限须容纳仍活跃的H1 UDP关联；不能将多个物理H1连接称为复用。

UoT默认关闭。出站启用时版本只能1或2，默认2；固定UDP和多目标关联分别有接口。v1保留域名 `sp.udp-over-tcp.arpa`，v2为 `sp.v2.udp-over-tcp.arpa`；不允许普通 `connect_tcp` 将这两个目标当网站访问。v2支持connect固定目标与逐包模式，v1逐包模式。原sing客户端保留域名CONNECT使用端口0，节点仅对这两个域名接受并映射内部占位1；普通网站端口0拒绝，原生出站保留域名使用占位1。网站UDP包保留空包、包边界和来源；上限同时受u16帧、运行时和真实IP UDP限制。多目标使用同一远端关联socket，不按目标拆成多个固定通道。节点启用UoT时声明要求出口具备关联能力，配置准备阶段拒绝不满足的出口。

当前 `Capabilities` 为TCP=true、UDP取决于UoT、tcp_eof=false；原生实现写端EOF映射到载体写端结束并继续读，但最终目标EOF的声明要等真实对端独立验收。不能由H2/H3有END_STREAM/FIN推定所有参照的半关闭行为。

`NaiveFactory::build_with_connector(options, Arc<dyn StreamConnector>)` 只允许H1/H2；该连接器先建立代理接入字节流，Naive再在其上校验自己的TLS。H3显式拒绝此构造，不忽略注入后直连。节点网站地址族由统一目标访问服务选择，接入IPv4/IPv6不限制目标网站族。

固定forwardproxy的H1分支尽管发Padding响应头，却使用无填充流；本模块H1按sing-box的padded线格式实现，两者组合不兼容，不提供首包猜测/无填充回退。固定Caddy的H2/H3只提供TCP，不识别UoT；原官方Naive客户端的Chrome网络栈、preamble与指纹行为也不属于本模块能力。

1.0.0接口核对范围：工厂名、JSON字段与默认值、严格未知字段拒绝、Basic真实凭据域、两类UDP接口、监听与业务数据能力、EOF准入和连接器限制均与实现对齐。软件版本由workspace统一继承；外层配置 `version:1` 是项目配置模式版本，UoT的1/2是线协议版本，均不随软件发布号改写。
