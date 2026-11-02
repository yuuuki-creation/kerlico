# ShadowTLS 复合流包装接口

节点通过 `NodeFactory::build(&NodeBuildContext)` 编译。每个 `members[]` 绑定管理 user_id、credential_epoch 和 native_credential；协议凭据与管理用户名、密码分开。原生凭据格式为 直接使用 inner 协议的原生凭据对象。inner.options 只含公共方法参数；外层 password/users 继续属于 options 的载体保护材料，不授予业务用户身份。

认证前只持 `IngressBinding`。真实协议校验成功后交接 `CredentialSet` 的槽与同次解码状态，经 `authenticated` 得到 `PeerSession`。每次 TCP 或 UDP 建立均由共享 Dispatcher 创建独立流归属；复用载体不会把成员或流标识混合。旧指纹接口已替换为 `CredentialManifest`，分别登记 Authentication 与 Protection。

出站使用 `OutboundFactory::compile(&Value) -> OutboundPlan`。编译完成字段、凭据与资产校验；Engine 只消费一次 `start(ServiceContext)`，构造唯一命名运行实例。此模块使用 Remote 策略，保留网站原域名/IP、端口和负载，只解析代理载体端点。远端失败不在本机更换代理、换族或回退直连。

`ConnectContext` 必须通过构造方法建立，嵌套阶段使用 `with_timeout` 收紧原期限。共享连接与票据按 `resource_key()` 的运行实例、成员与凭据代次分区。持久任务归命名服务，单个入站或请求取消不会关闭共享服务。显式 `shutdown` 停止并等待本实例任务；历史包级验证尚未覆盖新关闭路径。


更新日期：2026-10-31。状态：只读交接；r9 的 21 项与限定检查通过，默认对端矩阵节点54/54、客户端45/54。当前本地HRR安全修复未复验，不能登记整体完成；详细终态与摘要见测试记录。

`ShadowTlsFactory` / `ShadowTlsNodeFactory` 注册 `shadowtls`。它们只构造带真实内层的复合路径，不提供忽略网站目标的裸 Outbound。客户端的内层继续编码 `connect_tcp` 传入的 Destination，StreamConnector 只连接内层配置的代理 endpoint；节点解包后直接调用内层 `handle`，网站访问始终经过注入的 PeerSession。没有新增本地回环中转或外部内核业务子进程。

## 客户端配置

```json
{
  "version": 3,
  "password": "outer-test-only-token",
  "strict": true,
  "tls": {
    "server_name": "camouflage.example.invalid",
    "ca_pem": "<测试 CA PEM>",
    "version": "1.3",
    "alpn": ["http/1.1"]
  },
  "inner": {
    "type": "ss2022",
    "options": {
      "server": "127.0.0.1",
      "port": 14443,
      "method": "2022-blake3-aes-128-gcm"
    }
  }
}
```

地址只在 `inner.options.server/port` 保存一份；它是 ShadowTLS 接入地址。网站目标不从这里读取，也不因包装而丢失。SS2022 的 key/identity_keys 和 Shadowsocks 的 password 按各自原接口解释。

| 字段 | 行为 |
| --- | --- |
| version | 必填 1、2、3；不静默选版本 |
| password | v2/v3 非空、最多 4096 UTF-8 字节；v1 禁止，避免假认证字段 |
| strict | 只允许 v3；默认 true，要求 TLS1.3；显式 false 允许兼容 TLS1.2 |
| tls.server_name | 必填，正常验证证书与名称，不提供 insecure |
| tls.ca_pem | 可选，提供时只信任此 PEM 根，最多 1 MiB；省略使用公共根 |
| tls.version | auto（默认）、1.2、1.3；v1 固定 1.2；v3 strict 与 1.2 冲突时拒绝 |
| tls.alpn | 默认 http/1.1，最多 16 项，各 1–255 字节 |
| inner | 必填 `{type,options}`，仅 shadowsocks 的全部 10 个 AEAD 方法或 ss2022 三方法；保留其现有认证/EIH 配置 |

所有版本在握手后都不通过真实 TLS 加密业务。v3 的持续 4 字节截短 HMAC 和 v2 切换 HMAC 不等于内容加密，不能允许 none/legacy 或无内容保护的裸内层。UDP、UDP 关联及 tcp_eof 能力均为 false；原生 UDP 明确拒绝，不能绕过连接器。

## 节点配置

```json
{
  "version": 3,
  "strict": true,
  "users": [{"password": "outer-test-only-token"}],
  "handshake": {"host": "127.0.0.1", "port": 14444},
  "handshake_for_server_name": {
    "alternate.example.invalid": {"host": "127.0.0.1", "port": 14445}
  },
  "inner": {
    "type": "ss2022",
    "options": {
      "method": "2022-blake3-aes-128-gcm",
      "key": "<独立测试用标准 Base64 key>"
    }
  }
}
```

`handshake` 是必须显式配置的伪装 TLS 站点，不是网站出口。v2/v3 可按最多 32 个小写规范域名精确匹配 `handshake_for_server_name`，未匹配使用默认目标；不允许按任意客户端 SNI 自动拨号。v1 禁止此映射。

v2 仅用单个 password；v3 用 password 或 users，互斥，最多 256 个非空且独立的密码。v1 禁止 password/users 认证材料，节点身份完全由实际认证的 AEAD 内层提供。包装节点使用同一 NodeBuildContext 签发者构造内层，并通过 credential_manifest 继承内层 Authentication；v2/v3 的外层密码只登记为 Protection；版本别名不分域。原生 SS 与包装 SS 共用实际凭据时，配置阶段仍应拒绝。

节点只监听 TCP；内层原生 UDP 监听与虚拟载体均关闭。握手帧数最多 256、总记录字节最多 1 MiB，并受节点 connect_timeout 约束；成功切换后沿用内层空闲、取消、排空和全局/节点预算。未认证探测只允许回退到配置的握手站点，不调用网站 PeerSession。

## 记录与 EOF

TCP 任意拆分/合并不改变记录边界，部分记录在取消一次读操作后仍保存。业务记录最大纯负载 16384，接收 TLS-like 记录按 u16 字段最多 65535 字节（不把它误当实际 TLS 加密记录的长度限制）；半条记录 EOF 为错误，完整边界 EOF/Alert 与业务内容分开。记录桥队列有界，flush/shutdown 等待实际载体写出。流丢弃会中止桥任务，真实退出由节点或命名出站服务所有者等待，不能把 Drop 中的 abort 当成 join。

本轮记录桥将明确取消与普通I/O错误分别保存。取消通过`ConnectionAborted`及`Error::Cancelled`来源返回，完整读写方法能够结束；普通连接中止仍保留失败分类。V2/V3记录桥`read_exact`、`write_all`的取消行为有回归测试。

v2 保留真实 TLS session 以过滤晚到握手记录，首次非 TLS 业务记录后不再尝试恢复到 TLS；v3 验证并丢弃残留握手 HMAC 记录，首次真实服务端业务记录后停止握手分支。HMAC 失败不交付部分内容；错误状态通过 I/O 错误传回内层，不能伪装成干净 EOF。客户端禁用 resumption/0-RTT；首次 ClientHello 必须完整位于一条 TLS 记录，TCP 拆分不受此限制。

通用 tcp_eof=false，是对已知对端差异的保守能力声明。自端 FIN 行为和真实对端观察分别记录，不能从 TLS-like Alert 推断通用半关闭保证。协议不提供隐蔽性、抗封锁效果或吞吐保证。

固定来源、各版本弱点与首轮范围见[调研](../../reference/research_notes/shadowtls.md)，实际验证状态见[测试记录](../testing/shadowtls.md)。

## 完成权与节点任务契约

2026-11-02 本轮首轮编码，尚未构建、格式检查或运行验证。

业务入口返回 `TcpFlow`、`FixedUdpFlow` 或 `UdpAssociation`，拆分后唯一 `FlowCompletion` 留在实际会话 owner。字节与数据报仍只由 Dispatcher 计量，完成权只报告原因；最后 I/O、半部及完成权租约释放后才提交终态。底层出站 TCP 返回 `OpenedTcp`，本模块没有绑定证据时明确返回 `Unknown`，不以代理载体地址代填。

外层继续只提供载体保护，真实业务 flow 与绑定元数据由内层 Shadowsocks 或 SS2022 返回。不为同一业务再造完成权或计量；cover fallback 使用明确的 `relay_streams`，不创建用户网站 FlowRecord。

记录桥内部区分 `Node(NodeTasks)` 与 `Service(ServiceContext)`。入站使用实际节点所有者；出站编译不创建任务，一次性 `OutboundPlan.start` 将 connector 与内层协议绑定到同一个服务所有者，不从首个请求推导身份，也不构造第二个内层出站。重复绑定或任务接纳失败显式返回错误，不退回未登记的 spawn。桥同时观察请求与所属节点/服务的取消；真实 socket 析构及关闭后拒绝新桥的回归已编写、待验证。
