# VLESS 接口 0.2（开发中）

当前源码更新于2026-11-02，已编写共享运行与配置 v2 迁移，尚未执行本轮编译、格式、测试或互通。下文既有通过结果只属于各自历史输入，不能作为本轮验收。

节点通过 `NodeFactory::build(&NodeBuildContext)` 编译。每个 `members[]` 绑定管理 user_id、credential_epoch 和 native_credential；协议凭据与管理用户名、密码分开。原生凭据格式为 `{"uuid":"协议 UUID","flow":""}`。flow 可为空或 `xtls-rprx-vision`。

认证前只持 `IngressBinding`。真实协议校验成功后交接 `CredentialSet` 的槽与同次解码状态，经 `authenticated` 得到 `PeerSession`。每次 TCP 或 UDP 建立均由共享 Dispatcher 创建独立流归属；复用载体不会把成员或流标识混合。旧指纹接口已替换为 `CredentialManifest`，分别登记 Authentication 与 Protection。

出站使用 `OutboundFactory::compile(&Value) -> OutboundPlan`。编译完成字段、凭据与资产校验；Engine 只消费一次 `start(ServiceContext)`，构造唯一命名运行实例。此模块使用 Remote 策略，保留网站原域名/IP、端口和负载，只解析代理载体端点。远端失败不在本机更换代理、换族或回退直连。

`ConnectContext` 必须通过构造方法建立，嵌套阶段使用 `with_timeout` 收紧原期限。共享连接与票据按 `resource_key()` 的运行实例、成员与凭据代次分区。持久任务归命名服务，单个入站或请求取消不会关闭共享服务。显式 `shutdown` 停止并等待本实例任务；历史包级验证尚未覆盖新关闭路径。


更新日期：2026-10-30。本轮双向完整矩阵等快照已通过，最新共享生命周期增量尚未复验，见[快照记录](../testing/vless-combinations.md)。0.1 已发布范围及历史证据保留在[普通流记录](../testing/vless-ordinary-flow.md)；这些结果不外推本轮全部代码。

## 角色与分层

`VlessFactory` 注册出站 `vless`，`VlessNodeFactory` 注册服务端节点 `vless`。节点负责安全、VLESS 身份和协议解码，鉴权后只通过 `PeerSession` 访问业务目标。传输、安全、Encryption、Vision 和包编码分别装配，非法组合在配置阶段拒绝。最终仍是一个程序，协议通过 Cargo feature 裁剪。

节点和统一出口约定见[实际接口](node-egress.md)。每个节点拥有独立用户表、重放状态、Encryption ticket 和资源配额；IPv4、IPv6 节点不能复用 UUID。节点接入地址族不限制网站目标或上游代理载体的地址族。

## 出站配置

外层 `type=vless`，私有字段位于 `options`；未知字段拒绝。

| 字段 | 契约 |
| --- | --- |
| `server.host` / `server.port` | 节点地址与非零端口 |
| `server_family` | `auto`（默认）、`ipv4`、`ipv6`；仅筛选节点载体解析结果，不改变网站目标 |
| `uuid` | UUID，Debug 与错误隐藏身份 |
| `transport` | `tcp`/`raw` 字符串，或下表的带 `type` 对象 |
| `flow` | 空、`xtls-rprx-vision`、`xtls-rprx-vision-udp443`；后者只在客户端放开业务 UDP/443 |
| `encryption` | 默认 `none`；使用固定 Xray mlkem768x25519plus 字符串格式 |
| `security` | 默认 TLS；`tls`、`reality`、`none`，字段见下表 |
| `packet_encoding` | `udp`（默认）、`xudp`、`packetaddr`；Vision 自动使用 XUDP |
| `mux` | 可选 `{enabled,tcp,udp,concurrency,max_connections}`；默认值为 `true,true,true,8,4`，不提供对象则不建池 |

| 载体对象 | 字段与限制 |
| --- | --- |
| `{type:tcp}` | 无额外字段 |
| `{type:ws}` | `path`、`host`、`headers`、`early_data_bytes`、`heartbeat_period_secs` |
| `{type:httpupgrade}` | `path`、`host`、`headers` |
| `{type:grpc}` | `service_name`、`authority`、`multi_mode`、`idle_timeout_secs`、`health_check_timeout_secs`、`permit_without_stream`、`initial_window_size` |
| `{type:xhttp,settings:{…}}` | `path`、`host`、`mode`、`http_version`、`headers`、`no_grpc_header`、`max_post_bytes`、`min_post_interval_ms`、`max_buffered_posts`、`padding_bytes`、`download` |
| `{type:xdrive,settings:{…}}` | 专用存储载体，见下节 |

XHTTP `mode` 为 `auto`、`packet-up`、`stream-up`、`stream-one`；`http_version` 为 `auto`、`h1`、`h2`、`h3`。独立下载 `download` 包含自己的 `server`、`server_family`、`security` 和 `xhttp`，不得再嵌套下载或与 `stream-one` 并用。上下行分别解析地址、建立安全连接，保留各自 CA 和安全身份。

| 安全对象 | 字段与限制 |
| --- | --- |
| `{type:tls}` | `server_name`、`ca_pem`、`alpn`、`fingerprint`；自定义 CA 不能同时启用指纹整形；名称和证书链必须验证 |
| `{type:reality}` | `server_name`、`public_key`、`short_id`、`fingerprint`、可选 `mldsa65_verify`；指纹默认 `chrome`；只用于 RAW、gRPC、XHTTP/H2 |
| `{type:none}` | 未启用 Encryption 时仅允许回环节点地址 |

Vision 要求 RAW TLS/REALITY 或先启用 Encryption；不能用于 XDRIVE。Vision 不能复用 TCP 业务，可将 Mux 设为 `tcp:false,udp:true`。固定 Xray 对 XHTTP 也限制为 UDP Mux，本项目配置阶段拒绝 XHTTP 的 TCP Mux；TCP 使用 XHTTP 自身 XMUX。`packetaddr` 仅接受 IP 目标，不能与 Vision 或 Mux UDP 混用。Mux 并发为 1–256，物理连接为 1–32；达到上限返回资源错误，不无限排队或重放业务。

## 节点配置

节点外层包含 `tag`、`type:vless`、`listen`、`outbound`、可选 `max_sessions`。`options` 包含：

| 字段 | 契约 |
| --- | --- |
| 节点外层 `members[].native_credential` | 1–256 个 `{uuid,flow}`；不放入 options |
| `security` | 必填；`none`，或 TLS 的证书/密钥，或 REALITY 身份 |
| `transport` | 默认 TCP；对象字段见下文 |
| `decryption` | 默认 `none`；固定 Xray 服务端格式，最多 8 个密钥；暂拒绝非空自定义 padding |

TLS 使用 `certificate_pem`/`private_key_pem` 或 `certificate_file`/`private_key_file`；每种材料必须二选一，单项最大 1 MiB。REALITY 使用 `cover:{host,port}`、`private_key`、`server_names`、`short_ids`、`max_time_diff_ms`（默认 60000，最大 300000）；失败握手转发到固定 cover，不能把客户端目标当作回退地址。

节点传输对象分别为 TCP、`ws:{path,early_data_bytes}`、`httpupgrade:{path}`、`grpc:{service_name}`、`xhttp:{settings:{path,mode,http_version}}`、XDRIVE。XHTTP/H3 使用同一节点的 UDP 端口并要求 TLS；`auto` 可同时监听 TCP 与 UDP。HTTP 载体有有界队列、帧长度和会话限制。服务端接受原生 UDP、XUDP/Mux、packetaddr，各自保持包边界和目标语义。

## XDRIVE

客户端与服务端必须使用 Encryption、空 flow；客户端显式启用 TCP/UDP Mux。存储 endpoint 自行决定 HTTP 身份，禁止叠加 REALITY。服务端为虚拟监听，不绑定配置中的占位 `listen`；其 `security` 为 `none`，CA 放入存储设置。

`settings` 包含 `service`、`remote_folder`、`secrets`、可选 `template`、`s3`、`ca_pem`。服务为 `local`、`google-drive`、`template`、`s3`；S3 包含 `endpoint`、`region`、`bucket`、`path_style`。模板采用固定 Xray 的操作模板，支持 header/basic/OAuth2、预签名 URL、名称匹配和有界重试。Google Drive 包含 OAuth2 刷新、description 内联、media 与槽描述读写。

存储配置先编译为不可变计划，运行时按 ResourceKey 分别持有存储门限和 OAuth 缓存。HTTP 存储与令牌请求使用显式 Hyper HTTP/1 连接，每次操作独占连接，强制 Connection: close；不跟随重定向，保留 URL、请求头、表单与认证语义。TLS 验证名称和证书，关闭会话恢复。单次操作连同响应体和驱动结束共用60秒期限，响应体上限8 MiB。连接驱动与请求交换在同一个被拥有的 Future 中轮询，正常、错误或取消都结束真实连接，没有脱离该操作的 Hyper 任务。该新路径尚未运行互通验收。

显式设置 `ca_pem` 时，配置编译必须解析并接受至少一张证书，再加入公共根集合。空文本、只有非证书 PEM 块、损坏 PEM 或无效证书 DER 均返回 `Error::Config("XDRIVE 自定义 CA 必须包含有效证书")`。显式空值不会改用父载体提供的 CA；多证书中任意一个解析或添加失败，整项配置失败。未提供自定义 CA 时继续使用公共根。

入站每条存储会话直接拥有分段或槽环的读写驱动 Future，与载荷处理同时轮询。会话正常结束、错误或取消时先结束这些实际 Future，再报告会话完成。出站将同一读写驱动登记到命名服务的 `ServiceContext`，流释放只取消自己的驱动。节点存储发现循环的错误和取消统一停止本节点的会话子取消域，不取消其他节点或共享出站服务。

节点回收在同一个 `drain_timeout` 总期限内完成。前80%用于自然排空，随后强制取消未完成会话并在剩余期限内等待实际 JoinSet 结果；只有全部回收后才记录 `ForcedCleanup`。期限耗尽记录失败，若存在先前存储错误则保留该主要错误。上述生命周期及 CA 修订只已编写，新增回归仍待 worker 验证。

资源设置及默认值：`segment_bytes=65536`、`flush_interval_ms=20`、`poll_interval_ms=100`、`max_poll_interval_ms=2000`、`session_ttl_seconds=300`、`concurrency=4`、`eager_window_ms=1000`、`hole_timeout_ms=10000`。写端 flush 等待分段实际提交，shutdown 等待 END；读取按序号恢复并检测缺口。支持 WAL 分段，以及 Google Drive 对端公告的槽环。真实云账户互通必须另记证据，不能由本地或模拟存储通过推定。

## 流和数据报语义

`connect_tcp` 成功表示载体建立并发送请求，不能推定远端已认证或网站已连接；首次读取可能收到响应失败。失败后终止会话，不自动重放已发送字节。普通 VLESS 没有独立请求 EOF 帧；逻辑 shutdown 保留反向读取，`tcp_eof=false`。要求目标 EOF 的入口必须被能力校验拒绝。

数据报保留包边界和零长度；原生长度字段最大 65535，Mux 每帧负载上限 8192，实际对端/网络可能更小。截断、取消、错误身份或超时终止对应关联，不从残留半帧恢复。XUDP global ID 当前按物理载体内的逻辑会话处理；尚未提供跨载体迁移的全局 UDP 会话表。

`UserId`、`codec` 和 `VlessStream` 保留协议编解码接口；显式连接器扩展使用 `VlessOutbound::compile` 返回计划，再异步 `start`，不公开直接构造运行对象的入口。通用组合由工厂选择。旧 `codec` 的普通流限制不等同于节点入口的扩展解析器。

本轮未实现 mKCP、反向代理控制面、任意上游配置兼容、路由规则语言、TUN/Fake-IP；不得将本轮协议适配登记为完整 VPN 产品。已验证与待验证组合由总表和实际测试记录维护。

ML-DSA 验签、混合 NFS 链及真实云账户尚未互通验收；服务端未提供 ML-DSA 签名 seed 配置。本轮新迁移仍须完成整树远端检查。

## XDRIVE HTTP 迁移依据与差异

迁移前冻结锁的 SHA-256 为 `e6859965abca000d9870120b8ae1e814dd6269c3d088d1e277f89cae60d215ce`。锁内 reqwest 为0.12.28，反向依赖仅为 kerlico-vless，reqwest 依赖表没有 h2。固定 Git 依赖的 Cargo 清单也没有额外 reqwest 引用。reqwest 0.12.28 的 Cargo.toml 中，http2 功能明确启用可选 h2；rustls-tls、webpki 与 json 链不启用它。原工作区声明关闭默认功能，故此冻结输入没有 reqwest HTTP/2 路径；结论同时依据锁、引用关系和固定功能定义，不仅依据根声明。本轮没有运行新的依赖解析或构建。

| 原实际用法 | 新实现与差异 |
| --- | --- |
| redirect::Policy::none | 保留，302状态和响应体直接返回，不另行访问Location |
| URL与query | 继续用同一url类型解析、替换路径和query；fragment不发送到服务端；OAuth令牌URL中的userinfo仍按百分号解码生成Basic头。S3和模板业务URL原有的userinfo校验保留；S3签名、模板变量、预签名URL仍由原存储代码生成 |
| 自定义headers、basic与bearer | 保留头值与追加语义；HTTP/1操作明确发送Connection: close |
| Range、ETag | 原存储没有自动范围续传或ETag缓存；模板手工配置的这些头仍原样发送，不新增自动行为 |
| Content-Length与chunked | Hyper根据真实Full正文生成长度；响应仍支持标准长度和chunked解码；8 MiB累计限制保留 |
| OAuth刷新、JSON/XML、状态重试 | 令牌字段、过期窗口、401清缓存、429/5xx重试、JSON/XML解析保留原代码；令牌HTTP请求使用同一个受控客户端 |
| 超时和取消 | 60秒覆盖拨号、TLS、请求、完整响应和驱动结束；取消丢弃同一操作Future中的真实HTTP驱动 |
| 连接复用 | 改为每操作独占连接，不保留隐式HTTP连接池；协议Mux与命名出站实例的复用契约不变 |
| 环境代理 | 旧reqwest的ClientBuilder默认auto_sys_proxy为true并安装系统matcher；新客户端只连接显式URL，不读取HTTP(S)_PROXY或NO_PROXY。父任务已接受此差异，按显式载体与命名实例配置确定路径，不补隐式代理链，不称全部行为相同 |

对应代码测试仅已编写。尚未运行固定对端、真实云账户、异常HTTP状态或长时间回收验收。

## 完成权与节点任务契约

2026-11-02 本轮首轮编码，尚未构建、格式检查或运行验证。

业务入口返回 `TcpFlow`、`FixedUdpFlow` 或 `UdpAssociation`，拆分后唯一 `FlowCompletion` 留在实际会话 owner。字节与数据报仍只由 Dispatcher 计量，完成权只报告原因；最后 I/O、半部及完成权租约释放后才提交终态。底层出站 TCP 返回 `OpenedTcp`，本模块没有绑定证据时明确返回 `Unknown`，不以代理载体地址代填。

普通 TCP 使用 typed relay，建立后的响应首部写失败归到同一流；固定 UDP 的结束、超时与取消显式报告。Mux 的父级有界完成权表按逻辑会话及代次管理，关闭后的登记退回完成权和已固定原因，旧结果不能关闭新代次。Mux 没有方向 EOF，继续声明 `tcp_eof=false`；目标 EOF 触发本端收尾，尾部数据和整流 END 经真实 writer 确认写出后才 `ProtocolEnd`。错误 END 或 END 写失败为失败。packetaddr 与 XUDP 仍按各目标计量，父终因在清理取消前固定。XDRIVE 会话和 HTTP/3 原生驱动登记到节点任务所有者。跨物理请求的 XHTTP 表使用独立节点上下文，不捕获首个 peer 的取消、地址或租约。

Hyper HTTP/2 的 executor 同样使用 `NodeTasks` 登记真实 future；节点停止接纳后直接释放被拒绝的 future，不创建备用任务。XDRIVE 的存储会话 future 由该节点所有者持有，外层轮询 handler 中止后仍可等待真实存储读写析构。

Mux 物理载体正常 EOF 不代替逻辑 END：尚未收到 END、也未通过目标 EOF 与实际 END 写确认结束的活跃流报告 `ClosedByCaller`。已独立完成的逻辑流保持原结果；此规则不改变以控制 EOF 定义完整 UDP 关联结束的 UoT 或 SOCKS。
