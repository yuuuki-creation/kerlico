# 节点与统一目标访问接口

更新日期：2026-10-31。公共契约已实现并通过 worker 限定回归；完整装配按冻结快照和当前增量分别记录。

`NodeFactory` 将协议私有选项构造为 `InboundProtocol`，注册表检查节点标签、监听冲突、能力和认证指纹。IPv4、IPv6 节点分别配置；同协议跨节点认证指纹重复时拒绝整份配置。每个节点单独构造出站实例，避免带身份的连接池混用。

包装协议使用 `scoped_credential_fingerprints(default_protocol)` 返回 `ScopedCredentialFingerprint {protocol, fingerprint}`。默认将旧指纹映射到工厂协议域；有真实内层协议的包装必须保留内层域，再加入实际外层鉴权域，不能用包装 type 或版本别名绕过原生/包装节点之间的凭据查重。摘要不写日志，空或未参与认证的字段不能充当指纹。跨包装域与真实流注入共 2 项、SS 9 项及 SS2022 8 项包级回归和相关包严格 Clippy 已在 worker 通过。原 SS 夹具的 TCP/UDP 端口碰撞修正后已复验，不把该历史失败归为密码或载体问题。

额外的秘密隔离使用 `credential_isolation_fingerprints(default_protocol)`，默认委托上述分域鉴权指纹。注册表只按鉴权集合判断 `nodes` 准入；查重则合并鉴权与隔离集合，在单条目内消除两类集合的重复，再拒绝跨条目复用。隔离集合为空不能隐藏真实鉴权指纹，只有隔离秘密也不能获得公网鉴权资格。Mieru本地不安全UDP可据此阻止与TCP入口共享秘密，且继续保持空鉴权指纹、强制回环及local_inbounds限制。该新增公共契约已在 perf-02 全新六包隔离快照通过 core 2项、配置3项与流连接器2项，共7项测试，格式及严格Clippy通过；见[本轮记录](../testing/credential-isolation-contract.md)。它不代表 Mieru 等 WIP 协议实际适配已验收。

本地动态代理入口单独配置在 `local_inbounds`，沿用标签、type、listen、outbound、options 与会话限额字段。工厂必须通过 `allows_local_inbound()` 明确允许，监听强制为回环；当前 SOCKS/HTTP 和 Shadowsocks 工厂允许，后者的 none/plain 必须使用此入口。它们与所有入口共享标签、监听冲突、限额、目标访问和退出管理，但可在本机信任边界内不使用线协议认证。`nodes` 的非空独立凭据要求保持有效，不能把未参与认证的字段或空 key 哈希伪装成凭据，也不能通过更换字段把无认证入口发布到外部地址。

`InboundProtocol` 声明 TCP、UDP 或虚拟监听能力，分别实现 `handle`、`handle_udp`、`handle_virtual`。引擎只按能力绑定和调度，不按协议名称分支；IPv6 socket 设置 v6only。声明 TCP/UDP 的同一节点使用相同端口，端口为 0 时先取得实际端口再绑定另一网络。

`InboundContext` 提供取消、连接/空闲/排空预算、最大包长、最大流数、节点与全局共同约束的 `StreamBudget` 和 `NodeObserver`。新增可选的 `peer_addr`、`local_addr` 记录物理 TCP 地址，由引擎在接受连接时注入，虚拟载体和无连接入口为 None；SOCKS UDP 关联用它们校验来源，不把请求声明的地址当成真实对端。每个新增逻辑关联必须持有 lease；关闭预算后禁止新增，已有任务在排空期限内结束。节点事件同时汇总到节点统计和全局统计。

协议鉴权和解码后通过 `AccessService::connect_tcp/connect_udp` 访问目标；两个方法接收 `Destination`、`ConnectContext`，返回流或数据报通道。实际 `Egress` 实现委托给配置选定的出站。域名通过系统解析器解析、去重并优先尝试 IPv4，最多保留 32 个候选；TCP 仅在未发送业务前的连接失败中尝试下一地址，并共享总期限。UDP 选定首个候选后不重放数据报。IP 字面量保持原地址族。

节点接入地址族、代理载体地址族和网站地址族互不绑定。客户端访问 IPv6 节点后可以访问 IPv4 网站，反之亦然。当前统一的是实际访问服务；尚未实现独立 DNS 服务、路由规则或 Fake-IP。

流载体另用 `StreamConnector::connect_tcp(endpoint, context)`，endpoint 是内层配置的代理端点，网站 Destination 仍由实际代理协议编码。`tcp_eof()` 默认 false。SS/SS2022 提供 `from_options_with_connector(options, Arc<dyn StreamConnector>)`，注入后关闭原生 UDP，EOF 能力采用连接器明确声明；默认构造的行为保持。它不注册忽略网站地址的伪普通出站。协议组合在 ShadowTLS 新包内实际接线。公共回归覆盖 15 个方法/身份配置的真实载体注入、代理端点与网站目标区分、65537 字节和 EOF、UDP 不旁路及凭据域查重；ShadowTLS 外层真实对端另验。

固定目标数据报接收器增加可选 `peer_addr() -> Option<Destination>`，默认 None。它表示业务目标，不能返回代理服务器或中继的物理地址。`Egress` 在统一解析并选定首个候选后，将该字面目标随接收器提供；`net` 直连也可报告已连接的业务 peer。需要 IP 回包头的协议使用此元数据，不在协议模块重新解析域名。它不代表未来多来源 UDP 的逐包来源字段；已有 `recv`、空包及会话结束语义不变。该契约已通过 worker 包级回归与严格 Clippy，整树按冻结快照另行登记。

多目标且需要保留同一出口 socket 的路径另用 `DatagramAssociation`，不通过多个固定目标通道伪装关联。发送器 `send_to(packet, target)` 接收逐包目标；接收器 `recv_from()` 返回 `Option<(Destination, Vec<u8>)>`，分别保留业务来源和包边界。`Outbound` 与 `AccessService` 的 `associate_udp(context)` 默认拒绝，`supports_udp_association()` 默认 false；节点通过 `requires_udp_association()` 明确要求，配置阶段检查所选出口的能力。无法提供的代理出口不回退直连或固定目标通道。

`net` 直连在一个 IPv6 双栈 UDP socket 上发送两类地址，IPv4 回包地址规范化为 IPv4；不能建立该 socket 的系统在运行时返回错误。`Egress` 在每次发送前统一解析目标、优先 IPv4，共用该次发送的建立预算；只选择一个候选且不重放。单个关联的取消令牌覆盖发送和接收，完整包上限 65507 字节，空包合法。协议模块仍负责关联身份、节点 lease、关联数量、业务空闲和退出，不能在协议层绕开统一访问服务创建网站 socket。本轮公共关联与相关包级共 28 项测试和严格 Clippy 已通过；包含同端口跨目标/跨族、未联系来源、空包、取消与配置拒绝，最终整树另行登记。
