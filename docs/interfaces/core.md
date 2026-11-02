# 核心接口

更新日期为2026-11-02。本文描述完成权补齐波的源码契约，完整首轮已写齐并冻结，尚未对本输入执行构建或测试。旧共享运行输入的检查和失败记录见STATUS，不能替代这一输入的验收。

本轮核心审阅修复补齐分离TCP半部的取消等待，以及共享服务与EgressRuntime中断关闭后的任务、期限和报告保存。新增回归已编写，尚待海外worker统一构建和执行，不能据以下契约登记验证通过。

## 运行装配

`Registry::prepare(Config)`只校验v2配置、编译原生凭据和证书等资产，返回不可克隆的`PreparedConfig`。`OutboundFactory::compile`返回`OutboundPlan`，其中保存能力、`TargetPolicy`和一次性启动闭包。此时没有运行后端、监听器、网络任务或设备操作。

`Engine::bind`消费计划，只创建一个`EgressRuntime`和一个私有Dispatcher。每个命名计划调用一次`start(ServiceContext)`，随后绑定全部监听器。节点只存入站协议、监听和限额，不持有Outbound；固定转发也使用同一Dispatcher。应用不能取得可修改的运行出站表。

## 身份与访问

| 类型或接口 | 契约 |
| --- | --- |
| `UserId` | 持久管理UUID，与协议UUID、用户名和密码分别处理 |
| `CredentialIssuer` | 配置装配建立的节点签发者，带配置代次、成员凭据代次及单次运行绑定 |
| `CredentialSet<C>` | 原生候选与不透明成员槽；验证必须恰好命中一行，歧义拒绝 |
| `Verified<T>` | 同一次真实鉴别的成员与已解码状态，字段私有 |
| `IngressBinding` | 节点的鉴别入口；没有目标拨号方法 |
| `IngressBinding::authenticated` | 校验签发者、节点、运行及代次后返回`PeerSession`与解码状态 |
| `IngressBinding::local` | 仅显式Local入口可签发Local来源，不生成管理用户 |
| `PeerSession` | 唯一业务访问句柄，绑定可信来源、观测来源地址及节点取消域 |
| `OriginalTarget` | 分开保存经过校验的目标和安全原表示；旧Destination调用保留规范化表示 |
| `CredentialManifest` | 一份配置隔离清单，将Authentication成员槽与Protection分开；摘要不用于运行鉴别 |

旧`AccessService`及三套指纹方法已从公共trait删除。协议完成真实线格式验证后才能取得peer，不能按网络自报的用户名或UUID构造可信用户。异步库适配从库成功鉴别的实际槽交接Verified。SS2022的EIH终端用户与服务端外层身份分别处理。

`IngressBinding::stop_admission`不可逆且幂等，停止该运行绑定的新peer及TCP流、固定UDP流和多目标UDP关联的创建。`local`、`authenticated`与Dispatcher的route都复核同一状态，已有PeerSession不能绕过。成功route中的admission读取是请求准入线性化点；先于关闭的并发操作属于已接纳操作，继续由原节点任务所有者持有并在同一关闭预算内收尾。关闭后开始的三种open拒绝且不开新账本。该状态不取消已有I/O、peer或共享服务，新运行实例拥有自己的新绑定。

准入单位是TCP流、固定UDP流和多目标UDP关联的创建。已接纳UdpAssociation的send_to仍可访问多个目标，包含首次发送的目标，保留Full Cone语义。它仍受原出站、限额、取消域和关闭deadline约束，不能脱离原owner新开关联或延长排空。此细化没有新增目标容量。

## 数据与计量

`PeerSession::connect_tcp/connect_udp/associate_udp`分别返回`FlowOpen<TcpFlow>`、`FlowOpen<FixedUdpFlow>`和`FlowOpen<UdpAssociation>`。`open_tcp/open_udp`接收OriginalTarget并返回对应`FlowOpen`。它实现`Future`，现有`.await`仍取得相同的三类业务结果。结果不可克隆，不能提取裸通道；`into_parts`移交受计量I/O及唯一`FlowCompletion`。UDP发送、接收半部独立，允许一边等待接收一边发送；空包是一次数据报，None才表示整会话结束。

当前Dispatcher通过`FlowOpen::deferred`在首次poll执行准入、选路和账本建立。此装配尚未poll就调用`finish(outcome)`或释放时，不调用工厂、不启动后端且不生成记录；创建后停止准入、随后才poll的操作仍被拒绝。该惰性建账保证不适用于所有公开构造方式。

进入Opening后，`FlowOpen`持有该请求唯一完成权。`finish(self, outcome)`先调用报告回调，再释放真正的建立future；错误返回保留原错误并报告对应终因；成功则把同一个完成权移入返回流。普通Drop与panic沿用完成权兜底规则，不伪造成功。调用方若拥有逻辑请求child token，须先报告再取消该token；`FlowOpen`不取消可能被其他请求复用的外部上下文。

`SessionDispatcher`的三个方法也返回`FlowOpen`。跨crate装配使用公开的`deferred`、`tcp`、`fixed_udp`和`association`构造器，它们是可信调度器实现边界，不是Rust私有friend能力。typed构造器直接进入Opening，接收调用方提供的I/O future及一次性报告回调。调用方可以已经建立自己的账本，尚未poll的typed操作被finish或释放时也会报告。构造器本身不授予用户身份，不查找其他会话，也不创建账本。实际用户、节点、命名出站和FlowLease继续由Dispatcher绑定；协议业务通过PeerSession取得当前请求。该接口及建立期回归已编写，尚待本输入海外验证。

| 返回类型 | 拆分结果 |
| --- | --- |
| `TcpFlow` | `TcpFlowIo`、`FlowCompletion` |
| `FixedUdpFlow` | `FixedUdpSender`、`FixedUdpReceiver`、`FlowCompletion` |
| `UdpAssociation` | `AssociationSender`、`AssociationReceiver`、`FlowCompletion` |

完成权先报告`FlowOutcome`，随后才能触发清理取消、abort或释放。TCP双向EOF使用`DuplexEof`，协议定义的整会话正常结束使用`ProtocolEnd`；超时、取消和失败分别使用`Failed(FlowFailure)`，不能从任意`Ok(())`推导完成。报告只固定原因，最后I/O半部、待交付数据及完成权租约释放后才提交终态；之前记录仍为active。先观察到的失败优先，固定原因后清理错误不改写历史。未报告的普通释放用`ClosedByCaller`兜底，panic展开用`Failed(FlowFailure::Failed)`兜底，均不保证对端收到全部数据。

真实FlowLease仍处于Opening且尚无已知失败时，`ProtocolEnd`必须复核请求、peer、节点和命名服务四个真实取消域。任一域已取消就固定Cancelled，即使建立future尚未再次poll。后端成功后账本已离开Opening，此建立期规则不覆盖已交付流的独立ProtocolEnd；已有first_failure或Closing终因也不被后来取消改写。公开回调先于future析构的回归和三类真实账本回归已编写，尚待海外验证。

`relay_tcp(front, TcpFlow, idle, cancel)`持完成权执行双向转发。父载体表持权时，子任务可用`relay_tcp_io(front, &mut TcpFlowIo, idle, cancel)`，父级仍须报告真实结果。`relay_streams`只用于原始载体、掩护与底层测试，不用于业务访问返回值。HTTP普通请求直到响应body和目标driver结束后结算，响应头不是完成证据；多目标父级关闭先固定各活跃流原因，再取消和回收任务。

底层`Outbound::connect_tcp`与`DeviceNetwork::connect_tcp`返回`OpenedTcp { stream, info }`。`TcpConnectInfo`保存`TargetBind::Known { endpoint, evidence }`或`Unknown`，证据为`LocalSocket`或`PeerReported`。原生直连在擦除socket类型前读取真实绑定，上游SOCKS保留其实际BND报告；其他无可靠线证据的代理明确Unknown。占位、不确定地址和零端口不能冒充已知绑定，不能用代理端点、carrier本地地址、入站监听或网站地址代填。FlowRecord的target_bind与observed_target独立，未知不触发额外DNS。

Dispatcher只包装一次业务I/O。TCP按成功读交付和成功写的实际字节数累计，Pending、失败、EOF、flush和shutdown不增加字节。UDP成功发送或交付完整接收包时累计；零包增加包数而不增加字节。每个逻辑流或关联只有一个FlowId和FlowLease，完成权不携带用量、不重新开账本。已从出站读出的数据在后续入站投递失败时仍属该业务边界的下载量，终因另记失败。载体握手、TLS、复用控制帧不在此业务口径计量。

TCP业务I/O及物理PeerIo分别为read和write保存取消等待器。拆分到不同任务的两个Pending半部都由原取消域唤醒；flush和shutdown属于write方向。已完成的等待器不会再次poll，重复I/O返回不可重试的`ConnectionAborted`并保留`Error::Cancelled`作为错误来源。`write_all`和`read_exact`因此能够结束，不会持续重试`Interrupted`。等待器只共享原租约，不重复申请许可或计量。

`FlowFailure::from_io_error`只识别错误来源中类型明确的`Error::Cancelled`和`Error::Timeout`，`from_error`遇到I/O错误时委托同一规则。MeteredStream的read、write、flush和shutdown均传入实际底层错误，因此外层取消检查之后才发生的typed取消也保留正确原因。relay将明确取消还原为`Error::Cancelled`。普通系统`ConnectionAborted`和`TimedOut`仍是I/O失败，不能仅按错误种类推断业务终因。业务账本仍由原FlowLease固定首次真实原因，已知Timeout或失败不被后续清理取消覆盖。

`Engine::telemetry`返回只读运行期Telemetry。`usage()`按同一账本投影Engine、管理用户、节点和实际命名出站，维度之间不可再次相加。`records(after, limit)`最多返回4096条本进程保留记录。当前没有SQLite持久历史、带宽采样历史、持久水位或持久查询重置API，不声明完整统计目标已经完成。

## 预算与生命周期

ConnectContext持有公开的请求cancel与timeout，以及私有绝对建立deadline、可信ResourceKey、peer取消、节点取消和服务取消。run检查全部取消域及剩余期限；with_timeout只收紧预算，修改公开timeout不能延长原deadline。多目标关联的新目标解析用明确new_operation建立新期限，保留已有身份和取消域。

ResourceKey含运行命名实例、来源成员或Local归属及凭据代次。后端共享池据此分区，不能创建每成员完整Outbound。ServiceContext属于命名服务，不能来自第一个请求；spawn和spawn_tracked登记后台任务。ServiceTask可以单独abort并等待，正常取消不会关闭其他成员的共享服务，panic标记服务失败。

ServiceContext在所有者内保留真实JoinSet、首次绝对关闭deadline、协作退出截止时刻及累计失败和强制回收事实。关闭等待future被丢弃不会移走或丢弃真实任务，重试继续同一批join。EgressRuntime保留首次deadline及逐服务的backend结果、最近一次任务报告。已完成backend不重复执行，task超时不把服务移出后续join集合，也不阻止其他服务进入关闭和abort。重试读取已完成的迟到join及panic，以新任务报告替换旧快照后重新汇总，不重复累加。首次总期限不延长，期限之后只回收已经完成的join。两层关闭锁的等待及后续工作都受本次调用期限约束。较短调用超时不重置首次预算，真正超过首次期限的timed_out事实保留；超时仍未join的任务继续由服务所有者持有，不能声明资源已经释放。

Engine正常关闭先停止接入、有限排空并强制回收节点任务，再关闭命名服务并等待其登记任务。启动失败反向回收已经启动的服务，Error::Startup保留主要错误和清理超时、失败数。DeviceLease只借用原生路径，没有关闭设备WARP的接口；WARP数据路径和部署尚未实现。

`InboundContext.tasks`为`NodeTasks`，只拥有指定NodeId的实际派生future，没有目标、设备或出站能力。Engine在handler外保留同一所有者。`spawn_tracked`返回不可克隆的`NodeTask<T>`，可等待、abort；Drop只abort该child，真实JoinHandle仍由NodeTasks保留。一个peer结束不得关闭它。关闭后的spawn显式拒绝，不另起分离任务；panic取消所属节点，不取消其他节点或命名出站。

`InboundContext.peer_lease`仅在原物理TCP peer存在时为Some。PeerLease共享原global/node两层配额及peer取消域，不再次取得许可。Engine传入的物理I/O本身保留它，SessionIdentity/PeerSession和Dispatcher流租约也保留逃出context所需的引用；HTTP升级handler返回不会提前取消I/O或归还额度。显式peer取消立即生效，最后实际引用释放时取消并归还许可一次。节点级Runtime、UDP和虚拟入口不持首个peer的租约、取消根或来源元数据。

Engine关闭、NodeTasks、共享服务回收使用首次关闭时固定的绝对deadline，强制abort后的join同样有界。NodeTasks还固定自然结束及协作退出的阶段时刻，在abort之前持久保存强制计数。等待中断后继续原阶段和同一批真实join，不重新分配剩余比例。每次调用在取得关闭锁后仍受自己的等待期限约束；较短等待仅返回超时副本，不永久污染原总预算的报告。节点停止新接入和逻辑准入后并行排空，不同节点不会因一个节点等待而错过全局强制时点。局部协议的ForcedCleanup事实先由Engine暂存，只有外层handler和实际节点任务均已join且清理无失败才增加公开计数。超时返回清理未完成，不能把外层handler结束当成原生驱动已退出。节点内部任务不得调用整个NodeTasks的shutdown而等待自身。

`IoStream`要求Tokio AsyncRead、AsyncWrite、Send和Unpin，不要求Sync。Outbound保留为协议后端扩展trait，应用业务通过PeerSession进入；没有稳定C ABI或动态插件ABI承诺。

节点绑定拥有独立取消根，每个物理peer持自己的子取消域。结束一个peer不会关闭同节点其他peer或命名服务。NodeEvent新增ForcedCleanup，记录在原总预算内完成的强制回收；它不计作业务失败或数据包丢弃。运行用量快照的多个原子字段不是跨线程事务快照。
