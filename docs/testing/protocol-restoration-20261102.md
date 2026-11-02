# 协议恢复验证记录

更新日期：2026-11-02。本记录区分冻结输入与当前实现，不表示正式发行通过。后续编译、格式检查与测试按用户最新要求全部使用海外worker；旧授权下的本机结果保留在模块记录中。

## 输入与整树结果

初始Git基线为`21854e050d884f6b3b1191973574b0251f844142`，上面叠加四个收尾模块的首轮改动、27个自有包的GPL声明及文档。验证使用独立解析的522包锁，SHA256为`e6859965abca000d9870120b8ae1e814dd6269c3d088d1e277f89cae60d215ce`；主工作树原锁不自动取得这些结果。

perf-01使用既有Rust/Cargo1.99.1、Linux x86_64，单任务构建、测试单线程、无debug信息和增量缓存。不修改已有服务、系统网络或本机Clash。保存完整源码清单、归档摘要、命令、原始日志及终态；真实路径只留私有记录。

| 标签 | 输入与命令 | 实际结果 |
| --- | --- | --- |
| integration-r1 | 686文件，归档`8a1113a1e9a4fd225bbee8bed9d193c3547341fd3cd8c768b248a946be5dc2f5`；`cargo check --workspace --all-targets --locked` | 终态0，整树检查通过；尚未包含最新ShadowTLS夹具，不能外推后续输入 |
| integration-r2-tests | 689文件，归档`fcd739dc90c5e6b28628a73de743701327cef4c8b88d7a59f5f513b09bd3a454`；`cargo test --workspace --all-targets --no-fail-fast --locked -- --nocapture` | 终态101，70个测试程序合计408通过、2失败、2忽略；整树未通过 |
| integration-r3-tests | 689文件，归档`64886ad3347fb2787fd65650f3d685fda585d996f0c54f630314cfe85d55edb6`；同一整树测试命令 | 终态101，409通过、1失败、2忽略；Naive资产用例通过，但VLESS复用了旧测试产物，该次不能验证其修订源码 |
| vless-source-cache-r4 | 归档`7d20d187ad0844cebb7c3d522f1a887a2f68c207c6dd1fbc1122fbef9162f074`；原VLESS拒绝重复凭据测试 | 内容摘要校验并清理本任务工作区包产物后重新编译，终态0，1通过、3过滤；不是整树通过 |
| integration-r5-tests | 归档`b19e06dad3bf3803a80b39592e2eb1521665a9d923eab27aea60bb5a33f19a3a`；同一整树测试命令 | 内容输入校验启用，终态0，70个测试程序合计410通过、0失败、2忽略；耗时810.312秒 |

## r2失败与后续处理

Naive的`invalid_der_is_rejected_and_snapshot_contains_security_update`因未设置`KERLICO_TEST_ASSETS_DIR`失败。随后在worker准备阶段从固定HTTPS来源下载876字节资产，DER和SPKI摘要均匹配既有元数据；测试本身不联网、不忽略该项。资产仅留worker私有测试目录，不进入Git、源码包或发行包。

VLESS的`duplicate_node_credentials_are_rejected_without_disclosure`仍在匹配旧中文错误文本；当前配置校验已经拒绝重复入口凭据，但说明改为包含本地入口的统一措辞。r3改为先验证仅UUID不同的同参数双节点可准备，再要求重复UUID返回配置错误且不披露UUID。这样检查隔离行为，不依赖用户提示的固定中文；没有删除拒绝断言或修改生产隔离策略。

r3源码摘要包含该修订，运行日志却仍指向旧断言。原快照归零时间戳与共享target复用导致旧工作区测试产物被沿用，属于验证设施缺陷。现按工作区包及全局输入内容摘要识别变化，仅清理本任务target中对应包，并以worker文件锁保护缓存；不清理他人缓存或修改固定依赖源码。r4确实重新编译并通过修订后的原测试，r5随后完成上述整树复验。

两个既有忽略项属于AnyTLS和Snell的专用对端场景，未计作通过；仍须按对应模块补独立对端证据。本轮没有新增忽略或关闭失败模块。

## r2四个收尾模块的包级证据

| 模块 | 实际库/集成结果 | 仍需完成 |
| --- | --- | --- |
| SSR | 16+9，共25项通过，包括六项脚本化短写、分片、认证拒绝和取消回归 | 历史首包EOF/HMAC及固定参考矩阵继续验证，不从自端通过推定已修 |
| ShadowTLS | 16+11，共27项通过，包含真实Rustls票据经生产记录桥及HRR回归 | 新固定参考矩阵108/108通过，具体条件和未覆盖边界见下文；历史9项失败仍按原输入保留 |
| TrustTunnel | 13+11，共24项通过，含未知UDP源、双流隔离及H2完整记录credit | 固定Mihomo双向及TLS拒绝矩阵待执行；12项Python合成分类不替代互通 |
| Sudoku | 65+1+6+6+12，共90项通过 | 两个原生参考程序的完整互通仍待执行；原负载、8秒/120秒期限和32MiB阈值均保留 |

包级通过可独立记录，但不能把r2整树失败改写为通过，也不能将该输入外推到正在编写的共享运行、多用户迁移。后者仍需新的完整首轮和统一worker验收。

本机Clash期间发生一次用户确认的主动变更。最初保护记录保留，操作后另建保护基线，后续比较为未变；本任务未据此恢复或修改用户设置。

## 独立CLI构建与启动

perf-02在独立冻结工作区完成默认全部21模块的`cargo build -p kerlico --locked`，终态0。随后冻结的开发CLI为136159712字节，SHA256为`aa9071cb1528b663112c743da547ba607aec9e52bdcdc9c24331272d9ba447e5`。同一字节分别在perf-01、perf-02、perf-03执行`modules`和`--help`，六项退出码均为0；没有启动节点、修改服务或占用业务端口。该CLI用于接下来的固定协议互通，不是正式发行产物，不从启动通过推定全部组合通过。

## ShadowTLS真实对端与边界诊断

perf-01使用上述CLI、r5冻结工具，以及固定sing-box 1.14.4提交`c005f35300ce76427dc285481ec5695f5b179cd2`。参考二进制SHA256为`1264361b5f8868c8768f7555d3e77e20118bf503c41ac08bb290a0d99056aa3a`，握手站点采用OpenSSL 3.5.7并发服务，保留默认票据。

`matrix-r1`终态0，108/108配置通过，客户端与节点各54/54。每种角色覆盖九种内层配置与六条外层版本路径，独立IPv4/IPv6节点、两族及localhost目标、17/4096/65536字节、目标先发、四流并发和错误内外层凭据。退出检查及自有目标handler回收均完成。当前参考字节、OpenSSL版本与并发站点和旧r9条件不同，因此该结果不能证明历史九次失败具有同一根因或已在原条件下修复，也没有强制网络HRR。

`boundaries-r1`终态0，16/16受控外层业务配置完成，共128份采样。请求的TLS1.3晚到记录切点没有在真实运行中出现，部分记录前缀为0，也没有实际一字节ShadowTLS首写覆盖。因此这些样本不算晚到票据切片或一字节首写的网络验收；对应确定性生产桥与HRR回归以27项Rust结果为依据，二者分别记录。模块详情见[ShadowTLS记录](shadowtls.md)。

## Sudoku首轮原生对端诊断

固定Mihomo提交`3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8`的原生二进制摘要为`d015330c36f054434c6fab4dd6d53d41d9294dfb7750c9d7066712f8eebdfd5a`。首次完整矩阵在大UDP内容断言重复失败后，明确停止该自有作业，保留444条部分记录，其中294通过、85失败、27项入口限制、38项进程退出观察；没有终态全矩阵通过结果。

独立raw/AES128两角色诊断保留大包，追加实际长度和目标收包长度。客户端方向，目标完整收到64000/65507字节并回送，返回客户端时均为16384字节；节点方向，64000字节经Mihomo SOCKS入口后，目标只收到16374、16362、16368字节，分别等于16384减去IPv4、IPv6、域名SOCKS首部。0/17/4096字节和TCP控制通过。固定源码的`common/pool/buffer_standard.go`定义16KiB UDP缓冲，`common/net/packet`读取路径使用该缓冲，与所测截断位置一致。该证据说明这些大包受固定参考入口/回程限制，不能算本项目与其的大包互通通过，也不据此降低本项目包长。

官方v0.5.2.0原生程序在临时user/net namespace内完成完整矩阵，仅启用其中的回环，不改宿主网络。`official-all-r1`终态1，6515.807秒，494个计划配置产生11219条记录，9484通过、1002进程观察、687入口限制、28参考边界、18失败。失败为两项poll/auto并发尾部EOF、十项raw/ws的33MiB提前EOF、六项stream/poll/auto节点退出setup超时。记录数不能换算为配置全部通过；共享架构仍须使用新CLI另行验收。

另一个仅加日志的独立诊断保留raw/AES128、Mux on、节点方向的原33MiB与期限，终态1，27条为20通过、2失败、3入口限制和2退出观察。IPv6及域名目标失败时，本地逐流队列分别为4152320、4160512字节，再接收64512字节即超过4MiB而重置。相邻IPv4大流量通过。该结果确认两个失败的容量拒绝位置，尚未区分目标阻塞与调度排空原因；不能据此宣称重钥故障或唯一根因。官方源码有双向半关闭及等待，也不足以将失败归因于对端全关闭。后续进度观测仍在独立树准备，未提高容量或放宽断言。

## 专用忽略项与另外两包互通

`anytls-peer-r6`明确启用忽略项`sing_box_both_roles_tcp_and_uot_v2`，使用上述固定sing-box，终态0，1项通过、6过滤，覆盖两角色TCP及UoTv2。`snell-vectors-r8`以固定Go1.27.2、原锁定sing-snell提交及只读go.mod/go.sum生成64组原生向量，再运行`fixed_go_profile_and_cipher_vectors`，终态0，1项通过、8过滤。向量摘要为`39ae21220c2bb693e01af962f99ef904668128c54fe11372a4bf03c4a98610a6`。前一Snell准备因离线缓存缺模块而失败，未运行Rust测试；随后只在项目缓存取固定依赖，源文件摘要不变。两个专用结果不改写r5日志里的2项忽略，也不能代验共享迁移。

`ssr-mihomo-r1`使用固定Mihomo1.19.33摘要`817f50b3ac6a8b1c4360c5cf2961906057f3a883d970ebbcb0028a01632b620f`，完成192条，177通过、15失败，终态1。两族节点和目标、六protocol与六obfs的本项目节点方向有实际EOF/内容失败，不能据25项Rust通过宣称历史问题已关闭。原失败与对应两端日志均保留。

perf-03另以原Rust自端组合测试重复执行，`ssr-self-repeat-r1`保持全部协议/混淆、双栈及域名目标、原负载和期限。前27轮通过，第28轮在auth_sha1_v4/random_head、IPv6节点至IPv6目标读取先发问候时收到EOF，服务端同时报告Protocol校验/握手失败；作业终态101。该结果证明当前旧SDK1输入仍有自端偶发故障，不能用参考端限制代替解释。后续逐层字节观测尚未终态，不提前登记根因或修复。

`ssr-wire-repeat-r2`只加合成字节观测，第14轮在chain_B/random_head再次失败。worker对抓取字节复核：客户端完整随机头15字节，前14字节与全15字节CRC均为`0xffffffff`；服务端选14字节边界，末尾零进入IV，协议解密首字节即不同，双端网络字节无差异。生成端已在独立树改为只发送自身首个有效CRC边界，保持认证与原队列。精确分片回归1项通过，随后26项全包通过；`ssr-crc-repeat-r7`原组合100轮全部通过，终态0，705.978秒，归档`442993c5f89f71f64a368bebf17ef56e4c8880698571317e931549f3dbe0fc15`。最初精确命令因未写模块路径实际0项，日志保留且不计通过。

`tt-mihomo-r1`同一参考下终态1，316记录为194通过、60失败、58观察到限制、4未验。60项均为本项目客户端H2两种TLS及两族节点。新自有回环实例的OpenSSL诊断分别发送h2 ALPN，严格验证名称和CA；TLS1.2/1.3均终态0且验证成功，实际均没有协商ALPN。固定参考的HTTP2路径采用TLS上的先验解析，当前本项目H2严格ALPN检查会拒绝它。后续显式兼容模式仍须独立编码和实际互通，不能把诊断当该路径通过。

## 共享运行迁移首轮

首轮845文件的`shared-r1-metadata`归档为`a894398c602cd7e1633fcd55b0d25c7bd8b839f8020a3fe99cd5fac8c58f3285`。perf-02正式解析得到516包、27工作区成员，只有一个path来源的xray-transport。新锁摘要`81f2c589a954d9ad653eddc91951f18bce0bff28cb9d48f5a70a2f3a88560946`，其余既有包版本未被刷新；移除了不再使用的reqwest等六个包，供应路径替换同版本Git transport。

`shared-r2-check`因VMess服务端误用客户端resumption字段失败。worker独立副本`shared-r3-format`完成格式化，接回184个自有Rust文件，未修改第三方源码。后续r4/r5继续暴露Snell和ShadowTLS类型错误；r6使用keep-going集中发现剩余测试迁移错误，终态101。修正和生命周期审阅问题仍在处理中，尚无该迁移树整体验证通过结果。格式、依赖解析、旧快照测试均不算当前功能验收。

Naive/SSH实际任务等待修订27文件、XDRIVE生命周期/自定义CA修订6文件已接回并核对前后摘要。SSH采用固定russh-util0.52.0发布原件的最小供应补丁，内部actor向真实宿主登记；不拿dirty VCS对应Git签出替代发行原件。worker再次真实解析后锁为516包，摘要`306778a566ec6bc85f8f81572f86cd9489fcf1383557e0a41df661d9edb2dcd3`，只有一个path来源的russh-util。

| 标签 | 输入与命令 | 实际结果 |
| --- | --- | --- |
| shared-r8-check | 858文件，归档`796907b1b03d7659a56ea4f65c410f165c9165a793d03576527fc0cd7177700a`；整树all-targets、keep-going、locked | 终态101，SSH临时String借用及新XDRIVE测试的rcgen非穷尽结构构造失败 |
| shared-r9-check | 同范围修正，归档`74c948298a6aa2f85c9dac8052d4ba82d78e59651a463accebeb56bbea24244b`；相同命令 | 终态0，整树编译检查通过，仍有unused警告，未完成严格检查或行为验收 |
| shared-r10-tests | 858文件，归档`99032a845914734bca4f1a69ca4a2faef5d09615d8d638b0446c8e8e47f57cfc`；整树all-targets测试、no-fail-fast、locked | 终态101，84程序合计432通过、33失败、2忽略；715.021秒 |

r10的Naive固定资产已在perf-02准备并验证DER/SPKI摘要，失败不能归因于缺少该资产。真实失败涉及egress取消、Hysteria2/Mieru/Naive/TrustTunnel的池与预算、SS/SSR配置或成员行为、Snell/Trojan/VMess元数据、Sudoku多种载体，以及XDRIVE新析构回归和VLESS能力校验。受控panic回归打印panic但最终为ok的用例不计作失败。逐测试名称和原日志已保留，不能把432通过写成整树通过。

后续正在补齐原选设计的typed flow与唯一完成权，处理外层超时、入站错误和UDP父级终止的真实FlowRecord，并将真实节点子任务登记到Engine持有的NodeTasks。新代码及21适配仍在完整首轮，尚未运行新输入验证；r9、r10不能外推到该波。

该补齐波冻结881文件，完整清单SHA256为`97031766df93993e0a04aeb73519b5d9151635de9d36c69764aa41ae53e0977c`；主任务与三位独立审阅者均逐项核对原字节。`flow-r11-format`在perf-02格式化165个自有Rust文件，第三方不变。r12编译发现Engine类型、Snell应答分支、SSR与AnyTLS测试适配错误，r13仍有HTTP测试误用OpenedTcp；集中修正后`flow-r14-check`终态0，74.726秒，归档`6c9102d2373302ce4b677599476b8595b742c2d332547f0d5b445c898e9682ea`。

`flow-r15-tests`终态101，1389.101秒，87份完整程序摘要合计512通过、3失败、2忽略。另一个egress程序宣布19项，只观察到首项通过；随后取消回归超过614秒无输出且CPU持续变化，经精确进程归属核对后终止该自有程序，Cargo继续收集余项。该程序无完整摘要，其余断言不计入上述合计，不能把512写成整树通过。三项普通失败是SSR本地配置夹具、TrustTunnel兼容ALPN正例和池复用计数；原测试未删除或忽略。

worker读取固定Tokio 1.54.1实际源码确认，`write_all`在单次poll中重试`Interrupted`，对应源SHA256为`379df45494ed544add0bbf609aeaafad6426740292bbe7c7b1e5731307d2781a`。业务取消包装器持续返回该错误，造成取消回归忙循环；Tokio内部timeout无法抢占。修订改用携带`Error::Cancelled`来源的终止I/O错误，普通系统连接中止仍为失败。随后888文件集成输入在`flow-r17-check`通过整树all-targets检查，归档`d7e91e87280047d6745be2d043783999b6be0ba347ed9b62a9e481a6b0a8000b`；`flow-r18-cancel-watch`另设180秒进程级总期限，原精确回归实际1通过、20过滤，终态0，74.075秒，其中包含编译。此结果只确认该取消回归，不代替整树复验。

独立静态审阅为ISSUES，确认共享服务关闭等待中断、TCP分离任务取消唤醒、Hy2 GOAWAY、三协议UDP回包错误结算及TrustTunnel拒绝时的并发流终因问题。不能从r14编译通过推定这些行为正确。SSR与Sudoku的限定修订随后已合入888文件独立树，仍须新SDK2复验；持久统计、WARP、剩余协议、多语言和正式发行未完成。

后续两份复审仍为ISSUES，补充了计量器内层typed取消、超时服务迟到join、NodeTasks短等待与强制事实、Mieru服务端终因、Hy2未识别sniffer、AnyTLS物理交付及TrustTunnel拒绝来源等边界。部分修订已合入888文件独立集成树，其余在隔离树完整编码，均须按新输入重新验证。未将范围限定的SSR、Sudoku修复当成整个共享架构或发行通过。

## Sudoku清洁修订与限定复验

不含诊断日志的字节批次修订在`sudoku-fairness-package-r5`实际90通过、0失败、0忽略。清洁CLI归档为`f7284859c9feb3576a9f6a98015ae5da59bf8012c98fb590ab100215b4e56329`，CLI为25121968字节，SHA256为`26048b62a7c99baf7d716c3c561af73873680c6785c2d2037ea8e538a68acbf3`。

同一清洁字节的官方raw、ws各三目标33MiB复验均终态0，每组27记录，22通过、3入口限制、2进程观察。新增大帧慢流回归实际1项通过，在64512字节原生帧积压未触顶时和触顶后分别确认同载体快流内容及FIN，仅慢流reset且8MiB预算归还。随后仅对该回归两文件做worker格式化，没有冒称格式化后整树重测。

独立复审对这一小修复给限定范围PASS；ChaCha组合、两项并发尾部EOF、六项lifecycle超时、持续就绪读取下的定时回收边界和整个新SDK2仍待验收。原494配置的18失败保持原输入结果，不改写为全过。

## 后续库级与排空验证

`flow-r20-check`的888文件归档为`ebb2d606defd029e3a56ed04931ad110bbab8506c1658e6b015afc2f95f9ce96`，整树all-targets检查终态0，76.341秒。`flow-core-unit-r21`与`flow-tt-unit-r22`使用相同888文件归档`3b6188ffb7ef353727f00bd473f8d8bc18b7019e7918eb18e587d4b54ec62bc7`，分别在perf-03、perf-01运行库测试。前者10项通过、0失败，后者36项中29通过、7失败，均保留原日志和精确测试名。

TrustTunnel的6项H3节点排空测试在关闭准入后的业务往返失败，另1项H2目标拒绝测试在服务器收尾失败。不能将其统一归因于测试超时或已经通过的ALPN夹具。正在追溯固定h3/h2驱动的真实拒绝及结束语义，旧失败不删除或忽略。

Hy2新增修订让GOAWAY前已接纳、尚未读完类型varint的流继续由同一sniffer集合推进，真正的新流按原预算拒绝。`flow-hy2-unit-r24`未通过编译，4处trait调用需明确Bytes类型，未执行测试。修正后`flow-hy2-unit-r25`归档`f8cc9f050007ccee87dbd65dd104008e9ad267bf8cdb83903a18c3e3ace43b76`，库19项全部通过，0忽略，12.682秒含编译。原5项和新增6项GOAWAY回归均实际执行，新增项分别覆盖部分varint后继续业务、旧UDP与拒新流、未识别流期限、进展不重启期限、节点取消与载体失败。夹具使用真实协议Node、I/O、账本、配额及NodeTasks，不宣称完整Engine装配已验收。

独立复审S1的Sudoku持续Ready维护饥饿另成修订。相同两项真实Session driver回归分别搭配旧driver与候选，在`sudoku-gc-baseline-r26`和`sudoku-gc-candidate-r27`启动；当前尚无终态，不提前登记复现或修复通过。输入保持原250毫秒周期、容量和预算，受控恒就绪载体不作为性能测量或先前33MiB故障解释。

## 新SDK2后续结果与剩余门槛

上述Sudoku对照随后终态明确。r26为0通过、2失败，均在原回收等待超时；r27为2通过、0失败，48.961秒含编译。相同888文件仅生产driver一行分支顺序不同，两项回归逐字节相同。独立审阅给维护修订限定PASS。`flow-sudoku-package-r31`使用新SDK2集成归档`79e196e8ad2487ff8429bed481fc9bdb80dd28e8b3349ff6c9d9039c7390b5f8`，6程序99项全部通过，394.395秒；真实参考剩余组合仍须用新CLI复验。

同一889文件归档的`flow-core-actual-r30`在perf-02对core、egress、AnyTLS、Mieru执行all-targets，14程序合计103通过、0失败、1既有专用对端忽略。此输入含新核心生命周期修订和AnyTLS实际物理确认及取消终止回归，不包含后续Mieru Pending的FlowOpen修订。

TrustTunnel的H3准入拒绝改为真实H3_REQUEST_REJECTED reset及STOP_SENDING，固定h3的RequestEnd提前归resolver持有，成功移交同一个Arc，解析前退出也归还排空账项。`flow-tt-unit-r29`为36通过、1失败；原六项H3失败及新增预算用例已过，剩余H2关闭失败继续保留。r32精确诊断显示业务任务空、底层无流、客户端h2驱动正常退出后释放TLS，服务端关闭写入收到BrokenPipe。测试Fixture改为拥有TLS至双方关闭结束，生产错误分类未改。r33新增空字节断言失败，r34逐帧确认残留仅正常GOAWAY，精确原测试1项通过。格式后`flow-tt-unit-r36`完整库37项通过、0忽略，17.787秒，归档`1fefb49d7ad31a0dbfb7a299bd9780599d0ebc02d65a667de6209a0e3bb32e55`。独立源码与精确输入复审为限定PASS；固定h3原生回归及其他消费方另验。

`flow-anytls-hy2-r40`使用889文件归档`fb21079f5e8d2cd44bd24f8feab12832b32593e9ff90c19232029bced3b421fd`，5程序59通过、0失败、1既有专用忽略，50.529秒。AnyTLS以17个真实目标及32项反馈队列证明较早独立Timeout在End发送受阻时不被后来的物理失败覆盖，父先失败的清理反例也通过。Hy2两项新增真实控制流RESET回归和原GOAWAY回归通过。原输入对最终join与socket重绑未用同一原deadline包住，不能登记该时间边界已覆盖；后续收紧夹具仍待复验。

H3独立验证副本保留生产源码，增加与主图一致的Git patch及固定h3-quinn测试支撑。r37仅解析其独立锁；`h3-primitives-tests-r38`因新增三回归中的四个类型错误未编译通过，没有运行测试或监听。相应测试类型、仅loopback绑定、控制帧持续Ready时的轮询预算及GOAWAY发送取消安全正在独立树完整修订，当前未登记通过。生产主锁仍保持516包，不将独立测试锁当成发行依赖图。

Mieru Pending建立修订891文件的FlowOpen在首次poll准入并持唯一完成权，正常调用仍使用原open名称及await。后续验证和修订如下；此前等待记录保留原时点，不把历史通过外推新输入。

## 建立期取消与H3原生对照

| 作业 | 输入和范围 | 实际结果 |
| --- | --- | --- |
| `flow-r42-check` | 891文件，整树all-targets | 终态0，233.98秒 |
| `flow-pending-egress-r43` | 格式后的891文件，建立期出站回归 | 6通过 |
| `flow-mieru-pending-r44` | 同一891文件，Mieru库 | 19通过 |
| `flow-service-cancel-r47` | 893文件，core、egress、Mieru全部target | 14程序，95通过、0失败、0忽略，56.4秒 |
| `h3-quiescence-candidate-r48` | 独立H3测试支撑，898文件，完整库 | 260通过、0失败、0忽略，77.748秒 |
| `h3-quiescence-baseline-r50` | 同样898文件，仅恢复三个旧生产文件；同样17项受控回归 | 9通过、8失败、243过滤，47.841秒 |

r47归档为`bf71e2ee606178065dd579a6cbc3bee2905d9578b8521ecf840fded469c2f686`。服务取消先于正常END时，建立期结算保留Cancelled，已ready及较早失败不被覆盖；真实Mieru TCP/UDP控制帧和完成回调先于backend析构均有用例。两波独立源码复审的发现和修订分别保留，没有用早期r43、r44代替r47。

r48归档为`2fd47a79747cae44e445c72ad105947163bed652e3a0c9628fe63af2bea1e1b2`；r50为`af4b647e841932ec8430874fbd8beca553cba03f9adb2a1df73d9b5c12e29263`。两树全部测试和支撑相同，仅`connection.rs`、`frame.rs`、`server/connection.rs`三份生产文件不同，另895文件逐字节相同。新增八项全部在旧实现失败、候选通过，涉及两层预算后的控制错误、合法批次排空、拒绝请求与控制错误并存、grease打开或部分写出受阻。原九项受控和三项真实QUIC回归均在候选执行通过。此对照不是吞吐测量。

此前`h3-primitives-tests-r38`与`h3-primitives-tests-r45`均为测试编译失败，零测试执行，失败不删除。r51只在worker格式化三个H3文件；生产实现与测试支撑清单分开，独立测试Cargo、锁及h3-quinn副本不进入发行输入。后续须复验Hy2、TrustTunnel、Naive、VLESS和同一整树。

## Tor首轮输入

Tor限定首轮原生TCP、注册及文档已写入独立集成树，未登记支持或通过。`tor-integration-metadata-r49`的939文件归档为`8407f68a3fee4b1081c76c7cd2adf2ea0e63fc28733754862c6e6a4fd053430a`，仅metadata终态0，7.034秒。解析762包、28工作区包，主锁SHA256为`b44c5b4e58bcf75d59d1d2f3f6b31c17dbffb22c97cc5e263f85cb9c4b2ca387`。默认metadata图未选`tor-hsservice`、`hs-pow-full`和onion服务端功能；含开发及平台条件依赖，不能作为最终产物实际链接闭包。

Tor首轮独立评审为ISSUES。命名服务blocking任务的真实迟到join、首次关闭期限、服务失败分类、状态路径信任和验证工具证据仍在修订，真实Tor网络未运行。WireGuard进入研究，其余后续端点、持久统计、设备WARP、多语言与正式发行仍未完成。

`h3-consumers-r53`以939文件归档`16a0ee81b591071fce5571631c04a4075098655109794743015115cece6afdcb`对Hy2、TrustTunnel、Naive、VLESS运行全部targets，19程序161通过、0失败、0忽略，187.475秒。Hy2包含同一原deadline包住join和socket重绑的收紧夹具。此输入不包含后续服务回收和Tor评审修订。

`tor-native-first-check-r52`以939文件归档`31ecd8a9e0acae43eced009e360f0c22466a6420e2c0e9a5fe5e94a9254cd6e7`执行Tor包all-targets检查，终态0，无编译警告，151.956秒。`tor-native-first-tests-r54`归档为`740c6da403cf7f770a7ce69d34fd35543a3a65451fd8ce399f9793be53b3e786`，core与Tor共4程序32通过、1失败、0忽略，169.484秒。其中Tor库14项全过；唯一失败`interrupted_blocking_shutdown_retains_first_deadline_and_late_panic`在受控panic时仍持有夹具Gate锁，最后清理触发PoisonError。正在修正夹具，既有期限、panic和资源断言保留；不把这个失败当成真实回收问题已经解决。
