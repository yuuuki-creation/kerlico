# 项目状态

更新日期：2026-11-02，Asia/Shanghai。

最新发行顺序：用户明确要求“最快的速度发版然后再测试”。[1.0.0源码版](https://github.com/yuuuki-creation/kerlico/releases/tag/v1.0.0)已于2026-11-02 03:50 UTC公开发布，标签为v1.0.0，提交为`57f036c646d85ff71d78ba10aca8af52d1b7326c`，Git身份与标签均匿名。Release不是草稿或预发行，当前没有二进制附件。源码现含23协议模块，完整验收尚未完成，原目标继续保留；后续源码修复采用新补丁版本，不改写本标签。

用户随后明确要求暂停，当前任务已停止。发布标签和源码保留，未新建补丁发行。恢复须由用户明确继续。

发布后同一标签的977文件输入在perf-01通过整树all-targets检查r65，221.454秒；存在弃用和未使用项警告，不等于严格Clippy或测试通过。perf-02的release构建r66、perf-03的整树测试r67已按用户暂停要求停止，终态均为-15，自有子进程已确认清理，原始日志保留；未完成程序及整树测试不登记通过。当前没有1.0.0二进制附件。三项均在Release公开之后启动，全部在海外worker执行。

最新局部证据为r63核心/出站/Engine的14程序93通过、0失败、0忽略，回收死锁原r57实际失败、修订后通过，独立限定复审PASS。Tor新修订独立静态PASS，新增26项尚未执行；WireGuard全部首轮已写齐但未编译。r61 SSR-Mihomo 191通过、1失败；r62 TrustTunnel-Mihomo 258通过、54限制、4未测、无失败。各自输入独立，均不能证明1.0.0同一整树通过。持久统计、WARP、完整多语言及六项后续端点未完成，见[发行说明](docs/releases/1.0.0.md)。以下开发记录保留各自时点。

当前阶段：**按用户最新指令收尾未完成协议，并将后续编译测试统一放在海外worker。** 当前保留21个协议模块及既有文档改动，17个有范围明确的历史验证快照。四个收尾模块已有新包级证据，ShadowTLS本次固定矩阵通过，SSR、TrustTunnel与Sudoku真实矩阵仍有失败。共享出站与多用户迁移在独立树通过编译检查，尚未通过行为验收。保护本机Clash及既有服务；正式版本仍未发布或建立标签。

恢复任务先核对四个未收尾模块的真实差距，再推进总表尚未实现的Tor及IP隧道/覆盖网络端点。阶段记录与证据单独保存，不以旧源码快照、静态检查或候选库存在宣称新协议完成。工具链与测试隔离准备不修改Clash或系统网络；本地许可覆盖此前本机禁测约束。

用户进一步要求完成后正式发版，版本号及细节自主决定，并支持多语言。首批目标为简体中文和英语，覆盖CLI、用户提示、使用文档与发行说明；仍需完成协议与已确认架构、整树验证、许可/匿名及正式产物门槛，当前没有发布新正式版本。

恢复后的首轮修复已分别写入四个隔离工作树，并形成独立集成快照。旧授权下本机SSR整包25/25、Sudoku90/90、TrustTunnel24/24及三包严格Clippy通过；Sudoku严格检查的分块API适配、TrustTunnel测试循环修正后各自定向回归通过。ShadowTLS Windows整包因AWS-LC的`nanosleep64`链接失败，新增Rust夹具未运行；自有监听和线程回收平台检查9项通过。原始整树Windows检查的Linux-only REALITY依赖失败也保留，不能据局部结果登记Windows正式支持。

按用户后续要求，剩余编译与测试统一转至海外worker。首个整树all-targets检查通过；r2整树408通过、2失败、2既有专用对端忽略。Naive固定资产已准备并通过复验；VLESS修订后的测试在r3被旧产物复用，现已修正内容缓存校验，r4重新编译的原测试通过，r5随后完成整树410通过、0失败、2忽略。四个收尾包分别SSR25、ShadowTLS27、TrustTunnel24、Sudoku90项全过。ShadowTLS当前固定sing-box矩阵108/108通过，晚到记录诊断未实际触发请求的切片，不能登记该网络边界已覆盖；见[恢复记录](docs/testing/protocol-restoration-20261102.md)。perf-02独立默认CLI构建通过，同一开发字节在三台worker的help/modules启动六项通过，非正式产物。源码、锁与阶段分别保存，不外推正在编码的共享/多用户迁移。Clash的用户主动变更已确认并另存后续保护基线。

用户已指定项目采用GPL-3.0。根LICENSE完整原文、自有工作区及27包的`GPL-3.0-only`声明已写入并核对，第三方原许可保留；依赖通知、对应源码与最终产物审查仍待完成，见[许可说明](docs/licensing.md)。

共享运行迁移首轮845文件及858文件修正快照分别保留。r9整树检查通过，r10完整测试84程序为432通过、33失败、2忽略。其后881文件补齐波经修正通过r14检查；r15终态101，87份完整摘要512通过、3失败、2忽略，另一个19项程序因取消忙循环被终止，无完整摘要。终止事实与未完成断言不隐藏或计通过。当前888文件独立集成树通过r17整树检查，带独立进程期限的原取消精确回归r18实际1项通过。真实依赖图516包，xray-transport和russh-util各只有一个供应实例。独立复审仍有生命周期和协议终因问题，正继续修复，不继承旧r5通过；主工作树尚未接回迁移源码。

两项既有专用忽略测试已在perf-01分别实际执行并通过，AnyTLS固定sing-box双角色TCP/UoTv2一项，Snell固定Go对端64组向量消费一项；r5原日志仍保留2项忽略。新SSR-Mihomo矩阵177/192通过，15失败；TrustTunnel-Mihomo316记录有60失败，尚未完成交付。后者客户端H2路径的固定参考已实测TLS证书验证成功但不协商ALPN，显式兼容代码已写入881文件波，尚未取得新互通结果。Sudoku官方494配置完整矩阵终态1，11219记录中9484通过、18失败，其余为进程观察、入口限制及参考边界；失败明细见恢复记录。

perf-03的SSR生成端修订取得确定性回归1项、全包26项、100轮原组合及严格Clippy通过，Mihomo失败仍另验。Sudoku字节批次修订的清洁包级90项、清洁CLI官方raw/ws各三目标33MiB及大帧慢流回归通过，没有抬容量或缩减负载。两项独立复审均为限定范围PASS，已接入独立共享集成树但新SDK2仍须复验；Sudoku其他原失败与定时回收边界保留。

后续888文件输入通过r20整树检查，r21核心库10项通过。r22 TrustTunnel库36项中29通过、7失败，失败涉及H3节点排空与H2目标拒绝后的收尾，正在根据实际驱动错误修订，不登记完成。Hy2待识别流修订经r24首次编译发现4处trait调用问题，补全类型后r25库19项全部通过，含原5项与新增6项GOAWAY真实回归；独立复审、整树及完整Engine仍待验。Sudoku持续就绪维护修订已写齐，两项相同回归的旧实现/候选对照已在worker启动，尚未取得终态。

后续对照确认Sudoku维护旧实现两项超时、候选两项通过，独立限定PASS；r31新SDK2包级99项通过。r30核心/出站/AnyTLS/Mieru四包103通过、1既有专用忽略；r36 TrustTunnel库37项全过。r40 AnyTLS与Hy2共59通过、1既有忽略，覆盖满反馈队列保留独立Timeout及真实H3控制RESET。Hy2随后收紧最终清理的原期限，尚待复验。

Mieru Pending建立及服务取消先于正常END的修订已合入独立集成树。r42整树all-targets检查通过，r43建立期6项和r44 Mieru库19项通过；后续r47在893文件输入对core、egress、Mieru运行14程序，95通过、0失败、0忽略。两波修订均经过独立源码复审，不外推后续Tor和服务回收增量。

H3独立原生测试先在r38、r45因夹具类型错误未运行；修正后r48完整库260通过、0失败、0忽略。相同17项受控回归的旧生产实现对照r50为9通过、8失败，八项新增回归均复现；仅三个生产文件不同。修订区分预算让出与真实输入等待，并保留GOAWAY发送进度，独立限定复审PASS。r51在worker格式化三文件；r53对Hy2、TrustTunnel、Naive、VLESS执行19程序，161通过、0失败、0忽略，包含Hy2收紧后的原清理期限；当前整树仍须复验。

Tor原生TCP首轮及注册入口已写入独立集成树。r49解析762包、28工作区包，未选onion服务端或PoW功能；r52包级all-targets检查通过，r54 Tor库14项通过。同批core与Tor共32通过、1失败，唯一失败是受控panic夹具持锁导致清理时PoisonError；保留失败，尚未复验修订。首轮独立评审为ISSUES，服务blocking任务迟到回收、失败分类、状态路径和验证证据正在修复；真实Tor网络和产物链接许可闭包未验证。WireGuard双角色TCP/UDP首轮编码开始，任意远端ICMP不在此轮范围；另六项后续端点未开始实现。持久统计、设备WARP、多语言和正式发行仍未完成；本机Clash按用户确认后的基线核对未变。

## 最新架构要求

2026-11-01，用户明确所有节点共享同一个出站调度器，出站模块独立并全局共享。一个Engine运行实例只装配一个调度器，每条命名出站配置只构造一个运行实例；节点保留独立入站认证、会话归属、限额与取消。当前逐节点构造Outbound和Egress的源码尚未迁移，不能把同接口实现登记为已满足该要求。确认范围、接口建议及验证目标见[0009](docs/decisions/0009-global-egress-dispatcher.md)，目标流量图见[节点与统一出站](docs/node-egress.md#统一访问口)。本次仅更新架构约定与设计记录，未新增构建、测试、修复或发布结果。

用户进一步确认每节点部署时选择IPv4 only、IPv6 only或双栈；本节点负责的双栈出网缺族时，由设备级共享CF WARP的对应族出口补齐。远端可有多个代理，分流请求保留原始网站目标和负载，由远端执行自己的地址与失败策略，本机不因此换族、换代理或回退直连重试。共享调度器先分本地出网与远端透传，不能先统一解析改写所有目标；见[0010](docs/decisions/0010-node-egress-modes-and-warp.md)和[目标地址选择](docs/node-egress.md#目标地址选择)。节点模式、WARP部署和透传迁移均未实现或验证；未配置设备或恢复构建测试。

README与设计导航、总体架构、核心契约、TCP/UDP数据路径、资源生命周期、协议扩展、接口现状说明、决策索引及借鉴映射已按0009/0010同步。历史决定和测试保留原时点，现有接口明确标注迁移差距；文档更新不代表源码已满足新架构。

## 多用户与统计确认

用户已确认单节点支持多个独立用户，用户名默认附UUID，各用户具有自己的用户名与密码管理信息。需要逐用户保存上传/下载流量、带宽和域名/IP访问记录，Xray已核对的日志、在线、流量及查询导出能力按本项目结构适配；见[0011](docs/decisions/0011-users-statistics-and-access-records.md)及[统计设计](docs/statistics-and-users.md)。

设计建议采用稳定管理用户ID与协议凭据映射，可信用户归属贯穿共享Dispatcher；业务量唯一计量，节点、用户及实际出站分别归集，载体和设备量另列。带宽区分当前窗口、平均和采样峰值，历史用量与访问记录持久保存，查询清零不删除历史；远端网站IP未知时不强制本地解析。限速/额度/计费及具体参数尚未确认。

当前公共上下文没有稳定管理用户身份，Stats仍仅四类累计事件，部分协议多凭据不等于统一逐用户统计已具备。新文档、Xray固定来源及相关导航/契约已同步，运行源码、配置字段、存储和统计API均未迁移，没有新增构建测试或发行结果。

## 保留的代码与验证快照

- 首批 Trojan、VMess、Shadowsocks AEAD/legacy、SOCKS/HTTP 已完成限定实现与远端验证；具体角色、算法、对端和包长边界见下表及模块测试记录。
- 八模块冻结快照已通过 104 项工作区测试、1 项专用对端忽略项、严格 Clippy、格式与功能裁剪；同进程 16 个独立节点的 81 项联合检查通过。源码清单、锁文件及二进制摘要见[首批集成记录](docs/testing/protocol-batch-1.md)，不代表当前所有新增模块通过。
- SOCKS 11 项、HTTP 7 项包级回归及严格 Clippy 通过；此前后补正式 CLI 复验通过；固定 sing-box 52 项检查通过，另有 4 项参考入口零包限制未验收。公共多目标 UDP 关联、IPv4 优先、空包、取消、来源元数据和配置能力校验已通过相关测试。
- VLESS 额外客户端 Mux 矩阵已用首批冻结 CLI 复跑 30/30 通过，覆盖此前失败的 TCP+none 并发；见[续验记录](docs/testing/vless-combinations.md)。其他密码、存储和会话迁移分支仍按未验收项保留。
- 第二批 Snell、TUIC、Hysteria2 各自限定验收已完成：Snell 14 项 Rust、64 组独立向量和 36/36 对端组合；TUIC 9 项 Rust、144 项对端和 24 项生命周期检查；Hysteria2 8 项 Rust、544 项 CLI 检查。十一模块冻结整树已通过 139 项测试、2 项忽略项、严格 Clippy 和三种功能构建；22 节点联合检查 111/111 通过，见[第二批集成记录](docs/testing/protocol-batch-2.md)。
- Hysteria v1 已通过 16 项 Rust、官方 24/24 和 sing-box 12/12 组合；ShadowQUIC v1 已通过原固定 Mihomo，v2 已通过受控标准 Go 参照，原 Mihomo v2 失败保留；SSH 仅出站已通过 6 项 Rust、原生 OpenSSH 140 项和同进程 HTTP→SSH 200 项检查。各自范围见模块测试记录，未做当前全部模块整树验收。
- SSR、ShadowTLS首轮之后的测试步骤遇到工具内容风险检查中断，已完成已有作业及快照的只读交接；SSR的IV-only源码修正已通过两项纯回归，间歇EOF/HMAC问题未登记解决，ShadowTLS原未验步骤不恢复。现有通过与未修边界见模块测试记录。Gost Relay已通过15项Rust、严格Clippy、fmt与专用CLI构建，官方64配置704条记录及28项原始FIN阶段通过；官方零包与大包边界单列。当前任务未全部完成，没有开始发行或发布凭据。
- Mieru限定交付通过21项模块Rust及3项配置测试、严格Clippy/格式和专用CLI构建；官方API两个版本及原Mihomo分别88/88配置、176/176普通检查通过，生命周期与长度边界另列。默认TCP与Full Cone经统一出口；原UDP线格式仅显式本机不安全兼容，不能登记公网UDP。见[完整记录](docs/testing/mieru.md)。
- TrustTunnel r12的20项Rust、选定检查/构建与自端240/240通过；后续风险检查具体触发动作未知，已只读交接且不重试。H2窗口修正仅本地已写未编译，外部对端仍失败；回环旁路成功不计代理互通，IPv6缺口保留。Naive限定交付已完成：native-r12的26项Rust/严格检查及156配置900常规检查、同进程28检查通过，原资产边界另列。证书资产迁移后native-assets-r1又通过26项及6项资产控制、严格Clippy/fmt/限定构建；生产TLS/denylist未变，根锁未覆盖。详见模块记录，不外推整树。
- 公共流连接器与包装凭据域的 2 项回归、SS 9 项和 SS2022 8 项包级测试及严格 Clippy 已在 perf-01 通过；SS 夹具端口碰撞已修复并复验，结果不外推 ShadowTLS 真实对端。
- Sudoku r4的库49/49、预算1/1、HTTP6/6、Mux4/6、协议11/12通过，CLI构建通过；Mux两项及32MiB原期限失败保留。r5定向诊断中plain控制2项通过、Record+Obfs控制2项超时，原Mux仍4/6；legacy伪POST/伪Upgrade回归通过，Clippy/fmt通过。独立profiling仅解释旧r5输入的pure Encoder热点；最后table.rs/obfs.rs含被中断的性能增量，未经过任何构建/fmt/检查/测试，不能登记修复。两个原生参考CLI未启动互通，见[测试](docs/testing/sudoku.md)。
- 共享h3 0.0.8回移官方经典CONNECT伪头修正，并按实际字段计数；后补伪头唯一性/顺序拒绝，perf-01隔离原语测试21/21、默认/all-features库检查及格式通过，219项过滤。来源、失败和边界见third_party/h3/PATCHES.md；协议旧冻结输入继续独立保留，须各自复验新依赖，不外推TrustTunnel/Naive或旧Root的H3互通。
- 鉴权与秘密隔离集合分离接口已在perf-02全新六包冻结快照通过7项测试（core2、配置3、流注入2）、格式及严格Clippy；见[公共契约记录](docs/testing/credential-isolation-contract.md)。注册表只用鉴权集合判断nodes资格，用两集合并集拒绝跨条目复用；空隔离覆盖不能隐藏真实鉴权。Mieru实际秘密/身份域适配另随其完整首轮验证，不外推本次7项结果。
- 1.0准备仅完成依赖/feature metadata：27工作区包、522总包，全部21协议feature已解析；整树cargo check及Rustdoc尚未启动。公共API补充仅5文件文档注释，非注释源码核对不变，仍待统一检查。第三方许可材料在私有目录，项目许可、实际链接范围、12包文本缺口等未解决。相关作业只读确认均已终态，没有继续构建或测试；许可与API审阅见[停点审计](docs/releases/1.0.0-readonly-audit.md)。

仓库：[yuuuki-creation/kerlico](https://github.com/yuuuki-creation/kerlico)。资料与提交说明使用简体中文；作者、提交者固定为 `Anonymous <anonymous@example.invalid>`，不签名、不添加身份 trailer。凭证、原始日志和产物留在被忽略的 `.private/` 或专用 worker，不能进入 Git。

## 已确认的约束

- Rust 源码按功能和协议拆分，最终同一个可执行程序按配置承担客户端、服务端或两者。
- IPv4、IPv6服务端节点分别创建，认证凭据独立；同协议跨节点重复凭据在配置阶段拒绝。目标设计由共享出站模块先区分本地和远端：本地按节点单栈/双栈模式，双栈默认IPv4优先并由设备WARP补缺族；远端保留原目标自行处理。节点、代理载体和网站的地址族互不绑定，最新设计不等于当前实现已验收。
- 协议流程固定为“调研 → 编写 → 测试 → 修改”，第一次一次写完本轮完整范围，再集中测试与修改。
- 所有新增内容和对话遵循格莱斯准则。编译、格式、静态检查和测试只在专用 worker 执行，本地只编辑、阅读、同步和管理 Git。
- 上轮两个子代理分别处理 AnyTLS、SS2022，主任务继续 VLESS并保存快照。用户随后已重新要求多代理同时推进剩余协议，本轮实际分工与结果见上文。

## 已实现与验证范围

| 项目 | 已有结果 | 证据入口 |
| --- | --- | --- |
| 双端框架、独立节点与统一出口 | 历史三协议 35 项；首批八模块冻结 CLI 的 16 节点、两类目标、凭据隔离、并发、退出与重启 81 项通过 | [节点接口](docs/interfaces/node-egress.md)、[首批记录](docs/testing/protocol-batch-1.md) |
| AnyTLS | 原生 Rust TLS 双端、会话复用、padding、TCP/UoT v2；19 项 CLI 集成通过；停写回包修正后包级、回归及真实对端合计 11 项测试通过 | [接口](docs/interfaces/anytls.md)、[测试](docs/testing/anytls.md) |
| SS2022 | 三算法双端 TCP/原生 UDP，AES 终端 EIH 多用户及客户端身份链；8 项 Rust 测试、88 项限定互通及 17 组 CLI 集成通过 | [接口](docs/interfaces/ss2022.md)、[测试](docs/testing/ss2022.md) |
| SOCKS/HTTP | SOCKS 11 项、HTTP 7 项集成通过；固定 sing-box 52 项检查通过，4 项参考入口空包限制单列 | [SOCKS 测试](docs/testing/socks.md)、[HTTP 测试](docs/testing/http-proxy.md) |
| Shadowsocks AEAD/legacy | 45 方法自端、9 项 Rust 与 312 项限定真实对端检查通过；未列方法与长度不外推 | [接口](docs/interfaces/shadowsocks.md)、[测试](docs/testing/shadowsocks.md) |
| Trojan | 11 项 Rust、严格 Clippy、固定 Xray 20/20 双向组合通过；UDP 对端长度限制单列 | [接口](docs/interfaces/trojan.md)、[测试](docs/testing/trojan.md) |
| VMess | 11 项 Rust、严格 Clippy、Xray 48/48 和 sing-box RAW 16/16 配置通过；大包与地址族边界单列 | [接口](docs/interfaces/vmess.md)、[测试](docs/testing/vmess.md) |
| Hysteria v1 | 16 项 Rust、官方 24/24 与 sing-box 12/12 限定组合；对端大包、FIN 边界单列 | [测试](docs/testing/hysteria1.md) |
| ShadowQUIC | v1 原固定 Mihomo 24 配置通过；v2 受控 Go 参照 24 配置通过，原 Mihomo v2 仍失败 | [测试](docs/testing/shadowquic.md) |
| SSH | 仅 direct-tcpip 出站；6 项 Rust、OpenSSH 原生 140 项、HTTP→SSH 200 项检查通过 | [测试](docs/testing/ssh.md) |
| Gost Relay | 仅 CONNECT 出站；15项Rust、官方64配置704条记录及28项FIN阶段通过；无Full Cone，官方零包/大包限制单列 | [测试](docs/testing/gost-relay.md) |
| Mieru | 默认TCP双端、真实复用与Full Cone包隧道；21项模块及3项配置测试、三个对端各88配置通过；原UDP仅本机不安全兼容 | [接口](docs/interfaces/mieru.md)、[测试](docs/testing/mieru.md) |
| VLESS 普通及扩展组合 | RAW/WS/HTTPUpgrade/gRPC/XHTTP、TLS/REALITY、Vision、Encryption 等基础完整矩阵，客户端与服务端各 394/394 配置通过 | [接口](docs/interfaces/vless.md)、[快照记录](docs/testing/vless-combinations.md) |
| VLESS ML-KEM | TCP 测试矩阵双向各 44/44 配置通过；其中包含未加密基线，不能把 44 项全部称作 ML-KEM 加密场景 | 同上 |
| Vision 记录边界 | 按帧边界读取的独立回归通过，真实 REALITY+Vision 重复测试 30/30 通过 | 同上 |
| XHTTP 上下行分离 | 独立 CA/SNI、IPv4 上传与 IPv6 下载、H1/H2/H3 组合及错误证书/名称共 10/10 场景通过；含 H3 的场景为自端互通 | 同上 |
| XDRIVE | local、HTTP template、S3 模拟服务的双向互通共 6/6 场景通过；没有使用真实云账户 | 同上 |
| packetaddr | 固定 sing-box 双向、两种节点地址族、两类目标及 17/4096/12000 字节，共 4/4 场景通过 | 同上 |
| 构建与检查 | 早期完整工作区 49 项默认 Rust 测试通过；后续 VLESS 包级最新快照 27 项通过，格式、Clippy 和构建通过；另有早期 release 构建成功 | 同上，结果不外推到最新未验证增量 |

## 尚未完成项

1. 恢复时的生命周期与升级增量已纳入原树 55 项远端测试和构建；新协议、物理地址上下文与本地动态入口加入后，仍须完成最终整树、功能裁剪及真实组合复验，不能用原树通过结果代替当前全部代码验收。
2. Mux 额外客户端矩阵已复跑 30/30 通过；它只覆盖脚本选择的传输/安全/flow 与复用开关，不替代其他 Encryption、对端、角色或跨载体会话验收。
3. 工具已增加 `hybrid` 密钥选项，但混合 NFS 链尚未运行对应互通。ML-DSA 验签、真实 Google Drive/S3 账户、槽环完整互通和长期压力也未完成验收。
4. XUDP 服务端尚无跨物理载体迁移的全局 UDP 会话表。mKCP、反向代理控制面、TUN/Fake-IP、规则语言、热重载和项目整体许可证不属于本次已验证交付。
5. 当前构建基线为 **Rust 1.99.1、Linux x86_64**。隔离 1.96 容器实际被固定 `rust-reality` 及 `rr-*` 包的 1.99 要求拒绝。旧版 macOS/Rust 1.88 结果仅适用于已发布 0.1。
6. 0009至0011的共享出站、节点模式/WARP、管理用户身份、逐用户流量/带宽与访问历史仍是设计目标，未完成源码迁移或验证。

## 历史停点的恢复条件

以下三项保留此前停止时的要求。用户已经明确恢复当前任务，现阶段按本文开头和最新执行授权继续，不能再次将旧停点当成当前停止指令。

恢复开发后先读取 `AGENTS.md`、本文和[快照记录](docs/testing/vless-combinations.md)：

1. 先得到用户明确继续指令；此前不修复、不构建测试或发布。保留全部未验源码及失败，不以停用模块制造通过，原风险中断步骤不自动恢复。
2. 若继续，先核对当前源码/锁与已验证快照的差异，尤其Sudoku未验性能增量、SSR/ShadowTLS/TrustTunnel边界；再在worker完成整树、API、裁剪与组合验收。
3. 1.0.0须另完成许可、匿名历史和正式产物门槛后才发布，见[发行计划](docs/release-1.0.0.md)。本次只保存开发快照，不构成正式版验收。

## 资料导航

[设计导航](docs/README.md) · [接口](docs/interfaces/README.md) · [协议与组合唯一总表](reference/reports/三核心%20协议%20组合支持.md) · [借鉴映射](reference/design-map.md) · [仓库约定](docs/repository-workflow.md) · [匿名规则](docs/anonymity.md)
