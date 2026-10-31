# 项目状态

更新日期：2026-10-31，Asia/Shanghai。

当前阶段：**用户已要求停止修复，更新文档、提交push快照后结束本轮。** 当前保留21个协议模块，17个已有范围明确的验证快照，SSR、ShadowTLS、TrustTunnel与Sudoku仍未完成收尾。1.0.0仅保留发行计划，未发布、未建正式标签；后续须明确继续指令，不能自动恢复开发或验证。

## 本轮进行中

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
- IPv4、IPv6 服务端节点分别创建，认证凭据独立；同协议跨节点重复凭据在配置阶段拒绝。各协议通过统一 `AccessService` 访问网站目标，由 `egress` 默认优先 IPv4；节点、代理载体和网站的地址族互不绑定。
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

## 后续恢复条件

恢复开发后先读取 `AGENTS.md`、本文和[快照记录](docs/testing/vless-combinations.md)：

1. 先得到用户明确继续指令；此前不修复、不构建测试或发布。保留全部未验源码及失败，不以停用模块制造通过，原风险中断步骤不自动恢复。
2. 若继续，先核对当前源码/锁与已验证快照的差异，尤其Sudoku未验性能增量、SSR/ShadowTLS/TrustTunnel边界；再在worker完成整树、API、裁剪与组合验收。
3. 1.0.0须另完成许可、匿名历史和正式产物门槛后才发布，见[发行计划](docs/release-1.0.0.md)。本次只保存开发快照，不构成正式版验收。

## 资料导航

[设计导航](docs/README.md) · [接口](docs/interfaces/README.md) · [协议与组合唯一总表](reference/reports/三核心%20协议%20组合支持.md) · [借鉴映射](reference/design-map.md) · [仓库约定](docs/repository-workflow.md) · [匿名规则](docs/anonymity.md)
