# TrustTunnel 测试与停止交接

日期：2026-10-31。对应总表P-18。**当前未完成交付；仅完成已有证据的只读交接，不恢复原构建、测试或互通。** 最近完整包级通过快照为perf-02的r12：20项Rust、fmt、选定包/专用CLI严格Clippy及构建。当前本地另有两个文件的H2增量，未同步、未编译、未验证，不能外推r12通过结果。

## 停止原因与实际作业状态

主任务通知本轮遇到通用内容风险检查中断；本子任务未收到可识别具体动作或理由的直接拒绝回执，**确切触发动作和原因未知**。停止前的已知阶段是matrix-r12串行互通及本地H2连接credit修正编写，不能据此推定其中某一步触发中断。停止后仅读取既有状态、日志、源码与产物，并保存本地交接资料，没有改说法、换工具重试或启动新验证。

2026-10-31 02:52 UTC只读实机核对：20个已知作业全部有终态；没有live的构建、kerlico、官方/Mihomo对端或测试runner。仅本轮签名核对创建的项目私有keyring `gpg-agent`仍sleeping，实际PID/PPID保存在私有交接记录；按只读范围未终止它，不将其记作代理服务或已有业务服务。

| 命令标签 | 终态 | 实际阶段/限制 |
| --- | --- | --- |
| trusttunnel-r1 | 101 | metadata加载裁剪清单失败：缺egress的既有SS/SS2022 dev依赖，尚未编译TT |
| trusttunnel-r2 | 101 | 集成夹具读写半流次序写反，测试编译失败 |
| trusttunnel-r3 | 101 | 单元8通过、网络2通过/9失败；夹具JSON缺必需inbounds数组 |
| trusttunnel-r4 | 101 | 单元8、网络10通过；_check未结束请求引发RST |
| trusttunnel-r5 | 101 | 修正控制请求END_STREAM/FIN；剩余失败为活动H3退出后监听socket未及时释放 |
| trusttunnel-r6 | 101 | 19项Rust通过；选定包Clippy发现宏内相邻if及大枚举布局 |
| trusttunnel-r7 | 101 | 新增socket/poller释放回归，20项Rust通过；Clippy指出测试宏内相邻if |
| trusttunnel-r8 | 101 | 20项Rust通过；Clippy指出测试Default后赋值 |
| trusttunnel-r9 | 0 | 20项Rust、fmt、包/专用CLI严格Clippy、构建与工具语法检查通过 |
| trusttunnel-r10 | 0 | 独立出站UDP额度及释放再用增量，20项及上述检查通过 |
| trusttunnel-r11 | 0 | UDP双半持有额度/释放及关闭载体驱动清理，20项及上述检查通过；h3旧headers输入 |
| trusttunnel-r12 | 0 | 共享h3伪头唯一性/顺序增量纳入，20项及上述检查通过；H2连接credit仍为旧值 |
| reference-r1 | 0 | 两官方稳定归档摘要/签名/版本核对，不是协议互通 |
| mihomo-reference-r1 | 0 | 固定Mihomo摘要/版本核对，不是TT互通 |
| interop-self-r1 | 1 | 240记录中224通过/16失败；工具反复换UDP源，H1物理需求超过配置4 |
| interop-self-r2 | 1 | 稳定UDP源后236/240；剩4项为2 UDP+4 TCP需求6超过配置4 |
| interop-self-r3 | 0 | 工具显式配8个物理名额承载6连接需求；240/240，内核默认4/数据队列均未扩大 |
| interop-r11 | 1 | 自端240/240；官方原矩阵失败；因set-e后续Mihomo/wire未启动，不能填绿 |
| official-h1-control-r12 | 0 | 不先发送边界包的H1干净对照：30通过、2未测；TCP双族/并发正常 |
| matrix-r12 | 1 | 六套件均已跑完，具体计数与重分类见下表 |

每个命令标签的原始脚本、stdout/stderr、exit、日志SHA256均保存在私有目录。统一构建使用1个并发任务；10成员过滤快照只含必要已完成依赖及TT专用CLI，未执行其他协议自身测试或WIP整树。包与CLI的-D warnings通过；h3依赖仍输出9条既有警告及裁剪图未用patch提示，不宣称整个依赖树零警告。

## 最后完整通过快照与当前增量

| 对象 | SHA256 |
| --- | --- |
| r12 TT模块10文件 | `573d3bd508b8929fc41c4a26555252bc401b16c85c52552a8ac61df3f0c23a4c` |
| r12构建输入文件集合 | `e27165b803ae8a1689285b7672d03d7c0210a06a0403cbc8765f22c4c51b4c90` |
| r12专用CLI | `220a767913e34e1bce4a69fa579831258ebbb6de71bbbe9dacd0101e6f048d73` |
| r12实际worker锁 | `db8c05ac2181cb64cca2d930efb825a735655caf8fbc2dc8e066cd5badb2f452` |
| matrix-r12实际工具 | `e0bb21ab31e8b964ebceffd844dbd07915265ae0af151801dd4eefcb75cbc764` |
| 当前本地未验TT模块 | `1832a4da92caaaa2deb8b18b8e2d7a1251ec27019033dec254377e85ff57c3ce` |

模块/文件集合摘要算法：按相对路径排序，拼接`路径\0文件SHA256\0`后再SHA256。精确文件清单、匿名元数据源码归档、锁、日志与产物摘要存于私有交接资料；worker锁没有覆盖共享根锁。r11旧CLI及原矩阵单独保留，不能与r12新h3输入混同。

r12共享h3 headers.rs为`484e98d6507cc5abc6a7d1d03a8a2e9e36a33ca32258e2170b1fcf583a852805`；其21项请求/QPACK回归由公共任务另行记录，不计入本包20项。r11旧headers为`bfed028d619cbb5755f35a03357c69dab2cba3f0aa50cea004fe26e8d03723c3`。

当前与r12 worker包源码相比仅两文件变化，均**尚未同步到worker**：

- `src/client.rs`：已写H2客户端连接接收窗口2MiB，stream窗口仍131072；未编译/格式/Clippy或互通复验。
- `src/io.rs`：已写`h2_connection_credit_allows_atomic_large_udp_reply_after_small_replies`，模拟完整记录credit不足即丢包的H2响应端；该新增第21项测试**未运行**，不能写成通过。

依据是固定官方H2 DroppingSink要求当前credit覆盖整条UDP记录，以及r12四个65000字节回写超时；连接credit不足是待验证解释，新代码意图不等于问题已经解决。两文件差异已另存私有patch，未修改Node虚拟source端口条件，也未修Mihomo证书夹具。

## r12实际执行的20项测试

| 实际测试名 | 结果 |
| --- | --- |
| `config::tests::versions_and_limits_reject_unimplemented_options` | 通过 |
| `config::tests::basic_is_actual_authentication_and_password_is_extra_isolation` | 通过 |
| `http1::tests::oversized_h1_header_is_rejected_before_send` | 通过 |
| `server::tests::literal_domain_and_special_authorities_are_separate` | 通过 |
| `http1::tests::exact_header_preserves_early_tunnel_and_rejects_duplicate_auth` | 通过 |
| `udp::tests::hostile_lengths_and_truncation_are_bounded` | 通过 |
| `socket::tests::closing_quic_socket_releases_bind_even_when_native_pollers_are_still_owned` | 通过 |
| `udp::tests::zero_packet_ipv6_and_split_records_are_not_eof` | 通过 |
| `udp::tests::one_http_stream_has_separate_budgeted_flows_and_uses_access_peer_metadata` | 通过 |
| `disabled_udp_and_connect_deadline_are_explicit` | 通过 |
| `h1_health_and_icmp_responses_authenticate_before_unsupported` | 通过 |
| `bounded_pool_rejects_excess_streams_and_releases_cancelled_udp` | 通过 |
| `authentication_and_tls_failure_never_reach_business_target` | 通过 |
| `invalid_options_are_rejected_and_capabilities_match_physical_carrier` | 通过 |
| `immediate_target_eof_keeps_all_queued_data_across_http_flow_control` | 通过 |
| `real_credentials_and_additional_secret_domain_both_reject_cross_node_reuse` | 通过 |
| `all_five_tls_paths_both_node_families_and_both_business_families` | 通过 |
| `multiuser_basic_remains_required_with_optional_mtls` | 通过 |
| `same_target_udp_channels_keep_distinct_fixed_flows_and_domain_uses_egress` | 通过 |
| `idle_pool_is_reaped_health_uses_no_business_target_and_active_shutdown_is_bounded` | 通过 |

其中完整数据测试覆盖H1/TLS1.2、H1/TLS1.3、H2/TLS1.2、H2/TLS1.3、H3/TLS1.3；双节点/目标地址族、TCP17/4096/65536/262144、UDP0/17/4096/12000/65507、mTLS、多用户、真实HTTP/TT凭据域、统一Egress、预算/取消/空闲/退出等。该句只属于r12冻结输入，不含新增第21项。

## 真实互通与受控peer

固定参考：官方endpoint v1.1.0（二进制`9bb15f4e30e2ff196cf0aa387462c42387d9405ddfeb5caad133838560fa33cd`）、client v1.1.11（`e01411457f65c498063211fa670d55ea710d3a2d35534acd73438bd514df454a`）；归档摘要、固定公开密钥指纹和RSA签名已核对。Mihomo v1.19.33二进制为`817f50b3ac6a8b1c4360c5cf2961906057f3a883d970ebbcb0028a01632b620f`，tag对应研究commit。没有把参考程序作为内核数据路径实现。

下表计数为原始记录的pass/fail/observed-limit/not-tested；拒绝和进程退出记录也在pass中，不能全算业务成功。

| r12套件 | exit | 通过 | 失败 | 观察限制 | 未测 |
| --- | --- | --- | --- | --- | --- |
| self-r12 | 0 | 240 | 0 | 0 | 0 |
| official-r12 | 1 | 216 | 5 | 0 | 17 |
| mihomo-r12 | 1 | 54 | 60 | 36 | 4 |
| mihomo-mtls-r12 | 1 | 12 | 68 | 24 | 4 |
| wire-r12 | 0 | 96 | 0 | 0 | 0 |
| wire-mtls-r12 | 0 | 96 | 0 | 0 | 0 |

- 自端240/240；受控标准TLS/H1 wire节点96/96及其mTLS96/96通过。wire是本工具按规范编写的peer，不冒充官方H1客户端；官方CLI无H1上游选项。
- 官方r12的五个失败是H2客户端两TLS版本/两节点族的65000字节UDP回写四次超时，及官方客户端→本节点H3/IPv6的一次setup RuntimeError。后者没有完成定位，不能归因于协议解码。其他记录按实际执行角色保留，不登记全官方双向通过。
- 官方client固定源码对loopback目标硬编码VPN_CA_FORCE_BYPASS，Core killswitch也不覆盖此分支。r11原始195/51/42/18包含该旁路，已经保留原件并重分类为111通过、39失败、30限制观察、18未测、102路由无效、6仅进程退出；102条不能当TT鉴权/业务证据，错误Basic取得旁路回包不是本项目认证绕过。
- r12官方节点方向改用worker已存在的私有IPv4自有目标，错误凭据与正例均重新执行；没有增加地址或修改路由/服务。没有可用ULA，官方客户端IPv6业务目标缺条件，保持未测。Mihomo与自端的回环目标不受这个官方分支推定覆盖。
- 官方UDP零包/极限长度在r11已观察限制。其固定Dropping分支返回被丢弃前缀而非剩余tail，源码与边界后后续流失败相关；H1无边界包干净对照30通过。没有证明它是所有失败的唯一原因，原耦合序列失败未删除；r12正常矩阵不反复触发旧超限解析路径。
- Mihomo原始54个pass中只有36条TCP/并发业务正例；其余是拒绝/退出。listener证书路径被自身SAFE_PATHS拒绝、有效H3客户端出现unknown authority，均有实际日志；不能把未到达协议层的失败写成H3不兼容。固定Mihomo上行source写unknown 0:0，而本项目Node当前拒绝source port0，存在明确约束冲突，**未修、未复验**，不能把UDP失败全部归入证书夹具。
- Mihomo mTLS原始12个pass均为拒绝/退出，**没有业务正例**。证书路径/信任夹具与UDP约束未处理，不登记mTLS真实对端通过。

## 保留边界与交接位置

固定UDP不是DatagramAssociation/Full Cone；ICMP只保留认证后501/Unsupported，不运行原始socket权限实验。TCP通用tcp_eof仍false；没有性能、长期压力、跨平台或流量不可区分结论。

私有入口：`.private/builds/trusttunnel/readonly-handoff-r12.json`（完整exit/PID/脚本/日志与实际测试名）、`handoff-summary.json`、`r12-frozen-source.tar.gz`、`unverified-since-r12.patch`、各suite handoff-result、原始/重分类official-r11记录，以及独立锁/产物摘要。当前没有恢复后续步骤的授权；维持此停点，不启动r13或新对端探针。
