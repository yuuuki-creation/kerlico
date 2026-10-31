# Sudoku 首轮测试记录

更新日期：2026-10-31。**用户已要求停止修复并保存快照；没有继续验证。** r4库49/49、预算1/1、HTTP6/6、Mux4/6、协议11/12及专用CLI构建通过；r5定向诊断仍有超时，Clippy/fmt通过。当前两个性能源码文件含未验证增量，不等于上述快照；尚未完成全包或原生参考互通，不登记交付。

## 当前证据与本轮边界

完整首轮生产、文档、测试及工具写齐后，已在perf-01建立全新过滤快照并接入真实CLI注册。`vectors-r1`终态1：上游现有测试依赖testify v1.12.1不在研究探针的离线缓存，Go在包设置阶段失败，未执行纯导出测试、未生成fixture，也未开始Rust构建。保留失败日志；下一轮先按固定依赖下载缺少模块，导出过程仍禁用模块联网并固定只读依赖模式。

`vectors-r2`已终态0：两项固定Mihomo同包纯导出测试通过，生成6条KIP、9条UoT及两个AEAD方法的记录向量，并包含初始/会话双向派生。testify依赖只在准备阶段下载；导出时GOPROXY/GOSUMDB关闭、依赖只读，两个导出桥接之外的源码在测试前后均未变化。合成fixture已保存，SHA256为 `d8c50710da063a40288ca15a3a957e2fb6254737ad32b7fd921614effaa86321`。这不是Rust向量消费通过，也不是网络互通。

源码复核另发现待集中复验问题：FIN确认失败需永久锁存；复用HTTP首部和mux新逻辑流不能继承首次握手剩余预算；原生H1客户端未声明TE时Hyper会丢EOF trailer。修正和额外FIN/预算回归均已写，原生无TE H1兼容适配器已接入并另写7项回归，均无通过结果。依赖准备与源码复核分开记录，不把Go导出通过计作这些修正验收。`dependencies-r1`已终态0，仅生成独立锁和下载依赖，尚未编译Rust源码。

上述修正全部写齐后重新冻结；统一作业依次执行模块fmt、全包测试、严格Clippy、fmt复核及专用CLI构建。根Cargo.lock未被专用resolver覆盖，独立锁只存私有记录。

`rust-r1`实际终态101：库编译成功，40项库测试中39通过、1失败；失败为mux::tests::remote_fin_data_survives_physical_carrier_eof，accept的取消优先分支抢在已排队Open/Data/Fin之前返回Cancelled。集成测试、Clippy、fmt复核及CLI构建均未执行。格式化包快照已取回；修正改为先保留已排队且收到Fin、未Reset的逻辑流，节点父级取消仍立即拒绝，等待整包复验。另按本轮编译告警清理未用项及原子API弃用；不将39项结果外推到修正后输入。

`rust-r2`实际终态101：库40/40、独立后续首部预算1/1通过，HTTP控制5/6通过。失败输入包含多个Connection字段，服务端只取首个值导致在鉴权前错误返回400，未到测试期待的404；已按列表字段语义改为遍历全部Connection/Upgrade值，等待整包复验。Mux/协议集成、Clippy及CLI仍未执行，不把前述结果外推修正后输入。

`rust-r3`实际终态101：同一输入库40/40、预算1/1及HTTP控制6/6通过，Mux集成4/6通过；真实16流与慢流隔离两项在exchange的8秒读写预算内超时，已交独立定位，不放宽期限或减少负载绕过。协议集成与后续检查当时未执行。`remaining-r3`继续使用原冻结输入，运行尚未执行的protocol矩阵、Clippy、fmt和CLI构建，并分别保存状态；本地Mux修正不能混入该轮输入。原失败保持保留，不按局部通过登记整包完成。

`remaining-r3`实际终态1：协议矩阵9/12通过，471.21秒；32MiB双向重钥120秒超时、TLS真实mux并发8秒超时、双节点测试的正向接入early EOF三项失败。fmt复核通过；Clippy有9项错误。CLI过滤快照误删了.workspace形式的四个基础依赖，导致编译失败；产品原始清单未缺依赖，已修快照工具，下一轮重新生成专用resolver锁。日志与原冻结输入保留，不能把该失败登记为协议运行或平台缺失能力。

集中修改已写齐并冻结为`rust-r4`：双向共享唤醒器、单任务mux驱动及7项真实背压/放弃Future回归；表解码改用四hint组合查表并遍历64选四对原bitset解码；Auto在精确根探测路径接纳legacy、保留API路由。未改变载体/负载/重钥阈值或期限。r4重新生成修正过滤器后的专用锁，使用全包no-fail-fast并分别记录测试、Clippy、fmt和CLI终态，尚未全部结束。已有纯向量和新等价/双任务回归的单项成功不替代整包验收。

## 本轮停止时的实际结果

- `rust-r4`终态1：库49/49、预算1/1、HTTP6/6、Mux4/6、protocol11/12。失败为两项Mux原8秒超时及真实32MiB双向120秒超时；后者仅观察到257个32768字节块以上的进展，未证明跨更新完成。Clippy有3项测试代码告警，fmt及专用CLI构建通过；CLI摘要`c174ae55941f2ae9b86e3953d637399c6e880983d01bde58d8a837e76c081dfb`不是正式版产物。
- `rust-r5-diagnostics`终态1：plain relay控制2项通过、Record+Obfs控制2项8秒超时；原Mux仍4/6。目标字节、EOF、尾部和shutdown计数证明有持续进展，不能简单登记为已修复死锁；legacy伪POST/伪Upgrade后的真实KIP回归1项通过，Clippy/fmt通过。控制组19.545秒中user CPU为19.388秒；原Mux26.775秒中user CPU为23.344秒，仅作为诊断。
- 独立profiling固定旧r5算法，debug/opt3各精确1项、33个阶段记录通过，没有网络目标或生产源码算法变更。256KiB pure padding0 Encoder分别1034.1/25.3毫秒，说明未优化构建中的主要CPU成本在pure Encoder；优化模式是额外诊断，不替代原期限失败，也不证明新算法已通过。
- 停止时`src/codec/table.rs`和`obfs.rs`已写入n×24单次Uniform、24排列与采样缓存等性能增量及4项新回归，但本轮编码被用户中断，**没有运行任何构建、fmt、静态检查、测试或互通**。恢复前必须先审查整项增量，不能把旧LUT/Go向量或profiling结果外推到它。
- 两个固定原生参考CLI仅完成构建/源码核对，没有启动监听或互通。所有本项拥有的worker编译/测试作业均已终态，profiling与参考准备PID只读核对均不存在。

以上结果保留原负载、期限、失败与私有证据；当前只保存开发快照，后续得到明确继续指令才恢复。

研究阶段`tools/sudoku_reference_probe`在perf-01使用固定未修改Mihomo API，得到8条early握手语义、2条错误seed控制和8组表/流向量。该程序没有网络目标连接，不能证明完整参考客户端或服务端可用；原来源/摘要和研究结论保持不变。见[研究](../../reference/research_notes/sudoku.md)、[接口](../interfaces/sudoku.md)。

本轮完整范围为原生Rust双端、六载体raw/legacy/stream/poll/auto/ws、AES-128-GCM/ChaCha20-Poly1305及显式本地none、四方向表和pure/packed、自定义轮换、split TLS H1/H2与WS TLS H1、真实TCP mux、逐包多目标UoT，以及Registry/Engine独立节点和统一出口。角色、载体、方法、表、TLS、TCP/UDP、包长逐维记录；不声称每个维度已经做全部笛卡尔积。

none只允许回环字面出站和显式local_inbounds，没有可靠AEAD鉴权。seed规范化后是实际共享秘密，形似公钥的材料也不能公开；UserHash不是独立认证。原官方Go程序管理API/名单、反向隧道以及Mihomo适配器外层sing-mux私有扩展不在本轮范围；Sudoku自身9字节帧的TCP session mux属于本轮完整双向交付与真实对端验证范围。

## 已写集成测试：首轮24项，新增预算回归待执行

以下通过公开工厂构造Registry/Engine，包装器只在测试侧计数物理入口、捕获解码目标与预算；不增加生产后门。内存回声目标只作AccessService注入，另有真实Direct出口与双Engine测试。

| 文件 | 实际测试名 | 待验证断言 |
| --- | --- | --- |
| protocol | `six_carriers_three_methods_dual_stack_tcp_and_uot` | 六载体、三方法、两节点族、三类目标；TCP目标先发/数据/适用EOF，固定目标UDP 0/1/4096/65507 |
| protocol | `table_directions_pure_packed_padding_and_rotated_layouts` | raw/stream/poll/ws、四表、pure/packed、padding与两布局轮换 |
| protocol | `tls_h1_h2_split_and_h1_websocket_validate_chain_and_name` | split H1/H2、WS H1、两节点族、空UDP，错误CA和名称拒绝 |
| protocol | `two_node_credentials_never_cross_accept_or_fallback` | 同进程IPv4/IPv6节点独立seed，各载体错误seed不得到目标数据或访问出口 |
| protocol | `normalized_seed_aliases_and_none_obey_registry_gates` | 主标量/不同拆分/压缩点/大小写别名查重，none准入和秘密隔离 |
| protocol | `public_looking_and_split_key_aliases_use_the_same_real_secret` | 同一有效seed多种材料都能接入单节点，不伪称私钥所有权证明 |
| protocol | `uot_multi_target_empty_maximum_reject_oversize_and_keep_association` | 单关联多目标，空包/65507/65508拒绝后恢复，地址来源和取消 |
| protocol | `real_direct_egress_preserves_source_port_and_full_cone_unsolicited_source` | 真实UDP出口跨目标/跨族源端口保持、空包和65507、未预联系来源 |
| protocol | `tcp_rekey_crosses_32_mib_in_both_directions_without_tail_loss` | 真实双向32MiB以上内容和FIN尾部；独立120秒预算，未降低更新阈值 |
| protocol | `both_engines_forward_tcp_udp_and_validate_websocket_eof_capability` | 两个Engine之间实际TCP/UDP-forward，空包/65507与WS普通流EOF门槛 |
| protocol | `disabled_udp_and_rejected_target_do_not_create_association` | 双端UDP能力关闭、拒绝目标和后续有效TCP |
| protocol | `tls_h2_mux_concurrent_streams_share_transport_and_independent_fin` | TLS H1/H2上的单载体真实mux、八逻辑流及独立FIN |
| mux | `real_mux_uses_one_carrier_for_concurrent_distinct_targets_and_fin` | 六载体、16并发目标、物理入口计数不增长、FIN尾部 |
| mux | `logical_cancel_reset_and_target_rejection_leave_siblings_alive` | 单流取消/Reset/目标拒绝不关闭同载体兄弟流 |
| mux | `slow_stream_backpressure_does_not_block_another_stream` | 受控慢目标和超过队列大小的写入，其他流可用，取消释放 |
| mux | `mux_pool_limits_released_slots_and_idle_carrier_replacement` | 单池两流上限、逻辑名额归还、显式空闲截止与新载体替换 |
| mux | `server_logical_budget_recovers_after_cancel_and_client_drop` | 全局/节点共同预算耗尽、取消/客户端释放后名额全部归还 |
| mux | `root_shutdown_terminates_mux_uot_and_releases_backend_tasks` | 活动mux/UoT根取消，有界排空和后台任务归还 |
| http_controls | `http_paths_methods_query_and_mode_controls_do_not_reach_egress` | 真HTTP路径/方法/重复查询/early非法输入及模式门槛 |
| http_controls | `actual_http_upload_sequence_duplicate_conflict_gap_and_close` | 真HTTP上传序号、同批幂等、冲突/缺口/模式混用拒绝和close；FIN内部状态另验 |
| http_controls | `http_tokens_are_node_and_mode_bound_expire_and_release_quota` | token节点/模式隔离、会话上限、TTL后失效及名额归还 |
| http_controls | `invalid_websocket_auth_early_data_and_oversized_http_are_bounded` | 错WS认证/版本/key/path、坏early、声明超限上传及32KiB首部上限 |
| http_controls | `cover_fallback_is_fixed_target_safe_get_head_only` | 固定cover只接受安全GET/HEAD，不传任意目标路径或代理正文 |
| http_controls | `signed_websocket_masked_fragment_ping_and_invalid_unmasked_frame` | 真签名升级、mask空分片、Ping/Pong及非法未mask帧关闭，无业务出口 |

集中修正后新增budgets::later_h1_headers_use_a_fresh_budget_after_slow_initial_classification：首次首部消耗1.3秒、后续首部再等待1秒，后续请求仍应获得节点标准2秒预算，而非继承首次剩余量。另新增client内部rejected_fin_stays_failed_across_shutdown_and_flush，验证FIN拒绝/超时后连续shutdown/flush不能改报成功，已知反向尾部仍可读取；两项均待执行。

源码：[protocol](../../crates/protocol-sudoku/tests/protocol.rs)、[mux](../../crates/protocol-sudoku/tests/mux.rs)、[HTTP控制](../../crates/protocol-sudoku/tests/http_controls.rs)。测试侧内存目标与真实出口结果必须区分。

## 生产原语回归和新独立Go向量

既有源码回归覆盖Go Shuffle/table/clue/pure/packed向量、非法布局、部分读写和EOF、seed材料归一、双向派生/低阶点、KIP长度/nonce/特性/时间、AEAD更新/序号/截断/Rekey、UoT部分收发及取消、真实mux帧预算和Fin尾部。它们尚未运行，数量以worker实际发现和执行的名称为准。

主任务另写HTTP内部4项，均待执行：

- `upload_duplicate_is_exactly_once_and_fin_is_idempotent`
- `disconnected_upload_request_does_not_cancel_or_duplicate_owned_batch`
- `unpolled_pull_preserves_bytes_but_uncertain_delivery_closes_token`
- `eof_trailer_preserves_upload_half_and_reaper_returns_leases`

本轮新加`tests/vectors/mod.rs`三个lib测试，直接调用生产私有原语；默认fixture尚未生成，缺失时明确失败，不能自动通过或静默忽略：

- `reference_vectors::independent_go_initial_session_hkdf_and_direction_separation`
- `reference_vectors::independent_go_aead_epoch_sequence_replay_mac_and_direction_vectors`
- `reference_vectors::independent_go_kip_hello_address_and_uot_vectors`

`tools/sudoku_interop/export_vectors.py`会在固定Mihomo临时副本追加两个同包_test.go桥接，精确只执行`TestKerlicoExportControlVectors`和`TestKerlicoExportRecordVectors`，不改生产算法/只读缓存，不启动网络；输出合成HKDF/ECDH、两AEAD/epoch/序号/错误输入、KIP及UoT。当前两个导出测试和新fixture都没有运行或生成。桥接源码和执行后摘要将单独固定，不把导出探针当完整Go服务程序互通。

## CLI和真实对端工具：全部待运行

[工具说明](../../tools/sudoku_interop/README.md)包含固定来源、Linux worker门禁、来源构建、纯向量导出、真实CLI配置检查和七类逐维互通套件。`SOURCE.json`固定Mihomo提交/归档/生产文件和官方Sudoku v0.5.2.0提交/归档/模块摘要；固定版本原生程序承担参考角色，不使用Go/Python作为kerlico协议后端。

`check_configs.py`写14个CLI配置断言：合法三方法、双节点独立/重复seed、none节点/通配门槛、未知字段/错误安全开关/padding/布局，以及WS off/on的EOF能力。此处14是已写配置数量，不是通过数量。

`run.py`按客户端/服务端、先发方向、节点族、六载体、方法、表/pure/custom、mux、TLS、真实33MiB、错误凭据及停止/重启分别计划；每包UDP和每条TCP写独立结果。CLI并发不单独证明真实mux复用，须结合上述Engine物理入口计数。程序只清理自身创建的进程组，保留每个新标签的输入摘要、配置、原始日志、失败和终态。

已知参考边界必须保留：

1. 官方原程序客户端/服务端通配监听，原配置没有监听地址字段。工具要求实际独立user/net namespace并核对`/proc/self/ns/net`变化，仅启用其中lo；不具备能力时停止，不回退宿主通配。没有在本轮创建或运行namespace。
2. 官方当前go.mod要求Go1.27.2；旧研究Go1.26.10不符合。官方1.27.2归档/SHA已固定在SOURCE.json，尚未下载/执行，后续只在项目目录准备，不能修改系统工具链。原生server配置没有TLS证书/私钥槽位；该方向的原生TLS仍不能宣称支持。
3. 参考client没有强制H1/H2配置时，只记自动版本结果；不计强制H1/H2通过。WS按标准H1升级处理。
4. 原生参考client的SOCKS入口封装地址后，65507负载可能已超过本机UDP上限。此时尚未送达Sudoku，记录entry_limit；不把未发送包伪装成功。Rust内部协议和真实Direct路径仍独立要求0/65507与多目标关联。
5. none的结果只属于显式本机不安全兼容。公开部署、管理名单、Mihomo私有扩展和未选维度不从本轮数据推定。

## 下一次统一验证顺序

完整首轮源码/接口/工具写齐后，由主任务冻结仅本包及必要core/config/net/egress/engine和专用CLI的快照；不夹带其他WIP包，不在本地运行任何检查。

1. 核对固定来源与项目工具链，在perf-01新标签先生成独立Go纯向量，保存两个精确测试名/数量、源清单和结果摘要，再取回合成fixture。
2. 统一运行本包格式、test、严格Clippy和专用CLI构建；记录实际发现/执行/过滤数量、源码清单、Cargo.lock及二进制摘要。编译并发1，先复制独立bin后互通。
3. 执行配置、自端CLI和原Mihomo/官方Go双角色套件；按逐维真实结果修复复验，失败和入口/参考限制分开保存，原日志不覆盖。
4. 全部相关复验结束后才更新支持/交付状态；当前全部待验，未启动新的worker作业。
