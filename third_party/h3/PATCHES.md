# h3共享补丁

2026-11-02 新增解析前请求结束所有权修订及三项真实连接回归。海外 worker 的 `h3-primitives-tests-r38` 首次编译因测试类型错误退出，后续 `h3-primitives-tests-r45` 在测试编译阶段再次退出，均未启动测试。当前继续编写预算让出与真实输入等待的区分、grease 发送进展修订及对应回归，并集中修正 r45 的测试类型问题，尚未对本轮新输入编译、格式检查或测试。下方原有通过记录只对应原输入，不证明本轮 h3 或其协议消费方已通过。

日期：2026-10-31。当前状态：classic CONNECT补丁原有16项通过；后续伪头唯一性/顺序增量也已在perf-01隔离原语工作区完成请求头测试21/21、默认/all-features库检查及修改文件格式复核。此目录是共享依赖，不是TrustTunnel或Naive独有副本；不继承旧Root H3结果，也不代表各协议已互通。

## 伪头解码增量：限定原语已验证

Naive首轮负例复核发现，0.0.8的Header::try_from直接覆盖重复伪头，且丢失普通字段之前/之后的原始次序，上层Request/Response已无法恢复。依据[RFC9114第4.3节](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.3)，新增输入校验：六类现有伪头均不得重复，任何伪头均不得跟在普通字段之后。重复值相同也拒绝，普通重复头继续保留。只在同一headers.rs增加固定六位标记与顺序状态，沿用现有HeaderError，不改公开API、发送编码、QPACK或其他文件的算法。

五项新纯回归经真实QPACK序列化/解码后调用Header::try_from，覆盖所有六类的同值/异值重复、classic CONNECT的method/authority、响应status、所有伪头晚于普通头，以及合法不同伪头顺序/重复普通头。`headers-pseudo-unique-order`已终态0，新5项与原16项共21项通过，219项过滤；默认/all-features库检查、单文件格式复核通过。仍有上游原有警告，没有登记严格Clippy或整库测试通过。请求/响应角色字段适用性、trailer和完整HTTP/3错误流行为不因这五项扩大验收。

新增实际测试名为duplicate_pseudo_fields_never_overwrite_identical_or_distinct_values、classic_connect_rejects_duplicate_method_and_authority_after_qpack、response_rejects_duplicate_status_after_qpack、every_pseudo_field_must_precede_all_ordinary_fields、arbitrary_valid_pseudo_order_keeps_repeated_ordinary_fields，均带proto::headers::tests::前缀。

最新51文件src集合SHA256为 `bc8781bbbb1dae4552ac663d83b4a622e56e1e51bd5f5d4a87e3bdbcd0e9cc9b`，headers.rs为 `484e98d6507cc5abc6a7d1d03a8a2e9e36a33ca32258e2170b1fcf583a852805`；锁文件保持下文相同摘要。worker格式化文件已取回，完整差异更新于headers.patch，UPSTREAM.json另保留原CONNECT验证摘要。TrustTunnel/Naive旧冻结输入仍按原摘要登记，只有各自实际复验后才能登记新依赖输入。

## CONNECT-IP 协议常量

`src/ext.rs` 的 `Protocol` 增加 `CONNECT_IP`（`:protocol=connect-ip`，RFC 9484），供 `kerlico-masque` 使用。`Protocol` 是封闭类型，上层无法自行构造新值。

## 固定来源

基准为crates.io的h3 0.0.8发布包，源码提交 `22c1aa3f44d1463cd7644c8f654fffc9a6da305c`，发布包校验及LICENSE摘要见UPSTREAM.json。已将本项目只读缓存的src逐文件与官方发布包核对一致，未修改reference/.upstream。LICENSE原文保留。

官方已合入[standard CONNECT修复#322](https://github.com/hyperium/h3/commit/e07e69412876f7e26f026bd75a48b2704d8c8283)，但核对时crates.io最新仍0.0.8，[发布请求#369](https://github.com/hyperium/h3/issues/369)仍open。核对的官方HEAD为 `43745ad87e95b0c035ac9c547aad467303213425`。整树升级还会引入其他实现和构建条件变动；该修复自身仍保留classic CONNECT的旧伪头计数，不能原样满足本轮计数不变量。因此保持0.0.8/API/依赖，最小回移官方条件并补计数。

## 差异

原CONNECT增量仅修改src/proto/headers.rs的Pseudo::request（后补TryFrom输入校验见上文）：

1. 回移官方#322：CONNECT且没有Protocol扩展时，scheme/path设为None；不论传入URI原先是否带scheme/path，classic CONNECT均只保留method/authority伪头。
2. 本项目补充：根据实际存在的method、scheme、authority、path、protocol计数。典型classic CONNECT由错误的4修为2；普通GET/POST仍4，带authority的extended CONNECT仍5。Header.len/size中的普通头字段计数不变，QPACK大小约束算法不改。

HeaderIter、接收端into_request_parts、Protocol枚举、GET/POST默认https和路径规则均不改。接收端已能将authority-only还原Uri，本轮增加测试确认，不扩大输入校验范围。

保留发布包的src、README、LICENSE和版本元数据；Cargo.toml保留其规范化依赖/特性/构建设置，仅去掉可选authors元数据并用本说明替换生成文件提示，符合本仓库匿名规则。Cargo.toml.orig和发布包Cargo.lock不作为本地依赖复制；原始发布包摘要可核对完整基准。没有删改许可证声明或把上游身份用作本项目提交身份。

根Cargo.toml只添加third_party/h3的workspace exclude与crates.io path patch，workspace.dependencies的h3仍固定=0.0.8；其他根清单行由主任务维护。

## 回归范围

新增8项纯请求/序列化回归，位于proto::headers::tests：

- classic_connect_omits_scheme_path_and_reports_exact_count
- classic_connect_absolute_uri_also_omits_scheme_path
- classic_connect_qpack_serialization_and_limits
- classic_connect_authority_only_decode_accepts_tunnel_tokens
- ordinary_get_post_pseudo_fields_and_qpack_unchanged
- ordinary_authority_and_origin_forms_keep_defaults
- extended_connect_protocols_preserve_pseudo_fields_and_qpack
- non_connect_protocol_extension_remains_ignored

覆盖IPv4/IPv6/域名authority、_udp2/_check/_icmp、重复普通头、默认与显式scheme/path、两个现有Protocol值。逐项比较显式标准字段、Header迭代、字段数、QPACK原始序列化、解码还原和header大小精确阈值。普通/extended分支与相同显式字段的QPACK编码应逐字节一致。

所有首轮代码和测试完成后，仅在新perf-01原语工作区验证。上游h3的测试模块通过相对路径包含h3-quinn测试适配器；独立工作区只将h3作为workspace成员，提供固定h3-quinn 0.0.10源码作为测试支撑，不带其他协议/WIP或SSR实验。没有在本地构建或运行检查。

## 实际验证与终态

Rust/Cargo 1.99.1、Linux x86_64、构建并发1，使用独立target。发布包Cargo.lock保持锁定，验证锁SHA-256为 `98a0cdfd22548b031b914fdaf960600797afc99da1884b79c06053be40429dbc`。src集合共51文件，按相对路径排序输入“路径、NUL、内容、NUL”，SHA-256为 `5f5e413390b41101b8d63e93dcd1ff099b5fbd2d6667e110571909757bd450e7`；headers.rs为 `bfed028d619cbb5755f35a03357c69dab2cba3f0aa50cea004fe26e8d03723c3`。worker格式化文件已取回，源码差异仅该文件；可审计差异见headers.patch。

实际命令：

```sh
cargo fetch --locked
rustfmt --edition 2021 h3/src/proto/headers.rs
cargo check -p h3 --lib --locked --offline
cargo test -p h3 --lib --locked --offline --features i-implement-a-third-party-backend-and-opt-into-breaking-changes proto::headers::tests::
rustfmt --edition 2021 --check h3/src/proto/headers.rs
cargo check -p h3 --lib --locked --offline --all-features
```

Headers组实际16项通过、0失败、219项过滤。除前述新增8项外，实际运行的原有测试为preserves_duplicate_headers、request_has_authority、request_has_different_host_and_authority、request_has_empty_host、request_has_empty_authority、request_has_no_authority_nor_host、request_has_host、request_has_same_host_and_authority；完整名称均为proto::headers::tests::加该函数名。未运行上游QUIC连接测试、协议互通或SSR历史实验。

保留两个前置失败：headers-first在离线解析时缺assert_matches，exit101，尚未编译；headers-locked-deps补齐锁定依赖、完成默认库检查后，单测默认feature缺少ConnectionState导出而编译失败，exit101，尚未运行测试。上游单测依赖已有backend opt-in feature；补充正确构建参数后的headers-backend-feature完成16项测试、格式复核和all-features库检查，exit0。源码API和特性定义未为测试修改。

库检查有上游原有的未使用项/生命周期写法警告，lib test另有测试支撑的datagram配置警告；未修改这些无关源码，也不宣称严格Clippy通过。核对时该原语项目无活动进程。原始脚本、日志、实际测试名、依赖锁和源码清单保留于本地私有记录。

## 解析前请求结束所有权，待 worker 验证

固定源码在接纳请求流时将 StreamId 加入 `ongoing_streams`，原来直到解析出 HEADERS 才创建 `RequestEnd`。上层在配额不足时直接释放 resolver，或解析在建立 RequestStream 前失败，均不能通知连接移除该记录，可能阻止 GOAWAY 自然排空。

本轮只把已有 `Arc<RequestEnd>` 提前到 `Connection::create_resolver_internal` 创建 resolver 的时刻。`RequestResolver` 以私有字段持有它，成功解析后移交同一份 owner，提前退出由普通字段析构归还。没有添加 resolver 自定义 Drop、公开完成接口或手工重复通知。现有 RequestStream 拆分继续共享同一 Arc，最后一个半流释放才发送一次通知。公开函数签名、头部校验、错误码、QUIC 参数与依赖清单保持原样。

本轮全树只发现 `Connection::create_resolver_internal` 一个 RequestResolver 构造点。变更文件为 `src/server/connection.rs`、`src/server/request.rs` 与既有 `src/tests/connection.rs`。所有原许可、归属及先前 CONNECT 和伪头补丁保留。此补丁由本项目本轮编写，不标为上游已合入。

新增真实 QUIC 连接用例均位于 `tests::connection`。

- `unresolved_request_drop_allows_graceful_shutdown`，服务端不读取请求头就释放 resolver，客户端发送 GOAWAY 后必须自然排空。
- `rejected_unresolved_request_preserves_active_split_stream_and_drains`，新请求收到 H3_REQUEST_REJECTED，已建立的拆分流继续真实 DATA 往返，最后半流释放后自然排空。
- `incomplete_request_resolution_keeps_error_and_allows_graceful_shutdown`，解析前不完整请求仍返回 H3_REQUEST_INCOMPLETE，随后自然排空，不将原错误改为成功。

三项用例没有读取私有 `ongoing_streams` 来冒充网络结果，也没有新增 sleep。原非法帧、头部及请求错误用例保留。TrustTunnel 另有真实配额耗尽及原六项完整 H3 排空回归，共同验证消费方行为。

当前仅完成编写，未运行本轮任何验证。h3 的既有库测试仍需要隔离工作区提供固定 `h3-quinn` 测试支撑，并启用 `i-implement-a-third-party-backend-and-opt-into-breaking-changes`，不能只运行 TrustTunnel 库测试就登记此三项已通过。后续还须复验共享 h3 消费方，不能沿用原 headers 组通过记录。Cargo 清单和锁未为本次测试修改。

## 控制驱动进展与可取消关闭，待 worker 验证

独立源码审阅指出两项已有缺口。服务端 `poll_control` 持续处理同步 Ready 控制帧，一次 poll 没有工作上限。普通接纳原已存在此问题，Hysteria2 恢复排空期控制驱动后也会进入该路径。另一项发生在 `shutdown` 先写 `sent_closing`、后等待 GOAWAY 发送时。外层任务完成导致临时 accept future 被释放后，相同截止 ID 会跳过尚未完成的写入。两项原报告是静态机制分析，没有运行复现。

服务端当前每次处理最多 64 个控制帧，达到上限后唤醒自身并返回私有 Yielded 进展。接纳驱动仍继续轮询原有请求及请求完成通知。只有控制读取真正返回 Pending，才允许无活动请求的连接自然排空。预算让出不能作为已检查完缓冲帧的依据。原 SETTINGS、GOAWAY 单调性、非法帧及关键流错误检查保留。

仅限制服务端外层不足以约束未知帧和连续分片。`FrameStream` 另为每次调用的读取与解码迭代提供 64 步预算，未知帧的内部忽略循环共用该预算。预算耗尽后保留原解码器、半帧与缓冲并唤醒自身。私有 FrameProgress 将此 Yielded 传到连接和服务端，公开 poll 接口保留原签名。先尝试已有缓冲，避免每次让出后无条件追加新的就绪数据。未知帧仍按原协议忽略，没有复制帧解析器、增大缓冲或扩大传输窗口。这是迭代预算，不宣称单个后端调用或任意大单帧的墙钟执行时间上限。先解码缓冲也可能在尚未观测底层 RESET 时交付缓冲帧，不承诺与原版错误观察次序完全相同。

`ConnectionInner` 私有 `GoawaySend` 保存 Idle、Queued、Writing 和 Sent 状态。Queued 保存尚未提交的 ID，先等待控制发送流可用，才提交一次。Writing 让原发送流继续写同一帧，只另外保存尚未提交的最小下一 ID。重复相同或更大的 shutdown 仍驱动待写帧；更小 ID 在未提交时合并，已提交的原帧完整写完后再发更小值。`shutdown` 与普通控制驱动使用同一所有者，临时 future 释放不会销毁发送进度。没有额外 FIN、业务重放或新的关闭期限，发送错误仍成为原连接错误。

现有控制发送点只有构造期间的 SETTINGS 及运行期间的 GOAWAY。构造完成后由同一连接私有状态机拥有 GOAWAY 写入顺序，没有并行 writer。公开函数及 QUIC trait 签名保持原样。已编写的 RequestEnd 所有权、CONNECT 与伪头补丁、原版权与许可继续保留。

新增九项回归均位于 `tests::control`。

- `continuously_ready_control_keeps_accept_cancellation_and_timer_live`，同步持续 Ready 的相同和递减 GOAWAY、可忽略已知帧、未知帧及缓冲内未知帧批次下，公开 accept 仍接纳并保留请求，实际 Tokio 任务取消及定时任务能够完成。
- `continuously_ready_partial_unknown_frame_yields_without_losing_progress`，连续小分片组成未知大帧时仍让出，有限分片全部到达后继续读取后续 GOAWAY。
- `cancelled_accept_resumes_goaway_before_submission`，提交前窗口阻塞导致 accept 被其他真实任务完成取消，恢复后对端读取完整 GOAWAY。
- `cancelled_accept_resumes_partial_goaway_without_repeating_header`，线侧已收到一个帧头字节时取消，再次同 ID 关闭及恢复窗口后只收到一份完整 GOAWAY。
- `decreasing_shutdown_replaces_only_an_unsubmitted_goaway`，未提交的截止 ID 合并为更小值，随后更大请求不能扩大已选范围。
- `decreasing_shutdown_preserves_partial_goaway_and_sends_only_latest_limit`，半写原帧完整保留，多个尚未提交的更小值合并为最小值，线侧观察到合法不增的两帧。
- `cancelled_shutdown_is_resumed_by_accept_with_active_request`，已有请求未结束时只驱动 accept，也能完成此前被取消的 GOAWAY 写入。
- `pending_goaway_write_error_stays_a_connection_error`，待写控制流错误及重复关闭持续返回 H3_CLOSED_CRITICAL_STREAM。
- `control_errors_after_a_full_batch_keep_settings_and_goaway_validation`，跨批次后仍拒绝重复 SETTINGS、增大的 GOAWAY 和 DATA 控制帧。

这些用例通过受控 QUIC trait 提供确定的同步 Ready 输入及发送窗口，调用正式 Connection、accept、shutdown 和帧编码解码。取消由等待实际读取或发送阻塞信号的 Tokio 任务触发。定时任务从该信号后开始计时，不靠延时猜测发送状态。对端比较 GOAWAY 的完整编码字节并解码 ID，检查控制流没有 FIN，已有请求继续读取固定负载。这不是网络吞吐测试，也不冒称真实 QUIC 网络互通。旧代码的一次 poll 若不返回，进程外测试作业期限才可终止该回归，Tokio 超时本身不能中断该 poll。

保留原三项真实 QUIC 回归的负载、split 最后半流所有权断言、错误码和期限。上一输入将测试 helper `Server::next` 改为具体 `h3_quinn::Connection` 后丢失原 `Bytes` 推断约束，r45 出现多处 E0283。当前恢复 opaque `quic::Connection<Bytes>`，只明确其 BidiStream 为 `h3_quinn::BidiStream<Bytes>`，同时保留 Bytes 推断与 split 约束。另将不使用返回值的 `poll_type` 测试断言改为 is_ok，修正其错误类型没有 Debug 的 E0277，不修改生产错误类型。r45 共报告 43 项错误、4 项警告，退出 101，没有测试结果。当前修订仍待编译。

无头请求测试继续使用 `crate::config::Settings`，其 GET 请求字段大小仍为 179、上限仍为 12。该四字段大小按原请求分别为 42、43、51、43，没有改变结果迎合编译。测试 helper 两处监听继续绑定回环 `[::1]:0`，原目标本来就是 IPv6 回环；r38 和 r45 都在编译阶段退出，没有运行网络测试。

本轮没有修改 Cargo、feature、锁或测试支撑依赖，也没有执行本地构建与测试。海外 worker 仍须先编译，再运行新增控制组、原三项请求所有权回归、既有 frame 与 control/error 用例及完整 h3 库测试。还须复验 Hysteria2、TrustTunnel、Naive、VLESS H3 等消费方与整树。作者不提供独立复审通过结论。

## 控制输入排空与 grease 进展，待 worker 验证

独立源码评审发现，原新增预算仍把主动让出映射为普通 Pending。没有活动请求或新双向流时，单个已到达 chunk 中的 SETTINGS、63 个合法 GOAWAY(0) 和非法 DATA 会在外层预算耗尽后被当作正常排空。另一条交错是 SETTINGS、GOAWAY(0)、64 个未知空帧和非法 DATA，内层预算耗尽后同样可能提前返回 Ok(None)。原九项测试中的错误跨批用例保留了活动 resolver，不能覆盖这两个无活动请求交错。

本轮采用私有 FrameProgress 区分帧交付与 Yielded。FrameStream 和 ConnectionInner 的公开 poll 签名不变，内部调用将让出原因传到服务端。服务端将每次控制驱动结果归为 WaitingForInput 或 Yielded，只有前者允许自然结束。让出后仍处理请求完成和新 bidi，包括拒绝关闭范围外的新请求；不会用新标记跨调用保存一次 poll 的结论。原持久 GOAWAY 写状态机及解析前 RequestEnd 所有权保留。

同次源码核对还发现一个继承的 grease 缺口，与预算评审来源分开记录。原 ConnectionInner 已解出控制帧后才等待可选 grease 发送，发送 Pending 会让当前帧没有交给服务端。当前将原 grease 状态机移到每次读取控制输入之前独立推进。grease 的 Pending 不阻塞控制读取，已解出的帧直接交付。原打开、写入、结束发送及可选发送错误规则保持，未新建待交付帧副本，也未关闭 grease 绕过测试。

新增八项受控回归均位于 `tests::control`，全部通过公开 Connection、accept、shutdown 和 QUIC trait 的对端观察，不引用新的私有进展类型。

- `buffered_data_after_control_budget_is_not_a_clean_shutdown`，无活动请求，单 chunk 中 SETTINGS 加 63 个 GOAWAY(0) 后的 DATA 必须返回 H3_FRAME_UNEXPECTED。
- `buffered_data_after_unknown_frame_budget_is_not_a_clean_shutdown`，无活动请求，单 chunk 中 SETTINGS、GOAWAY(0)、64 个未知空帧后的 DATA 必须报相同错误。
- `idle_control_validation_survives_both_budgets`，两个预算交错后分别放入重复 SETTINGS、含禁用标识的 SETTINGS 和递增 GOAWAY，仍分别报告 H3_FRAME_UNEXPECTED、H3_SETTINGS_ERROR 和 H3_ID_ERROR。
- `finite_control_batches_drain_only_after_input_pending`，合法有限多批 GOAWAY 和未知帧全部处理后，后端实际观察到输入 Pending，公开 accept 才正常排空并发送一次 GOAWAY。
- `rejected_request_does_not_hide_buffered_control_error`，拒绝关闭范围外的新请求时，同样不能漏掉缓冲中的非法控制帧。
- `pending_grease_open_keeps_control_validation_and_shutdown_live`，可选 grease 打开确实 Pending 时，仍处理 GOAWAY、重复 SETTINGS、递增 GOAWAY 和非法 DATA。
- `pending_grease_write_keeps_control_validation_and_shutdown_live`，可选 grease 只发送一个字节后阻塞时，同样保留控制处理结果。
- `pending_grease_resumes_once_without_new_control_input`，已有请求仍存活，恢复 grease 打开或部分写窗口后无需新控制输入即可结束同一条 grease 流，对端只收到一个合法 grease 帧且原前缀不重复。

两条精确预算反例和后续错误矩阵将由主任务保留相同测试及编译夹具，只恢复 r45 生产代码作海外红绿对照。有限合法批次另观察后端真正等待，防止提前成功也通过测试。grease 用例开启该选项并明确观测打开或写入的阻塞信号，恢复后检查流数量、完整字节和结束状态。控制流仍不发送额外 FIN。

当前全部新增内容均为已编写、未验证。旧九项受控回归与三项真实 QUIC 回归保留，本说明不将受控窗口测试冒称真实 QUIC 窗口或网络互通。完整 h3、消费方和整树仍待海外 worker。任意后端单次 poll 的墙钟上限、客户端外层完整驱动与任意新 UNI 洪泛不在本次范围。
