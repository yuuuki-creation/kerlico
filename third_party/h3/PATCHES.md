# h3共享补丁

日期：2026-10-31。当前状态：classic CONNECT补丁原有16项通过；后续伪头唯一性/顺序增量也已在perf-01隔离原语工作区完成请求头测试21/21、默认/all-features库检查及修改文件格式复核。此目录是共享依赖，不是TrustTunnel或Naive独有副本；不继承旧Root H3结果，也不代表各协议已互通。

## 伪头解码增量：限定原语已验证

Naive首轮负例复核发现，0.0.8的Header::try_from直接覆盖重复伪头，且丢失普通字段之前/之后的原始次序，上层Request/Response已无法恢复。依据[RFC9114第4.3节](https://www.rfc-editor.org/rfc/rfc9114.html#section-4.3)，新增输入校验：六类现有伪头均不得重复，任何伪头均不得跟在普通字段之后。重复值相同也拒绝，普通重复头继续保留。只在同一headers.rs增加固定六位标记与顺序状态，沿用现有HeaderError，不改公开API、发送编码、QPACK或其他文件的算法。

五项新纯回归经真实QPACK序列化/解码后调用Header::try_from，覆盖所有六类的同值/异值重复、classic CONNECT的method/authority、响应status、所有伪头晚于普通头，以及合法不同伪头顺序/重复普通头。`headers-pseudo-unique-order`已终态0，新5项与原16项共21项通过，219项过滤；默认/all-features库检查、单文件格式复核通过。仍有上游原有警告，没有登记严格Clippy或整库测试通过。请求/响应角色字段适用性、trailer和完整HTTP/3错误流行为不因这五项扩大验收。

新增实际测试名为duplicate_pseudo_fields_never_overwrite_identical_or_distinct_values、classic_connect_rejects_duplicate_method_and_authority_after_qpack、response_rejects_duplicate_status_after_qpack、every_pseudo_field_must_precede_all_ordinary_fields、arbitrary_valid_pseudo_order_keeps_repeated_ordinary_fields，均带proto::headers::tests::前缀。

最新51文件src集合SHA256为 `bc8781bbbb1dae4552ac663d83b4a622e56e1e51bd5f5d4a87e3bdbcd0e9cc9b`，headers.rs为 `484e98d6507cc5abc6a7d1d03a8a2e9e36a33ca32258e2170b1fcf583a852805`；锁文件保持下文相同摘要。worker格式化文件已取回，完整差异更新于headers.patch，UPSTREAM.json另保留原CONNECT验证摘要。TrustTunnel/Naive旧冻结输入仍按原摘要登记，只有各自实际复验后才能登记新依赖输入。

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
