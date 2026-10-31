# 凭据隔离公共契约验证

日期：2026-10-31。状态：perf-02 全新隔离工作区的 `contract-r1` 终态 0；7 项 Rust 测试、所选包格式检查和严格 Clippy 通过。此记录只覆盖公共接口、注册表与既有 SS 流注入，不是任何 WIP 协议的认证或互通验收。

## 范围与隔离

工作区只同步 core-api、config、net、egress、protocol-shadowsocks、protocol-ss2022 六个已完成或本轮所需的包，以及根清单/锁和必要第三方补丁目录；没有 apps，也没有 ShadowTLS、SSR、Mieru、Sudoku、ShadowQUIC 等源码。worker 的 Cargo metadata 确认恰好这六个成员，target 位于新目录内。

根清单仅在该隔离副本中显式缩小 members/default-members、移除其他本地包引用；保留固定依赖补丁。原始与过滤后源码清单均已保存，没有改共享根清单或根锁，没有触碰 ShadowTLS 旧工作区/复现变体/归档。启动前可用内存约 6046 MiB、无 Cargo/Rust 构建进程，使用 CARGO_BUILD_JOBS=1。结束后新目录内构建/测试进程为 0。

## 实际命令

仅在 worker 执行：

```sh
cargo metadata --no-deps --format-version 1
cargo fmt -p kerlico-core -p kerlico-config -p kerlico-egress
cargo fmt -p kerlico-core -p kerlico-config -p kerlico-egress -- --check
cargo test -p kerlico-core -p kerlico-config --all-targets -- --nocapture
cargo test -p kerlico-egress --test stream_connector -- --nocapture
cargo clippy -p kerlico-core -p kerlico-config -p kerlico-egress --all-targets -- -D warnings
```

没有运行 SS/SS2022 各自的协议测试套件、egress 其他测试或任何 WIP 测试。Clippy 的 all-targets 包含所选包测试目标的静态检查，不表示执行它们全部测试。

## 实际测试名与结果

| 包/目标 | 测试名 | 结果 |
| --- | --- | --- |
| core | tests::address_validation_and_idna | 通过 |
| core | tests::cancellation_and_budget | 通过 |
| config / credential_isolation | isolation_secret_does_not_grant_public_authentication | 通过 |
| config / credential_isolation | authentication_and_isolation_share_one_cross_entry_secret_domain | 通过 |
| config / credential_isolation | an_empty_isolation_override_cannot_hide_real_authentication_duplicates | 通过 |
| egress / stream_connector | ss_stream_injection_keeps_endpoint_target_eih_and_capabilities_separate | 通过 |
| egress / stream_connector | actual_inner_and_outer_authentication_domains_prevent_wrapper_alias_bypass | 通过 |

共 7 项，无忽略项。3 项配置回归确认：隔离秘密不能授予 nodes 鉴权资格；鉴权与额外隔离集合共同拒绝跨条目复用；空隔离覆盖不能隐藏真实鉴权重复，非法域也被拒绝。测试使用合成协议对象，不拨号或监听。

流连接器回归在 worker 回环执行 15 个内层配置：10 个 SS AEAD、3 个 SS2022 单用户与2个 AES终端EIH。每个发送并回写 65537 字节，检查传输 endpoint 与网站 Destination 分离、目标只交给注入的 Echo AccessService、EOF 能力传播和原生 UDP 拒绝。另一个配置回归使用真实内层指纹与合成外层域检查包装别名；没有加载或运行 ShadowTLS 实现。

严格 Clippy 通过。Cargo 有 h3-quinn、ml-kem、quinn、quinn-proto 四项基线补丁未用于该缩小依赖图的提示；这些不是 Rust/Clippy 代码告警，未通过关闭 lint 规避检查。

## 源码与产物摘要

基线 6cbb3f94356889ab6d7311253c40af5259e00364 加本轮未提交文件。共 46 个输入文件；逐文件清单、原始输入归档、worker 解析后锁与终态日志保存在忽略的 `.private/builds/credential-contract/`。目录聚合按相对路径排序，拼接 `路径 + NUL + 文件SHA256 + LF` 后取 SHA-256。

| 对象 | SHA-256 |
| --- | --- |
| worker 格式化后的六包/必要依赖输入 | 96b226379fa2095c4acf88ff59d749d88f9cf0179b1982760d2efb83fdfb0929 |
| 仅 worker 使用的过滤根清单 | 2543f6688b90636f855f00d0959b5fef2eaf70c971bf52e6299db0ad02d73725 |
| 同步时共享根锁输入 | f53691f44e1e1203d9107f475eca7f76843dcb248256f7c41aba21b07fd40c68 |
| worker 缩小依赖图后的锁 | b0c36d72097c40eb947268d3bd879cb231a0b880d9c720e87a0b81d3b8307b18 |
| core-api/src/lib.rs | 97547ae2a6dddf0a18e8f3f5f727bee23e096732eefed0d147891d075530e289 |
| config/src/lib.rs | 94056358a4fded09fc01f0374b111d767c7309d26de87ab8fe4abf6c373c67b2 |
| config/tests/credential_isolation.rs | fbd9ed05f70e19afc54e204f91edda84f012aa8f39f5e499b591a15400cea1a7 |
| egress/tests/stream_connector.rs | 8e9711b448f6016c2f85bea40b5fe8d954cd6e5339794e6b9816cbea00d02a1f |

工具链：Rust/Cargo 1.99.1、rustfmt 1.10.0-stable、Clippy 0.1.99。只有 config 的新测试文件产生格式变化；回传前确认本地仍匹配起始摘要，没有覆盖并行改动。回传后，六包与第三方输入逐文件和 worker 一致；根清单与锁按过滤设计单独保留，不回写。

本轮未遇到新的风险检查拒绝，也没有恢复此前停止的 ShadowTLS 实验。本地仅编辑、阅读、同步及整理记录，没有编译、格式或测试。
