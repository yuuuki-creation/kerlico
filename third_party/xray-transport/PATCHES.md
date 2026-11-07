# 本地生命周期补丁

日期为2026-11-02。状态为已编写，尚未构建或验证。

新增 lifecycle.rs，登记所有本包生产异步任务并继承命名服务作用域。任务创建前取得完成计数守卫，未首次轮询就被取消也归还计数；关闭先封接纳，终止应用任务，关闭并等待QUIC endpoint空闲，最后等待运行任务退出。无所有者的生产spawn拒绝创建任务。

原有spawn调用改走同一登记函数，任务本体只创建一次。H3底层QUIC Runtime也使用该所有者，记录真实endpoint；外层任务计数不代替QUIC关闭等待。VLESS、VMess和Trojan在服务启动后装配所有者，由ServiceContext登记关闭桥，并在每次连接和返回流轮询时恢复作用域。

Cargo继承项展开为固定上游版本，三项内部依赖保持同一Git提交。原文件许可与署名保留，本地补丁不改变MPL-2.0许可。整树功能、并发取消、gRPC/XHTTP/H3/REALITY互通和退出回收仍须在worker验证。

tls.rs 的自动配置默认关闭会话恢复，避免共享配置缓存把 TLS 票据跨可信成员复用。连接池仍按 ResourceKey 分区；本补丁没有移除实际载体复用能力。

保留原集成测试，并把其编译期include引用的固定夹具复制到包内 tests/fixtures；include路径随目录迁移调整。调用外部上游oracle的原测试仍需要其原运行条件，不能由本补丁定向测试替代。

原Tokio异步测试已显式进入TaskOwner作用域，测试派生任务沿同一所有者登记；测试结束等待关闭，panic时由守卫取消。没有新增ignore或删除原测试。

集成审阅后移除了cfg(test)下缺少所有者仍创建detached任务的例外，测试与生产采用同一拒绝行为。任务panic通过持久watch状态通知上层ServiceContext，只停止对应命名服务；新增同owner关闭和其他owner继续的回归代码，尚未执行。

## QUIC 关闭不等排空期（2026-11-03）

`TaskOwner::shutdown` 对每个 endpoint 只等 200 毫秒，让 CONNECTION_CLOSE 发出，随后中止运行任务。原来等 `wait_idle`，排空期 3×PTO 在高延迟路径上超过关闭预算，进程退出码为 1。

## TLS1.2 时代 uTLS 档案省略 supported_versions（2026-11-07）

`utls_shaping.rs::extension_plan` 对不含 supported_versions 的档案（`android`、`hellochrome_58`、`hellofirefox_55` 等）禁用该扩展，`extension_order` 不再把它补在末尾，ClientHello 与 uTLS 一致。这些档案的配置只启用 TLS1.2，shaped-rustls 的 `apply_extension_plan` 只在该条件下允许省略。`utls_tls_shaping_tests::tls12_era_profiles_emit_the_utls_hello_without_supported_versions` 对照 oracle 夹具校验套件、扩展类型与长度和握手长度。

## uTLS ClientHello 通告档案的完整密码套件（2026-11-07）

`utls_shaping.rs::apply_utls_profile` 用 shaped-rustls 的 advertised cipher suites 发送档案的全部套件（含本实现没有的 CBC、RSA 密钥交换套件），GREASE 槽位按完整列表计。原来只发送已实现的套件，Chrome 档案从 15 个套件变成 9 个，JA3/JA4 与 uTLS、Mihomo、Xray 都不同，指纹失去意义。协商仍只接受已实现的套件：服务端选中未实现的套件时客户端终止握手。`utls_tls_shaping_tests` 的 `legacy_cipher_advertisement_*` 三个测试改为断言完整列表、仍可协商与选中遗留套件时握手失败。

## 测试

本包不是 workspace 成员（带独立 dev-dependencies），`cargo test --workspace` 不覆盖。`tools/test_xray_transport.sh` 以本包清单为根，套用根 `Cargo.toml` 的 `[patch]` 与 `Cargo.lock` 运行全部测试；`tools/worker_gate.sh` 的 `test-xray-transport` 步骤调用它。
