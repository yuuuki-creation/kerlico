# ShadowQUIC 受控依赖修改

日期：2026-10-31。两个依赖已在 `perf-03` 随本协议编译，10 个修改过的 Rust 文件格式检查通过；实际使用路径经 16 项包级测试验证。固定 Mihomo 的 v1 双端和真实回退通过，原固定 Mihomo v2 因缺失强制版本信息被拒绝；另外已通过受控 Go 参照的 v2 双端、完整负载、实际密钥更新与参数负例，不将该结果归于官方原资产。

两个目录均来自 crates.io 固定 0.4.0 发布包；原压缩包及逐文件摘要在各自 `SOURCE.json`，MIT/Apache-2.0 文本保留。发布包源码缓存只读，不在缓存中开发。移除独立示例、基准与开发依赖，避免把它们引入本项目构建；运行源码中的上游原注释与原许可保持原文。本项目新增说明使用简体中文。

| 目录/文件 | 必要修改 |
| --- | --- |
| quinn-jls/Cargo.toml | 固定 rustls-jls 1.3.7；proto 指向本目录内的受控 quinn-proto-jls；不修改全局 quinn/rustls patch |
| quinn-jls/src/jls.rs | 回退来源数上限、持有外部资源许可、较小且完整包可容纳的两包接收缓冲、无 panic 的 socket 包装、显式连接上游以限制响应来源、初次发送期限、持久发送器与真实 waker 的双向有界队列、令牌桶 burst 与平均速率、有显式闲置回收 |
| quinn-jls/src/endpoint.rs | 启动驱动前原子注入回退预算；暴露定时清理入口；接受任务创建转发 socket 后显式唤醒端点驱动，及时登记接收唤醒；两包回退批次；单个回退 I/O 错误只移除该来源，不关闭已认证连接共用端点 |
| quinn-jls/src/lib.rs | 导出上述预算类型，供节点挂接全局/节点 stream budget |
| quinn-proto-jls/src/packet.rs | 按 RFC9369 对 v2 Initial/0-RTT/Handshake/Retry 长头类型做循环映射；保留 v1 编码 |
| quinn-proto-jls/src/crypto/rustls.rs | 将 v2 交给 rustls 已有 Version::V2 初始盐/HKDF/更新机制；补 v2 Retry 常量及两方向完整性计算 |
| quinn-proto-jls/src/transport_parameters.rs | version_information 的有界、保留未知值的编解码；拒绝零版本、重复参数、非法长度及客户端未列当前版本；参数上限 256 字节 |
| quinn-proto-jls/src/endpoint.rs | 发送当前选定版本及服务端支持列表；客户端只列当前版本，禁用握手内兼容切换 |
| quinn-proto-jls/src/connection/mod.rs | 对端受认证 Chosen Version 必须等于当前版本；v2 缺失版本信息拒绝 |
| quinn-proto-jls/src/transport_error.rs | 补 RFC9368 的 VERSION_NEGOTIATION_ERROR=0x11 |
| quinn-proto-jls/src/lib.rs | 补 v2 版本入口；模块运行时再按显式 v1/v2 范围收紧端点集合 |

标准依据为 [RFC9369](https://www.rfc-editor.org/rfc/rfc9369.html) 与 [RFC9368](https://www.rfc-editor.org/rfc/rfc9368.html)。本轮显式选择 v1 或 v2，不做握手内兼容版本切换、跨版本自动重拨、TLS 会话恢复或 0-RTT；不能以版本号配置接受替代字节向量和真实对端验收。

资源许可由协议节点构造时注入，回退与已认证逻辑业务共同受全局/节点预算约束。初次回退后台发送仍持有许可，且由协议的作用域 Runtime 统一取消。新转发 socket 不启用 GRO，因此 65536 字节接收槽能保留一个完整 UDP 包，不会把聚合包长度误作小槽下标。

回退不能沿用一次性 noop waker 发送：首次 writable 未就绪时会丢掉握手包。两个方向均保留有限队列和发送器，由端点驱动的真实 waker 继续；发送 Pending 时归还速率 credit，不重复扣费。每个发送器保留独立 writable future，避免多发送器覆盖 Tokio 单 waker 槽。

集中修复时抓包确认：独立接受任务创建转发 socket 后，端点驱动未被唤醒，已有上游响应得不到轮询，短闲置回收先触发。补充唤醒后，v1/v2 普通 QUIC 的完整握手/回写与 700 ms 来源回收回归通过。抓包仅包含专用测试的两个回环端口，私有诊断产物不提交。
