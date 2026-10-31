# ShadowQUIC 双端实现前调研

日期：2026-10-31。完整首轮与集中修复已完成；包级测试/检查、固定 Mihomo v1 双端互通及单列受控 Go 参照 v2 通过，原固定 Mihomo v2 保留明确失败边界，结果见 `docs/testing/shadowquic.md`。

## 固定协议与认证证据

- [mihomo 应用格式](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/transport/shadowquic/protocol.go)：CONNECT=1、BIND=2、ASSOCIATE_DATAGRAM=3、ASSOCIATE_STREAM=4、AUTHENTICATE=5、EXTENSION=255。地址为 SOCKS5 地址；UDP 控制流登记地址与 16 位 ID，datagram 仅携带 ID 和负载；可靠单向流为 ID 后连续长度前缀包。
- [mihomo 服务端](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/transport/shadowquic/server.go)实现 CONNECT、两种 UDP 关联及部分扩展，明确拒绝 BIND/应用层 AUTHENTICATE。用户名来自 JLS 握手，不能用普通 QUIC 加一个应用认证头冒充。
- [固定 jls-tls](https://github.com/metacubex/jls-tls/blob/67adc0e2f796/jls.go)为 JLS v3：用户名、密码和清零 Random/PSK binder 的 Hello 分别派生 AES-GCM nonce/key，FakeRandom 完成双向认证。客户端必须核验服务端 JLS 状态；普通证书 TLS 成功不能视作 JLS 成功。
- 固定 mihomo 依赖 `jls-quic-go 732f2fc9a34d`、`jls-tls 67adc0e2f796`。服务端要求显式 JLS 上游，用于未通过 JLS 的 QUIC 传输回退；这与认证失败后换另一个代理节点或直连网站不同。
- [QUIC 版本入口](https://github.com/MetaCubeX/mihomo/blob/3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8/transport/shadowquic/quic_version.go)缺省 v1，可显式配置 v1/v2。两者必须分别验证。

## Rust 原语与依赖核查

原生 Rust `shadowquic 0.4.7`（发布包源码固定提交 `3b8af96bf0c97d409e9a59dbb716280a7c5136bb`）可作为接口与格式参考，MIT；不引入其完整路由、系统入口、Lua、REST 用户管理或全局运行器。其底层依赖可按独立包名与本项目现有 quinn/rustls 并存：

| 原语 | 固定版本/源码 | 许可 |
| --- | --- | --- |
| quinn-jls | 0.4.0，发布包源码 `fd3799f13f8707a05df9d1ba7b9f5c0afca0eedc` | MIT OR Apache-2.0 |
| quinn-proto-jls | 0.4.0 | MIT OR Apache-2.0 |
| rustls-jls | 1.3.7，发布包源码 `74cd5817554f3c58b49af9ccf072857174d3b798` | Apache-2.0 OR ISC OR MIT |

rustls-jls 有完整 JLS 客户端和服务端配置；quinn-jls 暴露 `is_jls`、`jls_chosen_user` 和通常的流/包接口。配置阶段不能拨号、监听或隐式解析上游域名，运行时先在总预算内解析为字面 IP，再构造回退配置。JLS 凭据不得进入日志；本轮禁用该 TLS 库的 logging feature，不对凭据配置使用 Debug。

## 发现的真实缺口

1. quinn-proto-jls 0.4.0 的 `DEFAULT_SUPPORTED_VERSIONS` 和 `crypto/rustls.rs::interpret_version` 只有 v1/draft，不能仅把 v2 数值加入配置就宣称支持。须补 RFC9369 初始密钥、Retry 和长头类型映射，逐方向与固定 mihomo 验证。
2. quinn-jls `src/jls.rs` 为每个未认证来源分配独立 socket 和 1 MiB 缓冲，HashMap 没有来源数上限；120 秒闲置回收又只在 I/O 轮询时触发。`wrap_udp_socket(...).unwrap()` 会把包装失败升级为 panic。必须有全局/节点资源许可、数量与缓冲上限、定时回收和错误处理，不能直接把它登记为符合本项目资源契约。
3. JLS 的初次转发使用后台任务，必须纳入节点取消与退出归属，不能在节点退出后保留未受约束的发送任务。
4. 应用 UDP 的地址映射与包可能跨 QUIC 载体乱序；必须为先到包建立有限缓存并在控制流登记后回放，拒绝重复 ID 跨关联覆盖，关闭控制流时释放双方映射与单向流。

已在协议目录内保存最小受控依赖副本，保留必需版权及 MIT/Apache 许可；只做上述真实缺口与 v2 修正，记录逐文件来源与差异。嵌套依赖应排除项目 workspace 的默认检查，模块本身的验收仍必须覆盖实际使用路径。

## 本轮目标范围与矩阵

本轮固定完整交付为 JLS v3 双端、QUIC v1/v2、TCP、datagram/stream 两种 Full Cone UDP、多用户独立节点、统一访问服务、三种已有拥塞控制、双向认证失败与真实上游回退、有界乱序缓存/关联/取消/关闭。业务目标全部由 `AccessService` 提供，Full Cone 使用现有 `DatagramAssociation`；上游回退只属于明确配置的传输端点。

BIND、应用 AUTHENTICATE、远程用户管理、Brutal/BBR3、0-RTT 与其他控制面不是已实现项；不预建配置开关。上述依赖方案、v2 参数与资源边界纳入一次完整首轮编码，随后统一在 `perf-03` 编译、检查、测试与集中修正。已复用核验过的 Mihomo v1.19.33，并通过 worker 合成普通 QUIC 上游验证真实回退；未连接无关公网业务。


受控副本具体改动见 `crates/protocol-shadowquic/vendor/MODIFICATIONS.md`。RFC9369/RFC9368 是 v2 的标准依据；rustls 底层已有 Version::V2 密钥派生，不代表上层 QUIC 已支持 v2。客户端只在选定版本尝试，发送仅含该版本的版本信息，以标准方式禁用兼容切换；会话恢复/0-RTT 同时禁用，拒绝跨版本票据和隐式降级。

发布包原摘要：quinn-jls 0.4.0 为 `ea00596eb53fa6f29899b0e48014ff4804bcfeda4aae5a228df25b9b64e315cf`；quinn-proto-jls 0.4.0 为 `383da615650985c5b656c7a9b6642bf74c27003e02f9aaac917ce8e81eb791e4`。逐文件原摘要保存在各副本 `SOURCE.json`。原压缩包摘要用于来源追踪，不能替代运行验证。

## 真实对端发现的 v2 边界

固定 [jls-quic-go 的传输参数源码](https://github.com/metacubex/jls-quic-go/blob/732f2fc9a34d/internal/wire/transport_parameters.go) 未实现 `version_information`（0x11），包括参数常量、数据结构和发送/接收逻辑。与之相对，[RFC9369 §4](https://www.rfc-editor.org/rfc/rfc9369.html#section-4) 要求支持 v2 的端点发送、处理并验证该参数。本模块保持强制验证；同一固定 Mihomo 节点的合成 JLS 诊断中，v1 成功，v2 返回 `VERSION_NEGOTIATION_ERROR=0x11`。这与完整矩阵中 24 个 v2 配置被复位的结果一致。

因此，v2 已有 RFC9369 密钥/长头/Retry 的固定字节向量、Rust 双端正用例，以及受认证参数缺失/伪造的拒绝用例，但没有获得固定 Mihomo v2 的真实互通验收。不能删除强制校验换取通过，也不能将将来修改过的参考构建冒充官方原资产。普通 QUIC 的 v2 回退可通过不解析其应用认证的原包转发完成；它不证明 Mihomo 的 JLS v2 已符合标准。

## 受控 Go 参照与第二处规范缺口

在保留原资产和失败记录的前提下，使用固定 Mihomo 的 ShadowQUIC 传输包建立双角色小型 Go 测试对端，不编译完整控制面，不参与 Rust 内核业务。固定 Go 1.26.10、两个上游归档与逐文件差异见 `tools/shadowquic_reference_peer/SOURCE.json`；许可证分别为 Mihomo 的 GPLv3、jls-quic-go 的 MIT、jls-tls/Go 的 BSD 三条款，原文本保留在 worker 下载源码中。

只补 0x11 后，v2 JLS 握手成功，但原完整 TCP 负载仍超时。固定 [updatable_aead.go](https://github.com/metacubex/jls-quic-go/blob/732f2fc9a34de12a58020a0ca75bf336095aed93/internal/handshake/updatable_aead.go) 的 `getNextTrafficSecret` 无条件使用 `quic ku`；[RFC9369 §3.3.2](https://www.rfc-editor.org/rfc/rfc9369.html#section-3.3.2) 明确要求 v2 改为 `quicv2 ku`。独立日志显示达到原有首次更新门槛后 Go 进入 KeyPhase=1，Rust 不能解密错误标签的更新包。没有修改 Rust 标签、缩小负载或提高更新门槛。

第二补丁只按版本选择更新标签。直接调用 Go 库真实更新函数的 RFC9001/RFC9369 附录 A.5 固定向量中，旧参照 v1 通过/v2 失败，修正后均通过。随后受控 v2 24 配置的 TCP/UDP/普通 QUIC 回退、8 组双向参数负例与合法控制组、8 配置 v1/v2 退出重启均通过；两方向完整负载日志均观察到 KeyPhase=1。最终三个二进制在新目录使用提交工具重建，摘要一致。

补丁 1（参数）、补丁 2（更新标签）与恶意参数测试副本分别保存；原官方资产、仅补参数的参照和失败结果保留。以上仅是受控参照验收，不代表原官方 Mihomo v2 已兼容，也不代表实现了握手内兼容版本切换、0-RTT 或性能承诺。
