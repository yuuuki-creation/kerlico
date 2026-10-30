# AnyTLS 实际接口

状态：已实现，并在 perf-03 完成包级检查、原生双端与固定 sing-box 双向互通；组合边界见[验证记录](../testing/anytls.md)。对应总表 P-15。

根程序已装配本模块，可用 `cargo build -p kerlico --no-default-features --features anytls` 单独启用两端；`anytls` 是 `protocol-anytls` 的功能别名。

`kerlico-anytls` 导出 `AnyTlsFactory` 与 `AnyTlsNodeFactory`，两者注册名均为 `anytls`。依赖现有核心、配置与底层 TLS 连接器；业务目标仅经注入的 `AccessService`，不在协议中解析或选择网站出口地址族。节点预算关闭后拒绝新逻辑流，已有流仍在排空预算内继续收发。

出站 options：

```json
{"server":{"host":"proxy.invalid","port":443},"password":"独立口令","tls":{"server_name":"proxy.invalid","ca_pem":null},"idle_session_timeout_ms":30000,"max_sessions":64}
```

节点 options：

```json
{"passwords":["本节点独立口令"],"tls":{"certificate_file":"server.pem","private_key_file":"server.key"}}
```

TLS 必选。节点也接受 `certificate_pem` / `private_key_pem` 内联内容，各自与文件字段互斥。默认公共根证书可追加出站 `ca_pem`；不提供跳过证书校验。节点可指定 `padding_scheme`，默认采用固定规范的方案。未知字段拒绝。

每个出站实例持有独立连接池和 padding 协商状态。忙会话不外借给其他应用流；闲置会话按顺序复用，逻辑流 ID 单调递增。节点接受同会话多个并发流，受流数和核心 `StreamBudget` 限制。节点凭据指纹用于装配阶段拒绝不同节点重复口令；节点用户表、认证连接和目标通道不跨节点共享。

实现 SHA-256 口令握手、v2 settings、SYN/PSH/FIN、SYNACK、心跳回应、padding 协商与丢弃。TCP 业务地址用 SOCKS 地址编码。UoT v2 使用保留域名，出站使用固定目标 connect 模式；节点同时解码固定目标与逐包地址模式，后者最多建立 32 个目标通道。数据报保留空包及包边界，帧最大 65535 字节，另受运行时限额与实际出口限制；原生双端已验证 65507 字节，对固定 sing-box 的互通只验证至 12000 字节。

`Capabilities` 为 TCP=true、UDP=true、tcp_eof=false；AnyTLS FIN 结束整个逻辑流，不能保证最终目标的 TCP 半关闭。ECH/uTLS/REALITY、ShadowTLS/Restls/JLS、通用 V2Ray transport、通用 mux、UoT v1 和主动心跳探测不在本轮接口内。认证失败直接拒绝，不回退到其他节点、用户表或伪装目标。

客户端逻辑流的 `shutdown` 只禁用后续写入并执行本地 flush，保留反向读取；后续写入返回 `BrokenPipe`。它不会发送 AnyTLS FIN 或承诺目标收到 EOF。完整关闭仍由对端 FIN 或调用方释放流对象触发；服务端真实 EOF/FIN 的处理保持独立。
