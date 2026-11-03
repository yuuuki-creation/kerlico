# 实验性功能

由 `tools/capability_matrix.py build` 生成，不要手改。

## config

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `cache-file` | 缓存文件配置对象 |  | 有 |  | 未实现 | 未测 |  |
| `clash-api` | Clash API 配置对象 |  | 有 |  | 部分 | 通过 |  |
| `debug` | experimental.debug 调试配置对象，文档未列 |  | 有 |  | 不适用 | 未测 |  |
| `v2ray-api` | V2Ray API 配置对象 |  | 有 |  | 未实现 | 未测 |  |

## debug

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `gc-percent` | experimental.debug.gc_percent，Go 运行时调试项，文档未列 |  | 有 |  | 不适用 | 未测 |  |
| `max-stack` | experimental.debug.max_stack，Go 运行时调试项，文档未列 |  | 有 |  | 不适用 | 未测 |  |
| `max-threads` | experimental.debug.max_threads，Go 运行时调试项，文档未列 |  | 有 |  | 不适用 | 未测 |  |
| `memory-limit` | experimental.debug.memory_limit，Go 运行时调试项，文档未列 |  | 有 |  | 不适用 | 未测 |  |
| `oom-killer` | experimental.debug.oom_killer，Go 运行时调试项，文档未列 |  | 有 |  | 不适用 | 未测 |  |
| `panic-on-fault` | experimental.debug.panic_on_fault，Go 运行时调试项，文档未列 |  | 有 |  | 不适用 | 未测 |  |
| `trace-back` | experimental.debug.trace_back，Go 运行时调试项，文档未列 |  | 有 |  | 不适用 | 未测 |  |

## global

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `dialer-ip4p-convert` | 启用 IP4P 地址转换 | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `fingerprints` | 全局证书指纹列表（配置结构存在；http 页面仍提及 experimental.fingerprints） | 有 |  |  | 未实现 | 未测 | 取值：`sha256 列表` |
| `quic-go-disable-ecn` | 禁用 quic-go ECN | 有 |  |  | 不适用 | 未测 | 取值：`false`、`true` |
| `quic-go-disable-gso` | 禁用 quic-go GSO | 有 |  |  | 不适用 | 未测 | 取值：`false`、`true` |
