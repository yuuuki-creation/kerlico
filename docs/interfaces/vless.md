# VLESS 接口 0.1

状态：普通流出站已实现，并通过固定 Xray、sing-box 对端互通；范围见[验证记录](../testing/vless-ordinary-flow.md)。更新日期：2026-10-30。关联总表任务：`K-V1`；固定目标 UDP 单独验收。

## 当前支持与拒绝

实现 `version=0`、UUID 身份、普通 flow、TCP 承载，提供 TCP 流和固定目标 UDP 的 u16 长度分帧。TLS 默认开启并验证服务端名称和证书链，可添加用户提供的 CA；没有跳过证书验证的配置。

只在回环服务器地址允许显式 `security.type=none`，用于受控测试。库构造器也执行此限制，不仅是 JSON 工厂。REALITY、Vision、XHTTP、Mux/XUDP、VLESS Encryption 和自定义 UUID 字符串映射尚未实现，配置请求这些能力会失败。

## Rust 接口

| 接口 | 契约 |
| --- | --- |
| `UserId::parse` / `from_bytes` | 接受 UUID 或 16 字节身份；Debug 隐藏身份内容，`matches` 使用恒定时间比较 |
| `codec::write_request` / `read_request` | 编解码 TCP/UDP 请求、IPv4/域名/IPv6；附加信息最多 255 字节，拒绝非空 flow 和不支持的命令 |
| `codec::read_request` | 只解码，不代表身份认证；服务端使用者必须单独校验 UserId |
| `write_response` / `read_response` | 响应版本必须为 0；不读取响应头之后的业务负载 |
| `write_datagram` / `read_datagram` | u16 大端长度，最大 65535；保留包边界与零长度；超限或中途截断返回错误 |
| `VlessStream<S>` | 请求已发送后使用的流；首次读取时处理响应头，写入不等待响应，分片和合并到达均不能吞掉业务字节 |
| `VlessOutbound::new` | 服务端地址、UserId 与 TCP/TLS 连接器注入；不依赖 engine 实现 |
| `VlessFactory` | 解码本协议私有 JSON 选项，验证组合并返回 `Outbound`；未知字段拒绝 |

`connect_tcp` 的成功表示 TCP/TLS 已建立、请求头已发送并 flush，不代表远端已认证或目标已连接。VLESS 没有这里可统一等待的成功状态，且对端可能收到首个业务字节后才发响应。响应失败在第一次读取时返回；调用者应结束整条会话，不继续发送或重放。

当前普通 flow 不提供独立的请求 EOF 帧。`VlessStream::shutdown` 关闭逻辑写端并 flush，保留载体继续接收响应；后续写入失败，不提前关闭 TCP/TLS 载体。`tcp_eof=false` 表示不保证最终目标收到写端 EOF；需要该保证的入口必须显式设置 `require_remote_eof=true`，校验会拒绝当前组合。不能把本地半关闭后的反向回写等同于透明传播远端 EOF。

UDP 通道在内部拆开流的读写半部，发送不等待响应头。截断、超时或取消后销毁整个关联，不从残留半帧重新开始。协议帧可表示 65535 字节，但实际网络、对端缓冲和 MTU 可能更小；某些参考端会丢弃零长度包，不能由本地帧测试推定对端兼容。

## 配置选项

出站外层使用 `type=vless`，`options` 为：

| 字段 | 要求 |
| --- | --- |
| `server.host` / `server.port` | 服务端地址和非零端口 |
| `uuid` | UUID；不在错误或 Debug 中输出 |
| `transport` | 默认 `tcp`，首版仅接受该值 |
| `flow` | 默认空；只接受空 |
| `encryption` | 默认 `none`，只接受该值 |
| `security` | 默认 TLS；可设 `{type: tls, server_name, ca_pem}`；服务名省略时使用 server.host |
| `security.type=none` | 仅回环服务器可用；不作为公网使用方式 |

字段表中的简写不是 JSON 示例。完整的可校验结构见[示例配置](../../examples/vless-tls.json)。不兼容上游配置文件的全部字段，不默默忽略未知项。

## 依据与验证

固定参考为 Xray `v26.10.29`，SHA `0afec66085a85191e9dd2a4a6646c7c9a94688d1`：[请求和响应编码](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/vless/encoding/encoding.go)、[附加信息与分帧](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/vless/encoding/addons.go)、[附加信息结构](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/vless/encoding/addons.proto)。滚动协议介绍仍含历史或设想性说明，当前实现以固定源码与实际互通为依据。

当前验收包括独立线格式向量、全部地址类型、逐字节截断、响应延迟、合并/分片、UDP 长度边界、TLS 证书与名称失败、取消/预算和配置拒绝。已完成的上游互通、Linux 构建与最低 Rust 版本结果保存在验证记录；未覆盖组合不继承这些结果。
