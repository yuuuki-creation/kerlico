# 核心接口 0.1

状态：框架已实现并通过首轮本地测试，接口仍可随真实协议接入演进。更新日期：2026-10-30。

## 模块依赖

`kerlico-core` 定义地址、I/O、取消和出站契约，不依赖 JSON 或具体协议。`kerlico-config` 定义 JSON 外层、工厂注册和准备结果。`kerlico-net` 实现 TCP/TLS、直连和拒绝。`kerlico-engine` 只使用已构造的出站接口；程序入口负责注册具体模块。

协议配置解析放在协议的工厂中。工厂依赖 config 的格式边界，core 不因此依赖序列化技术。这里是对早期“工厂全部放 core-api”草案的具体化调整。

## 公共契约

| 接口 | 行为 |
| --- | --- |
| `Destination::new(host, port)` | 区分 IPv4/IPv6 与 IDNA 规范化域名；端口必须非零，域名编码长度不超过 255 字节 |
| `Outbound::capabilities()` | 分别报告 TCP、目标写端 EOF 传播和固定目标 UDP；不隐含 XUDP、多目标、TUN 或其他传输 |
| `connect_tcp(target, context)` | 返回可读写流；完成程度由协议文档定义，不能一概当作远端业务已接纳 |
| `connect_udp(target, context)` | 返回固定目标的 `DatagramChannel`，发送与接收句柄分别独占各自状态，允许全双工 |
| `ConnectContext::run` | 建立阶段共用一次超时与取消预算；取消后销毁该次操作持有的资源 |
| `DatagramSender::send` | 发送完整包；中途取消后丢弃会话，不重试可能只发送了一部分的帧 |
| `DatagramReceiver::recv` | 返回一个完整包；空 Vec 是零长度包，None 是会话结束，二者不同 |
| `OutboundFactory::build` | 解析模块选项并构造本地对象；不拨号、不监听、不改系统网络 |
| `Registry::prepare` | 校验配置版本、标签、模块类型、引用与数据能力；未知字段和未注册模块拒绝，不回退直连 |
| `Engine::bind` | 一次准备全部监听器；中途失败时回收前面取得的资源 |
| `Engine::run(cancel)` | 停止新接入，给已有任务有限排空时间，再取消并回收；调用方应等待其返回 |

`timeout` 对一次 `ConnectContext::run` 调用生效。当前每次建立只调用一次，覆盖代理服务器解析、TCP/TLS 与请求发送；若调用方拆成多次操作，应自行维持总截止时间。成功返回后的流/包 I/O 取消与空闲预算由调用方或 engine 管理，不由建立上下文自动包办。

## 当前运行边界

入站暂为回环地址的 `tcp-forward` 与 `udp-forward`，每个入口指向固定目的地址和出站。这是用于真实端到端路径的转发入口，不冒充尚未实现的 SOCKS/HTTP 协议。

TCP 转发保留本地半关闭并继续收取反向数据；能否把写端 EOF 传播到最终目标由 `tcp_eof` 能力单独声明。直连提供该能力，当前普通 VLESS 不提供。入口配置 `require_remote_eof=true` 时，不兼容的出站在准备阶段被拒绝。空闲预算按成功读写推进。

UDP 每个来源有独立关联、有限包队列和出站通道，过大或排队失败的包整包丢弃。全局关联/连接数量共享 `max_sessions` 限额；不能把可配置的较大上限当成机器一定有足够资源的保证。

第一版无热重载、动态装载、进程级沙箱或无限重试。取消和超时关闭当前路径，不能在业务负载已经发送后透明换出站重放。真实用户名、凭证和配置内容不写进公开日志。

接口定义以 `crates/core-api/src/lib.rs`、`crates/config/src/lib.rs` 为准；VLESS 的建立和响应语义见[VLESS 接口](vless.md)。
