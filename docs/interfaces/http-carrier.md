# HTTP 载体基础设施

`kerlico-http-carrier` 从原 TrustTunnel 消费实现中提取，提供 H2/H3 DATA 字节流、有真实任务所有者的 QUIC runtime 与可关闭 UDP socket。它不实现 CONNECT 鉴权、目标路由、协议凭据、资源池或业务流量计量。

`BodyIo::boxed(Writer, Reader)` 接收原生 H2/H3 请求/响应端，返回 `BoxStream`。H2 写入等待完整流控许可，读取及时释放流控，关闭在最后一段 DATA 之后发 FIN；H3 使用原生请求流的分片、FIN 与 reset 语义。发送、接收与协议 handler 的所有权随返回流移动，不另起复制任务。

`runtime::ServiceRuntime::new(ServiceContext)` 把 QUIC 原生任务登记到命名服务。`NodeRuntime::new(&CancellationToken, NodeTasks)` 把节点 QUIC 原生任务登记到 Engine 持有的真实节点任务集合，维护独立子取消域。`guard()` 只停止自己的原生任务；`shutdown_at(endpoint, connections, deadline)` 在有限期限内关闭 endpoint、等待真实任务并返回 `Graceful` 或 `Forced`，任务失败与超时不会伪装成功。

`runtime::spawn_owned` 把 handler 的真实 future 登记到给定 `NodeTasks`，本地 JoinSet 只等待实际所有者的完成结果。调用者必须在自身关闭时取消子域、停止接纳并排空本地集合，不能只关闭 waiter 后宣称真实 handler 已退出。

`socket::wrap(std::net::UdpSocket)` 返回 `Arc<dyn quinn::AsyncUdpSocket>` 与 `Close`。关闭句柄会立即释放底层 socket、清理 poller 并唤醒等待者，不要求其他临时 Arc 引用先丢弃。`Close` 需要由对应 endpoint 的所有者保留并显式关闭。

海外验证 `masque-resume-carrier-r6`：共享 crate 原生所有权/socket 两项测试、原 TrustTunnel 单元 35 项、成员分区 1 项与网络 11 项、WireGuard 原 17 项和纯 IP 接口 2 项全部通过。`masque-resume-carrier-fmt-r7` 在海外完成格式化。该证据只说明基础设施迁移与原消费者回归，不构成 MASQUE 互通证据。
