# 用户态 IP 数据面

`kerlico_wireguard::ip` 将已有用户态 IP 栈与 WireGuard 加密载体分离，供 CONNECT-IP 等原生 IP 隧道复用。模块不注册协议、不创建系统 TUN、不更改设备网络，不执行身份认证或域名解析。

`StackOptions` 包含内部接口地址、允许范围、MTU 与 `StackLimits`。客户端的允许范围限制目标和接收来源；服务端的允许范围约束已分配给此可信会话的来源地址。调用方不能把未经鉴权的网络文本直接转换为 `PeerSession`。

`ClientTunnel` 提供字面 IP 的 TCP、固定 UDP 与多目标 UDP 关联。`ServerTunnel` 接收鉴权后可信 `PeerSession`，将解析出的 TCP/UDP 流交给同一共享 Dispatcher。已有业务计量只发生一次；IP 头、分片与载体开销不计入业务字节。

载体调用 `receive()` 交付完整 IP 包，并持续调用 `next_packet()` 读取待发 IP 包。后者同时推进 TCP 定时器；载体必须仅在单一协议数据路径中消费它。校验、片段重组、范围验证、TCP FIN、UDP 空包及容量限制复用现有实现。

调用方持有后台任务所有权与取消域。`close()` 停止准入并关闭本隧道，丢弃最后客户端句柄或服务端实例也会关闭。此关闭不替代调用方对既有 NodeTasks/ServiceContext 的真实任务回收。服务端各逻辑流仍由原节点任务所有者 join。

海外 `masque-resume-ip-api-r2` 通过原 WireGuard 17 项及新增纯 IP 接口 2 项；`masque-resume-carrier-r6` 在共享载体迁移后再次通过。新增验证实际回环双族 TCP 65537 字节、FIN 尾部、UDP 空包和 IPv4 65507/IPv6 65527 最大负载、伪造来源拒绝、可信用户唯一计量及关闭后的真实任务回收。该证据不能用于登记 MASQUE 协议已经实现或互通。
