# ShadowQUIC 双端接口

日期：2026-10-31。工厂类型为 `shadowquic`。QUIC v1 双端已通过固定 Mihomo 的 TCP、两种 UDP 模式与真实上游回退；v2 已通过 Rust 双端、固定向量及单列受控 Go 参照的完整负载互通、实际密钥更新与参数负例。原固定 Mihomo v2 缺少标准强制版本信息，实际互通被拒绝，不能登记为原资产兼容。详见 `docs/testing/shadowquic.md`。

## 客户端

```json
{
  "server": {"host": "127.0.0.1", "port": 10443},
  "username": "node-user",
  "password": "synthetic-password",
  "server_name": "cover.invalid",
  "alpn": ["h3"],
  "quic_version": "v1",
  "udp_mode": "datagram",
  "congestion_control": "cubic",
  "idle_timeout_secs": 60
}
```

JLS 在 TLS 握手中完成双向认证，必须取得 `is_jls=true` 才能暴露业务流；普通 TLS/证书成功不等于认证成功。传输使用独立包名的 quinn-jls/rustls-jls，未修改其他协议的全局 TLS/QUIC 实现。

`quic_version` 接受 `v1`、`v2`，缺省为 v1；`udp_mode` 接受 `datagram`、`stream`，缺省为 datagram。它们分别对应原生 QUIC datagram 与可靠单向流，不机械套用 TUIC 分片。`congestion_control` 为 `cubic`、`newreno`、`bbr` 的真实控制器，不提供仅改变名字的 BBR3/Brutal 选项，也没有性能结论。

用户名 1–256 字节，密码 1–4096 字节，server_name 必须是会发送 SNI 的 DNS 名称，服务器接入 IP 仍由 server.host 配置；ALPN 非空，每项不超过 255 字节。载体域名有界解析并优先取 IPv4 的首个候选，握手失败不尝试另一地址或另一身份。连接池按出站实例隔离；没有逻辑业务且闲置 30 秒后关闭 QUIC 连接，端点缓存随实例或出站回收。

TCP 无应用层成功回应，发送请求并返回不证明目标已经接纳。FIN 只关闭写方向，继续接收反向数据。QUIC v1/v2 使用受认证版本信息；客户端仅声明选定版本，不做自动跨版本回退或握手内兼容切换。TLS 恢复与 0-RTT 禁用，不跨版本/节点复用票据。

## 服务端节点

```json
{
  "users": [
    {"username": "node-user", "password": "synthetic-password"}
  ],
  "upstream": {"host": "127.0.0.1", "port": 11443},
  "server_name": "cover.invalid",
  "alpn": ["h3"],
  "quic_versions": ["v1", "v2"],
  "congestion_control": "cubic",
  "upstream_rate_bps": 16000000
}
```

单用户可用顶层 `username/password`，与 `users` 互斥。用户数 1–256，节点内重复用户名拒绝；跨节点重复用户名即使密码不同也拒绝。IPv4/IPv6 接入节点分别配置，不隐式共享凭据。节点只绑定 UDP 载体，内部 TCP/UDP 业务不依赖 TCP 监听。

服务器使用本地生成的临时证书承载握手，身份由 JLS secret 验证；不把它当作 PKI 或安全审计结论。`upstream` 是显式配置的普通 QUIC 传输上游，`server_name` 用于 JLS 名称校验；格式检查不拨号、不监听、不隐式解析域名。运行时在建立预算内解析传输上游，再构造端点。

未通过 JLS 的普通 QUIC 只能回退到上述传输上游，不能因此访问任意网站或改用另一代理节点。回退最多 64 个来源且不超过节点配置上限，同时持有全局和节点资源许可；每来源两包、共 128 KiB 接收缓冲，两个方向另各有最多 32 包/256 KiB 的发送队列；闲置不超过节点空闲预算且最高 30 秒，定时清理。`upstream_rate_bps` 为每来源回退速率，范围 8000–8000000000 bit/s，带一个完整 UDP 包的有限 burst。后台初次转发与 QUIC 驱动归属节点作用域，退出时统一取消。

通过 JLS 的 CONNECT、两类 UDP 关联经 `AccessService` 访问目标。节点要求出口提供 `DatagramAssociation`，准备阶段拒绝缺少该能力的代理，不降级为逐目标固定通道。域名解析、默认 IPv4 优先和地址族选择由统一 egress 承担；节点、传输上游和网站的地址族互不绑定。

## UDP、资源与错误边界

一个关联控制流登记多个地址与全连接唯一的 16 位 ID；datagram 只携带 ID 和负载，可靠单向流以 ID 开头并连续携带长度前缀包。双方命名空间独立，重复 ID 不得跨关联覆盖；关闭控制流释放两方向映射和相关单向流。已退役 ID 在同一连接内不重新登记，避免延迟包误入新关联。

Full Cone 关联跨目标/跨地址族保持同一出口 socket，并接收未先联系来源的包。客户端同时提供 `associate_udp` 和固定目标 `connect_udp`；后者按目标来源过滤。空包合法；本模块最大 UDP 负载 65507 字节，节点另遵守 `max_datagram_size`。datagram 超实际 MTU 时整包拒绝，不透明拆包；stream 模式用于大包。

每连接最多 4096 个活动 ID、每关联最多 256 个目标，可靠单向流最多 128；节点预算可能进一步收紧。新关联及服务器的可靠载体各持有资源许可。先于控制映射到达的包缓存最多 128 个 ID、每 ID 16 包、总计 256 KiB，5 秒后清理；未知可靠流最多等待映射 5 秒。半帧读取状态不会因其他后台事件重建；发送中取消后写端失效，必须丢弃关联，不能重试部分帧。

验证范围按角色、版本、模式与地址族分别登记；v2 的原固定 Mihomo 互通仍未通过，受控参照不等于原资产兼容。BIND、应用层 AUTHENTICATE、远程用户管理、Brutal/BBR3、0-RTT、ECH、指纹、热重载和其他平台没有交付；未知字段拒绝。连接统计扩展只返回当前连接计数，不开放用户管理权限。
