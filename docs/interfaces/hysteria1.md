# Hysteria v1 双端接口

更新日期：2026-10-31。状态：限定范围已在 perf-02 通过 16 项自端测试、严格检查，以及官方 v1.3.5 的 24 组和 sing-box 1.14.4 的 12 组真实双向矩阵；UDP 对端边界见测试记录，其他分支不继承结果。

`Hysteria1Factory`、`Hysteria1NodeFactory` 分别注册 `hysteria1` 出站与节点。线协议版本固定为 0x03；它与 Hysteria2 的 HTTP/3 鉴权和请求分离。节点物理监听为 QUIC/UDP，不能从 `supports_tcp=false` 推断没有 TCP 业务能力。

## 配置

出站必填 `server: {host,port}`、一项认证、`up_bps`/`down_bps` 和 `tls`；节点必填一项认证或 `users`、`tls`。单项认证二选一：`auth_str` 按 UTF-8 字节使用，`auth` 按标准 base64 解码；同时提供时拒绝。节点多用户为 `users: [{auth_str: ...}, {auth: ...}]`，与单项互斥，最多 256 项，解码后不得重复。认证字节非空、上限 4096。

| 参数 | 行为 |
| --- | --- |
| transport | udp（默认）或 wechat-video，均使用 UDP socket |
| obfs | 可选 xplus 密码；省略或空字符串表示不启用，上限 4096 UTF-8 字节 |
| udp | 默认 true；false 关闭逻辑 UDP 能力与 DATAGRAM 协商，物理载体仍是 QUIC/UDP |
| up_bps/down_bps | 字节/秒。客户端为 16384–10^12；节点可为 0（默认，跟随对端提示）或同范围正数 |
| limits.congestion_control | cubic（默认）、newreno、bbr，保留各自拥塞控制并按协商发送速率约束 pacer；没有 Brutal |
| limits.max_streams | 默认 64，范围 1–1024；有效节点上限还受引擎预算约束 |
| limits.udp_queue_packets | 每会话接收队列默认 32，范围 1–256 |
| limits.udp_queue_bytes | 每连接队列总负载默认 4 MiB，范围 64 KiB–16 MiB |
| limits.idle_timeout_ms | 默认 30000，范围 100–86400000；节点与引擎空闲预算取小值；客户端缓存无活动持有者时回收 |

TLS 客户端为 `tls: {server_name, ca_pem?, alpn?}`；节点为 `tls: {certificate_pem, private_key_pem, alpn?}`，或使用分别与内联互斥的 `certificate_file`/`private_key_file`。文件各不超过 1 MiB，默认 ALPN 为 `["hysteria"]`，不提供跳过证书校验或禁用 TLS 的选项。

```json
{
  "server": {"host": "127.0.0.1", "port": 14443},
  "auth_str": "hysteria1-test-only-node-token",
  "up_bps": 10000000,
  "down_bps": 10000000,
  "transport": "wechat-video",
  "obfs": "xplus-test-only-key",
  "tls": {"server_name": "proxy.example.invalid", "ca_pem": "<测试 CA PEM>"}
}
```

未知字段、Fake-TCP、端口列表/跳跃或 brutal 控制器明确拒绝，不静默回退。没有实现入口硬限速、PMTUD 优化、GSO/GRO/ECN、外部认证、ACME、TUN 或透明接入，不能据普通 QUIC 功能推定这些分支已支持。

## 协议与生命周期

- 客户端收到鉴权成功后才打开业务流。TCP 收到成功响应后才返回，表示网站侧 TCP 已建立，不等于目标应用已响应。自端保留独立 FIN，但旧官方转发器不能保证反向排空，因此通用出站 `tcp_eof=false`，不让 require_remote_eof 配置误通过；目标先发数据与自端 FIN 分别验收。
- 每条 QUIC 连接的标准控制器有独立协商速率状态；服务端发送/接收各按对应方向提示取小值。此行为不是 Brutal，也不构成吞吐或丢包性能保证。
- 节点按实际解码认证字节生成指纹，避免字符串/base64 别名绕过跨节点隔离；鉴权失败关闭当前连接，不尝试其他节点。
- UDP 每会话只创建一次 `AccessService::associate_udp`，同一 socket 访问多个目标，域名解析与 IPv4 优先由统一出口负责。提示地址不限制后续逐包目标；关联能力不足在配置阶段拒绝。
- UDP hold stream 结束时立即回收关联、路由与分片状态。节点会话号单调分配不复用，客户端拒绝重复活动会话号，异步清理回调核对代次。
- 单包负载上限为 65507，并同时受节点 `max_datagram_size` 限制；请求和目标回包都校验。零负载是合法包，不表示关闭。超限或队列满整包丢弃，不截短后发送。
- 分片按连接内会话/消息/代次组装，目标与数量必须一致；重复相同分片不重复计数，冲突丢弃整组。组装最多 128 组、4 MiB、10 秒；完整/冲突消息的近期记录有固定上限。缺片到期不交付。发送按连接串行提交每包全部分片，分片消息号耗尽后至少等待旧窗口过期。
- 载体、逻辑流与 UDP 会话分别取得预算；节点排空期禁止新连接/逻辑流，已有业务按预算结束。自身 socket 句柄随所有者显式关闭，不依赖 QUIC 关闭计时器释放端口。

本项目自端 UDP 已验至 12000 字节，固定官方 CLI 至 4096、固定 sing-box 转发路径至 8192；超限截短仅记负例，外部零包未验。

固定版本与已知对端差异见[调研](../../reference/research_notes/hysteria1.md)，真实结果见[测试记录](../testing/hysteria1.md)。
