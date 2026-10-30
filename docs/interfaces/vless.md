# VLESS 接口 0.2（开发中）

更新日期：2026-10-30。本轮双向完整矩阵等快照已通过，最新共享生命周期增量尚未复验，见[快照记录](../testing/vless-combinations.md)。0.1 已发布范围及历史证据保留在[普通流记录](../testing/vless-ordinary-flow.md)；这些结果不外推本轮全部代码。

## 角色与分层

`VlessFactory` 注册出站 `vless`，`VlessNodeFactory` 注册服务端节点 `vless`。节点负责安全、VLESS 身份和协议解码，鉴权后只通过 `AccessService` 访问业务目标。传输、安全、Encryption、Vision 和包编码分别装配，非法组合在配置阶段拒绝。最终仍是一个程序，协议通过 Cargo feature 裁剪。

节点和统一出口约定见[实际接口](node-egress.md)。每个节点拥有独立用户表、重放状态、Encryption ticket 和资源配额；IPv4、IPv6 节点不能复用 UUID。节点接入地址族不限制网站目标或上游代理载体的地址族。

## 出站配置

外层 `type=vless`，私有字段位于 `options`；未知字段拒绝。

| 字段 | 契约 |
| --- | --- |
| `server.host` / `server.port` | 节点地址与非零端口 |
| `server_family` | `auto`（默认）、`ipv4`、`ipv6`；仅筛选节点载体解析结果，不改变网站目标 |
| `uuid` | UUID，Debug 与错误隐藏身份 |
| `transport` | `tcp`/`raw` 字符串，或下表的带 `type` 对象 |
| `flow` | 空、`xtls-rprx-vision`、`xtls-rprx-vision-udp443`；后者只在客户端放开业务 UDP/443 |
| `encryption` | 默认 `none`；使用固定 Xray mlkem768x25519plus 字符串格式 |
| `security` | 默认 TLS；`tls`、`reality`、`none`，字段见下表 |
| `packet_encoding` | `udp`（默认）、`xudp`、`packetaddr`；Vision 自动使用 XUDP |
| `mux` | 可选 `{enabled,tcp,udp,concurrency,max_connections}`；默认值为 `true,true,true,8,4`，不提供对象则不建池 |

| 载体对象 | 字段与限制 |
| --- | --- |
| `{type:tcp}` | 无额外字段 |
| `{type:ws}` | `path`、`host`、`headers`、`early_data_bytes`、`heartbeat_period_secs` |
| `{type:httpupgrade}` | `path`、`host`、`headers` |
| `{type:grpc}` | `service_name`、`authority`、`multi_mode`、`idle_timeout_secs`、`health_check_timeout_secs`、`permit_without_stream`、`initial_window_size` |
| `{type:xhttp,settings:{…}}` | `path`、`host`、`mode`、`http_version`、`headers`、`no_grpc_header`、`max_post_bytes`、`min_post_interval_ms`、`max_buffered_posts`、`padding_bytes`、`download` |
| `{type:xdrive,settings:{…}}` | 专用存储载体，见下节 |

XHTTP `mode` 为 `auto`、`packet-up`、`stream-up`、`stream-one`；`http_version` 为 `auto`、`h1`、`h2`、`h3`。独立下载 `download` 包含自己的 `server`、`server_family`、`security` 和 `xhttp`，不得再嵌套下载或与 `stream-one` 并用。上下行分别解析地址、建立安全连接，保留各自 CA 和安全身份。

| 安全对象 | 字段与限制 |
| --- | --- |
| `{type:tls}` | `server_name`、`ca_pem`、`alpn`、`fingerprint`；自定义 CA 不能同时启用指纹整形；名称和证书链必须验证 |
| `{type:reality}` | `server_name`、`public_key`、`short_id`、`fingerprint`、可选 `mldsa65_verify`；指纹默认 `chrome`；只用于 RAW、gRPC、XHTTP/H2 |
| `{type:none}` | 未启用 Encryption 时仅允许回环节点地址 |

Vision 要求 RAW TLS/REALITY 或先启用 Encryption；不能用于 XDRIVE。Vision 不能复用 TCP 业务，可将 Mux 设为 `tcp:false,udp:true`。固定 Xray 对 XHTTP 也限制为 UDP Mux，本项目配置阶段拒绝 XHTTP 的 TCP Mux；TCP 使用 XHTTP 自身 XMUX。`packetaddr` 仅接受 IP 目标，不能与 Vision 或 Mux UDP 混用。Mux 并发为 1–256，物理连接为 1–32；达到上限返回资源错误，不无限排队或重放业务。

## 节点配置

节点外层包含 `tag`、`type:vless`、`listen`、`outbound`、可选 `max_sessions`。`options` 包含：

| 字段 | 契约 |
| --- | --- |
| `uuid`、`flow` | 单用户简写，不能与 `users` 同时提供 |
| `users` | 1–256 个 `{uuid,flow}`；flow 为空或 `xtls-rprx-vision` |
| `security` | 必填；`none`，或 TLS 的证书/密钥，或 REALITY 身份 |
| `transport` | 默认 TCP；对象字段见下文 |
| `decryption` | 默认 `none`；固定 Xray 服务端格式，最多 8 个密钥；暂拒绝非空自定义 padding |

TLS 使用 `certificate_pem`/`private_key_pem` 或 `certificate_file`/`private_key_file`；每种材料必须二选一，单项最大 1 MiB。REALITY 使用 `cover:{host,port}`、`private_key`、`server_names`、`short_ids`、`max_time_diff_ms`（默认 60000，最大 300000）；失败握手转发到固定 cover，不能把客户端目标当作回退地址。

节点传输对象分别为 TCP、`ws:{path,early_data_bytes}`、`httpupgrade:{path}`、`grpc:{service_name}`、`xhttp:{settings:{path,mode,http_version}}`、XDRIVE。XHTTP/H3 使用同一节点的 UDP 端口并要求 TLS；`auto` 可同时监听 TCP 与 UDP。HTTP 载体有有界队列、帧长度和会话限制。服务端接受原生 UDP、XUDP/Mux、packetaddr，各自保持包边界和目标语义。

## XDRIVE

客户端与服务端必须使用 Encryption、空 flow；客户端显式启用 TCP/UDP Mux。存储 endpoint 自行决定 HTTP 身份，禁止叠加 REALITY。服务端为虚拟监听，不绑定配置中的占位 `listen`；其 `security` 为 `none`，CA 放入存储设置。

`settings` 包含 `service`、`remote_folder`、`secrets`、可选 `template`、`s3`、`ca_pem`。服务为 `local`、`google-drive`、`template`、`s3`；S3 包含 `endpoint`、`region`、`bucket`、`path_style`。模板采用固定 Xray 的操作模板，支持 header/basic/OAuth2、预签名 URL、名称匹配和有界重试。Google Drive 包含 OAuth2 刷新、description 内联、media 与槽描述读写。

资源设置及默认值：`segment_bytes=65536`、`flush_interval_ms=20`、`poll_interval_ms=100`、`max_poll_interval_ms=2000`、`session_ttl_seconds=300`、`concurrency=4`、`eager_window_ms=1000`、`hole_timeout_ms=10000`。写端 flush 等待分段实际提交，shutdown 等待 END；读取按序号恢复并检测缺口。支持 WAL 分段，以及 Google Drive 对端公告的槽环。真实云账户互通必须另记证据，不能由本地或模拟存储通过推定。

## 流和数据报语义

`connect_tcp` 成功表示载体建立并发送请求，不能推定远端已认证或网站已连接；首次读取可能收到响应失败。失败后终止会话，不自动重放已发送字节。普通 VLESS 没有独立请求 EOF 帧；逻辑 shutdown 保留反向读取，`tcp_eof=false`。要求目标 EOF 的入口必须被能力校验拒绝。

数据报保留包边界和零长度；原生长度字段最大 65535，Mux 每帧负载上限 8192，实际对端/网络可能更小。截断、取消、错误身份或超时终止对应关联，不从残留半帧恢复。XUDP global ID 当前按物理载体内的逻辑会话处理；尚未提供跨载体迁移的全局 UDP 会话表。

公开的 0.1 `UserId`、`codec`、`VlessStream` 和 `VlessOutbound::new` 保留；通用组合由工厂选择。旧 `codec` 的普通流限制不等同于节点入口的扩展解析器。

本轮未实现 mKCP、反向代理控制面、任意上游配置兼容、路由规则语言、TUN/Fake-IP；不得将本轮协议适配登记为完整 VPN 产品。已验证与待验证组合由总表和实际测试记录维护。

ML-DSA 验签、混合 NFS 链及真实云账户尚未互通验收；服务端未提供 ML-DSA 签名 seed 配置。当前提交为用户要求保存的开发快照，下一轮先完成最新增量的远端检查。
