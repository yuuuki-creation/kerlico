# MASQUE CONNECT-IP 双端接口

更新日期：2026-11-04（Asia/Shanghai）

`kerlico-masque` 提供双端能力：命名出站 `masque`（`MasqueOutboundFactory`）与服务端节点 `masque`（`MasqueNodeFactory`）。两端均基于 HTTP/3 CONNECT-IP（RFC 9484）与 H3 Datagram 传输 IP 包，分别由 `kerlico_wireguard::ip::ClientTunnel` 与 `ServerTunnel` 用户态栈终结，不创建系统 TUN。业务能力为 TCP、TCP EOF、固定目标 UDP、同出口多目标 UDP 关联。

## 出站配置（`outbound.options`）

```json
{
  "server": {"host": "masque.example.net", "port": 443},
  "uri": "https://masque.example.net/",
  "auth": {"username": "member", "password": "<password>"},
  "headers": {"x-custom-auth": "token"},
  "tls": {
    "server_name": "masque.example.net",
    "ca_pem": "<PEM，可省略>",
    "certificate_pem": "<PEM，可省略>",
    "private_key_pem": "<PEM，可省略>"
  },
  "limits": {"max_tunnels": 64, "idle_timeout_ms": 60000}
}
```

| 字段 | 说明 |
| --- | --- |
| `server` | QUIC 载体端点。域名由本机解析，IPv4 优先。 |
| `uri` | CONNECT-IP 请求的 `https` 绝对 URI，`:authority` 与 `:path` 取自此处。省略时为 `https://<server_name>[:port]/`。含 URI Template 变量（`{target}`、`{ipproto}`）的 URI 被拒绝。 |
| `auth` | 可省略。提供时发送 `Authorization: Basic`；Xray 的 `username` 对应其用户 `email`，`password` 对应 `pass`。 |
| `headers` | 可省略。附加到 HTTP/3 CONNECT-IP 请求的自定义标头映射。 |
| `tls.server_name` | 必填，用于 SNI 和证书名称校验，与 `server` 独立。 |
| `tls.ca_pem` | 信任根。省略时使用内置 WebPKI 根。自签部署把服务端证书放在这里。 |
| `tls.certificate_pem`、`tls.private_key_pem` | 客户端证书，必须成对提供。 |
| `limits.max_tunnels` | 同时存在的隧道上限，范围 1–1024，默认 64。 |
| `limits.idle_timeout_ms` | 隧道没有活动流后保留的时长，范围 1000–86400000，默认 60000。 |

## 入站配置（`node.options`）

```json
{
  "address": ["10.89.0.2/32", "fd00:89::2/128"],
  "advertise_routes": ["0.0.0.0/0", "::/0"],
  "mtu": 1280,
  "path": "/",
  "tls": {
    "certificate_pem": "<PEM>",
    "private_key_pem": "<PEM>"
  },
  "users": [
    {"username": "member", "password": "<password>"}
  ]
}
```

| 字段 | 说明 |
| --- | --- |
| `address` | 必填，客户端隧道分配的 IPv4/IPv6 地址（字符串或数组，每个地址族最多一个），经 `ADDRESS_ASSIGN` 胶囊下发。 |
| `advertise_routes`（别名 `advertise-routes`） | 可省略。经 `ROUTE_ADVERTISEMENT` 胶囊下发的 CIDR 或 IP 范围列表，省略时默认通告 `0.0.0.0/0` 与 `::/0`。 |
| `mtu` | 服务端用户态 IP 栈 MTU，范围 1280–9000，默认 1280。 |
| `path` | 可省略。要求 CONNECT-IP 请求 `:path` 完全匹配该路径（须以 `/` 开头）。 |
| `tls` | 必填，服务端证书与私钥（`certificate_pem`/`private_key_pem` 或 `certificate_file`/`private_key_file`），ALPN 固定为 `h3`。 |
| `users` | 可省略。内联 `{username/email, password/pass, level}` 列表或节点级管理账户原生凭据（Basic 认证，常量时间 SHA-256 摘要比对）。 |

TLS 固定为 1.3，ALPN 固定为 `h3`，始终校验证书，不发送 0-RTT。

对应的 Xray 服务端：`protocol: masque` 入站，`streamSettings.network: masque`，`security: tls`，`tlsSettings.alpn: ["h3"]`，`masqueSettings.path` 与 `uri` 的路径一致。Xray 不校验 `:authority`。

## 行为

- **路由归属**：`TargetPolicy::Local`。CONNECT-IP 承载 IP 包，共享调度器先解析网站域名，出站只接受字面 IP。载体端点的解析与业务目标解析分开。
- **隧道与作用域**：按 `ConnectContext::resource_key()` 为每个可信来源建立一条隧道，一条 QUIC 连接只承载一个 CONNECT-IP 请求。首个流到达时建立，无活动流达到 `idle_timeout_ms` 后关闭，隧道失败不影响其他作用域，下一条流重新建立。隧道失败不重放业务数据，也不回退直连。
- **建立顺序**：等待对端 SETTINGS 同时开启 Extended CONNECT 和 HTTP Datagram，发送 `:protocol=connect-ip`、`capsule-protocol: ?1`，收到 2xx 后发送 ADDRESS_REQUEST（IPv4、IPv6 各一条），收到第一条可用的 ADDRESS_ASSIGN 后开始转发。
- **建立退避**：凭据属于整个出站，所以退避按出站计算，所有来源共用，新隧道逐个建立。代理返回 4xx 后 60 秒内不再重试，直接返回 `Rejected`。其他建立失败（5xx、QUIC 或协议错误）按 1 秒到 60 秒指数退避，期间返回明确错误，建立成功后清零。业务连接在建立完成前取消或超时的，这次建立不计入退避。
- **地址**：每个地址族取第一条未被拒绝的分配。前缀短于地址宽度时取第一个主机地址。代理撤回正在使用的地址时结束隧道。只分配一个地址族时，另一地址族的目标被拒绝。
- **路由**：收到 ROUTE_ADVERTISEMENT 后，通告范围外的目标直接返回 `Rejected`；收到通告之前不做本地过滤，由代理决定。
- **数据面**：IP 包走 QUIC DATAGRAM，负载为 Quarter Stream ID、Context ID 0、完整 IP 包。其他 Context ID、其他请求流的数据报及 HTTP/3 流上的 DATAGRAM Capsule 被丢弃。隧道内 MTU 默认 1280，更大的 UDP 由用户态栈分片。QUIC 路径 MTU 下限为 1350，DATAGRAM 放不下 1280 字节 IP 包时建立失败并返回 `Unsupported`。
- **保活**：QUIC 每 10 秒保活，空闲超时 30 秒。
- **对端请求地址**：客户端收到 ADDRESS_REQUEST 时逐条拒绝。

## 未实现

- HTTP/2 CONNECT-IP（Capsule 承载 IP 包）。
- Cloudflare WARP 的 `cf-connect-ip` 配置档：需要已注册设备身份。
- CONNECT-UDP（RFC 9298）、Mihomo `h3-l4proxy`。
- IP Flow Forwarding（URI Template 的 `target`、`ipproto`）。
- TCP/UDP 以外的任意 IP 协议转发；用户态栈只对 ICMP 做本地控制响应。
- 跳过证书校验。

## 真实限制

Xray 作为服务端时不向最终目标传递 TCP 半关闭：FIN 到达 Xray 后，`freedom` 出站不对目标调用 `CloseWrite`，1 秒后（`DownlinkOnly` 默认值）结束连接。依赖“先发 FIN 再收响应”的应用在该路径上收不到响应。

Xray 的 gVisor 栈丢弃源或目标为回环地址的 IP 包，隧道内不能访问代理本机的 `127.0.0.1` 或 `::1`。

代理进程重启后，旧隧道要等 QUIC 空闲超时（30 秒）才结束，期间新流失败，之后自动重新建立。

## 验证

`tools/interop_masque.py` 运行 `kerlico run`（SOCKS5 本地入站加本出站）对接固定提交 `0afec66` 的 Xray 26.10.29 masque 服务端。业务目标用文档地址，由 Xray `freedom.redirect` 转到本机 echo。

```sh
python3 tools/interop_masque.py --kerlico target/debug/kerlico --xray <xray 路径> --work-dir <新目录>
```
