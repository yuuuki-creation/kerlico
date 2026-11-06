# OpenVPN 双端接口

`kerlico-openvpn` 注册机器标识为 `openvpn` 的客户端出站（`OpenVpnFactory`）与服务端入站节点（`OpenVpnNodeFactory`），用 Rust 原生实现 OpenVPN 2.x 双端，不启动 `openvpn` 进程，不创建系统 TUN，不修改设备路由或 DNS。IP 包由 `kerlico_wireguard::ip` 的用户态 IP 数据面处理（出站用 `ClientTunnel`，入站每个客户端一个 `ServerTunnel`），详见 [IP 隧道](ip-tunnel.md)。

## 实现范围

- **载体**：UDP 与 TCP（2 字节大端长度分帧）。
- **控制通道**：P_CONTROL_HARD_RESET_CLIENT_V2 起始的 TLS 控制通道，key-method 2，可靠层带重传、乱序重排与 ACK。TLS 由 `rustls` 提供 1.2 与 1.3。
- **控制通道包装**：无包装、`tls-auth`（SHA1、SHA256、SHA384、SHA512，支持 `key-direction`）、`tls-crypt`、`tls-crypt-v2`。客户端读取上游 `--genkey tls-crypt-v2-client` 生成的密钥文件，服务端用上游服务端密钥解开客户端带来的 WKc。
- **客户端身份**：客户端证书、用户名密码，或两者同时使用。只用用户名密码时对应服务端的 `verify-client-cert none`。
- **数据通道**：AES-128-GCM、AES-256-GCM、CHACHA20-POLY1305，线格式 P_DATA_V2。算法经 NCP（`IV_CIPHERS`）由服务端选择。密钥派生同时支持 TLS 导出（`EXPORTER-OpenVPN-datakeys`）和旧服务端使用的 TLS 1.0 PRF，按服务端是否推送 `tls-ekm` 选择。
- **推送配置**：解析 `ifconfig`（`subnet`、`net30`、`p2p` 拓扑）、`ifconfig-ipv6`、`peer-id`、`cipher`、`ping`、`ping-restart`、`auth-token`、`key-derivation`、`protocol-flags` 与 `push-continuation`。
- **保活与换钥**：按 `ping` 发送保活包，超过 `ping-restart` 未收到认证包时重连。服务端或本端发起的软重置（`P_CONTROL_SOFT_RESET_V1`）会重新握手 TLS 并切换到新 `key_id`，隧道内已有 TCP 流不中断；旧接收密钥保留到下一次换钥。服务端推送 `auth-token` 后，换钥使用该令牌代替密码。
- **业务能力**：TCP、TCP 半关闭、固定目标 UDP、多目标 UDP 关联。

## 出站配置（`outbound.options`）

```json
{
  "remote": {"host": "vpn.example.invalid", "port": 1194},
  "proto": "udp",
  "ca_pem": "<CA 证书 PEM 文本>",
  "cert_pem": "<客户端证书 PEM 文本>",
  "key_pem": "<客户端私钥 PEM 文本>",
  "username": "user",
  "password": "<password>",
  "tls_crypt_key": "<OpenVPN 静态密钥文件文本>",
  "ciphers": ["AES-256-GCM", "AES-128-GCM", "CHACHA20-POLY1305"],
  "verify_x509_name": "server"
}
```

| 字段 | 默认 | 含义 |
| --- | --- | --- |
| `remote` | 必填 | 服务端地址。域名在每次连接时解析，优先 IPv4。 |
| `proto` | `udp` | `udp` 或 `tcp`。 |
| `bind` | 无 | 外层 socket 本地地址。 |
| `ca_pem` | 必填 | 校验服务端证书的 CA，PEM 文本，对应 `.ovpn` 的 `<ca>`。 |
| `cert_pem`、`key_pem` | 无 | 客户端证书与私钥，必须成对。私钥不能加密。 |
| `username`、`password` | 无 | 必须成对，各不超过 65534 字节。证书和用户名密码至少提供一种。 |
| `tls_auth` | 无 | `{"key": "<静态密钥文本>", "direction": 1, "digest": "SHA1"}`。`direction` 省略表示双向共用，`digest` 默认 `SHA1`，对应 `--auth`。与 `tls_crypt_key` 互斥。 |
| `tls_crypt_key` | 无 | `tls-crypt` 静态密钥文本。 |
| `tls_crypt_v2` | 无 | `tls-crypt-v2` 客户端密钥文本，内容为 `Kc` 后接 `WKc`，`WKc` 的长度字段在其末尾。三种包装互斥。 |
| `ciphers` | 全部三种 | 允许的数据通道算法，首项在服务端不推送 `cipher` 时使用。 |
| `verify_x509_name` | 无 | 服务端证书 CN 必须与之完全相同，对应 `verify-x509-name <值> name`。 |
| `allowed_ips` | 按分配地址族的全范围 | 允许经隧道访问的 CIDR。不读取推送的 `route`。 |
| `mtu` | `1400` | 隧道内 IP MTU，范围 `1280`–`9000`。不读取推送的 `tun-mtu`。 |
| `ping_secs` | `10` | 保活间隔，服务端推送 `ping` 时覆盖，`0` 关闭。 |
| `ping_restart_secs` | `0` | 重连判定时长，服务端推送 `ping-restart` 时覆盖，`0` 关闭。 |
| `reneg_secs` | `3600` | 本端发起换钥的间隔，`0` 关闭。序号接近 32 位上限时总会换钥。 |
| `handshake_timeout_secs` | `60` | 单次握手或换钥的时限，对应 `hand-window`，范围 `1`–`3600`。 |

## 安全性质

- 服务端证书校验信任链、有效期，并要求叶证书带 serverAuth 扩展用途（EKU）。不带 EKU 扩展的证书被拒绝，只有旧式 `nsCertType=server` 的证书同样被拒绝。这对应 `remote-cert-tls server` 的 EKU 部分，不检查上游同时比较的 keyUsage。OpenVPN 证书通常不含主机名，因此不校验 `remote` 与证书的主机名匹配。未设置 `verify_x509_name` 时，同一 CA 签发的任何 serverAuth 证书都能通过。
- 控制通道包装的认证和数据通道的 AEAD 都带防重放窗口（128 个序号）。认证失败的包直接丢弃，不影响会话。
- `tls-auth` 与 `tls-crypt` 的静态密钥长期不变，旧会话的包重放后仍能通过认证。因此只有回显本次随机会话 ID 的包才能绑定对端会话，之后只接受该会话的包；只有确认属于本会话的包才推进防重放窗口。窗口同时比较对端时间戳，早于已接受时间戳的包被丢弃。时间戳只与对端自身比较，不与本机时钟比较，两端时钟不需要同步。无包装时控制包没有认证和时间戳，上述防重放不适用，服务端身份只靠 TLS 证书保证。

## 目标策略与连接状态

- 出站声明 `TargetPolicy::Local`：隧道只承载字面 IP，域名由共享 `Dispatcher` 在本地解析。服务端推送的 `dhcp-option DNS` 不生效。
- 启动不等待握手。后台会话连接服务端，业务连接在隧道就绪前等待，直到本次连接超时；超时时返回上次会话的失败原因。
- 会话失败后按 1 秒到 60 秒指数退避重连。每次重连建立新 IP 栈，旧连接上的隧道内流随之结束。
- TCP 载体被对端背压时，读取、定时器和换钥继续运行，隧道暂停取新包。发送队列连续 60 秒写不完时判定对端失效并重连，不依赖服务端是否推送 `ping-restart`。
- 收到 `AUTH_FAILED` 或 `HALT` 时不再重试，命名出站进入失败状态，避免反复认证导致账户被锁。收到 `RESTART` 时按普通失败重连。

## 服务端入站（`node.options`）

服务端只实现 TLS 模式，每个会话做完整的 TLS 握手、key-method 2 交换和 `PUSH_REPLY`，数据进入该客户端独立的用户态 IP 栈，经共享 `Dispatcher` 出站。字段采用 sing-box `openvpn-server` 的拼写，括号内为同时接受的旧拼写。

```json
{
  "address": ["10.8.0.1/24", "fd00:8::1/64"],
  "network": ["udp", "tcp"],
  "topology": "subnet",
  "data_ciphers": ["AES-256-GCM", "CHACHA20-POLY1305"],
  "tls": {
    "certificate_path": "server.crt",
    "key_path": "server.key",
    "client_certificate_path": "ca.crt",
    "verify_client_certificate": "require",
    "crl_path": "crl.pem",
    "control_wrap": { "type": "tls_crypt_v2", "key_path": "v2-server.key" }
  },
  "push": { "routes": ["192.0.2.0/24"], "dns": ["192.0.2.53"] },
  "keepalive": { "interval": 10, "timeout": 60 },
  "max_clients": 256
}
```

成员凭据（`members[].native_credential`）为 `{"name": "<用户名或证书 CN>", "password": "<口令>", "address": "10.8.0.50", "push": {...}}`。带口令的成员按用户名与口令认证；不带口令的成员只接受 CN 等于 `name` 且已通过证书校验的客户端，此时 `verify_client_certificate` 必须为 `require`。节点至少需要一个成员。`address` 为该成员的固定地址，须在地址池内且各成员互不相同。

| 字段 | 默认 | 含义 |
| --- | --- | --- |
| `mode` | `tls` | 只接受 `tls`。`static_key` 及其字段（`static_key`、`key_direction`、`cipher`、`peer_address`、`remote`）在配置阶段报“尚未实现”。 |
| `network` | `udp` | `udp`、`tcp` 或两者；两种载体共用一个地址池。 |
| `address` | `10.8.0.1/24` | 服务端自身地址加前缀，每个地址族至多一个。IPv4 前缀不大于 30，IPv6 前缀在 64 到 124 之间。 |
| `topology` | `subnet` | `subnet`：客户端从网段内依次取地址，推送 `route-gateway` 与掩码。`net30`：每个客户端占一个 /30，推送到服务端地址的 `route`。`p2p`：每个客户端一个地址，`ifconfig` 对端为服务端地址。IPv6 客户端地址从网段的 `::1000` 起，与 IPv4 同序号。 |
| `data_ciphers`（`ciphers`） | 三种 AEAD | NCP 按此顺序取第一个客户端声明的算法。客户端声明来自 `IV_CIPHERS`；只有 `IV_NCP=2` 的 2.4 客户端视为支持两种 AES-GCM；更旧的客户端用其 OCC 串里的 `cipher`。只接受 AES-128-GCM、AES-256-GCM、CHACHA20-POLY1305。 |
| `data_ciphers_fallback` | 无 | 上述协商都失败时使用的算法；仍无结果时回 `AUTH_FAILED`。 |
| `max_clients` | `1024` | 握手中与已建立会话的总数上限。满额时新的硬重置被静默丢弃。 |
| `duplicate_cn` | `false` | 关闭时同一身份（证书 CN，无证书时为用户名）再次登录会顶掉旧会话并接手其地址。开启时并存，各占一个地址。 |
| `username_as_common_name` | `false` | 同时有证书与用户名时用用户名作身份。 |
| `keepalive` | `10`、`60` | 服务端 `interval` 秒没有发送时发保活包，`2×timeout` 秒未收到包时关闭会话；向客户端推送 `ping interval` 与 `ping-restart timeout`。`ping`（`ping_interval`）、`ping_restart` 单独覆盖服务端一侧，`push.ping_interval`、`push.ping_restart` 单独覆盖推送值，`0` 关闭。 |
| `handshake_window` | `60s` | 首次握手与每次换钥须在此时限内完成，否则关闭会话。 |
| `renegotiate_interval`（`renegotiate_seconds`） | `1h` | 服务端发起换钥的间隔；`renegotiate_disabled: true` 或 `0` 关闭。`renegotiate_bytes`、`renegotiate_packets` 按当前密钥收发的数据量触发。客户端发起的换钥总会应答。 |
| `transition_window` | `1h` | 换钥后旧接收密钥的保留时长。 |
| `replay_window`、`replay_window_time` | `64`、`15s` | 数据通道防重放窗口大小，以及最高序号到达后更早序号最多晚到多久。 |
| `mtu`（`tun_mtu`） | `1500` | 隧道 IP MTU；不为 1500 时推送 `tun-mtu`。 |
| `mss_fix` | 无 | 只做范围校验。隧道内 TCP 由用户态栈按 `mtu` 通告 MSS，没有单独的钳制。 |
| `push` | 无 | 见下表；成员的 `push` 追加在节点推送之后，其中 `ping` 类数值覆盖节点值。顶层 `route`、`route_ipv6`、`redirect_gateway`、`dhcp_option` 是 `push` 的简写。 |

`push` 字段：

| 字段 | 推送内容 |
| --- | --- |
| `routes`（`route`） | IPv4 CIDR 或“网络 掩码”写成 `route`，IPv6 CIDR 写成 `route-ipv6`。 |
| `route_ipv6` | `route-ipv6`。 |
| `redirect_gateway`、`redirect_gateway_flags` | `true` 时推送 `redirect-gateway`，flag 默认 `def1`。 |
| `dns` | IPv4 写成 `dhcp-option DNS`，IPv6 写成 `dhcp-option DNS6`。 |
| `dns_servers` | 每组 `{priority, addresses, resolve_domains, dnssec, transport, sni}` 写成 `dns server <priority> ...`，2.6 起的客户端识别。 |
| `search_domains` | `dns search-domains`。 |
| `dhcp_options` | `dhcp-option <值>`。 |
| `block_outside_dns` | `block-outside-dns`。 |
| `raw` | 原样推送；不能含逗号或换行。 |

推送超过约 960 字节时按 `push-continuation` 分成多条 `PUSH_REPLY`。

`tls` 字段：

| 字段 | 默认 | 含义 |
| --- | --- | --- |
| `certificate`、`certificate_path`、`key`、`key_path` | 必填 | 服务端证书链与私钥。缺少时配置报错，不生成自签证书。`extra_certs_pem`、`extra_certs_path` 追加到证书链。 |
| `client_certificate`（`ca`）、`client_certificate_path`（`ca_path`） | 无 | 校验客户端证书的 CA。 |
| `verify_client_certificate`（`client_authentication`、`verify_client_cert`） | 有 CA 或指纹时 `require`，否则 `none` | `require`：没有有效证书的客户端在 TLS 握手中被拒。`optional`：请求但不强制。`none`：不请求证书，此时只能用口令成员。顶层 `verify_client_cert_not_required: true` 等同 `none`。 |
| `peer_fingerprint` | 无 | 允许的客户端叶证书 SHA-256 指纹，十六进制，可带冒号。没有 CA 时只按指纹校验。 |
| `crl_path`、`crl_pem` | 无 | 只检查叶证书是否被吊销，需要配合 CA。 |
| `client_name`、`client_name_type` | 无、`name` | 对应 `verify-x509-name`：`name` 比较 CN，`name-prefix` 比较 CN 前缀，`subject` 比较 `C=.., CN=..` 形式的完整主题。旧写法 `verify_x509_name: {name, type}` 等价。 |
| `remote_certificate_tls` | `client` | 对应 `remote-cert-tls`：`client` 要求客户端证书带 clientAuth EKU 且带 keyUsage 扩展，`server` 同理，`none` 不检查。与 `remote_certificate_eku` 互斥。 |
| `remote_certificate_eku` | 无 | 要求的 EKU，名称或点分 OID。 |
| `remote_certificate_ku` | 无 | OpenVPN 记法的 keyUsage 掩码列表，如 `["a0", "88"]`，命中其一即可。 |
| `version_min`、`version_max` | `1.2`、`1.3` | rustls 最低只支持 1.2，`1.0`、`1.1` 作为下限按 1.2 处理。 |
| `cipher`、`cipher_suites` | 默认套件 | TLS 1.2 套件可写 OpenSSL 名（冒号分隔），TLS 1.3 套件写 IANA 名；只列出某一版本的套件时另一版本保持默认。不支持的名称在配置阶段报错。 |
| `groups`（`curve_preferences`） | 默认 | `X25519`、`P-256`、`P-384`，按给出顺序作为密钥交换组。 |
| `export_keying_material` | `true` | `false` 时即使客户端支持也用 TLS 1.0 PRF 派生数据通道密钥。 |
| `control_wrap` | 无 | `type` 为 `tls_auth`、`tls_crypt` 或 `tls_crypt_v2`，密钥写在 `key` 或 `key_path`。`tls_auth` 另有 `direction`（`server` 或 `0` 为默认，`client` 或 `1`）与 `auth`（默认 `SHA1`）。`tls_crypt_v2` 的密钥是 `--genkey tls-crypt-v2-server` 生成的服务端密钥；`v2_metadata_max_age` 拒绝元数据时间戳早于该时长的客户端密钥；`force_cookie: true` 报“尚未实现”。 |

服务端行为：

- 只有能通过控制通道包装认证的 key_id 0 硬重置才会创建会话并占用 `max_clients` 名额，伪造或无法认证的包不分配状态。`tls-crypt-v2` 从 `P_CONTROL_HARD_RESET_CLIENT_V3` 末尾读取 WKc 长度，用服务端密钥校验并解出客户端密钥 Kc，之后的控制包用 Kc 按 `tls-crypt` 处理。服务端不在 reset 中要求重发 WKc，客户端因此不会发送 `P_CONTROL_WKC_V1`。
- 口令或成员不匹配时与上游一样照常完成 key-method 交换，在客户端发出 `PUSH_REQUEST` 后回 `AUTH_FAILED`，确认送达或 5 秒后关闭。证书校验失败在 TLS 握手中以 alert 拒绝。
- 数据通道密钥：客户端 `IV_PROTO` 声明 TLS 导出时用 `EXPORTER-OpenVPN-datakeys`，对 2.6 客户端推送 `protocol-flags cc-exit tls-ekm`，对 2.5 客户端推送 `key-derivation tls-ekm`；2.4 客户端用 TLS 1.0 PRF。每个客户端分到唯一的 `peer-id`。
- 会话在以下情况结束，并释放名额、地址与 `peer-id`：TCP 连接断开、客户端发来 `EXIT` 控制消息或 OCC exit（客户端配置了 `explicit-exit-notify`）、超过 `ping-restart`、握手超时、被同名会话顶替、换钥时凭据不再匹配。同一 UDP 源地址上出现新的会话 ID 时视为客户端重启，旧会话立即作废。
- 换钥：客户端发来新 key_id 的 `P_CONTROL_SOFT_RESET_V1` 时，服务端重新做 TLS 握手与 key-method 交换并复核凭据；到期时服务端主动发起。新接收密钥立即生效，发送方向在本轮控制包全部确认后切换。
- 客户端数据包按 UDP 源地址归属会话，不支持地址漂移（floating）。

## 未实现

服务端入站：`static_key` 模式、`tls_crypt_v2` 的无状态 HMAC cookie（`force_cookie`）、CBC 等非 AEAD 数据通道、压缩、TAP、P_DATA_V1、`client-to-client`、`iroute`、`client-config-dir`、`auth-gen-token`、系统 TUN（`system`、`name`）、MSS 钳制、证书 profile 与 `ns_certificate_type`、客户端地址漂移。这些字段不在可接受字段内，配置时报未知字段或“尚未实现”。

客户端出站：静态密钥模式（`--secret`）、CBC 等非 AEAD 算法、压缩（服务端推送 `comp-lzo` 或 `compress` 时报不支持，包括 `comp-lzo no`）、TAP 模式、P_DATA_V1（服务端必须推送 `peer-id`，2.4 及以上默认如此）、数据通道 epoch 密钥、`explicit-exit-notify`、外层代理（`http-proxy`、`socks-proxy`）、`.ovpn` 文件导入、多个 `remote` 轮换、PKCS#11、加密私钥、`AUTH_PENDING` 流程（服务端挂起认证时在 `handshake_timeout_secs` 内持续重发 `PUSH_REQUEST`，超时后重连）。

## 互通验证

`tools/interop_openvpn.py` 在 worker 的容器内运行 Alpine 打包的官方 OpenVPN 2.6.20 与 2.4.12 服务端，通过 `kerlico run` 的 SOCKS5 本地入站发送真实 TCP 与 UDP，并检查回显字节。用例覆盖两种载体、四种包装（`tls-crypt-v2` 的密钥由官方 openvpn 生成）、三种算法、三种身份组合、内层 IPv6、双向换钥、服务端重启后的重连，以及错误密码、不受信 CA、错误 CN 和同 CA 签发的无 EKU 证书被拒绝。

```sh
cargo build -p kerlico --no-default-features --features protocol-socks,protocol-openvpn
cd tools && python3 interop_openvpn.py --kerlico <kerlico 路径> --work-dir <私有目录>
```

`tools/interop_openvpn_server.py` 验证服务端入站。kerlico 节点监听 Docker 默认网桥的网关地址，官方 OpenVPN 2.6.20 与 2.4.12 客户端在容器内连接，取得推送的隧道地址后经隧道访问回显容器的 TCP 与 UDP。回显服务回报的源地址必须是网桥网关，证明流量经 kerlico 转出。用例覆盖：

- UDP 与 TCP；`tls-crypt` 与官方生成密钥的 `tls-crypt-v2`；证书、口令及两者同时认证。
- NCP 按服务端顺序选中 CHACHA20-POLY1305；2.4 客户端的 PRF 派生；客户端发起换钥后继续收发。
- 两个客户端分别得到 `10.8.0.2` 与 `10.8.0.3`；`max_clients: 1` 下第二个客户端被挡住，第一个客户端退出后它接手 `10.8.0.2`。
- 不受信 CA 签发的客户端证书和错误口令被拒绝。

```sh
cargo build -p kerlico
cd tools && python3 interop_openvpn_server.py --kerlico <kerlico 路径> --work-dir <私有目录>
```
