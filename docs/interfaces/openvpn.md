# OpenVPN 客户端出站接口

`kerlico-openvpn` 注册机器标识为 `openvpn` 的出站，用 Rust 原生实现 OpenVPN 2.x 客户端，不启动 `openvpn` 进程，不创建系统 TUN，不修改设备路由或 DNS。IP 包由 `kerlico_wireguard::ip::ClientTunnel` 这一用户态 IP 数据面处理，详见 [IP 隧道](ip-tunnel.md)。

## 实现范围

- **载体**：UDP 与 TCP（2 字节大端长度分帧）。
- **控制通道**：P_CONTROL_HARD_RESET_CLIENT_V2 起始的 TLS 控制通道，key-method 2，可靠层带重传、乱序重排与 ACK。TLS 由 `rustls` 提供 1.2 与 1.3。
- **控制通道包装**：无包装、`tls-auth`（SHA1、SHA256、SHA384、SHA512，支持 `key-direction`）、`tls-crypt`。
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

## 未实现

静态密钥模式（`--secret`）、CBC 等非 AEAD 算法、压缩（服务端推送 `comp-lzo` 或 `compress` 时报不支持，包括 `comp-lzo no`）、TAP 模式、服务端角色、P_DATA_V1（服务端必须推送 `peer-id`，2.4 及以上默认如此）、`tls-crypt-v2`、数据通道 epoch 密钥、`explicit-exit-notify`、外层代理（`http-proxy`、`socks-proxy`）、`.ovpn` 文件导入、多个 `remote` 轮换、PKCS#11、加密私钥、`AUTH_PENDING` 流程（服务端挂起认证时在 `handshake_timeout_secs` 内持续重发 `PUSH_REQUEST`，超时后重连）。

## 互通验证

`tools/interop_openvpn.py` 在 worker 的容器内运行 Alpine 打包的官方 OpenVPN 2.6.20 与 2.4.12 服务端，通过 `kerlico run` 的 SOCKS5 本地入站发送真实 TCP 与 UDP，并检查回显字节。用例覆盖两种载体、三种包装、三种算法、三种身份组合、内层 IPv6、双向换钥、服务端重启后的重连，以及错误密码、不受信 CA、错误 CN 和同 CA 签发的无 EKU 证书被拒绝。

```sh
cargo build -p kerlico --no-default-features --features protocol-socks,protocol-openvpn
cd tools && python3 interop_openvpn.py --kerlico <kerlico 路径> --work-dir <私有目录>
```
