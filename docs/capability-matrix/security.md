# 安全层

由 `tools/capability_matrix.py build` 生成，不要手改。

## by-protocol

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | 各协议对 TLS 字段的要求 |  | 有 |  | 待标注 | 未测 | tls_required：`anytls(outbound)`、`hysteria`、`hysteria2`、`naive(outbound)`、`shadowtls(outbound)`、`tuic`<br>tls_optional：`anytls(inbound)`、`http`、`masque`、`naive(inbound)`、`trojan`、`vless`、`vmess`<br>no_tls_field：`direct`、`mixed`、`shadowsocks`、`shadowtls(inbound)`、`snell`、`socks`、`ssh`、`tor`、`wireguard`<br>约束：tls 必填依据各协议页与 source:protocol/*/ 的 ErrTLSRequired |

## cert-provider

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | 证书提供者的类型、挑战方式和认证组合 |  | 有 |  | 待标注 | 未测 | type：`acme`、`cloudflare-origin-ca`、`tailscale`<br>ref：`inline`、`tag`<br>acme_provider：`https://...`、`letsencrypt`、`zerossl`<br>acme_challenge：`dns-01`、`http-01`、`tls-alpn-01`<br>dns01_provider：`acmedns`、`alidns`、`cloudflare`<br>key_type：`ed25519`、`p256`、`p384`、`rsa2048`、`rsa4096`<br>origin_ca_auth：`api_token`、`origin_ca_key`<br>约束：api_token 与 origin_ca_key 冲突<br>约束：propagation_timeout 为 -1 时关闭传播检查<br>约束：provider 为 Let's Encrypt 且 profile 留空时，域名含 IP 自动用 shortlived<br>约束：provider 为 zerossl 时 external_account、email、account_key 至少一个<br>约束：配了 dns01_challenge 时其他挑战方式被禁用 |

## ech

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | ECH 组合 |  |  | 有 | 待标注 | 未测 | config_source：`domain+https`、`fixed`、`h2c`、`https`、`udp`<br>alpn_inner：`http/1.1(ws/httpupgrade)`、`用户配置`<br>fingerprint：`uTLS`<br>server_mode：`ech+non-ech`<br>约束：WARP masque 边缘不支持 ECH（docs/document/level-2/warp.md）<br>约束：WebSocket 或 HTTPUpgrade 时 inner 强制 http/1.1<br>约束：outer ALPN 总为 h2,http/1.1 |
| `config` | ECH 配置，空则 DNS 解析，否则 base64 | 有 |  |  | 待标注 | 未测 | 取值：`base64`<br>约束：可由 mihomo generate ech-keypair 生成，Config 填此，Key 填服务端 ech-key |
| `ech-config-list` | 仅客户端，ECHConfig |  |  | 有 | 待标注 | 未测 | 取值：`base64 固定 ECHConfig`、`example.com+https://1.1.1.1/dns-query`、`h2c://...`、`https://1.1.1.1/dns-query`、`udp://1.1.1.1`<br>约束：DNS 模式遵守 TTL，查询 SNI 或服务器域名<br>约束：默认端口 53/443 |
| `ech-server-keys` | 仅服务端，启用 ECH 的密钥 |  |  | 有 | 待标注 | 未测 | 约束：xray tls ech 生成<br>约束：配置后仍接受非 ECH 连接 |
| `ech-sockopt` | 查询 ECH DNS 的 socket 选项 |  |  | 有 | 待标注 | 未测 |  |
| `enable` | 启用 ECH | 有 |  |  | 待标注 | 未测 | 取值：`false`、`true` |
| `query-server-name` | DNS 解析 ECH 时用的域名 | 有 |  |  | 待标注 | 未测 | 取值：`域名` |

## jls

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `password` | JLS 密码 | 有 |  |  | 待标注 | 未测 | 取值：`字符串` |
| `username` | JLS 用户名 | 有 |  |  | 待标注 | 未测 | 取值：`字符串`<br>约束：用 sni、servername 作 SNI<br>约束：需 tls: true |

## mtls

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `certificate` | 客户端证书，填写开启 mTLS | 有 |  |  | 待标注 | 未测 | 取值：`PEM`、`路径`<br>约束：需与 private-key 同填 |
| `private-key` | 客户端私钥，填写开启 mTLS | 有 |  |  | 待标注 | 未测 | 取值：`PEM`、`路径`<br>约束：需与 certificate 同填 |
| `server` | 服务端 mTLS 见各入站 client-auth-type、client-auth-cert | 有 |  |  | 待标注 | 未测 | 取值：``、`request`、`require-and-verify`、`require-any`、`verify-if-given` |

## reality

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `reality` | REALITY 传输安全 |  |  | 有 | 待标注 | 未测 | 取值：`reality`<br>约束：仅支持 RAW、XHTTP、gRPC<br>约束：监听非 443 时告警（source:infra/conf/xray.go） |
| `combo` | REALITY 组合 |  |  | 有 | 待标注 | 未测 | transport：`grpc`、`raw`、`xhttp`<br>protocol：`http`、`shadowsocks`、`socks`、`trojan`、`vless`、`vmess`<br>flow：``、`xtls-rprx-vision`<br>sni：`serverName`、`无 SNI`<br>short_id：`空`、`非空`<br>post_quantum：`mldsa65`、`off`<br>fallback_limit：`off`、`on`<br>约束：Vision 只能配 raw<br>约束：XHTTP 文档称 REALITY 时 auto 用 stream-one<br>约束：socks、shadowsocks 未启用 XUDP 时 UDP 绕过 REALITY<br>约束：不支持 websocket、httpupgrade、mkcp、hysteria、masque |
| `after-bytes` | 限速起始字节，默认 0 |  |  | 有 | 待标注 | 未测 |  |
| `burst-bytes-per-sec` | 突发速率，大于 bytesPerSec 生效 |  |  | 有 | 待标注 | 未测 |  |
| `bytes-per-sec` | 基准速率，默认 0 不启用 |  |  | 有 | 待标注 | 未测 |  |
| `dest` | target 的旧名 |  |  | 有 | 待标注 | 未测 |  |
| `fingerprint` | 仅客户端，必填，同 TLS fingerprint |  |  | 有 | 待标注 | 未测 | 约束：不支持 unsafe |
| `limit-fallback-download` | 仅服务端，未验证回落连接限速 |  |  | 有 | 待标注 | 未测 | 约束：文档不建议启用；面板应随机化 |
| `limit-fallback-upload` | 仅服务端，未验证回落连接限速 |  |  | 有 | 待标注 | 未测 | 约束：文档不建议启用；面板应随机化 |
| `master-key-log` | 预主密钥日志路径，文档未写 |  |  | 有 | 待标注 | 未测 |  |
| `max-client-ver` | 仅服务端，客户端最高版本 x.y.z |  |  | 有 | 待标注 | 未测 |  |
| `max-time-diff` | 仅服务端，最大时间差毫秒 |  |  | 有 | 待标注 | 未测 |  |
| `min-client-ver` | 仅服务端，客户端最低版本 x.y.z |  |  | 有 | 待标注 | 未测 |  |
| `mldsa65-seed` | 仅服务端，ML-DSA-65 后量子签名私钥 |  |  | 有 | 待标注 | 未测 | 约束：target 证书长度必须大于 3500<br>约束：target 需支持 X25519MLKEM768<br>约束：不能与 privateKey 相同（source:infra/conf/transport_security.go） |
| `mldsa65-verify` | 仅客户端，mldsa65 公钥 |  |  | 有 | 待标注 | 未测 |  |
| `password` | 仅客户端，必填，服务端私钥对应公钥 |  |  | 有 | 待标注 | 未测 | 约束：旧称 publicKey，xray x25519 -i 生成 |
| `post-quantum` | target 支持 X25519MLKEM768 时客户端自动使用后量子密钥协商 |  |  | 有 | 待标注 | 未测 |  |
| `private-key` | 仅服务端，必填，xray x25519 生成 |  |  | 有 | 待标注 | 未测 |  |
| `public-key` | reality 服务端私钥对应公钥 | 有 |  | 有 | 待标注 | 未测 | 取值：`字符串`<br>约束：reality-opts 不为空即启用<br>约束：不考虑 xray v26.7.11+ 兼容性 |
| `server-name` | 仅客户端，服务端 serverNames 之一 |  |  | 有 | 待标注 | 未测 | 约束：填 IP 时发送无 SNI Client Hello |
| `server-names` | 仅服务端，必填，可用 SNI 列表 |  |  | 有 | 待标注 | 未测 | 约束：不支持通配符<br>约束：含 "" 时接受无 SNI，客户端 serverName 填 IP |
| `short-id` | 服务端 short id 之一 | 有 |  | 有 | 待标注 | 未测 | 取值：`字符串`<br>约束：最多 16 位 hex，长度必须为偶数，不足补 0 |
| `short-ids` | 仅服务端，必填，shortId 列表 |  |  | 有 | 待标注 | 未测 | 约束：含空值时客户端可空 |
| `show` | 输出调试信息 |  |  | 有 | 待标注 | 未测 |  |
| `spider-x` | 仅客户端，爬虫初始路径 |  |  | 有 | 待标注 | 未测 |  |
| `support-x25519mlkem768` | 支持 X25519-MLKEM768 密钥交换 | 有 |  |  | 待标注 | 未测 | 取值：`false`、`true` |
| `target` | 仅服务端，必填，回落目标，格式同 fallbacks dest |  |  | 有 | 待标注 | 未测 | 约束：旧称 dest，互为别名<br>约束：核心按该字段区分服务端配置，客户端不要填<br>约束：鉴权失败流量直接转发到 target |
| `type` | 回落网络类型，文档未写 |  |  | 有 | 待标注 | 未测 |  |
| `xver` | 仅服务端，PROXY protocol 版本 |  |  | 有 | 待标注 | 未测 | 取值：`0`、`1`、`2` |

## restls

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `password` | Restls 密码 | 有 |  |  | 待标注 | 未测 | 取值：`字符串`<br>约束：用 sni、servername 作 SNI<br>约束：需 tls: true |
| `restls-script` | 握手后载体流量脚本 | 有 |  |  | 待标注 | 未测 | 取值：`字符串` |
| `version-hint` | TLS 版本提示 | 有 |  |  | 待标注 | 未测 | 取值：`tls12`、`tls13` |

## shadow-tls

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `password` | ShadowTLS 密码 | 有 |  |  | 待标注 | 未测 | 取值：`字符串` |
| `version` | ShadowTLS 版本，留空默认 v2 | 有 |  |  | 待标注 | 未测 | 取值：`1`、`2`、`3`<br>约束：用 sni、servername 作 SNI<br>约束：需 tls: true |

## stream-settings

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `reality-settings` | REALITY 配置 |  |  | 有 | 待标注 | 未测 | 约束：仅 security 为 reality 有效<br>约束：仅支持 RAW、XHTTP、gRPC |
| `security` | 传输安全，默认 none |  |  | 有 | 待标注 | 未测 | 取值：`none`、`reality`、`tls`<br>约束：xtls 已移除，配置报错（source:infra/conf/transport_internet.go） |
| `tls-settings` | TLS 配置 |  |  | 有 | 待标注 | 未测 | 约束：不支持 DTLS<br>约束：仅 security 为 tls 有效<br>约束：支持 RAW、XHTTP、mKCP、gRPC、WebSocket、HTTPUpgrade、Hysteria、MASQUE |
| `xtls` | 旧 XTLS 安全层 |  |  | 已移除 | 待标注 | 未测 | 约束：配置报错，改用 xtls-rprx-vision |

## tls

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | TLS 的角色、引擎、模式、证书、校验和抗审查选项维度与约束 |  | 有 | 有 | 待标注 | 未测 | role：`inbound`、`outbound`<br>engine：`apple`、`go`、`windows`<br>mode：`reality`、`tls`、`tls+ech`、`tls+utls`<br>version：`1.0`、`1.1`、`1.2`、`1.3`<br>cert_source：`acme(deprecated)`、`certificate`、`certificate_path`、`certificate_provider`<br>peer_verify：`certificate`、`certificate_public_key_sha256`、`certificate_sha256`、`insecure`、`system`<br>mtls：`no`、`request`、`require-and-verify`、`require-any`、`verify-if-given`<br>anti_censorship：`fragment`、`record_fragment`、`spoof`<br>spoof_method：`wrong-ack`、`wrong-checksum`、`wrong-md5`、`wrong-sequence`、`wrong-timestamp`<br>ktls：`kernel_rx`、`kernel_tx`、`off`<br>约束：ACME 字段自 1.14.0 废弃，1.16.0 移除<br>约束：QUIC 下自定义 TLS 只支持 ECH<br>约束：REALITY 不支持 spoof、disable_sni（source:common/tls/reality_client.go、utls_client.go）<br>约束：REALITY 与 ECH 冲突（source:common/tls/reality_server.go）<br>约束：REALITY 客户端必须启用 uTLS（source:common/tls/reality_client.go）<br>约束：certificate_sha256、certificate_public_key_sha256 与 certificate、certificate_path 冲突（source:common/tls/std_client.go）<br>约束：kernel_tx、kernel_rx 仅 Linux 5.1+ 且仅 TLS 1.3<br>约束：spoof 仅 Linux、macOS、Windows 且需要提权，Windows ARM64 不支持<br>约束：spoof 必须不同于 server_name（source:common/tls/client.go）<br>约束：verify-if-given、require-and-verify 需要配 client_certificate、client_certificate_path、client_certificate_sha256、client_certificate_public_key_sha256 之一<br>约束：windows 引擎需要 Windows build 17763 以上，TLS 1.3 需要 Windows 11 或 Server 2022<br>约束：wrong-timestamp 不支持 macOS<br>约束：客户端未设 server_name 也未设 insecure 时报错（source:common/tls/client.go）<br>约束：客户端证书和私钥必须同时提供（source:common/tls/std_client.go）<br>约束：非 go 引擎不支持 disable_sni、cipher_suites、curve_preferences、客户端证书、fragment、record_fragment、kernel_tx、kernel_rx、ech、utls、reality<br>transport：`grpc`、`httpupgrade`、`hysteria`、`masque`、`mkcp`、`raw`、`websocket`、`xhttp`<br>cert_mode：`encipherment`、`issue`、`verify`<br>verify：`pin`、`system/builtin CA`、`verifyPeerCertByName`<br>fingerprint：`random`、`randomized`、`unsafe`、`utls 原名`、`浏览器`<br>mtls：`off`、`verify 证书`<br>ech：`off`、`on`<br>约束：REALITY 不支持 unsafe<br>约束：fingerprint 模拟只影响 Client Hello<br>约束：hysteria、masque 必须 tls |
| `acme` | TLS 内联 ACME 配置对象 |  | 废弃 |  | 待标注 | 未测 |  |
| `acme-alternative-http-port` | 用于 ACME HTTP 质询的备用端口；如果非空，将使用此端口而不是 80 来启动 HTTP 质询的侦听器。 |  | 废弃 |  | 待标注 | 未测 |  |
| `acme-alternative-tls-port` | 用于 ACME TLS-ALPN 质询的备用端口； 系统必须将 443 转发到此端口以使质询成功。 |  | 废弃 |  | 待标注 | 未测 |  |
| `acme-data-directory` | ACME 数据存储目录。 |  | 废弃 |  | 待标注 | 未测 |  |
| `acme-default-server-name` | 如果 ClientHello 的 ServerName 字段为空，则选择证书时要使用的服务器名称。 |  | 废弃 |  | 待标注 | 未测 |  |
| `acme-disable-http-challenge` | 禁用所有 HTTP 质询。 |  | 废弃 |  | 待标注 | 未测 |  |
| `acme-disable-tls-alpn-challenge` | 禁用所有 TLS-ALPN 质询。 |  | 废弃 |  | 待标注 | 未测 |  |
| `acme-dns01-challenge` | ACME DNS01 验证字段。 |  | 废弃 |  | 待标注 | 未测 |  |
| `acme-domain` | 域名列表。 |  | 废弃 |  | 待标注 | 未测 |  |
| `acme-email` | 创建或选择现有 ACME 服务器帐户时使用的电子邮件地址。 |  | 废弃 |  | 待标注 | 未测 |  |
| `acme-external-account` | EAB（外部帐户绑定）包含将 ACME 帐户绑定或映射到 CA 已知的其他帐户所需的信息。 |  | 废弃 |  | 待标注 | 未测 | 约束：为了启用 ACME 帐户绑定，运行 ACME 服务器的 CA 需要使用 ACME 之外的某种机制向 ACME 客户端提供 MAC 密钥和密钥标识符。 |
| `acme-external-account-key-id` | 密钥标识符。 |  | 废弃 |  | 待标注 | 未测 |  |
| `acme-external-account-mac-key` | MAC 密钥。 |  | 废弃 |  | 待标注 | 未测 |  |
| `acme-provider` | 要使用的 ACME CA 供应商。 |  | 废弃 |  | 待标注 | 未测 | 取值：`https://...`、`letsencrypt`、`zerossl` |
| `allow-insecure` | 跳过证书校验 |  |  | 已移除 | 待标注 | 未测 | 取值：`false`、`true`<br>约束：改用 pinnedPeerCertSha256、verifyPeerCertByName<br>约束：文档标弃用；源码 true 时报错（source:infra/conf/transport_security.go） |
| `alpn` | ALPN 列表，优先顺序 | 有 | 有 | 有 | 待标注 | 未测 | 取值：`FromMitM`、`h2`、`h3`、`http/1.1`<br>约束：无共同协议时连接失败<br>约束：FromMitM 只能单独一个元素 |
| `certificate` | 服务器证书链行数组，PEM 格式。 |  | 有 |  | 待标注 | 未测 |  |
| `certificate-path` | 服务器证书链路径，PEM 格式。 |  | 有 |  | 待标注 | 未测 |  |
| `certificate-provider` | 字符串或对象。 |  | 有 |  | 待标注 | 未测 | 约束：仅服务器<br>约束：自 sing-box 1.14.0 起 |
| `certificate-public-key-sha256` | 服务器证书公钥的 SHA-256 哈希列表，base64 格式。 |  | 有 |  | 待标注 | 未测 | 约束：仅客户端<br>约束：自 sing-box 1.13.0 起 |
| `certificate-sha256` | 服务器证书的 SHA-256 哈希列表，base64 格式。 |  | 有 |  | 待标注 | 未测 | 约束：仅客户端<br>约束：如果只需要固定公钥，请使用 `certificate_public_key_sha256`。<br>约束：自 sing-box 1.15.0 起 |
| `certificates` | 证书列表，建议 fullchain |  |  | 有 | 待标注 | 未测 |  |
| `cipher-suites` | 启用的 TLS 1.0–1.2 密码套件列表。 |  | 有 | 有 | 待标注 | 未测 | 取值：`TLS_AES_128_GCM_SHA256`、`TLS_AES_256_GCM_SHA384`、`TLS_CHACHA20_POLY1305_SHA256`、`TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA`、`TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`、`TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA`、`TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`、`TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256`、`TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA`、`TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`、`TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA`、`TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`、`TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256`、`TLS_RSA_WITH_AES_128_CBC_SHA`、`TLS_RSA_WITH_AES_128_GCM_SHA256`、`TLS_RSA_WITH_AES_256_CBC_SHA`、`TLS_RSA_WITH_AES_256_GCM_SHA384`<br>约束：列表的顺序被忽略。<br>约束：如果为空，则使用安全的默认列表。<br>约束：默认密码套件可能会随着时间的推移而改变。 |
| `client-authentication` | 要使用的客户端身份验证类型。 |  | 有 |  | 待标注 | 未测 | 取值：`no`、`request`、`require-and-verify`、`require-any`、`verify-if-given`<br>约束：* `no`（默认）<br>约束：仅服务器<br>约束：如果此选项设置为 `verify-if-given` 或 `require-and-verify`，则需要 `client_certificate`、`client_certificate_path`、`client_certificate_sha256` 或 `client_certificate_public_key_sha256` 中的一个。<br>约束：自 sing-box 1.13.0 起 |
| `client-certificate` | 客户端证书链行数组，PEM 格式。 |  | 有 |  | 待标注 | 未测 | 约束：仅客户端<br>约束：仅服务器<br>约束：自 sing-box 1.13.0 起 |
| `client-certificate-path` | 客户端证书链路径，PEM 格式。 |  | 有 |  | 待标注 | 未测 | 约束：仅客户端<br>约束：仅服务器<br>约束：自 sing-box 1.13.0 起 |
| `client-certificate-public-key-sha256` | 客户端证书公钥的 SHA-256 哈希列表，base64 格式。 |  | 有 |  | 待标注 | 未测 | 约束：仅服务器<br>约束：自 sing-box 1.13.0 起 |
| `client-certificate-sha256` | 客户端证书的 SHA-256 哈希列表，base64 格式。 |  | 有 |  | 待标注 | 未测 | 约束：仅服务器<br>约束：自 sing-box 1.15.0 起 |
| `client-key` | 客户端私钥行数组，PEM 格式。 |  | 有 |  | 待标注 | 未测 | 约束：仅客户端<br>约束：自 sing-box 1.13.0 起 |
| `client-key-path` | 客户端私钥路径，PEM 格式。 |  | 有 |  | 待标注 | 未测 | 约束：仅客户端<br>约束：自 sing-box 1.13.0 起 |
| `curve-preferences` | 支持的密钥交换机制集合。 |  | 有 | 有 | 待标注 | 未测 | 取值：`CurveP256`、`CurveP384`、`CurveP521`、`P256`、`P384`、`P521`、`SecP256r1MLKEM768`、`SecP384r1MLKEM1024`、`X25519`、`X25519MLKEM768`<br>约束：列表的顺序被忽略，密钥交换机制通过 Golang 的内部偏好顺序从此列表中选择。<br>约束：可用值，同时也是默认列表：<br>约束：自 sing-box 1.13.0 起<br>约束：SecP256r1MLKEM768、SecP384r1MLKEM1024 未被 utls 支持<br>约束：调整顺序不改变偏好 |
| `disable-sni` | 不要在 ClientHello 中发送服务器名称. |  | 有 |  | 待标注 | 未测 | 约束：仅客户端 |
| `disable-system-root` | true 时只用 certificates 中的证书 |  |  | 有 | 待标注 | 未测 |  |
| `ech` | ECH 配置对象 |  | 有 |  | 待标注 | 未测 |  |
| `ech-config` | ECH 配置行数组，PEM 格式。 |  | 有 |  | 待标注 | 未测 | 约束：仅客户端 |
| `ech-config-path` | ECH 配置路径，PEM 格式。 |  | 有 |  | 待标注 | 未测 | 约束：仅客户端 |
| `ech-dynamic-record-sizing-disabled` | 禁用 TLS 记录的自适应大小调整。 |  | 已移除 |  | 待标注 | 未测 | 约束：`dynamic_record_sizing_disabled` 已在 sing-box 1.12.0 废弃且已在 sing-box 1.13.0 中被移除。 |
| `ech-enabled` | 启用开关 |  | 有 |  | 待标注 | 未测 |  |
| `ech-key` | ECH 密钥行数组，PEM 格式。 |  | 有 |  | 待标注 | 未测 | 约束：仅服务器 |
| `ech-key-path` | ECH 密钥路径，PEM 格式。 |  | 有 |  | 待标注 | 未测 | 约束：仅服务器 |
| `ech-pq-signature-schemes-enabled` | 启用对后量子对等证书签名方案的支持。 |  | 已移除 |  | 待标注 | 未测 | 约束：`pq_signature_schemes_enabled` 已在 sing-box 1.12.0 废弃且已在 sing-box 1.13.0 中被移除。 |
| `ech-query-server-name` | 覆盖用于 ECH HTTPS 记录查询的域名。 |  | 有 |  | 待标注 | 未测 | 约束：仅客户端<br>约束：自 sing-box 1.13.0 起 |
| `enable-session-resumption` | 会话恢复，默认禁用 |  |  | 有 | 待标注 | 未测 | 约束：不是 0-RTT<br>约束：两端都启用才协商 |
| `enabled` | 启用 TLS |  | 有 |  | 待标注 | 未测 |  |
| `engine` | 要使用的 TLS 引擎。 |  | 有 |  | 待标注 | 未测 | 取值：`apple`、`go`、`windows`<br>约束：* `go`（默认）<br>约束：TLS 1.3 仅在 Windows 11 或 Windows Server 2022 及后续版本上协商。<br>约束：`windows` 通过 SSPI 使用 Schannel，仅在 Windows build 17763 及以上可用，包括 Windows 10 版本 1809、Windows Server 2019 及后续版本。<br>约束：不支持的字段：<br>约束：仅客户端<br>约束：自 sing-box 1.14.0 起<br>约束：默认版本范围为 TLS 1.2 到 TLS 1.3，与 `go` 引擎一致。 |
| `fingerprint` | 证书 SHA256 指纹 | 有 |  | 有 | 待标注 | 未测 | 取值：`360`、`Hello360_11_0`、`Hello360_7_5`、`Hello360_Auto`、`HelloAndroid_11_OkHttp`、`HelloChrome_100`、`HelloChrome_100_PSK`、`HelloChrome_102`、`HelloChrome_106_Shuffle`、`HelloChrome_112_PSK_Shuf`、`HelloChrome_114_Padding_PSK_Shuf`、`HelloChrome_120`、`HelloChrome_131`、`HelloChrome_133`、`HelloChrome_58`、`HelloChrome_62`、`HelloChrome_70`、`HelloChrome_72`、`HelloChrome_83`、`HelloChrome_87`、`HelloChrome_96`、`HelloChrome_Auto`、`HelloEdge_106`、`HelloEdge_85`……<br>约束：不是 HPKP 公钥指纹<br>约束：中级或根证书验证链，自 v1.19.20 还需符合 SNI<br>约束：叶子证书只比对指纹<br>约束：ECH 时 outer 总为 h2,http/1.1<br>约束：uTLS 下 ALPN 默认 h2,http/1.1；WebSocket/HTTPUpgrade 默认 http/1.1<br>约束：uTLS 下仍传递 serverName、disableSystemRoot、pinnedPeerCertSha256、masterKeyLog、echConfigList、echSockopt<br>约束：unsafe 恢复原生 Go TLS<br>约束：指纹名单来自文档与 source:transport/internet/tls/tls.go |
| `fragment` | 通过分段 TLS 握手数据包来绕过防火墙。 |  | 有 |  | 待标注 | 未测 | 约束：仅客户端<br>约束：在 Linux、Apple 平台和（需要管理员权限的）Windows 系统上，可以自动检测等待时间。<br>约束：由于性能不佳，请首先尝试 `record_fragment`，且仅应用于已知被阻止的服务器名称。<br>约束：自 sing-box 1.12.0 起 |
| `fragment-fallback-delay` | 当 TLS 分段无法自动确定等待时间时使用的回退值。 |  | 有 |  | 待标注 | 未测 | 约束：仅客户端<br>约束：自 sing-box 1.12.0 起<br>约束：默认使用 `500ms`。 |
| `handshake-timeout` | TLS 握手超时，采用 golang 的 Duration 格式。 |  | 有 |  | 待标注 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：默认使用 `15s`。 |
| `insecure` | 接受任何服务器证书。 |  | 有 |  | 待标注 | 未测 | 约束：仅客户端 |
| `kernel-rx` | 启用内核 TLS 接收支持。 |  | 有 |  | 待标注 | 未测 | 约束：仅支持 Linux 5.1+，如果可能，使用较新的内核。<br>约束：仅支持 TLS 1.3。<br>约束：自 sing-box 1.13.0 起 |
| `kernel-tx` | 启用内核 TLS 发送支持。 |  | 有 |  | 待标注 | 未测 | 约束：kTLS TX 仅当 `splice(2)` 可用时（两端经过握手后必须为没有附加协议的 TCP 或 TLS）才能提高性能；否则肯定会降低性能。<br>约束：仅支持 Linux 5.1+，如果可能，使用较新的内核。<br>约束：仅支持 TLS 1.3。<br>约束：自 sing-box 1.13.0 起 |
| `key` | 服务器 PEM 私钥行数组。 |  | 有 |  | 待标注 | 未测 | 约束：仅服务器 |
| `key-path` | 服务器私钥路径，PEM 格式。 |  | 有 |  | 待标注 | 未测 | 约束：仅服务器 |
| `master-key-log` | 预主密钥日志路径 |  |  | 有 | 待标注 | 未测 |  |
| `max-version` | 可接受的最大 TLS 版本。 |  | 有 | 有 | 待标注 | 未测 | 取值：`1.0`、`1.1`、`1.2`、`1.3`<br>约束：默认情况下，当前最高版本为 TLS 1.3。<br>约束：取值来自源码（source:transport/internet/tls/config.go） |
| `min-version` | 可接受的最低 TLS 版本。 |  | 有 | 有 | 待标注 | 未测 | 取值：`1.0`、`1.1`、`1.2`、`1.3`<br>约束：默认使用 TLS 1.2。<br>约束：取值来自源码（source:transport/internet/tls/config.go） |
| `mtls` | 文档用 usage=verify 验证远端证书；未单列 mTLS 配置，masque warp 另有客户端证书 |  |  | 有 | 待标注 | 未测 |  |
| `name-cert-verify` | 仅修改证书 DNSName 校验目标，不改 SNI | 有 |  |  | 待标注 | 未测 | 取值：`域名` |
| `pinned-peer-cert-sha256` | 证书 SHA256 pin，hex，逗号分隔 |  |  | 有 | 待标注 | 未测 | 约束：兼容带冒号格式<br>约束：命中叶子证书直接通过；命中 CA 时按 serverName 验签<br>约束：覆盖默认校验 |
| `reality` | REALITY 配置对象 |  | 有 |  | 待标注 | 未测 |  |
| `reality-enabled` | 启用开关 |  | 有 |  | 待标注 | 未测 |  |
| `reality-handshake` | 握手服务器地址和 拨号参数。 |  | 有 |  | 待标注 | 未测 | 约束：仅服务器<br>约束：必填 |
| `reality-handshake-server` | REALITY 握手服务器地址 |  | 有 |  | 待标注 | 未测 |  |
| `reality-handshake-server-port` | REALITY 握手服务器端口 |  | 有 |  | 待标注 | 未测 |  |
| `reality-max-time-difference` | 服务器和客户端之间的最大时间差。 |  | 有 |  | 待标注 | 未测 | 约束：仅服务器 |
| `reality-private-key` | 私钥，由 `sing-box generate reality-keypair` 生成。 |  | 有 |  | 待标注 | 未测 | 约束：仅服务器<br>约束：必填 |
| `reality-public-key` | 公钥，由 `sing-box generate reality-keypair` 生成。 |  | 有 |  | 待标注 | 未测 | 约束：仅客户端<br>约束：必填 |
| `reality-short-id` | 一个零到八位的十六进制字符串。 |  | 有 |  | 待标注 | 未测 | 约束：必填 |
| `record-fragment` | 将 TLS 握手分段为多个 TLS 记录以绕过防火墙。 |  | 有 |  | 待标注 | 未测 | 约束：仅客户端<br>约束：自 sing-box 1.12.0 起 |
| `reject-unknown-sni` | 服务端 SNI 不匹配证书时拒绝握手，默认 false |  |  | 有 | 待标注 | 未测 |  |
| `server-name` | 用于验证返回证书上的主机名，除非设置不安全。 |  | 有 | 有 | 待标注 | 未测 | 取值：`FromMitM`、`IP`、`[IPv6]`、`域名`<br>约束：FromMitM 用 tunnel 入站解密 TLS 的 SNI<br>约束：IP 不发 SNI<br>约束：留空用 address（域名） |
| `servername` | VMess、VLESS 的 SNI 字段 | 有 |  |  | 待标注 | 未测 | 取值：`域名` |
| `skip-cert-verify` | 跳过证书验证 | 有 |  |  | 待标注 | 未测 | 取值：`false`、`true` |
| `sni` | 服务器名称指示；VMess、VLESS 写 servername | 有 |  |  | 待标注 | 未测 | 取值：`域名`<br>约束：为空用 server |
| `spoof` | 在真实 ClientHello 之前注入一个伪造的、携带白名单 SNI 的 TLS ClientHello，以欺骗基于 SNI 过滤的中间盒放行连接。 |  | 有 |  | 待标注 | 未测 | 约束：Linux 上需要 `CAP_NET_RAW` 和 `CAP_NET_ADMIN`，macOS 上需要 root，Windows 上需要 Administrator。<br>约束：不支持 Windows ARM64。<br>约束：仅客户端<br>约束：仅支持 Linux、macOS 和 Windows，需要提升的权限。<br>约束：自 sing-box 1.14.0 起 |
| `spoof-method` | 控制伪造报文被真实服务器拒绝的方式。 |  | 有 |  | 待标注 | 未测 | 取值：`wrong-ack`、`wrong-checksum`、`wrong-md5`、`wrong-sequence`、`wrong-timestamp`<br>约束：仅客户端<br>约束：自 sing-box 1.14.0 起 |
| `tls` | 启用 tls | 有 |  | 有 | 待标注 | 未测 | 取值：`false`、`tls`、`true`<br>约束：trojan 强制启用<br>约束：本页列表未含 MASQUE，docs/config/transport.md 列出 MASQUE |
| `use-system-ca` | 默认 false 用内置 CA，true 用系统 CA |  |  | 有 | 待标注 | 未测 |  |
| `utls` | uTLS 是 "crypto/tls" 的一个分支，它提供了 ClientHello 指纹识别阻力。 |  | 有 |  | 待标注 | 未测 | 取值：`360`、`android`、`chrome`、`edge`、`firefox`、`ios`、`qq`、`random`、`randomized`、`safari`<br>约束：1.10.0 起已移除并回退到 chrome：chrome_psk、chrome_psk_shuffle、chrome_padding_psk_shuffle、chrome_pq、chrome_pq_psk<br>约束：仅客户端<br>约束：默认使用 chrome 指纹。 |
| `utls-enabled` | 启用开关 |  | 有 |  | 待标注 | 未测 |  |
| `utls-fingerprint` | uTLS 指纹名称 |  | 有 |  | 待标注 | 未测 | 取值：`360`、`android`、`chrome`、`edge`、`firefox`、`ios`、`qq`、`random`、`randomized`、`safari`<br>约束：留空时使用 chrome |
| `verify-peer-cert-by-name` | 仅客户端，校验证书用的名字，逗号分隔 |  |  | 有 | 待标注 | 未测 | 取值：`FromMitM`、`域名列表`<br>约束：覆盖 serverName 校验 |

## tlsmirror

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `connection-enrolment-primary-egress-outbound` | 连接登记出站侧控制出站标识，mihomo 一般留空 | 有 |  |  | 待标注 | 未测 | 取值：`字符串` |
| `connection-enrolment-primary-ingress-outbound` | 连接登记入站侧控制出站标识 | 有 |  |  | 待标注 | 未测 | 取值：`字符串` |
| `defer-instance-derived-write-time-base-nanoseconds` | 首写前固定延迟，纳秒 | 有 |  |  | 待标注 | 未测 | 取值：`整数` |
| `defer-instance-derived-write-time-uniform-random-multiplier-nanoseconds` | 首写前随机延迟上限，纳秒 | 有 |  |  | 待标注 | 未测 | 取值：`整数` |
| `embedded-traffic-generator-steps` | HTTP 载体流量步骤；未配置不启用，协议由 alpn 决定 | 有 |  |  | 待标注 | 未测 | 取值：`列表` |
| `embedded-traffic-generator-steps-connection-ready` | 该步骤完成后再交付代理连接 | 有 |  |  | 待标注 | 未测 | 取值：`false`、`true` |
| `embedded-traffic-generator-steps-connection-recall-exit` | 代理连接关闭后退出载体流量 | 有 |  |  | 待标注 | 未测 | 取值：`false`、`true` |
| `embedded-traffic-generator-steps-h2-do-not-wait-for-download-finish` | h2 载体不等响应体读完 | 有 |  |  | 待标注 | 未测 | 取值：`false`、`true` |
| `embedded-traffic-generator-steps-headers` | 请求头，name 配 value 或 values | 有 |  |  | 待标注 | 未测 | 取值：`列表` |
| `embedded-traffic-generator-steps-headers-name` | 请求头名 | 有 |  |  | 待标注 | 未测 | 取值：`字符串` |
| `embedded-traffic-generator-steps-headers-value` | 单个头值 | 有 |  |  | 待标注 | 未测 | 取值：`字符串` |
| `embedded-traffic-generator-steps-headers-values` | 多个头值 | 有 |  |  | 待标注 | 未测 | 取值：`列表` |
| `embedded-traffic-generator-steps-host` | 请求主机 | 有 |  |  | 待标注 | 未测 | 取值：`域名` |
| `embedded-traffic-generator-steps-method` | 请求方法 | 有 |  |  | 待标注 | 未测 | 取值：`HTTP 方法` |
| `embedded-traffic-generator-steps-name` | 步骤名 | 有 |  |  | 待标注 | 未测 | 取值：`字符串` |
| `embedded-traffic-generator-steps-next-step` | 下一步加权候选，weight、goto-location | 有 |  |  | 待标注 | 未测 | 取值：`列表` |
| `embedded-traffic-generator-steps-next-step-goto-location` | 跳转步骤下标 | 有 |  |  | 待标注 | 未测 | 取值：`整数` |
| `embedded-traffic-generator-steps-next-step-weight` | 候选权重 | 有 |  |  | 待标注 | 未测 | 取值：`整数` |
| `embedded-traffic-generator-steps-path` | 请求路径 | 有 |  |  | 待标注 | 未测 | 取值：`路径` |
| `embedded-traffic-generator-steps-wait-time` | 步骤后等待，base-nanoseconds、uniform-random-multiplier-nanoseconds | 有 |  |  | 待标注 | 未测 | 取值：`对象` |
| `embedded-traffic-generator-steps-wait-time-base-nanoseconds` | 等待固定时间，纳秒 | 有 |  |  | 待标注 | 未测 | 取值：`整数` |
| `embedded-traffic-generator-steps-wait-time-uniform-random-multiplier-nanoseconds` | 等待随机上限，纳秒 | 有 |  |  | 待标注 | 未测 | 取值：`整数` |
| `explicit-nonce-ciphersuites` | TLS 1.2 载体显式 nonce 套件 | 有 |  |  | 待标注 | 未测 | 取值：`整数列表` |
| `primary-key` | 必填，32 字节主密钥 base64 | 有 |  |  | 待标注 | 未测 | 取值：`base64`<br>约束：tls 为 true 且配置 tlsmirror-opts 时启用<br>约束：目前仅 VMess 支持<br>约束：载体复用 servername、alpn、skip-cert-verify、name-cert-verify、fingerprint、certificate、private-key、client-fingerprint、ech-opts |
| `sequence-watermarking-enabled` | 序列水印 | 有 |  |  | 待标注 | 未测 | 取值：`false`、`true` |
| `transport-layer-padding-enabled` | 传输层填充 | 有 |  |  | 待标注 | 未测 | 取值：`false`、`true` |

## utls

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `client-fingerprint` | 客户端 uTLS 指纹 | 有 |  |  | 待标注 | 未测 | 取值：`360`、`android`、`chrome`、`edge`、`firefox`、`ios`、`qq`、`random`、`safari`<br>约束：random 按 Cloudflare Radar 概率生成<br>约束：仅 VMess、VLESS、Trojan、AnyTLS |
| `global-client-fingerprint` | 全局客户端指纹，已弃用，改用 proxy 内 client-fingerprint | 废弃 |  |  | 待标注 | 未测 | 取值：`360`、`android`、`chrome`、`edge`、`firefox`、`ios`、`qq`、`random`、`safari` |
