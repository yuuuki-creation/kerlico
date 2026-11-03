# 证书

由 `tools/capability_matrix.py build` 生成，不要手改。

## dns01

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `override-domain` | 覆盖 DNS 质询记录使用的域名。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `propagation-delay` | 创建质询记录后，在开始传播检查前要等待的时间。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `propagation-timeout` | 等待质询记录传播完成的最长时间。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `provider` | DNS 提供商。 |  | 有 |  | 未实现 | 未测 | 取值：`acmedns`、`alidns`、`cloudflare` |
| `resolvers` | 进行 DNS 传播检查时优先使用的 DNS 解析器。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `ttl` | DNS 质询临时 TXT 记录的 TTL。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |

## dns01-acmedns

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `password` | acmedns DNS01 提供者的 password 字段 |  | 有 |  | 未实现 | 未测 | 约束：四个字段都不能为空（source:service/acme/service.go）<br>约束：自 sing-box 1.13.0 起 |
| `server-url` | acmedns DNS01 提供者的 server_url 字段 |  | 有 |  | 未实现 | 未测 | 约束：四个字段都不能为空（source:service/acme/service.go）<br>约束：自 sing-box 1.13.0 起 |
| `subdomain` | acmedns DNS01 提供者的 subdomain 字段 |  | 有 |  | 未实现 | 未测 | 约束：四个字段都不能为空（source:service/acme/service.go）<br>约束：自 sing-box 1.13.0 起 |
| `username` | acmedns DNS01 提供者的 username 字段 |  | 有 |  | 未实现 | 未测 | 约束：四个字段都不能为空（source:service/acme/service.go）<br>约束：自 sing-box 1.13.0 起 |

## dns01-alidns

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `access-key-id` | alidns DNS01 提供者的 access_key_id 字段 |  | 有 |  | 未实现 | 未测 |  |
| `access-key-secret` | alidns DNS01 提供者的 access_key_secret 字段 |  | 有 |  | 未实现 | 未测 |  |
| `region-id` | alidns DNS01 提供者的 region_id 字段 |  | 有 |  | 未实现 | 未测 |  |
| `security-token` | alidns DNS01 提供者的 security_token 字段 |  | 有 |  | 未实现 | 未测 |  |

## dns01-cloudflare

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `api-token` | cloudflare DNS01 提供者的 api_token 字段 |  | 有 |  | 未实现 | 未测 | 约束：zone_token 自 1.13.0 起，提供后 api_token 可限定到单个 zone |
| `zone-token` | cloudflare DNS01 提供者的 zone_token 字段 |  | 有 |  | 未实现 | 未测 | 约束：zone_token 自 1.13.0 起，提供后 api_token 可限定到单个 zone |

## provider-acme

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | ACME 证书提供者 |  | 有 |  | 未实现 | 未测 | 取值：`acme`<br>约束：自 sing-box 1.14.0 起<br>约束：需要 with_acme 构建标签 |
| `account-key` | 现有 ACME 帐户的 PEM 编码私钥。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `alternative-http-port` | 用于 ACME HTTP 质询的备用端口；如果非空，将使用此端口而不是 80 来启动 HTTP 质询的侦听器。 |  | 有 |  | 未实现 | 未测 |  |
| `alternative-tls-port` | 用于 ACME TLS-ALPN 质询的备用端口； 系统必须将 443 转发到此端口以使质询成功。 |  | 有 |  | 未实现 | 未测 |  |
| `data-directory` | ACME 数据存储目录。 |  | 有 |  | 未实现 | 未测 |  |
| `default-server-name` | 如果 ClientHello 的 ServerName 字段为空，则选择证书时要使用的服务器名称。 |  | 有 |  | 未实现 | 未测 |  |
| `disable-http-challenge` | 禁用所有 HTTP 质询。 |  | 有 |  | 未实现 | 未测 |  |
| `disable-tls-alpn-challenge` | 禁用所有 TLS-ALPN 质询。 |  | 有 |  | 未实现 | 未测 |  |
| `dns01-challenge` | ACME DNS01 质询字段。 |  | 有 |  | 未实现 | 未测 |  |
| `domain` | 域名列表。 |  | 有 |  | 未实现 | 未测 | 约束：必填 |
| `email` | 创建或选择现有 ACME 服务器帐户时使用的电子邮件地址。 |  | 有 |  | 未实现 | 未测 |  |
| `external-account` | EAB（外部帐户绑定）包含将 ACME 帐户绑定或映射到 CA 已知的其他帐户所需的信息。 |  | 有 |  | 未实现 | 未测 | 约束：为了启用 ACME 帐户绑定，运行 ACME 服务器的 CA 需要使用 ACME 之外的某种机制向 ACME 客户端提供 MAC 密钥和密钥标识符。 |
| `external-account-key-id` | 密钥标识符。 |  | 有 |  | 未实现 | 未测 |  |
| `external-account-mac-key` | MAC 密钥。 |  | 有 |  | 未实现 | 未测 |  |
| `http-client` | 用于所有提供者 HTTP 请求的 HTTP 客户端。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `key-type` | 为新证书生成的私钥类型。 |  | 有 |  | 未实现 | 未测 | 取值：`ed25519`、`p256`、`p384`、`rsa2048`、`rsa4096`<br>约束：自 sing-box 1.14.0 起 |
| `profile` | 用于证书签发的 ACME profile。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `provider` | 要使用的 ACME CA 提供商。 |  | 有 |  | 未实现 | 未测 | 取值：`https://...`、`letsencrypt`、`zerossl`<br>约束：当 `provider` 为 `zerossl` 时，必须至少设置 `external_account`、`email` 或 `account_key` 之一。 |

## provider-cloudflare-origin-ca

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | Cloudflare Origin CA 证书提供者 |  | 有 |  | 未实现 | 未测 | 取值：`cloudflare-origin-ca`<br>约束：自 sing-box 1.14.0 起 |
| `api-token` | 用于创建证书的 Cloudflare API Token。 |  | 有 |  | 未实现 | 未测 | 约束：与 `origin_ca_key` 冲突。<br>约束：自 sing-box 1.14.0 起<br>约束：需要 `Zone / SSL and Certificates / Edit` 权限。 |
| `data-directory` | 保存签发证书、私钥和元数据的根目录。 |  | 有 |  | 未实现 | 未测 | 约束：如果为空，sing-box 会使用与 ACME 证书提供者相同的默认数据目录：<br>约束：自 sing-box 1.14.0 起 |
| `domain` | 要写入证书的域名或通配符域名列表。 |  | 有 |  | 未实现 | 未测 | 约束：必填<br>约束：自 sing-box 1.14.0 起 |
| `http-client` | 用于所有提供者 HTTP 请求的 HTTP 客户端。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `origin-ca-key` | Cloudflare Origin CA 密钥 |  | 有 |  | 未实现 | 未测 | 约束：Conflict with `api_token`.<br>约束：与 `api_token` 冲突。<br>约束：自 sing-box 1.14.0 起 |
| `request-type` | 向 Cloudflare 请求的签名类型。 |  | 有 |  | 未实现 | 未测 | 取值：`origin-ecc`、`origin-rsa`<br>约束：自 sing-box 1.14.0 起 |
| `requested-validity` | 请求的证书有效期，单位为天。 |  | 有 |  | 未实现 | 未测 | 取值：`1095`、`30`、`365`、`5475`、`7`、`730`、`90`<br>约束：自 sing-box 1.14.0 起 |

## provider-common

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `tag` | 证书提供者的标签。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `type` | 证书提供者类型 |  | 有 |  | 未实现 | 未测 | 取值：`acme`、`cloudflare-origin-ca`、`tailscale`<br>约束：自 sing-box 1.14.0 起 |

## provider-tailscale

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | Tailscale 证书提供者 |  | 有 |  | 未实现 | 未测 | 取值：`tailscale`<br>约束：Tailscale 管理台必须启用 MagicDNS 和 HTTPS<br>约束：自 sing-box 1.14.0 起 |
| `endpoint` | 要复用的 Tailscale 端点 的标签。 |  | 有 |  | 未实现 | 未测 | 约束：必填<br>约束：必须在 Tailscale 管理控制台中启用 MagicDNS 和 HTTPS。<br>约束：自 sing-box 1.14.0 起 |

## store

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `certificate` | 要信任的证书行数组，PEM 格式。 |  | 有 |  | 部分 | 未测 | 约束：自 sing-box 1.12.0 起 |
| `certificate-directory-path` | 搜索要信任的证书的目录路径，PEM 格式。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.12.0 起 |
| `certificate-path` | 要信任的证书路径，PEM 格式。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.12.0 起 |
| `store` | 默认的 X509 受信任 CA 证书列表。 |  | 有 |  | 部分 | 未测 | 取值：`chrome`、`mozilla`、`none`、`system`<br>约束：自 sing-box 1.12.0 起 |

## system

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `disable-system-ca` | 见 config.env.disable_system_ca，可禁系统 CA | 有 |  |  | 已实现 | 未测 |  |

## tls

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `acme-external` | 自动证书未内置，文档建议 acme.sh 等外部工具 |  |  | 有 | 部分 | 未测 |  |
| `build-chain` | 签发时嵌入 CA 证书链 |  |  | 有 | 未实现 | 未测 | 约束：仅 usage issue<br>约束：只适合中间 CA |
| `certificate` | API HTTPS 证书，PEM 内容或路径 | 有 |  | 有 | 部分 | 未测 | 取值：`PEM`、`路径`<br>约束：目前仅用于 API 的 https<br>约束：自 v1.19.18 本地文件支持自动重载 |
| `certificate-file` | 证书文件路径 |  |  | 有 | 已实现 | 未测 | 约束：同时指定时优先于 certificate |
| `client-auth-cert` | 顶层 tls 的 mTLS 客户端证书 | 有 |  |  | 部分 | 未测 | 取值：`PEM`、`路径` |
| `client-auth-type` | 顶层 tls 的 mTLS 类型 | 有 |  |  | 部分 | 未测 | 取值：``、`request`、`require-and-verify`、`require-any`、`verify-if-given`<br>约束：verify-if-given、require-and-verify 时 client-auth-cert 必填 |
| `custom-certifactes` | 追加自定义信任证书（字段拼写以源码为准） | 有 |  |  | 部分 | 未测 | 取值：`PEM 列表` |
| `ech-key` | API HTTPS 的 ECH 密钥，填写即启用 | 有 |  |  | 未实现 | 未测 | 取值：`PEM`<br>约束：自 v1.19.18 本地文件支持自动重载 |
| `hot-reload` | 服务端证书每 3600 秒热重载 |  |  | 有 | 未实现 | 未测 |  |
| `key` | 密钥内容字符串数组 |  |  | 有 | 已实现 | 未测 |  |
| `key-file` | 密钥文件路径 |  |  | 有 | 已实现 | 未测 | 约束：不支持带密码的 key<br>约束：同时指定时优先于 key |
| `ocsp-stapling` | OCSP 装订间隔秒，默认 0 |  |  | 有 | 未实现 | 未测 | 约束：非 0 覆盖 3600 秒重载周期 |
| `one-time-loading` | 只加载一次，关闭热重载与 OCSP |  |  | 有 | 已实现 | 未测 |  |
| `private-key` | API HTTPS 私钥，PEM 内容或路径 | 有 |  |  | 部分 | 未测 | 取值：`PEM`、`路径`<br>约束：自 v1.19.18 本地文件支持自动重载 |
| `usage` | 证书用途，默认 encipherment |  |  | 有 | 未实现 | 未测 | 取值：`encipherment`、`issue`、`verify`<br>约束：verify 时 keyFile 和 key 可空<br>约束：verify、issue 必须为 CA<br>约束：无匹配证书时用 issue 签发 1 小时证书 |
