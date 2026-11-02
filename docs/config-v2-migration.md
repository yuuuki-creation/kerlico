# 配置 v2 迁移指南

更新日期：2026-11-02（Asia/Shanghai）

当前源码使用 **配置版本 2（JSON v2）**，旧版 v1 配置需按以下规则迁移后运行。最小可用结构参考 [examples/config-v2-minimal.json](../examples/config-v2-minimal.json)，完整字段约束见 [配置与命令行接口](interfaces/config.md)。

## 迁移步骤

1. **升级版本号与共享出站**：将根字段 `"version"` 设为 `2`。保留命名 `outbounds` 数组；多个入站节点引用同一出站 `tag` 时将共享同一个运行实例。
2. **创建管理账户**：使用 `kerlico account-new --prefix <name>` 从标准输入读取管理密码，生成带持久 `user_id`（UUID）与 Argon2id PHC 密码摘要（`password_hash`）的账户项，填入根配置 `accounts` 数组。
3. **分离节点成员与协议原生凭据**：
   - 将服务端入站节点的用户认证秘密从协议 `options` 移至节点 `members[].native_credential`，并关联对应的管理 `user_id`。
   - 协议传输载体、TLS 证书、外层混淆/保护密钥（如 ShadowTLS 握手密码、SS2022 AES EIH 外层 `identity_key`）与资源限制仍留在节点 `options` 中。
4. **独立声明 IPv4 / IPv6 节点成员**：IPv4 与 IPv6 监听节点分别配置独立的 `members` 与协议秘密；同一管理 `user_id` 需在各节点显式列入 `members` 方可访问对应节点。
5. **配置节点目标地址族模式（`mode`）**：按本节点负责的本地出网策略设置为 `ipv4-only`、`ipv6-only` 或 `dual-stack`（默认）。远端代理分流路径保留原始目标透传，不受本地节点 `mode` 改写。
6. **执行配置校验**：运行 `kerlico check -c <config.json>` 进行纯编译校验（不绑定端口或修改宿主网络）。

## 各入站协议 `native_credential` 格式

| 入站协议 | `native_credential` JSON 结构 |
| --- | --- |
| VLESS | `{"uuid": "<协议UUID>", "flow": "<可选flow>"}` |
| VMess | `{"uuid": "<协议UUID>"}` |
| Trojan、AnyTLS | `{"password": "<协议密码>"}` |
| SOCKS、HTTP、ShadowQUIC、Mieru、Naive、TrustTunnel | `{"username": "<原生用户名>", "password": "<协议密码>"}` |
| Shadowsocks (AEAD) | `{"password": "<协议密码>"}`（加密方法 `method` 留在节点 `options`） |
| SS2022 | `{"key": "<终端用户Key>"}`（AES EIH 外层身份留在 `options.identity_key`） |
| Snell | `{"psk": "<原生PSK>", "userkey": "<可选v6用户Key>"}` |
| TUIC | v4：`{"token": "<原生Token>"}`；v5：`{"uuid": "<协议UUID>", "password": "<协议密码>"}` |
| Hysteria v1 | `{"auth_str": "<文本>"}` 或 `{"auth": "<原生编码材料>"}`（二选一） |
| Hysteria2 | `{"auth": "<原生认证材料>"}` |
| SSR | `{"password": "<基础密码>", "user": {"id": 1, "password": "<可选UID密码>"}}` |
| Sudoku | `{"key": "<原生Key>"}` |
| ShadowTLS | 采用所选 `inner` 协议的凭据结构（外层握手密码属于 `Protection` 域，留在 `options`） |
| WireGuard | `{"public_key": "<Base64公钥>", "preshared_key": "<可选Base64 PSK>", "allowed_ips": ["..."], "persistent_keepalive": 25}` |

## 特殊角色与行为说明

- **仅出站协议（SSH / Gost Relay / Tor）**：远端认证材料或状态目录直接配置在对应命名 `outbound.options` 中，不使用入站管理账户。
- **显式本地无认证入口（`local_inbounds`）**：无真实用户鉴别的本地回环入口通过 `local_inbounds` 声明，运行时绑定 `Source::Local`，无需配置占位 `members`。
- **XDRIVE 存储载体连接行为**：XDRIVE 仅直连显式配置的存储服务 URL，不再隐式读取环境变量 `HTTP_PROXY`、`HTTPS_PROXY` 或 `NO_PROXY`。
