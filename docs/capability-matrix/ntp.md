# NTP

由 `tools/capability_matrix.py build` 生成，不要手改。

## config

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `enabled` | 启用 NTP 服务。 |  | 有 |  | 已实现 | 通过 |  |
| `interval` | 时间同步间隔。 |  | 有 |  | 已实现 | 通过 | 约束：默认使用 30 分钟。 |
| `server` | NTP 服务器地址。 |  | 有 |  | 已实现 | 通过 | 约束：必填 |
| `server-port` | NTP 服务器端口。 |  | 有 |  | 已实现 | 通过 | 约束：默认使用 123。 |
| `write-to-system` | NTP 写入系统时间，文档未列 |  | 有 |  | 已实现 | 通过 |  |

## ntp

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `dialer-proxy` | 可选，默认 DIRECT；NTP 默认直连，不走出站和路由规则 | 有 |  |  | 已实现 | 通过 | 取值：`出站名` |
| `enable` | 启用 NTP 服务 | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true` |
| `interval` | 同步间隔，单位分，默认 30 | 有 |  |  | 已实现 | 通过 | 取值：`整数` |
| `port` | NTP 端口，默认 123 | 有 |  |  | 已实现 | 通过 | 取值：`端口` |
| `server` | NTP 地址，默认 time.apple.com | 有 |  |  | 已实现 | 通过 | 取值：`域名` |
| `write-to-system` | 同步至系统时间 | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true`<br>约束：需要 root 或管理员 |
