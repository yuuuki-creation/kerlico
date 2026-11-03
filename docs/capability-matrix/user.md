# 用户与鉴权

由 `tools/capability_matrix.py build` 生成，不要手改。

## anytls

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `credentials` | anytls 入站 users 条目的字段 |  | 有 |  | 已实现 | 通过 | 取值：`name`、`password`<br>约束：认证通过的用户名可用于 auth_user 规则和 V2Ray API stats.users |

## auth

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | 用户和鉴权组合 |  |  | 有 | 部分 | 通过 | protocol：`http`、`hysteria`、`masque`、`shadowsocks`、`socks`、`trojan`、`vless`、`vmess`、`wireguard`<br>credential：`auth`、`email/pass`、`password`、`publicKey`、`user/pass`、`uuid`<br>runtime_change：`api adu/rmu`、`config`<br>约束：API 增删用户仅支持 VMess、VLESS、Trojan、Shadowsocks（docs/config/api.md）<br>约束：Hysteria users 仅配 hysteria 传输生效<br>约束：MASQUE 入站文档另说明 API 删除用户关闭隧道 |

## global

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `authentication` | http(s)、socks、mixed 代理的全局用户验证 | 有 |  |  | 部分 | 通过 | 取值：`user:pass 列表` |
| `skip-auth-prefixes` | 允许跳过验证的 IP 段 | 有 |  |  | 未实现 | 未测 | 取值：`CIDR 列表` |

## http

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `credentials` | http 入站 users 条目的字段 |  | 有 |  | 已实现 | 通过 | 取值：`password`、`username`<br>约束：认证通过的用户名可用于 auth_user 规则和 V2Ray API stats.users |

## hysteria

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `credentials` | hysteria 入站 users 条目的字段 |  | 有 |  | 已实现 | 通过 | 取值：`auth`、`auth_str`、`name`<br>约束：认证通过的用户名可用于 auth_user 规则和 V2Ray API stats.users |

## hysteria2

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `credentials` | hysteria2 入站 users 条目的字段 |  | 有 |  | 已实现 | 通过 | 取值：`name`、`password`<br>约束：认证通过的用户名可用于 auth_user 规则和 V2Ray API stats.users |

## identity

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `level-email` | 入站出站 level 决定策略，email 用于日志和统计 |  |  | 有 | 部分 | 通过 |  |

## inbound

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `in-user-match` | 入站用户名可被 IN-USER 规则匹配，load-balance hash-key in-user 也读取同一字段 | 有 |  |  | 已实现 | 通过 |  |
| `users-override` | 入站 users 不填遵从全局验证，填写忽略全局，users: [] 跳过验证 | 有 |  |  | 部分 | 通过 | 取值：`[]`、`列表`、`省略` |

## masque

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `credentials` | MASQUE 服务端 users 条目的字段 |  | 有 |  | 未实现 | 未测 | 取值：`password`、`username`<br>约束：通过 Authorization 头校验 |

## mixed

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `credentials` | mixed 入站 users 条目的字段 |  | 有 |  | 已实现 | 通过 | 取值：`password`、`username`<br>约束：认证通过的用户名可用于 auth_user 规则和 V2Ray API stats.users |

## naive

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `credentials` | naive 入站 users 条目的字段 |  | 有 |  | 已实现 | 通过 | 取值：`password`、`username`<br>约束：认证通过的用户名可用于 auth_user 规则和 V2Ray API stats.users |

## openvpn

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `credentials` | OpenVPN 服务端 users 条目的字段 |  | 有 |  | 未实现 | 未测 | 取值：`password`、`username`<br>约束：仅 TLS 模式 |

## policy

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `buffer-size` | 每请求内部缓存 KB |  |  | 有 | 未实现 | 未测 | 约束：ARM、MIPS、MIPSLE 默认 0；ARM64、MIPS64、MIPS64LE 默认 60；其他 512<br>约束：UDP 写入缓存满时丢弃<br>约束：XRAY_RAY_BUFFER_SIZE 单位 MB |
| `conn-idle` | 空闲时限秒，默认 300 |  |  | 有 | 部分 | 通过 |  |
| `downlink-only` | 上行关闭后时限秒，默认 1 |  |  | 有 | 部分 | 通过 |  |
| `handshake` | 握手时限秒，默认 60 |  |  | 有 | 部分 | 通过 |  |
| `levels` | 用户等级到策略映射 |  |  | 有 | 未实现 | 未测 | 取值：`"0"`<br>约束：键为字符串数字 |
| `uplink-only` | 下行关闭后时限秒，默认 1 |  |  | 有 | 部分 | 通过 |  |

## shadowsocks

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `credentials` | shadowsocks 入站 users 条目的字段 |  | 有 |  | 已实现 | 通过 | 取值：`name`、`password`<br>约束：认证通过的用户名可用于 auth_user 规则和 V2Ray API stats.users |

## shadowtls

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `credentials` | shadowtls 入站 users 条目的字段 |  | 有 |  | 部分 | 通过 | 取值：`name`、`password`<br>约束：认证通过的用户名可用于 auth_user 规则和 V2Ray API stats.users |

## snell

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `credentials` | snell 入站 users 条目的字段 |  | 有 |  | 已实现 | 通过 | 取值：`name`、`userkey`<br>约束：认证通过的用户名可用于 auth_user 规则和 V2Ray API stats.users |

## socks

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `credentials` | socks 入站 users 条目的字段 |  | 有 |  | 已实现 | 通过 | 取值：`password`、`username`<br>约束：认证通过的用户名可用于 auth_user 规则和 V2Ray API stats.users |

## ssm

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `dynamic-users` | SSM API 动态管理 Shadowsocks 用户，入站需 managed |  | 有 |  | 未实现 | 未测 | 约束：cache_path 保存流量和用户状态 |

## tailcat

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `credentials` | tailcat 入站 users 条目的字段 |  | 有 |  | 未实现 | 未测 | 取值：`name`、`public_key`<br>约束：认证通过的用户名可用于 auth_user 规则和 V2Ray API stats.users |

## trojan

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `credentials` | trojan 入站 users 条目的字段 |  | 有 |  | 已实现 | 通过 | 取值：`name`、`password`<br>约束：认证通过的用户名可用于 auth_user 规则和 V2Ray API stats.users |

## tuic

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `credentials` | tuic 入站 users 条目的字段 |  | 有 |  | 已实现 | 通过 | 取值：`name`、`password`、`uuid`<br>约束：认证通过的用户名可用于 auth_user 规则和 V2Ray API stats.users |

## vless

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `credentials` | vless 入站 users 条目的字段 |  | 有 |  | 已实现 | 通过 | 取值：`flow`、`name`、`uuid`<br>约束：认证通过的用户名可用于 auth_user 规则和 V2Ray API stats.users |

## vmess

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `credentials` | vmess 入站 users 条目的字段 |  | 有 |  | 部分 | 通过 | 取值：`alterId`、`name`、`uuid`<br>约束：认证通过的用户名可用于 auth_user 规则和 V2Ray API stats.users |
