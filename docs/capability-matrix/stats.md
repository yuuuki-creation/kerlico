# 统计

由 `tools/capability_matrix.py build` 生成，不要手改。

## access-log

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `connection-record` | 连接记录即 access log；webhook 提供命中通知 |  |  | 有 | 已实现 | 未测 |  |

## clash-api

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `connections` | Clash API 当前连接和累计流量，GET /connections |  | 有 |  | 部分 | 未测 | 取值：`GET /connections`<br>约束：支持 WebSocket，interval 查询参数 |
| `traffic` | Clash API 实时流量（字节每秒），GET /traffic |  | 有 |  | 部分 | 未测 | 取值：`GET /traffic`<br>约束：支持 WebSocket |

## connections

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `record` | 每连接 id、metadata、upload、download、start、chains、providerChains、rule、rulePayload | 有 |  |  | 部分 | 未测 | 取值：`JSON` |
| `totals` | /connections 的 downloadTotal、uploadTotal、memory | 有 |  |  | 部分 | 未测 | 取值：`字节` |

## counter

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `inbound-tag-traffic-downlink` | 入站下行字节 |  |  | 有 | 已实现 | 未测 |  |
| `inbound-tag-traffic-uplink` | 入站上行字节 |  |  | 有 | 已实现 | 未测 |  |
| `outbound-tag-traffic-downlink` | 出站下行字节 |  |  | 有 | 已实现 | 未测 |  |
| `outbound-tag-traffic-uplink` | 出站上行字节 |  |  | 有 | 已实现 | 未测 |  |
| `user-email-traffic-downlink` | 用户下行字节 |  |  | 有 | 已实现 | 未测 | 约束：用户无 Email 时不统计 |
| `user-email-traffic-uplink` | 用户上行字节 |  |  | 有 | 已实现 | 未测 | 约束：用户无 Email 时不统计 |

## policy

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `stats-inbound-downlink` | 开启所有入站下行统计 |  |  | 有 | 部分 | 未测 |  |
| `stats-inbound-uplink` | 开启所有入站上行统计 |  |  | 有 | 部分 | 未测 |  |
| `stats-outbound-downlink` | 开启所有出站下行统计 |  |  | 有 | 部分 | 未测 |  |
| `stats-outbound-uplink` | 开启所有出站上行统计 |  |  | 有 | 部分 | 未测 |  |
| `stats-user-downlink` | 开启当前等级用户流量统计 |  |  | 有 | 部分 | 未测 |  |
| `stats-user-online` | 开启当前等级用户在线统计，20 秒内活动算在线 |  |  | 有 | 部分 | 未测 |  |
| `stats-user-uplink` | 开启当前等级用户流量统计 |  |  | 有 | 部分 | 未测 |  |

## proxies

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `delay-history` | /proxies 的 history 与 extra 延迟记录 | 有 |  |  | 未实现 | 未测 | 取值：`JSON` |

## rules

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `hit-count` | /rules extra 的 disabled、hitCount、hitAt、missCount、missAt | 有 |  |  | 未实现 | 未测 | 取值：`JSON` |

## splice

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `lag` | 使用 Splice 时连接断开后才计入统计 |  |  | 有 | 不适用 | 未测 |  |

## ssm

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `stats` | SSM API 流量统计，GET /server/v1/stats，clear=true 读后清零 |  | 有 |  | 未实现 | 未测 | 取值：`GET /server/v1/stats` |

## stats

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `enable` | stats 对象存在即开启 |  |  | 有 | 部分 | 未测 | 约束：还需在 policy 开启对应项 |

## traffic

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `realtime-rate` | /traffic 实时 up、down 与 upTotal、downTotal | 有 |  |  | 部分 | 未测 | 取值：`字节`、`字节/秒` |

## v2ray-api

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | V2Ray 兼容 gRPC 统计 API |  | 有 |  | 未实现 | 未测 | 取值：`v2ray_api`<br>约束：listen 为空时禁用<br>约束：需要 with_v2ray_api 构建标签，默认未编入 |
| `combo` | V2Ray API 的统计范围和 RPC 组合 |  | 有 |  | 未实现 | 未测 | scope：`inbounds`、`outbounds`、`users`<br>rpc：`GetStats`、`GetSysStats`、`QueryStats`<br>约束：只统计列出的标签和用户<br>约束：需要 with_v2ray_api |
| `listen` | gRPC API 监听地址。 |  | 有 |  | 未实现 | 未测 |  |
| `stats` | 流量统计服务设置。 |  | 有 |  | 未实现 | 未测 |  |
| `stats-enabled` | 启用统计服务。 |  | 有 |  | 未实现 | 未测 |  |
| `stats-inbounds` | 统计流量的入站列表。 |  | 有 |  | 未实现 | 未测 |  |
| `stats-outbounds` | 统计流量的出站列表。 |  | 有 |  | 未实现 | 未测 |  |
| `stats-users` | 统计流量的用户列表。 |  | 有 |  | 未实现 | 未测 |  |
