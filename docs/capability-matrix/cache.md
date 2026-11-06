# 缓存

由 `tools/capability_matrix.py build` 生成，不要手改。

## api

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `flush` | /cache/fakeip/flush、/cache/dns/flush 清缓存 | 有 |  |  | 未实现 | 未测 |  |
| `storage` | /storage/{key} 持久 KV | 有 |  |  | 未实现 | 未测 | 取值：`JSON` |

## file

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `buffer-size` | 写缓存的大小。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.15.0 起<br>约束：默认使用 `1MB`。 |
| `cache-id` | 缓存文件中的标识符。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.8.0 起 |
| `enabled` | 启用缓存文件。 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.8.0 起 |
| `flush-interval` | 自动冲刷写缓存的间隔。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.15.0 起<br>约束：默认禁用。 |
| `path` | 缓存文件路径，默认使用`cache.db`。 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.8.0 起 |
| `rdrc-timeout` | 拒绝的 DNS 响应缓存超时。 |  | 废弃 |  | 不适用 | 未测 | 约束：`rdrc_timeout` 已在 sing-box 1.14.0 废弃，且将在 sing-box 1.16.0 中被移除，参阅迁移指南。<br>约束：自 sing-box 1.8.0 起<br>约束：默认使用 `7d`。 |
| `store-dns` | 将 DNS 缓存存储在缓存文件中。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `store-fakeip` | 将 fakeip 存储在缓存文件中。 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.8.0 起 |
| `store-rdrc` | 将拒绝的 DNS 响应缓存存储在缓存文件中。 |  | 废弃 |  | 不适用 | 未测 | 约束：`store_rdrc` 已在 sing-box 1.14.0 废弃，且将在 sing-box 1.16.0 中被移除，参阅迁移指南。<br>约束：自 sing-box 1.8.0 起 |

## profile

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `store-fake-ip` | 储存 fakeip 映射表，域名再次连接时用原映射 | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true` |
| `store-selected` | 储存 API 对策略组的选择供下次启动使用 | 有 |  |  | 部分 | 未测 | 取值：`false`、`true` |
