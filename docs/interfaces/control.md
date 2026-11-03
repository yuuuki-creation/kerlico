# 控制接口

配置 `control` 段后，kerlico 提供只读 HTTP/1.1 接口，返回 JSON。启动时打印实际监听地址。

```json
{ "control": { "listen": "127.0.0.1:9090", "secret": "<随机字符串>" } }
```

| 字段 | 约束说明 |
| --- | --- |
| `listen` | 监听地址。非回环地址必须配置 `secret`。不能与入站的 TCP 监听地址相同 |
| `secret` | 可选。配置后请求须带 `Authorization: Bearer <secret>`，否则返回 401 |

接口是明文 HTTP。跨机器访问时放在受信网络或 TLS 反向代理之后。

同时最多 64 条连接，超出的连接立即关闭。每条连接总时长上限 30 秒，含 keep-alive 复用。

## 端点

只接受 `GET`。

| 路径 | 返回 |
| --- | --- |
| `/v1/health` | `status`、本次运行的 `run`、已停止入口的标签 `failed_nodes`。全部入口运行时 `status` 为 `ok`，有入口停止时为 `degraded`，HTTP 状态都是 200 |
| `/v1/usage` | `engine`、`users`、`nodes`、`outbounds` 四个用量视图，以及 `active_flows`、`retained_records`、`evicted_records` |
| `/v1/online` | 在线来源：`user`、`node`、`address`、`active_flows`。`address` 遮罩为 IPv4 `/24`、IPv6 `/48`，同一网段合并计数 |
| `/v1/flows?after=<序号>&limit=<数量>` | 内存中保留的访问记录，来源地址已遮罩。`limit` 为 1 至 4096，默认 1000。`after`、`limit` 不是无符号整数时返回 400，错误码 `query.invalid` |
| `/v1/stats` | Engine 和各节点的处理单元计数 |

错误响应为 `{"error": "<稳定错误码>"}`，状态码 400、401、404 或 405。

接口只读内存账本，不查询 SQLite，随进程退出停止。历史数据用 `kerlico history` 查询，见[统计历史](history.md)。

入口运行中失败时，kerlico 立即向标准错误打印 `[错误码] 入口 <tag> 已停止：<原因>`，并把标签加入 `failed_nodes`。入口不会自行恢复，其余入口继续运行，重启进程才清除记录。
