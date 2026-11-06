# 控制接口

配置 `control` 段后，kerlico 提供只读 HTTP/1.1 接口，返回 JSON。启动时打印实际监听地址。

```json
{ "control": { "listen": "127.0.0.1:9090", "secret": "<随机字符串>" } }
```

| 字段 | 约束说明 |
| --- | --- |
| `listen` | 监听地址。非回环地址必须配置 `secret`。不能与入站的 TCP 监听地址相同 |
| `secret` | 可选。配置后请求须带 `Authorization: Bearer <secret>` 或查询参数 `?token=<secret>`，否则返回 401 |

接口是明文 HTTP。跨机器访问时放在受信网络或 TLS 反向代理之后。

同时最多 64 条连接，超出的连接立即关闭。每条连接总时长上限 30 秒，含 keep-alive 复用。

## 端点

支持核心状态端点（`/v1/*`）以及兼容 Clash / sing-box / Xray / SSM 的控制面管理端点。

| 路径 | 方法 | 返回与行为 |
| --- | --- | --- |
| `/v1/health` | `GET` | `status`、本次运行的 `run`、已停止入口的标签 `failed_nodes`，以及配置重载计数 `reloads`（`succeeded`、`failed`、最近一次失败的错误码 `last_error`）。全部入口运行时 `status` 为 `ok`，有入口停止时为 `degraded`，HTTP 状态都是 200 |
| `/v1/usage` | `GET` | `engine`、`users`、`nodes`、`outbounds` 四个用量视图，以及 `active_flows`、`retained_records`、`evicted_records` |
| `/v1/online` | `GET` | 在线来源：`user`、`node`、`address`、`active_flows`。`address` 遮罩为 IPv4 `/24`、IPv6 `/48`，同一网段合并计数 |
| `/v1/flows?after=<序号>&limit=<数量>` | `GET` | 内存中保留的访问记录，来源地址已遮罩。`limit` 为 1 至 4096，默认 1000 |
| `/v1/stats` | `GET` | Engine 和各节点的处理单元计数 |
| `/version` | `GET` | 内核版本号与兼容标志 |
| `/configs` | `GET` / `PUT` / `PATCH` | `GET` 读取当前运行模式与日志级别；`PUT` 重载整份配置，见[配置重载](#配置重载)；`PATCH` 只更新日志级别 |
| `/restart` | `POST` | 重读启动配置并重载，等同不带请求体的 `PUT /configs` |
| `/configs/geo`、`/upgrade/geo` | `POST` | 触发 GeoIP / GeoSite 数据库更新时间戳记录 |
| `/cache/fakeip/flush` | `POST` | 清空 Fake-IP 映射表及持久化缓存 |
| `/logs` | `GET` | 返回控制面环形日志缓冲条目 |
| `/rules`、`/routing/rules` | `GET` / `POST` / `DELETE` | 查询当前路由规则摘要，动态追加或删除路由规则 |
| `/routing/test` | `POST` | 对给定域名、IP、端口与协议模拟路由匹配并返回选中出站 |
| `/connections`、`/connections/<id>` | `GET` / `DELETE` | 列出活跃连接与累计上下行字节，关闭全部或指定连接 |
| `/proxies`、`/proxies/<name>`、`/proxies/<name>/delay` | `GET` / `PUT` | 查询全部出站与策略组状态、切换 `Select` 策略组选中项、测量或记录出站延迟历史 |
| `/group`、`/group/<name>`、`/group/<name>/delay` | `GET` | 查询策略组列表、单组详情或执行组内节点并发测速 |
| `/providers/proxies`、`/providers/proxies/<name>`、`/providers/proxies/<name>/healthcheck` | `GET` / `PUT` | 查询代理提供者列表与节点、触发订阅刷新或整组健康检查 |
| `/providers/rules`、`/providers/rules/<name>` | `GET` / `PUT` | 查询规则集提供者状态并触发刷新计数更新 |
| `/observatory/status` | `GET` | 返回全部出站与策略组节点的观测存活状态与最新 RTT |
| `/routing/balancers`、`/routing/balancers/<tag>` | `GET` / `PUT` | 查询路由均衡器状态或动态设置覆盖目标出站 |
| `/handler/inbound/users`、`/handler/inbound/user` | `GET` / `POST` / `DELETE` | 动态查询、添加或移除入站用户记录 |
| `/ssm/users`（含单用户子路径）、`/ssm/stats` | `GET` / `POST` / `PUT` / `DELETE` | Shadowsocks Server Management (SSM) v1 用户管理与流量统计接口 |

错误响应为 `{"error": "<稳定错误码>"}`，状态码 400、401、404 或 405。

接口只读内存账本，不查询 SQLite，随进程退出停止。历史数据用 `kerlico history` 查询，见[统计历史](history.md)。

入口运行中失败时，kerlico 立即向标准错误打印 `[错误码] 入口 <tag> 已停止：<原因>`，并把标签加入 `failed_nodes`。入口不会自行恢复，其余入口继续运行，重载配置或重启进程才清除记录。

## 配置重载

`PUT /configs`、`POST /restart` 与 Unix `SIGHUP` 进入同一个重载循环，请求按到达顺序逐个执行，HTTP 请求在新配置生效或确认失败后才返回。

`PUT /configs` 的请求体同 Mihomo：

| 字段 | 行为 |
| --- | --- |
| `payload` | 非空时按配置文本解析（JSON、JSONC 或 YAML；启动时带 `--format` 则按该格式），优先于 `path` |
| `path` | 绝对路径，须位于启动时 `-c` 文件所在目录或 `-C` 目录内 |
| 都缺省 | 重读启动命令的 `-c` 与 `-C` 来源 |

查询参数 `force` 可带可不带：kerlico 每次都重建全部监听。成功返回 204，失败返回 400 和错误码。

重载步骤：

1. 读取并校验新配置。失败时旧引擎不受影响，返回 `configuration.invalid` 等错误码。
2. 停止旧引擎：关闭全部入站监听，已有会话在 `limits.drain_timeout_ms` 内排空，统计历史完成最终提交。
3. 用新配置启动引擎并绑定监听。从步骤 2 关闭监听到此步绑定完成之间，新连接被拒绝。
4. 新引擎启动失败（如端口被占用）时，用上一份配置重新启动并返回 `startup.failed`。上一份配置也无法启动时进程以错误退出。

跨重载保留的只有控制接口监听器、`reloads` 计数与设备（WARP）所有者。出站、策略组运行态、内存用量视图、`failed_nodes` 与控制面日志随新引擎重建；统计历史 SQLite、Fake-IP 缓存文件和 `store-selected` 选择文件由新引擎按新配置重新打开，未配置 `store-selected` 时策略组选择回到默认值。

`control.listen` 变化、增删 `control` 段和改变 `device` 设置需重启进程：前两者在新配置中被忽略，控制接口仍在原地址服务；`device` 变化使重载以 `configuration.invalid` 失败。`secret`、CORS 与面板等其余 `control` 字段随重载生效。
