# 控制接口

配置 `control` 段（或 Mihomo 顶层 `external-controller`）后，kerlico 提供 HTTP/1.1 与 WebSocket 接口，返回 JSON。启动时打印实际监听地址。

```json
{ "control": { "listen": "127.0.0.1:9090", "secret": "<随机字符串>" } }
```

| 字段 | 约束说明 |
| --- | --- |
| `listen` | 监听地址。非回环地址必须配置 `secret`。不能与入站的 TCP 监听地址相同 |
| `secret` | 可选。配置后请求须带 `Authorization: Bearer <secret>` 或查询参数 `?token=<secret>`（浏览器的 WebSocket 只能用后者），否则返回 401 |
| `external_ui` | 可选。静态面板目录，在 `/ui/` 下提供；`external_ui_name` 指定其中的子目录。目录中不存在的文件返回 404 |

接口是明文 HTTP。跨机器访问时放在受信网络或 TLS 反向代理之后。

同时最多 64 条连接，超出的连接立即关闭。每条连接总时长上限 30 秒，含 keep-alive 复用；正在发送推送响应的连接不受此限。升级后的 WebSocket 会话与 HTTP 推送另计，同时最多 64 个，超出时回 503。

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
| `/configs` | `GET` / `PUT` / `PATCH` | `GET` 返回 Mihomo 形状的运行设置，见[运行设置](#运行设置)；`PUT` 重载整份配置，见[配置重载](#配置重载)；`PATCH` 改运行模式、日志级别与入站监听 |
| `/restart` | `POST` | 重读启动配置并重载，等同不带请求体的 `PUT /configs` |
| `/configs/geo`、`/upgrade/geo` | `POST` | 立即下载 `geox_url` 配置的全部 Geo 数据库；未配置回 400，任一失败回 503 与 `message` |
| `/cache/fakeip/flush` | `POST` | 清空 Fake-IP 映射表及持久化缓存 |
| `/cache/dns/flush` | `POST` | 清空全部 UDP、TCP、DoT 上游解析器的应答缓存；DoH 上游不缓存 |
| `/traffic`、`/memory`、`/logs?level=&format=` | `GET`（可升级为 WebSocket） | 推送端点，见[推送](#推送) |
| `/rules`、`/routing/rules` | `GET` | 编译后的顶层路由规则，按配置顺序列出 `type`、`payload`、`proxy`，最终出站以 `Match` 行收尾，见[规则表](#规则表) |
| `/routing/test` | `POST` | 对给定域名、IP、端口与协议模拟路由匹配并返回选中出站 |
| `/connections`、`/connections/<id>` | `GET` / `DELETE` | 活动连接表与进程累计上下行字节；`DELETE` 关闭全部或指定连接，见[连接表](#连接表)。WebSocket 升级后按 `interval` 推送快照 |
| `/dns/query?name=<域名>&type=<A\|AAAA>` | `GET` | 经运行期解析器（hosts、上游与缓存）解析，返回 Mihomo 应答形状，见[DNS 查询](#dns-查询) |
| `/proxies`、`/proxies/<name>`、`/proxies/<name>/delay?url=&timeout=&expected=` | `GET` / `PUT` | 查询全部出站与策略组状态、切换 `Select` 策略组选中项、经该出站实测延迟（见下文“延迟探测”） |
| `/group`、`/group/<name>`、`/group/<name>/delay?url=&timeout=&expected=` | `GET` | 查询策略组列表、单组详情，或并发实测组内全部候选，返回成功项 `{"<name>": <ms>}`；全部失败时 504 |
| `/providers/proxies`、`/providers/proxies/<name>`、`/providers/proxies/<name>/healthcheck`、`/providers/proxies/<name>/<proxy>/healthcheck` | `GET` / `PUT` | 查询代理提供者列表与节点（`updatedAt` 为最近一次成功加载时间，加载失败时带 `error`）；`PUT /providers/proxies/<name>` 立即下载，内容变化时重建引擎后回 204，下载或校验失败回 503 与 `message`；按提供者的 `health-check` 设置实测整组（204）或单个节点（返回 `delay`） |
| `/providers/rules`、`/providers/rules/<name>` | `GET` / `PUT` | 查询规则集状态（`updatedAt`、失败时 `error`）；`PUT` 立即重新下载或重读文件并原地替换，失败回 503 与 `message` |
| `/observatory/status` | `GET` | 返回全部出站与策略组节点的观测存活状态与最新 RTT |
| `/routing/balancers`、`/routing/balancers/<tag>` | `GET` / `PUT` | 查询路由均衡器状态或动态设置覆盖目标出站 |
| `/handler/inbound/users`、`/handler/inbound/user` | `GET` / `POST` / `DELETE` | 动态查询、添加或移除入站用户记录 |
| `/ssm/users`（含单用户子路径）、`/ssm/stats` | `GET` / `POST` / `PUT` / `DELETE` | Shadowsocks Server Management (SSM) v1 用户管理与流量统计接口 |

### 连接表

`GET /connections` 返回：

```json
{
  "downloadTotal": 1024, "uploadTotal": 512, "memory": 18874368,
  "connections": [{
    "id": "7",
    "metadata": {
      "network": "tcp", "type": "", "sourceIP": "127.0.0.1", "sourcePort": "50312",
      "destinationIP": "93.184.216.34", "destinationPort": "443", "host": "example.com",
      "sniffHost": "", "inboundName": "entry", "inboundUser": "", "process": "", "processPath": "",
      "remoteDestination": "93.184.216.34:443", "dnsMode": "normal"
    },
    "upload": 512, "download": 1024, "start": "2026-11-06T08:00:00.000Z",
    "chains": ["exit-a", "pick"], "providerChains": [],
    "rule": "DomainSuffix", "rulePayload": "example.com"
  }]
}
```

- 表项来自唯一业务账本：调度器建立的每条 TCP 流、固定目标 UDP 流与多目标 UDP 关联在开流时登记，租约结束时下线；字节数为计量边界的实时计数。
- `downloadTotal`、`uploadTotal` 是本次运行的累计业务字节，含已结束的流。
- `chains` 从最终命名出站开始，逐层列出经过的策略组，最后一项是规则目标。
- `rule`、`rulePayload` 是产生终结动作的规则；没有规则命中时为 `Match`。多目标 UDP 关联没有单一目标，固定为 `Match`。
- `process`、`processPath` 只在配置了进程规则时查询。`type` 暂为空串，入站协议类型尚未进入会话身份。
- 来源地址不遮罩：此表供已鉴权的管理端识别和关闭连接，不落盘。
- `DELETE /connections/<id>` 触发该流的关闭令牌：计量边界中止读写，转发结束，客户端收到 EOF 或复位。`DELETE /connections` 关闭全部活动流。未知或非数字 `id` 不做任何操作，均返回 204。
- 策略组开启 `interrupt-exist-connections` 后，`select` 切换选中项、`url-test` 与 `fallback` 因延迟记录改变当前成员时，经过该组但成员不是当前成员的流被关闭。`load-balance` 按流选择成员，不中断。
- WebSocket 连接 `/connections?interval=<毫秒>` 每隔 `interval`（缺省 1000，最小 100）推送一份与 `GET /connections` 相同的快照。不带升级的 `GET /connections` 回单次快照。

### 规则表

`GET /rules` 每行是 `{"index", "type", "payload", "proxy", "size": -1, "extra": {"disabled": false}}`。`type` 使用 Mihomo 规则类型名（`Domain`、`DomainSuffix`、`DomainKeyword`、`IPCIDR`、`GeoIP`、`DstPort`、`SrcIPCIDR`、`Network`、`RuleSet`、`Process` 等）。同一条规则有多个条件字段时显示为 `AND`，载荷为 `(类型,值),(类型,值)`；逻辑规则显示 `AND`/`OR`，`invert` 显示 `NOT`。`proxy` 为路由目标；`reject` 动作为 `REJECT`，其他非路由动作为动作名。只列顶层规则，`sub-rule` 行的 `proxy` 是子规则名。

### DNS 查询

```json
{"Status": 0, "TC": false, "RD": true, "RA": true, "AD": false, "CD": false,
 "Question": [{"Name": "svc.internal.", "Qtype": 1, "Qclass": 1}],
 "Answer": [{"name": "svc.internal.", "type": 1, "TTL": 0, "data": "10.0.0.5"}]}
```

- 缺少 `name` 返回 400；`type` 默认 `A`。
- 解析失败时 `Status` 为 2（SERVFAIL），无结果时省略 `Answer`。
- 只支持 `A` 与 `AAAA`，其他类型返回 `Status` 4（NOTIMP）。
- 解析器只返回地址，不带上游 TTL，`TTL` 固定为 0。

错误响应为 `{"error": "<稳定错误码>"}`，状态码 400、401、404 或 405。

## 推送

`/traffic`、`/memory`、`/logs`、`/connections` 带 `Upgrade: websocket` 请求时按 RFC 6455 升级，每条消息是一个 JSON 文本帧。`/traffic`、`/memory`、`/logs` 不带升级时回 `200`，以分块编码持续发送 JSON 行（每行一个对象，`\n` 结尾），同 Mihomo。推送跨配置重载继续，读取新一代引擎的数据。

| 端点 | 消息 | 频率 |
| --- | --- | --- |
| `/traffic` | `{"up","down","upTotal","downTotal"}`：`up`、`down` 为上一秒的业务字节数，`*Total` 为本次引擎运行的累计业务字节 | 每秒，首条在连接 1 秒后 |
| `/memory` | `{"inuse","oslimit"}`，含义同上表 | 每秒，首条立即发送 |
| `/logs?level=<级别>` | `{"type":"info","payload":"..."}`；`format=structured` 时为 `{"time","level","message","fields":[]}` | 事件发生时 |
| `/connections?interval=<毫秒>` | 同 `GET /connections` | 每 `interval` |

`level` 缺省 `info`，只推送不低于该级别的事件；`silent` 不推送。订阅者收到全部级别的事件，与进程日志级别无关，同 Mihomo。订阅者处理不及时时丢弃积压的旧事件。

## 日志

进程日志与 `/logs` 共用一条管线。级别取 `log.level`，其次顶层 `log-level`，缺省 `info`，按 `debug < info < warning < error < silent` 过滤输出；`trace` 视为 `debug`，`warn` 视为 `warning`，`fatal`、`panic` 视为 `error`，`none` 视为 `silent`。

| 字段 | 行为 |
| --- | --- |
| `log.output` | 缺省或 `stdout` 写标准输出；`stderr` 写标准错误；其他值为文件路径，追加写入。Xray 的 `error` 路径在未写 `output` 时同样生效 |
| `log.timestamp` | 为真时每行以 UTC 时间开头，如 `2026-11-06T08:00:00.000Z INFO ...` |
| `log.disabled` | 为真时级别为 `silent`，不写输出；`/logs` 订阅照常 |

每次启动和重载按新配置重新打开输出。连接建立时记 `info`，格式同 Mihomo：

```text
[TCP] 127.0.0.1:50312 --> example.com:443 match DomainSuffix(example.com) using Proxy[node-a]
[TCP] 127.0.0.1:50313 --> example.org:443 match Match using Proxy[DIRECT]
[TCP] 127.0.0.1:50314 --> example.net:443 doesn't match any rule using exit
[TCP] 127.0.0.1:50315 --> example.net:443 using GLOBAL
```

`using` 后为“第一层策略组[最终出站]”，没有策略组时为出站名。准入失败记 `warning`：`[TCP] dial <出站> <来源> --> <目标> error: <原因>`。

## 运行模式

顶层 `mode`（sing-box `clash_api.default_mode` 亦可）取 `rule`、`global` 或 `direct`，缺省 `rule`，不区分大小写。

- `rule`：按路由规则分流。
- `global`：全部连接交给 `GLOBAL` 策略组。
- `direct`：全部连接交给 `DIRECT`。

`global` 与 `direct` 不评估规则的拒绝、改写与出站，只保留规则中的 DNS 劫持与嗅探动作。

配置中没有名为 `GLOBAL` 的策略组或出站时，kerlico 生成一个 `select` 组 `GLOBAL`，成员依次为 `DIRECT`、`REJECT`、配置中声明的出站（不含提供者成员）、策略组，默认选中 `DIRECT`，可用 `PUT /proxies/GLOBAL` 切换，`store-selected` 同样记录。`DIRECT` 与 `REJECT` 内置出站总是存在，已有同名出站时沿用。

## 运行设置

`GET /configs` 返回 Mihomo 字段：`port`、`socks-port`、`mixed-port`、`redir-port`、`tproxy-port`（未开启为 0）、`allow-lan`、`bind-address`、`lan-allowed-ips`、`lan-disallowed-ips`、`interface-name`、`routing-mark`、`mode`、`log-level`、`ipv6`、`sniffing`、`geodata-mode`、`geo-auto-update`、`geo-update-interval`、`geox-url`、`tun`（`enable`、`device`、`stack`、`dns-hijack`、`auto-route`、`auto-detect-interface`）。`mode` 与 `log-level` 是运行值，其余取自当前运行的配置。`ipv6` 固定为 `true`，`tcp-concurrent`、`unified-delay` 固定为 `false`。

`PATCH /configs` 的请求体用同名字段：

| 字段 | 行为 |
| --- | --- |
| `mode` | 就地生效，已有连接不中断 |
| `log-level` | 就地生效 |
| `port`、`socks-port`、`mixed-port`、`redir-port`、`tproxy-port` | 0 关闭该入站，其他值改端口 |
| `allow-lan`、`bind-address`、`lan-allowed-ips`、`lan-disallowed-ips`、`interface-name` | 改写同名配置 |
| `tun` | 对象，逐键合并进顶层 `tun`；`{"enable": false}` 关闭 TUN 入站 |

只含 `mode`、`log-level` 时回 204，不重建引擎。含其他字段时把改动写进当前运行的配置，按[配置重载](#配置重载)重建引擎，成功回 204，失败回 400 与错误码；控制接口未接入重载循环时回 501。两种情况的改动都写入运行配置，之后由提供者更新触发的重载沿用；`PUT /configs`、`SIGHUP` 重读配置文件时恢复文件中的值。字段值不合法回 400 与 `message`。其他字段（如 `ipv6`、`sniffing`）忽略，并记一条 `warning` 日志。

## 延迟探测

语义对齐 Mihomo `URLTest`：经被测出站建立到测试 URL 的 TCP 连接（`https` 再做 TLS，校验内置公共根证书），发送 `HEAD <path> HTTP/1.1`，读到状态行即停止计时。延迟从拨号前算起，含连接、TLS 与首个响应行，最小 1 ms。`Remote` 出站把测试 URL 的主机名原样交给远端解析；`Local` 出站由调度器解析器解析后按候选地址依次尝试。被测名称是策略组时，先按组当前选择解析到具体出站再探测，结果记在组名下。

查询参数：

| 参数 | 含义 | 缺省 |
| --- | --- | --- |
| `url` | 百分号编码的 `http`/`https` 测试地址 | 策略组的 `url`；普通出站为 `https://cp.cloudflare.com/generate_204` |
| `timeout` | 毫秒，须大于 0 | 策略组的 `timeout`；普通出站为 5000 |
| `expected` | Mihomo `expected-status` 语法：`204`、`200/302`、`200-299,302`；空或 `*` 接受任意状态 | 策略组的 `expected-status`；普通出站接受任意状态 |

响应：成功 200 `{"delay": <ms>}`；超时 504 `{"message": "Timeout"}`；连接失败、响应不合法或状态码不满足 `expected` 时 503；名称不存在 404；参数不合法 400。`/group/<name>/delay` 会先清除非 `select` 组的手动固定选择。

每次探测都写入该名称的延迟历史（`/proxies` 的 `history`，最多 20 条）。成功时 `alive` 为 `true`；失败时 `alive` 立即为 `false`，历史追加一条 `delay: 0`。`url-test`、`fallback` 与 `load-balance` 选择时跳过 `alive` 为 `false` 的候选，`url-test` 和 `least-ping` 只比较非零延迟。

## 后台健康检查

运行时启动后为每个 `url-test`、`fallback`、`load-balance` 组，以及 `health-check.enable` 为真的代理提供者各建一个任务：启动时立即检查一轮，之后每 `interval` 秒并发探测全部成员（同时最多 10 个），超时与 `expected-status` 取组或提供者配置。`lazy` 为真（默认）时，若该组在上一周期内没有被路由使用，跳过本轮；提供者以包含其成员的任一策略组的使用时间为准。Xray `balancer` 不建任务。`url` 不合法的组不建任务，并在 `/logs` 记一条 `warning`。运行时关闭时任务随之取消并计入关闭报告。

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

跨重载保留的只有控制接口监听器、`reloads` 计数、推送订阅与设备（WARP）所有者；日志级别与输出按新配置重设。出站、策略组运行态、连接表、内存用量视图、`failed_nodes` 与控制面日志随新引擎重建；统计历史 SQLite、Fake-IP 缓存文件和 `store-selected` 选择文件由新引擎按新配置重新打开，未配置 `store-selected` 时策略组选择回到默认值。

`control.listen` 变化、增删 `control` 段和改变 `device` 设置需重启进程：前两者在新配置中被忽略，控制接口仍在原地址服务；`device` 变化使重载以 `configuration.invalid` 失败。`secret`、CORS 与面板等其余 `control` 字段随重载生效。
