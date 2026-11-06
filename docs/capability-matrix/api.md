# API

由 `tools/capability_matrix.py build` 生成，不要手改。

## api

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | API 接入组合 |  |  | 有 | 部分 | 通过 | mode：`inbound+routing`、`listen`<br>service：`HandlerService`、`LoggerService`、`ObservatoryService`、`ReflectionService`、`RoutingService`、`StatsService`<br>约束：inbound 方式用 tunnel 入站并路由到 api 出站 |
| `listen` | API 监听 IP 和端口，可选 |  |  | 有 | 部分 | 未测 | 约束：省略时需加 inbounds 和 routing<br>约束：简易模式不统计 API 入站流量 |
| `services` | 开启的 API |  |  | 有 | 部分 | 通过 | 取值：`HandlerService`、`LoggerService`、`ObservatoryService`、`ReflectionService`、`RoutingService`、`StatsService`<br>约束：ObservatoryService 文档未列（source:infra/conf/api.go） |
| `tag` | 出站标识 |  |  | 有 | 未实现 | 未测 | 约束：不能为空（source:infra/conf/api.go） |

## auth

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `bearer` | 请求带 Authorization: Bearer <secret> | 有 |  |  | 已实现 | 通过 | 取值：`Authorization: Bearer`<br>约束：路径不在工作目录需 SAFE_PATHS |
| `websocket-token` | WebSocket 可用 token 查询参数 | 有 |  |  | 部分 | 未测 | 取值：`token=<secret>` |

## cache-dns

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `post-cache-dns-flush` | 清除 dns 缓存，204 | 有 |  |  | 未实现 | 未测 | 取值：`POST` |

## cache-fakeip

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `post-cache-fakeip-flush` | 清除 fakeip 缓存，204 | 有 |  |  | 已实现 | 通过 | 取值：`POST` |

## clash

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | Clash RESTful API 服务 |  | 有 |  | 部分 | 通过 | 取值：`clash_api`<br>约束：external_controller 为空时禁用<br>约束：需要 with_clash_api 构建标签 |
| `combo` | Clash API 的 UI、认证和 CORS 组合 |  | 有 |  | 部分 | 未测 | ui：`external_ui`、`external_ui+download`、`none`<br>auth：`none`、`secret`<br>cors：`*`、`custom`<br>private_network：`off`、`on`<br>default_mode：`Rule`、`custom`<br>约束：default_mode 无直接效果，只供 clash_mode 规则使用<br>约束：公网网站访问私网 API 时要明确 access_control_allow_origin 并开 access_control_allow_private_network<br>约束：监听 0.0.0.0 时必须设 secret |
| `access-control-allow-origin` | 允许的 CORS 来源，默认使用 `*`。 |  | 有 |  | 已实现 | 未测 | 约束：自 sing-box 1.10.0 起<br>约束：要从公共网站访问私有网络上的 Clash API，必须在 `access_control_allow_origin` 中明确指定它而不是使用 `*`。 |
| `access-control-allow-private-network` | 允许从私有网络访问。 |  | 有 |  | 已实现 | 未测 | 约束：自 sing-box 1.10.0 起<br>约束：要从公共网站访问私有网络上的 Clash API，必须启用 `access_control_allow_private_network`。 |
| `cache-file` | 缓存文件路径，默认使用`cache.db`。 |  | 已移除 |  | 不适用 | 未测 | 约束：`cache_file` 已在 Clash API 中废弃，且已迁移到 `cache_file.enabled` 和 `cache_file.path`。<br>约束：自 sing-box 1.10.0 起<br>约束：配置后启动报错（source:experimental/clashapi/server.go） |
| `cache-id` | 缓存 ID。 |  | 已移除 |  | 不适用 | 未测 | 约束：`cache_id` 已在 Clash API 中废弃，且已迁移到 `cache_file.cache_id`。<br>约束：自 sing-box 1.10.0 起<br>约束：配置后启动报错（source:experimental/clashapi/server.go） |
| `default-mode` | Clash 中的默认模式，默认使用 `Rule`。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.10.0 起 |
| `delete-connections` | Clash API：关闭全部连接 |  | 有 |  | 已实现 | 未测 | 取值：`DELETE /connections`<br>约束：认证：Authorization: Bearer secret；WebSocket 可用 token 查询参数（source:experimental/clashapi/server.go） |
| `delete-connections-id` | Clash API：关闭指定连接 |  | 有 |  | 已实现 | 通过 | 取值：`DELETE /connections/{id}`<br>约束：认证：Authorization: Bearer secret；WebSocket 可用 token 查询参数（source:experimental/clashapi/server.go） |
| `external-controller` | RESTful web API 监听地址。 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.10.0 起 |
| `external-ui` | 到静态网页资源目录的相对路径或绝对路径。 |  | 有 |  | 已实现 | 未测 | 约束：自 sing-box 1.10.0 起 |
| `external-ui-download-detour` | 用于下载静态网页资源的出站的标签。 |  | 有 |  | 未实现 | 未测 | 约束：如果为空，将使用默认出站。<br>约束：自 sing-box 1.10.0 起 |
| `external-ui-download-url` | 静态网页资源的 ZIP 下载 URL，如果指定的 `external_ui` 目录为空，将使用。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.10.0 起<br>约束：默认使用 `https://github.com/MetaCubeX/Yacd-meta/archive/gh-pages.zip`。 |
| `get` | Clash API：问候 |  | 有 |  | 部分 | 通过 | 取值：`GET /`<br>约束：认证：Authorization: Bearer secret；WebSocket 可用 token 查询参数（source:experimental/clashapi/server.go） |
| `get-configs` | Clash API：读取配置 |  | 有 |  | 部分 | 未测 | 取值：`GET /configs`<br>约束：认证：Authorization: Bearer secret；WebSocket 可用 token 查询参数（source:experimental/clashapi/server.go） |
| `get-dns-query` | Clash API：DNS 查询，查询参数 name、type |  | 有 |  | 部分 | 通过 | 取值：`GET /dns/query`<br>约束：认证：Authorization: Bearer secret；WebSocket 可用 token 查询参数（source:experimental/clashapi/server.go） |
| `get-group` | Clash API：列出策略组 |  | 有 |  | 已实现 | 通过 | 取值：`GET /group`<br>约束：认证：Authorization: Bearer secret；WebSocket 可用 token 查询参数（source:experimental/clashapi/server.go） |
| `get-group-name` | Clash API：读取策略组 |  | 有 |  | 已实现 | 通过 | 取值：`GET /group/{name}`<br>约束：认证：Authorization: Bearer secret；WebSocket 可用 token 查询参数（source:experimental/clashapi/server.go） |
| `get-group-name-delay` | Clash API：测策略组延迟 |  | 有 |  | 已实现 | 通过 | 取值：`GET /group/{name}/delay`<br>约束：查询参数 url、timeout<br>约束：认证：Authorization: Bearer secret；WebSocket 可用 token 查询参数（source:experimental/clashapi/server.go） |
| `get-logs` | Clash API：日志流，level 查询参数 |  | 有 |  | 未实现 | 未测 | 取值：`GET /logs`<br>约束：支持 WebSocket<br>约束：认证：Authorization: Bearer secret；WebSocket 可用 token 查询参数（source:experimental/clashapi/server.go） |
| `get-memory` | Clash API：内存使用 |  | 有 |  | 部分 | 通过 | 取值：`GET /memory`<br>约束：支持 WebSocket<br>约束：认证：Authorization: Bearer secret；WebSocket 可用 token 查询参数（source:experimental/clashapi/server.go） |
| `get-profile-tracing` | Clash API：跟踪流 |  | 有 |  | 未实现 | 未测 | 取值：`GET /profile/tracing`<br>约束：认证：Authorization: Bearer secret；WebSocket 可用 token 查询参数（source:experimental/clashapi/server.go） |
| `get-providers-proxies` | Clash API：代理提供者列表（返回空表） |  | 有 |  | 已实现 | 未测 | 取值：`GET /providers/proxies`<br>约束：认证：Authorization: Bearer secret；WebSocket 可用 token 查询参数（source:experimental/clashapi/server.go） |
| `get-providers-proxies-name` | Clash API：读取代理提供者 |  | 有 |  | 已实现 | 通过 | 取值：`GET /providers/proxies/{name}`<br>约束：认证：Authorization: Bearer secret；WebSocket 可用 token 查询参数（source:experimental/clashapi/server.go） |
| `get-providers-proxies-name-healthcheck` | Clash API：代理提供者健康检查 |  | 有 |  | 已实现 | 未测 | 取值：`GET /providers/proxies/{name}/healthcheck`<br>约束：认证：Authorization: Bearer secret；WebSocket 可用 token 查询参数（source:experimental/clashapi/server.go） |
| `get-providers-rules` | Clash API：规则提供者列表 |  | 有 |  | 部分 | 未测 | 取值：`GET /providers/rules`<br>约束：认证：Authorization: Bearer secret；WebSocket 可用 token 查询参数（source:experimental/clashapi/server.go） |
| `get-providers-rules-name` | Clash API：读取规则提供者 |  | 有 |  | 部分 | 未测 | 取值：`GET /providers/rules/{name}`<br>约束：认证：Authorization: Bearer secret；WebSocket 可用 token 查询参数（source:experimental/clashapi/server.go） |
| `get-proxies` | Clash API：列出代理 |  | 有 |  | 部分 | 通过 | 取值：`GET /proxies`<br>约束：认证：Authorization: Bearer secret；WebSocket 可用 token 查询参数（source:experimental/clashapi/server.go） |
| `get-proxies-name` | Clash API：读取代理 |  | 有 |  | 部分 | 通过 | 取值：`GET /proxies/{name}`<br>约束：认证：Authorization: Bearer secret；WebSocket 可用 token 查询参数（source:experimental/clashapi/server.go） |
| `get-proxies-name-delay` | Clash API：测延迟 |  | 有 |  | 已实现 | 通过 | 取值：`GET /proxies/{name}/delay`<br>约束：查询参数 url、timeout<br>约束：认证：Authorization: Bearer secret；WebSocket 可用 token 查询参数（source:experimental/clashapi/server.go） |
| `get-rules` | Clash API：列出路由规则 |  | 有 |  | 已实现 | 通过 | 取值：`GET /rules`<br>约束：认证：Authorization: Bearer secret；WebSocket 可用 token 查询参数（source:experimental/clashapi/server.go） |
| `get-ui` | Clash API：外部 UI 静态页 |  | 有 |  | 部分 | 未测 | 取值：`GET /ui`<br>约束：external_ui 非空时<br>约束：认证：Authorization: Bearer secret；WebSocket 可用 token 查询参数（source:experimental/clashapi/server.go） |
| `get-version` | Clash API：版本 |  | 有 |  | 已实现 | 通过 | 取值：`GET /version`<br>约束：认证：Authorization: Bearer secret；WebSocket 可用 token 查询参数（source:experimental/clashapi/server.go） |
| `patch-configs` | Clash API：修改配置（mode 等） |  | 有 |  | 未实现 | 未测 | 取值：`PATCH /configs`<br>约束：认证：Authorization: Bearer secret；WebSocket 可用 token 查询参数（source:experimental/clashapi/server.go） |
| `patch-script` | Clash API：修改脚本 |  | 有 |  | 未实现 | 未测 | 取值：`PATCH /script`<br>约束：认证：Authorization: Bearer secret；WebSocket 可用 token 查询参数（source:experimental/clashapi/server.go） |
| `post-cache-dns-flush` | Clash API：清空 DNS 缓存 |  | 有 |  | 未实现 | 未测 | 取值：`POST /cache/dns/flush`<br>约束：认证：Authorization: Bearer secret；WebSocket 可用 token 查询参数（source:experimental/clashapi/server.go） |
| `post-cache-fakeip-flush` | Clash API：清空 FakeIP 缓存 |  | 有 |  | 已实现 | 通过 | 取值：`POST /cache/fakeip/flush`<br>约束：认证：Authorization: Bearer secret；WebSocket 可用 token 查询参数（source:experimental/clashapi/server.go） |
| `post-script` | Clash API：测试脚本 |  | 有 |  | 未实现 | 未测 | 取值：`POST /script`<br>约束：认证：Authorization: Bearer secret；WebSocket 可用 token 查询参数（source:experimental/clashapi/server.go） |
| `post-upgrade-ui` | Clash API：更新外部 UI |  | 有 |  | 未实现 | 未测 | 取值：`POST /upgrade/ui`<br>约束：认证：Authorization: Bearer secret；WebSocket 可用 token 查询参数（source:experimental/clashapi/server.go） |
| `put-configs` | Clash API：更新配置 |  | 有 |  | 已实现 | 通过 | 取值：`PUT /configs`<br>约束：认证：Authorization: Bearer secret；WebSocket 可用 token 查询参数（source:experimental/clashapi/server.go） |
| `put-providers-proxies-name` | Clash API：更新代理提供者 |  | 有 |  | 已实现 | 通过 | 取值：`PUT /providers/proxies/{name}`<br>约束：认证：Authorization: Bearer secret；WebSocket 可用 token 查询参数（source:experimental/clashapi/server.go） |
| `put-providers-rules-name` | Clash API：更新规则提供者 |  | 有 |  | 已实现 | 未测 | 取值：`PUT /providers/rules/{name}`<br>约束：认证：Authorization: Bearer secret；WebSocket 可用 token 查询参数（source:experimental/clashapi/server.go） |
| `put-proxies-name` | Clash API：切换 selector |  | 有 |  | 已实现 | 通过 | 取值：`PUT /proxies/{name}`<br>约束：认证：Authorization: Bearer secret；WebSocket 可用 token 查询参数（source:experimental/clashapi/server.go） |
| `secret` | RESTful API 的密钥（可选）通过指定 HTTP 标头 `Authorization: Bearer ${secret}` 进行身份验证如果 RESTful API 正在监听 0.0.0.0，请始终设置一个密钥。 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.10.0 起 |
| `store-fakeip` | 将 fakeip 存储在缓存文件中。 |  | 已移除 |  | 不适用 | 未测 | 约束：`store_selected` 已在 Clash API 中废弃，且已迁移到 `cache_file.store_fakeip`。<br>约束：自 sing-box 1.10.0 起<br>约束：配置后启动报错（source:experimental/clashapi/server.go） |
| `store-mode` | 将 Clash 模式存储在缓存文件中。 |  | 已移除 |  | 不适用 | 未测 | 约束：`store_mode` 已在 Clash API 中废弃，且默认启用当 `cache_file.enabled`。<br>约束：自 sing-box 1.10.0 起<br>约束：配置后启动报错（source:experimental/clashapi/server.go） |
| `store-selected` | 将 `Selector` 中出站的选定的目标出站存储在缓存文件中。 |  | 已移除 |  | 不适用 | 未测 | 约束：`store_selected` 已在 Clash API 中废弃，且默认启用当 `cache_file.enabled`。<br>约束：必须为目标出站设置标签。<br>约束：自 sing-box 1.10.0 起<br>约束：配置后启动报错（source:experimental/clashapi/server.go） |

## configs

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `get-configs` | 获取基本配置 | 有 |  |  | 部分 | 未测 | 取值：`GET` |
| `patch-configs` | 更新基本配置，204 | 有 |  |  | 未实现 | 未测 | 取值：`PATCH`<br>约束：body 如 {"mixed-port": 7890} |
| `put-configs` | 重新加载基本配置，204 | 有 |  |  | 已实现 | 通过 | 取值：`PUT`<br>约束：body {path,payload}<br>约束：force=true |

## configs-geo

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `post-configs-geo` | 更新 GEO 数据库，204 | 有 |  |  | 部分 | 未测 | 取值：`POST`<br>约束：body {path,payload} |

## connections

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `delete-connections` | 关闭所有连接，204 | 有 |  |  | 已实现 | 未测 | 取值：`DELETE` |
| `get-connections` | 连接信息 | 有 |  |  | 部分 | 通过 | 取值：`GET`、`WS`<br>约束：interval=毫秒，默认 1000 |

## connections-id

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `delete-connections-id` | 关闭特定连接，204 | 有 |  |  | 已实现 | 通过 | 取值：`DELETE` |

## controller

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | 控制接口维度 | 有 |  |  | 部分 | 未测 | listener：`external-controller`、`external-controller-pipe`、`external-controller-tls`、`external-controller-unix`<br>auth：`none`、`secret`<br>cors：`allow-origins`、`allow-private-network`、`off`<br>ui：`external-ui`、`external-ui-url`、`off`<br>doh：`external-doh-server`、`off`<br>约束：tls 需顶层 tls 证书<br>约束：unix、pipe、doh 不验证 secret |
| `external-controller` | RESTful API 监听地址 | 有 |  |  | 已实现 | 通过 | 取值：`host:port` |
| `external-controller-cors-allow-origins` | API CORS 允许来源 | 有 |  |  | 已实现 | 未测 | 取值：`来源列表` |
| `external-controller-cors-allow-private-network` | API CORS 允许私有网络 | 有 |  |  | 已实现 | 未测 | 取值：`false`、`true` |
| `external-controller-pipe` | Windows namedpipe API 监听地址 | 有 |  |  | 未实现 | 未测 | 取值：`管道路径`<br>约束：namedpipe 访问不验证 secret |
| `external-controller-routing-mark` | 为 external-controller 与 external-controller-tls 监听 socket 设置 routing-mark | 有 |  |  | 未实现 | 未测 | 取值：`整数`<br>约束：仅 Linux |
| `external-controller-tls` | HTTPS API 监听地址 | 有 |  |  | 未实现 | 未测 | 取值：`host:port`<br>约束：文档：使用 TLS 也必须填写 external-controller<br>约束：需配置顶层 tls 证书 |
| `external-controller-unix` | Unix socket API 监听地址 | 有 |  |  | 未实现 | 未测 | 取值：`路径`<br>约束：Unix socket 访问不验证 secret |
| `external-doh-server` | 在 RESTful API 端口上开启 DoH 服务器 | 有 |  |  | 未实现 | 未测 | 取值：`URL 路径`<br>约束：该 URL 不验证 secret |
| `secret` | API 访问密钥 | 有 |  |  | 已实现 | 通过 | 取值：`字符串` |

## debug-gc

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `put-debug-gc` | 主动 GC，204 | 有 |  |  | 不适用 | 未测 | 取值：`PUT`<br>约束：内核启动时日志级别须为 debug |

## debug-pprof

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `get-debug-pprof` | pprof，含 allocs、heap | 有 |  |  | 不适用 | 未测 | 取值：`GET`<br>约束：heap?raw=true 下载<br>约束：内核启动时日志级别须为 debug |

## dns-query

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `get-dns-query` | DNS 查询，返回 Status、Question、TC、RD、RA、AD、CD、Answer、Authority、Additional | 有 |  |  | 部分 | 通过 | 取值：`GET`<br>约束：name<br>约束：type |

## doh

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `post-get` | external-doh-server 路径 DoH | 有 |  |  | 未实现 | 未测 | 取值：`GET`、`POST`<br>约束：不验证 secret |

## group

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `get-group` | 策略组列表 | 有 |  |  | 已实现 | 通过 | 取值：`GET` |

## group-name

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `get-group-name` | 具体策略组 | 有 |  |  | 已实现 | 通过 | 取值：`GET` |

## group-name-delay

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `get-group-name-delay` | 测试组内节点并清除自动组 fixed | 有 |  |  | 已实现 | 通过 | 取值：`GET`<br>约束：expected<br>约束：timeout<br>约束：url |

## handler-service

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `add-inbound` | gRPC 方法 |  |  | 有 | 未实现 | 未测 |  |
| `add-outbound` | gRPC 方法 |  |  | 有 | 未实现 | 未测 |  |
| `alter-inbound` | gRPC 方法 |  |  | 有 | 未实现 | 未测 |  |
| `alter-outbound` | gRPC 方法 |  |  | 有 | 未实现 | 未测 |  |
| `get-inbound-users` | gRPC 方法 |  |  | 有 | 未实现 | 未测 |  |
| `get-inbound-users-count` | gRPC 方法 |  |  | 有 | 未实现 | 未测 |  |
| `list-inbounds` | gRPC 方法 |  |  | 有 | 未实现 | 未测 |  |
| `list-outbounds` | gRPC 方法 |  |  | 有 | 未实现 | 未测 |  |
| `overview` | 增删列入站出站；入站增删用户 |  |  | 有 | 未实现 | 未测 | 取值：`列入站`、`列出站`、`删除入站`、`删除出站`、`删除用户`、`添加入站`、`添加出站`、`添加用户`<br>约束：用户操作仅 VMess、VLESS、Trojan、Shadowsocks |
| `remove-inbound` | gRPC 方法 |  |  | 有 | 未实现 | 未测 |  |
| `remove-outbound` | gRPC 方法 |  |  | 有 | 未实现 | 未测 |  |

## logger-service

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `overview` | 重启内置 Logger，配合 logrotate |  |  | 有 | 未实现 | 未测 |  |
| `restart-logger` | gRPC 方法 |  |  | 有 | 未实现 | 未测 |  |

## logs

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `get-logs` | 实时日志 | 有 |  |  | 未实现 | 未测 | 取值：`GET`、`WS`<br>约束：format=structured<br>约束：level=info\|warning\|error\|debug |

## lua-dns

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `dns-query` | 经 DNS 客户端查询 |  |  | 有 | 不适用 | 未测 | 约束：DNS Hook 内不可用 |
| `dns-servers` | 上游服务器数组 |  |  | 有 | 不适用 | 未测 |  |
| `server-obj-id` | 服务器标识 |  |  | 有 | 不适用 | 未测 |  |
| `server-obj-query` | 直接查询指定上游 |  |  | 有 | 不适用 | 未测 | 约束：跳过全局 Hosts 和脚本 |

## lua-geodata

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `domain-matcher-obj-match` | 匹配器方法 |  |  | 有 | 不适用 | 未测 |  |
| `domain-matcher-obj-match-any` | 匹配器方法 |  |  | 有 | 不适用 | 未测 |  |
| `geodata-build-domain-matcher` | 创建域名匹配器 |  |  | 有 | 不适用 | 未测 | 取值：`domain:`、`dotless:`、`ext-domain:`、`ext-site:`、`ext:`、`full:`、`geosite:`、`keyword:`、`regexp:`<br>约束：无前缀默认 domain:，与路由 domain 默认子串不同 |
| `geodata-build-ipmatcher` | 创建 IP 匹配器 |  |  | 有 | 不适用 | 未测 |  |
| `ip-matcher-obj-any-match` | 匹配器方法 |  |  | 有 | 不适用 | 未测 |  |
| `ip-matcher-obj-filter-ips` | 匹配器方法 |  |  | 有 | 不适用 | 未测 |  |
| `ip-matcher-obj-match` | 匹配器方法 |  |  | 有 | 不适用 | 未测 |  |
| `ip-matcher-obj-matches` | 匹配器方法 |  |  | 有 | 不适用 | 未测 |  |
| `ip-matcher-obj-set-reverse` | 匹配器方法 |  |  | 有 | 不适用 | 未测 |  |
| `ip-matcher-obj-toggle-reverse` | 匹配器方法 |  |  | 有 | 不适用 | 未测 |  |

## lua-hook

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `handle-dnsquery` | DNS Hook，返回 ips, ttl, err |  |  | 有 | 不适用 | 未测 | 取值：`domain`、`fake`、`ipv4`、`ipv6`<br>约束：err 为 nil 时 TTL 必须 0..4294967295<br>约束：ips 必须是 slice<br>约束：空结果视为查询失败 |
| `handle-route` | 路由 Hook，返回 outboundTag, ruleTag, err |  |  | 有 | 不适用 | 未测 | 取值：`ctx`、`inboundTag`、`localPort`、`network`、`protocol`、`skipDNSResolve`、`sourcePort`、`targetDomain`、`targetPort`、`user`、`vlessRoute`<br>约束：未选中用默认出站<br>约束：标识不存在关闭连接<br>约束：错误时记录并尝试默认出站 |

## lua-log

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `log-debug` | 写日志，受 log.loglevel 控制 |  |  | 有 | 不适用 | 未测 |  |
| `log-error` | 写日志，受 log.loglevel 控制 |  |  | 有 | 不适用 | 未测 |  |
| `log-info` | 写日志，受 log.loglevel 控制 |  |  | 有 | 不适用 | 未测 |  |
| `log-warning` | 写日志，受 log.loglevel 控制 |  |  | 有 | 不适用 | 未测 |  |

## lua-net-ip

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `equal` | IP 比较 |  |  | 有 | 不适用 | 未测 |  |
| `string` | IP 转文本 |  |  | 有 | 不适用 | 未测 |  |

## lua-router

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `router-find-process` | 查找本机进程 |  |  | 有 | 不适用 | 未测 | 约束：Windows、Linux、macOS 内置；Android 需注册；iOS 不支持 |
| `router-local-os` | 路由常量 |  |  | 有 | 不适用 | 未测 |  |
| `router-network-tcp` | 路由常量 |  |  | 有 | 不适用 | 未测 |  |
| `router-network-udp` | 路由常量 |  |  | 有 | 不适用 | 未测 |  |
| `router-network-unix` | 路由常量 |  |  | 有 | 不适用 | 未测 |  |
| `router-network-unknown` | 路由常量 |  |  | 有 | 不适用 | 未测 |  |
| `router-pick-outbound` | 经负载均衡器选出站 |  |  | 有 | 不适用 | 未测 |  |

## lua-routing-context

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `get-attributes` | routing.Context 方法 |  |  | 有 | 不适用 | 未测 |  |
| `get-local-ips` | routing.Context 方法 |  |  | 有 | 不适用 | 未测 |  |
| `get-source-ips` | routing.Context 方法 |  |  | 有 | 不适用 | 未测 |  |
| `get-target-ips` | routing.Context 方法 |  |  | 有 | 不适用 | 未测 |  |

## memory

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `get-memory` | 实时内存，每秒推送 inuse、oslimit | 有 |  |  | 部分 | 通过 | 取值：`GET`、`WS` |

## metrics

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `debug-pprof` | pprof 调试 |  |  | 有 | 不适用 | 未测 | 取值：`/debug/pprof/goroutine`、`/debug/pprof/heap` |
| `debug-vars` | expvars，含 stats 和 observatory |  |  | 有 | 部分 | 通过 | 取值：`observatory`、`stats.inbound`、`stats.outbound`、`stats.user` |
| `listen` | 直接监听地址 |  |  | 有 | 部分 | 通过 | 约束：tag 为空自动为 Metrics<br>约束：两者都未设启动失败 |
| `tag` | 对应出站 tag，配 tunnel 入站与路由访问 |  |  | 有 | 未实现 | 未测 |  |

## observatory-service

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `get-outbound-status` | gRPC 方法 |  |  | 有 | 未实现 | 未测 |  |

## providers-proxies

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `get-providers-proxies` | 所有代理集合 | 有 |  |  | 已实现 | 未测 | 取值：`GET` |

## providers-proxies-name

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `get-providers-proxies-name` | 特定集合 | 有 |  |  | 已实现 | 通过 | 取值：`GET` |
| `put-providers-proxies-name` | 更新集合，204 | 有 |  |  | 已实现 | 通过 | 取值：`PUT` |

## providers-proxies-name-healthcheck

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `get-providers-proxies-name-healthcheck` | 触发集合健康检查，204 | 有 |  |  | 已实现 | 未测 | 取值：`GET` |

## providers-proxies-name-proxy

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `get-providers-proxies-name-proxy` | 集合内指定代理 | 有 |  |  | 已实现 | 未测 | 取值：`GET` |

## providers-proxies-name-proxy-healthcheck

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `get-providers-proxies-name-proxy-healthcheck` | 测试集合内指定代理 | 有 |  |  | 已实现 | 未测 | 取值：`GET`<br>约束：timeout<br>约束：url |

## providers-rules

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `get-providers-rules` | 所有规则集合 | 有 |  |  | 部分 | 未测 | 取值：`GET` |

## providers-rules-name

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `put-providers-rules-name` | 更新规则集合，204 | 有 |  |  | 已实现 | 未测 | 取值：`PUT` |

## proxies

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `get-proxies` | 代理信息，含 name、type、udp、uot、xudp、tfo、mptcp、smux、alive、history、extra、interface、routing-mark、provider-name、dialer-proxy；组另含 now、all、testUrl、hidden、icon、emptyFallback、expectedStatus、fixed | 有 |  |  | 部分 | 通过 | 取值：`GET` |

## proxies-name

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `delete-proxies-name` | 清除 fixed 选择（Selector 除外），204 | 有 |  |  | 已实现 | 未测 | 取值：`DELETE` |
| `get-proxies-name` | 具体代理 | 有 |  |  | 部分 | 通过 | 取值：`GET` |
| `put-proxies-name` | 选择代理，204 | 有 |  |  | 已实现 | 通过 | 取值：`PUT`<br>约束：body {"name":"日本"} |

## proxies-name-delay

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `get-proxies-name-delay` | 测试代理延迟 | 有 |  |  | 已实现 | 通过 | 取值：`GET`<br>约束：expected<br>约束：timeout<br>约束：url |

## reflection-service

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `list` | gRPC 反射，可 grpcurl list |  |  | 有 | 不适用 | 未测 | 取值：`grpc.reflection.v1alpha.ServerReflection`、`v2ray.core.app.proxyman.command.HandlerService`、`v2ray.core.app.stats.command.StatsService`、`xray.app.proxyman.command.HandlerService`、`xray.app.stats.command.StatsService` |

## restart

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `post-restart` | 重启内核，204 | 有 |  |  | 已实现 | 通过 | 取值：`POST`<br>约束：body {path,payload} |

## root

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `get` | 根路径 hello（文档未写） | 有 |  |  | 部分 | 通过 | 取值：`GET` |

## routing-service

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `add-rule` | gRPC 方法 |  |  | 有 | 未实现 | 未测 |  |
| `get-balancer-info` | gRPC 方法 |  |  | 有 | 已实现 | 通过 |  |
| `list-rule` | gRPC 方法 |  |  | 有 | 已实现 | 通过 |  |
| `override-balancer-target` | gRPC 方法 |  |  | 有 | 已实现 | 通过 |  |
| `overview` | 增删改规则、查询均衡器、封来源 IP |  |  | 有 | 未实现 | 未测 | 取值：`adrules`、`bi`、`bo`、`rmrules`、`sib` |
| `remove-rule` | gRPC 方法 |  |  | 有 | 未实现 | 未测 |  |
| `subscribe-routing-stats` | gRPC 方法 |  |  | 有 | 未实现 | 未测 |  |
| `test-route` | gRPC 方法 |  |  | 有 | 已实现 | 通过 |  |

## rules

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `get-rules` | 规则列表，index、type、payload、proxy、size、extra | 有 |  |  | 已实现 | 通过 | 取值：`GET` |

## rules-disable

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `patch-rules-disable` | 临时禁用规则，重启失效，204 | 有 |  |  | 未实现 | 未测 | 取值：`PATCH`<br>约束：body {"0": false,"1": true} |

## singbox

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | sing-box gRPC API 服务，兼容 gRPC-Web |  | 有 |  | 未实现 | 未测 | 取值：`api`<br>约束：自 sing-box 1.14.0 起 |
| `combo` | sing-box API 服务的面板、认证和安全层组合 |  | 有 |  | 未实现 | 未测 | dashboard：`bool`、`object`、`off`、`path`<br>auth：`none`、`secret`<br>security：`none`、`tls`<br>protocol：`grpc`、`grpc-web`<br>约束：dashboard 下载后在 /dashboard/ 提供，其他浏览器请求被重定向<br>约束：secret 为空时不认证<br>约束：update_interval 默认 1d |
| `access-control-allow-origin` | 允许的 CORS 来源,默认使用 `*`。 |  | 有 |  | 已实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `access-control-allow-private-network` | 允许从私有网络访问。 |  | 有 |  | 已实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `dashboard` | 下载并通过 API 监听器在 `/dashboard/` 提供的 Web 仪表板；其他浏览器请求将被重定向到该路径。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `dashboard-download-url` | 仪表板压缩包（zip）的下载 URL。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：默认使用 `https://github.com/SagerNet/sing-box-dashboard/archive/refs/heads/gh-pages.zip`。 |
| `dashboard-enabled` | 启用仪表板。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `dashboard-http-client` | 用于下载仪表板的 HTTP 客户端。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |
| `dashboard-path` | 存放仪表板文件的目录。 |  | 有 |  | 部分 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：默认使用工作目录下的 `dashboard`。 |
| `dashboard-update-interval` | 仪表板的更新间隔。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起<br>约束：默认使用 `1d`。 |
| `secret` | API 密钥。 |  | 有 |  | 已实现 | 通过 | 约束：自 sing-box 1.14.0 起<br>约束：默认无需认证。 |
| `tls` | TLS 配置,参阅 TLS。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.14.0 起 |

## singbox-grpc

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `cancel-open-connect-auth-challenge` | sing-box API StartedService 的 CancelOpenConnectAuthChallenge 方法 |  | 有 |  | 不适用 | 未测 | 取值：`CancelOpenConnectAuthChallenge`<br>约束：自 sing-box 1.14.0 起<br>约束：认证：authorization: Bearer secret gRPC 元数据 |
| `cancel-open-vpnchallenge` | sing-box API StartedService 的 CancelOpenVPNChallenge 方法 |  | 有 |  | 不适用 | 未测 | 取值：`CancelOpenVPNChallenge`<br>约束：自 sing-box 1.14.0 起<br>约束：认证：authorization: Bearer secret gRPC 元数据 |
| `cancel-taildrop-receiving` | sing-box API StartedService 的 CancelTaildropReceiving 方法 |  | 有 |  | 不适用 | 未测 | 取值：`CancelTaildropReceiving`<br>约束：自 sing-box 1.14.0 起<br>约束：认证：authorization: Bearer secret gRPC 元数据 |
| `clear-logs` | sing-box API StartedService 的 ClearLogs 方法 |  | 有 |  | 不适用 | 未测 | 取值：`ClearLogs`<br>约束：自 sing-box 1.14.0 起<br>约束：认证：authorization: Bearer secret gRPC 元数据 |
| `close-all-connections` | sing-box API StartedService 的 CloseAllConnections 方法 |  | 有 |  | 不适用 | 未测 | 取值：`CloseAllConnections`<br>约束：自 sing-box 1.14.0 起<br>约束：认证：authorization: Bearer secret gRPC 元数据 |
| `close-connection` | sing-box API StartedService 的 CloseConnection 方法 |  | 有 |  | 不适用 | 未测 | 取值：`CloseConnection`<br>约束：自 sing-box 1.14.0 起<br>约束：认证：authorization: Bearer secret gRPC 元数据 |
| `delete-taildrop-file` | sing-box API StartedService 的 DeleteTaildropFile 方法 |  | 有 |  | 不适用 | 未测 | 取值：`DeleteTaildropFile`<br>约束：自 sing-box 1.14.0 起<br>约束：认证：authorization: Bearer secret gRPC 元数据 |
| `download-taildrop-file` | sing-box API StartedService 的 DownloadTaildropFile 方法 |  | 有 |  | 不适用 | 未测 | 取值：`DownloadTaildropFile`<br>约束：自 sing-box 1.14.0 起<br>约束：认证：authorization: Bearer secret gRPC 元数据 |
| `get-clash-mode-status` | sing-box API StartedService 的 GetClashModeStatus 方法 |  | 有 |  | 不适用 | 未测 | 取值：`GetClashModeStatus`<br>约束：自 sing-box 1.14.0 起<br>约束：认证：authorization: Bearer secret gRPC 元数据 |
| `get-default-log-level` | sing-box API StartedService 的 GetDefaultLogLevel 方法 |  | 有 |  | 不适用 | 未测 | 取值：`GetDefaultLogLevel`<br>约束：自 sing-box 1.14.0 起<br>约束：认证：authorization: Bearer secret gRPC 元数据 |
| `get-deprecated-warnings` | sing-box API StartedService 的 GetDeprecatedWarnings 方法 |  | 有 |  | 不适用 | 未测 | 取值：`GetDeprecatedWarnings`<br>约束：自 sing-box 1.14.0 起<br>约束：认证：authorization: Bearer secret gRPC 元数据 |
| `get-started-at` | sing-box API StartedService 的 GetStartedAt 方法 |  | 有 |  | 不适用 | 未测 | 取值：`GetStartedAt`<br>约束：自 sing-box 1.14.0 起<br>约束：认证：authorization: Bearer secret gRPC 元数据 |
| `get-tailscale-certificate` | sing-box API StartedService 的 GetTailscaleCertificate 方法 |  | 有 |  | 不适用 | 未测 | 取值：`GetTailscaleCertificate`<br>约束：自 sing-box 1.14.0 起<br>约束：认证：authorization: Bearer secret gRPC 元数据 |
| `get-version` | sing-box API StartedService 的 GetVersion 方法 |  | 有 |  | 不适用 | 未测 | 取值：`GetVersion`<br>约束：自 sing-box 1.14.0 起<br>约束：认证：authorization: Bearer secret gRPC 元数据 |
| `mark-taildrop-inbox-read` | sing-box API StartedService 的 MarkTaildropInboxRead 方法 |  | 有 |  | 不适用 | 未测 | 取值：`MarkTaildropInboxRead`<br>约束：自 sing-box 1.14.0 起<br>约束：认证：authorization: Bearer secret gRPC 元数据 |
| `provide-usbdevices` | sing-box API StartedService 的 ProvideUSBDevices 方法 |  | 有 |  | 不适用 | 未测 | 取值：`ProvideUSBDevices`<br>约束：自 sing-box 1.14.0 起<br>约束：认证：authorization: Bearer secret gRPC 元数据 |
| `select-outbound` | sing-box API StartedService 的 SelectOutbound 方法 |  | 有 |  | 不适用 | 未测 | 取值：`SelectOutbound`<br>约束：自 sing-box 1.14.0 起<br>约束：认证：authorization: Bearer secret gRPC 元数据 |
| `send-taildrop-files` | sing-box API StartedService 的 SendTaildropFiles 方法 |  | 有 |  | 不适用 | 未测 | 取值：`SendTaildropFiles`<br>约束：自 sing-box 1.14.0 起<br>约束：认证：authorization: Bearer secret gRPC 元数据 |
| `set-clash-mode` | sing-box API StartedService 的 SetClashMode 方法 |  | 有 |  | 不适用 | 未测 | 取值：`SetClashMode`<br>约束：自 sing-box 1.14.0 起<br>约束：认证：authorization: Bearer secret gRPC 元数据 |
| `set-group-expand` | sing-box API StartedService 的 SetGroupExpand 方法 |  | 有 |  | 不适用 | 未测 | 取值：`SetGroupExpand`<br>约束：自 sing-box 1.14.0 起<br>约束：认证：authorization: Bearer secret gRPC 元数据 |
| `set-tailscale-exit-node` | sing-box API StartedService 的 SetTailscaleExitNode 方法 |  | 有 |  | 不适用 | 未测 | 取值：`SetTailscaleExitNode`<br>约束：自 sing-box 1.14.0 起<br>约束：认证：authorization: Bearer secret gRPC 元数据 |
| `start-network-quality-test` | sing-box API StartedService 的 StartNetworkQualityTest 方法 |  | 有 |  | 不适用 | 未测 | 取值：`StartNetworkQualityTest`<br>约束：自 sing-box 1.14.0 起<br>约束：认证：authorization: Bearer secret gRPC 元数据 |
| `start-stuntest` | sing-box API StartedService 的 StartSTUNTest 方法 |  | 有 |  | 不适用 | 未测 | 取值：`StartSTUNTest`<br>约束：自 sing-box 1.14.0 起<br>约束：认证：authorization: Bearer secret gRPC 元数据 |
| `start-tailscale-ping` | sing-box API StartedService 的 StartTailscalePing 方法 |  | 有 |  | 不适用 | 未测 | 取值：`StartTailscalePing`<br>约束：自 sing-box 1.14.0 起<br>约束：认证：authorization: Bearer secret gRPC 元数据 |
| `start-tailscale-sshsession` | sing-box API StartedService 的 StartTailscaleSSHSession 方法 |  | 有 |  | 不适用 | 未测 | 取值：`StartTailscaleSSHSession`<br>约束：自 sing-box 1.14.0 起<br>约束：认证：authorization: Bearer secret gRPC 元数据 |
| `submit-open-connect-auth-response` | sing-box API StartedService 的 SubmitOpenConnectAuthResponse 方法 |  | 有 |  | 不适用 | 未测 | 取值：`SubmitOpenConnectAuthResponse`<br>约束：自 sing-box 1.14.0 起<br>约束：认证：authorization: Bearer secret gRPC 元数据 |
| `submit-open-vpnchallenge-response` | sing-box API StartedService 的 SubmitOpenVPNChallengeResponse 方法 |  | 有 |  | 不适用 | 未测 | 取值：`SubmitOpenVPNChallengeResponse`<br>约束：自 sing-box 1.14.0 起<br>约束：认证：authorization: Bearer secret gRPC 元数据 |
| `subscribe-clash-mode` | sing-box API StartedService 的 SubscribeClashMode 方法 |  | 有 |  | 不适用 | 未测 | 取值：`SubscribeClashMode`<br>约束：自 sing-box 1.14.0 起<br>约束：认证：authorization: Bearer secret gRPC 元数据 |
| `subscribe-connections` | sing-box API StartedService 的 SubscribeConnections 方法 |  | 有 |  | 不适用 | 未测 | 取值：`SubscribeConnections`<br>约束：自 sing-box 1.14.0 起<br>约束：认证：authorization: Bearer secret gRPC 元数据 |
| `subscribe-groups` | sing-box API StartedService 的 SubscribeGroups 方法 |  | 有 |  | 不适用 | 未测 | 取值：`SubscribeGroups`<br>约束：自 sing-box 1.14.0 起<br>约束：认证：authorization: Bearer secret gRPC 元数据 |
| `subscribe-log` | sing-box API StartedService 的 SubscribeLog 方法 |  | 有 |  | 不适用 | 未测 | 取值：`SubscribeLog`<br>约束：自 sing-box 1.14.0 起<br>约束：认证：authorization: Bearer secret gRPC 元数据 |
| `subscribe-notifications` | sing-box API StartedService 的 SubscribeNotifications 方法 |  | 有 |  | 不适用 | 未测 | 取值：`SubscribeNotifications`<br>约束：自 sing-box 1.14.0 起<br>约束：认证：authorization: Bearer secret gRPC 元数据 |
| `subscribe-open-connect-status` | sing-box API StartedService 的 SubscribeOpenConnectStatus 方法 |  | 有 |  | 不适用 | 未测 | 取值：`SubscribeOpenConnectStatus`<br>约束：自 sing-box 1.14.0 起<br>约束：认证：authorization: Bearer secret gRPC 元数据 |
| `subscribe-open-vpnstatus` | sing-box API StartedService 的 SubscribeOpenVPNStatus 方法 |  | 有 |  | 不适用 | 未测 | 取值：`SubscribeOpenVPNStatus`<br>约束：自 sing-box 1.14.0 起<br>约束：认证：authorization: Bearer secret gRPC 元数据 |
| `subscribe-outbounds` | sing-box API StartedService 的 SubscribeOutbounds 方法 |  | 有 |  | 不适用 | 未测 | 取值：`SubscribeOutbounds`<br>约束：自 sing-box 1.14.0 起<br>约束：认证：authorization: Bearer secret gRPC 元数据 |
| `subscribe-service-status` | sing-box API StartedService 的 SubscribeServiceStatus 方法 |  | 有 |  | 不适用 | 未测 | 取值：`SubscribeServiceStatus`<br>约束：自 sing-box 1.14.0 起<br>约束：认证：authorization: Bearer secret gRPC 元数据 |
| `subscribe-status` | sing-box API StartedService 的 SubscribeStatus 方法 |  | 有 |  | 不适用 | 未测 | 取值：`SubscribeStatus`<br>约束：自 sing-box 1.14.0 起<br>约束：认证：authorization: Bearer secret gRPC 元数据 |
| `subscribe-taildrop-inbox` | sing-box API StartedService 的 SubscribeTaildropInbox 方法 |  | 有 |  | 不适用 | 未测 | 取值：`SubscribeTaildropInbox`<br>约束：自 sing-box 1.14.0 起<br>约束：认证：authorization: Bearer secret gRPC 元数据 |
| `subscribe-tailscale-status` | sing-box API StartedService 的 SubscribeTailscaleStatus 方法 |  | 有 |  | 不适用 | 未测 | 取值：`SubscribeTailscaleStatus`<br>约束：自 sing-box 1.14.0 起<br>约束：认证：authorization: Bearer secret gRPC 元数据 |
| `subscribe-usbipserver-status` | sing-box API StartedService 的 SubscribeUSBIPServerStatus 方法 |  | 有 |  | 不适用 | 未测 | 取值：`SubscribeUSBIPServerStatus`<br>约束：自 sing-box 1.14.0 起<br>约束：认证：authorization: Bearer secret gRPC 元数据 |
| `tailscale-logout` | sing-box API StartedService 的 TailscaleLogout 方法 |  | 有 |  | 不适用 | 未测 | 取值：`TailscaleLogout`<br>约束：自 sing-box 1.14.0 起<br>约束：认证：authorization: Bearer secret gRPC 元数据 |
| `urltest` | sing-box API StartedService 的 URLTest 方法 |  | 有 |  | 不适用 | 未测 | 取值：`URLTest`<br>约束：自 sing-box 1.14.0 起<br>约束：认证：authorization: Bearer secret gRPC 元数据 |

## singbox-grpc-managed

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `get-system-proxy-status` | 图形客户端 ManagedService 的 GetSystemProxyStatus 方法 |  | 有 |  | 不适用 | 未测 | 取值：`GetSystemProxyStatus` |
| `reload-service` | 图形客户端 ManagedService 的 ReloadService 方法 |  | 有 |  | 不适用 | 未测 | 取值：`ReloadService` |
| `set-system-proxy-enabled` | 图形客户端 ManagedService 的 SetSystemProxyEnabled 方法 |  | 有 |  | 不适用 | 未测 | 取值：`SetSystemProxyEnabled` |
| `stop-service` | 图形客户端 ManagedService 的 StopService 方法 |  | 有 |  | 不适用 | 未测 | 取值：`StopService` |
| `trigger-debug-crash` | 图形客户端 ManagedService 的 TriggerDebugCrash 方法 |  | 有 |  | 不适用 | 未测 | 取值：`TriggerDebugCrash` |
| `trigger-oomreport` | 图形客户端 ManagedService 的 TriggerOOMReport 方法 |  | 有 |  | 不适用 | 未测 | 取值：`TriggerOOMReport` |

## ssm

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | Shadowsocks 管理 RESTful API 服务 |  | 有 |  | 未实现 | 未测 | 取值：`ssm-api`<br>约束：自 sing-box 1.12.0 起<br>约束：选中的 Shadowsocks 入站必须开启 managed |
| `cache-path` | 如果设置，当服务器即将停止时，流量和用户状态将保存到指定的 JSON 文件中，以便在下次启动时恢复。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.12.0 起 |
| `delete-server-v1-users-username` | SSM API：删除用户 |  | 有 |  | 未实现 | 未测 | 取值：`DELETE /server/v1#users/{username}`<br>约束：前缀是 servers 配置的 HTTP 路径 |
| `get-server-v1` | SSM API：服务器信息 |  | 有 |  | 未实现 | 未测 | 取值：`GET /server/v1/`<br>约束：前缀是 servers 配置的 HTTP 路径 |
| `get-server-v1-users` | SSM API：列出用户 |  | 有 |  | 未实现 | 未测 | 取值：`GET /server/v1/users`<br>约束：前缀是 servers 配置的 HTTP 路径 |
| `get-server-v1-users-username` | SSM API：读取用户 |  | 有 |  | 未实现 | 未测 | 取值：`GET /server/v1#users/{username}`<br>约束：前缀是 servers 配置的 HTTP 路径 |
| `post-server-v1-users` | SSM API：添加用户 |  | 有 |  | 未实现 | 未测 | 取值：`POST /server/v1/users`<br>约束：前缀是 servers 配置的 HTTP 路径 |
| `put-server-v1-users-username` | SSM API：更新用户 |  | 有 |  | 未实现 | 未测 | 取值：`PUT /server/v1#users/{username}`<br>约束：前缀是 servers 配置的 HTTP 路径 |
| `servers` | 从 HTTP 端点到 Shadowsocks 入站 标签的映射对象。 |  | 有 |  | 未实现 | 未测 | 约束：必填<br>约束：自 sing-box 1.12.0 起<br>约束：选定的 Shadowsocks 入站必须配置启用 managed。 |
| `tls` | TLS 配置，参阅 TLS。 |  | 有 |  | 未实现 | 未测 | 约束：自 sing-box 1.12.0 起 |

## stats-service

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `get-all-online-users` | gRPC 方法 |  |  | 有 | 部分 | 通过 |  |
| `get-stats` | gRPC 方法 |  |  | 有 | 部分 | 通过 |  |
| `get-stats-online` | gRPC 方法 |  |  | 有 | 部分 | 通过 |  |
| `get-stats-online-ip-list` | gRPC 方法 |  |  | 有 | 部分 | 通过 |  |
| `get-sys-stats` | gRPC 方法 |  |  | 有 | 部分 | 通过 |  |
| `get-users-stats` | gRPC 方法 |  |  | 有 | 部分 | 通过 |  |
| `overview` | 内置数据统计服务 |  |  | 有 | 部分 | 通过 |  |
| `query-stats` | gRPC 方法 |  |  | 有 | 部分 | 通过 |  |

## storage-key

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `delete-storage-key` | 删存储值，204 | 有 |  |  | 未实现 | 未测 | 取值：`DELETE` |
| `get-storage-key` | 读存储值，不存在 null | 有 |  |  | 未实现 | 未测 | 取值：`GET` |
| `put-storage-key` | 写存储值，合法 JSON，最大 1MB，204 | 有 |  |  | 未实现 | 未测 | 取值：`PUT` |

## traffic

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `get-traffic` | 实时流量，每秒推送 up、down、upTotal、downTotal | 有 |  |  | 部分 | 通过 | 取值：`GET`、`WS` |

## ui

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `get` | GET /ui 面板静态资源 | 有 |  |  | 部分 | 未测 | 取值：`GET` |

## upgrade

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `post-upgrade` | 更新内核，返回 status ok | 有 |  |  | 未实现 | 未测 | 取值：`POST`<br>约束：channel=xxx<br>约束：force=true |

## upgrade-geo

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `post-upgrade-geo` | 更新 GEO 数据库，204 | 有 |  |  | 部分 | 未测 | 取值：`POST` |

## upgrade-ui

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `post-upgrade-ui` | 更新面板，须设置 external-ui | 有 |  |  | 未实现 | 未测 | 取值：`POST` |

## v2ray

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `get-stats` | V2Ray API StatsService：读取单个统计 |  | 有 |  | 部分 | 通过 | 取值：`GetStats` |
| `get-sys-stats` | V2Ray API StatsService：读取系统统计 |  | 有 |  | 部分 | 通过 | 取值：`GetSysStats` |
| `query-stats` | V2Ray API StatsService：按模式查询统计 |  | 有 |  | 部分 | 通过 | 取值：`QueryStats` |

## version

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `get-version` | 版本信息 meta、version | 有 |  |  | 已实现 | 通过 | 取值：`GET` |

## webui

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `dashboards` | 文档列出的外部面板 Yacd、Metacubexd、zashboard | 有 |  |  | 部分 | 未测 | 取值：`Metacubexd`、`Yacd`、`zashboard` |
| `external-ui` | 静态面板目录，经 API 地址 /ui 提供 | 有 |  |  | 已实现 | 未测 | 取值：`工作目录相对路径`、`绝对路径`<br>约束：不在工作目录时需用 SAFE_PATHS 加入安全路径 |
| `external-ui-name` | 面板子目录名，合并为 external-ui/<name> | 有 |  |  | 已实现 | 未测 | 取值：`字符串` |
| `external-ui-url` | 面板下载地址 | 有 |  |  | 未实现 | 未测 | 取值：`URL`<br>约束：source:docs/config.yaml 注明支持 zip 与 tgz |
