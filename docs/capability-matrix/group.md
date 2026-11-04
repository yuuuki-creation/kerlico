# 策略组

由 `tools/capability_matrix.py build` 生成，不要手改。

## balancer

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | 负载均衡组合 |  |  | 有 | 已实现 | 通过 | strategy：`leastLoad`、`leastPing`、`random`、`roundRobin`<br>observer：`burstObservatory`、`none`、`observatory`<br>fallback：`fallbackTag`、`none`<br>via：`api bo`、`loopback`、`lua PickOutbound`、`rule balancerTag`<br>约束：dialerProxy、fallbackTag 需 balancer 时用 loopback（docs/config/outbounds/loopback.md）<br>约束：leastPing、leastLoad 必须配观测站<br>约束：settings 只有 leastLoad 可加 |
| `fallback-tag` | 全部不可用时使用的出站 |  |  | 有 | 已实现 | 通过 |  |
| `selector` | 出站 tag 前缀匹配数组 |  |  | 有 | 已实现 | 通过 | 约束：不能为空 |
| `strategy` | 策略对象 |  |  | 有 | 已实现 | 通过 |  |
| `tag` | 均衡器标识 |  |  | 有 | 已实现 | 通过 |  |

## burst-observatory

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `connectivity` | 本地连通性检测网址，空不检测 |  |  | 有 | 未实现 | 未测 | 约束：仅 destination 失败时探测<br>约束：透明代理下可能回到 xray |
| `destination` | 探测网址，默认 https://connectivitycheck.gstatic.com/generate_204，应返回 204 |  |  | 有 | 未实现 | 未测 |  |
| `http-method` | HTTP 方法，默认 HEAD |  |  | 有 | 未实现 | 未测 | 取值：`GET`、`HEAD` |
| `interval` | 平均探测间隔，默认 1m，最小 10s |  |  | 有 | 未实现 | 未测 |  |
| `ping-config` | 探测配置 |  |  | 有 | 未实现 | 未测 | 约束：必须有效（source:infra/conf/observatory.go） |
| `sampling` | 保留结果数，默认 10 |  |  | 有 | 未实现 | 未测 |  |
| `subject-selector` | 出站 tag 前缀匹配 |  |  | 有 | 未实现 | 未测 |  |
| `timeout` | 超时，默认 5s |  |  | 有 | 未实现 | 未测 |  |

## common

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | 策略组维度 | 有 |  |  | 已实现 | 通过 | type：`fallback`、`load-balance`、`select`、`url-test`<br>member：`include-all`、`include-all-providers`、`include-all-proxies`、`proxies`、`use`<br>filter：`exclude-filter`、`exclude-type`、`filter`、`none`<br>lazy：`false`、`true`<br>disable-udp：`false`、`true`<br>nesting：`策略组`、`节点`<br>约束：empty-fallback 不支持代理组<br>约束：include-all-providers 使 use 失效<br>约束：健康检查不覆盖 use 引入节点 |
| `default-selected` | 默认选择节点；为空或不存在选第一个 | 有 |  |  | 已实现 | 通过 | 取值：`节点名` |
| `disable-udp` | 禁用该组 UDP | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true` |
| `empty-fallback` | 组为空时回退，默认 COMPATIBLE | 有 |  |  | 已实现 | 通过 | 取值：`proxy 名`<br>约束：不支持填代理组 |
| `exclude-filter` | 排除节点，` 分隔多个正则 | 有 |  |  | 已实现 | 通过 | 取值：`正则` |
| `exclude-type` | 按类型排除，\| 分隔，无视大小写，不支持正则 | 有 |  |  | 已实现 | 通过 | 取值：`Shadowsocks\|Http`<br>约束：仅排除引入的出站代理 |
| `expected-status` | 健康检查期望状态码，默认 * | 有 |  |  | 已实现 | 通过 | 取值：`*`、`200/302`、`200/302/400-503`、`204`、`400-503` |
| `filter` | 筛选节点，` 分隔多个正则 | 有 |  |  | 已实现 | 通过 | 取值：`正则`<br>约束：仅作用于引入集合与 include-all-proxies |
| `hidden` | API 返回 hidden | 有 |  |  | 未实现 | 未测 | 取值：`false`、`true` |
| `icon` | API 返回 icon | 有 |  |  | 未实现 | 未测 | 取值：`字符串` |
| `include-all` | 引入所有出站及集合，按名称排序 | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true`<br>约束：不含策略组 |
| `include-all-providers` | 引入所有集合，按名称排序 | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true`<br>约束：会使 use 失效 |
| `include-all-proxies` | 引入所有出站，按名称排序 | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true`<br>约束：不含策略组 |
| `interface-name` | 组出站接口，已弃用 | 废弃 |  |  | 不适用 | 未测 | 取值：`接口名` |
| `interval` | 健康检查间隔秒，不为 0 启用定时测试 | 有 |  |  | 已实现 | 通过 | 取值：`整数` |
| `lazy` | 懒惰，默认 true | 有 |  |  | 已实现 | 通过 | 取值：`false`、`true` |
| `max-failed-times` | 最大失败次数，超过强制健康检查，默认 5 | 有 |  |  | 已实现 | 通过 | 取值：`整数` |
| `name` | 必须，组名 | 有 |  |  | 已实现 | 通过 | 取值：`字符串` |
| `proxies` | 引入出站或其他组 | 有 |  |  | 已实现 | 通过 | 取值：`列表` |
| `routing-mark` | 组路由标记，已弃用 | 废弃 |  |  | 不适用 | 未测 | 取值：`整数` |
| `timeout` | 健康检查超时，毫秒 | 有 |  |  | 已实现 | 通过 | 取值：`整数` |
| `type` | 必须，组类型 | 有 |  |  | 已实现 | 通过 | 取值：`fallback`、`load-balance`、`relay`、`select`、`url-test` |
| `url` | 健康检查地址 | 有 |  |  | 已实现 | 通过 | 取值：`URL`<br>约束：只检查 proxies 字段，不检查 use 引入的节点 |
| `use` | 引入代理集合 | 有 |  |  | 已实现 | 通过 | 取值：`列表` |

## fallback

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | 当前节点超时时按顺序选第一个可用 | 有 |  |  | 已实现 | 通过 | 取值：`fallback` |

## global

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | 预置 GLOBAL 组，默认填充所有组与节点，可自定义 | 有 |  |  | 未实现 | 未测 | 取值：`GLOBAL`<br>约束：自定义时建议写全所有策略组 |

## least-load

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `least-load` | 最稳定 |  |  | 有 | 未实现 | 未测 | 取值：`leastLoad`<br>约束：全不可用且无 fallbackTag 时选默认出站<br>约束：必须配观测站，未覆盖节点被排除 |
| `baselines` | 最高可接受 RTT 标准差 |  |  | 有 | 未实现 | 未测 |  |
| `costs` | 出站权重数组 |  |  | 有 | 未实现 | 未测 |  |
| `expected` | 选出最优节点数，流量随机分配 |  |  | 有 | 未实现 | 未测 |  |
| `match` | 匹配出站 tag |  |  | 有 | 未实现 | 未测 |  |
| `max-rtt` | 最高可接受 RTT |  |  | 有 | 未实现 | 未测 |  |
| `regexp` | 是否正则匹配 tag |  |  | 有 | 未实现 | 未测 |  |
| `tolerance` | 可接受测速失败比例 |  |  | 有 | 未实现 | 未测 |  |
| `value` | 权重，越大越不易选中 |  |  | 有 | 未实现 | 未测 |  |

## least-ping

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `least-ping` | 延迟最低 |  |  | 有 | 未实现 | 未测 | 取值：`leastPing`<br>约束：全不可用且无 fallbackTag 时选默认出站<br>约束：必须配观测站，未覆盖节点被排除 |

## load-balance

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | 负载均衡 | 有 |  |  | 已实现 | 通过 | 取值：`load-balance` |
| `combo` | 负载均衡维度 | 有 |  |  | 已实现 | 通过 | strategy：`consistent-hashing`、`round-robin`、`sticky-sessions`<br>hash-key：``、`in-user`<br>约束：round-robin 配 hash-key 报错 |
| `hash-key` | 哈希 key 来源，未认证回退策略原 key | 有 |  |  | 已实现 | 通过 | 取值：``、`in-user`<br>约束：round-robin 配置会报错<br>约束：仅 consistent-hashing、sticky-sessions |
| `strategy` | 均衡策略 | 有 |  |  | 已实现 | 通过 | 取值：`consistent-hashing`、`round-robin`、`sticky-sessions`<br>约束：sticky-sessions 缓存 10 分钟过期<br>约束：目标地址为域名时用顶级域名匹配 |

## observatory

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | 观测组件 |  |  | 有 | 未实现 | 未测 | kind：`burstObservatory`、`observatory`<br>concurrency：`concurrent`、`serial`<br>约束：二者按需选其一<br>约束：固定间隔请求可能有行为特征<br>约束：标记故障最快 1 周期，最慢 2 周期 |
| `enable-concurrency` | 并发探测 |  |  | 有 | 未实现 | 未测 | 取值：`false`、`true` |
| `probe-interval` | 探测间隔 |  |  | 有 | 未实现 | 未测 | 取值：`10s`、`2h45m`、`h`、`m`、`ms`、`ns`、`s`、`us` |
| `probe-url` | 探测网址 |  |  | 有 | 未实现 | 未测 | 约束：源码键为 probeURL，大小写不敏感（source:infra/conf/observatory.go） |
| `subject-selector` | 出站 tag 前缀匹配 |  |  | 有 | 未实现 | 未测 |  |

## random

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `random` | 随机选择，默认 |  |  | 有 | 未实现 | 未测 | 取值：`random`<br>约束：有 fallbackTag 和观测站时排除不可用出站；无观测数据视为存活 |

## relay

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | relay 策略组已弃用，改用 dialer-proxy | 废弃 |  |  | 不适用 | 未测 | 取值：`relay` |

## round-robin

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `round-robin` | 轮询 |  |  | 有 | 未实现 | 未测 | 取值：`roundRobin`<br>约束：有 fallbackTag 和观测站时排除不可用出站；无观测数据视为存活 |

## select

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | 手动选择 | 有 | 有 |  | 已实现 | 通过 | 取值：`select`、`selector`<br>约束：目前只能通过 Clash API 控制 |
| `combo` | selector 组的默认值和切换行为组合 |  | 有 |  | 已实现 | 通过 | default：`first`、`named`<br>interrupt_exist_connections：`off`、`on`<br>control：`clash-api`、`cli:api group select`、`sing-box-api`<br>约束：outbounds 必填<br>约束：切换时内部连接总被中断，interrupt_exist_connections 只影响入站连接 |
| `default` | 默认的出站标签。 |  | 有 |  | 已实现 | 通过 | 约束：默认使用第一个出站。 |
| `interrupt-exist-connections` | 当选定的出站发生更改时，中断现有连接。 |  | 有 |  | 已实现 | 通过 | 约束：仅入站连接受此设置影响，内部连接将始终被中断。 |
| `outbounds` | 用于选择的出站标签列表。 |  | 有 |  | 已实现 | 通过 | 约束：必填 |

## types

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | sing-box 支持的策略组类型和链式方式 |  | 有 |  | 已实现 | 通过 | group_type：`selector`、`urltest`<br>chain：`dial detour`<br>约束：出站文档只列 selector、urltest 两种组，没有 fallback、load-balance、relay 类型<br>约束：链式出站用拨号字段 detour |

## url-test

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `protocol` | 按延迟自动选择 | 有 | 有 |  | 已实现 | 通过 | 取值：`url-test`、`urltest`<br>约束：interval 必须不大于 idle_timeout（source:protocol/group/urltest.go） |
| `combo` | urltest 组的测速参数组合 |  | 有 |  | 已实现 | 通过 | url：`custom`、`default`<br>interval：`custom`、`default-3m`<br>tolerance：`custom`、`default-50ms`<br>idle_timeout：`custom`、`default-30m`<br>interrupt_exist_connections：`off`、`on`<br>约束：interval 必须不大于 idle_timeout（source:protocol/group/urltest.go）<br>约束：outbounds 必填 |
| `idle-timeout` | 空闲超时。 |  | 有 |  | 已实现 | 通过 | 约束：默认使用 `30m`。 |
| `interrupt-exist-connections` | 当选定的出站发生更改时，中断现有连接。 |  | 有 |  | 已实现 | 通过 | 约束：仅入站连接受此设置影响，内部连接将始终被中断。 |
| `interval` | 测试间隔。 |  | 有 |  | 已实现 | 通过 | 约束：默认使用 `3m`。 |
| `outbounds` | 用于测试的出站标签列表。 |  | 有 |  | 已实现 | 通过 | 约束：必填 |
| `tolerance` | 切换容差 ms | 有 | 有 |  | 已实现 | 通过 | 取值：`整数`<br>约束：默认使用 `50`。 |
| `url` | 用于测试的链接。 |  | 有 |  | 已实现 | 通过 | 约束：默认使用 `https://www.gstatic.com/generate_204`。 |
