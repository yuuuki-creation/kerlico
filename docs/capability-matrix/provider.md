# 代理提供者

由 `tools/capability_matrix.py build` 生成，不要手改。

## content

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `format` | 集合文件内容格式 | 有 |  |  | 待标注 | 未测 | 取值：`base64`、`uri`、`yaml`<br>约束：uri、base64 不需要 proxies 字段<br>约束：三者不可写在同一文件 |

## outbound

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `unsupported` | 配置文档没有代理提供者（订阅）配置，只有 Clash API 的 /providers 路由且返回空表 |  | 有 |  | 待标注 | 未测 | 约束：路由规则集见 ruleset 类别 |

## proxy

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `combo` | 代理集合维度 | 有 |  |  | 待标注 | 未测 | type：`file`、`http`、`inline`<br>content：`age-armor`、`base64`、`uri`、`yaml`<br>health-check：`lazy`、`off`、`on`<br>override：`fields`、`none`、`override-expr`<br>filter：`exclude-filter`、`exclude-type`、`filter`、`none` |
| `age-secret-key` | 解密 age armor 配置 | 有 |  |  | 待标注 | 未测 | 取值：`AGE-SECRET-KEY`<br>约束：仅 x25519 与 mlkem768-x25519<br>约束：内容仅 age armor 格式<br>约束：核心不主动发送公钥，可在 header 设 X-Age-Public-Key |
| `exclude-filter` | 排除节点，` 分隔多个正则 | 有 |  |  | 待标注 | 未测 | 取值：`正则` |
| `exclude-type` | 按配置 type 排除，\| 分隔 | 有 |  |  | 待标注 | 未测 | 取值：`ss\|http` |
| `filter` | 筛选节点，` 分隔多个正则 | 有 |  |  | 待标注 | 未测 | 取值：`正则` |
| `header` | 请求头 | 有 |  |  | 待标注 | 未测 | 取值：`映射` |
| `health-check-enable` | 启用健康检查 | 有 |  |  | 待标注 | 未测 | 取值：`false`、`true` |
| `health-check-expected-status` | 期望状态码 | 有 |  |  | 待标注 | 未测 | 取值：`同 group.common.expected-status` |
| `health-check-interval` | 间隔秒 | 有 |  |  | 待标注 | 未测 | 取值：`整数` |
| `health-check-lazy` | 懒惰，默认 true | 有 |  |  | 待标注 | 未测 | 取值：`false`、`true` |
| `health-check-timeout` | 超时毫秒 | 有 |  |  | 待标注 | 未测 | 取值：`整数` |
| `health-check-url` | 健康检查地址 | 有 |  |  | 待标注 | 未测 | 取值：`https://cp.cloudflare.com`、`https://www.gstatic.com/generate_204` |
| `interval` | 更新间隔秒 | 有 |  |  | 待标注 | 未测 | 取值：`整数` |
| `name` | 必须，不能重复，建议不与策略组重名 | 有 |  |  | 待标注 | 未测 | 取值：`字符串` |
| `override-additional-prefix` | 节点名前缀 | 有 |  |  | 待标注 | 未测 | 取值：`字符串` |
| `override-additional-suffix` | 节点名后缀 | 有 |  |  | 待标注 | 未测 | 取值：`字符串` |
| `override-dialer-proxy` | 覆写 dialer-proxy | 有 |  |  | 待标注 | 未测 | 取值：`出站名` |
| `override-down` | 覆写 hysteria down | 有 |  |  | 待标注 | 未测 | 取值：`50 Mbps` |
| `override-interface-name` | 覆写接口 | 有 |  |  | 待标注 | 未测 | 取值：`接口名` |
| `override-ip-version` | 覆写 IP 版本 | 有 |  |  | 待标注 | 未测 | 取值：`dual`、`ipv4`、`ipv4-prefer`、`ipv6`、`ipv6-prefer` |
| `override-mptcp` | 覆写 mptcp | 有 |  |  | 待标注 | 未测 | 取值：`false`、`true` |
| `override-name-cert-verify` | 覆写校验名 | 有 |  |  | 待标注 | 未测 | 取值：`域名` |
| `override-override-expr` | yq v4 风格子集表达式覆盖，晚于固定字段 | 有 |  |  | 待标注 | 未测 | 取值：`表达式列表`<br>约束：不支持 as/$x、reduce、动态路径、递归下降<br>约束：不支持多文档、文件或环境访问<br>约束：函数限 length、keys、has、contains、select、reverse、sort、unique、flatten、any、all、map、map_values、filter、to_entries、from_entries、with_entries、any_c、all_c、test、sub、split、join、upcase、downcase、trim、tostring、tonumber、type、not<br>约束：每项须恰好产生一个 mapping |
| `override-proxy-name` | 节点名正则替换，pattern、target | 有 |  |  | 待标注 | 未测 | 取值：`列表` |
| `override-routing-mark` | 覆写路由标记 | 有 |  |  | 待标注 | 未测 | 取值：`整数` |
| `override-skip-cert-verify` | 覆写跳过验证 | 有 |  |  | 待标注 | 未测 | 取值：`false`、`true` |
| `override-tfo` | 覆写 tfo | 有 |  |  | 待标注 | 未测 | 取值：`false`、`true` |
| `override-udp` | 覆写 udp | 有 |  |  | 待标注 | 未测 | 取值：`false`、`true` |
| `override-udp-over-tcp` | 覆写 ss UoT | 有 |  |  | 待标注 | 未测 | 取值：`false`、`true` |
| `override-up` | 覆写 hysteria up | 有 |  |  | 待标注 | 未测 | 取值：`50 Mbps` |
| `path` | 可选，文件路径，不填用 url MD5 | 有 |  |  | 待标注 | 未测 | 取值：`路径`<br>约束：限制在 HomeDir；其他位置需 SAFE_PATHS |
| `payload` | inline 内容；http、file 解析失败时作备用 | 有 |  |  | 待标注 | 未测 | 取值：`列表` |
| `proxy` | 经指定代理下载 | 有 |  |  | 待标注 | 未测 | 取值：`出站名` |
| `size-limit` | 下载上限字节，0 不限 | 有 |  |  | 待标注 | 未测 | 取值：`整数` |
| `type` | 必须 | 有 |  |  | 待标注 | 未测 | 取值：`file`、`http`、`inline` |
| `url` | http 类型需配置 | 有 |  |  | 待标注 | 未测 | 取值：`URL` |
