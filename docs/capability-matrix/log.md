# 日志

由 `tools/capability_matrix.py build` 生成，不要手改。

## api

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `structured` | /logs?format=structured 输出 time、level、message、fields | 有 |  |  | 未实现 | 未测 | 取值：`structured` |

## config

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `disabled` | 禁用日志，启动后不输出日志。 |  | 有 |  | 未实现 | 未测 |  |
| `level` | 日志等级，可选值：`trace` `debug` `info` `warn` `error` `fatal` `panic`。 |  | 有 |  | 未实现 | 未测 | 取值：`debug`、`error`、`fatal`、`info`、`panic`、`trace`、`warn` |
| `output` | 输出文件路径，启动后将不输出到控制台。 |  | 有 |  | 未实现 | 未测 |  |
| `timestamp` | 添加时间到每行。 |  | 有 |  | 未实现 | 未测 |  |

## global

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `log-level` | 日志级别，仅在控制台和控制页面输出 | 有 |  |  | 未实现 | 未测 | 取值：`debug`、`error`、`info`、`silent`、`warning` |

## log

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `access` | 访问日志路径 |  |  | 有 | 部分 | 通过 | 取值：``、`none`、`文件路径`<br>约束：空输出 stdout；none 关闭 |
| `dns-log` | DNS 查询日志 |  |  | 有 | 部分 | 通过 |  |
| `error` | 错误日志路径 |  |  | 有 | 部分 | 通过 | 取值：``、`none`、`文件路径`<br>约束：空输出 stdout；none 关闭 |
| `loglevel` | 错误日志级别，默认 warning |  |  | 有 | 未实现 | 未测 | 取值：`debug`、`error`、`info`、`none`、`warning` |
| `mask-address` | IP 遮罩，默认不启用 |  |  | 有 | 部分 | 通过 | 取值：`/16+/32`、`full`、`half`、`quarter`<br>约束：/32、/128 不遮罩；/0 全遮<br>约束：自定义前 IPv4 后 IPv6，IPv4 须被 8 整除 |
