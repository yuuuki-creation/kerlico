# 流控

由 `tools/capability_matrix.py build` 生成，不要手改。

## vision

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `vision` | XTLS Vision 流控，内层握手随机填充 |  |  | 有 | 已实现 | 通过 | 取值：`xtls-rprx-vision`、`xtls-rprx-vision-udp443` |
| `xtls-rprx-vision` | VLESS Vision 流控，入站配在 users.flow，出站配在 flow | 有 |  |  | 已实现 | 通过 | 取值：`xtls-rprx-vision`<br>约束：Meta 的 xtls-* 流控等效 Xray 的 xtls-*-udp443；拦截 443 UDP 需逻辑规则 AND,((NETWORK,UDP),(DST-PORT,443)),REJECT<br>约束：文档与 adapter/outbound/vless.go 均未写传输层限制 |
| `combo` | Vision 组合 |  |  | 有 | 已实现 | 通过 | side：`inbound`、`outbound`<br>value：``、`xtls-rprx-vision`、`xtls-rprx-vision-udp443`<br>transport：`raw`、`其他(需 Encryption)`<br>security：`encryption`、`reality`、`tls`<br>inner：`other`、`tls1.3`<br>约束：不支持 xdrive（source:infra/conf/xray.go）<br>约束：入站只接受 xtls-rprx-vision<br>约束：内层 TLS 1.3 才直接对拷<br>约束：出站接受 xtls-rprx-vision、xtls-rprx-vision-udp443<br>约束：只能配 TCP+TLS/REALITY，或 VLESS Encryption（无传输限制） |
| `splice` | Linux 下自动 Splice |  |  | 有 | 未实现 | 未测 | 约束：Linux<br>约束：入站为 Dokodemo、Socks、HTTP 等纯 TCP 或其他 XTLS 入站<br>约束：出站 VLESS+XTLS<br>约束：网速统计滞后到断开 |
| `udp443-block` | xtls-rprx-vision 拦截 UDP 443，-udp443 不拦截 |  |  | 有 | 已实现 | 通过 |  |

## vless

| 编号 | 说明 | Mihomo | sing-box | Xray | kerlico | 实测 | 取值与约束 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `addons` | 附加信息 Flow/Seed 由 ProtoBuf 承载 |  |  | 有 | 已实现 | 通过 |  |
| `xtls-rprx-vision` | VLESS Vision 流控 |  | 有 |  | 已实现 | 通过 | 取值：`xtls-rprx-vision`<br>约束：文档只列这一种 flow<br>约束：文档未写传输层限制，需实测 |
