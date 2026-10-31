# Shadowsocks AEAD、基础与旧式流密码接口

日期：2026-10-31。状态：本轮原生 TCP/UDP 双端已实现，通过完整方法自端矩阵和独立对端限定互通；精确范围见测试记录。

`kerlico-shadowsocks` 提供 `ShadowsocksFactory`、`ShadowsocksNodeFactory`，协议类型均为 `shadowsocks`。客户端与节点共用固定密码/加密依赖，但每个节点持有独立密码、重放缓存与访问服务。SS2022 继续使用 `ss2022`，本模块拒绝其方法名称。

## 配置

出站 options：

```json
{"server":"127.0.0.1","port":8388,"method":"aes-128-gcm","password":"synthetic-shadowsocks-secret"}
```

节点 options：

```json
{"method":"aes-128-gcm","password":"independent-node-secret"}
```

每个 IPv4/IPv6 节点单独配置，凭据指纹分别覆盖密码与实际派生 key；跨节点重用同密码或同一有效 key 由注册表拒绝。旧式流方法及 none 额外要求 `allow_insecure:true`。none/plain 没有认证，不返回空 key 的占位指纹，不能放入要求独立凭据的 `nodes`；使用明确的回环 `local_inbounds`，字段相同，不能用 password 字段获得认证。该配置接线增量已通过 worker 配置回归、严格 Clippy、正式 CLI 和 none 的 24 项独立对端复验；密码算法与数据路径未改。字段严格解析，未知 plugin、transport、users、identity_keys 等均拒绝。非 none 的密码不能为空，UTF-8 长度不超过 4096 字节。

## 本轮方法范围

- AEAD：aes-128-gcm、aes-256-gcm、chacha20-ietf-poly1305、aes-128-ccm、aes-256-ccm、aes-128-gcm-siv、aes-256-gcm-siv、xchacha20-ietf-poly1305、sm4-gcm、sm4-ccm。
- 旧式流：AES、Camellia 各自的 128/192/256 位 ctr、cfb1、cfb8、cfb128、ofb；另有 chacha20-ietf、rc4-md5、rc4、table。`*-cfb` 接受为 `*-cfb128` 别名。
- `none` 与 `plain` 是无加密模式别名。aes-192-gcm、未列方法拒绝。

以上为代码接受范围，验收结果按[测试记录](../testing/shadowsocks.md)逐项登记。旧式流密码没有报文认证，重放检查不会改变这一性质；rc4/table 与 none 没有随机 nonce，不能提供有效 nonce 重放保护。

## 数据与资源语义

TCP 出站在建立预算内解析代理地址、拨号并发送目标首部；返回时不代表远端目标已确认成功。空首部写入允许目标主动先发数据，保留写端 EOF 和反向排空。服务端解码目标后调用统一 `AccessService::connect_tcp`；公网默认 IPv4 优先的目标策略由服务提供方负责。

UDP 出站每个固定目标通道使用独立连接式 UDP socket；源地址由内核限制为配置节点，返回报文还检查目标地址/端口。域名请求允许返回解析后的 IP。服务端按来源地址和目标分别建立关联，通过 `AccessService::connect_udp` 访问目标。每个关联占节点和全局预算、32 包有界队列，空闲后回收；取消与关闭有时间上限。

最大业务包 65000 字节，线包不超过 65507 字节；零长度业务包与通道关闭不同。异常认证或目标格式无效的 UDP 包整包丢弃。TCP 上游重放策略设为 Reject；UDP 在成功解码后记录 salt/IV，缓存最多 65536 项、保留 120 秒，未过期满额时拒绝新 nonce。该有限窗口不是永久重放防护。

本轮不实现 SIP003 插件、SS over WS/TLS/REALITY、UoT、sing-mux、多用户 relay 或 SSR；不能机械套用 VLESS 组合。
