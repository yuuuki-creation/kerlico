# Shadowsocks (AEAD / Legacy) 双端接口

更新日期：2026-11-02（Asia/Shanghai）。对应总表 P-03/P-05，验证结果见 [Shadowsocks 测试记录](../testing/shadowsocks.md)。本模块采用配置 v2 与全局共享 `Dispatcher`（`TargetPolicy::Remote`）；AEAD 节点成员凭据 `members[].native_credential` 格式为 `{"password": "<协议密码>"}`。无报文认证的旧式流密码与 `none`/`plain` 仅允许作为回环 `local_inbounds`（`Source::Local`，密码保留在 `options.password` 并需显式设置 `allow_insecure: true`）。

`kerlico-shadowsocks` 提供 `ShadowsocksFactory`、`ShadowsocksNodeFactory`，协议类型均为 `shadowsocks`。SS2022 使用独立的 `ss2022` 模块。

## 配置

出站 `options`：

```json
{"server":"127.0.0.1","port":8388,"method":"aes-128-gcm","password":"synthetic-shadowsocks-secret"}
```

节点 `options`：

```json
{"method":"aes-128-gcm"}
```

每个 IPv4/IPv6 节点独立配置，凭据隔离同时覆盖明文密码与实际派生 key，拒绝跨节点复用。非 `none` 密码不能为空，UTF-8 长度上限 4096 字节；未知字段（如 `plugin`、`transport`）直接拒绝。

## 支持方法范围

- **AEAD**：`aes-128-gcm`、`aes-256-gcm`、`chacha20-ietf-poly1305`、`aes-128-ccm`、`aes-256-ccm`、`aes-128-gcm-siv`、`aes-256-gcm-siv`、`xchacha20-ietf-poly1305`、`sm4-gcm`、`sm4-ccm`。
- **旧式流密码（仅 `local_inbounds` + `allow_insecure: true`）**：AES 与 Camellia 各自的 128/192/256 位 `ctr`、`cfb1`、`cfb8`、`cfb128`（含 `*-cfb` 别名）、`ofb`，以及 `chacha20-ietf`、`rc4-md5`、`rc4`、`table`。
- **明文模式（仅 `local_inbounds` + `allow_insecure: true`）**：`none`、`plain`。

## 数据、防重放与完成权契约

- **TCP**：出站在建立预算内拨号并发送目标首部，支持空首部写入（目标先发数据）与写端半关闭（`tcp_eof = true`）。服务端解码目标后调用 `PeerSession::connect_tcp` 并转发 `TcpFlow`。
- **UDP**：出站每个固定目标通道使用独立连接式 UDP Socket；服务端按来源地址与目标建立固定 UDP 通道（`PeerSession::connect_udp`），单关联配额 32 包有界队列。单包业务负载上限 65000 字节（线包上限 65507 字节），支持零字节空包。
- **防重放与完成权**：TCP 采用严格 salt 重放拒绝；UDP 解码成功后记录 salt/IV（有界缓存 65536 项、保留 120 秒）。固定 UDP 空闲记为 `Timeout`，取消记为 `Cancelled`，候选认证与目标任务均登记至 `NodeTasks`。
