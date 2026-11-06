# Shadowsocks (AEAD / Legacy) 双端接口

更新日期：2026-11-04（Asia/Shanghai）。对应总表 P-03/P-05，验证结果见 [Shadowsocks 测试记录](../testing/shadowsocks.md)。本模块采用配置 v2 与全局共享 `Dispatcher`（`TargetPolicy::Remote`）；AEAD 节点成员凭据 `members[].native_credential` 格式为 `{"password": "<协议密码>"}`。无报文认证的旧式流密码与 `none`/`plain` 仅允许作为回环 `local_inbounds`（`Source::Local`，密码保留在 `options.password` 并需显式设置 `allow_insecure: true`）。

`kerlico-shadowsocks` 提供 `ShadowsocksFactory`、`ShadowsocksNodeFactory`，协议类型均为 `shadowsocks`。SS2022 使用独立的 `ss2022` 模块。

## 配置

出站 `options`（可选启用 `udp_over_tcp` / `udp_over_tcp_version` UoT v1/v2 与 `multiplex` 通用 `sing-mux` 多路复用，见 [sing-mux](sing-mux.md)）：

```json
{"server":"127.0.0.1","port":8388,"method":"aes-128-gcm","password":"synthetic-shadowsocks-secret","udp_over_tcp":true,"udp_over_tcp_version":2}
```

节点 `options`（可选启用 `multiplex` 与 `mux_option_padding` 接纳 `sing-mux` 复用流，并自动识别 `sp.udp-over-tcp.arpa` 与 `sp.v2.udp-over-tcp.arpa` UoT 请求）：

```json
{"method":"aes-128-gcm","multiplex":{"enabled":true,"padding":false}}
```

每个 IPv4/IPv6 节点独立配置，凭据隔离同时覆盖明文密码与实际派生 key，拒绝跨节点复用。非 `none` 密码不能为空，UTF-8 长度上限 4096 字节；出站可选配置 `plugin` 与 `plugin-opts` / `plugin-opts-*` 插件参数，其余未知字段直接拒绝。

内建插件（客户端）：

- `obfs` / `obfs-local` / `simple-obfs`：仅 `mode: http`，参数 `host`、`path`（别名 `obfs-host`、`obfs-uri`）。首包附加 HTTP 请求头，剥离首个 HTTP 响应头。
- `v2ray-plugin` / `gost-plugin`：仅 `mode: websocket`，参数 `host`、`path`、`tls`、`headers`、`v2ray-http-upgrade`。默认 RFC 6455 WebSocket，负载按二进制帧收发；`v2ray-http-upgrade` 改用 HTTP Upgrade 原始流并要求 101 响应；`tls` 在同一条 TCP 连接上以 `host`（缺省为服务器地址）做 SNI 并校验证书。

其他插件名（`kcptun`、`restls`、`jls`、`shadow-tls` 等）、`obfs` 的 `tls` 模式，以及 `mux`、`skip-cert-verify`、`fingerprint`、`ech`、`v2ray-http-upgrade-fast-open` 或任何未列出的参数，在配置编译期报错，不会退回明文 TCP。

## 支持方法范围

- **AEAD**：`aes-128-gcm`、`aes-256-gcm`、`chacha20-ietf-poly1305`、`aes-128-ccm`、`aes-256-ccm`、`aes-128-gcm-siv`、`aes-256-gcm-siv`、`xchacha20-ietf-poly1305`、`sm4-gcm`、`sm4-ccm`。
- **旧式流密码（仅 `local_inbounds` + `allow_insecure: true`）**：AES 与 Camellia 各自的 128/192/256 位 `ctr`、`cfb1`、`cfb8`、`cfb128`（含 `*-cfb` 别名）、`ofb`，以及 `chacha20-ietf`、`rc4-md5`、`rc4`、`table`。
- **明文模式（仅 `local_inbounds` + `allow_insecure: true`）**：`none`、`plain`。

## 数据、防重放与完成权契约

- **TCP**：出站在建立预算内拨号并发送目标首部，支持空首部写入（目标先发数据）与写端半关闭（`tcp_eof = true`）。服务端解码目标后调用 `PeerSession::connect_tcp` 并转发 `TcpFlow`。
- **UDP**：出站每个固定目标通道使用独立连接式 UDP Socket；服务端按来源地址与目标建立固定 UDP 通道（`PeerSession::connect_udp`），单关联配额 32 包有界队列。单包业务负载上限 65000 字节（线包上限 65507 字节），支持零字节空包。
- **防重放与完成权**：TCP 采用严格 salt 重放拒绝；UDP 解码成功后记录 salt/IV（有界缓存 65536 项、保留 120 秒）。固定 UDP 空闲记为 `Timeout`，取消记为 `Cancelled`，候选认证与目标任务均登记至 `NodeTasks`。
