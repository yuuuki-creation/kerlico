# VMess AEAD 双端接口

日期：2026-10-31。状态：限定双端已通过远端包级检查及真实对端矩阵，精确范围见[验证记录](../testing/vmess.md)。工厂类型均为 `vmess`，客户端与服务端分别注册。

## 客户端

```json
{
  "server": {"host": "127.0.0.1", "port": 10443},
  "uuid": "00000000-0000-4000-8000-000000000001",
  "security": "aes-128-gcm",
  "tls": {"type": "tls", "server_name": "node.invalid", "ca_pem": "PEM 内容"},
  "transport": {"type": "tcp"},
  "chunk_masking": true,
  "global_padding": true,
  "authenticated_length": false,
  "no_termination_signal": false
}
```

`security` 接受 `auto`、`aes-128-gcm`、`chacha20-poly1305`；当前 `auto` 明确选择 AES-128-GCM。它是 VMess 内容算法，外层安全由 `tls` 配置，缺省为 `{"type":"none"}`。TLS 始终校验证书和名称，不提供 insecure 开关。未识别字段、非法 UUID、未知 cipher 和 padding 未启用 mask 均拒绝。

`transport` 缺省为 `{"type":"tcp"}`，另有 `{"type":"ws","path":"/proxy","host":"node.invalid"}`、`{"type":"httpupgrade","path":"/proxy"}`、`{"type":"grpc","service_name":"proxy","authority":"node.invalid","multi_mode":false}`。WS/HTTPUpgrade 使用 H1，gRPC 使用 H2。Xray 两方向已验证这些载体与 none/TLS、两种 cipher 的限定矩阵；sing-box 目前仅登记 RAW 真实互通。

建立预算覆盖载体建立与请求头发送。返回流时服务端响应头仍延迟校验，不能据此声称目标已接纳。每个会话有独立随机 key/IV 和计数器；耗尽后结束，禁止复用 nonce。

## 服务端

```json
{
  "users": [
    {"uuid": "00000000-0000-4000-8000-000000000001"},
    {"uuid": "00000000-0000-4000-8000-000000000002"}
  ],
  "security": {"type": "tls", "certificate_file": "node.crt", "private_key_file": "node.key"},
  "transport": {"type": "tcp"}
}
```

单用户可用 `uuid` 代替 `users`，两者互斥。用户数为 1–256，节点内重复 UUID 拒绝，跨同协议节点的凭据指纹由注册表拒绝。IPv4/IPv6 节点各自配置，不回退认证。TLS 证书与密钥可分别使用 `certificate_pem`、`private_key_pem` 内存值，内存与文件选项互斥，文件上限 1 MiB。

认证要求 AEAD 版本 1、合法 FNV1a、合法地址/端口与内容算法；AuthID 时差限 ±120 秒，AuthID 及用户/key/IV 会话身份分别防重放。节点有界缓存最多保留 65536 项，每项保留 300 秒；满额时拒绝新请求，不淘汰仍有效项。目标访问发生在认证之后，通过注入的 `AccessService`；节点入口地址族不决定网站地址族。

## 数据能力与边界

TCP 默认支持写端终止记录和继续读取反向数据；开启 `no_termination_signal` 后不声明目标 EOF 能力。UDP 为 VMess command 2 的固定目标记录，不是物理 UDP 监听；每次 send/read 保留一个包，本模块上限 65456 字节；真实对端实测范围为 Xray 17/1200 字节、sing-box 17/1200/12000 字节，另测的 Xray 12000/65000 字节及 sing-box 65000 字节未通过整包互通。空包与终止记录无法区分，因此发送空包明确报错。服务端另遵守引擎 `max_datagram_size`。数据报发送中被取消后，该写端失效，不重新发送可能已经发出部分的记录。

本轮不提供旧 MD5/alterId、CFB/none/zero、Vision、VLESS Encryption、REALITY、XHTTP、mKCP、旧 h2/http、QUIC transport、Mux/XUDP，未知选项拒绝；这些仍属于尚未交付范围。节点协议只声明 TCP 监听，由载体承载流与包。
