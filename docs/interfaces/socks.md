# SOCKS 双端接口

更新日期：2026-11-02（Asia/Shanghai）。验证结果见 [SOCKS 测试记录](../testing/socks.md)。本模块采用配置 v2 与全局共享 `Dispatcher`（`TargetPolicy::Remote`）；SOCKS5 节点成员凭据 `members[].native_credential` 格式为 `{"username": "<用户名>", "password": "<协议密码>"}`（RFC 1929 命中行决定管理用户），节点 `options` 仅保留 `version` 与 `userid`。SOCKS4/4a 与无认证 SOCKS5 仅作为回环 `local_inbounds`（`Source::Local`）。

`protocol-socks` 注册 `socks` 入站节点与出站。`version` 为字符串 `4`、`4a`、`5`，默认 `5`。三版本实现 CONNECT；5 另实现 UDP Associate，4/4a 不声明 UDP。BIND、GSSAPI、UDP 分片重组不支持。

出站选项：`server: {host, port}`、`version`、可选 `auth: {username, password}`、4/4a 的可选 `userid`。节点选项只含 `version` 与 `userid`；认证取自外层 `members`。未知字段、版本冲突、空或超过 255 字节的认证字段拒绝。节点接入后通过统一 `PeerSession` 访问目标。

SOCKS5 有认证时只协商用户名密码，没有认证时只协商无认证，禁止失败后降级。`nodes` 中的服务端必须配置独立认证；无认证 SOCKS5 与 SOCKS4/4a 使用单独的 `local_inbounds` 数组（必须回环监听）。SOCKS5 用户名密码在线路上明文传输。

SOCKS4 仅接受 IPv4 字面目标，域名和 IPv6 明确拒绝；4a 将域名交给代理端解析。5 支持 IPv4、IPv6 与域名。接入地址族不限制目标地址族。

SOCKS5 出站根据服务端实际返回的 UDP relay 地址绑定 socket，TCP 控制地址族不限制 relay 的地址族；域名 relay 优先控制连接的地址族，没有对应地址时允许另一族。控制关联及目标通道的空闲时间由成功业务读写推进，非法包不续期；持续单向发送保持原目标通道，更新活动计时不取消已开始的目标接收 future。

SOCKS5 出站提供固定 UDP 和 `DatagramAssociation`，SOCKS4/4a 均不提供 UDP。入站 TCP 不要求所选出站具有关联能力；收到 `UDP_ASSOCIATE` 时才检查，只有固定 UDP 或没有 UDP 的出站返回命令不支持。

SOCKS5 UDP 由 TCP 控制连接动态创建同地址族 UDP 端口，TCP 断开即回收关联。节点依赖 `InboundContext` 的物理 `peer_addr`/`local_addr` 校验 UDP 来源 IP；指定端口时固定来源端口，否则固定首个合法包的来源端口。整个控制连接只建立一个业务 `UdpAssociation` 并固定命名出站，多个目标沿用同一关联及可信成员。非零 `FRAG`、错误来源和无效包整包丢弃。UDP 载荷可以为空，封装总长不得超过 65507 字节。

## 完成权与绑定元数据

- CONNECT 从 `TcpFlow.info()` 取得 `TargetBind`：已知绑定保留 `LocalSocket` 或 `PeerReported` 证据；未知绑定仅在线格式使用兼容零回复，内部保持 `Unknown`。SOCKS4 仅编码可表示的 IPv4 绑定，其余情况使用兼容占位。SOCKS5 上游真实 IPv4、IPv6、域名 `BND` 原样保留，零端口或未指定 IP 归为未知。
- `UDP ASSOCIATE` 返回实际监听地址；成功回复写失败先报告失败，TCP 控制连接正常结束记为关联 `ProtocolEnd`，空闲超时记为 `Timeout`。
