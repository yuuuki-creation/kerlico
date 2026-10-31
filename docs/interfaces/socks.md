# SOCKS 接口

日期：2026-10-31。首轮代码已编写，尚未完成 worker 编译和互通验收。

`protocol-socks` 注册 `socks` 入站节点与出站。`version` 为字符串 `4`、`4a`、`5`，默认 `5`。三版本实现 CONNECT；5 另实现 UDP Associate，4/4a 不声明 UDP。BIND、GSSAPI、UDP 分片重组不支持。

出站选项：`server: {host, port}`、`version`、可选 `auth: {username, password}`、4/4a 的可选 `userid`。节点选项相同，但不含 `server`。未知字段、版本冲突、空或超过 255 字节的认证字段拒绝。配置与凭据不写入错误消息。节点接入后通过统一 AccessService 访问目标，不直接创建目标连接。

SOCKS5 有认证时只协商用户名密码，没有认证时只协商无认证，禁止失败后降级。认证指纹参与同协议跨节点去重。`nodes` 中的服务端仍必须有独立认证；无认证 SOCKS5 与 SOCKS4/4a 使用单独的 `local_inbounds` 数组，字段与节点相同但必须回环监听，不能注册为公网节点。userid 不是安全认证。SOCKS5 用户名密码在线路上明文传输。

SOCKS4 的域名目标在客户端解析为 IPv4；4a 在代理端解析。5 支持 IPv4、IPv6 与域名，解析交给目标访问服务。接入地址族不限制目标地址族。

SOCKS5 出站根据服务端实际返回的 UDP relay 地址绑定 socket，TCP 控制地址族不限制 relay 的地址族；域名 relay 优先控制连接的地址族，没有对应地址时允许另一族。独立 IPv4 控制/IPv6 relay 回归已在 worker 通过。控制关联及目标通道的空闲时间由成功业务读写推进，非法包不续期；持续单向发送保持原目标通道，更新活动计时不取消已开始的目标接收 future。

SOCKS5 UDP 由 TCP 控制连接动态创建同地址族 UDP 端口，TCP 断开即回收关联。节点依赖 InboundContext 的物理 peer_addr/local_addr 以校验 UDP 来源 IP；指定端口时固定来源端口，否则固定首个合法包的来源端口。每个目标独立建立通道并取得共享资源名额；最大目标数、负载长度、空闲、取消和关闭受现有预算限制。非零 FRAG、错误来源和无效包整包丢弃。出站每个通道固定目标，控制连接关闭后接收返回 None。UDP 载荷可以为空，封装总长不得超过 65507 字节。

当前 AccessService 不暴露目标 socket 本地地址，CONNECT 回复的 BND.ADDR/BND.PORT 为零；UDP Associate 回复实际绑定地址与端口。TCP 保留写端 EOF 与反向排空。握手与目标建立各自受 connect_timeout 限制，成功后的转发受 idle_timeout 和取消约束。

研究与验收矩阵见[研究记录](../../reference/research_notes/socks.md)，实际结果见[测试记录](../testing/socks.md)。
