# Mieru 双端接口

日期：2026-10-31。状态：原生双端、21 项 Rust 测试、config 3 项回归、严格 Clippy/格式/CLI 通过；两版官方 API 与原 Mihomo 的限定矩阵已验，包长和本地 UDP 风险分别记录于 `docs/testing/mieru.md`。类型名 `mieru`，导出 `MieruFactory` / `MieruNodeFactory`。调研及已复现的原 UDP 密码学限制见 `reference/research_notes/mieru.md`。

## 客户端出站

```json
{
  "server": {"host": "127.0.0.1", "port": 10443},
  "username": "node-user",
  "password": "synthetic-password",
  "transport": "tcp",
  "multiplexing": true,
  "no_wait": false,
  "max_sessions": 128,
  "idle_timeout_secs": 60,
  "mtu": 1400,
  "traffic": {"low_entropy_mode": 0, "mask_rotation": 0, "max_padding": 32}
}
```

默认载体为 TCP；它使用 Mieru 自身的 XChaCha20-Poly1305、时间密钥、分段与逻辑会话，不附加 WS/TLS/QUIC 等其他协议载体。可传输 TCP 及 Full Cone UDP 包隧道。`tcp_eof=false`：官方关闭语义是完整会话关闭，不能独立关闭写方向并继续等待新反向数据；需要 `require_remote_eof` 的固定入口在准备阶段拒绝。

用户名按 UTF-8 字节计为 1–64，密码为 1–4096 字节，两者拒绝 NUL。大小写与其他字符按原字节参与密钥派生。没有代理载体的 SNI、证书或 TLS 恢复配置。TCP 的服务器域名有界解析，优先 IPv4 首个候选，握手失败不自动换地址、凭据或另一节点。网站目标解析仍由统一出口处理。

`multiplexing=true` 在实例独立的物理载体内复用逻辑会话；false 每会话使用独立载体。`no_wait=true` 延迟到首次应用写入才发请求，并提前返回流；接入 TCP 成功不代表凭据或目标已通过，错误通过后续读/flush 返回，先读会等待首次写入。初始握手仍受预算约束，不提供无限闲置的未认证连接或 0-RTT 票据。

客户端 `max_sessions` 范围 1–128，空闲秒数 1–600，MTU 576–1500；MTU 只用于 UDP 兼容载体的发段上限，不把 TCP 限为该长度。每实例最多保留 128 个物理载体，创建超过 120 秒的载体不再增加新逻辑会话，已有会话继续使用原选定密钥。没有跨实例/节点共享密码连接池。

## TCP 服务端节点

`nodes` 条目采用如下 `options`：

```json
{
  "users": [{"username": "node-user", "password": "synthetic-password"}],
  "transport": "tcp",
  "user_hint_required": true,
  "traffic": {"low_entropy_mode": 0, "mask_rotation": 0, "max_padding": 32}
}
```

单用户也可用顶层 `username/password`，与 `users` 互斥；用户数 1–256，同节点不允许重复用户名。物理 TCP 与额外逻辑会话分别占用全局/节点预算。每次新会话先校验完整段、方向、时间、ID 和负载，再经 `AccessService` 处理精简 SOCKS 请求。TCP 目标实际建立后才发送成功回应；UDP Associate 使用 `DatagramAssociation`，缺少 Full Cone 能力的出口在准备阶段拒绝，不隐式降级或绕过出口。

鉴权与配置隔离分开：TCP 鉴权集合包含基于真实 `SHA256(password || 00 || username)` 基础秘密的指纹；隔离集合同时包含 `mieru` 基础秘密域与 `mieru-user` 用户名域。因此同名不同密码会按身份规则拒绝，相同实际凭据跨载体也会拒绝；不同身份的基础秘密因用户名参与而分别派生。IPv4/IPv6 节点分别配置身份与地址，不能把用户名指纹说成时间密钥或秘密指纹。

TCP 首 nonce 的内存重放表最多 16384 条，保留 360 秒；完整解密及合法首次打开之后才记录，未到期容量满时拒绝新增。重启不保留该内存表。实际元数据接受当前分钟前后各 1 分钟，客户端/服务端需要相符的系统时钟。时间密钥更新不等于已实现前向保密或密码学审计。

## 仅本机的旧 UDP 载体

原协议在一个 UDP 段中对元数据和负载复用同一 key/nonce，已由两个固定官方版本的独立探针复现已知明文异或关系。故公网 UDP 载体**未支持**；密码字段和成功互通不构成可靠鉴权保证。

本地兼容用途必须使用 `local_inbounds`，例如：

```json
{
  "tag": "local-compatibility",
  "type": "mieru",
  "listen": "127.0.0.1:11443",
  "outbound": "direct",
  "options": {
    "username": "local-user",
    "password": "different-synthetic-password",
    "transport": "udp",
    "unsafe_udp_compatibility": true
  }
}
```

该模式返回空鉴权集合、强制回环，并仍以隔离集合阻止复用其他 Mieru TCP/UDP 条目的秘密或用户名。即使 `nodes` 监听回环，也不能放入其中。出站同样要求显式标志及服务器为 IP 字面量回环；`localhost`、其他域名、非回环、IPv4-mapped IPv6 均拒绝。运行时再次核对 socket。TCP 带不安全 UDP 标志或一条配置混用两载体均拒绝；不修改官方 nonce/key 规则伪造兼容。此去重针对同一配置内的接入条目，不能检查其他进程或手填出站的秘密；本地兼容模式仍须使用独立于公网的凭据。

本地模式保留完整 UDP 线格式、会话、累积 ACK、有限窗口、乱序和重复抑制、RTO/快速重传与关闭回应墓碑。发送窗口为有界加性增大/乘性减小，没有提供名为 CUBIC/BBR 的无效开关，也没有性能结论。每次重传重新生成该段 nonce；这不修复同段内的既有复用问题。

## 数据与资源边界

UDP Associate 每包携带目标/来源，域名经统一出口解析并默认优先 IPv4；同一关联保持一个出口 socket、支持跨目标/地址族和未先联系来源。固定 UDP 通道只接受统一出口已经解析的 IP 目标，并过滤其他来源；多目标或域名使用关联接口，不在客户端私自解析网站地址。

UDP 负载最多 65507 字节，另受节点上限及“地址+负载”不超过 65535 字节限制；长域名可能降低可容纳负载。空 UDP 包合法，包隧道有独立长度/标记，不以空包表示 EOF。读取或写入在半帧处取消后，该方向失效，不得继续拼接新包或重试半帧。

每载体活动逻辑会话最多 128，累计 ID 最多 8192，不复用已退役 ID；预算可能进一步收紧。每逻辑待交付原字节上限 256 KiB，另有 32 KiB 双工缓冲与固定复制槽。TCP 待发队列最多 512 段/8 MiB，串行写端有界；慢逻辑流超过限额只关闭相应会话，不重置其他流的 nonce。帧首字节到达后按建立预算读完整帧，热队列也执行期限与回收。

UDP 兼容模式乱序缓冲最多 128 段、向对端通告的接收窗口最多 32 段，待发/未 ACK 最多 512 段；每段发送次数上限 20，RTO 100 ms–3 秒、退避最高 5 秒，ACK 与关闭控制不受数据零窗口阻塞。关闭墓碑最多 8192、360 秒，不持有网站 socket 或逻辑预算。源地址与身份固定，不做跨地址迁移。模块仅为自己持有的 UDP socket 请求 2 MiB 接收缓冲，受系统上限限制，不修改全局 sysctl；通告窗口保留内核 skb 与共享载体余量。

`traffic.low_entropy_mode` 为 0/1/2/3/4，分别关闭或使用 32/40/48/56 模式；`mask_rotation` 为 0、右旋 1–15 或左旋 16 的 1–15 倍，mode=0 时只能为 0。四种模式及填充均为流量编码，不是额外加密。未知字段、旧 v2、端口范围/漫游、任意固定 nonce、管理面、热重载、指纹和其他载体均没有交付。
