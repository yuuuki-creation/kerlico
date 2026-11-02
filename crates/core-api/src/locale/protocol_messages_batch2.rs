//! Shadowsocks 系列、Snell、TUIC、Trojan 与 VMess 的具体诊断。

pub(super) const DIAGNOSTICS: &[(&str, &str)] = &[
    ("AEAD 节点必须配置成员", "AEAD nodes must configure members"),
    (
        "QUIC节点任务异常退出",
        "A QUIC node task exited unexpectedly",
    ),
    (
        "QUIC节点强制清理未在期限内完成",
        "Forced cleanup of the QUIC node did not complete before the deadline",
    ),
    (
        "SS2022 必须使用独立 ss2022 模块",
        "SS2022 must use the separate ss2022 module",
    ),
    (
        "SSR UDP 需要同源口多目标访问服务",
        "SSR UDP requires multi-target access that retains one source port",
    ),
    (
        "SSR cipher 不在本轮范围",
        "The SSR cipher is outside the supported scope",
    ),
    (
        "SSR 出站未启用 UDP",
        "UDP is not enabled on the SSR outbound",
    ),
    (
        "SSR 原生凭据必须放在成员中",
        "SSR native credentials must be configured in members",
    ),
    (
        "SSR 必须显式设置 allow_insecure 以启用旧式兼容协议",
        "SSR requires an explicit allow_insecure setting to enable legacy compatibility protocols",
    ),
    ("SSR 成员凭据不合法", "Invalid SSR member credentials"),
    ("SSR 成员数量不合法", "Invalid SSR member count"),
    (
        "SSR 成员鉴别范围重复",
        "Duplicate SSR member authentication scopes",
    ),
    ("SSR 节点未启用 UDP", "UDP is not enabled on the SSR node"),
    (
        "ShadowTLS 出站尚未启动",
        "The ShadowTLS outbound has not started",
    ),
    (
        "ShadowTLS 出站重复启动",
        "The ShadowTLS outbound was started more than once",
    ),
    (
        "ShadowTLS 记录或认证不合法",
        "Invalid ShadowTLS record or authentication",
    ),
    (
        "ShadowTLS 配置不合法或组合未提供",
        "Invalid ShadowTLS configuration or unavailable combination",
    ),
    (
        "Shadowsocks password 为空或超过长度上限",
        "The Shadowsocks password is empty or exceeds the length limit",
    ),
    (
        "Shadowsocks 出站字段不合法",
        "Invalid Shadowsocks outbound fields",
    ),
    (
        "Shadowsocks 密码或方法不合法",
        "Invalid Shadowsocks password or method",
    ),
    (
        "Shadowsocks 成员凭据不合法",
        "Invalid Shadowsocks member credentials",
    ),
    (
        "Shadowsocks 成员密钥重复",
        "Duplicate Shadowsocks member keys",
    ),
    (
        "Shadowsocks 成员数量不合法",
        "Invalid Shadowsocks member count",
    ),
    (
        "Shadowsocks 报文认证或格式不合法",
        "Invalid Shadowsocks message authentication or format",
    ),
    (
        "Shadowsocks 方法不在支持范围",
        "The Shadowsocks method is outside the supported scope",
    ),
    (
        "Shadowsocks 流包装出站不提供原生 UDP",
        "A Shadowsocks stream-wrapper outbound does not provide native UDP",
    ),
    (
        "Shadowsocks 节点字段不合法",
        "Invalid Shadowsocks node fields",
    ),
    (
        "ShadowsocksR 参数、组合或资源限制不合法",
        "Invalid ShadowsocksR parameters, combination, or resource limits",
    ),
    (
        "ShadowsocksR 报文校验或握手不合法",
        "Invalid ShadowsocksR message verification or handshake",
    ),
    (
        "Snell UDP 需要业务目标的字面地址元数据",
        "Snell UDP requires literal-address metadata for the business target",
    ),
    (
        "Snell 报文认证或格式不合法",
        "Invalid Snell message authentication or format",
    ),
    ("Snell 配置不合法", "Invalid Snell configuration"),
    ("TUIC QUIC 握手失败", "The TUIC QUIC handshake failed"),
    (
        "TUIC UDP 写端已失效",
        "The TUIC UDP write half is no longer valid",
    ),
    ("TUIC udp_relay_mode 不合法", "Invalid TUIC udp_relay_mode"),
    (
        "TUIC v4 native 不支持超过 QUIC datagram MTU 的包",
        "TUIC v4 native mode does not support packets larger than the QUIC datagram MTU",
    ),
    (
        "TUIC 仅监听 QUIC UDP 载体",
        "TUIC only listens for QUIC UDP transports",
    ),
    (
        "TUIC 命令或分片格式不合法",
        "Invalid TUIC command or fragment format",
    ),
    (
        "TUIC 对端未启用 QUIC datagram",
        "The TUIC peer has not enabled QUIC datagrams",
    ),
    (
        "TUIC 节点需要多目标 UDP 关联出口",
        "TUIC nodes require a multi-target UDP association outbound",
    ),
    ("TUIC 配置不合法", "Invalid TUIC configuration"),
    ("TUIC载体已关闭", "The TUIC transport is closed"),
    (
        "TUIC连接任务异常退出",
        "A TUIC connection task exited unexpectedly",
    ),
    (
        "Trojan HTTP 任务状态失败",
        "The Trojan HTTP task state failed",
    ),
    ("Trojan HTTP 载体失败", "The Trojan HTTP transport failed"),
    (
        "Trojan HTTP 逻辑流退出失败",
        "The Trojan HTTP logical stream failed to exit",
    ),
    ("Trojan HTTPUpgrade 失败", "The Trojan HTTPUpgrade failed"),
    ("Trojan WS pong 失败", "The Trojan WebSocket pong failed"),
    ("Trojan WS 写入失败", "The Trojan WebSocket write failed"),
    ("Trojan WS 升级失败", "The Trojan WebSocket upgrade failed"),
    ("Trojan WS 帧失败", "The Trojan WebSocket frame failed"),
    ("Trojan gRPC Hunk 失败", "The Trojan gRPC Hunk failed"),
    ("Trojan gRPC 帧截断", "The Trojan gRPC frame is truncated"),
    (
        "Trojan gRPC 请求体失败",
        "The Trojan gRPC request body failed",
    ),
    (
        "Trojan 报文认证或格式不合法",
        "Invalid Trojan message authentication or format",
    ),
    (
        "Trojan 载体建立失败",
        "Could not establish the Trojan transport",
    ),
    ("Trojan 配置不合法", "Invalid Trojan configuration"),
    (
        "UDP 接收所有者异常退出",
        "The UDP receive owner exited unexpectedly",
    ),
    (
        "VMess HTTP 任务异常退出",
        "A VMess HTTP task exited unexpectedly",
    ),
    (
        "VMess HTTP 会话任务失败",
        "The VMess HTTP session task failed",
    ),
    ("VMess HTTP 载体失败", "The VMess HTTP transport failed"),
    ("VMess HTTPUpgrade 失败", "The VMess HTTPUpgrade failed"),
    (
        "VMess UDP 写端已失效",
        "The VMess UDP write half is no longer valid",
    ),
    (
        "VMess UDP 要求非空包且不超过 65456 字节",
        "VMess UDP requires nonempty packets no larger than 65456 bytes",
    ),
    (
        "VMess WebSocket 写入失败",
        "The VMess WebSocket write failed",
    ),
    (
        "VMess WebSocket 升级失败",
        "The VMess WebSocket upgrade failed",
    ),
    ("VMess WebSocket 帧错误", "Invalid VMess WebSocket frame"),
    (
        "VMess gRPC 不支持压缩",
        "VMess gRPC does not support compression",
    ),
    ("VMess gRPC 消息不合法", "Invalid VMess gRPC message"),
    ("VMess gRPC 消息截断", "The VMess gRPC message is truncated"),
    (
        "VMess gRPC 请求体失败",
        "The VMess gRPC request body failed",
    ),
    (
        "VMess 客户端配置不合法",
        "Invalid VMess client configuration",
    ),
    ("VMess 节点配置不合法", "Invalid VMess node configuration"),
    (
        "VMess 载体建立失败",
        "Could not establish the VMess transport",
    ),
    (
        "VMess 载体或 TLS 配置不合法",
        "Invalid VMess transport or TLS configuration",
    ),
    ("gRPC 长度失败", "The gRPC length check failed"),
    (
        "不支持压缩 gRPC 帧",
        "Compressed gRPC frames are not supported",
    ),
    (
        "已鉴权 SSR 必须配置成员",
        "Authenticated SSR must configure members",
    ),
    (
        "无鉴权 SSR 组合只允许本地接入",
        "Unauthenticated SSR combinations only permit local access",
    ),
    (
        "旧式 Shadowsocks 只允许无身份本地接入",
        "Legacy Shadowsocks only permits unauthenticated local access",
    ),
    (
        "旧式流方法或 none 必须显式允许不安全模式",
        "Legacy stream methods or none require an explicit opt-in to insecure mode",
    ),
    (
        "未启用 TLS 的 Trojan 仅允许回环服务器",
        "Trojan without TLS only permits loopback servers",
    ),
    (
        "未鉴权 SSR UDP 只能用作回环本地接入",
        "Unauthenticated SSR UDP can only be used for loopback local access",
    ),
    (
        "未鉴权 SSR 组合只能用作明确的回环本地接入",
        "Unauthenticated SSR combinations can only be used for explicit loopback local access",
    ),
    (
        "本地旧式 Shadowsocks 需要编码密码",
        "Local legacy Shadowsocks requires an encoded password",
    ),
    (
        "认证密码必须放在成员凭据中",
        "Authentication passwords must be placed in member credentials",
    ),
    (
        "载体后台任务异常退出",
        "A transport background task exited unexpectedly",
    ),
];
