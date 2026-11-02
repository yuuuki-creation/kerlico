pub(super) const DIAGNOSTICS: &[(&str, &str)] = &[
    ("配置不合法：", "Invalid configuration: "),
    ("协议错误：", "Protocol error: "),
    ("不支持的能力：", "Unsupported capability: "),
    ("网络 I/O 失败：", "I/O failed: "),
    ("地址或端口不合法", "Invalid address or port"),
    ("操作超时", "Operation timed out"),
    ("操作已取消", "Operation cancelled"),
    ("连接被策略拒绝", "Connection rejected by policy"),
    ("资源达到上限", "Resource limit reached"),
    ("HTTP DATA流失败", "HTTP DATA stream failed"),
    (
        "HTTP QUIC UDP状态不可用",
        "HTTP QUIC UDP state is unavailable",
    ),
    ("IP分片状态已损坏", "IP fragment state is corrupted"),
    (
        "IP数据面MTU或允许范围不合法",
        "Invalid IP data plane MTU or allowed range",
    ),
    (
        "IP数据面不提供该协议",
        "The IP data plane does not support this protocol",
    ),
    (
        "IP数据面允许范围不能重复或重叠",
        "IP data plane allowed ranges must not overlap or repeat",
    ),
    ("IP节点状态已损坏", "IP node state is corrupted"),
    (
        "IP节点需要多目标UDP出站",
        "IP nodes require an outbound with multi-target UDP support",
    ),
    (
        "WARP单次注册入口要求空状态",
        "One-time WARP registration requires empty state",
    ),
    (
        "WARP复用模式要求已有profile，禁止自动注册",
        "WARP reuse requires an existing profile; automatic registration is prohibited",
    ),
    (
        "WARP已有结果未知的注册意图，禁止自动重复注册",
        "A WARP registration intent has an unknown outcome; automatic re-registration is prohibited",
    ),
    (
        "WARP注册响应不符合固定WireGuard profile",
        "The WARP registration response does not match the fixed WireGuard profile",
    ),
    (
        "WARP状态目录须有可信祖先、私有权限及唯一写者",
        "The WARP state directory requires trusted ancestors, private permissions, and a single writer",
    ),
    (
        "WARP现有profile与持久私钥不匹配，禁止注册或启动",
        "The existing WARP profile does not match the stored private key; registration and startup are prohibited",
    ),
    (
        "WARP私有状态验证尚未实现此平台",
        "Private WARP state validation is not implemented on this platform",
    ),
    (
        "WARP需要原生载体路由",
        "WARP requires a native carrier route",
    ),
    (
        "WARP需要至少一个原生载体地址族",
        "WARP requires at least one native carrier address family",
    ),
    ("WireGuard出站运行失败", "The WireGuard outbound failed"),
    ("WireGuard载体运行失败", "The WireGuard carrier failed"),
    ("ZeroTier出站运行失败", "The ZeroTier outbound failed"),
    ("ZeroTier载体运行失败", "The ZeroTier carrier failed"),
    ("ZeroTier出站字段不合法", "Invalid ZeroTier outbound fields"),
    (
        "ZeroTier网络ID必须是16位十六进制，且不能是临时网络",
        "The ZeroTier network ID must be 16 hexadecimal digits and not an ad-hoc network",
    ),
    (
        "ZeroTier身份必须且只能配置identity或identity_file之一",
        "Configure exactly one of the ZeroTier identity or identity_file",
    ),
    ("ZeroTier身份格式不合法", "Invalid ZeroTier identity format"),
    (
        "ZeroTier身份缺少私钥",
        "The ZeroTier identity has no secret key",
    ),
    (
        "ZeroTier身份未通过工作量校验",
        "A ZeroTier identity failed its proof-of-work check",
    ),
    (
        "ZeroTier身份文件读写失败",
        "Could not read or write the ZeroTier identity file",
    ),
    (
        "ZeroTier至少需要一个根节点或能直达控制器的对端",
        "ZeroTier needs at least one root or a direct peer entry for the controller",
    ),
    (
        "ZeroTier种子节点配置不合法",
        "Invalid ZeroTier root or peer entry",
    ),
    (
        "ZeroTier载体绑定地址不合法",
        "Invalid ZeroTier carrier bind address",
    ),
    (
        "统计历史写者异常退出",
        "The statistics history writer exited unexpectedly",
    ),
    (
        "统计历史最终提交失败",
        "The final statistics history commit failed",
    ),
    (
        "设备准备期限须在120秒内",
        "The device preparation timeout must be positive and at most 120 seconds",
    ),
    ("设备后端关闭失败", "Device backend shutdown failed"),
    (
        "设备状态写者不可用",
        "The device state writer is unavailable",
    ),
    ("WARP准备失败：", "WARP preparation failed: "),
    (
        "WARP准备超时，注册意图保留",
        "WARP preparation timed out; the registration intent is retained",
    ),
    ("WARP注册HTTP状态", "WARP registration HTTP status "),
    (
        "；保留注册意图，不自动重试",
        "; the registration intent is retained without automatic retry",
    ),
];
