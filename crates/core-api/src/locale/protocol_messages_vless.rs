//! VLESS、安全层、复用与存储载体的具体诊断。

pub(super) const DIAGNOSTICS: &[(&str, &str)] = &[
    (
        "Encryption 写端仍被占用",
        "The Encryption write half is still in use",
    ),
    (
        "Encryption 状态不可用",
        "The Encryption state is unavailable",
    ),
    ("HTTP/3 TLS 配置不合法", "Invalid HTTP/3 TLS configuration"),
    ("HTTP/3 trailers 失败", "HTTP/3 trailers failed"),
    ("HTTP/3 上传失败", "HTTP/3 upload failed"),
    ("HTTP/3 下载失败", "HTTP/3 download failed"),
    ("HTTP/3 响应头失败", "HTTP/3 response headers failed"),
    ("HTTP/3 结束失败", "HTTP/3 finalization failed"),
    ("HTTP/3 节点必须提供 TLS", "HTTP/3 nodes must provide TLS"),
    ("HTTP/3 请求接收失败", "HTTP/3 request reception failed"),
    (
        "HTTP/3 连接初始化失败",
        "HTTP/3 connection initialization failed",
    ),
    ("Mux UDP 任务异常退出", "A Mux UDP task exited unexpectedly"),
    (
        "Mux 会话任务异常退出",
        "A Mux session task exited unexpectedly",
    ),
    ("Mux 会话已结束", "The Mux session has ended"),
    ("Mux 会话编号重复", "Duplicate Mux session number"),
    ("Mux 会话表不可用", "The Mux session table is unavailable"),
    ("Mux 元数据长度不合法", "Invalid Mux metadata length"),
    ("Mux 回包写入失败", "Could not write the Mux reply"),
    (
        "Mux 完成权状态损坏",
        "The Mux completion owner state is corrupted",
    ),
    ("Mux 对端拒绝会话", "The Mux peer rejected the session"),
    (
        "Mux 对端拒绝数据报会话",
        "The Mux peer rejected the datagram session",
    ),
    ("Mux 帧不完整", "The Mux frame is incomplete"),
    ("Mux 帧存在额外数据", "The Mux frame contains extra data"),
    (
        "Mux 并发或连接池参数不合法",
        "Invalid Mux concurrency or connection pool parameters",
    ),
    ("Mux 建立失败", "Could not establish Mux"),
    ("Mux 数据报会话失败", "The Mux datagram session failed"),
    ("Mux 载体中断", "The Mux transport was interrupted"),
    ("Mux 载体写入失败", "Could not write to the Mux transport"),
    ("Mux 载体已结束", "The Mux transport has ended"),
    ("Mux 连接池不可用", "The Mux connection pool is unavailable"),
    ("Mux 配置不可用", "The Mux configuration is unavailable"),
    ("QUIC 握手失败", "The QUIC handshake failed"),
    ("QUIC 空闲预算不合法", "Invalid QUIC idle time budget"),
    (
        "REALITY ClientFinished 校验失败",
        "REALITY ClientFinished verification failed",
    ),
    (
        "REALITY 不支持 WS 或 HTTPUpgrade",
        "REALITY does not support WebSocket or HTTPUpgrade",
    ),
    ("REALITY 客户端已结束", "The REALITY client has ended"),
    (
        "REALITY 密钥、名称或 short ID 不合法",
        "Invalid REALITY key, name, or short ID",
    ),
    (
        "REALITY 证书身份生成失败",
        "Could not generate the REALITY certificate identity",
    ),
    (
        "REALITY 身份或时间参数超出范围",
        "REALITY identity or time parameters are out of range",
    ),
    ("REALITY 配置不合法", "Invalid REALITY configuration"),
    (
        "REALITY 重放状态不可用",
        "The REALITY replay state is unavailable",
    ),
    (
        "VLESS Encryption 参数不合法",
        "Invalid VLESS Encryption parameters",
    ),
    (
        "VLESS Encryption 握手失败",
        "The VLESS Encryption handshake failed",
    ),
    (
        "VLESS decryption 参数不合法",
        "Invalid VLESS decryption parameters",
    ),
    (
        "VLESS decryption 密钥链、票据使用期或 padding 超出当前范围",
        "The VLESS decryption key chain, ticket lifetime, or padding is outside the supported range",
    ),
    (
        "VLESS decryption 超过长度限制",
        "VLESS decryption exceeds the length limit",
    ),
    (
        "VLESS 传输或安全选项不合法",
        "Invalid VLESS transport or security options",
    ),
    (
        "VLESS 响应版本不匹配",
        "The VLESS response version does not match",
    ),
    (
        "VLESS 地址类型不支持",
        "The VLESS address type is not supported",
    ),
    ("VLESS 指令", "VLESS commands"),
    ("VLESS 版本不支持", "The VLESS version is not supported"),
    (
        "VLESS 用户标识必须是 UUID",
        "VLESS user identifiers must be UUIDs",
    ),
    ("VLESS 节点配置不合法", "Invalid VLESS node configuration"),
    (
        "VLESS 请求头编码失败",
        "Could not encode the VLESS request header",
    ),
    (
        "VLESS 载体建立失败",
        "Could not establish the VLESS transport",
    ),
    ("VLESS 配置字段不合法", "Invalid VLESS configuration fields"),
    (
        "VLESS 附加信息格式不合法",
        "Invalid VLESS additional-information format",
    ),
    (
        "Vision 不能复用 TCP 业务；可仅启用 Mux UDP",
        "Vision cannot multiplex TCP traffic; only Mux UDP may be enabled",
    ),
    ("Vision 的 UDP 必须使用 XUDP", "Vision UDP must use XUDP"),
    (
        "Vision 要求直接 TLS/REALITY，或先启用 VLESS Encryption",
        "Vision requires direct TLS/REALITY or VLESS Encryption enabled first",
    ),
    ("XDRIVE HTTP 参数不合法", "Invalid XDRIVE HTTP parameters"),
    ("XDRIVE HTTP 操作失败", "The XDRIVE HTTP operation failed"),
    ("XDRIVE 存储请求失败", "The XDRIVE storage request failed"),
    (
        "XDRIVE 存储配置不合法",
        "Invalid XDRIVE storage configuration",
    ),
    ("XDRIVE 对端槽失败", "The XDRIVE peer slot failed"),
    (
        "XDRIVE 必须使用 Encryption，地址族由存储 endpoint 决定",
        "XDRIVE must use Encryption; the storage endpoint determines the address family",
    ),
    (
        "XDRIVE 必须显式启用 TCP/UDP Mux",
        "XDRIVE requires TCP/UDP Mux to be explicitly enabled",
    ),
    ("XDRIVE 槽公告不合法", "Invalid XDRIVE slot announcement"),
    ("XDRIVE 槽头不合法", "Invalid XDRIVE slot header"),
    ("XDRIVE 槽序号不合法", "Invalid XDRIVE slot sequence number"),
    (
        "XDRIVE 槽数量或 ID 不合法",
        "Invalid XDRIVE slot count or ID",
    ),
    ("XDRIVE 槽校验不合法", "Invalid XDRIVE slot verification"),
    ("XDRIVE 槽类型不合法", "Invalid XDRIVE slot type"),
    ("XDRIVE 槽编码不合法", "Invalid XDRIVE slot encoding"),
    ("XDRIVE 槽长度不合法", "Invalid XDRIVE slot length"),
    (
        "XDRIVE 的 HTTP 身份由存储 endpoint 配置",
        "XDRIVE HTTP identity is configured by the storage endpoint",
    ),
    (
        "XDRIVE 自定义 CA 必须包含有效证书",
        "The XDRIVE custom CA must contain a valid certificate",
    ),
    (
        "XDRIVE 节点要求 decryption、空 flow 和存储自身 TLS 配置",
        "XDRIVE nodes require decryption, an empty flow, and TLS configured by the storage transport",
    ),
    (
        "XDRIVE 要求 Encryption 且不能使用 Vision",
        "XDRIVE requires Encryption and cannot use Vision",
    ),
    (
        "XHTTP 的 Mux 仅支持 UDP；TCP 使用载体自己的 XMUX",
        "XHTTP Mux only supports UDP; TCP uses the transport's own XMUX",
    ),
    ("XUDP 目标不是 UDP", "The XUDP target is not UDP"),
    (
        "packetaddr 与 Mux UDP 必须分开配置",
        "packetaddr and Mux UDP must be configured separately",
    ),
    ("packetaddr 回包失败", "The packetaddr reply failed"),
    (
        "packetaddr 回包没有负载",
        "The packetaddr reply has no payload",
    ),
    (
        "packetaddr 地址格式不合法或被截断",
        "The packetaddr address format is invalid or truncated",
    ),
    (
        "packetaddr 地址类型不合法",
        "Invalid packetaddr address type",
    ),
    (
        "packetaddr 地址被截断",
        "The packetaddr address is truncated",
    ),
    ("packetaddr 域名目标", "packetaddr domain targets"),
    (
        "包装载体上的 Vision 需要 Encryption",
        "Vision over a wrapped transport requires Encryption",
    ),
    (
        "存储未提供槽写入",
        "The storage transport does not provide slot writes",
    ),
    (
        "存储未提供槽描述",
        "The storage transport does not provide slot descriptions",
    ),
    (
        "存储未提供槽正文",
        "The storage transport does not provide slot bodies",
    ),
    (
        "当前载体的 Mux 通道只允许 UDP",
        "Mux channels on this transport only permit UDP",
    ),
    (
        "无传输安全且未启用 Encryption 时只允许回环服务器",
        "Without transport security or Encryption, only loopback servers are permitted",
    ),
    (
        "无传输安全的 VLESS 只允许回环测试地址",
        "VLESS without transport security only permits loopback test addresses",
    ),
    ("系统时间不可用", "System time is unavailable"),
    (
        "自定义 CA 当前不能与 TLS 指纹整形一起使用",
        "A custom CA cannot currently be combined with TLS fingerprint shaping",
    ),
    (
        "节点地址不属于指定载体地址族",
        "The node address does not belong to the specified transport address family",
    ),
    ("节点存储载体", "Node storage transports"),
    (
        "非 TCP 传输必须使用带 type 的选项对象",
        "Non-TCP transports require an options object with a type field",
    ),
];
