//! OpenVPN 控制通道、数据通道与出站配置的具体诊断。

pub(super) const DIAGNOSTICS: &[(&str, &str)] = &[
    (
        "OpenVPN 控制包格式不合法",
        "Malformed OpenVPN control packet",
    ),
    ("OpenVPN 静态密钥不合法", "Invalid OpenVPN static key"),
    (
        "OpenVPN 控制包认证失败",
        "OpenVPN control packet authentication failed",
    ),
    (
        "OpenVPN 数据通道密钥不合法",
        "Invalid OpenVPN data channel key",
    ),
    (
        "OpenVPN 数据通道序号耗尽",
        "OpenVPN data channel packet IDs are exhausted",
    ),
    (
        "OpenVPN 数据包加密失败",
        "Could not encrypt an OpenVPN data packet",
    ),
    (
        "OpenVPN 密钥交换消息不合法",
        "Invalid OpenVPN key exchange message",
    ),
    (
        "OpenVPN TLS 会话创建失败",
        "Could not create the OpenVPN TLS session",
    ),
    (
        "OpenVPN 控制通道已关闭",
        "The OpenVPN control channel was closed",
    ),
    (
        "OpenVPN 控制消息过大",
        "OpenVPN control message is too large",
    ),
    (
        "OpenVPN 服务端证书校验失败",
        "OpenVPN server certificate verification failed",
    ),
    (
        "OpenVPN 服务端拒绝了 TLS 握手",
        "The OpenVPN server rejected the TLS handshake",
    ),
    ("OpenVPN TLS 握手失败", "OpenVPN TLS handshake failed"),
    (
        "OpenVPN 服务端要求重新连接",
        "The OpenVPN server asked the client to reconnect",
    ),
    (
        "OpenVPN 服务端要求压缩，本实现不支持",
        "The OpenVPN server requires compression, which is not supported",
    ),
    (
        "OpenVPN 推送配置缺少隧道地址",
        "The pushed OpenVPN configuration has no tunnel address",
    ),
    (
        "OpenVPN 服务端未启用 P_DATA_V2",
        "The OpenVPN server did not enable P_DATA_V2",
    ),
    (
        "OpenVPN 服务端选择的数据通道算法未启用",
        "The data channel cipher selected by the OpenVPN server is not enabled",
    ),
    ("OpenVPN TLS 密钥导出失败", "OpenVPN TLS key export failed"),
    (
        "OpenVPN 证书或私钥不合法",
        "Invalid OpenVPN certificate or private key",
    ),
    ("OpenVPN 出站字段不合法", "Invalid OpenVPN outbound fields"),
    (
        "OpenVPN 出站需要客户端证书或用户名密码",
        "The OpenVPN outbound requires a client certificate or a username and password",
    ),
    ("OpenVPN 载体运行失败", "The OpenVPN carrier failed"),
    ("OpenVPN 出站运行失败", "The OpenVPN outbound failed"),
    (
        "OpenVPN 服务端关闭了 TCP 连接",
        "The OpenVPN server closed the TCP connection",
    ),
    ("OpenVPN 包过大", "OpenVPN packet is too large"),
];
