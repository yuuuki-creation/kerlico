//! QUIC 协议、复用载体与 SSH 的具体诊断。

pub(super) const DIAGNOSTICS: &[(&str, &str)] = &[
    (
        "Gost Relay 出站字段不合法",
        "Invalid Gost Relay outbound fields",
    ),
    ("Gost Relay 帧不合法", "Invalid Gost Relay frame"),
    (
        "Gost Relay 认证字段超过255字节",
        "A Gost Relay authentication field exceeds 255 bytes",
    ),
    (
        "Hysteria v1 使用 QUIC UDP 监听",
        "Hysteria v1 uses QUIC UDP listeners",
    ),
    (
        "Hysteria v1 出站已禁用 UDP",
        "UDP is disabled on the Hysteria v1 outbound",
    ),
    (
        "Hysteria v1 对端未启用 QUIC 数据报",
        "The Hysteria v1 peer has not enabled QUIC datagrams",
    ),
    (
        "Hysteria v1 对端未启用 UDP",
        "The Hysteria v1 peer has not enabled UDP",
    ),
    (
        "Hysteria v1 节点已禁用或未协商 UDP",
        "UDP is disabled or was not negotiated on the Hysteria v1 node",
    ),
    (
        "Hysteria v1 节点需要同 socket 多目标 UDP 出口",
        "Hysteria v1 nodes require multi-target UDP egress over one socket",
    ),
    (
        "Hysteria v1 配置不合法",
        "Invalid Hysteria v1 configuration",
    ),
    (
        "Hysteria v1 鉴权、响应或报文不合法",
        "Invalid Hysteria v1 authentication, response, or message",
    ),
    (
        "Hysteria2 UDP 节点需要多目标目标访问服务",
        "Hysteria2 UDP nodes require multi-target access",
    ),
    (
        "Hysteria2 UDP 载体已关闭",
        "The Hysteria2 UDP transport is closed",
    ),
    (
        "Hysteria2 出站字段不合法",
        "Invalid Hysteria2 outbound fields",
    ),
    (
        "Hysteria2 固定速率拥塞模式尚未实现",
        "Hysteria2 fixed-rate congestion mode is not implemented",
    ),
    (
        "Hysteria2 对端未启用 QUIC 数据报",
        "The Hysteria2 peer has not enabled QUIC datagrams",
    ),
    (
        "Hysteria2 对端未启用 UDP",
        "The Hysteria2 peer has not enabled UDP",
    ),
    (
        "Hysteria2 报文或握手不合法",
        "Invalid Hysteria2 message or handshake",
    ),
    (
        "Hysteria2 物理监听仅使用 QUIC/UDP",
        "Hysteria2 physical listeners only use QUIC/UDP",
    ),
    (
        "Hysteria2 用户凭据字段不合法",
        "Invalid Hysteria2 user credential fields",
    ),
    ("Hysteria2 节点字段不合法", "Invalid Hysteria2 node fields"),
    (
        "Hysteria2 配置或 TLS 参数不合法",
        "Invalid Hysteria2 configuration or TLS parameters",
    ),
    ("Hysteria2载体已关闭", "The Hysteria2 transport is closed"),
    (
        "JLS 上游不能指向当前节点",
        "The JLS upstream must not point to the current node",
    ),
    (
        "Mieru UDP 写端已失效",
        "The Mieru UDP write half is no longer valid",
    ),
    (
        "Mieru UDP 地址与负载超过包封装上限",
        "The Mieru UDP address and payload exceed the packet encapsulation limit",
    ),
    (
        "Mieru UDP 读端已失效",
        "The Mieru UDP read half is no longer valid",
    ),
    (
        "Mieru UDP 负载超过上限",
        "The Mieru UDP payload exceeds the limit",
    ),
    (
        "Mieru UDP 载体仅允许显式本地不安全兼容模式",
        "The Mieru UDP transport only permits explicit local insecure compatibility mode",
    ),
    (
        "Mieru 不安全 UDP 仅允许回环载体",
        "Mieru insecure UDP only permits loopback transports",
    ),
    (
        "Mieru 不安全 UDP 必须回环监听",
        "Mieru insecure UDP must listen on loopback",
    ),
    (
        "Mieru 不安全 UDP 载体仅允许 IP 字面量回环端点",
        "Mieru insecure UDP transports only permit literal-IP loopback endpoints",
    ),
    ("Mieru 低熵段不合法", "Invalid Mieru low-entropy segment"),
    ("Mieru 报文不合法", "Invalid Mieru message"),
    (
        "Mieru 节点需要 Full Cone UDP 关联出口",
        "Mieru nodes require a Full Cone UDP association outbound",
    ),
    ("Mieru 配置无效", "Invalid Mieru configuration"),
    (
        "Naive QUIC TLS 配置不合法",
        "Invalid Naive QUIC TLS configuration",
    ),
    (
        "Naive UDP 需要显式启用 UoT",
        "Naive UDP requires UoT to be explicitly enabled",
    ),
    (
        "Naive 报文格式、认证或协商不合法",
        "Invalid Naive message format, authentication, or negotiation",
    ),
    ("Naive 配置不合法", "Invalid Naive configuration"),
    ("Naive任务清理失败", "Naive task cleanup failed"),
    (
        "Naive桥任务异常退出",
        "A Naive bridge task exited unexpectedly",
    ),
    (
        "Naive桥任务所有者已损坏",
        "The Naive bridge task owner state is corrupted",
    ),
    (
        "Naive节点任务异常退出",
        "A Naive node task exited unexpectedly",
    ),
    (
        "Naive节点强制清理未在期限内完成",
        "Forced cleanup of the Naive node did not complete before the deadline",
    ),
    (
        "Relay UDP 帧头截断",
        "The Relay UDP frame header is truncated",
    ),
    (
        "Relay UDP 正文截断",
        "The Relay UDP frame body is truncated",
    ),
    (
        "SSH direct-tcpip 不提供 UDP",
        "SSH direct-tcpip does not provide UDP",
    ),
    ("SSH 出站字段不合法", "Invalid SSH outbound fields"),
    (
        "SSH 对端未提供 RSA SHA-2 签名",
        "The SSH peer did not provide RSA SHA-2 signatures",
    ),
    (
        "SSH 握手、鉴权或通道建立失败",
        "SSH handshake, authentication, or channel establishment failed",
    ),
    (
        "SSH 私钥必须明确选择内存 PEM 或文件",
        "An SSH private key must explicitly select either in-memory PEM or a file",
    ),
    (
        "SSH 私钥或解密口令不合法",
        "Invalid SSH private key or decryption passphrase",
    ),
    (
        "SSH 私钥文件不能允许组或其他用户访问",
        "SSH private key files must not permit access by group members or other users",
    ),
    (
        "SSH 私钥文件无法读取",
        "Could not read the SSH private key file",
    ),
    (
        "SSH 私钥算法不在本轮支持范围",
        "The SSH private key algorithm is outside the supported scope",
    ),
    ("SSH 选项或凭据不合法", "Invalid SSH options or credentials"),
    ("SSH任务异常退出", "An SSH task exited unexpectedly"),
    (
        "SSH任务所有者已损坏",
        "The SSH task owner state is corrupted",
    ),
    (
        "SSH驱动未交付通道",
        "The SSH driver did not deliver a channel",
    ),
    (
        "ShadowQUIC JLS 握手失败",
        "The ShadowQUIC JLS handshake failed",
    ),
    (
        "ShadowQUIC datagram 不支持超 MTU 的整包",
        "ShadowQUIC datagram mode does not support whole packets larger than the MTU",
    ),
    (
        "ShadowQUIC server_name 必须是发送 SNI 的 DNS 名称",
        "ShadowQUIC server_name must be a DNS name sent as SNI",
    ),
    ("ShadowQUIC udp_mode 不合法", "Invalid ShadowQUIC udp_mode"),
    (
        "ShadowQUIC 仅监听 QUIC UDP 载体",
        "ShadowQUIC only listens for QUIC UDP transports",
    ),
    (
        "ShadowQUIC 任务缺少运行所有者",
        "The ShadowQUIC task has no runtime owner",
    ),
    (
        "ShadowQUIC 命令未提供",
        "The ShadowQUIC command is not provided",
    ),
    (
        "ShadowQUIC 报文或映射不合法",
        "Invalid ShadowQUIC message or mapping",
    ),
    (
        "ShadowQUIC 节点需要 Full Cone UDP 关联出口",
        "ShadowQUIC nodes require a Full Cone UDP association outbound",
    ),
    ("ShadowQUIC 配置不合法", "Invalid ShadowQUIC configuration"),
    ("ShadowQUIC载体已关闭", "The ShadowQUIC transport is closed"),
    (
        "TLS 模式不接受明文许可字段",
        "TLS mode does not accept plaintext opt-in fields",
    ),
    (
        "TrustTunnel UDP 写任务已结束",
        "The TrustTunnel UDP writer task has ended",
    ),
    (
        "TrustTunnel UDP 写任务提前结束",
        "The TrustTunnel UDP writer task ended prematurely",
    ),
    (
        "TrustTunnel UDP 出口缺少可编码业务来源",
        "The TrustTunnel UDP outbound has no encodable business source address",
    ),
    (
        "TrustTunnel UDP 出口缺少真实业务来源",
        "The TrustTunnel UDP outbound has no actual business source address",
    ),
    (
        "TrustTunnel UDP 回复未完成",
        "The TrustTunnel UDP reply did not complete",
    ),
    (
        "TrustTunnel UDP 子任务异常退出",
        "A TrustTunnel UDP subtask exited unexpectedly",
    ),
    ("TrustTunnel UDP 已关闭", "TrustTunnel UDP is closed"),
    (
        "TrustTunnel UDP 需要统一出口提供无歧义字面 IP",
        "TrustTunnel UDP requires unambiguous literal IP targets selected by the dispatcher",
    ),
    (
        "TrustTunnel 请求、响应或数据不合法",
        "Invalid TrustTunnel request, response, or data",
    ),
    (
        "TrustTunnel 配置不合法",
        "Invalid TrustTunnel configuration",
    ),
    (
        "公网 Mieru UDP 载体未支持",
        "Public Mieru UDP transports are not supported",
    ),
    (
        "固定 Mieru UDP 通道不支持远端域名目标；多目标使用 UDP 关联",
        "Fixed-target Mieru UDP channels do not support remote domain targets; use a UDP association for multiple targets",
    ),
    (
        "固定转发必须使用明确的 IP 目标",
        "Fixed forwarding requires an explicit IP target",
    ),
    (
        "该 Mieru 条目没有 TCP 载体",
        "This Mieru entry has no TCP transport",
    ),
    (
        "该Naive节点只启用H3监听",
        "This Naive node only enables H3 listeners",
    ),
    (
        "该Naive节点未启用H3监听",
        "H3 listeners are not enabled on this Naive node",
    ),
    (
        "请求目标与已知固定转发目标不同",
        "The requested target differs from the known fixed-forward target",
    ),
    (
        "非字面回环的明文 Relay 需要 allow_insecure",
        "A plaintext Relay endpoint outside literal loopback requires allow_insecure",
    ),
];
