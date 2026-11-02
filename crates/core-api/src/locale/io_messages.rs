//! 协议 I/O 适配层的具体诊断，与原生 ErrorKind 分别保留。
pub(super) const DIAGNOSTICS: &[(&str, &str)] = &[
    ("Tor流I/O失败", "Tor stream I/O failed"),
    (
        "ShadowTLS ClientHello 不合法",
        "Invalid ShadowTLS ClientHello",
    ),
    (
        "ShadowTLS 会话状态不可用",
        "The ShadowTLS session state is unavailable",
    ),
    ("HTTP 上传帧不合法", "Invalid HTTP upload frame"),
    ("HTTP 升级会话失败", "The HTTP upgrade session failed"),
    ("HTTP 节点路径不合法", "Invalid HTTP node path"),
    ("HTTP 节点连接失败", "The HTTP node connection failed"),
    (
        "HTTP 请求体读取失败",
        "Could not read the HTTP request body",
    ),
    ("HTTPUpgrade 升级失败", "The HTTPUpgrade handshake failed"),
    (
        "Mieru 逻辑会话已终止",
        "The Mieru logical session has ended",
    ),
    (
        "Mieru本地UDP缺少实际来源地址",
        "The local Mieru UDP stream has no actual source address",
    ),
    (
        "ShadowTLS 摘要状态不可用",
        "The ShadowTLS digest state is unavailable",
    ),
    (
        "Snell 认证任务异常退出",
        "The Snell authentication task exited unexpectedly",
    ),
    (
        "TrustTunnel H1/H2 使用 TCP 物理监听",
        "TrustTunnel H1/H2 requires a physical TCP listener",
    ),
    (
        "TrustTunnel H2 请求清理未在期限内完成",
        "TrustTunnel H2 request cleanup did not finish before the deadline",
    ),
    (
        "TrustTunnel H3 使用 UDP 物理监听",
        "TrustTunnel H3 requires a physical UDP listener",
    ),
    (
        "TrustTunnel H3 请求清理未在期限内完成",
        "TrustTunnel H3 request cleanup did not finish before the deadline",
    ),
    (
        "TrustTunnel ICMP 尚无统一目标访问契约",
        "TrustTunnel ICMP has no shared target access contract yet",
    ),
    ("UoT v2 模式不合法", "Invalid UoT v2 mode"),
    (
        "UoT 回包在物理交付前结束",
        "The UoT response ended before physical delivery",
    ),
    (
        "WebSocket 写入失败",
        "Could not write to the WebSocket stream",
    ),
    ("WebSocket 帧不合法", "Invalid WebSocket frame"),
    ("XDRIVE 写入已结束", "XDRIVE writing has ended"),
    ("XDRIVE 分段缺口超时", "The XDRIVE segment gap timed out"),
    ("XDRIVE 对端分段失败", "The XDRIVE peer segment failed"),
    ("XDRIVE 提交失败", "The XDRIVE commit failed"),
    ("XDRIVE 读取失败", "Could not read from XDRIVE"),
    (
        "XDRIVE 资源或时间参数不合法",
        "Invalid XDRIVE resource or timing parameters",
    ),
    ("XHTTP 下载已关闭", "The XHTTP download is closed"),
    ("XHTTP 下载已结束", "The XHTTP download has ended"),
    ("XHTTP 写端已关闭", "The XHTTP write side is closed"),
    (
        "XHTTP 节点模式或版本不合法",
        "Invalid XHTTP node mode or version",
    ),
    ("gRPC Hunk 不合法", "Invalid gRPC Hunk"),
    ("gRPC service_name 不合法", "Invalid gRPC service_name"),
    ("gRPC 帧被截断", "The gRPC frame is truncated"),
    ("gRPC 长度不合法", "Invalid gRPC length"),
    (
        "客户端复用会话不接受对端Open",
        "A client multiplexed session does not accept peer Open frames",
    ),
    (
        "节点非 TCP 载体须提供选项对象",
        "A non-TCP node transport requires an options object",
    ),
    ("服务任务异常退出", "A service task exited unexpectedly"),
    (
        "Tor协议版本已不满足网络要求，所属出站已停止",
        "The Tor protocol version no longer meets network requirements; its outbound has stopped",
    ),
    (
        "Tor建立或运行失败",
        "Tor connection setup or operation failed",
    ),
    (
        "Tor状态文件不可用或已被其他实例占用",
        "Tor state files are unavailable or are in use by another instance",
    ),
    (
        "Tor网络或远端目标不可用",
        "The Tor network or remote target is unavailable",
    ),
    (
        "Tor远端拒绝连接",
        "The Tor remote endpoint refused the connection",
    ),
    (
        "AnyTLS 流在物理交付前结束",
        "The AnyTLS stream ended before physical delivery",
    ),
    (
        "AnyTLS 流字节序号耗尽",
        "The AnyTLS stream byte sequence is exhausted",
    ),
    (
        "Encryption 写端已关闭",
        "The Encryption write side is closed",
    ),
    (
        "Encryption 记录体被截断",
        "The Encryption record body is truncated",
    ),
    (
        "Encryption 记录头被截断",
        "The Encryption record header is truncated",
    ),
    (
        "Encryption 记录无法继续写入",
        "The Encryption record cannot accept further writes",
    ),
    (
        "HTTP下载未完整结束",
        "The HTTP download did not finish completely",
    ),
    (
        "Hysteria v1 UDP 状态不可用",
        "The Hysteria v1 UDP state is unavailable",
    ),
    (
        "Hysteria v1 包装超出单包边界",
        "Hysteria v1 wrapping exceeds the datagram boundary",
    ),
    (
        "Hysteria v1 发送状态不可用",
        "The Hysteria v1 send state is unavailable",
    ),
    (
        "Hysteria v1 接收状态不可用",
        "The Hysteria v1 receive state is unavailable",
    ),
    (
        "Hysteria2 QUIC 关闭失败",
        "Could not close the Hysteria2 QUIC stream",
    ),
    (
        "Hysteria2 QUIC 写入失败",
        "Could not write to the Hysteria2 QUIC stream",
    ),
    (
        "Hysteria2 QUIC 刷新失败",
        "Could not flush the Hysteria2 QUIC stream",
    ),
    (
        "Hysteria2 QUIC 流已结束",
        "The Hysteria2 QUIC stream has ended",
    ),
    (
        "Hysteria2 QUIC 读取失败",
        "Could not read from the Hysteria2 QUIC stream",
    ),
    ("Mux 会话失败", "The Mux session failed"),
    ("Mux 写端已关闭", "The Mux write side is closed"),
    (
        "Naive 载体或分帧不合法",
        "Invalid Naive transport or framing",
    ),
    (
        "Naive 载体流读取、写入或分帧失败",
        "Naive transport reading, writing, or framing failed",
    ),
    (
        "Naive所属运行服务已关闭",
        "The runtime service owning Naive is closed",
    ),
    (
        "Naive流在排空前结束",
        "The Naive stream ended before draining",
    ),
    ("Naive流已取消", "The Naive stream was cancelled"),
    ("REALITY 写端已关闭", "The REALITY write side is closed"),
    (
        "REALITY 记录处理失败",
        "Could not process the REALITY record",
    ),
    (
        "Relay 延迟响应未通过校验",
        "The Relay deferred response failed validation",
    ),
    (
        "Relay 延迟响应超过建立预算",
        "The Relay deferred response exceeded the connection setup budget",
    ),
    ("Relay 目标不可达", "The Relay target is unreachable"),
    ("Relay 连接已取消", "The Relay connection was cancelled"),
    ("SMUX v1 帧不合法", "Invalid SMUX v1 frame"),
    (
        "SSH 远端目标连接失败",
        "Could not connect to the target through SSH",
    ),
    ("SSH 连接已回收", "The SSH connection has been retired"),
    ("SSR 写端已关闭", "The SSR write side is closed"),
    ("SSR 流已关闭", "The SSR stream is closed"),
    (
        "Salamander 数据报超出单包边界",
        "The Salamander datagram exceeds the packet boundary",
    ),
    (
        "Salamander 状态不可用",
        "The Salamander state is unavailable",
    ),
    (
        "ShadowTLS 半条记录被截断",
        "The partial ShadowTLS record is truncated",
    ),
    (
        "ShadowTLS 记录桥已终止",
        "The ShadowTLS record bridge has ended",
    ),
    (
        "ShadowsocksR 会话校验或传输失败",
        "ShadowsocksR session validation or transport failed",
    ),
    (
        "Sudoku H1请求在首部或正文边界前截断",
        "The Sudoku H1 request is truncated before the header or body boundary",
    ),
    (
        "Sudoku H1请求边界不合法或超过预算",
        "The Sudoku H1 request boundary is invalid or exceeds the budget",
    ),
    (
        "Sudoku HTTP下载中断",
        "The Sudoku HTTP download was interrupted",
    ),
    ("Sudoku HTTP会话已关闭", "The Sudoku HTTP session is closed"),
    ("Sudoku HTTP传输失败", "The Sudoku HTTP transport failed"),
    (
        "Sudoku WS帧或连接不合法",
        "Invalid Sudoku WebSocket frame or connection",
    ),
    ("Sudoku会话已取消", "The Sudoku session was cancelled"),
    (
        "Sudoku记录载体已关闭",
        "The Sudoku record transport is closed",
    ),
    ("Sudoku载体已关闭", "The Sudoku transport is closed"),
    ("Sudoku逻辑流已关闭", "The Sudoku logical stream is closed"),
    (
        "Tor客户端未开放该载体能力",
        "The Tor client does not expose this transport capability",
    ),
    ("Tor载体状态已损坏", "The Tor transport state is corrupted"),
    ("Tor载体连接失败", "The Tor transport connection failed"),
    (
        "TrustTunnel HTTP 流失败",
        "The TrustTunnel HTTP stream failed",
    ),
    (
        "TrustTunnel UDP 状态不可用",
        "The TrustTunnel UDP state is unavailable",
    ),
    (
        "VLESS Encryption 记录不合法",
        "Invalid VLESS Encryption record",
    ),
    ("VLESS 写端已关闭", "The VLESS write side is closed"),
    ("VLESS 响应头已失败", "The VLESS response header has failed"),
    (
        "VLESS 响应头被截断",
        "The VLESS response header is truncated",
    ),
    (
        "VLESS 响应附加信息不支持",
        "Unsupported VLESS response additional information",
    ),
    (
        "VMess 报文认证或格式不合法",
        "Invalid VMess message authentication or format",
    ),
    (
        "VMess 数据报接收缓冲区不足",
        "The VMess datagram receive buffer is too small",
    ),
    (
        "VMess 数据报超过长度上限",
        "The VMess datagram exceeds the length limit",
    ),
    (
        "WireGuard TCP写端已关闭",
        "The WireGuard TCP write side is closed",
    ),
    (
        "WireGuard TCP刷新前连接已关闭",
        "The WireGuard TCP connection closed before flushing",
    ),
    (
        "WireGuard TCP读取状态不合法",
        "Invalid WireGuard TCP read state",
    ),
    (
        "WireGuard TCP连接已重置",
        "The WireGuard TCP connection was reset",
    ),
    (
        "WireGuard目标TCP拒绝连接",
        "The WireGuard target refused the TCP connection",
    ),
    ("候选输入锁已失效", "The candidate input lock is poisoned"),
    ("候选输出锁已失效", "The candidate output lock is poisoned"),
    (
        "认证首部超过限制",
        "The authentication header exceeds the limit",
    ),
];
