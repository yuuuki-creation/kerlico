//! Tailscale 出站的具体诊断。

pub(super) const DIAGNOSTICS: &[(&str, &str)] = &[
    (
        "Tailscale出站字段不合法",
        "Invalid Tailscale outbound fields",
    ),
    ("Tailscale auth_key不合法", "Invalid Tailscale auth_key"),
    ("Tailscale hostname不合法", "Invalid Tailscale hostname"),
    (
        "Tailscale exit_node不能为空",
        "The Tailscale exit_node must not be empty",
    ),
    (
        "Tailscale start_timeout_ms不合法",
        "Invalid Tailscale start_timeout_ms",
    ),
    (
        "Tailscale control_url不合法",
        "Invalid Tailscale control_url",
    ),
    ("Tailscale状态文件不合法", "Invalid Tailscale state file"),
    (
        "Tailscale对端公钥不合法",
        "Invalid Tailscale peer public key",
    ),
    (
        "Tailscale消息加密失败",
        "Failed to encrypt a Tailscale message",
    ),
    (
        "Tailscale控制握手失败",
        "The Tailscale control handshake failed",
    ),
    (
        "Tailscale控制面拒绝握手",
        "The Tailscale control server rejected the handshake",
    ),
    (
        "Tailscale控制连接密钥已耗尽",
        "The Tailscale control connection ran out of nonces",
    ),
    (
        "Tailscale控制记录帧不合法",
        "Invalid Tailscale control record",
    ),
    (
        "Tailscale控制记录帧解密失败",
        "Failed to decrypt a Tailscale control record",
    ),
    (
        "Tailscale控制记录帧加密失败",
        "Failed to encrypt a Tailscale control record",
    ),
    (
        "Tailscale HTTP响应不合法",
        "Invalid Tailscale HTTP response",
    ),
    (
        "Tailscale控制面公钥请求失败",
        "The Tailscale control key request failed",
    ),
    ("Tailscale控制面公钥不合法", "Invalid Tailscale control key"),
    ("DERP帧过大", "The DERP frame is too large"),
    ("DERP HTTP升级失败", "The DERP HTTP upgrade failed"),
    ("DERP服务端问候不合法", "Invalid DERP server greeting"),
    ("DERP服务端信息不合法", "Invalid DERP server info"),
    ("DERP握手帧顺序不合法", "Invalid DERP handshake frame order"),
    (
        "Tailscale节点地址已变化，需要重启出站",
        "The Tailscale node address changed; restart the outbound",
    ),
    ("Tailscale载体运行失败", "The Tailscale carrier failed"),
    ("Tailscale出站运行失败", "The Tailscale outbound failed"),
    (
        "Tailscale netmap消息过大",
        "The Tailscale netmap message is too large",
    ),
    (
        "Tailscale netmap消息不合法",
        "Invalid Tailscale netmap message",
    ),
    (
        "Tailscale控制面拒绝注册",
        "The Tailscale control server rejected registration",
    ),
    (
        "Tailscale注册响应不合法",
        "Invalid Tailscale registration response",
    ),
    (
        "Tailscale节点未获授权，auth_key需要人工批准",
        "The Tailscale node is not authorized; the auth_key needs manual approval",
    ),
    (
        "Tailscale控制响应过大",
        "The Tailscale control response is too large",
    ),
];
