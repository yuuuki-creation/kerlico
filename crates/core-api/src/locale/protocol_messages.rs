//! 协议诊断目录；技术标识与凭据字段名保持原文。

pub(super) const DIAGNOSTICS: &[(&str, &str)] = &[
    (
        "AnyTLS FIN 未完成物理交付",
        "AnyTLS FIN was not delivered over the transport",
    ),
    ("AnyTLS padding stop 不合法", "Invalid AnyTLS padding stop"),
    ("AnyTLS padding 区间不合法", "Invalid AnyTLS padding range"),
    (
        "AnyTLS padding 序号不合法",
        "Invalid AnyTLS padding sequence number",
    ),
    ("AnyTLS padding 方案不合法", "Invalid AnyTLS padding scheme"),
    (
        "AnyTLS padding 方案过长",
        "The AnyTLS padding scheme is too long",
    ),
    (
        "AnyTLS padding 缺少 stop",
        "The AnyTLS padding scheme is missing stop",
    ),
    ("AnyTLS 会话已关闭", "The AnyTLS session is closed"),
    ("AnyTLS 出站字段不合法", "Invalid AnyTLS outbound fields"),
    (
        "AnyTLS 口令或会话限制不合法",
        "Invalid AnyTLS password or session limits",
    ),
    (
        "AnyTLS 命令或方向不合法",
        "Invalid AnyTLS command or direction",
    ),
    ("AnyTLS 地址类型不合法", "Invalid AnyTLS address type"),
    (
        "AnyTLS 对端拒绝会话",
        "The AnyTLS peer rejected the session",
    ),
    ("AnyTLS 心跳长度不合法", "Invalid AnyTLS heartbeat length"),
    (
        "AnyTLS 流建立顺序不合法",
        "Invalid AnyTLS stream establishment order",
    ),
    ("AnyTLS 节点配置不合法", "Invalid AnyTLS node configuration"),
    ("AnyTLS 设置编码不合法", "Invalid AnyTLS settings encoding"),
    (
        "AnyTLS 设置重复或流标识不合法",
        "Duplicate AnyTLS settings or invalid stream identifier",
    ),
    ("AnyTLS 载体失败", "The AnyTLS transport failed"),
    (
        "HTTP CONNECT 不提供 UDP",
        "HTTP CONNECT does not provide UDP",
    ),
    ("HTTP TLS 版本不可用", "The HTTP TLS version is unavailable"),
    ("HTTP TLS 私钥缺失", "The HTTP TLS private key is missing"),
    (
        "HTTP TLS 证书或私钥不合法",
        "Invalid HTTP TLS certificate or private key",
    ),
    (
        "HTTP 代理报文格式或状态不合法",
        "Invalid HTTP proxy message format or state",
    ),
    (
        "HTTP 代理认证字段不合法",
        "Invalid HTTP proxy authentication fields",
    ),
    ("HTTP 出站字段不合法", "Invalid HTTP outbound fields"),
    (
        "HTTP 用户凭据字段不合法",
        "Invalid HTTP user credential fields",
    ),
    ("HTTP 节点字段不合法", "Invalid HTTP node fields"),
    (
        "SOCKS UDP关联需要TCP对端地址",
        "SOCKS UDP association requires the TCP peer address",
    ),
    (
        "SOCKS UDP关联需要TCP本地地址",
        "SOCKS UDP association requires the TCP local address",
    ),
    (
        "SOCKS userid 字段不合法或与版本冲突",
        "Invalid SOCKS userid field or a conflict with the selected version",
    ),
    ("SOCKS 出站字段不合法", "Invalid SOCKS outbound fields"),
    (
        "SOCKS 报文格式或状态不合法",
        "Invalid SOCKS message format or state",
    ),
    (
        "SOCKS 用户凭据字段不合法",
        "Invalid SOCKS user credential fields",
    ),
    ("SOCKS 节点字段不合法", "Invalid SOCKS node fields"),
    (
        "SOCKS 请求命令未实现",
        "The SOCKS request command is not implemented",
    ),
    (
        "SOCKS4 不能透传域名目标，请使用 SOCKS4a 或 SOCKS5",
        "SOCKS4 cannot pass domain targets through; use SOCKS4a or SOCKS5",
    ),
    (
        "SOCKS4/4a 不支持 IPv6 目标",
        "SOCKS4/4a does not support IPv6 targets",
    ),
    ("SOCKS4/4a 不支持 UDP", "SOCKS4/4a does not support UDP"),
    (
        "SOCKS4/4a 不支持用户名密码认证",
        "SOCKS4/4a does not support username/password authentication",
    ),
    (
        "SOCKS4/4a 只能作为 Local 入站",
        "SOCKS4/4a can only be used as a Local inbound",
    ),
    (
        "SOCKS5 用户名和密码必须为 1 至 255 字节",
        "SOCKS5 usernames and passwords must contain 1 to 255 bytes",
    ),
    (
        "SS2022 ChaCha 不支持 EIH 多用户",
        "SS2022 ChaCha does not support EIH multi-user mode",
    ),
    (
        "SS2022 ChaCha 不支持 identity key",
        "SS2022 ChaCha does not support an identity key",
    ),
    (
        "SS2022 identity 链 key 必须独立",
        "Keys in an SS2022 identity chain must be independent",
    ),
    (
        "SS2022 identity 链最多八层",
        "An SS2022 identity chain supports at most eight layers",
    ),
    (
        "SS2022 key 必须为标准 Base64",
        "SS2022 keys must use standard Base64",
    ),
    (
        "SS2022 key 长度或 Base64 编码不合法",
        "Invalid SS2022 key length or Base64 encoding",
    ),
    (
        "SS2022 客户端参数不合法",
        "Invalid SS2022 client parameters",
    ),
    (
        "SS2022 必须配置认证成员",
        "SS2022 requires authenticated members",
    ),
    ("SS2022 成员凭据不合法", "Invalid SS2022 member credentials"),
    ("SS2022 成员密钥重复", "Duplicate SS2022 member keys"),
    ("SS2022 成员数量不合法", "Invalid SS2022 member count"),
    (
        "SS2022 报文认证或格式不合法",
        "Invalid SS2022 message authentication or format",
    ),
    (
        "SS2022 方法不在本轮支持范围",
        "The SS2022 method is outside the supported scope",
    ),
    (
        "SS2022 流包装出站不提供原生 UDP",
        "An SS2022 stream-wrapper outbound does not provide native UDP",
    ),
    (
        "SS2022 用户与服务 key 不得重复",
        "SS2022 user keys and the service key must be distinct",
    ),
    (
        "SS2022 用户数超过上限",
        "The SS2022 user count exceeds the limit",
    ),
    (
        "SS2022 空首部写入长度异常",
        "Unexpected SS2022 empty-header write length",
    ),
    ("SS2022 节点参数不合法", "Invalid SS2022 node parameters"),
    ("Ss2022 出站字段不合法", "Invalid SS2022 outbound fields"),
    ("Ss2022 节点字段不合法", "Invalid SS2022 node fields"),
    ("Tor关闭状态已损坏", "The Tor shutdown state is corrupted"),
    ("Tor内部配置不合法", "Invalid internal Tor configuration"),
    ("Tor出站字段不合法", "Invalid Tor outbound fields"),
    (
        "Tor出站需要设备TCP连接能力",
        "The Tor outbound requires device TCP connectivity",
    ),
    (
        "Tor后台任务异常退出",
        "A Tor background task exited unexpectedly",
    ),
    ("Tor启动状态已关闭", "The Tor startup state is closed"),
    (
        "Tor客户端只提供TCP出站",
        "The Tor client only provides TCP outbounds",
    ),
    ("Tor客户端状态已损坏", "The Tor client state is corrupted"),
    ("Tor状态所有者已损坏", "The Tor state owner is corrupted"),
    (
        "Tor状态目录的完整祖先信任检查尚未实现该平台",
        "Full ancestor trust validation for Tor state directories is not implemented on this platform",
    ),
    (
        "Tor状态目录须是项目相对路径，时间预算须在允许范围内",
        "Tor state directories must be project-relative paths, and time budgets must be within the allowed range",
    ),
    (
        "Tor状态路径须有完整可信祖先，目录与锁须私有且未被其他实例占用",
        "Tor state paths require trusted ancestors; directories and locks must be private and not held by another instance",
    ),
    (
        "Tor运行环境不可用",
        "The Tor runtime environment is unavailable",
    ),
    (
        "Tor需要运行中的Tokio执行器",
        "Tor requires a running Tokio executor",
    ),
    (
        "WireGuard AllowedIPs必须使用规范网络地址",
        "WireGuard AllowedIPs must use canonical network addresses",
    ),
    (
        "WireGuard MTU必须为1280至9000字节",
        "WireGuard MTU must be between 1280 and 9000 bytes",
    ),
    (
        "WireGuard TCP栈产生了意外控制包",
        "The WireGuard TCP stack produced an unexpected control packet",
    ),
    (
        "WireGuard UDP回包地址族与原来源不一致",
        "The WireGuard UDP reply address family does not match the original source",
    ),
    (
        "WireGuard不处理IPv4选项",
        "WireGuard does not handle IPv4 options",
    ),
    (
        "WireGuard不处理IPv6路由扩展头",
        "WireGuard does not handle IPv6 routing extension headers",
    ),
    (
        "WireGuard会话尚未确认",
        "The WireGuard session has not been confirmed",
    ),
    (
        "WireGuard内部IP包不合法",
        "Invalid WireGuard inner IP packet",
    ),
    (
        "WireGuard出站不提供该IP协议",
        "The WireGuard outbound does not provide this IP protocol",
    ),
    (
        "WireGuard出站字段不合法",
        "Invalid WireGuard outbound fields",
    ),
    (
        "WireGuard出站运行服务已失败",
        "The WireGuard outbound runtime service has failed",
    ),
    (
        "WireGuard加密产生了意外内部包",
        "WireGuard encryption produced an unexpected inner packet",
    ),
    ("WireGuard加密失败", "WireGuard encryption failed"),
    (
        "WireGuard单peer的AllowedIPs不能重复或重叠",
        "AllowedIPs for one WireGuard peer must not overlap or be duplicated",
    ),
    (
        "WireGuard密钥必须为非零32字节的标准Base64",
        "WireGuard keys must be nonzero 32-byte values encoded as standard Base64",
    ),
    (
        "WireGuard对端公钥不能等于本机公钥或使用低阶点",
        "The WireGuard peer public key must differ from the local public key and must not use a low-order point",
    ),
    (
        "WireGuard成员公钥及来源范围必须独立，不能包含节点接口地址",
        "WireGuard member public keys and source ranges must be independent and must not include node interface addresses",
    ),
    ("WireGuard成员字段不合法", "Invalid WireGuard member fields"),
    (
        "WireGuard排空产生了意外内部包",
        "WireGuard draining produced an unexpected inner packet",
    ),
    (
        "WireGuard未配置该内部地址族",
        "This WireGuard inner address family is not configured",
    ),
    (
        "WireGuard每个内部地址族只能配置一个接口地址",
        "WireGuard permits only one interface address per inner address family",
    ),
    (
        "WireGuard用户态栈状态已损坏",
        "The WireGuard userspace stack state is corrupted",
    ),
    (
        "WireGuard节点不转发该IP协议",
        "The WireGuard node does not forward this IP protocol",
    ),
    (
        "WireGuard节点仅接受UDP载体",
        "WireGuard nodes only accept UDP transports",
    ),
    ("WireGuard节点字段不合法", "Invalid WireGuard node fields"),
    (
        "WireGuard节点必须配置独立认证成员",
        "WireGuard nodes must configure independently authenticated members",
    ),
    (
        "WireGuard节点需要真实多目标UDP关联",
        "WireGuard nodes require an actual multi-target UDP association",
    ),
    (
        "WireGuard载体未发送完整数据报",
        "The WireGuard transport did not send the complete datagram",
    ),
    (
        "WireGuard载体端点必须为单播地址",
        "WireGuard transport endpoints must be unicast addresses",
    ),
    (
        "WireGuard载体绑定与对端地址族不一致",
        "The WireGuard transport bind address family does not match the peer",
    ),
    (
        "WireGuard载体绑定地址不合法",
        "Invalid WireGuard transport bind address",
    ),
    (
        "WireGuard配置或资源边界不合法",
        "Invalid WireGuard configuration or resource limits",
    ),
    (
        "WireGuard需要共享调度器提供字面IP目标",
        "WireGuard requires literal IP targets selected by the shared dispatcher",
    ),
    (
        "入站必须使用真实多目标UDP关联",
        "The inbound requires an actual multi-target UDP association",
    ),
    (
        "所选出站不支持SOCKS多目标UDP关联",
        "The selected outbound does not support SOCKS multi-target UDP associations",
    ),
    (
        "测试目标不得触发DNS",
        "Test targets must not trigger DNS resolution",
    ),
    (
        "认证任务异常退出",
        "An authentication task exited unexpectedly",
    ),
];
