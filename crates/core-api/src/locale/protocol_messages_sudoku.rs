//! Sudoku HTTP、记录、布局及复用的具体诊断。

pub(super) const DIAGNOSTICS: &[(&str, &str)] = &[
    (
        "HTTP transport复用仅适用于split载体",
        "HTTP transport reuse only applies to split transports",
    ),
    (
        "HTTP/2要求未被TLS对端协商",
        "The TLS peer did not negotiate the required HTTP/2 protocol",
    ),
    (
        "HTTP上传序号模式不能混用",
        "HTTP upload sequence modes must not be mixed",
    ),
    ("HTTP上传序号缺口", "Gap in the HTTP upload sequence"),
    ("HTTP上传方向已结束", "The HTTP upload direction has ended"),
    (
        "HTTP重复上传内容或序号不一致",
        "The content or sequence number of a repeated HTTP upload does not match",
    ),
    ("Sudoku HTTP Host不合法", "Invalid Sudoku HTTP Host"),
    (
        "Sudoku HTTP上传EOF未确认",
        "The Sudoku HTTP upload EOF was not acknowledged",
    ),
    (
        "Sudoku HTTP下载未就绪",
        "The Sudoku HTTP download is not ready",
    ),
    (
        "Sudoku HTTP载体连接失败",
        "Could not connect the Sudoku HTTP transport",
    ),
    (
        "Sudoku Local只允许显式none编码",
        "Sudoku Local only permits explicit none encoding",
    ),
    (
        "Sudoku TLS证书、私钥或名称不合法",
        "Invalid Sudoku TLS certificate, private key, or name",
    ),
    ("Sudoku WS升级失败", "The Sudoku WebSocket upgrade failed"),
    ("Sudoku WS请求不合法", "Invalid Sudoku WebSocket request"),
    (
        "Sudoku clue在EOF前截断",
        "The Sudoku clue was truncated before EOF",
    ),
    (
        "Sudoku none出站只能使用字面回环端点",
        "Sudoku none outbounds can only use literal loopback endpoints",
    ),
    (
        "Sudoku none必须单独明确允许不安全兼容",
        "Sudoku none requires a separate explicit opt-in to insecure compatibility",
    ),
    (
        "Sudoku padding或轮换表数量不合法",
        "Invalid Sudoku padding or rotation table count",
    ),
    ("Sudoku padding范围不合法", "Invalid Sudoku padding range"),
    (
        "Sudoku path_root只能是单个有界路径段",
        "Sudoku path_root must be a single bounded path segment",
    ),
    (
        "Sudoku seed凭据不能为空或超过4096字节",
        "Sudoku seed credentials must not be empty or exceed 4096 bytes",
    ),
    (
        "Sudoku table方向模式不合法",
        "Invalid Sudoku table direction mode",
    ),
    (
        "Sudoku 帧、序号或鉴权不合法",
        "Invalid Sudoku frame, sequence number, or authentication",
    ),
    (
        "Sudoku不能丢弃未读旧密钥数据后Rekey",
        "Sudoku cannot rekey after discarding unread data encrypted with the old key",
    ),
    (
        "Sudoku不能在待写记录中切换table",
        "Sudoku cannot switch tables while a record is pending write",
    ),
    ("Sudoku出站字段不合法", "Invalid Sudoku outbound fields"),
    (
        "Sudoku出站池预算不合法",
        "Invalid Sudoku outbound pool budget",
    ),
    (
        "Sudoku同一节点不能重复启动",
        "The same Sudoku node must not be started more than once",
    ),
    (
        "Sudoku布局必须恰有两个x、两个p和四个v",
        "A Sudoku layout must contain exactly two x, two p, and four v positions",
    ),
    (
        "Sudoku布局没有可用padding",
        "The Sudoku layout has no usable padding",
    ),
    (
        "Sudoku意图未协商或格式不合法",
        "The Sudoku intent was not negotiated or has an invalid format",
    ),
    ("Sudoku成员凭据不合法", "Invalid Sudoku member credentials"),
    (
        "Sudoku无法生成记录epoch",
        "Could not generate the Sudoku record epoch",
    ),
    (
        "Sudoku无法生成非零记录序号",
        "Could not generate a nonzero Sudoku record sequence number",
    ),
    (
        "Sudoku节点protocol必须是对象",
        "The Sudoku node protocol must be an object",
    ),
    (
        "Sudoku节点会话预算不合法",
        "Invalid Sudoku node session budget",
    ),
    ("Sudoku节点字段不合法", "Invalid Sudoku node fields"),
    (
        "Sudoku节点密钥须来自成员凭据",
        "Sudoku node keys must come from member credentials",
    ),
    (
        "Sudoku表生成缺少唯一编码",
        "Sudoku table generation did not produce unique encodings",
    ),
    (
        "Sudoku轮换表hint冲突",
        "Conflicting Sudoku rotation table hints",
    ),
    (
        "Sudoku配置未启用UoT",
        "UoT is not enabled in the Sudoku configuration",
    ),
    (
        "Sudoku随机源不可用",
        "The Sudoku random source is unavailable",
    ),
    (
        "auto须在同一节点建立流程选择具体载体",
        "auto must select a concrete transport during establishment of the same node",
    ),
    (
        "raw/legacy不接受HTTP TLS开关",
        "raw/legacy does not accept the HTTP TLS option",
    ),
    (
        "raw/legacy节点不使用HTTP路径门槛",
        "raw/legacy nodes do not use HTTP path admission checks",
    ),
    (
        "raw/legacy节点不接受HTTP TLS开关",
        "raw/legacy nodes do not accept the HTTP TLS option",
    ),
    (
        "raw载体不接受无效HTTP字段",
        "The raw transport does not accept invalid HTTP fields",
    ),
    (
        "入站UDP回写不完整",
        "The inbound UDP reply was not written completely",
    ),
    (
        "全ASCII方向不接受无效的自定义布局",
        "The all-ASCII direction does not accept invalid custom layouts",
    ),
    ("对端未选择Sudoku TCP", "The peer did not select Sudoku TCP"),
    ("对端未选择Sudoku UoT", "The peer did not select Sudoku UoT"),
    (
        "对端未选择Sudoku session mux",
        "The peer did not select Sudoku session mux",
    ),
    (
        "强制HTTP/2仅适用于TLS split载体",
        "Forcing HTTP/2 only applies to TLS split transports",
    ),
    (
        "此连接器只处理raw/legacy载体",
        "This connector only handles raw/legacy transports",
    ),
    (
        "系统时间早于Unix纪元",
        "System time is before the Unix epoch",
    ),
];
