//! Mihomo 代理字段映射与分享链接解析的诊断片段；代理名、字段名与取值保持原文。

pub(super) const DIAGNOSTICS: &[(&str, &str)] = &[
    (
        "Mihomo 代理条目须为映射",
        "A Mihomo proxy entry must be a mapping",
    ),
    (
        "Mihomo 代理条目缺少 name",
        "A Mihomo proxy entry is missing name",
    ),
    ("Mihomo 代理 ", "Mihomo proxy "),
    (" 的字段 ", " field "),
    (" 取值不受支持：", " has an unsupported value: "),
    (" 类型不合法", " has an invalid type"),
    (" 缺少字段 ", " is missing field "),
    (" 的类型 ", " type "),
    (" 不受支持", " is not supported"),
    ("出站条目缺少 tag", "An outbound entry is missing tag"),
    ("出站条目 ", "Outbound entry "),
    (" 缺少 type", " is missing type"),
    ("分享链接格式不合法：", "Malformed share link: "),
    ("分享链接 ", "Share link "),
    (" 的参数 ", " parameter "),
];
