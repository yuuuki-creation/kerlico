//! 显式语言呈现；错误的结构、归属和原始诊断不随语言改变。

use crate::Error;
use std::fmt;
mod foundation_messages;
mod io_messages;
mod protocol_messages;
mod protocol_messages_batch2;
mod protocol_messages_batch3;
mod protocol_messages_openvpn;
mod protocol_messages_sudoku;
mod protocol_messages_vless;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Language {
    ZhCn,
    #[default]
    En,
}
impl Language {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "zh-CN" => Some(Self::ZhCn),
            "en" => Some(Self::En),
            _ => None,
        }
    }
    pub fn from_locale(value: &str) -> Self {
        let language = value.split(['-', '_', '.', '@']).next().unwrap_or("");
        if language.eq_ignore_ascii_case("zh") {
            Self::ZhCn
        } else {
            Self::En
        }
    }
    pub fn select(self, chinese: &'static str, english: &'static str) -> &'static str {
        match self {
            Self::ZhCn => chinese,
            Self::En => english,
        }
    }
}

pub struct LocalizedError<'a> {
    error: &'a Error,
    language: Language,
}
impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidAddress => "address.invalid",
            Self::Config(_) => "configuration.invalid",
            Self::Unsupported(_) => "capability.unsupported",
            Self::Protocol(_) => "protocol.invalid",
            Self::Rejected => "policy.rejected",
            Self::Cancelled => "operation.cancelled",
            Self::Timeout => "operation.timeout",
            Self::ResourceLimit => "resource.limit",
            Self::Io(_) => "io.failed",
            Self::Startup { .. } => "startup.failed",
            Self::Shutdown { .. } => "shutdown.incomplete",
        }
    }
    pub fn localized(&self, language: Language) -> LocalizedError<'_> {
        LocalizedError {
            error: self,
            language,
        }
    }
}
fn detail(f: &mut fmt::Formatter<'_>, message: &str) -> fmt::Result {
    if let Some(english) = diagnostic_translation(message) {
        return f.write_str(english);
    }
    let mut remaining = message;
    while let Some((start, chinese, english)) = diagnostics()
        .filter_map(|(chinese, english)| {
            remaining
                .find(chinese)
                .map(|start| (start, *chinese, *english))
        })
        .min_by_key(|(start, chinese, _)| (*start, std::cmp::Reverse(chinese.len())))
    {
        raw_detail(f, &remaining[..start])?;
        f.write_str(english)?;
        remaining = &remaining[start + chinese.len()..];
    }
    raw_detail(f, remaining)
}
fn raw_detail(f: &mut fmt::Formatter<'_>, message: &str) -> fmt::Result {
    if message
        .chars()
        .any(|character| ('\u{3400}'..='\u{9fff}').contains(&character))
    {
        write!(f, "[untranslated detail] {message}")
    } else {
        f.write_str(message)
    }
}
impl fmt::Display for LocalizedError<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.language == Language::ZhCn {
            return fmt::Display::fmt(self.error, f);
        }
        match self.error {
            Error::InvalidAddress => f.write_str("Invalid address or port"),
            Error::Config(message) => {
                f.write_str("Invalid configuration: ")?;
                detail(f, message)
            }
            Error::Unsupported(message) => {
                f.write_str("Unsupported capability: ")?;
                detail(f, message)
            }
            Error::Protocol(message) => {
                f.write_str("Protocol error: ")?;
                detail(f, message)
            }
            Error::Rejected => f.write_str("Connection rejected by policy"),
            Error::Cancelled => f.write_str("Operation cancelled"),
            Error::Timeout => f.write_str("Operation timed out"),
            Error::ResourceLimit => f.write_str("Resource limit reached"),
            Error::Io(error) => {
                f.write_str("I/O failed: ")?;
                if let Some(cause) = error
                    .get_ref()
                    .and_then(|cause| cause.downcast_ref::<Error>())
                {
                    fmt::Display::fmt(&cause.localized(self.language), f)
                } else if let Some(code) = error.raw_os_error() {
                    write!(f, "{:?} (OS error {code}; ", error.kind())?;
                    detail(f, &error.to_string())?;
                    f.write_str(")")
                } else {
                    detail(f, &error.to_string())
                }
            }
            Error::Startup {
                primary,
                cleanup_timed_out,
                cleanup_failures,
            } => write!(
                f,
                "Startup failed: {}; cleanup_timed_out={cleanup_timed_out}, cleanup_failures={cleanup_failures}",
                primary.localized(self.language)
            ),
            Error::Shutdown {
                primary,
                cleanup_timed_out,
                cleanup_failures,
            } => {
                f.write_str("Shutdown incomplete; primary=")?;
                if let Some(primary) = primary {
                    fmt::Display::fmt(&primary.localized(self.language), f)?;
                } else {
                    f.write_str("none")?;
                }
                write!(
                    f,
                    "; cleanup_timed_out={cleanup_timed_out}, cleanup_failures={cleanup_failures}"
                )
            }
        }
    }
}

/// 查找完整诊断的译文；未知动态详情由调用方保留，不吞掉原始原因。
pub fn diagnostic_translation(message: &str) -> Option<&'static str> {
    diagnostics().find_map(|(chinese, english)| (*chinese == message).then_some(*english))
}
fn diagnostics() -> impl Iterator<Item = &'static (&'static str, &'static str)> {
    DIAGNOSTICS
        .iter()
        .chain(io_messages::DIAGNOSTICS)
        .chain(foundation_messages::DIAGNOSTICS)
        .chain(protocol_messages::DIAGNOSTICS)
        .chain(protocol_messages_batch2::DIAGNOSTICS)
        .chain(protocol_messages_batch3::DIAGNOSTICS)
        .chain(protocol_messages_openvpn::DIAGNOSTICS)
        .chain(protocol_messages_vless::DIAGNOSTICS)
        .chain(protocol_messages_sudoku::DIAGNOSTICS)
}
const DIAGNOSTICS: &[(&str, &str)] = &[
    (
        "统计历史写者启动失败",
        "Could not start the statistics history writer",
    ),
    (
        "统计历史提交队列不可用",
        "The statistics history commit queue is unavailable",
    ),
    (
        "统计历史最终提交队列不可用",
        "The statistics history final commit queue is unavailable",
    ),
    (
        "用量和带宽查询一次只可指定一个投影维度",
        "Usage and bandwidth queries accept only one projection dimension at a time",
    ),
    (
        "累计用量不接受时间或分页参数",
        "Cumulative usage does not accept time filters or pagination parameters",
    ),
    (
        "本地代理入口必须回环监听，且模块须明确允许",
        "Local proxy inbounds must listen on loopback and be explicitly allowed by the module",
    ),
    (
        "标识必须是 1 至 64 个字母、数字、横线或下划线",
        "Identifiers must contain 1 to 64 ASCII letters, digits, hyphens, or underscores",
    ),
    ("出站标签重复", "Duplicate outbound tag"),
    (
        "出站不提供所需的远端 EOF 能力",
        "The outbound does not provide the required remote EOF capability",
    ),
    (
        "出站不支持入站需要的数据能力",
        "The outbound does not support the data capabilities required by the inbound",
    ),
    (
        "出站类型未注册或未编译",
        "The outbound type is not registered or was not compiled in",
    ),
    (
        "出站未提供多目标 UDP 关联",
        "The outbound does not provide a multi-target UDP association",
    ),
    (
        "当前节点组合仅允许回环监听",
        "This node combination only permits loopback listeners",
    ),
    (
        "多目标直连需要统一出口提供字面 IP",
        "Multi-target direct egress requires literal IP targets selected by the dispatcher",
    ),
    (
        "服务任务所有者已损坏",
        "The service task owner state is corrupted",
    ),
    (
        "共享服务任务未交付结果",
        "The shared service task did not deliver a result",
    ),
    (
        "固定转发入口只允许回环地址",
        "Fixed-forward inbounds only permit loopback listeners",
    ),
    (
        "管理密码必须保存为 Argon2id PHC 摘要",
        "Management passwords must be stored as Argon2id PHC hashes",
    ),
    (
        "管理密码必须保存为 Argon2id v19 PHC 摘要",
        "Management passwords must be stored as Argon2id v19 PHC hashes",
    ),
    (
        "管理密码盐生成失败",
        "Could not generate a management password salt",
    ),
    (
        "管理密码摘要参数超出支持范围",
        "Management password hash parameters are outside the supported range",
    ),
    (
        "管理密码摘要缺少并行参数",
        "The management password hash is missing its parallelism parameter",
    ),
    (
        "管理密码摘要缺少迭代参数",
        "The management password hash is missing its iteration parameter",
    ),
    (
        "管理密码摘要缺少内存参数",
        "The management password hash is missing its memory parameter",
    ),
    (
        "管理密码摘要生成失败",
        "Could not generate the management password hash",
    ),
    (
        "管理用户 ID 必须是 UUID",
        "Management user IDs must be UUIDs",
    ),
    (
        "管理用户 ID 不能为零",
        "Management user IDs must not be nil UUIDs",
    ),
    (
        "管理用户 ID 或用户名重复",
        "Duplicate management user ID or username",
    ),
    (
        "管理用户名必须是 1 至 128 个非空白字符",
        "Management usernames must contain 1 to 128 non-whitespace characters",
    ),
    (
        "基础处理器不接受额外选项",
        "The base handler does not accept additional options",
    ),
    ("监听地址重复", "Duplicate listener address"),
    (
        "节点不能使用 IPv4-mapped IPv6 监听地址",
        "Nodes must not use IPv4-mapped IPv6 listener addresses",
    ),
    (
        "节点成员引用的管理账户不存在",
        "A node member references a management account that does not exist",
    ),
    (
        "节点会话上限必须在全局限额内",
        "The node session limit must be within the global limit",
    ),
    (
        "节点计划已被另一个运行实例消费",
        "The node plan has already been consumed by another runtime instance",
    ),
    ("节点类型重复注册", "Duplicate node type registration"),
    (
        "节点没有可用监听能力",
        "The node has no supported listener capability",
    ),
    (
        "节点任务所有者已损坏",
        "The node task owner state is corrupted",
    ),
    (
        "节点任务未交付结果",
        "The node task did not deliver a result",
    ),
    ("节点任务异常退出", "A node task exited unexpectedly"),
    (
        "节点未提供 UDP 监听",
        "The node does not provide a UDP listener",
    ),
    (
        "节点未提供虚拟载体监听",
        "The node does not provide a virtual transport listener",
    ),
    (
        "节点协议未注册或未编译",
        "The node protocol is not registered or was not compiled in",
    ),
    (
        "节点需要保持同一出口 socket 的多目标 UDP 关联",
        "The node requires a multi-target UDP association that retains one egress socket",
    ),
    (
        "节点引用的出站不存在",
        "The node references an outbound that does not exist",
    ),
    (
        "节点与入站标签重复",
        "Duplicate tag across nodes and inbounds",
    ),
    (
        "仅支持配置版本 2；迁移说明见 docs/config-v2-migration.md",
        "Only configuration version 2 is supported; see docs/config-v2-migration.en.md",
    ),
    (
        "仅支持配置版本 2；请按 docs/config-v2-migration.md 迁移账户、成员和原生凭据",
        "Only configuration version 2 is supported; migrate accounts, members, and native credentials using docs/config-v2-migration.en.md",
    ),
    (
        "每个节点成员必须具有真实鉴别凭据",
        "Every node member must have valid authentication credentials",
    ),
    (
        "每节点原生凭据候选不能超过1024项",
        "A node must not have more than 1024 native credential candidates",
    ),
    ("模块类型重复注册", "Duplicate module type registration"),
    (
        "配置代次必须大于零",
        "The configuration epoch must be greater than zero",
    ),
    (
        "配置和凭据代次必须大于零",
        "Configuration and credential epochs must be greater than zero",
    ),
    ("配置文件超过 1 MiB", "The configuration file exceeds 1 MiB"),
    (
        "凭据代次必须大于零",
        "The credential epoch must be greater than zero",
    ),
    (
        "入口凭据重复，节点及本地入口必须独立配置",
        "Duplicate inbound credentials; nodes and local inbounds must use independent credentials",
    ),
    (
        "入口认证凭据重复或成员映射不合法",
        "Duplicate inbound authentication credentials or invalid member mapping",
    ),
    ("入站标签重复", "Duplicate inbound tag"),
    ("引用的出站不存在", "The referenced outbound does not exist"),
    (
        "原生凭据行与节点成员数量不一致",
        "The number of native credential rows does not match the node member count",
    ),
    (
        "远端节点必须配置真实认证成员",
        "Remote nodes must configure members with valid authentication credentials",
    ),
    (
        "账户前缀须为 1 至 80 个非空白字符，管理密码须为 12 至 1024 字节",
        "Account prefixes must contain 1 to 80 non-whitespace characters, and management passwords must contain 12 to 1024 bytes",
    ),
    (
        "直连后端只接受调度器已选定的字面目标",
        "The direct backend only accepts literal targets selected by the dispatcher",
    ),
    (
        "资源限制超出支持范围",
        "Resource limits are outside the supported range",
    ),
    ("CA 证书不合法", "Invalid CA certificate"),
    (
        "CA PEM 不包含证书",
        "The CA PEM does not contain a certificate",
    ),
    ("JSON 结构或字段不合法", "Invalid JSON structure or fields"),
    ("TLS 版本不可用", "The requested TLS version is unavailable"),
    ("TLS 服务端名称不合法", "Invalid TLS server name"),
    (
        "UDP 关联未发送完整数据报",
        "The UDP association did not send the complete datagram",
    ),
    (
        "UDP通道未发送完整数据报",
        "The UDP channel did not send the complete datagram",
    ),
    (
        "管理账户无法编码",
        "Could not encode the management account",
    ),
    (
        "帮助命令不存在",
        "The requested help command does not exist",
    ),
    ("没有配置入站", "No inbounds are configured"),
    ("入口任务异常退出", "An inbound task exited unexpectedly"),
    (
        "节点入口任务异常退出",
        "A node inbound task exited unexpectedly",
    ),
    ("节点入口回收失败", "Node inbound cleanup failed"),
    (
        "运行账本状态已损坏",
        "The runtime ledger state is corrupted",
    ),
    ("出站绑定不存在", "The outbound binding does not exist"),
    (
        "所选命名出站没有 TCP 能力",
        "The selected named outbound does not support TCP",
    ),
    (
        "所选命名出站没有固定 UDP 能力",
        "The selected named outbound does not support fixed-target UDP",
    ),
    (
        "所选命名出站没有多目标 UDP 关联能力",
        "The selected named outbound does not support multi-target UDP associations",
    ),
    (
        "运行后端与编译能力或启动状态不一致",
        "The running backend does not match its compiled capabilities or startup state",
    ),
    (
        "服务后台任务异常退出",
        "A service background task exited unexpectedly",
    ),
    (
        "服务回收线程异常退出",
        "The service retirement thread exited unexpectedly",
    ),
    (
        "会话回收时任务异常退出",
        "A task exited unexpectedly during session cleanup",
    ),
    (
        "强制回收时任务异常退出",
        "A task exited unexpectedly during forced cleanup",
    ),
    (
        "数据库不属于统计历史",
        "The database does not belong to statistics history",
    ),
    ("统计查询无法编码", "Could not encode the statistics query"),
    (
        "统计历史版本不支持",
        "Unsupported statistics history version",
    ),
    (
        "统计历史版本高于当前程序",
        "The statistics history version is newer than this program",
    ),
    (
        "统计历史存储操作失败",
        "The statistics history storage operation failed",
    ),
    (
        "统计路径权限或硬链接数量不安全",
        "Unsafe statistics path permissions, ownership, or hard-link count",
    ),
    ("路由规则不合法", "Invalid routing rule"),
    ("DNS 配置不合法", "Invalid DNS configuration"),
    ("TUN 选项不合法", "Invalid TUN options"),
    (
        "TUN 节点没有物理 TCP 入口",
        "A TUN node has no physical TCP entry",
    ),
    (
        "非回环控制接口必须配置非空密钥",
        "A non-loopback control interface requires a non-empty secret",
    ),
    ("直连出站字段不合法", "Invalid direct outbound fields"),
    (
        "直连出站接口名不合法或平台不支持",
        "Invalid direct outbound interface name, or unsupported on this platform",
    ),
    (
        "路由规则引用的出站不存在",
        "A routing rule references an outbound that does not exist",
    ),
    (
        "设备状态目录必须是绝对路径",
        "The device state directory must be an absolute path",
    ),
    (
        "此构建未启用 warp",
        "This build does not include the warp feature",
    ),
    (
        "设备回收未干净完成",
        "The device owner did not shut down cleanly",
    ),
    (
        "统计目录、采样间隔或保留天数不合法",
        "Invalid statistics directory, sampling interval, or retention period",
    ),
    (
        "统计目录包含其他应用数据库",
        "The statistics directory contains another application's database",
    ),
    (
        "统计目录不能为空或包含上级路径",
        "The statistics directory must not be empty or contain parent-directory components",
    ),
    (
        "统计目录及文件必须为普通私有路径",
        "Statistics directories and files must be regular private paths",
    ),
    (
        "统计目录已有写者",
        "The statistics directory already has a writer",
    ),
    (
        "历史记录必须在流量开始前且仅启用一次",
        "History recording must be enabled exactly once before any flows start",
    ),
];

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn language_is_explicit_and_nested_causes_keep_their_details() {
        let error = Error::Startup {
            primary: Box::new(Error::Config("出站标签重复".into())),
            cleanup_timed_out: true,
            cleanup_failures: 2,
        };
        assert_eq!(error.code(), "startup.failed");
        assert!(
            error
                .localized(Language::En)
                .to_string()
                .contains("Duplicate outbound tag")
        );
        assert!(
            error
                .localized(Language::En)
                .to_string()
                .contains("cleanup_failures=2")
        );
        assert_eq!(
            error.localized(Language::ZhCn).to_string(),
            error.to_string()
        );
        let unknown = Error::Config("尚未收录的具体原因".into());
        assert!(
            unknown
                .localized(Language::En)
                .to_string()
                .contains("[untranslated detail] 尚未收录的具体原因")
        );
        let typed = Error::Io(std::io::Error::other(Error::Timeout));
        assert_eq!(
            typed.localized(Language::En).to_string(),
            "I/O failed: Operation timed out"
        );
        let wrapped = Error::Io(std::io::Error::other(
            "unexpected error: ShadowTLS ClientHello 不合法",
        ));
        assert_eq!(
            wrapped.localized(Language::En).to_string(),
            "I/O failed: unexpected error: Invalid ShadowTLS ClientHello"
        );
        assert_eq!(Language::from_locale("zh_CN.UTF-8"), Language::ZhCn);
        assert_eq!(Language::from_locale("C.UTF-8"), Language::En);
        let prepared = Error::Config(format!(
            "WARP准备失败：{}",
            Error::Config("WARP状态目录须有可信祖先、私有权限及唯一写者".into())
        ));
        let rendered = prepared.localized(Language::En).to_string();
        assert!(rendered.contains("WARP preparation failed: Invalid configuration: "));
        assert!(rendered.contains("trusted ancestors"));
        assert!(!rendered.contains("untranslated detail"));
        let http = Error::Config("WARP注册HTTP状态503；保留注册意图，不自动重试".into());
        assert_eq!(
            http.localized(Language::En).to_string(),
            "Invalid configuration: WARP registration HTTP status 503; the registration intent is retained without automatic retry"
        );
    }
}
