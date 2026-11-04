use super::Args;
use clap::{
    Arg, ArgAction, Command, CommandFactory, FromArgMatches,
    error::{ContextKind, ContextValue, ErrorKind},
};
use kerlico_core::Language;
use std::error::Error as _;
use std::ffi::OsString;

fn environment_language() -> Language {
    ["LC_ALL", "LC_MESSAGES", "LANG"]
        .into_iter()
        .filter_map(|name| std::env::var(name).ok())
        .find(|value| !value.is_empty())
        .map_or(Language::En, |value| Language::from_locale(&value))
}
pub(super) fn language_from_args(raw: &[OsString]) -> Language {
    let mut language = environment_language();
    let mut arguments = raw.iter().skip(1);
    while let Some(argument) = arguments.next() {
        if argument == "--" {
            break;
        }
        let value = if argument == "--lang" {
            arguments.next().and_then(|value| value.to_str())
        } else {
            argument
                .to_str()
                .and_then(|value| value.strip_prefix("--lang="))
        };
        if let Some(selected) = value.and_then(Language::parse) {
            language = selected;
        }
    }
    language
}
pub(super) fn command(language: Language) -> Command {
    let mut command = Args::command()
        .disable_help_subcommand(true)
        .disable_help_flag(true)
        .disable_version_flag(true)
        .about(language.select("模块化代理内核", "Modular client and server proxy core"))
        .mut_arg("lang", |argument| {
            argument.hide_possible_values(true).help(language.select(
                "界面语言（zh-CN/en）；默认读取 LC_ALL、LC_MESSAGES、LANG",
                "Interface language (zh-CN/en); defaults to LC_ALL, LC_MESSAGES, then LANG",
            ))
        })
        .arg(
            Arg::new("help")
                .short('h')
                .long("help")
                .action(ArgAction::Help)
                .help(language.select("显示帮助", "Print help")),
        )
        .arg(
            Arg::new("version")
                .short('V')
                .long("version")
                .action(ArgAction::Version)
                .help(language.select("显示版本", "Print version")),
        );
    if language == Language::ZhCn {
        command = command.help_template("{name} {version}\n{about-with-newline}\n用法：{usage}\n\n命令：\n{subcommands}\n选项：\n{options}\n{after-help}");
    }
    for subcommand in command.get_subcommands_mut() {
        let about = match subcommand.get_name() {
            "help" => language.select("显示全部或指定命令的帮助。", "Print help for all commands or one command."),
            "account-new" => language.select("从标准输入读取管理密码，输出持久账户 JSON。", "Read a management password from standard input and print a persistent account as JSON."),
            "modules" => language.select("按角色列出当前构建真实注册的模块。", "List the modules registered in this build, grouped by role."),
            "check" => language.select("校验配置和模块能力，不监听或拨号。", "Validate configuration and module capabilities without listening or dialing."),
            "run" => language.select("启动客户端转发入口与服务端节点。", "Start client forwarding inbounds and server nodes."),
            "history" => language.select("只读查询统计历史，输出 JSON。", "Query statistics history read-only and print JSON."),
            "generate" => language.select("生成 UUID、随机串与各类协议密钥对。", "Generate UUIDs, random strings, and protocol keypairs."),
            "tls" => language.select("生成自签名 TLS 证书或计算证书哈希。", "Generate self-signed TLS certificates or compute certificate hashes."),
            "xray" => language.select("兼容 Xray 工具链的密钥与加密参数生成命令。", "Xray-compatible keypair and encryption generator subcommands."),
            "format" => language.select("格式化配置文件。", "Format configuration files."),
            "merge" => language.select("合并多个配置文件或配置目录。", "Merge multiple configuration files or directories."),
            "rule-set" => language.select("编译、反编译、转换、匹配与合并规则集。", "Compile, decompile, convert, match, and merge rule-sets."),
            "geoip" => language.select("查询、列出或导出 GeoIP 数据库。", "Query, list, or export GeoIP databases."),
            "geosite" => language.select("查询、列出或导出 Geosite 数据库。", "Query, list, or export Geosite databases."),
            "tools" => language.select("网络连通性、STUN、测速与时间同步工具集。", "Network connectivity, STUN, quality, and time sync tools."),
            _ => continue,
        };
        let mut localized = subcommand.clone().about(about).disable_help_flag(true).arg(
            Arg::new("help")
                .short('h')
                .long("help")
                .action(ArgAction::Help)
                .help(language.select("显示帮助", "Print help")),
        );
        if localized.has_subcommands() {
            localized = localized.disable_help_subcommand(true);
        }
        if language == Language::ZhCn {
            let template = if localized.get_name() == "help" {
                "{about-with-newline}\n用法：{usage}\n\n参数：\n{positionals}\n选项：\n{options}\n{after-help}"
            } else if localized.has_subcommands() {
                "{about-with-newline}\n用法：{usage}\n\n命令：\n{subcommands}\n选项：\n{options}\n{after-help}"
            } else {
                "{about-with-newline}\n用法：{usage}\n\n选项：\n{options}\n{after-help}"
            };
            localized = localized.help_template(template);
        }
        if matches!(localized.get_name(), "check" | "run") {
            localized = localized.mut_arg("config", |argument| {
                argument.help(language.select("配置 v2 JSON 文件", "Configuration v2 JSON file"))
            });
        } else if localized.get_name() == "history" {
            for (name, chinese, english) in [
                (
                    "directory",
                    "统计历史目录（默认 state/telemetry）",
                    "Statistics directory (default: state/telemetry)",
                ),
                (
                    "kind",
                    "查询类型（usage/flows/bandwidth/events；默认 usage）",
                    "Query type (usage/flows/bandwidth/events; default: usage)",
                ),
                ("user", "用户 UUID 筛选", "Filter by user UUID"),
                ("node", "节点标识筛选", "Filter by node ID"),
                (
                    "outbound",
                    "命名出站标识筛选",
                    "Filter by named outbound ID",
                ),
                (
                    "since_ms",
                    "起始 Unix 毫秒（默认 0）",
                    "Starting Unix milliseconds (default: 0)",
                ),
                (
                    "after",
                    "排除已读游标（默认 0）",
                    "Exclude cursors already read (default: 0)",
                ),
                (
                    "limit",
                    "每页条数（1 至 4096；默认 1000）",
                    "Rows per page (1 to 4096; default: 1000)",
                ),
            ] {
                localized = localized.mut_arg(name, |argument| {
                    argument
                        .hide_default_value(true)
                        .hide_possible_values(true)
                        .help(language.select(chinese, english))
                });
            }
            localized = localized
                .mut_arg("since_ms", |argument| {
                    argument.value_parser(clap::builder::ValueParser::new(move |value: &str| {
                        value.parse::<u64>().map_err(|_| {
                            language.select(
                                "必须是 0 至 18446744073709551615 的整数",
                                "Must be an integer from 0 to 18446744073709551615",
                            )
                        })
                    }))
                })
                .mut_arg("after", |argument| {
                    argument.value_parser(clap::builder::ValueParser::new(move |value: &str| {
                        value
                            .parse::<i64>()
                            .ok()
                            .filter(|value| *value >= 0)
                            .ok_or_else(|| {
                                language.select(
                                    "必须是 0 至 9223372036854775807 的整数",
                                    "Must be an integer from 0 to 9223372036854775807",
                                )
                            })
                    }))
                })
                .mut_arg("limit", |argument| {
                    argument.value_parser(clap::builder::ValueParser::new(move |value: &str| {
                        value
                            .parse::<usize>()
                            .ok()
                            .filter(|value| (1..=4096).contains(value))
                            .ok_or_else(|| {
                                language.select(
                                    "必须是 1 至 4096 的整数",
                                    "Must be an integer from 1 to 4096",
                                )
                            })
                    }))
                });
        } else if localized.get_name() == "account-new" {
            localized = localized.mut_arg("prefix", |argument| {
                argument.hide_default_value(true).help(language.select(
                    "生成用户名前缀（默认 user）",
                    "Prefix used to generate the username (default: user)",
                ))
            });
        } else if localized.get_name() == "help" {
            localized = localized.mut_arg("command", |argument| {
                argument.help(language.select(
                    "要查看的命令；省略时列出全部命令",
                    "Command to inspect; omit to list all commands",
                ))
            });
        }
        *subcommand = localized;
    }
    command.build();
    command
}
pub(super) fn parse_args(raw: &[OsString], language: Language) -> Result<Args, clap::Error> {
    let mut command = command(language);
    let matches = command.try_get_matches_from_mut(raw)?;
    let mut args = Args::from_arg_matches(&matches)?;
    if let super::Command::Generate { target, .. } = &mut args.command
        && target == "uuid"
    {
        for os in raw.iter().skip(1) {
            if let Some(s) = os.to_str()
                && s.starts_with("generate-")
            {
                *target = s.to_owned();
                break;
            }
        }
    }
    if let super::Command::Help {
        command: Some(name),
    } = &args.command
        && command.find_subcommand(name).is_none()
    {
        let mut error = clap::Error::new(ErrorKind::InvalidSubcommand).with_cmd(&command);
        error.insert(
            ContextKind::InvalidSubcommand,
            ContextValue::String(name.clone()),
        );
        error.insert(
            ContextKind::ValidSubcommand,
            ContextValue::Strings(
                command
                    .get_subcommands()
                    .map(|command| command.get_name().to_owned())
                    .collect(),
            ),
        );
        return Err(error);
    }
    Ok(args)
}
pub(super) fn render_error(error: &clap::Error, language: Language) -> String {
    if matches!(
        error.kind(),
        ErrorKind::DisplayHelp
            | ErrorKind::DisplayVersion
            | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
    ) {
        return error.to_string();
    }
    let (code, summary) = match error.kind() {
        ErrorKind::UnknownArgument => ("cli.unknown_argument", "无法识别参数"),
        ErrorKind::InvalidSubcommand => ("cli.invalid_subcommand", "无法识别命令"),
        ErrorKind::MissingSubcommand => ("cli.missing_subcommand", "必须指定命令"),
        ErrorKind::MissingRequiredArgument => ("cli.missing_argument", "缺少必需参数"),
        ErrorKind::ArgumentConflict => ("cli.argument_conflict", "参数不能同时使用"),
        ErrorKind::InvalidValue | ErrorKind::ValueValidation => {
            ("cli.invalid_value", "参数值不合法")
        }
        ErrorKind::TooManyValues => ("cli.too_many_values", "参数值数量过多"),
        ErrorKind::TooFewValues => ("cli.too_few_values", "参数值数量不足"),
        ErrorKind::InvalidUtf8 => ("cli.invalid_encoding", "参数不是有效 UTF-8 文本"),
        ErrorKind::NoEquals => ("cli.missing_equals", "该参数的值必须使用等号指定"),
        _ => ("cli.invalid_arguments", "命令行参数不合法"),
    };
    if language == Language::En {
        return format!("[{code}] {error}");
    }
    let mut result = format!("错误 [{code}]：{summary}\n");
    for (kind, value) in error.context() {
        let label = match kind {
            ContextKind::InvalidArg => "参数",
            ContextKind::InvalidSubcommand => "命令",
            ContextKind::PriorArg => "先前参数",
            ContextKind::ValidSubcommand => "可用命令",
            ContextKind::ValidValue => "可用值",
            ContextKind::InvalidValue => "收到的值",
            ContextKind::ActualNumValues => "实际值数量",
            ContextKind::ExpectedNumValues => "预期值数量",
            ContextKind::MinValues => "最少值数量",
            ContextKind::SuggestedCommand | ContextKind::SuggestedSubcommand => "建议命令",
            ContextKind::SuggestedArg => "建议参数",
            ContextKind::SuggestedValue => "建议值",
            ContextKind::TrailingArg => "尾部参数",
            ContextKind::Suggested => "建议",
            ContextKind::Custom => "详情",
            ContextKind::Usage => {
                let usage = value.to_string();
                result.push_str(&format!(
                    "\n用法：{}\n",
                    usage.strip_prefix("Usage: ").unwrap_or(&usage)
                ));
                continue;
            }
            _ => "详情",
        };
        result.push_str(&format!("  {label}：{value}\n"));
    }
    if let Some(source) = error.source() {
        result.push_str(&format!("  详情：{source}\n"));
    }
    result.push_str("\n使用 --help 查看帮助。\n");
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    fn arguments(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }
    #[test]
    fn global_language_selects_help_errors_and_preserves_values() {
        let chinese = command(Language::ZhCn)
            .try_get_matches_from(["kerlico", "check", "--help"])
            .unwrap_err();
        assert!(render_error(&chinese, Language::ZhCn).contains("配置 v2 JSON 文件"));
        let english = command(Language::En)
            .try_get_matches_from(["kerlico", "check", "--help"])
            .unwrap_err();
        assert!(render_error(&english, Language::En).contains("Configuration v2 JSON file"));
        let error = command(Language::ZhCn)
            .try_get_matches_from(["kerlico", "--unknown-option"])
            .unwrap_err();
        let rendered = render_error(&error, Language::ZhCn);
        assert!(rendered.contains("无法识别参数"));
        assert!(rendered.contains("--unknown-option"));
        assert_eq!(
            language_from_args(&arguments(&["kerlico", "check", "--lang=en"])),
            Language::En
        );
        assert_eq!(
            language_from_args(&arguments(&[
                "kerlico",
                "--lang",
                "zh-CN",
                "--",
                "--lang=en"
            ])),
            Language::ZhCn
        );
    }
}
