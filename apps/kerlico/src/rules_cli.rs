//! `rule-set`、`geoip`、`geosite` 子命令：在 sing-box 源格式/`.srs` 与 Mihomo yaml/text/`.mrs`
//! 之间转换，查询与导出 V2Ray `.dat` 和 MaxMind `.mmdb` 数据库。

use clap::Subcommand;
use kerlico_core::{Error, Result};
use kerlico_routing::{
    Behavior, GeoSiteRef, SourceRuleSetFile, compile_ruleset_to_mrs, compile_ruleset_to_srs,
    convert_adguard_lines, decompile_with_behavior,
    domain_set::DomainSetBuilder,
    geodata::{self, compile_ips, compile_sites, dat_entries, ip_entry, is_mmdb, site_items},
    mmdb::Mmdb,
    parse_ruleset_bytes, ruleset_to_mihomo_lines,
};
use std::path::{Path, PathBuf};

#[derive(Subcommand)]
pub(crate) enum RuleSetCommand {
    /// 编译为二进制规则集：输出扩展名为 `.mrs` 或 `-t mrs` 时写 Mihomo 格式，否则写 sing-box `.srs`。
    Compile {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(short = 't', long = "type")]
        kind: Option<String>,
        /// 输入为 Mihomo yaml/text 时的 behavior：domain、ipcidr 或 classical。
        #[arg(long)]
        behavior: Option<String>,
    },
    /// 任意支持格式转为 sing-box 源格式 JSON。
    Decompile {
        input: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long)]
        behavior: Option<String>,
    },
    /// 格式互转：输入按内容识别（`-t adguard` 读 AdGuard 过滤规则），输出按 `-o` 扩展名
    /// （`.srs`、`.mrs`、`.yaml`、`.txt`/`.list`、`.json`）或 `--to`。
    Convert {
        input: PathBuf,
        #[arg(short = 't', long = "type", default_value = "auto")]
        kind: String,
        #[arg(long)]
        to: Option<String>,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long)]
        behavior: Option<String>,
    },
    Format {
        input: PathBuf,
        #[arg(short, long)]
        write: bool,
    },
    /// 对一个或多个域名/IP 测试是否命中，每个目标输出一行 JSON。
    Match {
        rule_set: PathBuf,
        #[arg(required = true)]
        targets: Vec<String>,
        #[arg(short, long)]
        format: Option<String>,
        #[arg(long)]
        behavior: Option<String>,
    },
    Merge {
        output: Option<PathBuf>,
        #[arg(short, long)]
        config: Vec<PathBuf>,
        #[arg(short = 'C', long = "config-directory", alias = "confdir")]
        config_directory: Vec<PathBuf>,
    },
    Upgrade {
        input: PathBuf,
        #[arg(short, long)]
        write: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum GeoCommand {
    /// 列出数据库中的全部分类代码（`.dat`）。
    List,
    /// 查询目标所属分类；`--code` 只检查一个分类（GeoSite 可写 `cn@cn`、`!cn`）。
    Lookup {
        #[arg(required = true)]
        targets: Vec<String>,
        #[arg(long)]
        code: Option<String>,
    },
    /// 把一个分类导出为规则集，输出格式按 `-o` 扩展名。
    Export {
        code: String,
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

fn behavior(raw: Option<&str>) -> Result<Option<Behavior>> {
    raw.map(Behavior::parse).transpose()
}

fn load(input: &Path, behavior_raw: Option<&str>) -> Result<SourceRuleSetFile> {
    let bytes = std::fs::read(input)?;
    decompile_with_behavior(&bytes, behavior(behavior_raw)?)
}

fn json(source: &SourceRuleSetFile) -> Result<String> {
    serde_json::to_string_pretty(source)
        .map(|text| format!("{text}\n"))
        .map_err(|_| Error::Config("规则集序列化失败".into()))
}

/// 按目标格式写出；`kind` 缺省时取输出扩展名，都没有时输出 JSON。
fn write_ruleset(
    source: &SourceRuleSetFile,
    output: Option<&Path>,
    kind: Option<&str>,
) -> Result<()> {
    let kind = kind
        .map(str::to_ascii_lowercase)
        .or_else(|| {
            output
                .and_then(|p| p.extension())
                .and_then(|e| e.to_str())
                .map(str::to_ascii_lowercase)
        })
        .unwrap_or_else(|| "json".into());
    let bytes = match kind.as_str() {
        "srs" | "binary" => compile_ruleset_to_srs(source)?,
        "mrs" => compile_ruleset_to_mrs(source)?,
        "yaml" | "yml" => {
            let (_, lines) = ruleset_to_mihomo_lines(source)?;
            let mut text = String::from("payload:\n");
            for line in lines {
                text.push_str(&format!("  - '{}'\n", line.replace('\'', "''")));
            }
            text.into_bytes()
        }
        "text" | "txt" | "list" => {
            let (_, lines) = ruleset_to_mihomo_lines(source)?;
            lines
                .iter()
                .map(|l| format!("{l}\n"))
                .collect::<String>()
                .into_bytes()
        }
        "json" | "source" => json(source)?.into_bytes(),
        other => return Err(Error::Config(format!("不支持的输出格式：{other}"))),
    };
    match output {
        Some(path) => std::fs::write(path, bytes)?,
        None => {
            use std::io::Write;
            std::io::stdout().write_all(&bytes)?;
        }
    }
    Ok(())
}

pub(crate) fn run_ruleset_cmd(action: RuleSetCommand) -> Result<()> {
    match action {
        RuleSetCommand::Compile {
            input,
            output,
            kind,
            behavior,
        } => {
            let source = load(&input, behavior.as_deref())?;
            let kind = kind.unwrap_or_else(|| {
                match output
                    .as_ref()
                    .and_then(|p| p.extension())
                    .and_then(|e| e.to_str())
                {
                    Some(ext) if ext.eq_ignore_ascii_case("mrs") => "mrs".into(),
                    _ => "srs".into(),
                }
            });
            let out = output.unwrap_or_else(|| input.with_extension(&kind));
            write_ruleset(&source, Some(&out), Some(&kind))
        }
        RuleSetCommand::Decompile {
            input,
            output,
            behavior,
        } => write_ruleset(
            &load(&input, behavior.as_deref())?,
            output.as_deref(),
            Some("json"),
        ),
        RuleSetCommand::Convert {
            input,
            kind,
            to,
            output,
            behavior,
        } => {
            let source = if kind.eq_ignore_ascii_case("adguard") {
                convert_adguard_lines(&std::fs::read_to_string(&input)?)?
            } else if kind.eq_ignore_ascii_case("auto") {
                load(&input, behavior.as_deref())?
            } else {
                return Err(Error::Config(
                    "convert --type 仅支持 auto 或 adguard".into(),
                ));
            };
            write_ruleset(&source, output.as_deref(), to.as_deref())
        }
        RuleSetCommand::Format { input, write } => {
            let text = json(&load(&input, None)?)?;
            if write {
                std::fs::write(&input, text)?;
            } else {
                print!("{text}");
            }
            Ok(())
        }
        RuleSetCommand::Match {
            rule_set,
            targets,
            format,
            behavior,
        } => {
            let bytes = std::fs::read(&rule_set)?;
            let rules = parse_ruleset_bytes(&bytes, format.as_deref(), behavior.as_deref())?;
            let set = kerlico_routing::CompiledRuleSet {
                tag: String::new(),
                rules,
            };
            for target in targets {
                let (hosts, ips): (Vec<&str>, Vec<std::net::IpAddr>) = match target.parse() {
                    Ok(ip) => (Vec::new(), vec![ip]),
                    Err(_) => (vec![target.as_str()], Vec::new()),
                };
                let matched = set.matches(&hosts, &ips, 443, kerlico_routing::Network::Tcp, None);
                println!(
                    "{}",
                    serde_json::json!({ "target": target, "matched": matched })
                );
            }
            Ok(())
        }
        RuleSetCommand::Merge {
            output,
            config,
            config_directory,
        } => {
            let mut files = config;
            for dir in config_directory {
                let mut paths: Vec<PathBuf> = std::fs::read_dir(dir)?
                    .filter_map(|e| e.ok().map(|d| d.path()))
                    .filter(|p| p.is_file())
                    .collect();
                paths.sort();
                files.extend(paths);
            }
            let mut merged = SourceRuleSetFile {
                version: 2,
                rules: Vec::new(),
            };
            for file in files {
                let source = load(&file, None)?;
                merged.version = merged.version.max(source.version);
                merged.rules.extend(source.rules);
            }
            write_ruleset(&merged, output.as_deref(), None)
        }
        RuleSetCommand::Upgrade { input, write } => {
            let mut source = load(&input, None)?;
            source.version = source.version.max(2);
            let text = json(&source)?;
            if write {
                std::fs::write(&input, text)?;
            } else {
                print!("{text}");
            }
            Ok(())
        }
    }
}

fn geo_file(is_geoip: bool, file: Option<&Path>) -> Result<Vec<u8>> {
    let path = match file {
        Some(path) => path.to_path_buf(),
        None if is_geoip && Path::new("Country.mmdb").exists() => PathBuf::from("Country.mmdb"),
        None if is_geoip => PathBuf::from("GeoIP.dat"),
        None => PathBuf::from("GeoSite.dat"),
    };
    std::fs::read(&path)
        .map_err(|error| Error::Config(format!("无法读取 {}：{error}", path.display())))
}

pub(crate) fn run_geo_cmd(is_geoip: bool, file: Option<&Path>, action: GeoCommand) -> Result<()> {
    let bytes = geo_file(is_geoip, file)?;
    match action {
        GeoCommand::List => {
            if is_mmdb(&bytes) {
                return Err(Error::Config(
                    "mmdb 数据库没有分类列表，请用 .dat 文件".into(),
                ));
            }
            let mut codes: Vec<String> = dat_entries(&bytes)?.into_iter().map(|(c, _)| c).collect();
            codes.sort();
            codes.dedup();
            for code in codes {
                println!("{code}");
            }
            Ok(())
        }
        GeoCommand::Lookup { targets, code } if is_geoip => {
            geoip_lookup(bytes, &targets, code.as_deref())
        }
        GeoCommand::Lookup { targets, code } => geosite_lookup(&bytes, &targets, code.as_deref()),
        GeoCommand::Export { code, output } => {
            let source = if is_geoip {
                geodata::export_geoip_ruleset(&bytes, &code)?
            } else {
                geodata::export_geosite_ruleset(&bytes, &code)?
            };
            write_ruleset(&source, output.as_deref(), None)
        }
    }
}

fn geoip_lookup(bytes: Vec<u8>, targets: &[String], code: Option<&str>) -> Result<()> {
    let ips = targets
        .iter()
        .map(|t| {
            t.parse::<std::net::IpAddr>()
                .map_err(|_| Error::Config(format!("GeoIP 查询目标须为 IP 地址：{t}")))
        })
        .collect::<Result<Vec<_>>>()?;
    let code = code.map(|c| c.trim().to_ascii_lowercase());
    if is_mmdb(&bytes) {
        let db = Mmdb::parse(bytes)?;
        let asn = db.check_asn().is_ok();
        for (target, ip) in targets.iter().zip(ips) {
            if asn {
                let (number, org) = db.asn(ip)?.unwrap_or_default();
                println!(
                    "{}",
                    serde_json::json!({ "ip": target, "asn": number, "organization": org })
                );
            } else {
                let mut codes = db.country_codes(ip)?;
                if let Some(code) = &code {
                    codes.retain(|c| c == code);
                }
                println!("{}", serde_json::json!({ "ip": target, "codes": codes }));
            }
        }
        return Ok(());
    }
    let sets: Vec<(String, kerlico_routing::IpSet, bool)> = match &code {
        Some(code) => compile_ips(&bytes, &[code.as_str()])?
            .into_iter()
            .map(|(c, (s, r))| (c, s, r))
            .collect(),
        None => dat_entries(&bytes)?
            .into_iter()
            .map(|(c, msg)| ip_entry(msg).map(|(s, r)| (c, s, r)))
            .collect::<Result<_>>()?,
    };
    for (target, ip) in targets.iter().zip(ips) {
        let mut codes: Vec<&str> = sets
            .iter()
            .filter(|(_, set, reverse)| set.contains(ip) != *reverse)
            .map(|(c, _, _)| c.as_str())
            .collect();
        codes.sort_unstable();
        codes.dedup();
        println!("{}", serde_json::json!({ "ip": target, "codes": codes }));
    }
    Ok(())
}

fn geosite_lookup(bytes: &[u8], targets: &[String], code: Option<&str>) -> Result<()> {
    let hosts: Vec<String> = targets
        .iter()
        .map(|t| t.trim().trim_end_matches('.').to_ascii_lowercase())
        .collect();
    let mut hits: Vec<Vec<String>> = vec![Vec::new(); hosts.len()];
    match code {
        Some(code) => {
            let site = GeoSiteRef::parse(code)?;
            let sets = compile_sites(bytes, &[&site])?;
            let set = &sets[site.key()];
            for (host, hit) in hosts.iter().zip(&mut hits) {
                if set.matches(host) != site.negate {
                    hit.push(code.to_owned());
                }
            }
        }
        None => {
            for (list, msg) in dat_entries(bytes)? {
                let mut builder = DomainSetBuilder::default();
                for item in site_items(msg)? {
                    builder.insert(item.rule);
                }
                let set = builder.build()?;
                for (host, hit) in hosts.iter().zip(&mut hits) {
                    if set.matches(host) && !hit.contains(&list) {
                        hit.push(list.clone());
                    }
                }
            }
        }
    }
    for (target, mut codes) in targets.iter().zip(hits) {
        codes.sort();
        println!(
            "{}",
            serde_json::json!({ "domain": target, "codes": codes })
        );
    }
    Ok(())
}
