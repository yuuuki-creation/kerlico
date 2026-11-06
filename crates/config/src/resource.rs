//! 落盘资源（proxy-provider、规则集、Geo 数据库）的缓存位置、下载规格与内容校验。

use crate::{CompiledRuleSet, GeoIpDat, GeoSiteDat, RuleSetSource, parse_subscription_content};
use kerlico_core::{Error, OutId, Result};
use std::{fmt, path::PathBuf, time::Duration};

/// 未配置 `size-limit` 或配置为 0 时的下载上限。
pub const DEFAULT_SIZE_LIMIT: u64 = 64 * 1024 * 1024;

/// Geo 数据库文件；默认缓存名与 Mihomo 工作目录下的文件名一致。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum GeoFile {
    GeoIp,
    GeoSite,
    Mmdb,
    Asn,
}

impl GeoFile {
    pub const ALL: [Self; 4] = [Self::GeoIp, Self::GeoSite, Self::Mmdb, Self::Asn];

    pub fn name(self) -> &'static str {
        match self {
            Self::GeoIp => "geoip",
            Self::GeoSite => "geosite",
            Self::Mmdb => "mmdb",
            Self::Asn => "asn",
        }
    }

    pub fn default_path(self) -> PathBuf {
        PathBuf::from(match self {
            Self::GeoIp => "GeoIP.dat",
            Self::GeoSite => "GeoSite.dat",
            Self::Mmdb => "Country.mmdb",
            Self::Asn => "GeoLite2-ASN.mmdb",
        })
    }

    fn validate(self, bytes: &[u8]) -> Result<()> {
        let valid = match self {
            Self::GeoIp => !GeoIpDat::parse(bytes)?.is_empty(),
            Self::GeoSite => !GeoSiteDat::parse(bytes)?.is_empty(),
            Self::Mmdb | Self::Asn => bytes
                .windows(MMDB_METADATA_MARKER.len())
                .any(|w| w == MMDB_METADATA_MARKER),
        };
        if valid {
            Ok(())
        } else {
            Err(Error::Config(format!(
                "{} 数据库内容为空或格式不符",
                self.name()
            )))
        }
    }
}

const MMDB_METADATA_MARKER: &[u8] = b"\xAB\xCD\xEFMaxMind.com";

/// 资源的身份：控制接口按它触发刷新，状态按它登记。
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ResourceKey {
    ProxyProvider(String),
    RuleSet(String),
    Geo(GeoFile),
}

impl fmt::Display for ResourceKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProxyProvider(name) => write!(f, "proxy-provider {name}"),
            Self::RuleSet(tag) => write!(f, "rule-set {tag}"),
            Self::Geo(file) => write!(f, "geo {}", file.name()),
        }
    }
}

/// 资源内容如何校验与生效。
#[derive(Clone, Debug)]
pub enum ResourceKind {
    /// 成员在配置准备时编译为命名出站，内容变化须重建引擎代际。
    ProxyProvider(String),
    /// 内容编译后换入路由表的规则集槽；`required` 表示被路由规则引用。
    RuleSet {
        source: RuleSetSource,
        required: bool,
    },
    /// 只落盘；运行时 GeoIP/GeoSite 匹配尚不读取这些文件。
    Geo(GeoFile),
}

/// 下载来源：`interval` 为零时只在缓存缺失时下载，`detour` 为空时直连。
#[derive(Clone, Debug)]
pub struct Download {
    pub url: String,
    pub interval: Duration,
    pub detour: Option<OutId>,
    pub headers: Vec<(String, String)>,
    pub size_limit: u64,
}

/// 一项落盘资源；`download` 为空时只读本地文件。
#[derive(Clone, Debug)]
pub struct ResourceSpec {
    pub kind: ResourceKind,
    pub path: PathBuf,
    pub download: Option<Download>,
}

/// 校验通过的内容；规则集带上编译结果，供直接换入。
pub enum Accepted {
    RuleSet(CompiledRuleSet),
    Members(usize),
    Geo,
}

impl ResourceSpec {
    pub fn key(&self) -> ResourceKey {
        match &self.kind {
            ResourceKind::ProxyProvider(name) => ResourceKey::ProxyProvider(name.clone()),
            ResourceKind::RuleSet { source, .. } => ResourceKey::RuleSet(source.tag.clone()),
            ResourceKind::Geo(file) => ResourceKey::Geo(*file),
        }
    }

    /// 写入缓存前校验内容；校验失败的下载不覆盖已有缓存。
    pub fn accept(&self, bytes: &[u8]) -> Result<Accepted> {
        match &self.kind {
            ResourceKind::ProxyProvider(name) => {
                let text = std::str::from_utf8(bytes)
                    .map_err(|_| Error::Config(format!("proxy-provider {name} 内容不是 UTF-8")))?;
                let members = parse_subscription_content(text)?.len();
                if members == 0 {
                    return Err(Error::Config(format!(
                        "proxy-provider {name} 内容没有可用节点"
                    )));
                }
                Ok(Accepted::Members(members))
            }
            ResourceKind::RuleSet { source, .. } => {
                Ok(Accepted::RuleSet(source.compile(Some(bytes))?))
            }
            ResourceKind::Geo(file) => file.validate(bytes).map(|()| Accepted::Geo),
        }
    }
}

/// `proxy`、`detour`、`download_detour` 写 `DIRECT`/`direct` 或留空都表示直连下载。
pub(crate) fn download_detour(raw: Option<&str>) -> Result<Option<OutId>> {
    match raw.map(str::trim) {
        None | Some("") => Ok(None),
        Some(name) if name.eq_ignore_ascii_case("direct") => Ok(None),
        Some(name) => OutId::parse(name).map(Some),
    }
}

pub(crate) fn size_limit(raw: Option<u64>) -> u64 {
    raw.filter(|limit| *limit > 0).unwrap_or(DEFAULT_SIZE_LIMIT)
}

/// 读缓存或本地文件；文件不存在返回 `None`，其他读取错误照常返回。
pub(crate) fn read_cached(path: &std::path::Path) -> Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(Error::Io(error)),
    }
}
