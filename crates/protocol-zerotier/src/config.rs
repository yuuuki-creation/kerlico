use kerlico_core::{Error, Result};
use serde::Deserialize;
use std::{
    fs,
    io::{ErrorKind, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
};
use zerotier_node::{Address, Identity, NodeOptions, Seed, default_planet_roots};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClientOptions {
    network: String,
    #[serde(default)]
    identity: Option<String>,
    #[serde(default)]
    identity_file: Option<PathBuf>,
    #[serde(default)]
    roots: Vec<SeedOptions>,
    #[serde(default)]
    peers: Vec<SeedOptions>,
    #[serde(default)]
    public_planet: bool,
    #[serde(default)]
    pub bind: Option<SocketAddr>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SeedOptions {
    identity: String,
    endpoints: Vec<SocketAddr>,
}

pub(crate) enum IdentitySource {
    Inline(Identity),
    File(PathBuf),
}

/// 已通过语法校验的配置。工作量校验较慢，留到启动时在阻塞线程执行。
pub(crate) struct Prepared {
    pub network_id: u64,
    pub identity: IdentitySource,
    pub roots: Vec<Seed>,
    pub peers: Vec<Seed>,
    pub bind: Option<SocketAddr>,
}

fn parse_seeds(seeds: Vec<SeedOptions>) -> Result<Vec<Seed>> {
    seeds
        .into_iter()
        .map(|seed| {
            let identity = Identity::parse(&seed.identity)
                .ok()
                .filter(|identity| !identity.has_secret())
                .ok_or_else(|| Error::Config("ZeroTier种子节点配置不合法".into()))?;
            if seed.endpoints.is_empty()
                || seed
                    .endpoints
                    .iter()
                    .any(|endpoint| endpoint.port() == 0 || endpoint.ip().is_unspecified())
            {
                return Err(Error::Config("ZeroTier种子节点配置不合法".into()));
            }
            Ok(Seed {
                identity,
                endpoints: seed.endpoints,
            })
        })
        .collect()
}

impl ClientOptions {
    pub(crate) fn prepare(self) -> Result<Prepared> {
        let network_id = parse_network_id(&self.network)?;
        let identity = match (self.identity, self.identity_file) {
            (Some(value), None) => {
                let identity = Identity::parse(&value)
                    .map_err(|_| Error::Config("ZeroTier身份格式不合法".into()))?;
                if !identity.has_secret() {
                    return Err(Error::Config("ZeroTier身份缺少私钥".into()));
                }
                IdentitySource::Inline(identity)
            }
            (None, Some(path)) if !path.as_os_str().is_empty() => IdentitySource::File(path),
            _ => {
                return Err(Error::Config(
                    "ZeroTier身份必须且只能配置identity或identity_file之一".into(),
                ));
            }
        };
        let mut roots = parse_seeds(self.roots)?;
        if self.public_planet {
            roots.extend(default_planet_roots());
        }
        let peers = parse_seeds(self.peers)?;
        let controller = Address::controller_of(network_id);
        if roots.is_empty()
            && !peers
                .iter()
                .any(|seed| seed.identity.address() == controller)
        {
            return Err(Error::Config(
                "ZeroTier至少需要一个根节点或能直达控制器的对端".into(),
            ));
        }
        if self
            .bind
            .is_some_and(|bind| bind.ip().is_multicast() || bind.ip().to_canonical() != bind.ip())
        {
            return Err(Error::Config("ZeroTier载体绑定地址不合法".into()));
        }
        Ok(Prepared {
            network_id,
            identity,
            roots,
            peers,
            bind: self.bind,
        })
    }
}

fn parse_network_id(value: &str) -> Result<u64> {
    let invalid = || Error::Config("ZeroTier网络ID必须是16位十六进制，且不能是临时网络".into());
    if value.len() != 16 {
        return Err(invalid());
    }
    let id = u64::from_str_radix(value, 16).map_err(|_| invalid())?;
    if id >> 56 == 0xff || Address::controller_of(id).is_reserved() {
        return Err(invalid());
    }
    Ok(id)
}

/// 崩溃不能留下残缺的身份文件：内容写入并落盘后才出现在目标路径。硬链接在目标已存在时失败，
/// 并发启动的另一方因此不会覆盖先写入的身份；不支持硬链接的文件系统退回 rename。
/// 返回 false 表示目标已被占用。
fn publish_secret(path: &Path, temporary: &Path, text: &str) -> std::io::Result<bool> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(temporary)?;
    file.write_all(text.as_bytes())?;
    file.sync_all()?;
    drop(file);
    let published = match fs::hard_link(temporary, path) {
        Ok(()) => true,
        Err(error) if error.kind() == ErrorKind::AlreadyExists => false,
        Err(_) => {
            fs::rename(temporary, path)?;
            true
        }
    };
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        let parent = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(published)
}

fn parse_identity_file(text: &str) -> Result<Identity> {
    let identity = Identity::parse(text).map_err(|_| Error::Protocol("ZeroTier身份格式不合法"))?;
    if !identity.has_secret() {
        return Err(Error::Protocol("ZeroTier身份缺少私钥"));
    }
    Ok(identity)
}

/// 读取 `identity.secret` 格式的身份文件；文件不存在时生成并以 0600 权限写入。
fn load_or_create_identity(path: &Path) -> Result<Identity> {
    let io_error = || Error::Protocol("ZeroTier身份文件读写失败");
    match fs::read_to_string(path) {
        Ok(text) => parse_identity_file(&text),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            let identity = Identity::generate();
            let text = identity.to_secret_string().map_err(|_| io_error())?;
            if let Some(parent) = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                fs::create_dir_all(parent).map_err(|_| io_error())?;
            }
            // 新身份的地址是随机的，临时文件名因此不与其他写入者或崩溃残留冲突。
            let mut name = path.file_name().ok_or_else(io_error)?.to_os_string();
            name.push(format!(".{}.tmp", identity.address()));
            let temporary = path.with_file_name(name);
            let published = publish_secret(path, &temporary, &text);
            let _ = fs::remove_file(&temporary);
            if published.map_err(|_| io_error())? {
                Ok(identity)
            } else {
                parse_identity_file(&fs::read_to_string(path).map_err(|_| io_error())?)
            }
        }
        Err(_) => Err(io_error()),
    }
}

/// 阻塞：身份生成需要数秒，每个身份校验需要一次内存密集哈希。
pub(crate) fn build_node_options(prepared: Prepared) -> Result<(NodeOptions, Option<SocketAddr>)> {
    let identity = match prepared.identity {
        IdentitySource::Inline(identity) => identity,
        IdentitySource::File(path) => load_or_create_identity(&path)?,
    };
    if !identity.locally_validate() {
        return Err(Error::Protocol("ZeroTier身份未通过工作量校验"));
    }
    if prepared
        .roots
        .iter()
        .chain(&prepared.peers)
        .any(|seed| !seed.identity.locally_validate())
    {
        return Err(Error::Protocol("ZeroTier身份未通过工作量校验"));
    }
    Ok((
        NodeOptions {
            identity,
            network_id: prepared.network_id,
            roots: prepared.roots,
            peers: prepared.peers,
        },
        prepared.bind,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SECRET: &str = "26fdbcd524:0:ade8db815db56cb544adea61ef3023deacbf7194352d2d353477505b179a0248cbf8091d5f179fe4ea1db72bcea0162c4775f47088aa688f7fc7d70ccb7b74c6:a0ed2afd4e7a3bbaef3887e362496efa83b1c0e32596c09f427afecd6fa60a97bac7c41e0931fb6c64d498d60d0b2f9df24d39283db2eb734693864b7c4399ca";
    const ROOT: &str = "8a013571a2:0:0f711554a5aa81e383f19dd332cb4d7d28d0a159cc1d4ba02023266babe6860bb675010ab16792c22ec4393eec776ee678a16d713f3d686b0d6c9e2edda20a51";

    fn options(value: serde_json::Value) -> Result<Prepared> {
        serde_json::from_value::<ClientOptions>(value)
            .map_err(|_| Error::Config("bad".into()))?
            .prepare()
    }

    fn valid() -> serde_json::Value {
        json!({
            "network": "8a013571a2000001",
            "identity": SECRET,
            "peers": [{"identity": ROOT, "endpoints": ["192.0.2.1:9993"]}],
        })
    }

    #[test]
    fn accepts_controller_reachable_by_direct_peer_and_builds_after_proof_of_work() {
        let prepared = options(valid()).unwrap();
        assert_eq!(prepared.network_id, 0x8a01_3571_a200_0001);
        assert_eq!(prepared.peers.len(), 1);
        let (node, bind) = build_node_options(prepared).unwrap();
        assert_eq!(node.identity.address().to_string(), "26fdbcd524");
        assert_eq!(bind, None);
    }

    #[test]
    fn rejects_unusable_configurations() {
        for (field, value) in [
            ("network", json!("8a013571a2")),
            ("network", json!("ff13571a20000001")),
            ("network", json!("00000000000000zz")),
            ("identity", json!(ROOT)),
            ("identity", json!("not-an-identity")),
            ("identity_file", json!("both.secret")),
            ("peers", json!([])),
            (
                "peers",
                json!([{"identity": SECRET, "endpoints": ["192.0.2.1:9993"]}]),
            ),
            ("peers", json!([{"identity": ROOT, "endpoints": []}])),
            (
                "peers",
                json!([{"identity": ROOT, "endpoints": ["0.0.0.0:9993"]}]),
            ),
            ("bind", json!("224.0.0.1:0")),
            ("unknown", json!(1)),
        ] {
            let mut config = valid();
            config[field] = value;
            assert!(options(config).is_err(), "{field} must be rejected");
        }

        let mut unreachable = valid();
        unreachable["network"] = json!("1111111111000001");
        assert!(options(unreachable).is_err());
    }

    #[test]
    fn public_planet_supplies_roots() {
        let mut config = valid();
        config["peers"] = json!([]);
        config["public_planet"] = json!(true);
        assert!(!options(config).unwrap().roots.is_empty());
    }

    #[test]
    fn identity_file_is_created_once_and_reused() {
        let directory = std::env::temp_dir().join(format!("kerlico-zt-{}", std::process::id()));
        let path = directory.join("nested").join("identity.secret");
        let _ = fs::remove_dir_all(&directory);
        let created = load_or_create_identity(&path).unwrap();
        let loaded = load_or_create_identity(&path).unwrap();
        assert_eq!(created, loaded);
        assert!(loaded.has_secret());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        fs::write(&path, "garbage").unwrap();
        assert!(load_or_create_identity(&path).is_err());
        fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn publishing_leaves_a_complete_private_file_and_never_replaces_an_existing_one() {
        let directory = std::env::temp_dir().join(format!("kerlico-zt-pub-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join("identity.secret");
        let temporary = directory.join("identity.secret.1.tmp");

        assert!(publish_secret(&path, &temporary, "first").unwrap());
        fs::remove_file(&temporary).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "first");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        assert!(!publish_secret(&path, &temporary, "second").unwrap());
        assert_eq!(fs::read_to_string(&path).unwrap(), "first");
        fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn creating_an_identity_leaves_no_temporary_file() {
        let directory = std::env::temp_dir().join(format!("kerlico-zt-tmp-{}", std::process::id()));
        let _ = fs::remove_dir_all(&directory);
        let path = directory.join("identity.secret");
        load_or_create_identity(&path).unwrap();
        let names: Vec<_> = fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, ["identity.secret"]);
        fs::remove_dir_all(&directory).unwrap();
    }
}
