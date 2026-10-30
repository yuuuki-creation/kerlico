use base64::{Engine, engine::general_purpose::STANDARD};
use kerlico_core::{Destination, Error, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use shadowsocks::{
    ServerConfig,
    config::{ServerAddr, ServerUser, ServerUserManager},
    crypto::CipherKind,
};
use std::{collections::HashSet, net::SocketAddr};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClientOptions {
    pub server: String,
    pub port: u16,
    pub method: String,
    pub key: String,
    #[serde(default)]
    pub identity_keys: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NodeOptions {
    pub method: String,
    pub key: String,
    #[serde(default)]
    pub users: Vec<String>,
}

pub(crate) fn method(name: &str) -> Result<CipherKind> {
    match name {
        "2022-blake3-aes-128-gcm" => Ok(CipherKind::AEAD2022_BLAKE3_AES_128_GCM),
        "2022-blake3-aes-256-gcm" => Ok(CipherKind::AEAD2022_BLAKE3_AES_256_GCM),
        "2022-blake3-chacha20-poly1305" => Ok(CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305),
        _ => Err(Error::Config("SS2022 方法不在本轮支持范围".into())),
    }
}

pub(crate) fn key(text: &str, method: CipherKind) -> Result<Vec<u8>> {
    let key = STANDARD
        .decode(text)
        .map_err(|_| Error::Config("SS2022 key 必须为标准 Base64".into()))?;
    if key.len() != method.key_len() || STANDARD.encode(&key) != text {
        return Err(Error::Config("SS2022 key 长度或 Base64 编码不合法".into()));
    }
    Ok(key)
}

pub(crate) fn fingerprint(key: &[u8]) -> [u8; 32] {
    Sha256::digest(key).into()
}

pub(crate) fn client(options: ClientOptions) -> Result<(ServerConfig, Destination)> {
    let method = method(&options.method)?;
    let raw = key(&options.key, method)?;
    let target = Destination::new(&options.server, options.port)?;
    if options.identity_keys.len() > 8 {
        return Err(Error::Config("SS2022 identity 链最多八层".into()));
    }
    let password = if !options.identity_keys.is_empty() {
        if !shadowsocks::config::method_support_eih(method) {
            return Err(Error::Config("SS2022 ChaCha 不支持 identity key".into()));
        }
        let mut seen = HashSet::from([raw]);
        for identity in &options.identity_keys {
            if !seen.insert(key(identity, method)?) {
                return Err(Error::Config("SS2022 identity 链 key 必须独立".into()));
            }
        }
        format!("{}:{}", options.identity_keys.join(":"), options.key)
    } else {
        options.key
    };
    let config = ServerConfig::new(
        ServerAddr::DomainName(target.host(), target.port()),
        password,
        method,
    )
    .map_err(|_| Error::Config("SS2022 客户端参数不合法".into()))?;
    Ok((config, target))
}

pub(crate) fn node(options: NodeOptions) -> Result<(ServerConfig, Vec<[u8; 32]>)> {
    let method = method(&options.method)?;
    let raw = key(&options.key, method)?;
    if options.users.len() > 1024 {
        return Err(Error::Config("SS2022 用户数超过上限".into()));
    }
    if !options.users.is_empty() && !shadowsocks::config::method_support_eih(method) {
        return Err(Error::Config("SS2022 ChaCha 不支持 EIH 多用户".into()));
    }
    let mut config = ServerConfig::new(
        "127.0.0.1:1".parse::<SocketAddr>().expect("固定地址合法"),
        options.key,
        method,
    )
    .map_err(|_| Error::Config("SS2022 节点参数不合法".into()))?;
    let mut keys = vec![fingerprint(&raw)];
    let mut seen = HashSet::from([raw]);
    if !options.users.is_empty() {
        let mut manager = ServerUserManager::new();
        for (index, text) in options.users.iter().enumerate() {
            let raw = key(text, method)?;
            if !seen.insert(raw.clone()) {
                return Err(Error::Config("SS2022 用户与服务 key 不得重复".into()));
            }
            keys.push(fingerprint(&raw));
            manager.add_user(ServerUser::new(format!("user-{index}"), raw));
        }
        config.set_user_manager(manager);
    }
    Ok((config, keys))
}
