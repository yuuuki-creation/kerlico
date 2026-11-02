//! 持久管理账户。账户标识与协议认证材料互不代用。

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use kerlico_core::{Error, Result, UserId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccountSpec {
    pub user_id: String,
    pub username: String,
    pub password_hash: String,
    #[serde(default = "enabled")]
    pub enabled: bool,
}
fn enabled() -> bool {
    true
}

impl AccountSpec {
    /// 创建一次后写回配置。准备配置不会随机生成管理 ID 或用户名。
    pub fn create(prefix: &str, password: &[u8]) -> Result<Self> {
        if prefix.is_empty()
            || prefix.len() > 80
            || prefix.chars().any(|c| c.is_control() || c.is_whitespace())
            || password.len() < 12
            || password.len() > 1024
        {
            return Err(Error::Config(
                "账户前缀须为 1 至 80 个非空白字符，管理密码须为 12 至 1024 字节".into(),
            ));
        }
        let id = UserId::generate();
        let salt: [u8; 16] = rand::random();
        let salt = SaltString::encode_b64(&salt)
            .map_err(|_| Error::Config("管理密码盐生成失败".into()))?;
        let password_hash = Argon2::default()
            .hash_password(password, &salt)
            .map_err(|_| Error::Config("管理密码摘要生成失败".into()))?
            .to_string();
        Ok(Self {
            user_id: id.to_string(),
            username: format!("{prefix}_{id}"),
            password_hash,
            enabled: true,
        })
    }
    pub fn validate(&self) -> Result<UserId> {
        let id = UserId::parse(&self.user_id)?;
        if self.username.is_empty()
            || self.username.len() > 128
            || self
                .username
                .chars()
                .any(|c| c.is_control() || c.is_whitespace())
        {
            return Err(Error::Config(
                "管理用户名必须是 1 至 128 个非空白字符".into(),
            ));
        }
        let hash = PasswordHash::new(&self.password_hash)
            .map_err(|_| Error::Config("管理密码必须保存为 Argon2id PHC 摘要".into()))?;
        if hash.algorithm.as_str() != "argon2id"
            || hash.version != Some(19)
            || hash.salt.is_none()
            || hash.hash.is_none()
        {
            return Err(Error::Config(
                "管理密码必须保存为 Argon2id v19 PHC 摘要".into(),
            ));
        }
        let memory = hash
            .params
            .get_decimal("m")
            .ok_or_else(|| Error::Config("管理密码摘要缺少内存参数".into()))?;
        let iterations = hash
            .params
            .get_decimal("t")
            .ok_or_else(|| Error::Config("管理密码摘要缺少迭代参数".into()))?;
        let parallel = hash
            .params
            .get_decimal("p")
            .ok_or_else(|| Error::Config("管理密码摘要缺少并行参数".into()))?;
        if !(19_456..=262_144).contains(&memory)
            || !(2..=10).contains(&iterations)
            || !(1..=8).contains(&parallel)
        {
            return Err(Error::Config("管理密码摘要参数超出支持范围".into()));
        }
        Ok(id)
    }
    pub fn verify_password(&self, password: &[u8]) -> Result<bool> {
        self.validate()?;
        if !self.enabled || password.len() > 1024 {
            return Ok(false);
        }
        let hash = PasswordHash::new(&self.password_hash).map_err(|_| Error::Rejected)?;
        Ok(Argon2::default().verify_password(password, &hash).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn account_identity_survives_serialization_and_rename() {
        let account = AccountSpec::create("test", b"synthetic-management-password").unwrap();
        assert_eq!(account.username, format!("test_{}", account.user_id));
        assert!(
            account
                .verify_password(b"synthetic-management-password")
                .unwrap()
        );
        assert!(
            !account
                .verify_password(b"incorrect-management-password")
                .unwrap()
        );
        let encoded = serde_json::to_vec(&account).unwrap();
        assert!(!String::from_utf8_lossy(&encoded).contains("synthetic-management-password"));
        let mut restored: AccountSpec = serde_json::from_slice(&encoded).unwrap();
        restored.username = "renamed-test-account".into();
        assert_eq!(restored.validate().unwrap(), account.validate().unwrap());
        restored.enabled = false;
        assert!(
            !restored
                .verify_password(b"synthetic-management-password")
                .unwrap()
        );
    }
}
