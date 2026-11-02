//! 线上带前缀的 Curve25519 公钥、本机私钥与 NaCl box。

use crypto_box::{
    PublicKey, SalsaBox, SecretKey,
    aead::{Aead, generic_array::GenericArray},
};
use kerlico_core::{Error, Result};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use std::{fs, io::Write, path::Path};
use x25519_dalek::{PublicKey as DalekPublic, StaticSecret};
use zeroize::Zeroizing;

const NONCE: usize = 24;

macro_rules! public_key {
    ($name:ident, $prefix:literal) => {
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        pub struct $name(pub [u8; 32]);
        impl $name {
            pub fn parse(value: &str) -> Option<Self> {
                let mut key = [0; 32];
                hex::decode_to_slice(value.strip_prefix($prefix)?, &mut key).ok()?;
                Some(Self(key))
            }
            pub fn is_zero(&self) -> bool {
                self.0 == [0; 32]
            }
            pub fn text(&self) -> String {
                format!("{}{}", $prefix, hex::encode(self.0))
            }
        }
        impl Serialize for $name {
            fn serialize<S: Serializer>(
                &self,
                serializer: S,
            ) -> std::result::Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.text())
            }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(
                deserializer: D,
            ) -> std::result::Result<Self, D::Error> {
                let value = String::deserialize(deserializer)?;
                Self::parse(&value).ok_or_else(|| de::Error::custom("invalid key"))
            }
        }
    };
}
public_key!(NodeKey, "nodekey:");
public_key!(DiscoKey, "discokey:");
public_key!(MachineKey, "mkey:");

#[derive(Clone)]
pub struct Secret(StaticSecret);
impl Secret {
    pub fn generate() -> Self {
        let mut bytes = Zeroizing::new([0; 32]);
        OsRng.fill_bytes(bytes.as_mut());
        Self::from_bytes(*bytes)
    }
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(StaticSecret::from(bytes))
    }
    pub fn bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }
    pub fn public(&self) -> [u8; 32] {
        DalekPublic::from(&self.0).to_bytes()
    }
    /// 拒绝低阶点产生的全零共享秘密，与上游 `curve25519.X25519` 一致。
    pub fn diffie_hellman(&self, peer: &[u8; 32]) -> Result<[u8; 32]> {
        let shared = self.0.diffie_hellman(&DalekPublic::from(*peer));
        if !shared.was_contributory() {
            return Err(Error::Protocol("Tailscale对端公钥不合法"));
        }
        Ok(shared.to_bytes())
    }
    /// 输出 `nonce || tag || ciphertext`，即上游 `SealTo`/`Seal` 的线格式。
    pub fn seal(&self, peer: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce = [0; NONCE];
        OsRng.fill_bytes(&mut nonce);
        self.seal_with_nonce(peer, &nonce, plaintext)
    }
    fn seal_with_nonce(
        &self,
        peer: &[u8; 32],
        nonce: &[u8; NONCE],
        plaintext: &[u8],
    ) -> Result<Vec<u8>> {
        let sealed = self
            .salsa_box(peer)
            .encrypt(GenericArray::from_slice(nonce), plaintext)
            .map_err(|_| Error::Protocol("Tailscale消息加密失败"))?;
        let mut output = Vec::with_capacity(NONCE + sealed.len());
        output.extend_from_slice(nonce);
        output.extend_from_slice(&sealed);
        Ok(output)
    }
    pub fn open(&self, peer: &[u8; 32], sealed: &[u8]) -> Option<Vec<u8>> {
        if sealed.len() < NONCE {
            return None;
        }
        let (nonce, ciphertext) = sealed.split_at(NONCE);
        self.salsa_box(peer)
            .decrypt(GenericArray::from_slice(nonce), ciphertext)
            .ok()
    }
    fn salsa_box(&self, peer: &[u8; 32]) -> SalsaBox {
        SalsaBox::new(&PublicKey::from(*peer), &SecretKey::from(self.bytes()))
    }
}

#[derive(Clone)]
pub struct Identity {
    pub machine: Secret,
    pub node: Secret,
}
impl Identity {
    /// 存在状态文件时读取，否则新建并以私有权限落盘；不写路径则只在进程内有效。
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let Some(path) = path else {
            return Ok(Self::generate());
        };
        match fs::read_to_string(path) {
            Ok(text) => Self::decode(&text),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let identity = Self::generate();
                identity.store(path)?;
                Ok(identity)
            }
            Err(error) => Err(error.into()),
        }
    }
    fn generate() -> Self {
        Self {
            machine: Secret::generate(),
            node: Secret::generate(),
        }
    }
    fn decode(text: &str) -> Result<Self> {
        let invalid = || Error::Config("Tailscale状态文件不合法".into());
        let stored: serde_json::Value = serde_json::from_str(text).map_err(|_| invalid())?;
        let secret = |field: &str| -> Result<Secret> {
            let mut bytes = [0; 32];
            hex::decode_to_slice(stored[field].as_str().ok_or_else(invalid)?, &mut bytes)
                .map_err(|_| invalid())?;
            Ok(Secret::from_bytes(bytes))
        };
        Ok(Self {
            machine: secret("machine_key")?,
            node: secret("node_key")?,
        })
    }
    fn store(&self, path: &Path) -> Result<()> {
        let text = Zeroizing::new(
            serde_json::json!({
                "machine_key": hex::encode(self.machine.bytes()),
                "node_key": hex::encode(self.node.bytes()),
            })
            .to_string(),
        );
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent)?;
        }
        let partial = path.with_extension("partial");
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options.open(&partial)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        fs::rename(&partial, path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixed_keys_round_trip_and_reject_other_prefixes() {
        let hex = "11".repeat(32);
        let key: NodeKey = serde_json::from_str(&format!("\"nodekey:{hex}\"")).unwrap();
        assert_eq!(key.0, [0x11; 32]);
        assert_eq!(
            serde_json::to_string(&key).unwrap(),
            format!("\"nodekey:{hex}\"")
        );
        assert!(NodeKey::parse(&format!("mkey:{hex}")).is_none());
        assert!(NodeKey::parse("nodekey:11").is_none());
    }

    #[test]
    fn nacl_box_matches_published_vector() {
        // NaCl 文档 tests/box.c 的 alice/bob 密钥、nonce 与明文。
        let alice = Secret::from_bytes(
            hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
                .unwrap()
                .try_into()
                .unwrap(),
        );
        let bob_public: [u8; 32] =
            hex::decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
                .unwrap()
                .try_into()
                .unwrap();
        let nonce: [u8; 24] = hex::decode("69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37")
            .unwrap()
            .try_into()
            .unwrap();
        let plaintext = hex::decode(concat!(
            "be075fc53c81f2d5cf141316ebeb0c7b5228c52a4c62cbd44b66849b64244ffc",
            "e5ecbaaf33bd751a1ac728d45e6c61296cdc3c01233561f41db66cce314adb31",
            "0e3be8250c46f06dceea3a7fa1348057e2f6556ad6b1318a024a838f21af1fde",
            "048977eb48f59ffd4924ca1c60902e52f0a089bc76897040e082f93776384864",
            "5e0705"
        ))
        .unwrap();
        let sealed = alice
            .seal_with_nonce(&bob_public, &nonce, &plaintext)
            .unwrap();
        assert_eq!(
            hex::encode(&sealed[24..]),
            concat!(
                "f3ffc7703f9400e52a7dfb4b3d3305d98e993b9f48681273c29650ba32fc76ce",
                "48332ea7164d96a4476fb8c531a1186ac0dfc17c98dce87b4da7f011ec48c972",
                "71d2c20f9b928fe2270d6fb863d51738b48eeee314a7cc8ab932164548e526ae",
                "90224368517acfeabd6bb3732bc0e9da99832b61ca01b6de56244a9e88d5f9b3",
                "7973f622a43d14a6599b1f654cb45a74e355a5"
            )
        );
    }

    #[test]
    fn state_file_survives_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state").join("tailscale.json");
        let first = Identity::load(Some(&path)).unwrap();
        let second = Identity::load(Some(&path)).unwrap();
        assert_eq!(first.node.public(), second.node.public());
        assert_eq!(first.machine.public(), second.machine.public());
        fs::write(&path, "{}").unwrap();
        assert!(Identity::load(Some(&path)).is_err());
    }
}
