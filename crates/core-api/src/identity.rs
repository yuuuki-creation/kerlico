//! 管理账户、节点成员与协议鉴别结果。凭据内容只保留在协议自己的候选表中。

use crate::{Error, Result};
use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct UserId(uuid::Uuid);

impl UserId {
    pub fn parse(value: &str) -> Result<Self> {
        let value = uuid::Uuid::parse_str(value)
            .map_err(|_| Error::Config("管理用户 ID 必须是 UUID".into()))?;
        if value.is_nil() {
            return Err(Error::Config("管理用户 ID 不能为零".into()));
        }
        Ok(Self(value))
    }
    pub fn generate() -> Self {
        Self(uuid::Uuid::from_bytes(random_uuid()))
    }
}

impl fmt::Display for UserId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

fn random_uuid() -> [u8; 16] {
    let mut bytes: [u8; 16] = rand::random();
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    bytes
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct RunId(uuid::Uuid);
impl RunId {
    pub fn generate() -> Self {
        Self(uuid::Uuid::from_bytes(random_uuid()))
    }
}
impl fmt::Display for RunId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct NodeId(String);
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct OutId(String);
macro_rules! label_id {
    ($ty:ident) => {
        impl $ty {
            pub fn parse(value: &str) -> Result<Self> {
                if value.is_empty()
                    || value.len() > 64
                    || !value
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
                {
                    return Err(Error::Config(
                        "标识必须是 1 至 64 个字母、数字、横线或下划线".into(),
                    ));
                }
                Ok(Self(value.to_owned()))
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
        impl fmt::Display for $ty {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }
    };
}
label_id!(NodeId);
label_id!(OutId);

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Source {
    User {
        node: NodeId,
        user: UserId,
        credential_epoch: u64,
    },
    Local {
        node: NodeId,
    },
}
impl Source {
    pub fn node(&self) -> &NodeId {
        match self {
            Self::User { node, .. } | Self::Local { node } => node,
        }
    }
    pub fn user(&self) -> Option<UserId> {
        match self {
            Self::User { user, .. } => Some(*user),
            Self::Local { .. } => None,
        }
    }
}

#[derive(Clone)]
pub struct Membership {
    pub user: UserId,
    pub credential_epoch: u64,
    pub enabled: bool,
}

struct Issuer {
    node: NodeId,
    config_epoch: u64,
    run: AtomicU64,
    members: Vec<Membership>,
}

/// 由配置装配建立。协议只用它绑定配置内的候选，不能从线上的用户名建立成员。
#[derive(Clone)]
pub struct CredentialIssuer(Arc<Issuer>);
impl CredentialIssuer {
    pub fn new(node: NodeId, config_epoch: u64, members: Vec<Membership>) -> Result<Self> {
        if members.len() > 1024 {
            return Err(Error::Config("每节点原生凭据候选不能超过1024项".into()));
        }
        if config_epoch == 0 || members.iter().any(|m| m.credential_epoch == 0) {
            return Err(Error::Config("配置和凭据代次必须大于零".into()));
        }
        Ok(Self(Arc::new(Issuer {
            node,
            config_epoch,
            members,
            run: AtomicU64::new(0),
        })))
    }
    pub fn node(&self) -> &NodeId {
        &self.0.node
    }
    pub fn len(&self) -> usize {
        self.0.members.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.members.is_empty()
    }
    pub fn activate(&self, run: u64) -> Result<()> {
        if run == 0 {
            return Err(Error::Rejected);
        }
        self.0
            .run
            .compare_exchange(0, run, Ordering::AcqRel, Ordering::Acquire)
            .map(|_| ())
            .map_err(|_| Error::Config("节点计划已被另一个运行实例消费".into()))
    }
    pub fn bind<C>(&self, rows: Vec<C>) -> Result<CredentialSet<C>> {
        if rows.len() != self.len() {
            return Err(Error::Config("原生凭据行与节点成员数量不一致".into()));
        }
        Ok(CredentialSet {
            issuer: self.clone(),
            rows: Arc::new(rows),
        })
    }
    pub(crate) fn accept<T>(&self, verified: Verified<T>) -> Result<(Source, T)> {
        let principal = verified.principal;
        if !Arc::ptr_eq(&self.0, &principal.issuer.0)
            || principal.run == 0
            || principal.run != self.0.run.load(Ordering::Acquire)
            || principal.config_epoch != self.0.config_epoch
        {
            return Err(Error::Rejected);
        }
        let member = self.0.members.get(principal.index).ok_or(Error::Rejected)?;
        if !member.enabled || member.credential_epoch != principal.credential_epoch {
            return Err(Error::Rejected);
        }
        Ok((
            Source::User {
                node: self.0.node.clone(),
                user: member.user,
                credential_epoch: member.credential_epoch,
            },
            verified.decoded,
        ))
    }
}

pub struct CredentialSet<C> {
    issuer: CredentialIssuer,
    rows: Arc<Vec<C>>,
}
impl<C> Clone for CredentialSet<C> {
    fn clone(&self) -> Self {
        Self {
            issuer: self.issuer.clone(),
            rows: self.rows.clone(),
        }
    }
}

#[derive(Clone)]
pub struct CredentialSlot {
    issuer: CredentialIssuer,
    index: usize,
}
struct Principal {
    issuer: CredentialIssuer,
    index: usize,
    run: u64,
    config_epoch: u64,
    credential_epoch: u64,
}
pub struct Verified<T> {
    principal: Principal,
    decoded: T,
}

impl<C> CredentialSet<C> {
    pub fn len(&self) -> usize {
        self.rows.len()
    }
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
    pub fn rows(&self) -> impl Iterator<Item = (CredentialSlot, &C)> {
        self.rows.iter().enumerate().map(|(index, row)| {
            (
                CredentialSlot {
                    issuer: self.issuer.clone(),
                    index,
                },
                row,
            )
        })
    }
    pub fn verify<E, T>(
        &self,
        evidence: &E,
        mut verify: impl FnMut(&C, &E) -> Result<Option<T>>,
    ) -> Result<Verified<T>> {
        let mut matched = None;
        for (slot, row) in self.rows() {
            if let Some(decoded) = verify(row, evidence)? {
                if matched.is_some() {
                    return Err(Error::Rejected);
                }
                matched = Some((slot, decoded));
            }
        }
        let (slot, decoded) = matched.ok_or(Error::Rejected)?;
        self.verified(&slot, decoded)
    }
    /// 异步原生库适配器完成真实鉴别后，交接原候选槽和同一次解码状态。
    pub fn verified<T>(&self, slot: &CredentialSlot, decoded: T) -> Result<Verified<T>> {
        if !Arc::ptr_eq(&self.issuer.0, &slot.issuer.0) {
            return Err(Error::Rejected);
        }
        let member = self
            .issuer
            .0
            .members
            .get(slot.index)
            .ok_or(Error::Rejected)?;
        let run = self.issuer.0.run.load(Ordering::Acquire);
        if !member.enabled || run == 0 {
            return Err(Error::Rejected);
        }
        Ok(Verified {
            principal: Principal {
                issuer: self.issuer.clone(),
                index: slot.index,
                run,
                config_epoch: self.issuer.0.config_epoch,
                credential_epoch: member.credential_epoch,
            },
            decoded,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CredentialPurpose {
    Authentication { slot: usize },
    Protection,
}

#[derive(Clone)]
pub struct CredentialEntry {
    pub protocol: String,
    pub purpose: CredentialPurpose,
    pub fingerprint: [u8; 32],
}
#[derive(Clone, Default)]
pub struct CredentialManifest {
    entries: Vec<CredentialEntry>,
}
impl CredentialManifest {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn authentication(&mut self, protocol: &str, slot: usize, fingerprint: [u8; 32]) {
        self.entries.push(CredentialEntry {
            protocol: protocol.to_owned(),
            purpose: CredentialPurpose::Authentication { slot },
            fingerprint,
        });
    }
    pub fn protection(&mut self, protocol: &str, fingerprint: [u8; 32]) {
        self.entries.push(CredentialEntry {
            protocol: protocol.to_owned(),
            purpose: CredentialPurpose::Protection,
            fingerprint,
        });
    }
    pub fn extend(&mut self, other: Self) {
        self.entries.extend(other.entries);
    }
    pub fn entries(&self) -> &[CredentialEntry] {
        &self.entries
    }
}
