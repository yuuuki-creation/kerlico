//! `sing-mux` 多路复用，线格式与 sagernet/sing-mux（sing-box 与 Mihomo 共用）互通：
//! 会话请求头、前 16 次写入的填充记录、smux v1 / yamux / HTTP/2（h2mux）子协议、
//! 流请求与状态响应、UDP 固定目标流与逐包地址流，以及 Brutal 带宽交换。

mod client;
mod frame;
mod h2mux;
mod padding;
mod server;
mod wire;

pub use client::SingMuxClient;
pub use server::serve_inbound;

use kerlico_core::{Destination, Error, Result};
use serde::{Deserialize, Deserializer, Serialize};

pub const MAGIC_HOST: &str = "sp.mux.sing-box.arpa";
pub const SING_MUX_HOST: &str = MAGIC_HOST;
pub const MAGIC_PORT: u16 = 444;

pub fn magic_destination() -> Destination {
    Destination::new(MAGIC_HOST, MAGIC_PORT).expect("合法内置 sing-mux 目标")
}

pub fn is_magic_target(target: &Destination) -> bool {
    target.host().eq_ignore_ascii_case(MAGIC_HOST)
}

pub fn is_sing_mux_target(target: &Destination) -> bool {
    is_magic_target(target)
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SingMuxProtocol {
    #[default]
    #[serde(alias = "h2")]
    H2Mux,
    Smux,
    Yamux,
}

impl SingMuxProtocol {
    fn code(self) -> u8 {
        match self {
            Self::Smux => 0,
            Self::Yamux => 1,
            Self::H2Mux => 2,
        }
    }

    fn from_code(code: u8) -> Result<Self> {
        match code {
            0 => Ok(Self::Smux),
            1 => Ok(Self::Yamux),
            2 => Ok(Self::H2Mux),
            _ => Err(Error::Protocol("未知的 sing-mux 子协议编号")),
        }
    }
}

/// TCP Brutal 带宽（Mbps）。客户端把 `down_mbps` 告知服务端作为下行速率，
/// 服务端须在载体套接字上装载 tcp-brutal 内核模块。
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SingMuxBrutalConfig {
    pub enabled: bool,
    pub up_mbps: u64,
    pub down_mbps: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SingMuxOutboundConfig {
    pub enabled: bool,
    pub protocol: SingMuxProtocol,
    #[serde(alias = "max-connections")]
    pub max_connections: Option<u32>,
    #[serde(alias = "min-streams")]
    pub min_streams: Option<u32>,
    #[serde(alias = "max-streams")]
    pub max_streams: Option<u32>,
    pub padding: bool,
    #[serde(alias = "only-tcp")]
    pub only_tcp: bool,
    pub brutal: Option<SingMuxBrutalConfig>,
}

const MBPS_TO_BYTES: u64 = 125_000;

impl SingMuxOutboundConfig {
    pub fn validate(&self) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        if self.max_connections == Some(0) {
            return Err(Error::Config("multiplex.max_connections 不能为 0".into()));
        }
        if self.min_streams == Some(0) {
            return Err(Error::Config("multiplex.min_streams 不能为 0".into()));
        }
        if self.max_streams == Some(0) {
            return Err(Error::Config("multiplex.max_streams 不能为 0".into()));
        }
        if let Some(brutal) = self.brutal.as_ref().filter(|b| b.enabled)
            && (brutal.up_mbps == 0 || brutal.down_mbps == 0)
        {
            return Err(Error::Config(
                "multiplex.brutal 启用时 up_mbps 与 down_mbps 必须大于 0".into(),
            ));
        }
        Ok(())
    }

    pub fn handles_tcp(&self) -> bool {
        self.enabled
    }

    pub fn handles_udp(&self) -> bool {
        self.enabled && !self.only_tcp
    }

    /// 启用时返回（上行，下行）字节每秒。
    fn brutal_bps(&self) -> Option<(u64, u64)> {
        let brutal = self.brutal.as_ref().filter(|b| b.enabled)?;
        Some((
            brutal.up_mbps.saturating_mul(MBPS_TO_BYTES),
            brutal.down_mbps.saturating_mul(MBPS_TO_BYTES),
        ))
    }
}

fn reject_inbound_brutal<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<SingMuxBrutalConfig>, D::Error> {
    let brutal = Option::<SingMuxBrutalConfig>::deserialize(deserializer)?;
    if brutal.as_ref().is_some_and(|b| b.enabled) {
        return Err(serde::de::Error::custom(
            "入站 multiplex.brutal 需要在载体套接字上设置 TCP Brutal，kerlico 入站不支持；\
             客户端的 Brutal 交换会收到拒绝响应",
        ));
    }
    Ok(brutal)
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SingMuxInboundConfig {
    pub enabled: bool,
    pub padding: bool,
    #[serde(
        deserialize_with = "reject_inbound_brutal",
        skip_serializing_if = "Option::is_none"
    )]
    pub brutal: Option<SingMuxBrutalConfig>,
}

impl SingMuxInboundConfig {
    pub fn effective_with_padding(
        config: Option<&Self>,
        legacy_padding: Option<bool>,
    ) -> Option<Self> {
        let (enabled, padding) = match (config, legacy_padding) {
            (Some(cfg), Some(pad)) => (cfg.enabled || pad, cfg.padding || pad),
            (Some(cfg), None) if cfg.enabled || cfg.padding => (true, cfg.padding),
            (Some(_), None) | (None, None) => return None,
            (None, Some(pad)) => (true, pad),
        };
        Some(Self {
            enabled,
            padding,
            brutal: None,
        })
    }
}

#[cfg(test)]
mod tests;
