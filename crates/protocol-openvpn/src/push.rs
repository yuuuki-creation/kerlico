//! TLS 通道内的文本控制消息与 `PUSH_REPLY` 选项解析。

use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum ControlMessage<'a> {
    PushReply(&'a str),
    AuthFailed,
    Halt,
    Restart,
    Other,
}
pub(crate) fn classify(text: &str) -> ControlMessage<'_> {
    if let Some(options) = text.strip_prefix("PUSH_REPLY") {
        return ControlMessage::PushReply(options.strip_prefix(',').unwrap_or(options));
    }
    match text.split(',').next().unwrap_or(text) {
        "AUTH_FAILED" => ControlMessage::AuthFailed,
        "HALT" => ControlMessage::Halt,
        "RESTART" => ControlMessage::Restart,
        _ => ControlMessage::Other,
    }
}

#[derive(Default, Debug, Eq, PartialEq)]
pub(crate) struct PushedConfig {
    pub address_v4: Option<Ipv4Addr>,
    pub address_v6: Option<Ipv6Addr>,
    pub peer_id: Option<u32>,
    pub cipher: Option<String>,
    pub ping: Option<u64>,
    pub ping_restart: Option<u64>,
    pub tls_ekm: bool,
    pub auth_token: Option<String>,
    pub compression: bool,
}
impl PushedConfig {
    /// 合并一条 `PUSH_REPLY`；还有后续分片（`push-continuation 2`）时返回 `true`。
    pub fn apply(&mut self, options: &str) -> bool {
        let mut more = false;
        for option in options.split(',') {
            let mut fields = option.split_ascii_whitespace();
            let Some(name) = fields.next() else { continue };
            let first = fields.next();
            match name {
                "ifconfig" => self.address_v4 = first.and_then(|value| value.parse().ok()),
                "ifconfig-ipv6" => {
                    self.address_v6 = first
                        .and_then(|value| value.split('/').next())
                        .and_then(|value| value.parse().ok());
                }
                "peer-id" => self.peer_id = first.and_then(|value| value.parse().ok()),
                "cipher" => self.cipher = first.map(str::to_owned),
                "ping" => self.ping = first.and_then(|value| value.parse().ok()),
                "ping-restart" => self.ping_restart = first.and_then(|value| value.parse().ok()),
                "auth-token" => self.auth_token = first.map(str::to_owned),
                "key-derivation" => self.tls_ekm |= first == Some("tls-ekm"),
                "protocol-flags" => {
                    self.tls_ekm |=
                        first == Some("tls-ekm") || fields.any(|flag| flag == "tls-ekm");
                }
                "comp-lzo" | "compress" => self.compression = true,
                "push-continuation" => more = first == Some("2"),
                _ => {}
            }
        }
        more
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_recognises_server_control_keywords() {
        assert_eq!(classify("AUTH_FAILED"), ControlMessage::AuthFailed);
        assert_eq!(classify("AUTH_FAILED,bad"), ControlMessage::AuthFailed);
        assert_eq!(classify("HALT,bye"), ControlMessage::Halt);
        assert_eq!(classify("RESTART"), ControlMessage::Restart);
        assert_eq!(classify("INFO,hello"), ControlMessage::Other);
        assert_eq!(classify("PUSH_REPLY,a b"), ControlMessage::PushReply("a b"));
    }

    #[test]
    fn subnet_push_reply_from_openvpn_2_6_yields_the_tunnel_config() {
        let mut config = PushedConfig::default();
        let more = config.apply(
            "route-gateway 10.8.0.1,topology subnet,ping 10,ping-restart 120,\
             ifconfig-ipv6 fd42::1000/64 fd42::1,ifconfig 10.8.0.2 255.255.255.0,peer-id 3,\
             cipher AES-256-GCM,protocol-flags cc-exit tls-ekm dyn-tls-crypt,auth-token SESS_ID",
        );
        assert!(!more);
        assert_eq!(config.address_v4, Some(Ipv4Addr::new(10, 8, 0, 2)));
        assert_eq!(config.address_v6, Some("fd42::1000".parse().unwrap()));
        assert_eq!(config.peer_id, Some(3));
        assert_eq!(config.cipher.as_deref(), Some("AES-256-GCM"));
        assert_eq!((config.ping, config.ping_restart), (Some(10), Some(120)));
        assert!(config.tls_ekm);
        assert_eq!(config.auth_token.as_deref(), Some("SESS_ID"));
        assert!(!config.compression);
    }

    #[test]
    fn net30_local_address_and_continuation_and_compression_are_detected() {
        let mut config = PushedConfig::default();
        assert!(config.apply("ifconfig 10.8.0.6 10.8.0.5,push-continuation 2"));
        assert!(!config.apply("key-derivation tls-ekm,comp-lzo no,push-continuation 1"));
        assert_eq!(config.address_v4, Some(Ipv4Addr::new(10, 8, 0, 6)));
        assert!(config.tls_ekm);
        assert!(config.compression);
    }
}
