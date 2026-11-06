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

/// 服务端在 `PUSH_REPLY` 中声明的数据通道密钥派生方式。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum KeyDerivation {
    /// 2.4 及更早客户端：TLS 1.0 PRF。
    Prf,
    /// 2.5 客户端：`key-derivation tls-ekm`。
    EkmLegacyFlag,
    /// 2.6 起：`protocol-flags ... tls-ekm`。
    EkmProtocolFlag,
}

pub(crate) struct ReplyContext<'a> {
    pub assignment: &'a crate::server::registry::Assignment,
    pub ping: Option<u64>,
    pub ping_restart: Option<u64>,
    pub peer_id: u32,
    pub cipher: &'a str,
    pub key_derivation: KeyDerivation,
    pub cc_exit: bool,
    pub tun_mtu: Option<usize>,
}

/// 上游客户端按 `PUSH_BUNDLE_SIZE`（1024）接收单条推送；超出时用 `push-continuation` 分片。
const PUSH_BUDGET: usize = 960;

/// `lines` 为配置生成的通用推送项，末尾追加本会话的地址、保活与数据通道参数。
pub(crate) fn push_reply(lines: &[String], context: &ReplyContext<'_>) -> Vec<Vec<u8>> {
    use crate::server::registry::Topology;
    let mut options: Vec<String> = lines.to_vec();
    let assignment = context.assignment;
    match assignment.topology {
        Topology::Subnet => {
            if let Some(v4) = assignment.v4 {
                options.push(format!("route-gateway {}", v4.peer));
            }
        }
        Topology::Net30 | Topology::P2p => {
            if let Some(server) = assignment.server_v4 {
                options.push(format!("route {server}"));
            }
        }
    }
    options.push(format!("topology {}", assignment.topology.name()));
    if let Some(ping) = context.ping {
        options.push(format!("ping {ping}"));
    }
    if let Some(restart) = context.ping_restart {
        options.push(format!("ping-restart {restart}"));
    }
    if let Some(v6) = assignment.v6 {
        options.push(format!(
            "ifconfig-ipv6 {}/{} {}",
            v6.client, v6.prefix, v6.server
        ));
    }
    if let Some(v4) = assignment.v4 {
        let second = match assignment.topology {
            Topology::Subnet => v4.netmask,
            Topology::Net30 | Topology::P2p => v4.peer,
        };
        options.push(format!("ifconfig {} {second}", v4.client));
    }
    options.push(format!("peer-id {}", context.peer_id));
    options.push(format!("cipher {}", context.cipher));
    if let Some(mtu) = context.tun_mtu {
        options.push(format!("tun-mtu {mtu}"));
    }
    let mut flags = Vec::new();
    if context.cc_exit {
        flags.push("cc-exit");
    }
    match context.key_derivation {
        KeyDerivation::Prf => {}
        KeyDerivation::EkmLegacyFlag => options.push("key-derivation tls-ekm".to_owned()),
        KeyDerivation::EkmProtocolFlag => flags.push("tls-ekm"),
    }
    if !flags.is_empty() {
        options.push(format!("protocol-flags {}", flags.join(" ")));
    }

    let mut bundles: Vec<Vec<String>> = vec![Vec::new()];
    let mut size = 0;
    for option in options {
        let current = bundles.last_mut().expect("至少一组");
        if !current.is_empty() && size + option.len() + 1 > PUSH_BUDGET {
            bundles.push(Vec::new());
            size = 0;
        }
        size += option.len() + 1;
        bundles.last_mut().expect("至少一组").push(option);
    }
    let count = bundles.len();
    bundles
        .into_iter()
        .enumerate()
        .map(|(index, mut bundle)| {
            if count > 1 {
                let marker = if index + 1 == count { 1 } else { 2 };
                bundle.push(format!("push-continuation {marker}"));
            }
            let mut message = format!("PUSH_REPLY,{}", bundle.join(",")).into_bytes();
            message.push(0);
            message
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::registry::{AddressPool, Topology};

    fn reply(topology: Topology, prefixes: &[&str], lines: &[String]) -> Vec<String> {
        let prefixes: Vec<String> = prefixes.iter().map(|text| (*text).to_owned()).collect();
        let assignment = AddressPool::new(topology, &prefixes).unwrap().assignment(0);
        push_reply(
            lines,
            &ReplyContext {
                assignment: &assignment,
                ping: Some(10),
                ping_restart: Some(60),
                peer_id: 7,
                cipher: "AES-256-GCM",
                key_derivation: KeyDerivation::EkmProtocolFlag,
                cc_exit: true,
                tun_mtu: None,
            },
        )
        .into_iter()
        .map(|message| String::from_utf8(message[..message.len() - 1].to_vec()).unwrap())
        .collect()
    }

    #[test]
    fn subnet_push_reply_round_trips_through_the_client_parser() {
        let messages = reply(
            Topology::Subnet,
            &["10.8.0.1/24", "fd00:8::1/64"],
            &["route 192.0.2.0 255.255.255.0".to_owned()],
        );
        assert_eq!(
            messages,
            [
                "PUSH_REPLY,route 192.0.2.0 255.255.255.0,route-gateway 10.8.0.1,topology subnet,\
              ping 10,ping-restart 60,ifconfig-ipv6 fd00:8::1000/64 fd00:8::1,\
              ifconfig 10.8.0.2 255.255.255.0,peer-id 7,cipher AES-256-GCM,protocol-flags cc-exit tls-ekm"
            ]
        );
        let ControlMessage::PushReply(options) = classify(&messages[0]) else {
            panic!("not a push reply");
        };
        let mut config = PushedConfig::default();
        assert!(!config.apply(options));
        assert_eq!(config.address_v4, Some(Ipv4Addr::new(10, 8, 0, 2)));
        assert_eq!(config.address_v6, Some("fd00:8::1000".parse().unwrap()));
        assert_eq!(config.peer_id, Some(7));
        assert!(config.tls_ekm);
    }

    #[test]
    fn net30_push_reply_names_the_peer_and_routes_the_server_address() {
        let messages = reply(Topology::Net30, &["10.8.0.1/24"], &[]);
        assert!(messages[0].contains("route 10.8.0.1,topology net30"));
        assert!(messages[0].contains("ifconfig 10.8.0.6 10.8.0.5"));
    }

    #[test]
    fn long_push_reply_is_split_with_continuation_markers() {
        let routes: Vec<String> = (0..80)
            .map(|index| format!("route 198.18.{index}.0 255.255.255.0"))
            .collect();
        let messages = reply(Topology::Subnet, &["10.8.0.1/24"], &routes);
        assert!(messages.len() > 1);
        assert!(messages.iter().all(|message| message.len() < 1024));
        let mut config = PushedConfig::default();
        for (index, message) in messages.iter().enumerate() {
            let ControlMessage::PushReply(options) = classify(message) else {
                panic!("not a push reply");
            };
            assert_eq!(config.apply(options), index + 1 < messages.len());
        }
        assert_eq!(config.address_v4, Some(Ipv4Addr::new(10, 8, 0, 2)));
    }

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
