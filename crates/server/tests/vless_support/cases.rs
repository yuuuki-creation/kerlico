use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::support::Result;
use super::xdrive_mock::Service;

pub const ID: &str = "db275cb4-f058-4073-897b-a45f265120ba";
pub const INGRESS_ID: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
const INGRESS_ID_TEXT: &str = "01020304-0506-0708-090a-0b0c0d0e0f10";
pub const ORIGIN_NAME: &str = "matrix-origin.test";
pub const TLS_NAME: &str = "localhost";
const PATH: &str = "/matrix";
const SHORT_ID: &str = "12ab34cd";
pub const AUTH: &str = "matrix-hysteria-auth";
pub const FORWARDED: &str = "203.0.113.8";

#[derive(Clone, Copy)]
pub enum Network {
    Raw,
    RawHttp(bool),
    Kcp(&'static str),
    WebSocket(bool),
    Upgrade(bool),
    Grpc(bool),
    Xhttp(&'static str),
    Hysteria,
    Xdrive,
}

impl Network {
    fn name(self) -> &'static str {
        match self {
            Self::Raw | Self::RawHttp(_) => "raw",
            Self::Kcp(_) => "mkcp",
            Self::WebSocket(_) => "ws",
            Self::Upgrade(_) => "httpupgrade",
            Self::Grpc(_) => "grpc",
            Self::Xhttp(_) => "xhttp",
            Self::Hysteria => "hysteria",
            Self::Xdrive => "xdrive",
        }
    }
}

#[derive(Clone, Copy)]
pub enum Security {
    None,
    Tls(&'static str),
    Reality,
}

impl Security {
    fn name(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Tls(_) => "tls",
            Self::Reality => "reality",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Payload {
    Tcp,
    TwoTcp,
    Rounds(usize),
    InnerTls,
    Udp,
    Udp53,
    Udp443,
}

impl Payload {
    pub fn udp(self) -> bool {
        matches!(self, Self::Udp | Self::Udp53 | Self::Udp443)
    }

    pub fn origin_port(self) -> u16 {
        match self {
            Self::Udp53 => 53,
            Self::Udp443 => 443,
            _ => 0,
        }
    }
}

/// What a tap between the client and the server must see: how many carriers, and the VLESS
/// command each one opens with when the carrier is plaintext.
#[derive(Clone, Copy)]
pub struct Carriers {
    pub count: usize,
    pub command: Option<u8>,
}

pub struct Case {
    pub name: String,
    network: Network,
    pub security: Security,
    pub payload: Payload,
    pub mock: Option<Service>,
    custom_upgrade: bool,
    cipher: Option<&'static str>,
    pub resume: bool,
    flow: &'static str,
    mux: Option<Value>,
    /// Run Xray with its default cone UDP instead of `xray.cone.disabled`.
    pub cone: bool,
    pub carriers: Option<Carriers>,
    /// Every client must refuse the flow before it opens a carrier.
    pub rejected: bool,
    pin: bool,
    tls12: bool,
    mldsa: bool,
    xhttp: Option<XhttpOptions>,
    h2_params: Option<&'static str>,
    xmux: Option<&'static str>,
    xff: Option<bool>,
    sockopt: Option<&'static str>,
}

#[derive(Clone, Copy)]
enum XhttpOptions {
    Header,
    Cookie,
    Query,
    Stream,
    SeparateDownload,
}

impl Case {
    pub fn new(
        name: impl Into<String>,
        network: Network,
        security: Security,
        payload: Payload,
    ) -> Self {
        Self {
            name: name.into(),
            network,
            security,
            payload,
            mock: None,
            custom_upgrade: false,
            cipher: None,
            resume: false,
            flow: "",
            mux: None,
            cone: false,
            carriers: None,
            rejected: false,
            pin: false,
            tls12: false,
            mldsa: false,
            xhttp: None,
            h2_params: None,
            xmux: None,
            xff: None,
            sockopt: None,
        }
    }

    pub fn sockopt(mut self, json: &'static str) -> Self {
        self.sockopt = Some(json);
        self
    }

    /// The client sends X-Forwarded-For. The server trusts it only when `marker` adds the trusted header.
    pub fn xff(mut self, marker: bool) -> Self {
        self.xff = Some(marker);
        self
    }

    pub fn forwarded(&self) -> Option<bool> {
        self.xff
    }

    fn xff_headers(&self) -> Value {
        let mut headers = json!({"X-Forwarded-For": FORWARDED, "X-Test": "forwarded"});
        if self.xff == Some(true) {
            headers["X-Trusted-CDN"] = json!("1");
        }
        headers
    }

    pub fn h2_params(mut self, params: &'static str) -> Self {
        self.h2_params = Some(params);
        self
    }

    pub fn xmux(mut self, xmux: &'static str) -> Self {
        self.xmux = Some(xmux);
        self
    }

    pub fn counts_carriers(&self) -> bool {
        self.xmux.is_some()
    }

    pub fn encryption(mut self, cipher: &'static str, resume: bool) -> Self {
        self.cipher = Some(cipher);
        self.resume = resume;
        self
    }

    fn vision(mut self, allow_443: bool) -> Self {
        self.flow = if allow_443 {
            "xtls-rprx-vision-udp443"
        } else {
            "xtls-rprx-vision"
        };
        self
    }

    fn mux(self) -> Self {
        self.mux_with(json!({"enabled": true, "concurrency": 8,
            "xudpConcurrency": 8, "xudpProxyUDP443": "allow"}))
    }

    /// Both clients get the same Xray `mux` object.
    fn mux_with(mut self, mux: Value) -> Self {
        self.mux = Some(mux);
        self
    }

    fn cone(mut self) -> Self {
        self.cone = true;
        self
    }

    fn carriers(mut self, count: usize, command: Option<u8>) -> Self {
        self.carriers = Some(Carriers { count, command });
        self
    }

    /// Concurrent flows that must share one carrier whatever its security.
    fn single_carrier(self) -> Self {
        self.carriers(1, None)
    }

    fn rejected(mut self) -> Self {
        self.rejected = true;
        self.carriers(0, None)
    }

    fn custom_upgrade(mut self) -> Self {
        self.custom_upgrade = true;
        self
    }

    fn upgrade_settings(&self, early: bool, server: bool) -> Value {
        if !self.custom_upgrade {
            let mut settings = json!({"path": path(early), "host": TLS_NAME});
            if self.xff.is_some() && !server {
                settings["headers"] = self.xff_headers();
            }
            return settings;
        }
        let websocket = matches!(self.network, Network::WebSocket(_));
        let mut target = PATH.to_owned();
        if early {
            target.push_str("?ed=8192");
        }
        if !websocket || !server {
            target.push(if early { '&' } else { '?' });
            target.push_str("cover=1");
        }
        let mut headers = json!({"X-Matrix-Carrier": "custom", "User-Agent": "matrix/1.0"});
        if websocket {
            headers["Host"] = json!(TLS_NAME);
            json!({"path": target, "headers": headers})
        } else {
            headers["Sec-WebSocket-Key"] = json!("dGhlIHNhbXBsZSBub25jZQ==");
            json!({"path": target, "host": TLS_NAME, "headers": headers})
        }
    }

    fn mldsa(mut self) -> Self { self.mldsa = true; self }

    fn xhttp(mut self, options: XhttpOptions) -> Self {
        self.xhttp = Some(options);
        self
    }

    pub fn separate_download(&self) -> bool {
        matches!(self.xhttp, Some(XhttpOptions::SeparateDownload))
    }

    fn xhttp_settings(&self, keys: &Keys, mode: &str, server: bool) -> Value {
        let mut settings = json!({"path": PATH, "host": TLS_NAME, "mode": mode});
        if self.xff.is_some() && !server {
            settings["headers"] = self.xff_headers();
        }
        for (key, text) in [("h2Params", self.h2_params), ("xmux", self.xmux)] {
            if let Some(text) = text {
                settings[key] = serde_json::from_str(text).expect("XHTTP fixture JSON");
            }
        }
        let extra = match self.xhttp {
            Some(XhttpOptions::Header) => json!({
                "sessionIDPlacement": "query", "sessionIDKey": "session",
                "seqPlacement": "cookie", "seqKey": "packet",
                "uplinkDataPlacement": "header", "uplinkDataKey": "X-Data-Chunk",
                "uplinkChunkSize": 95, "uplinkHTTPMethod": "GET",
                "xPaddingObfsMode": true, "xPaddingPlacement": "queryInHeader",
                "xPaddingHeader": "X-Cover", "xPaddingKey": "cover", "xPaddingMethod": "tokenish",
                "xPaddingBytes": "80-123", "scMaxEachPostBytes": "2048-3072",
                "scMinPostsIntervalMs": 1, "serverMaxHeaderBytes": 16384
            }),
            Some(XhttpOptions::Cookie) => json!({
                "sessionIDPlacement": "header", "seqPlacement": "query",
                "uplinkDataPlacement": "cookie", "uplinkDataKey": "data",
                "uplinkChunkSize": "64-144", "uplinkHTTPMethod": "OPTIONS",
                "xPaddingObfsMode": true, "xPaddingPlacement": "cookie",
                "xPaddingKey": "cover", "xPaddingBytes": 97,
                "scMaxEachPostBytes": "2048-3072", "scMinPostsIntervalMs": 1,
                "headers": {"X-Matrix": "custom"}
            }),
            Some(XhttpOptions::Query) => json!({
                "sessionIDPlacement": "cookie", "seqPlacement": "header",
                "uplinkDataPlacement": "body", "uplinkHTTPMethod": "GET",
                "xPaddingObfsMode": true, "xPaddingPlacement": "query",
                "xPaddingMethod": "tokenish", "xPaddingBytes": 90
            }),
            Some(XhttpOptions::Stream) => json!({
                "sessionIDPlacement": "header",
                "uplinkHTTPMethod": "PATCH", "noGRPCHeader": true, "noSSEHeader": true,
                "xPaddingObfsMode": true, "xPaddingPlacement": "header", "xPaddingBytes": 110,
                "scStreamUpServerSecs": 1
            }),
            Some(XhttpOptions::SeparateDownload) if !server => json!({
                "downloadSettings": {
                    "address": "127.0.0.1", "port": keys.download,
                    "network": "xhttp", "security": "reality",
                    "realitySettings": {"fingerprint": "chrome", "serverName": TLS_NAME,
                        "password": keys.reality_public, "shortId": SHORT_ID},
                    "xhttpSettings": {"path": format!("{PATH}?download=1"), "host": TLS_NAME}
                }
            }),
            _ => return settings,
        };
        settings["extra"] = extra;
        settings
    }

    fn inbound_flow(&self) -> &'static str {
        self.flow.strip_suffix("-udp443").unwrap_or(self.flow)
    }

    pub fn xray_client(&self, keys: &Keys, front: u16, peer: u16, origin: u16) -> Value {
        let network = if self.payload.udp() { "udp" } else { "tcp" };
        let mut outbound = json!({
            "protocol": "vless",
            "settings": {"address": "127.0.0.1", "port": peer, "id": ID,
                "encryption": keys.encryption, "flow": self.flow},
            "streamSettings": self.xray_stream(keys, false),
        });
        if let Some(mux) = &self.mux {
            outbound["mux"] = mux.clone();
        }
        json!({"log": {"loglevel": "info"}, "inbounds": [{
            "protocol": "tunnel", "listen": "127.0.0.1", "port": front,
            "settings": {"address": "127.0.0.1", "port": origin, "network": network},
        }], "outbounds": [outbound]})
    }

    pub fn xray_server(&self, keys: &Keys, peer: u16, origin: u16) -> Value {
        json!({
            "log": {"loglevel": "info"},
            "dns": {"hosts": {ORIGIN_NAME: "127.0.0.1"}},
            "inbounds": [{
                "protocol": "vless", "listen": "127.0.0.1", "port": peer,
                "settings": {"decryption": keys.decryption, "users": [{"id": ID, "flow": self.inbound_flow()}]},
                "streamSettings": self.xray_stream(keys, true),
            }],
            "outbounds": [{"protocol": "freedom",
                "streamSettings": {"sockopt": {"domainStrategy": "ForceIPv4"}},
                "settings": {"finalRules": [{"action": "allow", "network": "tcp,udp", "ip": ["127.0.0.1/32"], "port": origin.to_string()}]},
            }],
        })
    }

    fn xray_stream(&self, keys: &Keys, server: bool) -> Value {
        let mut stream = json!({"network": self.network.name(), "security": self.security.name()});
        match self.security {
            Security::None => {}
            Security::Tls(alpn) => {
                let mut tls = if server && self.mock.is_none() {
                    json!({"certificates": [{"certificateFile": keys.cert, "keyFile": keys.key}]})
                } else {
                    json!({"serverName": TLS_NAME, "pinnedPeerCertSha256": keys.pin})
                };
                if !alpn.is_empty() {
                    tls["alpn"] = json!([alpn]);
                }
                if self.tls12 {
                    tls["minVersion"] = json!("1.2");
                    tls["maxVersion"] = json!("1.2");
                }
                if self.tls12 || self.mock.is_some() {
                    tls["fingerprint"] = json!("unsafe");
                }
                stream["tlsSettings"] = tls;
            }
            Security::Reality => {
                stream["realitySettings"] = if server {
                    json!({"target": format!("127.0.0.1:{}", keys.decoy),
                        "serverNames": [TLS_NAME], "privateKey": keys.reality_private, "shortIds": [SHORT_ID]})
                } else {
                    json!({"fingerprint": "chrome", "serverName": TLS_NAME,
                        "password": keys.reality_public, "shortId": SHORT_ID})
                };
                if self.mldsa {
                    stream["realitySettings"][if server { "mldsa65Seed" } else { "mldsa65Verify" }] = json!(if server { &keys.mldsa_seed } else { &keys.mldsa_verify });
                }
            }
        }
        match self.network {
            Network::Raw | Network::Kcp("none") => {}
            Network::RawHttp(custom) => stream["rawSettings"] = json!({"header": raw_http_header(custom)}),
            Network::Kcp(mask) => stream["finalmask"] = json!({"udp": kcp_masks(mask)}),
            Network::WebSocket(early) | Network::Upgrade(early) => {
                let key = if matches!(self.network, Network::WebSocket(_)) {
                    "wsSettings"
                } else {
                    "httpupgradeSettings"
                };
                stream[key] = self.upgrade_settings(early, server);
            }
            Network::Grpc(multi) => {
                stream["grpcSettings"] = grpc_options(multi, server);
                if self.name == "grpc-tls-sudoku" { stream["finalmask"] = grpc_sudoku(); }
            }
            Network::Xhttp(mode) => {
                stream["xhttpSettings"] = self.xhttp_settings(keys, mode, server)
            }
            Network::Hysteria => stream["hysteriaSettings"] = json!({"version": 2, "auth": AUTH}),
            Network::Xdrive => {
                if let Some(service) = self.mock {
                    let addr = keys.mock_addr.expect("mock storage address");
                    stream["address"] = json!(addr.ip().to_string());
                    stream["port"] = json!(addr.port());
                    stream["xdriveSettings"] = service.config(addr, self.security);
                } else {
                    stream["xdriveSettings"] = json!({"service": "local", "remoteFolder": keys.storage});
                }
            }
        }
        if let Some(params) = self.quic_parameters(server) {
            stream["finalmask"] = json!({"quicParams": params});
        }
        if let Some(params) = self.kcp_parameters(server) {
            stream["kcpSettings"] = params;
        }
        if server && self.name == "hysteria-quic-masquerade-string" {
            stream["hysteriaSettings"]["masquerade"] = masquerade_string();
        }
        if let Some(sockopt) = self.sockopt {
            stream["sockopt"] = serde_json::from_str(sockopt).expect("sockopt fixture JSON");
        }
        if server && self.xff.is_some() {
            stream["sockopt"] = json!({"trustedXForwardedFor": ["X-Trusted-CDN"]});
        }
        stream
    }

    pub fn kerlico_server(&self, keys: &Keys, port: u16) -> Value {
        let mut settings = self.kerlico_settings(keys, true);
        settings["users"] =
            json!([{"email": "matrix-user", "id": ID, "flow": self.inbound_flow()}]);
        json!({"inbounds": [{"tag": "matrix", "protocol": "vless", "listen": "127.0.0.1", "port": port,
            "outbound": "native-v4", "rules": [{"geoip": ["private"], "outbound": "native-v4"}], "settings": settings}]})
    }

    pub fn kerlico_landing(&self, keys: &Keys, port: u16, peer: u16) -> Value {
        json!({
            "inbounds": [{"tag": "inject", "protocol": "vless", "listen": "127.0.0.1", "port": port,
                "outbound": "landing", "rules": [{"domain": [format!("full:{ORIGIN_NAME}")], "outbound": "landing"}],
                "settings": {"decryption": "none", "users": [{"email": "inject-user", "id": INGRESS_ID_TEXT}]}}],
            "landing": {"protocol": "vless", "address": "127.0.0.1", "port": peer,
                "settings": self.kerlico_settings(keys, false)},
        })
    }

    fn kerlico_settings(&self, keys: &Keys, server: bool) -> Value {
        let mut settings =
            json!({"network": self.network.name(), "security": self.security.name()});
        if server {
            settings["decryption"] = json!(keys.decryption);
        } else {
            settings["encryption"] = json!(keys.encryption);
            settings["id"] = json!(ID);
            settings["flow"] = json!(self.flow);
            settings["mux"] = self.mux.clone().unwrap_or(json!(false));
        }
        match self.security {
            Security::None => {}
            Security::Tls(alpn) => {
                if !alpn.is_empty() {
                    settings["alpn"] = json!(alpn);
                }
                if server && self.mock.is_none() {
                    settings["certificateFile"] = json!(keys.cert);
                    settings["keyFile"] = json!(keys.key);
                } else {
                    settings["serverName"] = json!(TLS_NAME);
                    if self.pin || self.mock.is_some() {
                        settings["pinnedPeerCertSha256"] = json!(keys.pin);
                    } else {
                        settings["allowInsecure"] = json!(true);
                    }
                }
            }
            Security::Reality => {
                settings["shortId"] = json!(SHORT_ID);
                if server {
                    settings["privateKey"] = json!(keys.reality_private);
                    settings["target"] = json!(format!("127.0.0.1:{}", keys.decoy));
                } else {
                    settings["publicKey"] = json!(keys.reality_public);
                    settings["serverName"] = json!(TLS_NAME);
                }
                if self.mldsa {
                    settings[if server { "mldsa65Seed" } else { "mldsa65Verify" }] = json!(if server { &keys.mldsa_seed } else { &keys.mldsa_verify });
                }
            }
        }
        match self.network {
            Network::Raw | Network::Kcp("none") => {}
            Network::RawHttp(custom) => settings["header"] = raw_http_header(custom),
            Network::Kcp(mask) => {
                if matches!(mask, "seed" | "dns-seed") {
                    settings["seed"] = json!("matrix-mkcp-seed");
                }
                if mask != "seed" {
                    settings["header"] = json!(if mask == "dns-seed" { "dns" } else { mask });
                }
                if matches!(mask, "dns" | "dns-seed") {
                    settings["domain"] = json!("example.com");
                }
            }
            Network::WebSocket(early) | Network::Upgrade(early) => {
                let upgrade = self.upgrade_settings(early, server);
                settings.as_object_mut().unwrap().extend(upgrade.as_object().unwrap().clone());
            }
            Network::Grpc(multi) => {
                settings.as_object_mut().unwrap().extend(grpc_options(multi, server).as_object().unwrap().clone());
                if self.name == "grpc-tls-sudoku" { settings["finalmask"] = grpc_sudoku(); }
            }
            Network::Xhttp(mode) => {
                let xhttp = self.xhttp_settings(keys, mode, server);
                settings.as_object_mut().unwrap().extend(xhttp.as_object().unwrap().clone());
            }
            Network::Hysteria => {
                settings["version"] = json!(2);
                settings["auth"] = json!(AUTH);
            }
            Network::Xdrive => {
                if let Some(service) = self.mock {
                    let addr = keys.mock_addr.expect("mock storage address");
                    settings["storageAddress"] = json!(addr.ip().to_string());
                    settings["storagePort"] = json!(addr.port());
                    settings["xdriveSettings"] = service.config(addr, self.security);
                } else {
                    settings["service"] = json!("local");
                    settings["remoteFolder"] = json!(keys.storage);
                }
            }
        }
        if let Some(params) = self.quic_parameters(server) {
            settings["finalmask"] = json!({"quicParams": params});
        }
        if let Some(params) = self.kcp_parameters(server) {
            settings["kcpSettings"] = params;
        }
        if server && self.name == "hysteria-quic-masquerade-string" {
            settings["masquerade"] = masquerade_string();
        }
        if let Some(sockopt) = self.sockopt {
            settings["sockopt"] = serde_json::from_str(sockopt).expect("sockopt fixture JSON");
        }
        if server && self.xff.is_some() {
            settings["sockopt"] = json!({"trustedXForwardedFor": ["X-Trusted-CDN"]});
        }
        settings
    }

    fn kcp_parameters(&self, server: bool) -> Option<Value> {
        if !self.name.starts_with("mkcp-parameters-") {
            return None;
        }
        Some(if server {
            json!({"mtu":700,"tti":15,"uplinkCapacity":1,"downlinkCapacity":1,
                "cwndMultiplier":2,"maxSendingWindow":700})
        } else {
            json!({"mtu":520,"tti":10,"uplinkCapacity":2,"downlinkCapacity":2,
                "cwndMultiplier":3,"maxSendingWindow":1040})
        })
    }

    fn quic_parameters(&self, server: bool) -> Option<Value> {
        match self.name.as_str() {
            "hysteria-quic-negotiated-brutal" => Some(json!({
                "congestion": "brutal",
                "brutalUp": if server { "12 Mbps" } else { "8 Mbps" },
                "brutalDown": if server { "4 Mbps" } else { "6 Mbps" },
                "debug": true
            })),
            "hysteria-quic-forced-brutal" => Some(json!({
                "congestion": "force-brutal",
                "brutalUp": "2 Mbps",
                "brutalDisableLossCompensation": true,
                "debug": true
            })),
            "hysteria-quic-aggressive-bbr" => Some(json!({
                "congestion": "bbr", "bbrProfile": "aggressive", "debug": true
            })),
            "xhttp-h3-quic-reno" => Some(json!({
                "congestion": "reno", "disableChromeParrot": true,
                "initStreamReceiveWindow": 32768, "maxStreamReceiveWindow": 131072,
                "initConnectionReceiveWindow": 65536, "maxConnectionReceiveWindow": 262144,
                "maxIncomingStreams": 8, "maxIdleTimeout": 12, "keepAlivePeriod": 3,
                "disablePathMTUDiscovery": true, "disableGSO": true, "disableStatelessReset": true
            })),
            "xhttp-h3-quic-conservative-bbr" => Some(json!({
                "congestion": "bbr", "bbrProfile": "conservative", "debug": true
            })),
            _ => None,
        }
    }
}

fn masquerade_string() -> Value {
    json!({"type":"string","content":"matrix Hysteria cover\n","statusCode":418,"headers":{"X-Cover":"matrix"}})
}

fn grpc_options(multi: bool, server: bool) -> Value {
    json!({
        "serviceName": "/matrix/v 1/tun|multi",
        "multiMode": multi,
        "authority": "matrix-authority.example",
        "user_agent": "matrix-grpc/1",
        "idle_timeout": if server { 1 } else { 10 },
        "health_check_timeout": 2,
        "permit_without_stream": true,
        "initial_windows_size": 131072
    })
}

fn grpc_sudoku() -> Value {
    json!({"tcp": [{"type": "sudoku", "settings": {"password": "mask-flow-test", "paddingMin": 5, "paddingMax": 15}}]})
}

pub struct Keys {
    pub cert: PathBuf,
    pub key: PathBuf,
    pub cert_pem: String,
    pub key_pem: String,
    pub pin: String,
    pub storage: PathBuf,
    pub mock_addr: Option<SocketAddr>,
    pub decoy: u16,
    pub download: u16,
    reality_private: String,
    reality_public: String,
    encryption: String,
    decryption: String,
    mldsa_seed: String,
    mldsa_verify: String,
}

impl Keys {
    pub fn generate(dir: &Path, case: &Case) -> Result<Self> {
        let mut certificate = rcgen::CertificateParams::new(vec![TLS_NAME.to_string()])?;
        if case.mldsa {
            // Xray REALITY copies the decoy's TLS record lengths. Leave room for
            // the 3309-byte ML-DSA-65 signature in its replacement certificate.
            let mut padding = vec![0x04, 0x82, 0x10, 0x00]; // DER OCTET STRING, 4096 bytes
            padding.resize(4 + 4096, 0);
            certificate.custom_extensions.push(rcgen::CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 32473, 1],
                padding,
            ));
        }
        let key_pair = rcgen::KeyPair::generate()?;
        let certificate = certificate.self_signed(&key_pair)?;
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        let cert_pem = certificate.pem();
        let key_pem = key_pair.serialize_pem();
        let pin = format!("{:x}", Sha256::digest(certificate.der().as_ref()));
        fs::write(&cert, &cert_pem)?;
        fs::write(&key, &key_pem)?;
        let (reality_private, reality_public) = kerlico_vless::reality_pair();
        let (mldsa_seed, mldsa_verify) = if case.mldsa {
            let (seed, _) = kerlico_vless::native_pair();
            let seed = kerlico_vless::encode_reality_key(&seed);
            let signer = kerlico_vless::RealityMldsa65Signer::from_base64(&seed).ok_or("ML-DSA seed")?;
            let public = signer.verification_key();
            (seed, public)
        } else { (String::new(), String::new()) };
        let (encryption, decryption) = if let Some(cipher) = case.cipher {
            let (secret, public) = kerlico_vless::native_pair();
            let rtt = if case.resume { "0rtt" } else { "1rtt" };
            let seconds = if case.resume { "300-600s" } else { "0s" };
            (
                kerlico_vless::encode_key(&format!("mlkem768x25519plus.{cipher}.{rtt}."), &public),
                kerlico_vless::encode_key(
                    &format!("mlkem768x25519plus.{cipher}.{seconds}."),
                    &secret,
                ),
            )
        } else {
            ("none".into(), "none".into())
        };
        Ok(Self {
            cert,
            key,
            cert_pem,
            key_pem,
            pin,
            storage: dir.join("storage"),
            mock_addr: None,
            decoy: 0,
            download: 0,
            reality_private: kerlico_vless::encode_reality_key(&reality_private),
            reality_public: kerlico_vless::encode_reality_key(&reality_public),
            encryption,
            decryption,
            mldsa_seed,
            mldsa_verify,
        })
    }
}

fn path(early: bool) -> &'static str {
    if early {
        "/matrix?ed=2048"
    } else {
        PATH
    }
}

fn raw_http_header(custom: bool) -> Value {
    if !custom {
        return json!({"type": "http"});
    }
    json!({
        "type": "http",
        "request": {
            "version": "1.0",
            "method": "PUT",
            "path": ["/matrix", "/cdn"],
            "headers": {"Host": ["cover.example", "cdn.example"], "User-Agent": "matrix/1.0", "X-Cover": ["raw"]}
        },
        "response": {
            "status": "404",
            "reason": "Cover",
            "headers": {"Content-Type": ["application/octet-stream"], "Transfer-Encoding": ["chunked"]}
        }
    })
}

fn kcp_masks(mask: &str) -> Vec<Value> {
    let mut masks = Vec::new();
    if matches!(mask, "seed" | "dns-seed") {
        masks.push(json!({"type": "mkcp-legacy", "settings": {"value": "matrix-mkcp-seed"}}));
    }
    match mask {
        "seed" => {}
        "original" => masks.push(json!({"type": "mkcp-legacy"})),
        "dns" | "dns-seed" => masks.push(
            json!({"type": "mkcp-legacy", "settings": {"header": "dns", "value": "example.com"}}),
        ),
        header => masks.push(json!({"type": "mkcp-legacy", "settings": {"header": header}})),
    }
    masks
}

pub fn cases() -> Vec<Case> {
    use Network::*;
    use Payload::*;
    use Security::*;

    let mut cases = Vec::new();
    cases.push(Case::new("raw-reality-mldsa65", Raw, Reality, Tcp).mldsa());
    cases.push(Case::new("grpc-reality-mldsa65", Grpc(false), Reality, Tcp).mldsa());
    for (name, security) in [("none", None), ("tls", Tls("")), ("reality", Reality)] {
        cases.push(Case::new(format!("raw-{name}-tcp"), Raw, security, Tcp));
        cases.push(Case::new(format!("raw-{name}-udp"), Raw, security, Udp));
    }
    let mut tls12 = Case::new("raw-tls12-tcp", Raw, Tls(""), Tcp);
    tls12.tls12 = true;
    cases.push(tls12);
    let mut pinned = Case::new("raw-tls-pinned", Raw, Tls(""), Tcp);
    pinned.pin = true;
    cases.push(pinned);
    cases.push(Case::new("raw-mux-tcp-interleaved", Raw, None, TwoTcp).mux());
    cases.push(Case::new("raw-mux-xudp", Raw, None, Udp).mux());
    cases.push(Case::new("raw-udp-cone", Raw, None, Udp).cone().carriers(1, Some(3)));
    cases.push(Case::new("raw-udp53-cone", Raw, None, Udp53).cone().carriers(1, Some(2)));
    for (concurrency, carriers) in [(8, 1), (1, 2)] {
        cases.push(
            Case::new(format!("raw-mux-tcp-concurrency-{concurrency}"), Raw, None, TwoTcp)
                .mux_with(json!({"enabled": true, "concurrency": concurrency}))
                .carriers(carriers, Some(3)),
        );
    }
    cases.push(
        Case::new("raw-mux-udp443-allow", Raw, None, Udp443)
            .cone()
            .mux_with(json!({"enabled": true, "xudpProxyUDP443": "allow"}))
            .carriers(1, Some(3)),
    );
    cases.push(
        Case::new("raw-mux-udp443-skip", Raw, None, Udp443)
            .cone()
            .mux_with(json!({"enabled": true, "xudpProxyUDP443": "skip"}))
            .carriers(1, Some(2)),
    );
    cases.push(Case::new("raw-http-auth-default", RawHttp(false), None, Tcp));
    cases.push(Case::new("raw-http-auth-tls", RawHttp(true), Tls("http/1.1"), Tcp));
    cases.push(Case::new("raw-http-auth-reality", RawHttp(true), Reality, Tcp));
    cases.push(Case::new("raw-http-auth-encryption-vision", RawHttp(true), None, InnerTls).encryption("native", false).vision(false));
    for (name, network) in [("ws", WebSocket(false)), ("httpupgrade", Upgrade(false))] {
        cases.push(Case::new(format!("{name}-none"), network, None, Tcp));
        cases.push(Case::new(
            format!("{name}-tls-h1"),
            network,
            Tls("http/1.1"),
            Tcp,
        ));
    }
    cases.push(Case::new("ws-early-data", WebSocket(true), None, Tcp));
    cases.push(Case::new("ws-early-data-tls", WebSocket(true), Tls("http/1.1"), Tcp));
    cases.push(Case::new("httpupgrade-early-data-tls", Upgrade(true), Tls("http/1.1"), Tcp));
    cases.push(Case::new("ws-custom-headers-early", WebSocket(true), None, Tcp).custom_upgrade());
    cases.push(Case::new("ws-custom-headers-encryption-vision", WebSocket(true), Tls("http/1.1"), InnerTls).custom_upgrade().encryption("native", false).vision(false));
    cases.push(Case::new("httpupgrade-custom-headers", Upgrade(false), None, Tcp).custom_upgrade());
    cases.push(Case::new("httpupgrade-custom-headers-early-tls", Upgrade(true), Tls("http/1.1"), Tcp).custom_upgrade());
    cases.push(Case::new("httpupgrade-custom-headers-encryption-vision", Upgrade(true), Tls("http/1.1"), InnerTls).custom_upgrade().encryption("native", false).vision(false));
    cases.push(Case::new(
        "httpupgrade-early-data",
        Upgrade(true),
        None,
        Tcp,
    ));
    for (name, security) in [("h2c", None), ("tls", Tls("h2")), ("reality", Reality)] {
        cases.push(Case::new(
            format!("grpc-{name}-tun"),
            Grpc(false),
            security,
            TwoTcp,
        ).single_carrier());
        cases.push(Case::new(
            format!("grpc-{name}-tunmulti"),
            Grpc(true),
            security,
            TwoTcp,
        ).single_carrier());
    }
    cases.push(Case::new("grpc-tls-sudoku", Grpc(true), Tls("h2"), TwoTcp).single_carrier());
    for mask in [
        "none",
        "original",
        "seed",
        "dns",
        "dns-seed",
        "dtls",
        "srtp",
        "utp",
        "wechat",
        "wireguard",
    ] {
        cases.push(Case::new(format!("mkcp-{mask}"), Kcp(mask), None, Tcp));
    }
    cases.push(Case::new("mkcp-tls", Kcp("none"), Tls(""), Tcp));
    cases.push(Case::new("mkcp-parameters-plain", Kcp("none"), None, Tcp));
    cases.push(Case::new("mkcp-parameters-tls", Kcp("none"), Tls(""), Tcp));
    cases.push(Case::new("mkcp-parameters-seed", Kcp("seed"), None, Tcp));
    for (name, security) in [
        ("h1-none", None),
        ("h1-tls", Tls("http/1.1")),
        ("h2-tls", Tls("h2")),
        ("h3-tls", Tls("h3")),
        ("h2-reality", Reality),
    ] {
        for mode in ["packet-up", "stream-up", "stream-one", "auto"] {
            cases.push(Case::new(
                format!("xhttp-{name}-{mode}"),
                Xhttp(mode),
                security,
                Tcp,
            ));
        }
    }
    cases.push(Case::new("xhttp-h1-header-get", Xhttp("packet-up"), None, Tcp).xhttp(XhttpOptions::Header));
    cases.push(Case::new("xhttp-h2-cookie-options", Xhttp("packet-up"), Tls("h2"), Tcp).xhttp(XhttpOptions::Cookie));
    cases.push(Case::new("xhttp-h3-query-get", Xhttp("packet-up"), Tls("h3"), Tcp).xhttp(XhttpOptions::Query));
    cases.push(Case::new("xhttp-h1-stream-patch", Xhttp("stream-up"), None, Tcp).xhttp(XhttpOptions::Stream));
    cases.push(Case::new("xhttp-reality-auto-separate-download", Xhttp("auto"), Reality, Tcp).xhttp(XhttpOptions::SeparateDownload));
    cases.push(Case::new("xhttp-h2-tls-max-streams-1", Xhttp("packet-up"), Tls("h2"), TwoTcp).h2_params(r#"{"MaxConcurrentStreams":1}"#));
    cases.push(Case::new("xhttp-h2-reality-max-streams-1", Xhttp("packet-up"), Reality, TwoTcp).h2_params(r#"{"MaxConcurrentStreams":1}"#));
    for rounds in [1, 2, 3, 4, 5, 6, 7, 8] {
        cases.push(Case::new(format!("xhttp-h2-xmux-requests-3-rounds-{rounds}"), Xhttp("packet-up"), Tls("h2"), Rounds(rounds)).xmux(r#"{"hMaxRequestTimes":3}"#));
    }
    cases.push(Case::new("xhttp-h2-xmux-requests-1-rounds-3", Xhttp("packet-up"), Tls("h2"), Rounds(3)).xmux(r#"{"hMaxRequestTimes":1}"#));
    cases.push(Case::new("xhttp-h2-xmux-requests-2-rounds-4", Xhttp("packet-up"), Tls("h2"), Rounds(4)).xmux(r#"{"hMaxRequestTimes":2}"#));
    cases.push(Case::new("xhttp-h2-xmux-stream-up-requests-1", Xhttp("stream-up"), Tls("h2"), TwoTcp).xmux(r#"{"hMaxRequestTimes":1}"#));
    cases.push(Case::new("xhttp-h2-xmux-stream-up-requests-2", Xhttp("stream-up"), Tls("h2"), TwoTcp).xmux(r#"{"hMaxRequestTimes":2}"#));
    cases.push(Case::new("xhttp-h2-xmux-stream-one-requests-1", Xhttp("stream-one"), Tls("h2"), TwoTcp).xmux(r#"{"hMaxRequestTimes":1}"#));
    cases.push(Case::new("xhttp-h2-xmux-reuse-1", Xhttp("packet-up"), Tls("h2"), TwoTcp).xmux(r#"{"cMaxReuseTimes":1}"#));
    cases.push(Case::new("xhttp-h2-xmux-connections-2", Xhttp("packet-up"), Tls("h2"), TwoTcp).xmux(r#"{"maxConnections":2}"#));
    for (name, network, security) in [
        ("ws-none", WebSocket(false), None),
        ("httpupgrade-none", Upgrade(false), None),
        ("xhttp-h1-packet-up", Xhttp("packet-up"), None),
        ("xhttp-h2-tls-stream-up", Xhttp("stream-up"), Tls("h2")),
    ] {
        for marker in [true, false] {
            let name = format!("{name}-forwarded-{}", if marker { "trusted" } else { "forged" });
            cases.push(Case::new(name, network, security, Tcp).xff(marker));
        }
    }
    const SOCKOPT: &str = r#"{"TCPKeepAliveIdle":30,"tcpKEEPALIVEInterval":10,"TcpUserTimeout":10000,"Penetrate":true,"TcpFastOpen":false,"DomainStrategy":"UseIPv4","UnknownOption":{"nested":[1]}}"#;
    cases.push(Case::new("raw-tls-sockopt-mixed-case", Raw, Tls(""), Tcp).sockopt(SOCKOPT));
    cases.push(Case::new("ws-none-sockopt-mixed-case", WebSocket(false), None, Tcp).sockopt(SOCKOPT));
    cases.push(Case::new("xhttp-h2-tls-sockopt-mixed-case", Xhttp("packet-up"), Tls("h2"), Tcp).sockopt(SOCKOPT));
    cases.push(Case::new("hysteria-tls-tcp", Hysteria, Tls("h3"), Tcp));
    cases.push(Case::new("hysteria-tls-udp", Hysteria, Tls("h3"), Udp));
    for name in ["hysteria-quic-negotiated-brutal", "hysteria-quic-forced-brutal", "hysteria-quic-aggressive-bbr", "hysteria-quic-masquerade-string"] {
        cases.push(Case::new(name, Hysteria, Tls("h3"), Tcp));
    }
    for name in ["xhttp-h3-quic-reno", "xhttp-h3-quic-conservative-bbr"] {
        cases.push(Case::new(name, Xhttp("stream-one"), Tls("h3"), Tcp));
    }
    cases.push(
        Case::new("xdrive-local-mux-tcp", Xdrive, None, TwoTcp)
            .encryption("native", false)
            .mux(),
    );
    cases.push(
        Case::new("xdrive-local-xudp", Xdrive, None, Udp)
            .encryption("native", false)
            .mux(),
    );
    for (name, service, security, payload) in [
        ("template-http1-tcp", Service::Template, None, TwoTcp),
        ("template-http2-tls-tcp", Service::Template, Tls("h2"), TwoTcp),
        ("template-http3-xudp", Service::Template, Tls("h3"), Udp),
        ("s3-path-http1-tcp", Service::S3 { virtual_host: false }, None, TwoTcp),
        ("s3-path-http2-tls-xudp", Service::S3 { virtual_host: false }, Tls("h2"), Udp),
        ("s3-virtual-http3-xudp", Service::S3 { virtual_host: true }, Tls("h3"), Udp),
        ("drive-http1-tls-ring-tcp", Service::Drive, Tls("http/1.1"), TwoTcp),
        ("drive-http2-tls-ring-tcp", Service::Drive, Tls("h2"), TwoTcp),
        ("drive-http3-ring-xudp", Service::Drive, Tls("h3"), Udp),
    ] {
        let mut case = Case::new(format!("xdrive-mock-{name}"), Xdrive, security, payload)
            .encryption("native", false)
            .mux();
        case.mock = Some(service);
        cases.push(case);
    }
    for cipher in ["native", "xorpub", "random"] {
        cases.push(
            Case::new(format!("raw-encryption-{cipher}-1rtt"), Raw, None, Tcp)
                .encryption(cipher, false),
        );
        cases.push(
            Case::new(
                format!("raw-encryption-{cipher}-ticket-reconnect"),
                Raw,
                None,
                Tcp,
            )
            .encryption(cipher, true),
        );
        cases.push(
            Case::new(
                format!("raw-encryption-{cipher}-vision"),
                Raw,
                None,
                InnerTls,
            )
            .encryption(cipher, false)
            .vision(false),
        );
    }
    for (name, network, security) in [
        ("raw-tls", Raw, Tls("")),
        ("raw-reality", Raw, Reality),
        ("mkcp", Kcp("none"), None),
        ("ws", WebSocket(false), None),
        ("httpupgrade-tls", Upgrade(false), Tls("http/1.1")),
        ("grpc-tls", Grpc(true), Tls("h2")),
        ("xhttp-h2-tls", Xhttp("stream-up"), Tls("h2")),
        ("hysteria-tls", Hysteria, Tls("h3")),
    ] {
        cases.push(
            Case::new(format!("{name}-encryption"), network, security, Tcp)
                .encryption("native", false),
        );
    }
    cases.push(Case::new("raw-tls-vision-tcp", Raw, Tls(""), Tcp).vision(false));
    cases.push(Case::new("raw-tls-vision-inner-tls", Raw, Tls(""), InnerTls).vision(false));
    cases.push(Case::new("raw-reality-vision-inner-tls", Raw, Reality, InnerTls).vision(false));
    cases
        .push(Case::new("mkcp-tls-vision-inner-tls", Kcp("none"), Tls(""), InnerTls).vision(false));
    cases.push(
        Case::new(
            "xhttp-encryption-vision-inner-tls",
            Xhttp("stream-one"),
            Tls("h2"),
            InnerTls,
        )
        .encryption("native", false)
        .vision(false),
    );
    cases.push(Case::new("raw-tls-vision-xudp", Raw, Tls(""), Udp).vision(false));
    cases.push(Case::new("raw-tls-vision-udp443", Raw, Tls(""), Udp443).vision(true));
    cases
}

/// Flows Xray's outbound refuses at dispatch although it accepts the config.
pub fn rejected_cases() -> Vec<Case> {
    use Network::Raw;
    use Payload::Udp443;
    use Security::None;

    vec![
        Case::new("reject-mux-udp443-default", Raw, None, Udp443)
            .cone()
            .mux_with(json!({"enabled": true}))
            .rejected(),
        Case::new("reject-mux-udp443-reject", Raw, None, Udp443)
            .cone()
            .mux_with(json!({"enabled": true, "xudpProxyUDP443": "reject"}))
            .rejected(),
    ]
}
