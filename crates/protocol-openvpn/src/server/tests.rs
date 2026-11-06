use super::*;
use crate::{
    data::DataCipher,
    push::PushedConfig,
    session::{Credentials, Event, Session, Settings},
    tls::client_config,
    wrap::{CryptV2ServerKey, WrapKeys},
};
use kerlico_core::CancellationToken;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, DnType,
    ExtendedKeyUsagePurpose, IsCa, Issuer, KeyIdMethod, KeyPair, KeyUsagePurpose,
    RevokedCertParams, SerialNumber,
};
use serde_json::{Value, json};
use std::net::Ipv4Addr;

struct Authority {
    params: CertificateParams,
    key: KeyPair,
    pem: String,
}
impl Authority {
    fn new(name: &str) -> Self {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let key = KeyPair::generate().unwrap();
        let pem = params.self_signed(&key).unwrap().pem();
        Self { params, key, pem }
    }
    /// 返回证书与私钥 PEM；`usage` 为空时证书不带 EKU，`key_usage` 为假时不带 KU。
    fn issue(
        &self,
        name: &str,
        usage: Vec<ExtendedKeyUsagePurpose>,
        key_usage: bool,
        serial: u64,
    ) -> (String, String) {
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name.push(DnType::CommonName, name);
        params.extended_key_usages = usage;
        if key_usage {
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        }
        params.serial_number = Some(SerialNumber::from(serial));
        let key = KeyPair::generate().unwrap();
        let certificate = params
            .signed_by(&key, &Issuer::from_params(&self.params, &self.key))
            .unwrap();
        (certificate.pem(), key.serialize_pem())
    }
    fn client(&self, name: &str, serial: u64) -> (String, String) {
        self.issue(
            name,
            vec![ExtendedKeyUsagePurpose::ClientAuth],
            true,
            serial,
        )
    }
    fn revoke(&self, serial: u64) -> String {
        CertificateRevocationListParams {
            this_update: rcgen::date_time_ymd(2024, 1, 1),
            next_update: rcgen::date_time_ymd(2099, 1, 1),
            crl_number: SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs: vec![RevokedCertParams {
                serial_number: SerialNumber::from(serial),
                revocation_time: rcgen::date_time_ymd(2024, 1, 1),
                reason_code: None,
                invalidity_date: None,
            }],
            key_identifier_method: KeyIdMethod::Sha256,
        }
        .signed_by(&Issuer::from_params(&self.params, &self.key))
        .unwrap()
        .pem()
        .unwrap()
    }
}

struct Pki {
    ca: Authority,
    server: (String, String),
}
fn pki() -> Pki {
    let ca = Authority::new("test-ca");
    let server = ca.issue("server", vec![ExtendedKeyUsagePurpose::ServerAuth], true, 1);
    Pki { ca, server }
}

fn node_options(pki: &Pki, extra: Value) -> Value {
    let mut options = json!({
        "address": ["10.8.0.1/24"],
        "tls": { "certificate": pki.server.0, "key": pki.server.1 },
    });
    merge(&mut options, extra);
    options
}
fn merge(target: &mut Value, extra: Value) {
    match (target, extra) {
        (Value::Object(target), Value::Object(extra)) => {
            for (key, value) in extra {
                match target.get_mut(&key) {
                    Some(existing) if existing.is_object() && value.is_object() => {
                        merge(existing, value);
                    }
                    _ => {
                        target.insert(key, value);
                    }
                }
            }
        }
        (target, extra) => *target = extra,
    }
}

fn plan(options: Value) -> Result<Plan> {
    let options =
        serde_json::from_value(options).map_err(|error| Error::Config(error.to_string()))?;
    Plan::build(options, Vec::new())
}

struct TestGate {
    users: Vec<ServerUserConfig>,
    plans: BTreeMap<String, UserPlan>,
    username_as_common_name: bool,
}
impl Gate for TestGate {
    fn admit(
        &mut self,
        ticket: &mut Ticket,
        request: &AuthRequest<'_>,
    ) -> std::result::Result<Grant, &'static str> {
        let row = self
            .users
            .iter()
            .find(|row| credential_matches(row, request))
            .ok_or("")?;
        let plan = &self.plans[&row.name];
        ticket
            .assign(
                &identity(request, self.username_as_common_name),
                plan.fixed_slot,
            )
            .map_err(|_| "no free address in the pool")?;
        Ok(Grant {
            push: plan.push.clone(),
            tunnel: None,
        })
    }
    fn readmit(&mut self, request: &AuthRequest<'_>, expected: &str) -> bool {
        self.users
            .iter()
            .any(|row| credential_matches(row, request))
            && identity(request, self.username_as_common_name) == expected
    }
}

struct Server {
    tls: Arc<rustls::ServerConfig>,
    wrap: NodeWrap,
    registry: Arc<Registry>,
    settings: Arc<SessionSettings>,
    gate: TestGate,
}
impl Server {
    fn new(options: Value) -> Self {
        let plan = plan(options).unwrap();
        Self {
            tls: plan.tls,
            wrap: plan.wrap,
            registry: plan.registry,
            gate: TestGate {
                users: plan.users,
                plans: plan.user_plans,
                username_as_common_name: plan.settings.username_as_common_name,
            },
            settings: Arc::new(plan.settings),
        }
    }
}

struct ClientSpec<'a> {
    ca: &'a str,
    identity: Option<&'a (String, String)>,
    credentials: Option<(&'a str, &'a str)>,
    wrap: WrapKeys,
    ciphers: Vec<DataCipher>,
    peer_info: &'a str,
}
impl<'a> ClientSpec<'a> {
    fn new(ca: &'a str) -> Self {
        Self {
            ca,
            identity: None,
            credentials: None,
            wrap: WrapKeys::Plain,
            ciphers: DataCipher::ALL.to_vec(),
            peer_info: MODERN_PEER_INFO,
        }
    }
    fn session(self, now: Instant) -> Session {
        let identity = self
            .identity
            .map(|(certificate, key)| (certificate.as_str(), key.as_str()));
        let settings = Arc::new(Settings {
            tls: client_config(self.ca, identity, Some("server")).unwrap(),
            wrap: self.wrap,
            credentials: self.credentials.map(|(username, password)| Credentials {
                username: username.to_owned(),
                password: password.to_owned(),
            }),
            ciphers: self.ciphers,
            options: "V4,dev-type tun,link-mtu 1549,tun-mtu 1500,proto UDPv4,cipher AES-256-GCM,auth [null-digest],keysize 256,key-method 2,tls-client".to_owned(),
            peer_info: self.peer_info.to_owned(),
            ping: None,
            ping_restart: None,
            reneg: None,
            handshake: Duration::from_secs(60),
        });
        Session::new(settings, now).unwrap()
    }
}

const MODERN_PEER_INFO: &str = "IV_VER=2.6.20\nIV_PLAT=linux\nIV_PROTO=990\nIV_NCP=2\nIV_CIPHERS=AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305\n";

#[derive(Debug)]
enum Outcome {
    Up(PushedConfig),
    ServerRefused,
    ClientFailed(Error),
    Stalled,
}

/// 在内存中交换两端的包，直到客户端收到推送、任一端失败或不再有包。
fn pump(
    server: &mut Server,
    session: &mut Option<ServerSession>,
    client: &mut Session,
    now: Instant,
) -> Outcome {
    for _ in 0..64 {
        let c2s = client.take_outbox();
        let s2c = session
            .as_mut()
            .map(ServerSession::take_outbox)
            .unwrap_or_default();
        if c2s.is_empty() && s2c.is_empty() {
            break;
        }
        for packet in c2s {
            let step = match session {
                Some(session) => session.receive(now, &packet, &mut server.gate),
                None => {
                    let Some((mut started, first)) = ServerSession::start(
                        server.settings.clone(),
                        server.tls.clone(),
                        &server.wrap,
                        &server.registry,
                        CancellationToken::new(),
                        now,
                        &packet,
                    ) else {
                        continue;
                    };
                    let step = started.begin(now, first, &mut server.gate);
                    *session = Some(started);
                    step
                }
            };
            if step.is_err() {
                for packet in session.as_mut().unwrap().take_outbox() {
                    if let Err(client_error) = client.receive(now, &packet) {
                        return Outcome::ClientFailed(client_error);
                    }
                }
                return Outcome::ServerRefused;
            }
        }
        for packet in s2c {
            if let Err(error) = client.receive(now, &packet) {
                return Outcome::ClientFailed(error);
            }
        }
        for event in client.take_events() {
            if let Event::Up(config) = event {
                return Outcome::Up(config);
            }
        }
    }
    Outcome::Stalled
}

fn connect(
    server: &mut Server,
    client: ClientSpec<'_>,
    now: Instant,
) -> (Outcome, Option<ServerSession>, Session) {
    let mut client = client.session(now);
    let mut session = None;
    let outcome = pump(server, &mut session, &mut client, now);
    // 推送后客户端会再确认，排空余下的包。
    if matches!(outcome, Outcome::Up(_)) {
        let _ = pump(server, &mut session, &mut client, now);
    }
    (outcome, session, client)
}

fn address(outcome: &Outcome) -> Option<Ipv4Addr> {
    match outcome {
        Outcome::Up(config) => config.address_v4,
        _ => None,
    }
}

const IPV4_PING: [u8; 20] = [
    0x45, 0x00, 0x00, 0x14, 1, 2, 3, 4, 64, 17, 0, 0, 10, 8, 0, 2, 10, 8, 0, 1,
];

fn exchange_data(session: &mut ServerSession, client: &mut Session, now: Instant) -> bool {
    client.send_packet(now, &IPV4_PING).unwrap();
    for wire in client.take_outbox() {
        session.receive(now, &wire, &mut NoGate).unwrap();
    }
    let received = session.take_packets() == vec![IPV4_PING.to_vec()];
    session.send_packet(now, &IPV4_PING).unwrap();
    for wire in session.take_outbox() {
        client.receive(now, &wire).unwrap();
    }
    let sent = client
        .take_events()
        .iter()
        .any(|event| matches!(event, Event::Packet(packet) if packet == &IPV4_PING));
    received && sent
}

struct NoGate;
impl Gate for NoGate {
    fn admit(
        &mut self,
        _: &mut Ticket,
        _: &AuthRequest<'_>,
    ) -> std::result::Result<Grant, &'static str> {
        Err("")
    }
    fn readmit(&mut self, _: &AuthRequest<'_>, _: &str) -> bool {
        false
    }
}

fn cert_node(pki: &Pki, extra: Value) -> Server {
    let mut options = node_options(
        pki,
        json!({
            "tls": { "client_certificate": pki.ca.pem, "verify_client_certificate": "require" },
            "users": [{ "name": "alice" }],
        }),
    );
    merge(&mut options, extra);
    Server::new(options)
}

#[test]
fn certificate_signed_by_the_client_ca_logs_in_and_carries_data() {
    let pki = pki();
    let mut server = cert_node(&pki, json!({}));
    let alice = pki.ca.client("alice", 10);
    let now = Instant::now();
    let mut spec = ClientSpec::new(&pki.ca.pem);
    spec.identity = Some(&alice);
    let (outcome, session, mut client) = connect(&mut server, spec, now);
    assert_eq!(
        address(&outcome),
        Some(Ipv4Addr::new(10, 8, 0, 2)),
        "{outcome:?}"
    );
    assert!(exchange_data(&mut session.unwrap(), &mut client, now));
}

#[test]
fn missing_untrusted_revoked_or_misnamed_client_certificates_are_refused() {
    let pki = pki();
    let other = Authority::new("other-ca");
    let now = Instant::now();
    let refused = |server: &mut Server, identity: Option<&(String, String)>| {
        let mut spec = ClientSpec::new(&pki.ca.pem);
        spec.identity = identity;
        let (outcome, _, _) = connect(server, spec, now);
        assert!(
            matches!(outcome, Outcome::ServerRefused | Outcome::ClientFailed(_)),
            "{outcome:?}"
        );
        assert_eq!(
            server.registry.active(),
            0,
            "refused session released its slot"
        );
    };
    let mut server = cert_node(&pki, json!({}));
    refused(&mut server, None);
    refused(&mut server, Some(&other.client("alice", 11)));
    refused(
        &mut server,
        Some(
            &pki.ca
                .issue("alice", vec![ExtendedKeyUsagePurpose::ServerAuth], true, 12),
        ),
    );
    refused(
        &mut server,
        Some(&pki.ca.issue(
            "alice",
            vec![ExtendedKeyUsagePurpose::ClientAuth],
            false,
            13,
        )),
    );
    refused(&mut server, Some(&pki.ca.client("mallory", 14)));

    let mut revoked = cert_node(&pki, json!({ "tls": { "crl_pem": pki.ca.revoke(15) } }));
    refused(&mut revoked, Some(&pki.ca.client("alice", 15)));
    let mut spec = ClientSpec::new(&pki.ca.pem);
    let fresh = pki.ca.client("alice", 16);
    spec.identity = Some(&fresh);
    assert!(
        matches!(connect(&mut revoked, spec, now).0, Outcome::Up(_)),
        "unrevoked serial still logs in"
    );

    let mut named = cert_node(
        &pki,
        json!({ "tls": { "client_name": "dept-", "client_name_type": "name-prefix" }, "users": [{ "name": "dept-a" }] }),
    );
    refused(&mut named, Some(&pki.ca.client("alice", 17)));
    let mut spec = ClientSpec::new(&pki.ca.pem);
    let dept = pki.ca.client("dept-a", 18);
    spec.identity = Some(&dept);
    assert!(matches!(connect(&mut named, spec, now).0, Outcome::Up(_)));
}

#[test]
fn peer_fingerprint_pins_a_self_signed_client_certificate_without_a_ca() {
    let pki = pki();
    let own = Authority::new("alice");
    let leaf = own.client("alice", 20);
    let der = crate::tls::parse_certificates(&leaf.0).unwrap();
    let pin: String = crate::tls::fingerprint(der[0].as_ref())
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    let mut server = Server::new(node_options(
        &pki,
        json!({ "tls": { "peer_fingerprint": [pin] }, "users": [{ "name": "alice" }] }),
    ));
    let now = Instant::now();
    let mut spec = ClientSpec::new(&pki.ca.pem);
    spec.identity = Some(&leaf);
    assert!(matches!(connect(&mut server, spec, now).0, Outcome::Up(_)));
    let stranger = own.client("alice", 21);
    let mut spec = ClientSpec::new(&pki.ca.pem);
    spec.identity = Some(&stranger);
    assert!(!matches!(connect(&mut server, spec, now).0, Outcome::Up(_)));
}

fn password_node(pki: &Pki, extra: Value) -> Server {
    let mut options = node_options(
        pki,
        json!({ "users": [{ "name": "alice", "password": "secret" }, { "name": "bob", "password": "hunter2" }] }),
    );
    merge(&mut options, extra);
    Server::new(options)
}

fn password_client<'a>(pki: &'a Pki, user: &'a str, password: &'a str) -> ClientSpec<'a> {
    let mut spec = ClientSpec::new(&pki.ca.pem);
    spec.credentials = Some((user, password));
    spec
}

#[test]
fn password_login_assigns_unique_addresses_and_releases_them_on_disconnect() {
    let pki = pki();
    let mut server = password_node(&pki, json!({}));
    let now = Instant::now();
    let (first, first_session, _) =
        connect(&mut server, password_client(&pki, "alice", "secret"), now);
    let (second, second_session, _) =
        connect(&mut server, password_client(&pki, "bob", "hunter2"), now);
    assert_eq!(address(&first), Some(Ipv4Addr::new(10, 8, 0, 2)));
    assert_eq!(address(&second), Some(Ipv4Addr::new(10, 8, 0, 3)));
    let (wrong, _, _) = connect(&mut server, password_client(&pki, "alice", "nope"), now);
    assert!(
        matches!(wrong, Outcome::ClientFailed(Error::Rejected)),
        "client sees AUTH_FAILED: {wrong:?}"
    );
    drop(first_session);
    let (third, _third_session, _) =
        connect(&mut server, password_client(&pki, "alice", "secret"), now);
    assert_eq!(
        address(&third),
        Some(Ipv4Addr::new(10, 8, 0, 2)),
        "released address reused"
    );
    drop(second_session);
}

#[test]
fn max_clients_counts_handshaking_sessions_and_frees_on_close() {
    let pki = pki();
    let mut server = password_node(&pki, json!({ "max_clients": 1 }));
    let now = Instant::now();
    let (first, session, _) = connect(&mut server, password_client(&pki, "alice", "secret"), now);
    assert!(matches!(first, Outcome::Up(_)));
    let (second, none, _) = connect(&mut server, password_client(&pki, "bob", "hunter2"), now);
    assert!(
        matches!(second, Outcome::Stalled) && none.is_none(),
        "{second:?}"
    );
    drop(session);
    let (third, _, _) = connect(&mut server, password_client(&pki, "bob", "hunter2"), now);
    assert!(matches!(third, Outcome::Up(_)));
}

#[test]
fn second_login_with_the_same_name_kicks_the_first_unless_duplicate_cn() {
    let pki = pki();
    let now = Instant::now();
    let mut strict = password_node(&pki, json!({}));
    let (_, first, _) = connect(&mut strict, password_client(&pki, "alice", "secret"), now);
    let (second, _second_session, _) =
        connect(&mut strict, password_client(&pki, "alice", "secret"), now);
    assert_eq!(
        address(&second),
        Some(Ipv4Addr::new(10, 8, 0, 2)),
        "kicked session's address passes on"
    );
    assert!(matches!(first.unwrap().tick(now), Err(Error::Cancelled)));

    let mut shared = password_node(&pki, json!({ "duplicate_cn": true }));
    let (_, first, _) = connect(&mut shared, password_client(&pki, "alice", "secret"), now);
    let (second, _second, _) = connect(&mut shared, password_client(&pki, "alice", "secret"), now);
    assert_eq!(address(&second), Some(Ipv4Addr::new(10, 8, 0, 3)));
    assert!(first.unwrap().tick(now).is_ok());
}

#[test]
fn push_reply_carries_configured_routes_dns_topology_and_per_user_address() {
    let pki = pki();
    let mut server = Server::new(node_options(
        &pki,
        json!({
            "address": ["10.9.0.1/24", "fd00:9::1/64"],
            "topology": "net30",
            "push": { "routes": ["192.0.2.0/24"], "dns": ["192.0.2.53"], "redirect_gateway": true },
            "keepalive": { "interval": 7, "timeout": 40 },
            "users": [
                { "name": "alice", "password": "secret", "address": "10.9.0.10", "push": { "routes": ["198.51.100.0/24"] } },
                { "name": "bob", "password": "hunter2" }
            ],
        }),
    ));
    let now = Instant::now();
    let (alice, _a, _) = connect(&mut server, password_client(&pki, "alice", "secret"), now);
    let (bob, _b, _) = connect(&mut server, password_client(&pki, "bob", "hunter2"), now);
    let Outcome::Up(alice) = alice else {
        panic!("{alice:?}")
    };
    assert_eq!(
        alice.address_v4,
        Some(Ipv4Addr::new(10, 9, 0, 10)),
        "fixed per-user address"
    );
    assert_eq!(alice.ping, Some(7));
    assert_eq!(alice.ping_restart, Some(40));
    assert_eq!(
        address(&bob),
        Some(Ipv4Addr::new(10, 9, 0, 6)),
        "first free net30 block skips the reserved one"
    );
    let Outcome::Up(bob) = bob else {
        unreachable!()
    };
    assert_eq!(bob.address_v6, Some("fd00:9::1000".parse().unwrap()));
}

#[test]
fn push_reply_text_lists_what_the_config_asks_for() {
    let assignment =
        registry::AddressPool::new(registry::Topology::Subnet, &["10.8.0.1/24".to_owned()])
            .unwrap()
            .assignment(0);
    let plan = plan(node_options(
        &pki(),
        json!({
            "push": { "routes": ["192.0.2.0/24"], "dns": ["192.0.2.53"], "redirect_gateway": true },
            "users": [{ "name": "a", "password": "b" }],
        }),
    ))
    .unwrap();
    let messages = crate::push::push_reply(
        &plan.settings.push_lines,
        &crate::push::ReplyContext {
            assignment: &assignment,
            ping: plan.settings.push_ping,
            ping_restart: plan.settings.push_ping_restart,
            peer_id: 0,
            cipher: "AES-256-GCM",
            key_derivation: crate::push::KeyDerivation::EkmProtocolFlag,
            cc_exit: false,
            tun_mtu: None,
        },
    );
    assert_eq!(
        String::from_utf8_lossy(&messages[0]),
        "PUSH_REPLY,redirect-gateway def1,route 192.0.2.0 255.255.255.0,dhcp-option DNS 192.0.2.53,\
         route-gateway 10.8.0.1,topology subnet,ping 10,ping-restart 60,ifconfig 10.8.0.2 255.255.255.0,\
         peer-id 0,cipher AES-256-GCM,protocol-flags tls-ekm\0"
    );
}

#[test]
fn ncp_follows_server_order_within_what_the_client_offers() {
    let pki = pki();
    let mut server = password_node(
        &pki,
        json!({ "data_ciphers": ["CHACHA20-POLY1305", "AES-128-GCM"] }),
    );
    let now = Instant::now();
    let mut spec = password_client(&pki, "alice", "secret");
    spec.peer_info = "IV_VER=2.6.20\nIV_PROTO=990\nIV_CIPHERS=AES-256-GCM:AES-128-GCM\n";
    let (outcome, session, mut client) = connect(&mut server, spec, now);
    let Outcome::Up(config) = &outcome else {
        panic!("{outcome:?}")
    };
    assert_eq!(config.cipher.as_deref(), Some("AES-128-GCM"));
    assert!(exchange_data(&mut session.unwrap(), &mut client, now));

    let mut spec = password_client(&pki, "bob", "hunter2");
    spec.peer_info = "IV_VER=2.6.20\nIV_PROTO=990\nIV_CIPHERS=AES-256-GCM\n";
    let (outcome, _, _) = connect(&mut server, spec, now);
    assert!(
        matches!(outcome, Outcome::ClientFailed(Error::Rejected)),
        "no shared cipher: {outcome:?}"
    );
}

#[test]
fn legacy_client_without_tls_ekm_uses_prf_keys() {
    let pki = pki();
    let mut server = password_node(&pki, json!({}));
    let now = Instant::now();
    let mut spec = password_client(&pki, "alice", "secret");
    spec.peer_info = "IV_VER=2.4.12\nIV_PROTO=2\nIV_NCP=2\n";
    let (outcome, session, mut client) = connect(&mut server, spec, now);
    let Outcome::Up(config) = &outcome else {
        panic!("{outcome:?}")
    };
    assert!(!config.tls_ekm);
    assert!(exchange_data(&mut session.unwrap(), &mut client, now));
}

#[test]
fn ping_restart_and_handshake_window_close_idle_sessions() {
    let pki = pki();
    let mut server = password_node(&pki, json!({ "ping_restart": 30, "handshake_window": 5 }));
    let now = Instant::now();
    let (_, session, _) = connect(&mut server, password_client(&pki, "alice", "secret"), now);
    let mut session = session.unwrap();
    assert!(session.tick(now + Duration::from_secs(29)).is_ok());
    assert!(matches!(
        session.tick(now + Duration::from_secs(31)),
        Err(Error::Timeout)
    ));

    let mut client = password_client(&pki, "bob", "hunter2").session(now);
    let first = client.take_outbox().remove(0);
    let (mut half, unwrapped) = ServerSession::start(
        server.settings.clone(),
        server.tls.clone(),
        &server.wrap,
        &server.registry,
        CancellationToken::new(),
        now,
        &first,
    )
    .unwrap();
    half.begin(now, unwrapped, &mut server.gate).unwrap();
    assert!(half.tick(now + Duration::from_secs(4)).is_ok());
    assert!(matches!(
        half.tick(now + Duration::from_secs(6)),
        Err(Error::Timeout)
    ));
}

#[test]
fn server_sends_ping_when_idle() {
    let pki = pki();
    let mut server = password_node(&pki, json!({ "ping": 3 }));
    let now = Instant::now();
    let (_, session, mut client) =
        connect(&mut server, password_client(&pki, "alice", "secret"), now);
    let mut session = session.unwrap();
    session.tick(now + Duration::from_secs(1)).unwrap();
    assert!(session.take_outbox().is_empty());
    session.tick(now + Duration::from_secs(4)).unwrap();
    let pings = session.take_outbox();
    assert_eq!(pings.len(), 1);
    client.receive(now, &pings[0]).unwrap();
    assert!(
        client.take_events().is_empty(),
        "keepalive ping is not delivered as an IP packet"
    );
}

#[test]
fn server_initiated_renegotiation_moves_both_sides_to_a_new_key_id() {
    let pki = pki();
    let mut server = password_node(&pki, json!({ "renegotiate_interval": "10s", "ping": 0 }));
    let now = Instant::now();
    let (_, session, mut client) =
        connect(&mut server, password_client(&pki, "alice", "secret"), now);
    let mut session = Some(session.unwrap());
    let later = now + Duration::from_secs(11);
    session.as_mut().unwrap().tick(later).unwrap();
    for _ in 0..4 {
        let _ = pump(&mut server, &mut session, &mut client, later);
        session.as_mut().unwrap().tick(later).unwrap();
    }
    let session = session.as_mut().unwrap();
    session.send_packet(later, &IPV4_PING).unwrap();
    let wire = session.take_outbox();
    assert_eq!(wire[0][0] & 7, 1, "data now uses key_id 1");
    assert!(exchange_data(session, &mut client, later));
}

#[test]
fn client_initiated_renegotiation_is_answered() {
    let pki = pki();
    let mut server = password_node(&pki, json!({ "renegotiate_disabled": true, "ping": 0 }));
    let now = Instant::now();
    let settings_client = {
        Arc::new(Settings {
            tls: client_config(&pki.ca.pem, None, Some("server")).unwrap(),
            wrap: WrapKeys::Plain,
            credentials: Some(Credentials {
                username: "bob".to_owned(),
                password: "hunter2".to_owned(),
            }),
            ciphers: DataCipher::ALL.to_vec(),
            options: String::new(),
            peer_info: MODERN_PEER_INFO.to_owned(),
            ping: None,
            ping_restart: None,
            reneg: Some(Duration::from_secs(5)),
            handshake: Duration::from_secs(60),
        })
    };
    let mut client = Session::new(settings_client, now).unwrap();
    let mut session = None;
    assert!(matches!(
        pump(&mut server, &mut session, &mut client, now),
        Outcome::Up(_)
    ));
    let later = now + Duration::from_secs(6);
    for _ in 0..4 {
        client.tick(later).unwrap();
        let _ = pump(&mut server, &mut session, &mut client, later);
        session.as_mut().unwrap().tick(later).unwrap();
    }
    let session = session.as_mut().unwrap();
    client.send_packet(later, &IPV4_PING).unwrap();
    let wire = client.take_outbox();
    assert_eq!(wire.last().unwrap()[0] & 7, 1, "client rekeyed to key_id 1");
    for packet in wire {
        session.receive(later, &packet, &mut NoGate).unwrap();
    }
    assert_eq!(session.take_packets(), vec![IPV4_PING.to_vec()]);
}

#[test]
fn tls_crypt_v2_server_unwraps_the_client_key_and_completes_the_handshake() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let pki = pki();
    let server_key = "-----BEGIN OpenVPN tls-crypt-v2 server key-----\n".to_owned()
        + &STANDARD.encode((0u8..128).collect::<Vec<_>>())
        + "\n-----END OpenVPN tls-crypt-v2 server key-----\n";
    let mut server = password_node(
        &pki,
        json!({ "tls": { "control_wrap": { "type": "tls_crypt_v2", "key": server_key } } }),
    );
    let sealer = CryptV2ServerKey::parse(&server_key).unwrap();
    let client_key: [u8; 256] = std::array::from_fn(|index| (index * 7) as u8);
    let wkc = sealer.seal_client_key(&client_key, &[0, b'u']);
    let file = format!(
        "-----BEGIN OpenVPN tls-crypt-v2 client key-----\n{}\n-----END OpenVPN tls-crypt-v2 client key-----\n",
        STANDARD.encode([client_key.as_slice(), &wkc].concat())
    );
    let now = Instant::now();
    let mut spec = password_client(&pki, "alice", "secret");
    spec.wrap = WrapKeys::parse_crypt_v2(&file).unwrap();
    let (outcome, session, mut client) = connect(&mut server, spec, now);
    assert_eq!(
        address(&outcome),
        Some(Ipv4Addr::new(10, 8, 0, 2)),
        "{outcome:?}"
    );
    assert!(exchange_data(&mut session.unwrap(), &mut client, now));

    let mut plain = password_client(&pki, "alice", "secret");
    plain.wrap = WrapKeys::Plain;
    assert!(
        matches!(connect(&mut server, plain, now).0, Outcome::Stalled),
        "unwrapped reset is dropped"
    );
}

#[test]
fn tls_crypt_and_tls_auth_wrapped_logins_succeed() {
    let pki = pki();
    let body: String = (0..256)
        .map(|index| format!("{:02x}", (index * 3) % 251))
        .collect();
    let key = format!(
        "-----BEGIN OpenVPN Static key V1-----\n{body}\n-----END OpenVPN Static key V1-----\n"
    );
    let static_key = crate::wrap::StaticKey::parse(&key).unwrap();
    let now = Instant::now();
    let mut crypt = password_node(
        &pki,
        json!({ "tls": { "control_wrap": { "type": "tls_crypt", "key": key } } }),
    );
    let mut spec = password_client(&pki, "alice", "secret");
    spec.wrap = WrapKeys::crypt(&static_key);
    assert!(matches!(connect(&mut crypt, spec, now).0, Outcome::Up(_)));
    let mut auth = password_node(
        &pki,
        json!({ "tls": { "control_wrap": { "type": "tls_auth", "key": key, "direction": "server", "auth": "SHA256" } } }),
    );
    let mut spec = password_client(&pki, "alice", "secret");
    spec.wrap = WrapKeys::auth(&static_key, crate::wrap::AuthDigest::Sha256, Some(1));
    assert!(matches!(connect(&mut auth, spec, now).0, Outcome::Up(_)));
}

#[test]
fn config_rejects_what_the_server_does_not_implement() {
    let pki = pki();
    let users = json!({ "users": [{ "name": "a", "password": "b" }] });
    let build = |extra: Value| {
        let mut options = node_options(&pki, users.clone());
        merge(&mut options, extra);
        plan(options).map(|_| ())
    };
    assert!(build(json!({})).is_ok());
    let error = |extra: Value| match build(extra) {
        Err(Error::Config(message)) => message,
        other => panic!("expected a config error, got {other:?}"),
    };
    assert!(error(json!({ "mode": "static_key" })).contains("static_key"));
    assert!(error(json!({ "static_key": "x" })).contains("static_key"));
    assert!(error(json!({ "tls": { "certificate": null, "key": null } })).contains("证书"));
    assert!(
        error(json!({ "tls": { "verify_client_certificate": "require" } }))
            .contains("client_certificate")
    );
    assert!(error(json!({ "data_ciphers": ["BF-CBC"] })).contains("BF-CBC"));
    assert!(error(json!({ "tls": { "control_wrap": { "type": "tls_crypt_v2", "key": "k", "force_cookie": true } } })).contains("force_cookie"));
    assert!(
        error(json!({ "tls": { "version_min": "1.3", "version_max": "1.2" } })).contains("版本")
    );
    assert!(
        error(json!({ "tls": { "cipher": "ECDHE-RSA-AES128-SHA" } }))
            .contains("ECDHE-RSA-AES128-SHA")
    );
    assert!(
        error(json!({ "client_to_client": true })).contains("client_to_client"),
        "unimplemented field is rejected"
    );
    assert!(plan(node_options(&pki, json!({}))).is_err(), "no members");
    assert!(
        plan(node_options(&pki, json!({ "users": [{ "name": "a" }] }))).is_err(),
        "certificate-only member needs required client certificates"
    );
}

#[test]
fn tls_version_and_suite_settings_shape_the_handshake() {
    let pki = pki();
    let now = Instant::now();
    let mut tls12 = password_node(
        &pki,
        json!({ "tls": { "version_max": "1.2", "cipher": "ECDHE-ECDSA-AES128-GCM-SHA256", "groups": "P-256" } }),
    );
    let (outcome, session, _) = connect(&mut tls12, password_client(&pki, "alice", "secret"), now);
    assert!(matches!(outcome, Outcome::Up(_)), "{outcome:?}");
    drop(session);
    let mut only_chacha = password_node(
        &pki,
        json!({ "tls": { "version_min": "1.3", "cipher_suites": ["TLS_CHACHA20_POLY1305_SHA256"] } }),
    );
    assert!(matches!(
        connect(
            &mut only_chacha,
            password_client(&pki, "alice", "secret"),
            now
        )
        .0,
        Outcome::Up(_)
    ));
    let mut ecdsa_mismatch = password_node(
        &pki,
        json!({ "tls": { "version_max": "1.2", "cipher": "ECDHE-RSA-AES128-GCM-SHA256" } }),
    );
    assert!(
        !matches!(
            connect(
                &mut ecdsa_mismatch,
                password_client(&pki, "alice", "secret"),
                now
            )
            .0,
            Outcome::Up(_)
        ),
        "an ECDSA server key cannot use an RSA-only TLS 1.2 suite"
    );
}

#[test]
fn factory_accepts_sing_box_field_names_and_members() {
    let pki = pki();
    let options = node_options(
        &pki,
        json!({
            "network": "tcp",
            "data_ciphers": ["AES-256-GCM"],
            "keepalive": { "interval": "10s", "timeout": "1m" },
            "renegotiate_interval": "1h",
            "replay_window": 128,
            "replay_window_time": "15s",
            "max_clients": 16,
            "tls": {
                "client_certificate": pki.ca.pem,
                "verify_client_certificate": "optional",
                "remote_certificate_tls": "client",
                "version_min": "1.2"
            },
            "push": { "routes": ["10.0.0.0/8"], "dns_servers": [{ "addresses": ["10.0.0.53"] }] }
        }),
    );
    let node = OpenVpnNodeFactory
        .build(&NodeBuildContext::for_test(
            options,
            vec![json!({ "username": "alice", "password": "secret" })],
        ))
        .expect("sing-box spellings build");
    assert!(node.supports_tcp() && !node.supports_udp());
}
