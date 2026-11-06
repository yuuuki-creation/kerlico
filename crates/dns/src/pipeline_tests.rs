use super::*;
use crate::{DnsDialer, wire::TYPE_A};
use kerlico_core::{BoxFuture, BoxStream, DatagramChannel, Destination};
use serde_json::json;
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::atomic::{AtomicUsize, Ordering},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};

const TYPE_TXT: u16 = 16;

enum Zone {
    Records(Vec<(u16, Vec<u8>, u32)>),
    NxDomain,
    Truncated,
}

type ZoneFn = Arc<dyn Fn(&str, u16, bool) -> Zone + Send + Sync>;

fn a(ip: [u8; 4], ttl: u32) -> Zone {
    Zone::Records(vec![(TYPE_A, ip.to_vec(), ttl)])
}

fn has_ecs(query: &[u8]) -> bool {
    wire::records(query).unwrap_or_default().iter().any(|r| {
        r.rtype == wire::TYPE_OPT
            && query[r.rdata.clone()].len() >= 2
            && query[r.rdata.start..r.rdata.start + 2] == [0, 8]
    })
}

fn zone_reply(zone: &ZoneFn, query: &[u8], udp: bool) -> Vec<u8> {
    let q = wire::parse_question(query).unwrap();
    let (rcode, tc, records) = match zone(&q.name, q.qtype, has_ecs(query)) {
        Zone::Records(r) => (0, false, r),
        Zone::NxDomain => (3, false, Vec::new()),
        Zone::Truncated if udp => (0, true, Vec::new()),
        Zone::Truncated => (0, false, vec![(TYPE_A, vec![10, 0, 0, 53], 60)]),
    };
    let mut out = query[..2].to_vec();
    out.push(0x81 | if tc { 0x02 } else { 0 });
    out.push(0x80 | rcode);
    out.extend_from_slice(&[0, 1]);
    out.extend_from_slice(&(records.len() as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(&query[12..q.end]);
    for (rtype, rdata, ttl) in records {
        out.extend_from_slice(&[0xc0, 0x0c]);
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&[0, 1]);
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&rdata);
    }
    out
}

/// 回环权威服务器：同一端口提供 UDP 与 TCP，按 `zone` 回答并计数。
struct Auth {
    addr: SocketAddr,
    hits: Arc<AtomicUsize>,
}

async fn auth(zone: impl Fn(&str, u16, bool) -> Zone + Send + Sync + 'static) -> Auth {
    let zone: ZoneFn = Arc::new(zone);
    let (udp, tcp, addr) = loop {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = udp.local_addr().unwrap();
        if let Ok(tcp) = TcpListener::bind(addr).await {
            break (udp, tcp, addr);
        }
    };
    let hits = Arc::new(AtomicUsize::new(0));
    let (z, h) = (zone.clone(), hits.clone());
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let (n, peer) = udp.recv_from(&mut buf).await.unwrap();
            h.fetch_add(1, Ordering::SeqCst);
            let reply = zone_reply(&z, &buf[..n], true);
            udp.send_to(&reply, peer).await.unwrap();
        }
    });
    let h = hits.clone();
    tokio::spawn(async move {
        loop {
            let (mut s, _) = tcp.accept().await.unwrap();
            let zone = zone.clone();
            h.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut len = [0u8; 2];
                while s.read_exact(&mut len).await.is_ok() {
                    let mut q = vec![0u8; u16::from_be_bytes(len) as usize];
                    s.read_exact(&mut q).await.unwrap();
                    let r = zone_reply(&zone, &q, false);
                    s.write_all(&(r.len() as u16).to_be_bytes()).await.unwrap();
                    s.write_all(&r).await.unwrap();
                }
            });
        }
    });
    Auth { addr, hits }
}

fn resolver(value: serde_json::Value) -> DnsResolver {
    let mut value = value;
    value["use-system-hosts"] = json!(false);
    DnsResolver::new(&serde_json::from_value(value).unwrap()).unwrap()
}

fn v4(s: &str) -> IpAddr {
    s.parse().unwrap()
}

async fn ask(r: &DnsResolver, name: &str, qtype: u16) -> DnsAnswer {
    let q = wire::build_query(0x4242, name, qtype).unwrap();
    r.query(&q, Purpose::Wire).await.unwrap()
}

fn ips(a: &DnsAnswer) -> Vec<IpAddr> {
    wire::answer_ips(&a.message)
}

#[tokio::test]
async fn local_resolution_uses_policy_hosts_and_main() {
    let main = auth(|_, t, _| {
        if t == TYPE_A {
            a([10, 0, 0, 1], 60)
        } else {
            Zone::Records(vec![])
        }
    })
    .await;
    let pol = auth(|_, t, _| {
        if t == TYPE_A {
            a([10, 0, 0, 2], 60)
        } else {
            Zone::Records(vec![])
        }
    })
    .await;
    let r = resolver(json!({
        "nameserver": [format!("udp://{}", main.addr)],
        "nameserver-policy": {"+.policy.test,*.star.test": format!("udp://{}", pol.addr)},
        "hosts": {"*.lan.test": "10.9.0.1", "alias.test": "x.policy.test"},
        "ipv6": false
    }));
    assert_eq!(
        r.resolve("www.example.test").await.unwrap(),
        vec![v4("10.0.0.1")]
    );
    assert_eq!(
        r.resolve("a.b.policy.test").await.unwrap(),
        vec![v4("10.0.0.2")]
    );
    assert_eq!(
        r.resolve("one.star.test").await.unwrap(),
        vec![v4("10.0.0.2")]
    );
    assert_eq!(
        r.resolve("two.one.star.test").await.unwrap(),
        vec![v4("10.0.0.1")]
    );
    assert_eq!(
        r.resolve("box.lan.test").await.unwrap(),
        vec![v4("10.9.0.1")]
    );
    assert_eq!(r.resolve("alias.test").await.unwrap(), vec![v4("10.0.0.2")]);
    let aaaa = ask(&r, "www.example.test", wire::TYPE_AAAA).await;
    assert_eq!(aaaa.source, AnswerSource::Ipv6Disabled);
}

#[tokio::test]
async fn fallback_filter_follows_mihomo() {
    let main = auth(|n, _, _| match n {
        "polluted.test" => a([192, 0, 2, 66], 60),
        "missing.test" => Zone::NxDomain,
        _ => a([10, 1, 1, 1], 60),
    })
    .await;
    let fb = auth(|_, _, _| a([10, 2, 2, 2], 60)).await;
    let r = resolver(json!({
        "nameserver": [format!("udp://{}", main.addr)],
        "fallback": [format!("tcp://{}", fb.addr)],
        "fallback-filter": {"geoip": false, "ipcidr": ["192.0.2.0/24"], "domain": ["+.forced.test"]},
        "ipv6": false
    }));
    let main_hit = ask(&r, "clean.test", TYPE_A).await;
    assert_eq!(ips(&main_hit), vec![v4("10.1.1.1")]);
    assert!(matches!(
        main_hit.source,
        AnswerSource::Upstream {
            group: GroupKind::Main,
            ..
        }
    ));
    let polluted = ask(&r, "polluted.test", TYPE_A).await;
    assert_eq!(ips(&polluted), vec![v4("10.2.2.2")]);
    assert!(matches!(
        polluted.source,
        AnswerSource::Upstream {
            group: GroupKind::Fallback,
            ..
        }
    ));
    let forced = ask(&r, "a.forced.test", TYPE_A).await;
    assert!(matches!(
        forced.source,
        AnswerSource::Upstream {
            group: GroupKind::Fallback,
            ..
        }
    ));
    let missing = ask(&r, "missing.test", TYPE_A).await;
    assert_eq!(
        ips(&missing),
        vec![v4("10.2.2.2")],
        "主组无地址时用 fallback"
    );
}

#[tokio::test]
async fn fake_ip_filter_modes_and_pass_through_types() {
    let up = auth(|_, t, _| match t {
        TYPE_TXT => Zone::Records(vec![(TYPE_TXT, b"\x05hello".to_vec(), 60)]),
        _ => a([10, 3, 3, 3], 60),
    })
    .await;
    let black = resolver(json!({
        "nameserver": [format!("udp://{}", up.addr)],
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "fake-ip-filter": ["+.real.test"],
    }));
    let fake = ask(&black, "x.test", TYPE_A).await;
    assert_eq!(fake.source, AnswerSource::FakeIp);
    let fake_ip = ips(&fake)[0];
    assert!(black.is_fake_ip(fake_ip));
    assert_eq!(black.lookup_fake_ip(fake_ip).as_deref(), Some("x.test"));
    assert_eq!(
        ips(&ask(&black, "a.real.test", TYPE_A).await),
        vec![v4("10.3.3.3")]
    );
    let txt = ask(&black, "x.test", TYPE_TXT).await;
    assert_eq!(
        wire::message_json(&txt.message)["Answer"][0]["data"],
        "\"hello\""
    );
    let https = ask(&black, "x.test", wire::TYPE_HTTPS).await;
    assert_eq!(https.source, AnswerSource::FakeIp);
    assert!(wire::records(&https.message).unwrap().is_empty());
    assert_eq!(
        black.resolve("x.test").await.unwrap()[0],
        v4("10.3.3.3"),
        "Local 解析不分配 Fake-IP"
    );

    let white = resolver(json!({
        "nameserver": [format!("udp://{}", up.addr)],
        "enhanced-mode": "fake-ip",
        "fake-ip-filter-mode": "whitelist",
        "fake-ip-filter": ["+.fake.test"],
    }));
    assert_eq!(
        ask(&white, "a.fake.test", TYPE_A).await.source,
        AnswerSource::FakeIp
    );
    assert_eq!(
        ips(&ask(&white, "other.test", TYPE_A).await),
        vec![v4("10.3.3.3")]
    );
}

#[tokio::test]
async fn cache_honors_ttl_and_serves_stale_while_refreshing() {
    let up = auth(|_, _, _| a([10, 4, 4, 4], 1)).await;
    let r = resolver(json!({"nameserver": [format!("udp://{}", up.addr)], "ipv6": false}));
    let first = ask(&r, "c.test", TYPE_A).await;
    assert!(matches!(first.source, AnswerSource::Upstream { .. }));
    let second = ask(&r, "c.test", TYPE_A).await;
    assert!(matches!(
        second.source,
        AnswerSource::Cache { stale: false, .. }
    ));
    assert_eq!(wire::id(&second.message), 0x4242);
    assert_eq!(up.hits.load(Ordering::SeqCst), 1);
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let stale = ask(&r, "c.test", TYPE_A).await;
    assert!(matches!(
        stale.source,
        AnswerSource::Cache { stale: true, .. }
    ));
    assert_eq!(wire::min_ttl(&stale.message), Some(1));
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(up.hits.load(Ordering::SeqCst), 2, "过期命中触发后台刷新");

    let strict = resolver(json!({
        "nameserver": [format!("udp://{}", up.addr)],
        "optimistic-cache": false,
        "cache-algorithm": "arc",
        "ipv6": false
    }));
    ask(&strict, "s.test", TYPE_A).await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert!(matches!(
        ask(&strict, "s.test", TYPE_A).await.source,
        AnswerSource::Upstream { .. }
    ));
}

struct Sets1;
impl SetLookup for Sets1 {
    fn has_rule_set(&self, tag: &str) -> bool {
        tag == "ads"
    }
    fn rule_set_matches_domain(&self, tag: &str, host: &str) -> bool {
        tag == "ads" && host == "tracker.test"
    }
    fn rule_set_matches_ip(&self, _: &str, _: IpAddr) -> bool {
        false
    }
    fn geosite_matches(&self, code: &str, host: &str) -> bool {
        code == "cn" && host.ends_with(".cn.test")
    }
    fn geoip_matches(&self, _: &str, _: IpAddr) -> bool {
        false
    }
}

#[tokio::test]
async fn rules_rule_sets_and_geosite_use_injected_sets() {
    let main = auth(|_, _, _| a([10, 5, 5, 1], 60)).await;
    let cn = auth(|_, _, _| a([10, 5, 5, 2], 60)).await;
    let r = resolver(json!({
        "servers": [format!("udp://{}", main.addr), {"tag": "cn", "type": "udp", "server": "127.0.0.1", "server_port": cn.addr.port()}],
        "nameserver-policy": {"geosite:cn": "cn"},
        "rules": [
            {"rule_set": ["ads"], "action": "reject"},
            {"domain_suffix": ["drop.test"], "action": "reject", "method": "drop"},
            {"domain_keyword": ["route"], "server": "cn"}
        ],
        "ipv6": false
    }));
    assert!(DnsResolver::new(&serde_json::from_value(json!({"servers": ["udp://127.0.0.1"], "rules": [{"domain": ["a.test"], "server": "nope"}]})).unwrap()).is_err());
    assert!(
        r.bind(Arc::new(NoSets), None).is_err(),
        "引用不存在的规则集时绑定失败"
    );
    r.bind(Arc::new(Sets1), None).unwrap();
    assert_eq!(
        ask(&r, "tracker.test", TYPE_A).await.source,
        AnswerSource::Rejected
    );
    assert_eq!(
        ips(&ask(&r, "ads.tracker.test", TYPE_A).await),
        vec![v4("10.5.5.1")],
        "规则集按内容匹配，不按标签子串"
    );
    assert!(matches!(
        r.exchange_packet(&wire::build_query(1, "x.drop.test", TYPE_A).unwrap())
            .await,
        Err(Error::Rejected)
    ));
    assert!(matches!(
        r.resolve("tracker.test").await,
        Err(Error::Rejected)
    ));
    let routed = ask(&r, "my-route.test", TYPE_A).await;
    assert_eq!(
        routed.source,
        AnswerSource::Upstream {
            group: GroupKind::Rule,
            server: "cn".into()
        }
    );
    let geo = ask(&r, "www.cn.test", TYPE_A).await;
    assert_eq!(ips(&geo), vec![v4("10.5.5.2")]);
    assert!(matches!(
        geo.source,
        AnswerSource::Upstream {
            group: GroupKind::Policy,
            ..
        }
    ));
}

#[tokio::test]
async fn truncation_retries_over_tcp_and_ecs_is_sent() {
    let up = auth(|n, _, ecs| match n {
        "big.test" => Zone::Truncated,
        _ if ecs => a([10, 6, 6, 6], 60),
        _ => a([10, 6, 6, 0], 60),
    })
    .await;
    let r =
        resolver(json!({"nameserver": [format!("{}#ecs=203.0.113.0/24", up.addr)], "ipv6": false}));
    assert_eq!(r.resolve("big.test").await.unwrap(), vec![v4("10.0.0.53")]);
    assert_eq!(r.resolve("geo.test").await.unwrap(), vec![v4("10.6.6.6")]);
    let global = resolver(
        json!({"nameserver": [format!("udp://{}", up.addr)], "client-subnet": "198.51.100.1", "ipv6": false}),
    );
    assert_eq!(
        global.resolve("geo2.test").await.unwrap(),
        vec![v4("10.6.6.6")]
    );
}

#[tokio::test]
async fn hostname_upstreams_use_default_nameserver_and_proxy_server_group() {
    let target = auth(|_, _, _| a([10, 7, 7, 7], 60)).await;
    let boot = auth(|n, _, _| {
        if n == "ns.test" {
            a([127, 0, 0, 1], 60)
        } else {
            Zone::NxDomain
        }
    })
    .await;
    let proxy = auth(|_, _, _| a([10, 7, 7, 8], 60)).await;
    let r = resolver(json!({
        "default-nameserver": [format!("udp://{}", boot.addr)],
        "nameserver": [format!("tcp://ns.test:{}", target.addr.port())],
        "proxy-server-nameserver": [format!("udp://{}", proxy.addr)],
        "ipv6": false
    }));
    assert_eq!(r.resolve("site.test").await.unwrap(), vec![v4("10.7.7.7")]);
    assert_eq!(
        r.resolve_proxy_host("node.test").await.unwrap(),
        vec![v4("10.7.7.8")]
    );
    assert!(
        DnsResolver::new(
            &serde_json::from_value(
                json!({"default-nameserver": ["tls://dns.test"], "nameserver": ["udp://127.0.0.1"]})
            )
            .unwrap()
        )
        .is_err()
    );
}

struct RecordingDialer {
    seen: std::sync::Mutex<Vec<(Via, String)>>,
}

impl DnsDialer for RecordingDialer {
    fn knows(&self, outbound: &str) -> bool {
        outbound == "proxy-a"
    }
    fn connect_tcp<'a>(
        &'a self,
        via: &'a Via,
        target: &'a Destination,
    ) -> BoxFuture<'a, Result<BoxStream>> {
        Box::pin(async move {
            self.seen
                .lock()
                .unwrap()
                .push((via.clone(), target.to_string()));
            let s = tokio::net::TcpStream::connect((target.host().as_str(), target.port())).await?;
            Ok(Box::new(s) as BoxStream)
        })
    }
    fn connect_udp<'a>(
        &'a self,
        via: &'a Via,
        target: &'a Destination,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async move {
            self.seen
                .lock()
                .unwrap()
                .push((via.clone(), target.to_string()));
            let s = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
            s.connect((target.host().as_str(), target.port())).await?;
            struct Tx(Arc<UdpSocket>);
            struct Rx(Arc<UdpSocket>);
            impl kerlico_core::DatagramSender for Tx {
                fn send<'b>(&'b mut self, p: &'b [u8]) -> BoxFuture<'b, Result<()>> {
                    Box::pin(async move { self.0.send(p).await.map(|_| ()).map_err(Error::Io) })
                }
            }
            impl kerlico_core::DatagramReceiver for Rx {
                fn recv(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>>> {
                    Box::pin(async move {
                        let mut b = vec![0u8; 4096];
                        let n = self.0.recv(&mut b).await?;
                        b.truncate(n);
                        Ok(Some(b))
                    })
                }
            }
            Ok(DatagramChannel {
                sender: Box::new(Tx(s.clone())),
                receiver: Box::new(Rx(s)),
            })
        })
    }
}

#[tokio::test]
async fn detour_and_respect_rules_dial_through_the_dialer() {
    let up = auth(|_, _, _| a([10, 8, 8, 8], 60)).await;
    let r = resolver(json!({
        "nameserver": [format!("udp://{}#proxy-a", up.addr), format!("tcp://{}#RULES", up.addr)],
        "ipv6": false,
        "disable-cache": true
    }));
    assert_eq!(r.referenced_outbounds(), ["proxy-a".to_owned()]);
    let dialer = Arc::new(RecordingDialer {
        seen: std::sync::Mutex::new(Vec::new()),
    });
    r.bind(Arc::new(NoSets), Some(dialer.clone())).unwrap();
    assert_eq!(r.resolve("via.test").await.unwrap(), vec![v4("10.8.8.8")]);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let seen = dialer.seen.lock().unwrap().clone();
    assert!(
        seen.iter()
            .any(|(v, _)| *v == Via::Outbound("proxy-a".into()))
    );
    assert!(seen.iter().any(|(v, _)| *v == Via::Rules));

    let unknown = resolver(json!({"nameserver": [format!("udp://{}#missing", up.addr)]}));
    assert!(unknown.bind(Arc::new(NoSets), Some(dialer)).is_err());
    assert!(
        DnsResolver::new(
            &serde_json::from_value(
                json!({"nameserver": ["udp://127.0.0.1"], "respect-rules": true})
            )
            .unwrap()
        )
        .is_err()
    );
}

#[tokio::test]
async fn listener_serves_udp_and_tcp_through_the_pipeline() {
    let up = auth(|_, t, _| match t {
        TYPE_TXT => Zone::Records(vec![(TYPE_TXT, b"\x02ok".to_vec(), 60)]),
        _ => a([10, 10, 10, 10], 60),
    })
    .await;
    let r = resolver(
        json!({"nameserver": [format!("udp://{}", up.addr)], "listen": "127.0.0.1:0", "hosts": {"h.test": "10.0.0.9"}}),
    );
    assert_eq!(r.listen_addr(), Some("127.0.0.1:0".parse().unwrap()));
    let (udp, tcp) = crate::listener::bind(r.listen_addr().unwrap())
        .await
        .unwrap();
    let addr = udp.local_addr().unwrap();
    let rr = r.clone();
    let handler: crate::listener::Handler = Arc::new(move |p: Vec<u8>| {
        let rr = rr.clone();
        Box::pin(async move { rr.exchange_packet(&p).await })
    });
    tokio::spawn(crate::listener::serve_udp(udp, handler.clone()));
    tokio::spawn(crate::listener::serve_tcp(tcp, handler));

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .send_to(&wire::build_query(7, "h.test", TYPE_A).unwrap(), addr)
        .await
        .unwrap();
    let mut buf = [0u8; 512];
    let n = client.recv(&mut buf).await.unwrap();
    assert_eq!(wire::answer_ips(&buf[..n]), vec![v4("10.0.0.9")]);

    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    let q = wire::build_query(8, "t.test", TYPE_TXT).unwrap();
    s.write_all(&(q.len() as u16).to_be_bytes()).await.unwrap();
    s.write_all(&q).await.unwrap();
    let mut len = [0u8; 2];
    s.read_exact(&mut len).await.unwrap();
    let mut reply = vec![0u8; u16::from_be_bytes(len) as usize];
    s.read_exact(&mut reply).await.unwrap();
    assert_eq!(wire::id(&reply), 8);
    assert_eq!(wire::message_json(&reply)["Answer"][0]["data"], "\"ok\"");
}

fn self_signed() -> (
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
) {
    let cert =
        rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::try_from(cert.signing_key.serialize_der()).unwrap();
    (vec![cert.cert.der().clone()], key)
}

fn server_tls(alpn: &[u8], tls13: bool) -> rustls::ServerConfig {
    let (certs, key) = self_signed();
    let builder = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ));
    let builder = if tls13 {
        builder
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
    } else {
        builder.with_safe_default_protocol_versions().unwrap()
    };
    let mut cfg = builder
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    cfg.alpn_protocols = vec![alpn.to_vec()];
    cfg
}

#[tokio::test]
async fn doh_only_and_doq_only_configs_resolve() {
    let zone: ZoneFn = Arc::new(|_, t, _| {
        if t == TYPE_A {
            a([10, 11, 0, 1], 60)
        } else {
            Zone::Records(vec![])
        }
    });

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_tls(b"h2", false)));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let doh_addr = listener.local_addr().unwrap();
    let z = zone.clone();
    tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            let z = z.clone();
            tokio::spawn(async move {
                let tls = acceptor.accept(tcp).await.unwrap();
                let mut conn = h2::server::handshake(tls).await.unwrap();
                while let Some(Ok((req, mut respond))) = conn.accept().await {
                    assert_eq!(req.uri().path(), "/dns-query");
                    let mut body = req.into_body();
                    let mut q = Vec::new();
                    while let Some(Ok(chunk)) = body.data().await {
                        q.extend_from_slice(&chunk);
                    }
                    assert_eq!(wire::id(&q), 0, "RFC 8484 要求 ID 为 0");
                    let reply = zone_reply(&z, &q, false);
                    let resp = http::Response::builder().status(200).body(()).unwrap();
                    let mut tx = respond.send_response(resp, false).unwrap();
                    tx.send_data(bytes::Bytes::from(reply), true).unwrap();
                }
            });
        }
    });
    let doh = resolver(
        json!({"nameserver": [format!("https://{doh_addr}/dns-query#skip-cert-verify=true")], "ipv6": false}),
    );
    assert_eq!(
        doh.resolve("doh.test").await.unwrap(),
        vec![v4("10.11.0.1")]
    );
    assert_eq!(
        doh.resolve("doh2.test").await.unwrap(),
        vec![v4("10.11.0.1")],
        "复用 HTTP/2 连接"
    );

    let crypto =
        quinn::crypto::rustls::QuicServerConfig::try_from(server_tls(b"doq", true)).unwrap();
    let endpoint = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(crypto)),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let doq_addr = endpoint.local_addr().unwrap();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let z = zone.clone();
            tokio::spawn(async move {
                let conn = incoming.await.unwrap();
                while let Ok((mut tx, mut rx)) = conn.accept_bi().await {
                    let data = rx.read_to_end(65537).await.unwrap();
                    let reply = zone_reply(&z, &data[2..], false);
                    let mut frame = (reply.len() as u16).to_be_bytes().to_vec();
                    frame.extend_from_slice(&reply);
                    tx.write_all(&frame).await.unwrap();
                    tx.finish().unwrap();
                }
            });
        }
    });
    let doq = resolver(
        json!({"nameserver": [format!("quic://{doq_addr}#skip-cert-verify=true")], "ipv6": false}),
    );
    assert_eq!(
        doq.resolve("doq.test").await.unwrap(),
        vec![v4("10.11.0.1")]
    );
    assert!(
        DnsResolver::new(
            &serde_json::from_value(json!({"nameserver": ["quic://127.0.0.1#proxy-a"]})).unwrap()
        )
        .is_err()
    );
    let _ = Ipv4Addr::LOCALHOST;
}

#[tokio::test]
async fn rcode_upstream_and_dns_enable_flag() {
    let r = resolver(
        json!({"nameserver": ["udp://127.0.0.1:9"], "nameserver-policy": {"+.blocked.test": "rcode://refused"}}),
    );
    let refused = ask(&r, "x.blocked.test", TYPE_A).await;
    assert_eq!(wire::rcode(&refused.message), wire::RCODE_REFUSED);
    let spec: DnsSpec = serde_json::from_value(json!({"enable": false, "ipv6": true})).unwrap();
    assert!(!spec.enabled());
}
