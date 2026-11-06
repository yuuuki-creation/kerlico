use kerlico_net::sniff::{SniffProtocol, SniffResult, Sniffed, UdpSniffer, sniff_tcp};

/// 夹具格式：`#` 开头为来源说明，其余每行一个十六进制数据包。
fn fixture(name: &str) -> Vec<Vec<u8>> {
    let path = format!(
        "{}/tests/fixtures/sniff/{name}.hex",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            (0..l.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&l[i..i + 2], 16).unwrap())
                .collect()
        })
        .collect()
}

fn one(name: &str) -> Vec<u8> {
    fixture(name).remove(0)
}

fn found(verdict: Sniffed) -> SniffResult {
    match verdict {
        Sniffed::Found(res) => res,
        other => panic!("expected Found, got {other:?}"),
    }
}

fn tcp_all(buf: &[u8]) -> Sniffed {
    sniff_tcp(buf, &SniffProtocol::ALL)
}

fn pseudo_random(seed: u64, len: usize) -> Vec<u8> {
    let mut x = seed;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

#[test]
fn protocol_names_and_networks() {
    assert_eq!(SniffProtocol::parse("HTTPS"), Some(SniffProtocol::Tls));
    assert_eq!(SniffProtocol::parse("ssl"), Some(SniffProtocol::Tls));
    assert_eq!(SniffProtocol::parse("BT"), Some(SniffProtocol::Bittorrent));
    assert_eq!(SniffProtocol::parse("gopher"), None);
    for p in SniffProtocol::ALL {
        assert_eq!(SniffProtocol::parse(p.as_str()), Some(p));
        assert!(p.tcp() || p.udp());
    }
    assert_eq!(
        &SniffProtocol::ALL[..3],
        &[SniffProtocol::Tls, SniffProtocol::Http, SniffProtocol::Quic]
    );
    assert!(SniffProtocol::Bittorrent.tcp() && SniffProtocol::Bittorrent.udp());
    assert!(!SniffProtocol::Quic.tcp() && !SniffProtocol::Ssh.udp());
}

#[test]
fn tls_openssl_client_hello() {
    let hello = one("openssl-tls13-client-hello");
    let res = found(tcp_all(&hello));
    assert_eq!(res.protocol, SniffProtocol::Tls);
    assert_eq!(res.domain.as_deref(), Some("tls.example.com"));
    assert_eq!(res.alpn.as_deref(), Some("h2"));
    for cut in [1, 3, 5, 6, 200, hello.len() - 1] {
        assert_eq!(tcp_all(&hello[..cut]), Sniffed::NeedMore, "cut at {cut}");
    }
    assert_eq!(sniff_tcp(&hello, &[SniffProtocol::Http]), Sniffed::Miss);
}

#[test]
fn http_curl_get() {
    let req = one("curl-http11-get");
    let res = found(tcp_all(&req));
    assert_eq!(res.protocol, SniffProtocol::Http);
    assert_eq!(res.domain.as_deref(), Some("http.example.com"));
    assert_eq!(tcp_all(b"GE"), Sniffed::NeedMore);
    assert_eq!(
        tcp_all(b"GET /sniff HTTP/1.1\r\nHost: http.exa"),
        Sniffed::NeedMore
    );
    assert_eq!(tcp_all(b"GET / HTTP/2.0\r\n\r\n"), Sniffed::Miss);
    let ip_host = found(tcp_all(b"GET / HTTP/1.1\r\nHost: 192.0.2.1:8080\r\n\r\n"));
    assert_eq!(ip_host.domain, None);
}

#[test]
fn ssh_banners() {
    let res = found(tcp_all(&one("openssh-client-banner")));
    assert_eq!(res.protocol, SniffProtocol::Ssh);
    assert_eq!(
        res.client.as_deref(),
        Some("OpenSSH_10.0p2 Debian-7+deb13u4")
    );
    assert_eq!(res.domain, None);
    let dropbear = found(tcp_all(&one("singbox-ssh-dropbear")));
    assert_eq!(dropbear.client.as_deref(), Some("dropbear"));
    assert_eq!(tcp_all(b"SSH-2.0"), Sniffed::NeedMore);
    assert_eq!(tcp_all(b"SSH-2.0-OpenSSH_10.0"), Sniffed::NeedMore);
    assert_eq!(tcp_all(b"SSH-2.1"), Sniffed::Miss);
}

#[test]
fn rdp_connection_requests() {
    let res = found(tcp_all(&one("singbox-rdp-negotiation-request")));
    assert_eq!(res.protocol, SniffProtocol::Rdp);

    let cookie = b"Cookie: mstshash=probe\r\n";
    let mut mstsc = vec![0x03, 0x00, 0x00, 0x00, 0x00, 0xe0, 0, 0, 0, 0, 0];
    mstsc.extend_from_slice(cookie);
    mstsc.extend_from_slice(&[0x01, 0x00, 0x08, 0x00, 0x0b, 0x00, 0x00, 0x00]);
    let len = mstsc.len() as u16;
    mstsc[2..4].copy_from_slice(&len.to_be_bytes());
    mstsc[4] = (len - 5) as u8;
    assert_eq!(found(tcp_all(&mstsc)).protocol, SniffProtocol::Rdp);
    assert_eq!(tcp_all(&mstsc[..9]), Sniffed::NeedMore);
    assert_eq!(tcp_all(&mstsc[..15]), Sniffed::NeedMore);
}

#[test]
fn bittorrent_tcp_handshake() {
    for pkt in fixture("singbox-bittorrent-handshake") {
        assert_eq!(found(tcp_all(&pkt)).protocol, SniffProtocol::Bittorrent);
    }
    assert_eq!(tcp_all(b"\x13BitTorrent"), Sniffed::NeedMore);
    assert_eq!(tcp_all(b"\x13BitTorrenu"), Sniffed::Miss);
}

#[test]
fn bittorrent_udp_utp_tracker_dht() {
    for name in ["singbox-utp", "singbox-udp-tracker"] {
        for pkt in fixture(name) {
            let res = found(UdpSniffer::new(&SniffProtocol::ALL).push(&pkt));
            assert_eq!(res.protocol, SniffProtocol::Bittorrent, "{name}");
        }
    }
    let dht = b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe";
    let res = found(UdpSniffer::new(&[SniffProtocol::Bittorrent]).push(dht));
    assert_eq!(res.protocol, SniffProtocol::Bittorrent);
    let not_utp = one("singbox-not-utp");
    assert_eq!(
        UdpSniffer::new(&SniffProtocol::ALL).push(&not_utp),
        Sniffed::Miss
    );
}

#[test]
fn dtls_records() {
    for name in [
        "openssl-dtls12-client-hello",
        "singbox-dtls-client-hello",
        "singbox-dtls-application-data",
    ] {
        let res = found(UdpSniffer::new(&SniffProtocol::ALL).push(&one(name)));
        assert_eq!(res.protocol, SniffProtocol::Dtls, "{name}");
        assert_eq!(res.domain, None);
    }
}

#[test]
fn stun_binding_request() {
    let pkt = one("singbox-stun-binding-request");
    let res = found(UdpSniffer::new(&SniffProtocol::ALL).push(&pkt));
    assert_eq!(res.protocol, SniffProtocol::Stun);
    assert_eq!(
        UdpSniffer::new(&[SniffProtocol::Quic]).push(&pkt),
        Sniffed::Miss
    );
}

/// 推入全部数据包，返回首个非 `NeedMore` 结论与此前推入的包数。
fn run_quic(packets: &[Vec<u8>]) -> (Sniffed, usize) {
    let mut sniffer = UdpSniffer::new(&SniffProtocol::ALL);
    for (i, pkt) in packets.iter().enumerate() {
        let verdict = sniffer.push(pkt);
        if verdict != Sniffed::NeedMore {
            assert_eq!(sniffer.push(b"\x00late"), verdict, "verdict must stick");
            return (verdict, i + 1);
        }
    }
    (Sniffed::NeedMore, packets.len())
}

#[test]
fn quic_initial_fixtures() {
    let cases = [
        ("curl-http3-initial", "quic.example.com"),
        ("singbox-quic-chromium", "google.com"),
        ("singbox-quic-uquic-chrome115", "www.google.com"),
        ("singbox-quic-firefox", "www.google.com"),
        ("singbox-quic-safari", "www.google.com"),
        ("mihomo-quic-single-packet-google", "www.google.com"),
        ("mihomo-quic-single-packet-cloudflare", "cloudflare-dns.com"),
        ("mihomo-quic-fragmented-nginx", "quic.nginx.org"),
        ("mihomo-quic-fragmented-openai", "chat.openai.com"),
        ("mihomo-quic-fragmented-with-zero-rtt", "fonts.gstatic.com"),
        (
            "mihomo-quic-out-of-order-duplicate-fragments",
            "ogads-pa.clients6.google.com",
        ),
        ("mihomo-quic-many-out-of-order-fragments", "www.google.com"),
        ("mihomo-quic-v2-fragmented", "test.example.com"),
    ];
    for (name, domain) in cases {
        let (verdict, _) = run_quic(&fixture(name));
        let res = found(verdict);
        assert_eq!(res.protocol, SniffProtocol::Quic, "{name}");
        assert_eq!(res.domain.as_deref(), Some(domain), "{name}");
        assert_eq!(res.client, None);
    }
}

#[test]
fn quic_chrome_hello_split_over_three_initials() {
    let packets = fixture("singbox-quic-chrome-new");
    let mut sniffer = UdpSniffer::new(&SniffProtocol::ALL);
    assert_eq!(sniffer.push(&packets[0]), Sniffed::NeedMore);
    assert_eq!(sniffer.push(&packets[1]), Sniffed::NeedMore);
    let res = found(sniffer.push(&packets[2]));
    assert_eq!(res.domain.as_deref(), Some("www.google.com"));
}

#[test]
fn quic_two_packet_hello_needs_both_in_any_order() {
    let packets = fixture("mihomo-quic-fragmented-openai");
    let mut sniffer = UdpSniffer::new(&[SniffProtocol::Quic]);
    assert_eq!(sniffer.push(&packets[0]), Sniffed::NeedMore);
    assert_eq!(
        found(sniffer.push(&packets[1])).domain.as_deref(),
        Some("chat.openai.com")
    );

    let mut reversed = UdpSniffer::new(&[SniffProtocol::Quic]);
    assert_eq!(reversed.push(&packets[1]), Sniffed::NeedMore);
    assert_eq!(
        found(reversed.push(&packets[0])).domain.as_deref(),
        Some("chat.openai.com")
    );
}

#[test]
fn quic_coalesced_initials_in_one_datagram() {
    let datagram = fixture("mihomo-quic-fragmented-nginx").concat();
    let res = found(UdpSniffer::new(&SniffProtocol::ALL).push(&datagram));
    assert_eq!(res.domain.as_deref(), Some("quic.nginx.org"));
}

#[test]
fn quic_corrupted_initial_is_miss() {
    let mut pkt = one("mihomo-quic-single-packet-google");
    let last = pkt.len() - 1;
    pkt[last] ^= 0xff;
    assert_eq!(
        UdpSniffer::new(&SniffProtocol::ALL).push(&pkt),
        Sniffed::Miss
    );
}

#[test]
fn random_bytes_miss() {
    for seed in [0x9e37_79b9_7f4a_7c15, 0xdead_beef_cafe_f00d, 7] {
        let mut bytes = pseudo_random(seed, 512);
        // 首字节固定为任何嗅探器都不认的值，结论与种子无关。
        bytes[0] = 0xaa;
        assert_eq!(tcp_all(&bytes), Sniffed::Miss);
        let mut sniffer = UdpSniffer::new(&SniffProtocol::ALL);
        assert_eq!(sniffer.push(&bytes), Sniffed::Miss);
        assert_eq!(
            sniffer.push(&one("mihomo-quic-single-packet-google")),
            Sniffed::Miss
        );
    }
    assert_eq!(sniff_tcp(&one("curl-http11-get"), &[]), Sniffed::Miss);
    assert_eq!(
        UdpSniffer::new(&[SniffProtocol::Ssh]).push(b"x"),
        Sniffed::Miss
    );
}
