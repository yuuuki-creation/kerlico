//! 真实订阅形状：常见附加字段加 `override` 块，与 Mihomo 一样只跳过语义无法实现的成员。

use kerlico_config::ProxyProviderSpec;
use serde_json::{Value, json};

const SUBSCRIPTION: &str = r#"
proxies:
  - {name: "HK 01", type: ss, server: 203.0.113.10, port: 8388, cipher: aes-256-gcm, password: pw, udp: true, client-fingerprint: chrome, tfo: false}
  - name: JP 02
    type: vmess
    server: vm.example.com
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
    alterId: 0
    cipher: auto
    udp: true
    tls: true
    servername: vm.example.com
    skip-cert-verify: false
    network: ws
    ws-opts:
      path: /ray
      headers:
        Host: vm.example.com
  - name: US 03
    type: vless
    server: vl.example.com
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
    flow: xtls-rprx-vision
    tls: true
    udp: true
    servername: www.example.com
    client-fingerprint: chrome
    network: tcp
    reality-opts:
      public-key: q4Rh2Xb8Q0Gx7sVfS0bE8Zx6c1mI2wN5yL3kJ9pTqWc
      short-id: 0123abcd
  - {name: SG 04, type: trojan, server: t.example.com, port: 443, password: pw, sni: t.example.com, udp: true, alpn: [h2, http/1.1], skip-cert-verify: false}
  - name: TW 05
    type: hysteria2
    server: h2.example.com
    port: 443
    ports: 20000-30000
    hop-interval: 30
    password: pw
    sni: h2.example.com
    obfs: salamander
    obfs-password: salamander-pw
    up: 50 Mbps
    down: 200 Mbps
  - name: KR 06
    type: tuic
    server: tu.example.com
    port: 443
    uuid: 11111111-2222-3333-4444-555555555555
    password: pw
    alpn: [h3]
    sni: tu.example.com
    congestion-controller: bbr
    udp-relay-mode: native
    reduce-rtt: true
    request-timeout: 8000
    disable-sni: false
  - {name: DE 07, type: trojan, server: e.example.com, port: 443, password: pw, sni: e.example.com, ech-opts: {enable: true, config: AEn+DQBF}}
"#;

#[test]
fn real_world_subscription_loads_supported_members_and_lists_the_rest() {
    let spec: ProxyProviderSpec = serde_json::from_value(json!({
        "type": "inline",
        "payload": [SUBSCRIPTION],
        "override": {
            "udp": true,
            "skip-cert-verify": true,
            "up": "100 Mbps",
            "down": "500 Mbps",
            "tfo": false,
            "additional-prefix": "[sub] ",
        },
    }))
    .unwrap();
    let (provider, specs) = spec.compile("sub").expect("订阅整体可加载");
    let kinds: Vec<(&str, &str)> = specs
        .iter()
        .map(|s| (s.tag.as_str(), s.kind.as_str()))
        .collect();
    assert_eq!(
        kinds,
        [
            ("sub-HK-01", "shadowsocks"),
            ("sub-JP-02", "vmess"),
            ("sub-US-03", "vless"),
            ("sub-SG-04", "trojan"),
            ("sub-TW-05", "hysteria2"),
            ("sub-KR-06", "tuic"),
        ]
    );
    let options = |tag: &str| -> &Value { &specs.iter().find(|s| s.tag == tag).unwrap().options };
    assert_eq!(options("sub-JP-02")["tls"]["insecure"], true);
    assert_eq!(options("sub-SG-04")["security"]["insecure"], true);
    assert_eq!(options("sub-TW-05")["tls"]["insecure"], true);
    assert_eq!(options("sub-TW-05")["up"], "100 Mbps");
    assert_eq!(options("sub-KR-06")["tls"]["insecure"], true);
    assert_eq!(options("sub-US-03")["security"]["type"], "reality");
    assert!(
        options("sub-US-03")["security"]
            .get("allow_insecure")
            .is_none()
    );
    assert!(options("sub-HK-01").get("up").is_none());
    let [failure] = provider.failed_members.as_slice() else {
        panic!("{:?}", provider.failed_members);
    };
    assert!(
        failure.contains("DE 07") && failure.contains("ech-opts"),
        "{failure}"
    );
}
