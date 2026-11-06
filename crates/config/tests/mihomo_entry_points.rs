use kerlico_config::{ProxyProviderSpec, parse_config_value};
use serde_json::{Value, json};

const TROJAN_YAML: &str = "proxies:\n  - name: same\n    type: trojan\n    server: t.example.com\n    port: 443\n    password: pw\n    sni: t.example.com\n    network: grpc\n    grpc-opts:\n      grpc-service-name: grpc-svc\n";
const TROJAN_LINK: &str =
    "trojan://pw[at]t.example.com:443?sni=t.example.com&type=grpc&serviceName=grpc-svc#same";
const VLESS_YAML: &str = "proxies:\n  - name: same\n    type: vless\n    server: vl.example.com\n    port: 443\n    uuid: 11111111-2222-3333-4444-555555555555\n    tls: true\n    servername: vl.example.com\n    client-fingerprint: chrome\n    network: ws\n    ws-opts:\n      path: /vl\n      headers:\n        Host: vl.example.com\n";
const VLESS_LINK: &str = "vless://11111111-2222-3333-4444-555555555555[at]vl.example.com:443?encryption=none&security=tls&sni=vl.example.com&fp=chrome&type=ws&host=vl.example.com&path=%2Fvl#same";
const HY2_YAML: &str = "proxies:\n  - name: same\n    type: hysteria2\n    server: h2.example.com\n    port: 443\n    password: pw\n    sni: h2.example.com\n    obfs: salamander\n    obfs-password: salamander-pw\n";
const HY2_LINK: &str = "hy2://pw[at]h2.example.com:443/?sni=h2.example.com&obfs=salamander&obfs-password=salamander-pw#same";
const SS_YAML: &str = "proxies:\n  - name: same\n    type: ss\n    server: 203.0.113.10\n    port: 8388\n    cipher: aes-256-gcm\n    password: pw\n";
const SS_LINK: &str = "ss://YWVzLTI1Ni1nY206cHc[at]203.0.113.10:8388#same";

/// 链接里的 `@` 以 `[at]` 书写，避免被提交钩子当作邮箱地址。
fn at(link: &str) -> String {
    link.replace("[at]", "@")
}

fn provider(payload: Value) -> (String, Value) {
    let spec = ProxyProviderSpec {
        kind: "inline".into(),
        payload: vec![payload],
        ..Default::default()
    };
    let (_, mut specs) = spec.compile("sub").expect("provider compiles");
    assert_eq!(specs.len(), 1);
    let s = specs.remove(0);
    (s.kind, s.options)
}

fn top_level(yaml: &str) -> (String, Value) {
    let value = parse_config_value(yaml.as_bytes()).expect("top-level yaml");
    let out = &value["outbounds"][0];
    (
        out["type"].as_str().unwrap().to_owned(),
        out["options"].clone(),
    )
}

#[test]
fn top_level_proxies_provider_members_and_share_links_produce_identical_options() {
    for (yaml, link) in [
        (TROJAN_YAML, TROJAN_LINK),
        (VLESS_YAML, VLESS_LINK),
        (HY2_YAML, HY2_LINK),
        (SS_YAML, SS_LINK),
    ] {
        let expected = top_level(yaml);
        assert_eq!(provider(Value::String(yaml.into())), expected, "{link}");
        assert_eq!(provider(Value::String(at(link))), expected, "{link}");
    }
}

#[test]
fn provider_members_keep_mihomo_shape_out_of_kerlico_options() {
    let (kind, options) = provider(Value::String(TROJAN_YAML.into()));
    assert_eq!(kind, "trojan");
    assert_eq!(
        options,
        json!({"server":{"host":"t.example.com","port":443},"password":"pw","security":{"type":"tls","server_name":"t.example.com"},"transport":{"type":"grpc","service_name":"grpc-svc"}})
    );
}

#[test]
fn unknown_share_link_parameter_fails_naming_it() {
    let spec = ProxyProviderSpec {
        kind: "inline".into(),
        payload: vec![Value::String(at(
            "trojan://pw[at]t.example.com:443?sni=t.example.com&mystery=1#x",
        ))],
        ..Default::default()
    };
    let err = spec.compile("sub").err().expect("rejected").to_string();
    assert!(err.contains("mystery"), "{err}");
}

#[test]
fn unknown_provider_member_field_fails_naming_proxy_and_field() {
    let yaml = format!("{TROJAN_YAML}    alpn: [h2]\n");
    let spec = ProxyProviderSpec {
        kind: "inline".into(),
        payload: vec![Value::String(yaml)],
        ..Default::default()
    };
    let err = spec.compile("sub").err().expect("rejected").to_string();
    assert!(err.contains("same") && err.contains("alpn"), "{err}");
}
