use kerlico_config::{ProxyProviderSpec, parse_config_value, parse_subscription_content};
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
fn unimplemented_provider_member_fields_warn_or_skip_the_member() {
    let yaml = format!("{TROJAN_YAML}    alpn: [h2]\n");
    assert_eq!(provider(Value::String(yaml)), top_level(TROJAN_YAML));
    let spec = ProxyProviderSpec {
        kind: "inline".into(),
        payload: vec![Value::String(format!(
            "{TROJAN_YAML}    ech-opts:\n      enable: true\n"
        ))],
        ..Default::default()
    };
    let (provider, specs) = spec.compile("sub").expect("provider compiles");
    assert!(specs.is_empty());
    let [failure] = provider.failed_members.as_slice() else {
        panic!("{:?}", provider.failed_members);
    };
    assert!(
        failure.contains("same") && failure.contains("ech-opts"),
        "{failure}"
    );
}

#[test]
fn failing_top_level_proxy_fails_the_config_only_when_referenced() {
    let proxies = "proxies:\n  - name: ok\n    type: ss\n    server: 203.0.113.10\n    port: 8388\n    cipher: aes-256-gcm\n    password: pw\n  - name: bad\n    type: trojan\n    server: t.example.com\n    port: 443\n    password: pw\n    ech-opts:\n      enable: true\n";
    let value = parse_config_value(proxies.as_bytes()).expect("未引用的失败代理被跳过");
    let tags: Vec<_> = value["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|out| out["tag"].as_str().unwrap())
        .collect();
    assert_eq!(tags, ["ok"]);
    for referenced in [
        "proxy-groups:\n  - name: sel\n    type: select\n    proxies: [ok, bad]\n",
        "rules:\n  - MATCH,bad\n",
    ] {
        let Err(err) = parse_config_value(format!("{proxies}{referenced}").as_bytes()) else {
            panic!("被引用的失败代理使配置加载失败");
        };
        let err = err.to_string();
        assert!(err.contains("bad") && err.contains("ech-opts"), "{err}");
    }
}

#[test]
fn kerlico_native_members_keep_their_shape() {
    let content = r#"[{"tag":"n1","type":"direct"},{"tag":"n2","type":"socks","options":{"server":{"host":"s.example.com","port":1080}}}]"#;
    let got: Vec<_> = parse_subscription_content(content)
        .expect("native members parse")
        .into_iter()
        .map(|s| (s.tag, s.kind, s.options))
        .collect();
    assert_eq!(
        got,
        [
            ("n1".to_owned(), "direct".to_owned(), json!({})),
            (
                "n2".to_owned(),
                "socks".to_owned(),
                json!({"server":{"host":"s.example.com","port":1080}})
            ),
        ]
    );
}

#[test]
fn unknown_native_member_field_fails_naming_tag_and_field() {
    let err = parse_subscription_content(r#"[{"tag":"n1","type":"direct","server":"x"}]"#)
        .err()
        .expect("rejected")
        .to_string();
    assert!(err.contains("n1") && err.contains("server"), "{err}");
}
