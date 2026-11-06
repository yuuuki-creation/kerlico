use kerlico_config::{OutboundSpec, ProxyProviderSpec};
use serde_json::{Value, json};

fn members() -> Vec<Value> {
    vec![
        json!({"name": "ss-hk", "type": "ss", "server": "203.0.113.10", "port": 8388,
               "cipher": "aes-256-gcm", "password": "pw"}),
        json!({"name": "vmess-jp", "type": "vmess", "server": "vm.example.com", "port": 443,
               "uuid": "11111111-2222-3333-4444-555555555555", "alterId": 0, "cipher": "auto",
               "tls": true, "servername": "vm.example.com"}),
        json!({"name": "trojan-us", "type": "trojan", "server": "t.example.com", "port": 443,
               "password": "pw", "sni": "t.example.com"}),
        json!({"name": "hy2-sg", "type": "hysteria2", "server": "h2.example.com", "port": 443,
               "password": "pw", "sni": "h2.example.com"}),
        json!({"name": "vless-de", "type": "vless", "server": "vl.example.com", "port": 443,
               "uuid": "11111111-2222-3333-4444-555555555555", "tls": true,
               "servername": "vl.example.com"}),
    ]
}

fn compile(payload: Vec<Value>, over: Value) -> kerlico_core::Result<Vec<OutboundSpec>> {
    let spec: ProxyProviderSpec = serde_json::from_value(json!({
        "type": "inline",
        "payload": payload,
        "override": over,
    }))
    .expect("provider spec parses");
    spec.compile("sub").map(|(_, specs)| specs)
}

fn by_tag<'a>(specs: &'a [OutboundSpec], tag: &str) -> &'a OutboundSpec {
    specs.iter().find(|s| s.tag == tag).unwrap_or_else(|| {
        panic!(
            "缺少 {tag}：{:?}",
            specs.iter().map(|s| &s.tag).collect::<Vec<_>>()
        )
    })
}

fn hand_written(member: Value, extra: Value) -> kerlico_core::Result<OutboundSpec> {
    let mut member = member;
    member
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    compile_plain(member)
}

fn compile_plain(member: Value) -> kerlico_core::Result<OutboundSpec> {
    let spec: ProxyProviderSpec =
        serde_json::from_value(json!({"type": "inline", "payload": [member]})).unwrap();
    let (_, mut specs) = spec.compile("sub")?;
    Ok(specs.remove(0))
}

#[test]
fn dialing_fields_reach_every_type() {
    let specs = compile(
        members(),
        json!({"dialer-proxy": "hop", "interface-name": "eth9", "routing-mark": 7, "tfo": true}),
    )
    .unwrap();
    assert_eq!(specs.len(), 5);
    for (tag, kind) in [
        ("ss-hk", "shadowsocks"),
        ("vmess-jp", "vmess"),
        ("trojan-us", "trojan"),
        ("hy2-sg", "hysteria2"),
        ("vless-de", "vless"),
    ] {
        let s = by_tag(&specs, tag);
        assert_eq!(s.kind, kind);
        assert_eq!(s.options["dialer-proxy"], "hop", "{tag}");
        assert_eq!(s.options["interface-name"], "eth9", "{tag}");
        assert_eq!(s.options["routing-mark"], 7, "{tag}");
        assert_eq!(s.options["tfo"], true, "{tag}");
        assert!(s.options.get("skip-cert-verify").is_none());
    }
}

#[test]
fn override_equals_hand_written_proxy() {
    let specs = compile(
        members(),
        json!({"dialer-proxy": "hop", "interface-name": "eth9"}),
    )
    .unwrap();
    for member in members() {
        let tag = member["name"].as_str().unwrap().to_owned();
        let direct = hand_written(
            member,
            json!({"dialer-proxy": "hop", "interface-name": "eth9"}),
        )
        .unwrap();
        let via = by_tag(&specs, &tag);
        assert_eq!(via.kind, direct.kind);
        assert_eq!(via.options, direct.options, "{tag}");
    }
}

#[test]
fn skip_cert_verify_uses_the_per_type_tls_field() {
    let specs = compile(vec![members().remove(4)], json!({"skip-cert-verify": true})).unwrap();
    assert_eq!(specs[0].options["security"]["allow_insecure"], true);
    assert!(specs[0].options.get("skip-cert-verify").is_none());
}

#[test]
fn hysteria2_up_down_are_mapped() {
    let specs = compile(
        vec![members().remove(3)],
        json!({"up": "30 Mbps", "down": "200 Mbps"}),
    )
    .unwrap();
    let direct = hand_written(
        members().remove(3),
        json!({"up": "30 Mbps", "down": "200 Mbps"}),
    )
    .unwrap();
    assert_eq!(specs[0].options["up"], "30 Mbps");
    assert_eq!(specs[0].options["down"], "200 Mbps");
    assert_eq!(specs[0].options, direct.options);
}

#[test]
fn unsupported_override_matches_hand_written_error() {
    for (member, over) in [
        (members().remove(2), json!({"skip-cert-verify": true})),
        (members().remove(1), json!({"skip-cert-verify": true})),
        (members().remove(0), json!({"up": "30 Mbps"})),
        (members().remove(2), json!({"ip-version": "ipv6"})),
    ] {
        let key = over.as_object().unwrap().keys().next().unwrap().clone();
        let expected = hand_written(member.clone(), over.clone())
            .err()
            .expect("应报错")
            .to_string();
        let got = compile(vec![member], over)
            .err()
            .expect("应报错")
            .to_string();
        assert_eq!(got, expected, "override {key}");
    }
}

#[test]
fn override_replaces_member_value() {
    let mut member = members().remove(4);
    member["skip-cert-verify"] = json!(false);
    member["interface-name"] = json!("old0");
    let specs = compile(
        vec![member],
        json!({"skip-cert-verify": true, "interface-name": "new0"}),
    )
    .unwrap();
    assert_eq!(specs[0].options["security"]["allow_insecure"], true);
    assert_eq!(specs[0].options["interface-name"], "new0");
}

#[test]
fn names_are_rewritten_in_upstream_order() {
    let specs = compile(
        members(),
        json!({
            "proxy-name": [
                {"pattern": "^(\\w+)-(\\w+)$", "target": "$2_$1"},
                {"pattern": "^hk_", "target": "HK_"}
            ],
            "additional-prefix": "A-",
            "additional-suffix": "-Z"
        }),
    )
    .unwrap();
    let tags: Vec<_> = specs.iter().map(|s| s.tag.as_str()).collect();
    assert_eq!(
        tags,
        [
            "A-HK_ss-Z",
            "A-jp_vmess-Z",
            "A-us_trojan-Z",
            "A-sg_hy2-Z",
            "A-de_vless-Z"
        ]
    );
}

#[test]
fn filters_see_the_original_name() {
    let spec: ProxyProviderSpec = serde_json::from_value(json!({
        "type": "inline",
        "payload": members(),
        "filter": "hk",
        "override": {"additional-prefix": "x-", "proxy-name": [{"pattern": "hk", "target": "zz"}]},
    }))
    .unwrap();
    let (compiled, specs) = spec.compile("sub").unwrap();
    assert_eq!(specs.len(), 1);
    assert_eq!(specs[0].tag, "x-ss-zz");
    assert_eq!(compiled.proxies.len(), 1);
}

#[test]
fn exclude_type_uses_mihomo_type_names() {
    let spec: ProxyProviderSpec = serde_json::from_value(json!({
        "type": "inline",
        "payload": members(),
        "exclude-type": "ss|vmess",
    }))
    .unwrap();
    let (_, specs) = spec.compile("sub").unwrap();
    let kinds: Vec<_> = specs.iter().map(|s| s.kind.as_str()).collect();
    assert_eq!(kinds, ["trojan", "hysteria2", "vless"]);
}

#[test]
fn native_members_accept_name_ops_only() {
    let native = json!({"tag": "native-1", "type": "direct", "options": {}});
    let specs = compile(
        vec![native.clone()],
        json!({"additional-prefix": "P-", "proxy-name": [{"pattern": "1", "target": "one"}]}),
    )
    .unwrap();
    assert_eq!(specs[0].tag, "P-native-one");
    let err = compile(vec![native], json!({"udp": true}))
        .err()
        .expect("应报错");
    assert!(err.to_string().contains("kerlico 原生出站"), "{err}");
}

#[test]
fn invalid_proxy_name_regex_is_rejected() {
    let err = compile(
        members(),
        json!({"proxy-name": [{"pattern": "(", "target": ""}]}),
    )
    .err()
    .expect("应报错");
    assert!(err.to_string().contains("proxy-name"), "{err}");
}

#[test]
fn share_link_members_get_overrides_too() {
    let link =
        "hy2://secretpass[at]us.example.com:443?sni=us.example.com#US-Hy2".replace("[at]", "@");
    let spec: ProxyProviderSpec = serde_json::from_value(json!({
        "type": "inline",
        "payload": [link],
        "override": {"up": "10 Mbps", "additional-suffix": "-V1"},
    }))
    .unwrap();
    let (_, specs) = spec.compile("sub").unwrap();
    assert_eq!(specs[0].tag, "US-Hy2-V1");
    assert_eq!(specs[0].options["up"], "10 Mbps");
}
