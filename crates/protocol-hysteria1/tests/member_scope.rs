use serde_json::json;
#[allow(dead_code)]
mod shared {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tools/protocol_b_test_support.rs"
    ));
}
#[tokio::test]
async fn quic_auth_selects_member_scope() {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = certificate.cert.pem();
    let key = certificate.signing_key.serialize_pem();
    let users = vec![
        json!({"auth_str":"synthetic-secret-a"}),
        json!({"auth_str":"synthetic-secret-b"}),
    ];
    let clients = users.iter().map(|user|json!({"auth_str":user["auth_str"],"tls":{"server_name":"localhost","ca_pem":cert},"up_bps":20_000_000,"down_bps":20_000_000})).collect();
    shared::assert_member_scope(
        &kerlico_hysteria1::Hysteria1NodeFactory,
        &kerlico_hysteria1::Hysteria1Factory,
        json!({"tls":{"certificate_pem":cert,"private_key_pem":key}}),
        users,
        clients,
    )
    .await;
}
