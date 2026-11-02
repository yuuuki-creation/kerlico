use serde_json::json;
#[allow(dead_code)]
mod shared {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tools/protocol_b_test_support.rs"
    ));
}
#[tokio::test]
async fn all_trusttunnel_transports_select_member_per_connect() {
    for transport in ["h1", "h2", "h3"] {
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert = certificate.cert.pem();
        let key = certificate.signing_key.serialize_pem();
        let users = vec![
            json!({"username":"member-a","password":"synthetic-secret-a"}),
            json!({"username":"member-b","password":"synthetic-secret-b"}),
        ];
        let clients=users.iter().map(|user|json!({"auth":user,"transport":transport,"tls":{"server_name":"localhost","ca_pem":cert}})).collect();
        shared::assert_member_scope(
            &kerlico_trusttunnel::TrustTunnelNodeFactory,
            &kerlico_trusttunnel::TrustTunnelFactory,
            json!({"transport":transport,"tls":{"certificate_pem":cert,"private_key_pem":key}}),
            users,
            clients,
        )
        .await;
    }
}
