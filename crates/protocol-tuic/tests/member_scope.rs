use serde_json::json;
#[allow(dead_code)]
mod shared {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tools/protocol_b_test_support.rs"
    ));
}
#[tokio::test]
async fn both_tuic_authentication_versions_select_member_scope() {
    for version in [4, 5] {
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert = certificate.cert.pem();
        let key = certificate.signing_key.serialize_pem();
        let users = if version == 4 {
            vec![
                json!({"token":"synthetic-token-a"}),
                json!({"token":"synthetic-token-b"}),
            ]
        } else {
            vec![
                json!({"uuid":"00000000-0000-4000-8000-000000000001","password":"synthetic-secret-a"}),
                json!({"uuid":"00000000-0000-4000-8000-000000000002","password":"synthetic-secret-b"}),
            ]
        };
        let clients = users
            .iter()
            .map(|user| {
                let mut client = user.clone();
                client["version"] = json!(version);
                client["tls"] = json!({"server_name":"localhost","ca_pem":cert});
                client
            })
            .collect();
        shared::assert_member_scope(
            &kerlico_tuic::TuicNodeFactory,
            &kerlico_tuic::TuicFactory,
            json!({"version":version,"tls":{"certificate_pem":cert,"private_key_pem":key}}),
            users,
            clients,
        )
        .await;
    }
}
