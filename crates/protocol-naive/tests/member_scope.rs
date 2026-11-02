use serde_json::json;
#[allow(dead_code)]
mod shared {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tools/protocol_b_test_support.rs"
    ));
}
#[tokio::test]
async fn all_naive_transports_select_member_per_connect() {
    for transport in ["h1", "h2", "h3"] {
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert = certificate.cert.pem();
        let key = certificate.signing_key.serialize_pem();
        let users = vec![
            json!({"username":"member-a","password":"synthetic-secret-a"}),
            json!({"username":"member-b","password":"synthetic-secret-b"}),
        ];
        let clients = users
            .iter()
            .map(|user| {
                let mut client = user.clone();
                client["transport"] = json!(transport);
                client["tls"] = json!({"server_name":"localhost","ca_pem":cert});
                client
            })
            .collect();
        shared::assert_member_scope(
            &kerlico_naive::NaiveNodeFactory,
            &kerlico_naive::NaiveFactory,
            json!({"transports":[transport],"tls":{"certificate_pem":cert,"private_key_pem":key}}),
            users,
            clients,
        )
        .await;
    }
}
