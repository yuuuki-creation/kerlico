use serde_json::json;
#[allow(dead_code)]
mod shared {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tools/protocol_b_test_support.rs"
    ));
}
mod common;
#[tokio::test]
async fn jls_library_selected_user_controls_member_scope() {
    let cover = common::cover("127.0.0.1").await;
    let users = vec![
        json!({"username":"member-a","password":"synthetic-secret-a"}),
        json!({"username":"member-b","password":"synthetic-secret-b"}),
    ];
    for version in ["v1", "v2"] {
        let clients = users
            .iter()
            .map(|user| {
                let mut client = user.clone();
                client["server_name"] = json!(common::NAME);
                client["quic_version"] = json!(version);
                client
            })
            .collect();
        shared::assert_member_scope(&kerlico_shadowquic::ShadowQuicNodeFactory, &kerlico_shadowquic::ShadowQuicFactory,
            json!({"server_name":common::NAME,"upstream":{"host":"127.0.0.1","port":cover.address.port()},"quic_versions":[version]}), users.clone(), clients).await;
    }
}
