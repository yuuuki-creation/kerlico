use serde_json::json;
#[allow(dead_code)]
mod shared {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tools/protocol_b_test_support.rs"
    ));
}
#[tokio::test]
async fn actual_decryption_key_selects_member_scope() {
    let users = vec![
        json!({"username":"member-a","password":"synthetic-secret-a"}),
        json!({"username":"member-b","password":"synthetic-secret-b"}),
    ];
    shared::assert_member_scope(
        &kerlico_mieru::MieruNodeFactory,
        &kerlico_mieru::MieruFactory,
        json!({}),
        users.clone(),
        users,
    )
    .await;
}
