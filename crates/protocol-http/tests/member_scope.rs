use serde_json::json;
#[allow(dead_code)]
mod shared {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tools/protocol_b_test_support.rs"
    ));
}
#[tokio::test]
async fn basic_auth_members_keep_distinct_scopes_and_original_target() {
    let users = vec![
        json!({"username":"member-a","password":"synthetic-secret-a"}),
        json!({"username":"member-b","password":"synthetic-secret-b"}),
    ];
    let clients = users.iter().map(|user| json!({"auth":user})).collect();
    shared::assert_member_scope(
        &kerlico_http::HttpNodeFactory,
        &kerlico_http::HttpFactory,
        json!({}),
        users,
        clients,
    )
    .await;
}

#[test]
fn authenticated_local_fixture_becomes_a_member_node() {
    let credential = json!({"username":"fixture-member","password":"synthetic-secret"});
    let value = shared::configuration(
        json!({"outbounds":[{"tag":"exit","type":"direct"}],"local_inbounds":[
            {"tag":"authenticated","type":"http","listen":"127.0.0.1:0","outbound":"exit","options":{"auth":credential}},
            {"tag":"local","type":"socks","listen":"127.0.0.1:0","outbound":"exit","options":{}}
        ]}),
    );
    kerlico_config::parse(&serde_json::to_vec(&value).unwrap()).unwrap();
    assert_eq!(value["nodes"][0]["tag"], "authenticated");
    assert_eq!(
        value["nodes"][0]["members"][0]["native_credential"],
        credential
    );
    assert!(value["nodes"][0]["options"].get("auth").is_none());
    assert_eq!(value["accounts"].as_array().unwrap().len(), 1);
    assert_eq!(value["local_inbounds"].as_array().unwrap().len(), 1);
    assert_eq!(value["local_inbounds"][0]["tag"], "local");
    assert_eq!(value["local_inbounds"][0]["members"], json!([]));
    assert_eq!(shared::configuration(value.clone()), value);
}
