use serde_json::json;
#[allow(dead_code)]
mod shared {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tools/protocol_b_test_support.rs"
    ));
}
#[tokio::test]
async fn raw_split_and_websocket_match_real_member_key() {
    for mode in ["raw", "stream", "ws"] {
        let users = vec![
            json!({"key":"synthetic-member-a-sudoku"}),
            json!({"key":"synthetic-member-b-sudoku"}),
        ];
        let clients=users.iter().map(|user|json!({"protocol":{"key":user["key"],"aead":"chacha20-poly1305","padding_min":0,"padding_max":0},"http_mask":{"mode":mode}})).collect();
        shared::assert_member_scope(&kerlico_sudoku::SudokuNodeFactory, &kerlico_sudoku::SudokuFactory,
            json!({"protocol":{"aead":"chacha20-poly1305","padding_min":0,"padding_max":0},"http_mask":{"mode":mode}}), users, clients).await;
    }
}
