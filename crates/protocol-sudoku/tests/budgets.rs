mod common;

use common::*;
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

async fn response(stream: &mut TcpStream) -> Vec<u8> {
    tokio::time::timeout(WAIT, async {
        let mut bytes = Vec::new();
        while !bytes.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            stream.read_exact(&mut byte).await.unwrap();
            bytes.push(byte[0]);
            assert!(bytes.len() <= 32 * 1024);
        }
        assert!(bytes.starts_with(b"HTTP/1.1 405"));
        bytes
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn later_h1_headers_use_a_fresh_budget_after_slow_initial_classification() {
    let server = Running::start(
        configuration(
            node_options("stream", KEY, "chacha20-poly1305"),
            false,
            false,
        ),
        Arc::new(State::default()),
    )
    .await;
    let mut stream = TcpStream::connect(server.addresses["node"]).await.unwrap();
    let partial = b"GET /missing HTTP/1.1\r\nHost: localhost\r\nX-Sudoku-Tunnel: stream\r\n";
    stream.write_all(partial).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1300)).await;
    stream.write_all(b"\r\n").await.unwrap();
    response(&mut stream).await;
    stream.write_all(partial).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1000)).await;
    stream.write_all(b"\r\n").await.unwrap();
    response(&mut stream).await;
    drop(stream);
    server.close().await;
}
