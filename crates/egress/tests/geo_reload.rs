//! Geo 数据接入运行时：规则引用的 `GeoSite.dat` 缺失时启动即下载，刷新后不重启即生效，
//! 新文件缺少引用的分类时拒绝换入并保留旧数据。
//!
//! Geo 文件按 Mihomo 习惯放在工作目录，本测试独占一个进程并切换到临时目录。

use kerlico_config::{GeoFile, Registry, ResourceKey, parse};
use kerlico_egress::{EgressRuntime, Refreshed, native_device};
use kerlico_net::DirectFactory;
use kerlico_routing::geodata::fixture;
use serde_json::json;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

async fn origin(body: Arc<Mutex<Vec<u8>>>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let body = body.lock().unwrap().clone();
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut chunk = [0u8; 1024];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => request.extend_from_slice(&chunk[..n]),
                    }
                }
                let mut reply =
                    format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len())
                        .into_bytes();
                reply.extend_from_slice(&body);
                let _ = stream.write_all(&reply).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    port
}

fn routed(runtime: &EgressRuntime, host: &str) -> String {
    runtime
        .control_plane()
        .test_route(host, 443, "tcp", "")
        .unwrap()["outbound"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn referenced_geosite_downloads_at_startup_and_reloads_without_restart() {
    let dir = tempfile::tempdir().unwrap();
    std::env::set_current_dir(dir.path()).unwrap();
    let body = Arc::new(Mutex::new(fixture::geosite(&[(
        "corp",
        &[(2, "corp.test", &[])],
    )])));
    let port = origin(body.clone()).await;
    let config = json!({
        "version": 2,
        "outbounds": [{"tag": "a", "type": "direct"}, {"tag": "b", "type": "direct"}],
        "inbounds": [{"tag": "entry", "type": "tcp-forward", "listen": "127.0.0.1:0",
            "outbound": "b", "target": {"host": "unused.invalid", "port": 80}}],
        "geox_url": {"geosite": format!("http://127.0.0.1:{port}/geosite.dat")},
        "route": {"rules": [{"geosite": ["corp"], "outbound": "a"}], "final": "b"}
    });
    let mut registry = Registry::default();
    registry.register(DirectFactory).unwrap();
    let plan = registry
        .prepare(parse(&serde_json::to_vec(&config).unwrap()).unwrap())
        .unwrap()
        .into_parts()
        .egress;
    let resources = plan.resources().to_vec();
    let runtime = EgressRuntime::start(plan, native_device(), Duration::from_secs(1))
        .await
        .unwrap();
    let refresher = runtime.start_resources(resources).await.unwrap();
    assert!(
        dir.path().join("GeoSite.dat").exists(),
        "引用的 GeoSite.dat 应在启动时下载"
    );
    assert_eq!(routed(&runtime, "www.corp.test"), "a");
    assert_eq!(routed(&runtime, "www.other.test"), "b");

    *body.lock().unwrap() = fixture::geosite(&[("corp", &[(2, "other.test", &[])])]);
    let key = ResourceKey::Geo(GeoFile::GeoSite);
    assert_eq!(
        refresher.refresh(&key).await.unwrap().unwrap(),
        Refreshed::Changed
    );
    assert_eq!(routed(&runtime, "www.corp.test"), "b");
    assert_eq!(routed(&runtime, "www.other.test"), "a");

    *body.lock().unwrap() = fixture::geosite(&[("unrelated", &[(2, "corp.test", &[])])]);
    let error = refresher.refresh(&key).await.unwrap().unwrap_err();
    assert!(error.to_string().contains("corp"), "{error}");
    assert_eq!(
        routed(&runtime, "www.other.test"),
        "a",
        "缺分类的新文件不换入"
    );

    std::fs::write(
        dir.path().join("GeoSite.dat"),
        fixture::geosite(&[("unrelated", &[(2, "x.test", &[])])]),
    )
    .unwrap();
    let error = registry
        .prepare(parse(&serde_json::to_vec(&config).unwrap()).unwrap())
        .err()
        .expect("本地 GeoSite.dat 缺少引用的分类时配置应失败");
    assert!(error.to_string().contains("corp"), "{error}");
}
