#![cfg(unix)]

use serde_json::{Value, json};
use std::{
    fs,
    io::{BufRead, BufReader, ErrorKind, Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::current_dir().unwrap().join(format!(
            "cli-reload-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Running(Child);
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn config(listen: u16, echo: u16, control: u16) -> Value {
    json!({
        "version":2,"outbounds":[{"tag":"exit","type":"direct"}],
        "inbounds":[{"tag":"entry","type":"tcp-forward","listen":format!("127.0.0.1:{listen}"),
            "target":{"host":"127.0.0.1","port":echo},"outbound":"exit"}],
        "control":{"listen":format!("127.0.0.1:{control}")},
        "limits":{"drain_timeout_ms":1000}
    })
}

fn start(config: &Path) -> Running {
    let mut child = Running(
        Command::new(env!("CARGO_BIN_EXE_kerlico"))
            .env("LC_ALL", "C")
            .args(["--lang", "en", "run", "--config"])
            .arg(config)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let stdout = child.0.stdout.take().unwrap();
    let (lines, received) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            let _ = lines.send(line);
        }
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let line = received
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .expect("control interface did not start");
        if line.starts_with("Control interface is listening on") {
            break child;
        }
    }
}

fn http(port: u16, method: &str, path: &str, body: Option<&Value>) -> (u16, Value) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let body = body.map(Value::to_string).unwrap_or_default();
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    let status = response["HTTP/1.1 ".len().."HTTP/1.1 ".len() + 3]
        .parse()
        .unwrap();
    let payload = response
        .split_once("\r\n\r\n")
        .map_or("", |(_, payload)| payload);
    (status, serde_json::from_str(payload).unwrap_or(Value::Null))
}

fn reloads(control: u16) -> Value {
    http(control, "GET", "/v1/health", None).1["reloads"].clone()
}

fn wait_for_reloads(control: u16, succeeded: u64, failed: u64) -> Value {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let current = reloads(control);
        if current["succeeded"] == succeeded && current["failed"] == failed {
            return current;
        }
        assert!(
            Instant::now() < deadline,
            "reload counters stayed at {current}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn assert_forwards(listen: u16, echo: &TcpListener) {
    let mut client = TcpStream::connect(("127.0.0.1", listen)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let (mut peer, _) = echo.accept().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    client.write_all(b"ping").unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut received = Vec::new();
    peer.read_to_end(&mut received).unwrap();
    assert_eq!(received, b"ping");
    peer.write_all(b"pong").unwrap();
    peer.shutdown(Shutdown::Write).unwrap();
    received.clear();
    client.read_to_end(&mut received).unwrap();
    assert_eq!(received, b"pong");
}

fn assert_refuses(listen: u16) {
    let error = TcpStream::connect(("127.0.0.1", listen)).unwrap_err();
    assert_eq!(error.kind(), ErrorKind::ConnectionRefused);
}

fn sighup(child: &Running) {
    assert!(
        Command::new("kill")
            .args(["-HUP", &child.0.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
}

#[test]
fn sighup_reload_moves_the_listener_and_keeps_serving_on_invalid_config() {
    let directory = Directory::new();
    let path = directory.0.join("config.json");
    let echo = TcpListener::bind("127.0.0.1:0").unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    let (first, second, control) = (free_port(), free_port(), free_port());
    fs::write(&path, config(first, echo_port, control).to_string()).unwrap();
    let child = start(&path);
    assert_forwards(first, &echo);
    assert_eq!(
        reloads(control),
        json!({"succeeded":0,"failed":0,"last_error":null})
    );

    fs::write(&path, config(second, echo_port, control).to_string()).unwrap();
    sighup(&child);
    wait_for_reloads(control, 1, 0);
    assert_forwards(second, &echo);
    assert_refuses(first);

    fs::write(&path, "{\"version\":2,").unwrap();
    sighup(&child);
    let failed = wait_for_reloads(control, 1, 1);
    assert_eq!(failed["last_error"], "configuration.invalid");
    assert_forwards(second, &echo);
}

#[test]
fn put_configs_reloads_payload_and_path_and_rolls_back_a_failed_start() {
    let directory = Directory::new();
    let path = directory.0.join("config.json");
    let echo = TcpListener::bind("127.0.0.1:0").unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    let (first, second, control) = (free_port(), free_port(), free_port());
    fs::write(&path, config(first, echo_port, control).to_string()).unwrap();
    let _child = start(&path);

    let payload = json!({"payload": config(second, echo_port, control).to_string()});
    assert_eq!(
        http(control, "PUT", "/configs?force=true", Some(&payload)).0,
        204
    );
    assert_forwards(second, &echo);
    assert_refuses(first);

    let other = directory.0.join("other.json");
    fs::write(&other, config(first, echo_port, control).to_string()).unwrap();
    let by_path = json!({"path": other.canonicalize().unwrap()});
    assert_eq!(http(control, "PUT", "/configs", Some(&by_path)).0, 204);
    assert_forwards(first, &echo);
    assert_refuses(second);

    let (status, body) = http(
        control,
        "PUT",
        "/configs",
        Some(&json!({"payload": "{\"version\":1}"})),
    );
    assert_eq!(
        (status, &body["error"]),
        (400, &json!("configuration.invalid"))
    );
    assert_eq!(
        http(
            control,
            "PUT",
            "/configs",
            Some(&json!({"path": "other.json"}))
        )
        .0,
        400
    );
    let outside = json!({"path": std::env::temp_dir().canonicalize().unwrap()});
    assert_eq!(http(control, "PUT", "/configs", Some(&outside)).0, 400);
    assert_forwards(first, &echo);

    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    let busy = occupied.local_addr().unwrap().port();
    let clash = json!({"payload": config(busy, echo_port, control).to_string()});
    let (status, body) = http(control, "PUT", "/configs", Some(&clash));
    assert_eq!((status, &body["error"]), (400, &json!("startup.failed")));
    assert_forwards(first, &echo);
    assert_eq!(reloads(control)["succeeded"], 2);
    assert_eq!(reloads(control)["failed"], 3);

    assert_eq!(http(control, "POST", "/restart", None).0, 204);
    assert_forwards(first, &echo);
}

#[test]
fn concurrent_reload_requests_run_one_after_another() {
    let directory = Directory::new();
    let path = directory.0.join("config.json");
    let echo = TcpListener::bind("127.0.0.1:0").unwrap();
    let echo_port = echo.local_addr().unwrap().port();
    let (first, second, control) = (free_port(), free_port(), free_port());
    fs::write(&path, config(first, echo_port, control).to_string()).unwrap();
    let _child = start(&path);

    let requests: Vec<_> = [first, second, first, second]
        .into_iter()
        .map(|listen| {
            let payload = json!({"payload": config(listen, echo_port, control).to_string()});
            std::thread::spawn(move || http(control, "PUT", "/configs", Some(&payload)).0)
        })
        .collect();
    for request in requests {
        assert_eq!(request.join().unwrap(), 204);
    }
    assert_eq!(reloads(control)["succeeded"], 4);
    let first_open = TcpStream::connect(("127.0.0.1", first)).is_ok();
    let second_open = TcpStream::connect(("127.0.0.1", second)).is_ok();
    assert!(first_open != second_open, "exactly one listener remains");
}

/// 回环订阅源：返回当前内容，`None` 时回 500。
fn subscription_origin() -> (u16, std::sync::Arc<std::sync::Mutex<Option<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let body = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
    let shared = body.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => request.extend_from_slice(&chunk[..n]),
                }
            }
            let reply = match shared.lock().unwrap().clone() {
                Some(body) => format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                ),
                None => "HTTP/1.1 500 Broken\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_owned(),
            };
            let _ = stream.write_all(reply.as_bytes());
        }
    });
    (port, body)
}

fn provider_members(control: u16) -> Vec<String> {
    let (status, body) = http(control, "GET", "/providers/proxies/sub", None);
    assert_eq!(status, 200, "{body}");
    body["proxies"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["name"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn provider_update_endpoint_downloads_and_rebuilds_with_new_members() {
    let directory = Directory::new();
    let path = directory.0.join("config.json");
    let (origin, body) = subscription_origin();
    *body.lock().unwrap() = Some(json!([{"tag": "n1", "type": "direct"}]).to_string());
    let (listen, control) = (free_port(), free_port());
    let mut value = config(listen, free_port(), control);
    value["proxy_providers"] = json!({"sub": {"type": "http",
        "url": format!("http://127.0.0.1:{origin}/sub"),
        "path": directory.0.join("sub.json"), "interval": 3600}});
    value["proxy_groups"] = json!([{"name": "pick", "type": "select", "use": ["sub"]}]);
    fs::write(&path, value.to_string()).unwrap();
    let _child = start(&path);

    wait_for_reloads(control, 1, 0);
    assert_eq!(provider_members(control), ["n1"]);

    *body.lock().unwrap() = Some(json!([{"tag": "n2", "type": "direct"}]).to_string());
    assert_eq!(http(control, "PUT", "/providers/proxies/sub", None).0, 204);
    assert_eq!(reloads(control)["succeeded"], 2);
    assert_eq!(provider_members(control), ["n2"]);

    *body.lock().unwrap() = None;
    let (status, failure) = http(control, "PUT", "/providers/proxies/sub", None);
    assert_eq!(status, 503, "{failure}");
    assert!(failure["message"].as_str().unwrap().contains("500"));
    assert_eq!(provider_members(control), ["n2"]);
    let (_, listed) = http(control, "GET", "/providers/proxies/sub", None);
    assert!(listed["error"].as_str().unwrap().contains("500"));
}
