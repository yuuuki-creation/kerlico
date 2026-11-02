#![cfg(unix)]

use serde_json::{Value, json};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        use std::os::unix::fs::DirBuilderExt;
        let path = std::env::current_dir().unwrap().join(format!(
            "cli-history-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
struct Running(Child);
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn command() -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_kerlico"));
    command
        .env("LC_ALL", "C")
        .env_remove("LC_MESSAGES")
        .env_remove("LANG");
    command
}
fn query(directory: &Path, arguments: &[&str]) -> Value {
    let result = command()
        .args(["--lang", "en", "history", "--directory"])
        .arg(directory)
        .args(arguments)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    serde_json::from_slice(&result.stdout).unwrap()
}
fn run_and_transfer(config: &Path, echo: &TcpListener) {
    let mut child = Running(
        command()
            .args(["--lang", "en", "run", "--config"])
            .arg(config)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let stdout = child.0.stdout.take().unwrap();
    let (ready, listening) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut line = String::new();
        BufReader::new(stdout).read_line(&mut line).unwrap();
        ready.send(line).unwrap();
    });
    let line = listening.recv_timeout(Duration::from_secs(5)).unwrap();
    reader.join().unwrap();
    let address: SocketAddr = line
        .strip_prefix("Inbound entry is listening on ")
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    for _ in 0..2 {
        let mut client = TcpStream::connect_timeout(&address, Duration::from_secs(2)).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let (mut peer, _) = echo.accept().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        client.write_all(b"request").unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        let mut received = Vec::new();
        peer.read_to_end(&mut received).unwrap();
        assert_eq!(received, b"request");
        peer.write_all(b"reply").unwrap();
        peer.shutdown(Shutdown::Write).unwrap();
        received.clear();
        client.read_to_end(&mut received).unwrap();
        assert_eq!(received, b"reply");
    }
    assert!(
        Command::new("kill")
            .args(["-TERM", &child.0.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let deadline = Instant::now() + Duration::from_secs(3);
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "CLI did not finish within the shutdown budget"
        );
        std::thread::sleep(Duration::from_millis(5));
    };
    let mut stderr = String::new();
    child
        .0
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(status.success(), "{stderr}");
}

#[test]
fn real_cli_restart_persists_exact_totals_and_queries_before_pagination() {
    let directory = Directory::new();
    let history = directory.0.join("history");
    let config = directory.0.join("config.json");
    let echo = TcpListener::bind("127.0.0.1:0").unwrap();
    fs::write(&config, serde_json::to_vec(&json!({
        "version":2,"outbounds":[{"tag":"exit","type":"direct"}],
        "inbounds":[{"tag":"entry","type":"tcp-forward","listen":"127.0.0.1:0",
            "target":{"host":"127.0.0.1","port":echo.local_addr().unwrap().port()},"outbound":"exit"}],
        "telemetry":{"directory":history,"sample_interval_ms":60000},
        "limits":{"drain_timeout_ms":1000}
    })).unwrap()).unwrap();
    let checked = command()
        .args(["check", "--config"])
        .arg(&config)
        .output()
        .unwrap();
    assert!(checked.status.success());
    assert!(!history.exists());
    for _ in 0..2 {
        run_and_transfer(&config, &echo);
    }
    let modified = fs::metadata(history.join("history.sqlite3"))
        .unwrap()
        .modified()
        .unwrap();
    let usage = query(&history, &[]);
    let engine = usage
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["dimension"] == "engine")
        .unwrap();
    assert_eq!(engine["usage"]["upload_bytes"], 28);
    assert_eq!(engine["usage"]["download_bytes"], 20);
    let node = query(&history, &["--node", "entry"]);
    assert_eq!(node.as_array().unwrap().len(), 1);
    assert_eq!(node[0]["dimension"], "node");
    assert_eq!(node[0]["usage"]["upload_bytes"], 28);
    assert_eq!(query(&history, &["--node", "absent"]), json!([]));
    let flows = query(
        &history,
        &["--kind", "flows", "--node", "entry", "--outbound", "exit"],
    );
    assert_eq!(flows.as_array().unwrap().len(), 4);
    let first = query(&history, &["--kind", "flows", "--limit", "1"]);
    assert_eq!(first.as_array().unwrap().len(), 1);
    let cursor = first[0][0].as_i64().unwrap().to_string();
    assert_eq!(
        query(&history, &["--kind", "flows", "--after", &cursor])
            .as_array()
            .unwrap()
            .len(),
        3
    );
    let bandwidth = query(
        &history,
        &["--kind", "bandwidth", "--outbound", "exit", "--limit", "1"],
    );
    assert_eq!(bandwidth.as_array().unwrap().len(), 1);
    assert_eq!(bandwidth[0][1]["dimension"], "outbound");
    assert_eq!(bandwidth[0][1]["key"], "exit");
    assert_eq!(
        fs::metadata(history.join("history.sqlite3"))
            .unwrap()
            .modified()
            .unwrap(),
        modified
    );
}

#[test]
fn history_help_and_numeric_errors_are_localized_without_creating_storage() {
    let directory = Directory::new();
    let missing = directory.0.join("missing");
    for (language, word) in [("zh-CN", "只读查询"), ("en", "read-only")] {
        let help = command()
            .args(["--lang", language, "history", "--help"])
            .output()
            .unwrap();
        assert!(help.status.success());
        assert!(String::from_utf8_lossy(&help.stdout).contains(word));
        for argument in ["--limit", "--after", "--since-ms"] {
            let output = command()
                .args(["--lang", language, "history", "--directory"])
                .arg(&missing)
                .args([argument, "abc"])
                .output()
                .unwrap();
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert_eq!(output.status.code(), Some(2));
            assert!(stderr.contains("cli.invalid_value"));
            assert!(
                stderr.contains(if language == "zh-CN" {
                    "必须是"
                } else {
                    "Must be"
                }),
                "{stderr}"
            );
            assert!(!stderr.contains("invalid digit"));
        }
    }
    let missing_query = command()
        .args(["history", "--directory"])
        .arg(&missing)
        .output()
        .unwrap();
    assert!(!missing_query.status.success());
    assert!(!missing.exists());
}
