#![cfg(unix)]

use serde_json::json;
use std::{fs, os::unix::fs::DirBuilderExt, process::Command};

fn config(state: &std::path::Path) -> serde_json::Value {
    json!({
        "version": 2,
        "outbounds": [{"tag":"exit","type":"direct"}],
        "inbounds": [{"tag":"entry","type":"tcp-forward","listen":"127.0.0.1:0",
            "target":{"host":"127.0.0.1","port":9},"outbound":"exit"}],
        "device": {"state_directory": state, "registration": "existing-only"}
    })
}

#[test]
fn run_uses_the_device_section_and_never_registers_without_an_identity() {
    let directory = tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap();
    let state = directory.path().join("state");
    fs::DirBuilder::new().mode(0o700).create(&state).unwrap();
    let file = directory.path().join("config.json");
    fs::write(&file, serde_json::to_vec(&config(&state)).unwrap()).unwrap();
    let check = Command::new(env!("CARGO_BIN_EXE_kerlico"))
        .args(["--lang", "en", "check", "--config"])
        .arg(&file)
        .output()
        .unwrap();
    assert!(check.status.success(), "check 不接触设备状态");
    let run = Command::new(env!("CARGO_BIN_EXE_kerlico"))
        .args(["--lang", "en", "run", "--config"])
        .arg(&file)
        .output()
        .unwrap();
    assert!(!run.status.success(), "缺失身份时 run 必须失败");
    assert!(
        fs::read_dir(&state)
            .unwrap()
            .all(|entry| entry.unwrap().file_name() != "identity.json"),
        "不应发起注册"
    );
}

#[test]
fn shipped_examples_pass_check() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples");
    for name in [
        "client-routes-v2.json",
        "config-v2-minimal.json",
        "local-forward-v2.json",
        "vless-tls.json",
        "tun-v2.json",
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_kerlico"))
            .args(["--lang", "en", "check", "--config"])
            .arg(root.join(name))
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
}
