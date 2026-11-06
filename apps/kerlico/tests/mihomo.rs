use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "kerlico-mihomo-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn write(&self, name: &str, text: &str) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, text).unwrap();
        path
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn kerlico(args: &[&str], config: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kerlico"))
        .env("LC_ALL", "C")
        .env_remove("LC_MESSAGES")
        .env_remove("LANG")
        .args(args)
        .arg("-c")
        .arg(config)
        .output()
        .unwrap()
}
fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[path = "cases/mihomo.rs"]
mod cases;
use cases::*;

fn single(name: &str, body: &str) -> String {
    format!("proxies:\n  - name: {name}\n{body}rules:\n  - MATCH,{name}\n")
}

#[test]
fn every_mihomo_type_compiles_through_the_real_registry_with_expected_options() {
    let dir = Directory::new();
    let mut failures = Vec::new();
    for (name, body, kind, expected) in cases() {
        let path = dir.write(&format!("{name}.yaml"), &single(name, &body));
        let check = kerlico(&["check"], &path);
        if !check.status.success() {
            failures.push(format!("{name}: check failed: {}", text(&check.stderr)));
            continue;
        }
        let dump = kerlico(&["run", "--dump"], &path);
        assert!(dump.status.success(), "{name}: {}", text(&dump.stderr));
        let value: Value = serde_json::from_slice(&dump.stdout).unwrap();
        let outbound = value["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["tag"] == name)
            .unwrap_or_else(|| panic!("{name}: outbound missing"));
        if outbound["type"] != kind || outbound["options"] != expected {
            failures.push(format!(
                "{name}: got type {} options {}",
                outbound["type"], outbound["options"]
            ));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn unknown_mihomo_field_fails_config_loading_naming_proxy_and_field() {
    let dir = Directory::new();
    let body = "    type: vmess\n    server: v.example.com\n    port: 443\n    uuid: 11111111-2222-3333-4444-555555555555\n    network: ws\n    ws-opts:\n      path: /ws\n      bogus-key: 1\n";
    let path = dir.write("bad.yaml", &single("vmess-bad", body));
    let out = kerlico(&["check"], &path);
    let stderr = text(&out.stderr);
    assert!(!out.status.success());
    assert!(
        stderr.contains("vmess-bad") && stderr.contains("ws-opts.bogus-key"),
        "{stderr}"
    );
    assert!(!stderr.contains("[untranslated detail]"), "{stderr}");

    let body = "    type: trojan\n    server: t.example.com\n    port: 443\n    password: pw\n    client-fingerprint: chrome\n";
    let path = dir.write("fp.yaml", &single("trojan-fp", body));
    let out = kerlico(&["check"], &path);
    let stderr = text(&out.stderr);
    assert!(!out.status.success());
    assert!(
        stderr.contains("trojan-fp") && stderr.contains("client-fingerprint"),
        "{stderr}"
    );
}

#[test]
fn provider_file_and_share_link_nodes_compile_through_the_real_registry() {
    let dir = Directory::new();
    let members = dir.write(
        "members.yaml",
        "proxies:\n  - name: same\n    type: trojan\n    server: t.example.com\n    port: 443\n    password: pw\n    sni: t.example.com\n    network: grpc\n    grpc-opts:\n      grpc-service-name: grpc-svc\n",
    );
    let config = format!(
        "proxy-providers:\n  file-sub:\n    type: file\n    path: {}\n  link-sub:\n    type: inline\n    payload:\n      - \"trojan://pw[at]t.example.com:443?sni=t.example.com&type=grpc&serviceName=grpc-svc#link-same\"\nproxy-groups:\n  - name: auto\n    type: select\n    use: [file-sub, link-sub]\nrules:\n  - MATCH,auto\n",
        serde_json::to_string(members.to_str().unwrap()).unwrap()
    );
    let path = dir.write("providers.yaml", &config.replace("[at]", "@"));
    let out = kerlico(&["check"], &path);
    assert!(out.status.success(), "{}", text(&out.stderr));
}

#[test]
fn golden_full_mihomo_config_loads() {
    let golden = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/mihomo-full.yaml");
    let out = kerlico(&["check"], &golden);
    assert!(out.status.success(), "{}", text(&out.stderr));
}
