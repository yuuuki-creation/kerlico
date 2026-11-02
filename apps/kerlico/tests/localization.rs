use std::{
    fs,
    path::PathBuf,
    process::{Command, Output, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "kerlico-i18n-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&path).unwrap();
        Self(path)
    }
    fn config(&self, value: serde_json::Value) -> PathBuf {
        let path = self.0.join("config.json");
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        path
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
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
fn output(arguments: &[&str]) -> Output {
    command().args(arguments).output().unwrap()
}
fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap()
}
fn configuration() -> serde_json::Value {
    serde_json::json!({"version":2,"outbounds":[{"tag":"direct","type":"direct"}],
        "inbounds":[{"tag":"entry","type":"tcp-forward","listen":"127.0.0.1:0","target":{"host":"127.0.0.1","port":9},"outbound":"direct"}]})
}

#[test]
fn real_help_and_parser_errors_use_selected_language_with_stable_arguments() {
    for (language, word) in [("zh-CN", "用法"), ("en", "Usage")] {
        for subcommand in [
            None,
            Some("check"),
            Some("run"),
            Some("account-new"),
            Some("modules"),
        ] {
            let mut arguments = vec!["--lang", language];
            if let Some(subcommand) = subcommand {
                arguments.push(subcommand);
            }
            arguments.push("--help");
            let result = output(&arguments);
            assert!(result.status.success(), "{}", text(&result.stderr));
            assert!(text(&result.stdout).contains(word));
            assert!(text(&result.stdout).contains("--lang"));
        }
        let help = output(&["--lang", language, "help", "check"]);
        assert!(help.status.success());
        assert!(text(&help.stdout).contains("--config"));
        let unknown = output(&["--lang", language, "--unknown-option"]);
        assert_eq!(unknown.status.code(), Some(2));
        let unknown = text(&unknown.stderr);
        assert!(unknown.contains("cli.unknown_argument"));
        assert!(unknown.contains("--unknown-option"));
        assert!(unknown.contains(if language == "en" {
            "unexpected argument"
        } else {
            "无法识别参数"
        }));
        let missing = output(&["--lang", language, "check"]);
        assert_eq!(missing.status.code(), Some(2));
        assert!(text(&missing.stderr).contains("--config"));
        assert!(text(&missing.stderr).contains("cli.missing_argument"));
        let invalid_help = output(&["--lang", language, "help", "no-such-command"]);
        assert_eq!(invalid_help.status.code(), Some(2));
        assert!(text(&invalid_help.stderr).contains("no-such-command"));
        assert!(text(&invalid_help.stderr).contains("cli.invalid_subcommand"));
    }
    let invalid_language = output(&["--lang", "invalid", "modules"]);
    assert_eq!(invalid_language.status.code(), Some(2));
    assert!(text(&invalid_language.stderr).contains("invalid"));
}

#[test]
fn real_configuration_messages_and_io_errors_keep_diagnostic_details() {
    let directory = Directory::new();
    for (language, valid, invalid) in [
        ("zh-CN", "配置检查通过", "仅支持配置版本 2"),
        (
            "en",
            "Configuration is valid",
            "Only configuration version 2",
        ),
    ] {
        let config = directory.config(configuration());
        let result = command()
            .args(["--lang", language, "check", "-c"])
            .arg(&config)
            .output()
            .unwrap();
        assert!(result.status.success(), "{}", text(&result.stderr));
        assert!(text(&result.stdout).contains(valid));
        directory.config(serde_json::json!({"version":1}));
        let result = command()
            .args(["--lang", language, "check", "-c"])
            .arg(&config)
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(1));
        assert!(text(&result.stderr).contains("configuration.invalid"));
        assert!(text(&result.stderr).contains(invalid));
        let result = command()
            .args(["--lang", language, "run", "-c"])
            .arg(directory.0.join("missing.json"))
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(1));
        assert!(text(&result.stderr).contains("io.failed"));
        if language == "en" {
            assert!(text(&result.stderr).contains("OS error"));
        }
    }
}

#[test]
fn language_environment_precedence_and_modules_are_stable() {
    let chinese = command()
        .env("LC_ALL", "zh_CN.UTF-8")
        .arg("--help")
        .output()
        .unwrap();
    assert!(text(&chinese.stdout).contains("模块化代理内核"));
    let english = command()
        .env("LC_ALL", "en_US.UTF-8")
        .env("LC_MESSAGES", "zh_CN.UTF-8")
        .arg("--help")
        .output()
        .unwrap();
    assert!(text(&english.stdout).contains("Modular client and server proxy core"));
    let override_language = command()
        .env("LC_ALL", "zh_CN.UTF-8")
        .args(["--lang=en", "--help"])
        .output()
        .unwrap();
    assert!(text(&override_language.stdout).contains("Modular client and server proxy core"));
    let chinese = output(&["modules", "--lang=zh-CN"]);
    let english = output(&["modules", "--lang=en"]);
    assert_eq!(chinese.stdout, english.stdout);
    assert!(text(&english.stdout).contains("outbound/direct"));
}

#[cfg(any(
    feature = "protocol-anytls",
    feature = "protocol-http",
    feature = "protocol-socks",
    feature = "protocol-ss2022",
    feature = "protocol-tor",
    feature = "protocol-wireguard",
    feature = "protocol-shadowsocks",
    feature = "protocol-shadowsocksr",
    feature = "protocol-shadowtls",
    feature = "protocol-snell",
    feature = "protocol-tuic",
    feature = "protocol-trojan",
    feature = "protocol-vmess",
    feature = "protocol-gost-relay",
    feature = "protocol-hysteria1",
    feature = "protocol-hysteria2",
    feature = "protocol-shadowquic",
    feature = "protocol-mieru",
    feature = "protocol-naive",
    feature = "protocol-trusttunnel",
    feature = "protocol-ssh",
    feature = "protocol-vless",
    feature = "protocol-sudoku"
))]
#[test]
fn compiled_protocol_configuration_errors_are_localized() {
    let cases: &[(&str, &str, &str)] = &[
        #[cfg(feature = "protocol-anytls")]
        (
            "anytls",
            "AnyTLS 出站字段不合法",
            "Invalid AnyTLS outbound fields",
        ),
        #[cfg(feature = "protocol-http")]
        (
            "http",
            "HTTP 出站字段不合法",
            "Invalid HTTP outbound fields",
        ),
        #[cfg(feature = "protocol-socks")]
        (
            "socks",
            "SOCKS 出站字段不合法",
            "Invalid SOCKS outbound fields",
        ),
        #[cfg(feature = "protocol-ss2022")]
        (
            "ss2022",
            "Ss2022 出站字段不合法",
            "Invalid SS2022 outbound fields",
        ),
        #[cfg(feature = "protocol-tor")]
        ("tor", "Tor出站字段不合法", "Invalid Tor outbound fields"),
        #[cfg(feature = "protocol-wireguard")]
        (
            "wireguard",
            "WireGuard出站字段不合法",
            "Invalid WireGuard outbound fields",
        ),
        #[cfg(feature = "protocol-shadowsocks")]
        (
            "shadowsocks",
            "Shadowsocks 出站字段不合法",
            "Invalid Shadowsocks outbound fields",
        ),
        #[cfg(feature = "protocol-shadowsocksr")]
        (
            "shadowsocksr",
            "ShadowsocksR 参数、组合或资源限制不合法",
            "Invalid ShadowsocksR parameters, combination, or resource limits",
        ),
        #[cfg(feature = "protocol-shadowtls")]
        (
            "shadowtls",
            "ShadowTLS 配置不合法或组合未提供",
            "Invalid ShadowTLS configuration or unavailable combination",
        ),
        #[cfg(feature = "protocol-snell")]
        ("snell", "Snell 配置不合法", "Invalid Snell configuration"),
        #[cfg(feature = "protocol-tuic")]
        ("tuic", "TUIC 配置不合法", "Invalid TUIC configuration"),
        #[cfg(feature = "protocol-trojan")]
        (
            "trojan",
            "Trojan 配置不合法",
            "Invalid Trojan configuration",
        ),
        #[cfg(feature = "protocol-vmess")]
        (
            "vmess",
            "VMess 客户端配置不合法",
            "Invalid VMess client configuration",
        ),
        #[cfg(feature = "protocol-gost-relay")]
        (
            "gost-relay",
            "Gost Relay 出站字段不合法",
            "Invalid Gost Relay outbound fields",
        ),
        #[cfg(feature = "protocol-hysteria1")]
        (
            "hysteria1",
            "Hysteria v1 配置不合法",
            "Invalid Hysteria v1 configuration",
        ),
        #[cfg(feature = "protocol-hysteria2")]
        (
            "hysteria2",
            "Hysteria2 出站字段不合法",
            "Invalid Hysteria2 outbound fields",
        ),
        #[cfg(feature = "protocol-shadowquic")]
        (
            "shadowquic",
            "ShadowQUIC 配置不合法",
            "Invalid ShadowQUIC configuration",
        ),
        #[cfg(feature = "protocol-mieru")]
        ("mieru", "Mieru 配置无效", "Invalid Mieru configuration"),
        #[cfg(feature = "protocol-naive")]
        ("naive", "Naive 配置不合法", "Invalid Naive configuration"),
        #[cfg(feature = "protocol-trusttunnel")]
        (
            "trusttunnel",
            "TrustTunnel 配置不合法",
            "Invalid TrustTunnel configuration",
        ),
        #[cfg(feature = "protocol-ssh")]
        ("ssh", "SSH 出站字段不合法", "Invalid SSH outbound fields"),
        #[cfg(feature = "protocol-vless")]
        (
            "vless",
            "VLESS 配置字段不合法",
            "Invalid VLESS configuration fields",
        ),
        #[cfg(feature = "protocol-sudoku")]
        (
            "sudoku",
            "Sudoku出站字段不合法",
            "Invalid Sudoku outbound fields",
        ),
    ];
    for &(kind, chinese, english) in cases {
        let directory = Directory::new();
        let config = directory.config(serde_json::json!({"version":2,"outbounds":[{"tag":"proxy","type":kind,"options":{"invalid":true}}]}));
        for (language, expected) in [("zh-CN", chinese), ("en", english)] {
            let result = command()
                .args(["--lang", language, "check", "-c"])
                .arg(&config)
                .output()
                .unwrap();
            assert_eq!(result.status.code(), Some(1));
            assert!(
                text(&result.stderr).contains(expected),
                "{kind}: {}",
                text(&result.stderr)
            );
            assert!(!text(&result.stderr).contains("[untranslated detail]"));
        }
    }
}

#[cfg(unix)]
#[test]
fn real_runtime_listener_and_startup_error_are_localized() {
    use std::io::{BufRead, BufReader};
    for (language, listener, no_inbound) in [
        ("zh-CN", "入口 entry 已监听", "没有配置入站"),
        (
            "en",
            "Inbound entry is listening",
            "No inbounds are configured",
        ),
    ] {
        let directory = Directory::new();
        let config = directory.config(configuration());
        let mut child = command()
            .args(["--lang", language, "run", "-c"])
            .arg(&config)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (send, receive) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut line = String::new();
            let result = BufReader::new(stdout).read_line(&mut line);
            let _ = send.send((result, line));
        });
        let observed = receive.recv_timeout(Duration::from_secs(3));
        let _ = Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status();
        let deadline = std::time::Instant::now() + Duration::from_secs(8);
        while child.try_wait().unwrap().is_none() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        if child.try_wait().unwrap().is_none() {
            child.kill().unwrap();
        }
        let result = child.wait_with_output().unwrap();
        reader.join().unwrap();
        let (read, line) = observed.unwrap();
        read.unwrap();
        assert!(line.contains(listener), "{line}");
        assert!(result.status.success(), "{}", text(&result.stderr));
        directory.config(
            serde_json::json!({"version":2,"outbounds":[{"tag":"direct","type":"direct"}]}),
        );
        let result = command()
            .args(["--lang", language, "run", "-c"])
            .arg(config)
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(1));
        assert!(text(&result.stderr).contains(no_inbound));
    }
}
