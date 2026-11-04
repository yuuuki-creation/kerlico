use clap::{Parser, Subcommand, ValueEnum};
use kerlico_config::{Registry, parse};
use kerlico_core::{CancellationToken, Error, Language, Result};
use kerlico_engine::Engine;
use kerlico_net::{
    DirectFactory, DnsFactory, RedirectNodeFactory, RejectFactory, TproxyNodeFactory,
};
use std::path::PathBuf;
mod cli;

#[derive(Parser)]
#[command(name = "kerlico", version, about = "模块化代理内核")]
struct Args {
    #[arg(long, global = true, value_enum)]
    lang: Option<CliLanguage>,
    #[command(subcommand)]
    command: Command,
}
#[derive(Clone, Copy, ValueEnum)]
enum CliLanguage {
    #[value(name = "zh-CN")]
    ZhCn,
    #[value(name = "en")]
    En,
}
impl From<CliLanguage> for Language {
    fn from(language: CliLanguage) -> Self {
        match language {
            CliLanguage::ZhCn => Self::ZhCn,
            CliLanguage::En => Self::En,
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// 只读查询统计历史，输出可分页的 JSON。
    History {
        #[arg(long, default_value = "state/telemetry")]
        directory: PathBuf,
        #[arg(long, value_enum, default_value = "usage")]
        kind: HistoryKind,
        #[arg(long)]
        user: Option<String>,
        #[arg(long)]
        node: Option<String>,
        #[arg(long)]
        outbound: Option<String>,
        #[arg(long, default_value_t = 0)]
        since_ms: u64,
        #[arg(long, default_value_t = 0)]
        after: i64,
        #[arg(long, default_value_t = 1000)]
        limit: usize,
    },
    Help {
        command: Option<String>,
    },
    /// 从标准输入读取管理密码，输出一次生成的持久账户 JSON。
    AccountNew {
        #[arg(long, default_value = "user")]
        prefix: String,
    },
    /// 按角色列出当前构建真实注册的模块。
    Modules,
    /// 校验配置和模块能力，不监听或拨号。
    Check {
        #[arg(short, long)]
        config: PathBuf,
    },
    /// 启动配置的客户端转发入口与服务端节点。
    Run {
        #[arg(short, long)]
        config: PathBuf,
    },
    /// 生成 UUID、随机字节、X25519/WireGuard/ECH/TLS/后量子与协议密钥对。
    #[command(
        visible_aliases = [
            "generate-uuid",
            "generate-reality-keypair",
            "generate-wg-keypair",
            "generate-ech-keypair",
            "generate-vless-x25519",
            "generate-vless-mlkem768",
            "generate-sudoku-keypair"
        ]
    )]
    Generate {
        #[arg(default_value = "uuid")]
        target: String,
        #[arg(long, default_value_t = 32)]
        length: usize,
        #[arg(long)]
        hex: bool,
        #[arg(long)]
        base64: bool,
        #[arg(long, default_value_t = 12)]
        months: u32,
        #[arg(long, default_value = "example.com")]
        domain: String,
        #[arg(long)]
        seed: Option<String>,
    },
    /// 生成自签名 TLS 证书或计算证书 SHA-256 指纹。
    Tls {
        #[arg(default_value = "cert")]
        action: String,
        #[arg(long, default_value = "example.com")]
        domain: String,
        #[arg(long, default_value_t = 12)]
        months: u32,
        #[arg(long)]
        cert: Option<String>,
    },
    /// 兼容 Xray 工具链的密钥与加密参数生成命令。
    Xray {
        #[arg(default_value = "uuid")]
        target: String,
        #[arg(long)]
        seed: Option<String>,
        #[arg(long, default_value = "example.com")]
        domain: String,
        #[arg(long, default_value_t = 12)]
        months: u32,
    },
}
#[derive(Clone, Copy, ValueEnum)]
enum HistoryKind {
    Usage,
    Flows,
    Bandwidth,
    Events,
}

fn registry() -> Result<Registry> {
    let mut registry = Registry::default();
    registry.register(DirectFactory)?;
    registry.register(RejectFactory)?;
    registry.register(DnsFactory)?;
    registry.register_node(RedirectNodeFactory)?;
    registry.register_node(TproxyNodeFactory)?;
    #[cfg(feature = "protocol-tor")]
    registry.register(kerlico_tor::TorFactory)?;
    #[cfg(feature = "protocol-openconnect")]
    registry.register(kerlico_openconnect::OpenConnectFactory)?;
    #[cfg(feature = "protocol-tailscale")]
    registry.register(kerlico_tailscale::TailscaleFactory)?;
    #[cfg(feature = "protocol-wireguard")]
    {
        registry.register(kerlico_wireguard::WireGuardFactory)?;
        registry.register_node(kerlico_wireguard::WireGuardNodeFactory)?;
    }
    #[cfg(feature = "protocol-masque")]
    {
        registry.register(kerlico_masque::MasqueFactory)?;
        registry.register_node(kerlico_masque::MasqueNodeFactory)?;
    }
    #[cfg(feature = "protocol-openvpn")]
    registry.register(kerlico_openvpn::OpenVpnFactory)?;
    #[cfg(feature = "protocol-easytier")]
    registry.register(kerlico_easytier::EasyTierFactory)?;
    #[cfg(feature = "protocol-zerotier")]
    registry.register(kerlico_zerotier::ZeroTierFactory)?;
    #[cfg(feature = "protocol-tun")]
    registry.register_node(kerlico_tun::TunNodeFactory)?;
    #[cfg(feature = "protocol-vless")]
    registry.register(kerlico_vless::VlessFactory)?;
    #[cfg(feature = "protocol-vless")]
    registry.register_node(kerlico_vless::VlessNodeFactory)?;
    #[cfg(feature = "protocol-anytls")]
    {
        registry.register(kerlico_anytls::AnyTlsFactory)?;
        registry.register_node(kerlico_anytls::AnyTlsNodeFactory)?;
    }
    #[cfg(feature = "protocol-ss2022")]
    {
        registry.register(kerlico_ss2022::Ss2022Factory)?;
        registry.register_node(kerlico_ss2022::Ss2022NodeFactory)?;
    }
    #[cfg(feature = "protocol-socks")]
    {
        registry.register(kerlico_socks::SocksFactory)?;
        registry.register_node(kerlico_socks::SocksNodeFactory)?;
    }
    #[cfg(feature = "protocol-trojan")]
    {
        registry.register(kerlico_trojan::TrojanFactory)?;
        registry.register_node(kerlico_trojan::TrojanNodeFactory)?;
    }
    #[cfg(feature = "protocol-vmess")]
    {
        registry.register(kerlico_vmess::VmessFactory)?;
        registry.register_node(kerlico_vmess::VmessNodeFactory)?;
    }
    #[cfg(feature = "protocol-http")]
    {
        registry.register(kerlico_http::HttpFactory)?;
        registry.register_node(kerlico_http::HttpNodeFactory)?;
        registry.register_node(kerlico_http::MixedNodeFactory)?;
    }
    #[cfg(feature = "protocol-snell")]
    {
        registry.register(kerlico_snell::SnellFactory)?;
        registry.register_node(kerlico_snell::SnellNodeFactory)?;
    }
    #[cfg(feature = "protocol-tuic")]
    {
        registry.register(kerlico_tuic::TuicFactory)?;
        registry.register_node(kerlico_tuic::TuicNodeFactory)?;
    }
    #[cfg(feature = "protocol-hysteria2")]
    {
        registry.register(kerlico_hysteria2::Hysteria2Factory)?;
        registry.register_node(kerlico_hysteria2::Hysteria2NodeFactory)?;
    }
    #[cfg(feature = "protocol-ssh")]
    registry.register(kerlico_ssh::SshFactory)?;
    #[cfg(feature = "protocol-gost-relay")]
    registry.register(kerlico_gost_relay::GostRelayFactory)?;
    #[cfg(feature = "protocol-trusttunnel")]
    {
        registry.register(kerlico_trusttunnel::TrustTunnelFactory)?;
        registry.register_node(kerlico_trusttunnel::TrustTunnelNodeFactory)?;
    }
    #[cfg(feature = "protocol-naive")]
    {
        registry.register(kerlico_naive::NaiveFactory)?;
        registry.register_node(kerlico_naive::NaiveNodeFactory)?;
    }
    #[cfg(feature = "protocol-sudoku")]
    {
        registry.register(kerlico_sudoku::SudokuFactory)?;
        registry.register_node(kerlico_sudoku::SudokuNodeFactory)?;
    }
    #[cfg(feature = "protocol-shadowquic")]
    {
        registry.register(kerlico_shadowquic::ShadowQuicFactory)?;
        registry.register_node(kerlico_shadowquic::ShadowQuicNodeFactory)?;
    }
    #[cfg(feature = "protocol-hysteria1")]
    {
        registry.register(kerlico_hysteria1::Hysteria1Factory)?;
        registry.register_node(kerlico_hysteria1::Hysteria1NodeFactory)?;
    }
    #[cfg(feature = "protocol-shadowsocksr")]
    {
        registry.register(kerlico_shadowsocksr::ShadowsocksRFactory)?;
        registry.register_node(kerlico_shadowsocksr::ShadowsocksRNodeFactory)?;
    }
    #[cfg(feature = "protocol-shadowtls")]
    {
        registry.register(kerlico_shadowtls::ShadowTlsFactory)?;
        registry.register_node(kerlico_shadowtls::ShadowTlsNodeFactory)?;
    }
    #[cfg(feature = "protocol-mieru")]
    {
        registry.register(kerlico_mieru::MieruFactory)?;
        registry.register_node(kerlico_mieru::MieruNodeFactory)?;
    }
    #[cfg(feature = "protocol-shadowsocks")]
    {
        registry.register(kerlico_shadowsocks::ShadowsocksFactory)?;
        registry.register_node(kerlico_shadowsocks::ShadowsocksNodeFactory)?;
    }
    Ok(registry)
}

#[tokio::main]
async fn main() {
    let raw: Vec<_> = std::env::args_os().collect();
    let language = cli::language_from_args(&raw);
    let args = match cli::parse_args(&raw, language) {
        Ok(args) => args,
        Err(error) => {
            let rendered = cli::render_error(&error, language);
            if error.use_stderr() {
                eprint!("{rendered}");
            } else {
                print!("{rendered}");
            }
            std::process::exit(error.exit_code());
        }
    };
    let language = args.lang.map(Language::from).unwrap_or(language);
    if let Err(error) = execute(args, language).await {
        eprintln!("[{}] {}", error.code(), error.localized(language));
        std::process::exit(1);
    }
}

async fn execute(args: Args, language: Language) -> Result<()> {
    if let Command::Help { command } = &args.command {
        let mut help = cli::command(language);
        let target = if let Some(name) = command {
            help.find_subcommand_mut(name)
                .expect("帮助命令已通过参数校验")
        } else {
            &mut help
        };
        println!("{}", target.render_long_help());
        return Ok(());
    }
    let registry = registry()?;
    let (config, run) = match args.command {
        Command::History {
            directory,
            kind,
            user,
            node,
            outbound,
            since_ms,
            after,
            limit,
        } => {
            let user = user
                .map(|value| kerlico_core::UserId::parse(&value).map(|id| id.to_string()))
                .transpose()?;
            let node = node
                .map(|value| kerlico_core::NodeId::parse(&value).map(|id| id.to_string()))
                .transpose()?;
            let outbound = outbound
                .map(|value| kerlico_core::OutId::parse(&value).map(|id| id.to_string()))
                .transpose()?;
            let scope = if matches!(kind, HistoryKind::Flows | HistoryKind::Events) {
                None
            } else {
                match (&user, &node, &outbound) {
                    (None, None, None) => None,
                    (Some(user), None, None) => Some(kerlico_egress::HistoryScope::User(
                        kerlico_core::UserId::parse(user)?,
                    )),
                    (None, Some(node), None) => Some(kerlico_egress::HistoryScope::Node(
                        kerlico_core::NodeId::parse(node)?,
                    )),
                    (None, None, Some(outbound)) => Some(kerlico_egress::HistoryScope::Outbound(
                        kerlico_core::OutId::parse(outbound)?,
                    )),
                    _ => {
                        return Err(Error::Config(
                            "用量和带宽查询一次只可指定一个投影维度".into(),
                        ));
                    }
                }
            };
            if matches!(kind, HistoryKind::Usage) && (since_ms != 0 || after != 0 || limit != 1000)
            {
                return Err(Error::Config("累计用量不接受时间或分页参数".into()));
            }
            let history = kerlico_egress::HistoryReader::open(&directory)?;
            let result = match kind {
                HistoryKind::Usage => serde_json::to_value(history.usage_in(scope.as_ref())?),
                HistoryKind::Flows => {
                    serde_json::to_value(history.flows(&kerlico_egress::HistoryQuery {
                        user,
                        node,
                        outbound,
                        since_ms,
                        after,
                        limit,
                        ..Default::default()
                    })?)
                }
                HistoryKind::Events => {
                    serde_json::to_value(history.events(&kerlico_egress::HistoryQuery {
                        user,
                        node,
                        outbound,
                        since_ms,
                        after,
                        limit,
                        ..Default::default()
                    })?)
                }
                HistoryKind::Bandwidth => serde_json::to_value(history.bandwidth_in(
                    since_ms,
                    after,
                    limit,
                    scope.as_ref(),
                )?),
            }
            .map_err(|_| Error::Protocol("统计查询无法编码"))?;
            println!(
                "{}",
                serde_json::to_string_pretty(&result)
                    .map_err(|_| Error::Protocol("统计查询无法编码"))?
            );
            return Ok(());
        }
        Command::Help { .. } => unreachable!("帮助命令已处理"),
        Command::AccountNew { prefix } => {
            use std::io::Read;
            let mut password = Vec::new();
            std::io::stdin().take(1027).read_to_end(&mut password)?;
            if password.ends_with(b"\n") {
                password.pop();
                if password.ends_with(b"\r") {
                    password.pop();
                }
            }
            let account = kerlico_config::AccountSpec::create(&prefix, &password);
            password.fill(0);
            let account = account?;
            println!(
                "{}",
                serde_json::to_string_pretty(&account)
                    .map_err(|_| Error::Config("管理账户无法编码".into()))?
            );
            return Ok(());
        }
        Command::Modules => {
            for kind in registry.kinds() {
                println!("outbound/{kind}");
            }
            for kind in registry.node_kinds() {
                println!("inbound/{kind}");
            }
            return Ok(());
        }
        Command::Generate {
            target,
            length,
            hex,
            base64: _,
            months,
            domain,
            seed,
        } => {
            return run_generate(&target, length, hex, months, &domain, seed.as_deref());
        }
        Command::Tls {
            action,
            domain,
            months,
            cert,
        } => {
            return run_tls(&action, &domain, months, cert.as_deref());
        }
        Command::Xray {
            target,
            seed,
            domain,
            months,
        } => {
            return run_xray(&target, seed.as_deref(), &domain, months);
        }
        Command::Check { config } => (config, false),
        Command::Run { config } => (config, true),
    };
    let metadata = std::fs::metadata(&config)?;
    if metadata.len() > 1024 * 1024 {
        return Err(Error::Config("配置文件超过 1 MiB".into()));
    }
    let prepared = registry.prepare(parse(&std::fs::read(&config)?)?)?;
    if cfg!(not(feature = "warp")) && prepared.device().is_some() {
        return Err(Error::Config("此构建未启用 warp".into()));
    }
    if !run {
        println!(
            "{}",
            language.select("配置检查通过", "Configuration is valid")
        );
        return Ok(());
    }
    let device = Device::start(&prepared)?;
    let result = match device.lease(&prepared).await {
        Ok(lease) => serve(prepared, config, lease, language).await,
        Err(error) => Err(error),
    };
    let retired = device.shutdown().await;
    result.and(retired)
}

fn run_generate(
    target: &str,
    length: usize,
    hex: bool,
    months: u32,
    domain: &str,
    seed: Option<&str>,
) -> Result<()> {
    match target {
        "uuid" | "generate-uuid" => {
            println!("{}", kerlico_net::generate::generate_uuid());
        }
        "rand" | "generate-rand" => {
            if hex {
                println!("{}", kerlico_net::generate::generate_rand_hex(length));
            } else {
                println!("{}", kerlico_net::generate::generate_rand_base64(length));
            }
        }
        "rand-base64" | "generate-rand-base64" => {
            println!("{}", kerlico_net::generate::generate_rand_base64(length));
        }
        "rand-hex" | "generate-rand-hex" => {
            println!("{}", kerlico_net::generate::generate_rand_hex(length));
        }
        "reality-keypair"
        | "generate-reality-keypair"
        | "vless-x25519"
        | "generate-vless-x25519"
        | "x25519" => {
            let kp = kerlico_net::generate::generate_x25519_keypair(seed)?;
            println!("PrivateKey: {}", kp.private_key);
            println!("PublicKey: {}", kp.public_key);
            println!("Password: {}", kp.public_key);
            println!("Hash32: {}", kp.hash32);
        }
        "wg-keypair" | "generate-wg-keypair" | "wg" => {
            let kp = kerlico_net::generate::generate_x25519_keypair(seed)?;
            println!("PrivateKey: {}", kp.private_key_std);
            println!("PublicKey: {}", kp.public_key_std);
        }
        "ech-keypair" | "generate-ech-keypair" => {
            let kp = kerlico_net::generate::generate_ech_keypair(domain);
            println!("{}", kp.config_pem);
            println!("{}", kp.key_pem);
        }
        "tls-keypair" | "generate-tls-keypair" | "tls" => {
            let tls = kerlico_net::generate::generate_tls_keypair(domain, months);
            println!("{}", tls.cert_pem);
            println!("{}", tls.key_pem);
            println!("CertSHA256: {}", tls.cert_sha256_hex);
            println!("PublicKeySHA256: {}", tls.spki_sha256_hex);
        }
        "vless-mlkem768" | "generate-vless-mlkem768" | "mlkem768" => {
            let kp = kerlico_net::generate::generate_mlkem768(seed)?;
            println!("Seed: {}", kp.seed);
            println!("Client: {}", kp.client);
            println!("Hash32: {}", kp.hash32);
        }
        "mldsa65" => {
            let kp = kerlico_net::generate::generate_mldsa65(seed)?;
            println!("Seed: {}", kp.seed);
            println!("VerifyKey: {}", kp.verify_key);
        }
        "vlessenc" => {
            let out = kerlico_net::generate::generate_vlessenc()?;
            println!("Authentication: X25519");
            println!("decryption: {}", out.x25519_decryption);
            println!("encryption: {}", out.x25519_encryption);
            println!("Authentication: ML-KEM-768");
            println!("decryption: {}", out.mlkem768_decryption);
            println!("encryption: {}", out.mlkem768_encryption);
        }
        "sudoku-keypair" | "generate-sudoku-keypair" => {
            #[cfg(feature = "protocol-sudoku")]
            {
                let (priv_hex, pub_hex) = kerlico_sudoku::generate_keypair()?;
                println!("PrivateKey: {priv_hex}");
                println!("PublicKey: {pub_hex}");
            }
            #[cfg(not(feature = "protocol-sudoku"))]
            {
                let priv_hex = kerlico_net::generate::generate_rand_hex(64);
                let pub_hex = kerlico_net::generate::generate_rand_hex(32);
                println!("PrivateKey: {priv_hex}");
                println!("PublicKey: {pub_hex}");
            }
        }
        _ => return Err(Error::Config("未知的生成目标类型".into())),
    }
    Ok(())
}

fn run_tls(action: &str, domain: &str, months: u32, cert: Option<&str>) -> Result<()> {
    match action {
        "cert" => run_generate("tls-keypair", 32, false, months, domain, None),
        "hash" => {
            let hash = if let Some(pem_or_path) = cert {
                kerlico_net::generate::compute_tls_hash(pem_or_path)?
            } else {
                let generated = kerlico_net::generate::generate_tls_keypair(domain, months);
                kerlico_net::generate::compute_tls_hash(&generated.cert_pem)?
            };
            println!("SHA256Hex: {}", hash.cert_sha256_hex);
            println!("SHA256Base64: {}", hash.cert_sha256_base64);
            Ok(())
        }
        _ => Err(Error::Config(
            "未知的 TLS 子命令（支持 cert 与 hash）".into(),
        )),
    }
}

fn run_xray(target: &str, seed: Option<&str>, domain: &str, months: u32) -> Result<()> {
    match target {
        "uuid" | "x25519" | "wg" | "tls" | "mldsa65" | "mlkem768" | "vlessenc" => {
            run_generate(target, 32, false, months, domain, seed)
        }
        _ => Err(Error::Config("未知的 Xray 生成子命令".into())),
    }
}

async fn serve(
    prepared: kerlico_config::PreparedConfig,
    config_path: PathBuf,
    device: kerlico_core::DeviceLease,
    language: Language,
) -> Result<()> {
    let control = prepared.control().cloned();
    let engine =
        Engine::bind_with_options(prepared, kerlico_core::RuntimeOptions { device, language })
            .await?;
    for (tag, address) in engine.listeners()? {
        match language {
            Language::ZhCn => println!("入口 {tag} 已监听 {address}"),
            Language::En => println!("Inbound {tag} is listening on {address}"),
        }
    }
    let stop_control = CancellationToken::new();
    let control = match control {
        Some(spec) => {
            let server = kerlico_control::ControlServer::bind(&spec, &engine).await?;
            let address = server.local_addr()?;
            match language {
                Language::ZhCn => println!("控制接口已监听 {address}"),
                Language::En => println!("Control interface is listening on {address}"),
            }
            Some(tokio::spawn(server.serve(stop_control.clone())))
        }
        None => None,
    };
    let token = CancellationToken::new();
    let control_plane = engine.control_plane().clone();
    let running = engine.run(token.clone());
    tokio::pin!(running);
    #[cfg(unix)]
    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    let result = loop {
        #[cfg(unix)]
        tokio::select! {
            result = &mut running => break result,
            signal = shutdown_signal() => {
                signal?;
                token.cancel();
                break running.await;
            }
            _ = sighup.recv() => {
                if let Ok(bytes) = std::fs::read(&config_path)
                    && let Ok(parsed) = parse(&bytes)
                    && let Ok(reg) = registry()
                    && reg.prepare(parsed).is_ok()
                {
                    control_plane.record_config_reload(Some(config_path.display().to_string()));
                    control_plane.push_log("info", "SIGHUP 配置重载校验完成");
                } else {
                    control_plane.push_log("warning", "SIGHUP 配置重载校验失败");
                }
            }
        }
        #[cfg(not(unix))]
        tokio::select! {
            result = &mut running => break result,
            signal = shutdown_signal() => {
                let _ = (&config_path, &control_plane);
                signal?;
                token.cancel();
                break running.await;
            }
        }
    };
    stop_control.cancel();
    if let Some(control) = control {
        let _ = control.await;
    }
    result
}

/// 配置了 `device` 且有 `dual-stack` 本地出网时才持有 WARP 所有者，其余情况用原生设备。
struct Device {
    #[cfg(feature = "warp")]
    runtime: Option<kerlico_device::DeviceRuntime>,
}

impl Device {
    #[cfg(feature = "warp")]
    fn start(prepared: &kerlico_config::PreparedConfig) -> Result<Self> {
        let runtime = match prepared.device() {
            Some(spec) if prepared.device_requirements().auto_warp => {
                let directory = spec.state_directory.clone();
                let options = match spec.registration {
                    kerlico_config::DeviceRegistration::CreateOnce => {
                        kerlico_device::DeviceOptions::new(directory)
                    }
                    kerlico_config::DeviceRegistration::ExistingOnly => {
                        kerlico_device::DeviceOptions::existing(directory)
                    }
                };
                Some(kerlico_device::DeviceRuntime::start(options)?)
            }
            _ => None,
        };
        Ok(Self { runtime })
    }

    #[cfg(not(feature = "warp"))]
    fn start(_: &kerlico_config::PreparedConfig) -> Result<Self> {
        Ok(Self {})
    }

    async fn lease(
        &self,
        prepared: &kerlico_config::PreparedConfig,
    ) -> Result<kerlico_core::DeviceLease> {
        #[cfg(feature = "warp")]
        if let Some(runtime) = &self.runtime {
            return runtime.prepare(prepared.device_requirements()).await;
        }
        let _ = prepared;
        Ok(kerlico_net::native_device())
    }

    async fn shutdown(self) -> Result<()> {
        #[cfg(feature = "warp")]
        if let Some(runtime) = self.runtime {
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
            let report = runtime.shutdown_at(deadline).await;
            if !report.is_clean() {
                return Err(Error::Protocol("设备回收未干净完成"));
            }
        }
        Ok(())
    }
}

async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {result=tokio::signal::ctrl_c()=>result?,_=terminate.recv()=>{}}
        Ok(())
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
        Ok(())
    }
}
