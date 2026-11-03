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
        Command::Check { config } => (config, false),
        Command::Run { config } => (config, true),
    };
    let metadata = std::fs::metadata(&config)?;
    if metadata.len() > 1024 * 1024 {
        return Err(Error::Config("配置文件超过 1 MiB".into()));
    }
    let prepared = registry.prepare(parse(&std::fs::read(config)?)?)?;
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
        Ok(lease) => serve(prepared, lease, language).await,
        Err(error) => Err(error),
    };
    let retired = device.shutdown().await;
    result.and(retired)
}

async fn serve(
    prepared: kerlico_config::PreparedConfig,
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
    let running = engine.run(token.clone());
    tokio::pin!(running);
    let result = tokio::select! {
        result=&mut running=>result,
        signal=shutdown_signal()=>{signal?;token.cancel();running.await},
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
