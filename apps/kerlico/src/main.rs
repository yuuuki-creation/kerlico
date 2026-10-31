use clap::{Parser, Subcommand};
use kerlico_config::{Registry, parse};
use kerlico_core::{CancellationToken, Error, Result};
use kerlico_engine::Engine;
use kerlico_net::{DirectFactory, RejectFactory};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "kerlico", version, about = "模块化代理内核")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
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

fn registry() -> Result<Registry> {
    let mut registry = Registry::default();
    registry.register(DirectFactory)?;
    registry.register(RejectFactory)?;
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
    if let Err(error) = execute().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

async fn execute() -> Result<()> {
    let args = Args::parse();
    let registry = registry()?;
    let (config, run) = match args.command {
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
    if !run {
        println!("配置检查通过");
        return Ok(());
    }
    let engine = Engine::bind(prepared).await?;
    for (tag, address) in engine.listeners()? {
        println!("入口 {tag} 已监听 {address}");
    }
    let token = CancellationToken::new();
    let running = engine.run(token.clone());
    tokio::pin!(running);
    tokio::select! {
        result=&mut running=>result,
        signal=shutdown_signal()=>{signal?;token.cancel();running.await},
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
