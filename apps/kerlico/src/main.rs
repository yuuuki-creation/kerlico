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
    /// 列出当前构建真实注册的出站模块。
    Modules,
    /// 校验配置和模块能力，不监听或拨号。
    Check {
        #[arg(short, long)]
        config: PathBuf,
    },
    /// 启动固定目标的回环 TCP/UDP 转发入口。
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
                println!("{kind}");
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
