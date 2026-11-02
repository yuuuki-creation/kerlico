use crate::{
    config::{Options, Prepared},
    error::Failure,
    runtime::{StartupGuard, TaskOwner, TorRuntime},
    storage::StateLease,
    stream::TorStream,
};
use arti_client::{BootstrapBehavior, StreamPrefs, TorClient, TorClientBuilder};
use kerlico_config::{OutboundFactory, OutboundPlan};
use kerlico_core::{
    Address, BoxFuture, Capabilities, ConnectContext, DatagramChannel, Destination, Error,
    OpenedTcp, Outbound, Result, ServiceContext, TargetPolicy, TcpConnectInfo,
};
use serde_json::Value;
use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

const CAPABILITIES: Capabilities = Capabilities {
    tcp: true,
    tcp_eof: false,
    udp: false,
};

/// 原生Tor客户端TCP出站工厂，不提供入站、UDP或目标半关闭能力。
pub struct TorFactory;

struct TorOutbound {
    client: Mutex<Option<Arc<TorClient<TorRuntime>>>>,
    owner: TaskOwner,
}
impl Drop for TorOutbound {
    fn drop(&mut self) {
        self.owner.close();
    }
}

fn preferences(target: &Destination) -> StreamPrefs {
    let mut preferences = StreamPrefs::new();
    match target.address() {
        Address::Ip(IpAddr::V4(_)) => {
            preferences.ipv4_only();
        }
        Address::Ip(IpAddr::V6(_)) => {
            preferences.ipv6_only();
        }
        Address::Domain(_) => {
            preferences.ipv4_preferred();
        }
    }
    preferences
}

impl Outbound for TorOutbound {
    fn capabilities(&self) -> Capabilities {
        CAPABILITIES
    }

    fn shutdown(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            self.owner.close();
            self.client
                .lock()
                .map_err(|_| Error::Protocol("Tor客户端状态已损坏"))?
                .take();
            self.owner.shutdown().await
        })
    }

    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<OpenedTcp>> {
        Box::pin(async move {
            self.owner.check()?;
            let client = self
                .client
                .lock()
                .map_err(|_| Error::Protocol("Tor客户端状态已损坏"))?
                .clone()
                .ok_or(Error::Cancelled)?;
            let cancel = self.owner.cancel();
            context
                .run(async {
                    self.owner.wait_ready().await?;
                    let operation = async {
                        self.owner.check()?;
                        let isolated = client.isolated_client();
                        let host = target.host();
                        let stream = isolated
                            .connect_with_prefs(
                                (host.as_str(), target.port()),
                                &preferences(target),
                            )
                            .await
                            .map_err(|error| Failure::from_arti(&error).error())?;
                        self.owner.check()?;
                        let storage = self.owner.lease()?;
                        Ok(OpenedTcp {
                            stream: Box::new(TorStream::new(
                                stream,
                                self.owner.clone(),
                                storage,
                                context,
                            )),
                            info: TcpConnectInfo::unknown(),
                        })
                    };
                    tokio::select! {
                        biased;
                        _ = cancel.cancelled() => { self.owner.check()?; Err(Error::Cancelled) }
                        result = operation => result,
                    }
                })
                .await
        })
    }

    fn connect_udp<'a>(
        &'a self,
        _: &'a Destination,
        _: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async { Err(Error::Unsupported("Tor客户端只提供TCP出站")) })
    }
}

async fn start(prepared: Prepared, host: ServiceContext) -> Result<Arc<dyn Outbound>> {
    start_with_builder(prepared, host, |builder| builder).await
}

pub(crate) async fn start_with_builder<F>(
    prepared: Prepared,
    host: ServiceContext,
    configure: F,
) -> Result<Arc<dyn Outbound>>
where
    F: FnOnce(TorClientBuilder<TorRuntime>) -> TorClientBuilder<TorRuntime> + Send + 'static,
{
    let mut guard = StartupGuard(Some(host.clone()));
    let cancel = host.cancel();
    let id = host.id().clone();
    let directory = prepared.data_directory;
    let storage_task = host.spawn_blocking_tracked(move || StateLease::open(&directory, &id))?;
    let storage = tokio::select! {
        biased;
        _ = cancel.cancelled() => return Err(Error::Cancelled),
        result = storage_task => Arc::new(result??),
    };
    let owner = TaskOwner::new(host.clone(), storage.clone(), prepared.shutdown_timeout)?;
    let runtime = owner.runtime(prepared.carrier_timeout)?;
    let fatal_owner = owner.clone();
    let client_task = host.spawn_blocking_tracked(move || {
        let config = storage.config()?;
        let builder = TorClient::with_runtime(runtime)
            .config(config)
            .bootstrap_behavior(BootstrapBehavior::Manual)
            .local_resource_timeout(Duration::ZERO)
            .protocol_shutdown_handler(move |_| fatal_owner.fail(Failure::Deprecated));
        configure(builder)
            .create_unbootstrapped()
            .map_err(|error| Failure::from_arti(&error).error())
    })?;
    let client = tokio::select! {
        biased;
        _ = cancel.cancelled() => return Err(Error::Cancelled),
        result = client_task => result??,
    };
    let bootstrap_client = client.clone();
    let bootstrap_owner = owner.clone();
    let bootstrap_deadline = tokio::time::Instant::now() + prepared.bootstrap_timeout;
    host.spawn(async move {
        let cancel = bootstrap_owner.cancel();
        tokio::select! {
            biased;
            _ = cancel.cancelled() => {}
            result = tokio::time::timeout_at(bootstrap_deadline, bootstrap_client.bootstrap()) => {
                match result {
                    Ok(Ok(())) => bootstrap_owner.ready(),
                    Ok(Err(error)) => bootstrap_owner.fail(Failure::from_arti(&error)),
                    Err(_) => bootstrap_owner.fail(Failure::Timeout),
                }
            }
        }
    })?;
    guard.0 = None;
    Ok(Arc::new(TorOutbound {
        client: Mutex::new(Some(client)),
        owner,
    }))
}

impl OutboundFactory for TorFactory {
    fn kind(&self) -> &'static str {
        "tor"
    }

    fn compile(&self, options: &Value) -> Result<OutboundPlan> {
        let options: Options = serde_json::from_value(options.clone())
            .map_err(|_| Error::Config("Tor出站字段不合法".into()))?;
        let prepared = options.prepare()?;
        Ok(OutboundPlan::new(
            CAPABILITIES,
            false,
            TargetPolicy::Remote,
            move |host| Box::pin(start(prepared, host)),
        ))
    }
}
