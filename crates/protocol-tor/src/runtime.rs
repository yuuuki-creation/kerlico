use crate::{
    error::Failure,
    network::{CarrierProvider, CarrierRoute},
    storage::StateLease,
};
use futures::{
    future::FutureObj,
    task::{Spawn, SpawnError},
};
use kerlico_core::{BoxFuture, CancellationToken, DialerOptions, Error, Result, ServiceContext};
use std::{
    future::Future,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{sync::watch, time::Instant};
use tor_rtcompat::{Blocking, CompoundRuntime, tokio::TokioRustlsRuntime};

pub(crate) type TorRuntime = CompoundRuntime<
    TaskOwner,
    TokioRustlsRuntime,
    TokioRustlsRuntime,
    CarrierProvider,
    CarrierProvider,
    TokioRustlsRuntime,
    CarrierProvider,
>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Status {
    Bootstrapping,
    Ready,
    Failed(Failure),
    Closing,
}

struct Owner {
    host: ServiceContext,
    executor: tokio::runtime::Handle,
    storage: Mutex<Option<Arc<StateLease>>>,
    status: watch::Sender<Status>,
    shutdown_timeout: Duration,
    shutdown_deadline: Mutex<Option<Instant>>,
}

#[derive(Clone)]
pub(crate) struct TaskOwner(Arc<Owner>);

impl TaskOwner {
    pub fn new(
        host: ServiceContext,
        storage: Arc<StateLease>,
        shutdown_timeout: Duration,
    ) -> Result<Self> {
        let executor = tokio::runtime::Handle::try_current()
            .map_err(|_| Error::Protocol("Tor需要运行中的Tokio执行器"))?;
        let (status, _) = watch::channel(Status::Bootstrapping);
        Ok(Self(Arc::new(Owner {
            host,
            executor,
            storage: Mutex::new(Some(storage)),
            status,
            shutdown_timeout,
            shutdown_deadline: Mutex::new(None),
        })))
    }

    pub fn runtime(&self, carrier_timeout: Duration, dialer: DialerOptions) -> Result<TorRuntime> {
        let route = if dialer.is_default() {
            CarrierRoute::Device(
                self.0
                    .host
                    .device()
                    .ok_or(Error::Unsupported("Tor出站需要设备TCP连接能力"))?,
            )
        } else {
            CarrierRoute::Dialer(dialer)
        };
        if rustls::crypto::CryptoProvider::get_default().is_none() {
            let _ = rustls::crypto::ring::default_provider().install_default();
        }
        let base =
            TokioRustlsRuntime::current().map_err(|_| Error::Protocol("Tor运行环境不可用"))?;
        let carrier =
            CarrierProvider::new(route, self.cancel(), self.0.host.status(), carrier_timeout);
        Ok(CompoundRuntime::new(
            self.clone(),
            base.clone(),
            base.clone(),
            carrier.clone(),
            carrier.clone(),
            base,
            carrier,
        ))
    }

    pub fn cancel(&self) -> CancellationToken {
        self.0.host.cancel()
    }

    pub fn check(&self) -> Result<()> {
        self.0.host.check()?;
        match *self.0.status.borrow() {
            Status::Failed(failure) => return Err(failure.error()),
            Status::Closing => return Err(Error::Cancelled),
            _ => {}
        }
        if self.cancel().is_cancelled() {
            Err(Error::Cancelled)
        } else {
            Ok(())
        }
    }

    pub fn lease(&self) -> Result<Arc<StateLease>> {
        self.check()?;
        self.0
            .storage
            .lock()
            .map_err(|_| Error::Protocol("Tor状态所有者已损坏"))?
            .clone()
            .ok_or(Error::Cancelled)
    }

    pub fn ready(&self) {
        self.0.status.send_if_modified(|status| {
            if *status == Status::Bootstrapping {
                *status = Status::Ready;
                true
            } else {
                false
            }
        });
    }

    pub fn fail(&self, failure: Failure) {
        self.0.host.fail(failure.service_failure());
        self.0.status.send_if_modified(|status| {
            if matches!(status, Status::Failed(_)) {
                false
            } else {
                *status = Status::Failed(failure);
                true
            }
        });
    }

    pub fn close(&self) {
        self.0.status.send_if_modified(|status| {
            if matches!(status, Status::Failed(_) | Status::Closing) {
                false
            } else {
                *status = Status::Closing;
                true
            }
        });
        self.0.host.cancel().cancel();
    }

    pub async fn wait_ready(&self) -> Result<()> {
        let mut status = self.0.status.subscribe();
        let cancel = self.cancel();
        loop {
            self.check()?;
            if *status.borrow_and_update() == Status::Ready {
                return Ok(());
            }
            tokio::select! {
                biased;
                _ = cancel.cancelled() => { self.check()?; return Err(Error::Cancelled); }
                changed = status.changed() => changed.map_err(|_| Error::Protocol("Tor启动状态已关闭"))?,
            }
        }
    }

    pub async fn shutdown(&self) -> Result<()> {
        let deadline = {
            let mut deadline = self
                .0
                .shutdown_deadline
                .lock()
                .map_err(|_| Error::Protocol("Tor关闭状态已损坏"))?;
            *deadline.get_or_insert_with(|| Instant::now() + self.0.shutdown_timeout)
        };
        self.close();
        let report = self.0.host.shutdown(deadline).await;
        if report.timed_out {
            return Err(Error::Timeout);
        }
        if report.failed_tasks != 0 {
            return Err(Error::Protocol("Tor后台任务异常退出"));
        }
        self.0
            .storage
            .lock()
            .map_err(|_| Error::Protocol("Tor状态所有者已损坏"))?
            .take();
        Ok(())
    }
}

impl Spawn for TaskOwner {
    fn spawn_obj(&self, future: FutureObj<'static, ()>) -> std::result::Result<(), SpawnError> {
        let lease = self.lease().map_err(|_| SpawnError::shutdown())?;
        let cancel = self.cancel();
        self.0
            .host
            .spawn(async move {
                let _lease = lease;
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => {}
                    () = future => {}
                }
            })
            .map_err(|_| SpawnError::shutdown())
    }
}

impl Blocking for TaskOwner {
    type ThreadHandle<T: Send + 'static> = BoxFuture<'static, T>;

    fn spawn_blocking<F, T>(&self, callback: F) -> Self::ThreadHandle<T>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let Ok(lease) = self.lease() else {
            return Box::pin(std::future::pending());
        };
        let (send, receive) = tokio::sync::oneshot::channel();
        let task = self.0.host.spawn_blocking_tracked(move || {
            let _lease = lease;
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(callback)) {
                Ok(output) => {
                    let _ = send.send(Ok(output));
                }
                Err(payload) => {
                    let _ = send.send(Err(payload));
                    panic!("Tor阻塞任务异常退出");
                }
            }
        });
        Box::pin(async move {
            let Ok(_task) = task else {
                return std::future::pending().await;
            };
            match receive.await {
                Ok(Ok(output)) => output,
                Ok(Err(payload)) => std::panic::resume_unwind(payload),
                Err(_) => std::future::pending().await,
            }
        })
    }

    fn reenter_block_on<F>(&self, future: F) -> F::Output
    where
        F: Future,
        F::Output: Send + 'static,
    {
        self.0.executor.block_on(future)
    }
}

pub(crate) struct StartupGuard(pub Option<ServiceContext>);
impl Drop for StartupGuard {
    fn drop(&mut self) {
        if let Some(host) = &self.0 {
            host.cancel().cancel();
        }
    }
}
