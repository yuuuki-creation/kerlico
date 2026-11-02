use kerlico_core::{CancellationToken, Error, Result, ServiceContext, ServiceTask};
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};

pub(crate) struct Drivers {
    host: ServiceContext,
    cancel: CancellationToken,
    tasks: Mutex<Option<Vec<ServiceTask<()>>>>,
    drained: tokio::sync::Mutex<Option<bool>>,
}
impl Drivers {
    pub fn new(host: ServiceContext) -> Arc<Self> {
        Arc::new(Self {
            cancel: host.cancel().child_token(),
            host,
            tasks: Mutex::new(Some(Vec::new())),
            drained: tokio::sync::Mutex::new(None),
        })
    }
    pub fn cancel(&self) -> CancellationToken {
        self.cancel.clone()
    }
    pub fn spawn(&self, future: impl Future<Output = ()> + Send + 'static) -> Result<()> {
        let mut tasks = self
            .tasks
            .lock()
            .map_err(|_| Error::Protocol("SSH任务所有者已损坏"))?;
        let tasks = tasks.as_mut().ok_or(Error::Cancelled)?;
        if self.cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        tasks.retain(|task| !task.is_finished());
        tasks.push(self.host.spawn_tracked(future)?);
        Ok(())
    }
    pub async fn shutdown(&self) -> Result<()> {
        let mut drained = self.drained.lock().await;
        if let Some(failed) = *drained {
            return if failed {
                Err(Error::Protocol("SSH任务异常退出"))
            } else {
                Ok(())
            };
        }
        self.cancel.cancel();
        let tasks = self
            .tasks
            .lock()
            .map_err(|_| Error::Protocol("SSH任务所有者已损坏"))?
            .take()
            .unwrap_or_default();
        let mut failed = false;
        for task in tasks {
            failed |= task.await.is_err();
        }
        *drained = Some(failed);
        if failed {
            Err(Error::Protocol("SSH任务异常退出"))
        } else {
            Ok(())
        }
    }
}
impl russh_util::runtime::TaskSpawner for Drivers {
    fn spawn(
        &self,
        future: Pin<Box<dyn Future<Output = ()> + Send>>,
    ) -> std::result::Result<(), russh_util::runtime::SpawnRejected> {
        self.spawn(future)
            .map_err(|_| russh_util::runtime::SpawnRejected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::{
        io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
        net::{TcpListener, TcpStream},
        time::{Instant, timeout},
    };

    struct Handshake;
    impl russh::client::Handler for Handshake {
        type Error = russh::Error;
    }

    #[tokio::test]
    async fn forced_outer_kex_abort_keeps_real_actor_in_service_owner() {
        let host = ServiceContext::for_test();
        let drivers = Drivers::new(host.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socket = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (peer, _) = listener.accept().await.unwrap();
        let mut peer = BufReader::new(peer);
        let outer = host
            .spawn_tracked(russh_util::runtime::scope(drivers, async move {
                russh::client::connect_stream(
                    Arc::new(russh::client::Config::default()),
                    socket,
                    Handshake,
                )
                .await
            }))
            .unwrap();
        let mut banner = String::new();
        timeout(Duration::from_secs(1), peer.read_line(&mut banner))
            .await
            .unwrap()
            .unwrap();
        peer.get_mut()
            .write_all(b"SSH-2.0-synthetic-peer\r\n")
            .await
            .unwrap();
        timeout(Duration::from_secs(1), peer.read_u8())
            .await
            .unwrap()
            .unwrap();
        outer.abort();
        assert!(outer.await.is_err());
        let report = host
            .shutdown(Instant::now() + Duration::from_millis(300))
            .await;
        assert!(report.is_clean());
        assert!(report.forced_tasks >= 1);
        let mut bytes = Vec::new();
        let _ = timeout(Duration::from_secs(1), peer.read_to_end(&mut bytes))
            .await
            .unwrap();
    }

    #[tokio::test]
    #[allow(clippy::async_yields_async)]
    async fn nested_native_spawn_inherits_owner_and_releases_socket() {
        let host = ServiceContext::for_test();
        let drivers = Drivers::new(host.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socket = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (mut peer, _) = listener.accept().await.unwrap();
        let (started, ready) = tokio::sync::oneshot::channel();
        let outer = russh_util::runtime::scope(drivers, async move {
            russh_util::runtime::spawn(async move {
                let nested = russh_util::runtime::spawn(async move {
                    let mut socket = socket;
                    started.send(()).unwrap();
                    let _ = socket.read_u8().await;
                });
                let _ = nested.await;
            })
        })
        .await;
        ready.await.unwrap();
        drop(outer);
        let report = host
            .shutdown(Instant::now() + Duration::from_millis(300))
            .await;
        assert!(report.is_clean());
        assert!(report.forced_tasks >= 1);
        assert_eq!(
            timeout(Duration::from_secs(1), peer.read_u8())
                .await
                .unwrap()
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }

    #[tokio::test]
    #[allow(clippy::async_yields_async)]
    async fn closed_owner_rejects_native_spawn_without_running_it() {
        let host = ServiceContext::for_test();
        let drivers = Drivers::new(host.clone());
        drivers.shutdown().await.unwrap();
        let ran = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen = ran.clone();
        let task = russh_util::runtime::scope(drivers, async move {
            russh_util::runtime::spawn(async move {
                seen.store(true, std::sync::atomic::Ordering::Release);
            })
        })
        .await;
        assert!(task.await.is_err());
        assert!(!ran.load(std::sync::atomic::Ordering::Acquire));
        assert!(
            host.shutdown(Instant::now() + Duration::from_secs(1))
                .await
                .is_clean()
        );
    }
}
