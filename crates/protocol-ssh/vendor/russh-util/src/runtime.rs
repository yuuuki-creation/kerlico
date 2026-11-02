use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

/// 由宿主登记实际运行任务，拒绝登记时不得另起脱离所有者的任务。
pub trait TaskSpawner: Send + Sync {
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) -> Result<(), SpawnRejected>;
}

#[derive(Debug)]
pub struct SpawnRejected;

tokio::task_local! {
    static TASK_SPAWNER: Arc<dyn TaskSpawner>;
}

/// 使当前操作及其通过本模块创建的后代任务使用同一宿主。
pub async fn scope<F: Future>(spawner: Arc<dyn TaskSpawner>, future: F) -> F::Output {
    TASK_SPAWNER.scope(spawner, future).await
}

#[derive(Debug)]
pub struct JoinError;

impl std::fmt::Display for JoinError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "JoinError")
    }
}

impl std::error::Error for JoinError {}

pub struct JoinHandle<T>
where
    T: Send,
{
    handle: tokio::sync::oneshot::Receiver<T>,
    rejected: bool,
}

#[cfg(target_arch = "wasm32")]
macro_rules! spawn_impl {
    ($fn:expr) => {
        wasm_bindgen_futures::spawn_local($fn)
    };
}

#[cfg(not(target_arch = "wasm32"))]
macro_rules! spawn_impl {
    ($fn:expr) => {
        tokio::spawn($fn)
    };
}

pub fn spawn<F, T>(future: F) -> JoinHandle<T>
where
    F: Future<Output = T> + 'static + Send,
    T: Send + 'static,
{
    let (sender, receiver) = tokio::sync::oneshot::channel();
    let task = async {
        let result = future.await;
        let _ = sender.send(result);
    };
    let rejected = if let Ok(spawner) = TASK_SPAWNER.try_with(Arc::clone) {
        spawner.spawn(Box::pin(scope(spawner.clone(), task))).is_err()
    } else {
        spawn_impl!(task);
        false
    };
    JoinHandle { handle: receiver, rejected }
}

impl<T> Future for JoinHandle<T>
where
    T: Send,
{
    type Output = Result<T, JoinError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.rejected {
            return Poll::Ready(Err(JoinError));
        }
        match Pin::new(&mut self.handle).poll(cx) {
            Poll::Ready(Ok(val)) => Poll::Ready(Ok(val)),
            Poll::Ready(Err(_)) => Poll::Ready(Err(JoinError)),
            Poll::Pending => Poll::Pending,
        }
    }
}
