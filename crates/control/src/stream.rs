//! 推送端点 `/traffic`、`/memory`、`/logs`、`/connections`：同一个生产者既写 WebSocket 文本帧，
//! 也写 HTTP 分块响应的 JSON 行（同 Mihomo）。生产者每次取当前代引擎的观测句柄，重载后继续推送。

use crate::Shared;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use hyper::body::{Body, Frame, SizeHint};
use hyper_util::rt::TokioIo;
use kerlico_core::{
    CancellationToken,
    log::{self, LogEvent, LogLevel},
};
use serde_json::{Value, json};
use std::{
    convert::Infallible,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::sync::{broadcast::error::RecvError, mpsc};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{Message, protocol::Role},
};
use tokio_util::task::TaskTracker;

const TICK: Duration = Duration::from_secs(1);
const MIN_CONNECTIONS_INTERVAL: Duration = Duration::from_millis(100);
const QUEUE: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Feed {
    /// 每秒一条 `{"up","down","upTotal","downTotal"}`，速率为上一秒的业务字节差。
    Traffic,
    Memory,
    Logs {
        level: LogLevel,
        structured: bool,
    },
    /// 每 `interval` 毫秒一份 `GET /connections` 快照，缺省 1000。
    Connections {
        interval: Duration,
    },
}

impl Feed {
    /// 只在 HTTP 请求上作推送的端点；`/connections` 不带升级时仍回单次快照。
    pub(crate) fn parse(path: &str, query: &str, websocket: bool) -> Option<Self> {
        let param = |name: &str| crate::query_str(query, name);
        match path {
            "/traffic" => Some(Self::Traffic),
            "/memory" => Some(Self::Memory),
            "/logs" => Some(Self::Logs {
                level: param("level")
                    .and_then(LogLevel::parse)
                    .unwrap_or(LogLevel::Info),
                structured: param("format") == Some("structured"),
            }),
            "/connections" if websocket => Some(Self::Connections {
                interval: param("interval")
                    .and_then(|raw| raw.parse().ok())
                    .map_or(TICK, Duration::from_millis)
                    .max(MIN_CONNECTIONS_INTERVAL),
            }),
            _ => None,
        }
    }

    /// 在后台生产 JSON 文本，接收端关闭或取消时停止。
    pub(crate) fn spawn(
        self,
        tasks: &TaskTracker,
        shared: Arc<Shared>,
        cancel: CancellationToken,
    ) -> mpsc::Receiver<String> {
        let (tx, rx) = mpsc::channel(QUEUE);
        tasks.spawn(async move {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => {}
                _ = self.produce(&shared, &tx) => {}
            }
        });
        rx
    }

    async fn produce(self, shared: &Shared, tx: &mpsc::Sender<String>) {
        match self {
            Self::Traffic => {
                let mut last = totals(shared);
                let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + TICK, TICK);
                loop {
                    ticker.tick().await;
                    let now = totals(shared);
                    let message = json!({
                        "up": now.0.saturating_sub(last.0),
                        "down": now.1.saturating_sub(last.1),
                        "upTotal": now.0,
                        "downTotal": now.1,
                    });
                    last = now;
                    if tx.send(message.to_string()).await.is_err() {
                        return;
                    }
                }
            }
            Self::Memory => {
                let mut ticker = tokio::time::interval(TICK);
                loop {
                    ticker.tick().await;
                    let message = json!({
                        "inuse": kerlico_egress::resident_memory_bytes(),
                        "oslimit": 0u64,
                    });
                    if tx.send(message.to_string()).await.is_err() {
                        return;
                    }
                }
            }
            Self::Logs { level, structured } => {
                let mut events = log::subscribe();
                loop {
                    let event = match events.recv().await {
                        Ok(event) => event,
                        Err(RecvError::Lagged(_)) => continue,
                        Err(RecvError::Closed) => return,
                    };
                    if level == LogLevel::Silent || event.level < level {
                        continue;
                    }
                    if tx
                        .send(log_json(&event, structured).to_string())
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
            Self::Connections { interval } => {
                let mut ticker = tokio::time::interval(interval);
                loop {
                    ticker.tick().await;
                    let snapshot = shared
                        .current()
                        .control_plane
                        .active_connections_json()
                        .unwrap_or(Value::Null);
                    if tx.send(snapshot.to_string()).await.is_err() {
                        return;
                    }
                }
            }
        }
    }
}

fn totals(shared: &Shared) -> (u64, u64) {
    shared.current().telemetry.usage().map_or((0, 0), |usage| {
        (usage.engine.upload_bytes, usage.engine.download_bytes)
    })
}

/// 缺省为 Mihomo 经典形状 `{"type","payload"}`；`format=structured` 时为 `{"time","level","message","fields"}`。
fn log_json(event: &LogEvent, structured: bool) -> Value {
    if structured {
        json!({
            "time": log::rfc3339_ms(event.time_ms),
            "level": event.level.as_str(),
            "message": event.payload,
            "fields": [],
        })
    } else {
        json!({"type": event.level.as_str(), "payload": event.payload})
    }
}

/// HTTP 分块响应体：每条 JSON 一行。
pub(crate) struct LineBody(pub(crate) mpsc::Receiver<String>);

impl Body for LineBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        self.0.poll_recv(cx).map(|line| {
            line.map(|mut line| {
                line.push('\n');
                Ok(Frame::data(Bytes::from(line)))
            })
        })
    }

    fn is_end_stream(&self) -> bool {
        false
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

/// 握手完成后的 WebSocket 会话：转发生产者的文本，读取并丢弃对端消息，对端关闭或取消时结束。
pub(crate) async fn serve_websocket(
    upgrade: hyper::upgrade::OnUpgrade,
    mut feed: mpsc::Receiver<String>,
    cancel: CancellationToken,
) {
    let Ok(upgraded) = upgrade.await else {
        return;
    };
    let mut socket =
        WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Server, None).await;
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            incoming = socket.next() => match incoming {
                Some(Ok(Message::Close(_))) | Some(Err(_)) | None => return,
                Some(Ok(_)) => {}
            },
            message = feed.recv() => match message {
                Some(text) => {
                    if socket.send(Message::text(text)).await.is_err() {
                        return;
                    }
                }
                None => break,
            },
        }
    }
    let _ = socket.close(None).await;
}
