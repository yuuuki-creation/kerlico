//! 运行期只读 HTTP 控制接口：健康状态、用量、在线来源、访问记录和入口计数。
use bytes::Bytes;
use http_body_util::Full;
use hyper::{
    Method, Request, Response, StatusCode, body::Incoming, header, server::conn::http1,
    service::service_fn,
};
use hyper_util::rt::TokioIo;
use kerlico_config::ControlSpec;
use kerlico_core::{CancellationToken, Error, Result};
use kerlico_egress::{StoredFlow, Telemetry};
use kerlico_engine::{Engine, FailedNodes, Stats};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};
use tokio::{net::TcpListener, task::JoinSet};

const MAX_CONNECTIONS: usize = 64;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

struct Source {
    secret: Option<String>,
    telemetry: Telemetry,
    stats: Arc<Stats>,
    nodes: BTreeMap<String, Arc<Stats>>,
    failed: FailedNodes,
}

pub struct ControlServer {
    listener: TcpListener,
    source: Arc<Source>,
}

impl ControlServer {
    pub async fn bind(spec: &ControlSpec, engine: &Engine) -> Result<Self> {
        Ok(Self {
            listener: TcpListener::bind(spec.listen).await?,
            source: Arc::new(Source {
                secret: spec.secret.clone(),
                telemetry: engine.telemetry(),
                stats: engine.stats(),
                nodes: engine.node_stats(),
                failed: engine.failed_nodes(),
            }),
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    pub async fn serve(self, cancel: CancellationToken) {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                biased;
                _ = cancel.cancelled() => break,
                accepted = self.listener.accept() => {
                    let stream = match accepted {
                        Ok((stream, _)) => stream,
                        Err(_) => {
                            tokio::time::sleep(ACCEPT_BACKOFF).await;
                            continue;
                        }
                    };
                    while connections.try_join_next().is_some() {}
                    if connections.len() >= MAX_CONNECTIONS {
                        continue;
                    }
                    let source = self.source.clone();
                    connections.spawn(async move {
                        let service = service_fn(move |request| {
                            let source = source.clone();
                            async move { Ok::<_, std::convert::Infallible>(respond(&source, &request)) }
                        });
                        let _ = tokio::time::timeout(
                            CONNECTION_TIMEOUT,
                            http1::Builder::new().serve_connection(TokioIo::new(stream), service),
                        )
                        .await;
                    });
                }
            }
        }
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
}

fn authorized(secret: Option<&str>, header: Option<&[u8]>) -> bool {
    let Some(secret) = secret else {
        return true;
    };
    let Some(provided) = header.and_then(|value| value.strip_prefix(b"Bearer ")) else {
        return false;
    };
    provided.len() == secret.len()
        && provided
            .iter()
            .zip(secret.as_bytes())
            .fold(0, |difference, (a, b)| difference | (a ^ b))
            == 0
}

fn stats_json(stats: &Stats) -> Value {
    json!({
        "accepted": stats.accepted.load(Ordering::Relaxed),
        "completed": stats.completed.load(Ordering::Relaxed),
        "failed": stats.failed.load(Ordering::Relaxed),
        "dropped": stats.dropped.load(Ordering::Relaxed),
        "forced_cleanup": stats.forced_cleanup.load(Ordering::Relaxed),
        "history_failures": stats.history_failures.load(Ordering::Relaxed),
    })
}

fn query_number(query: &str, name: &str) -> Option<u64> {
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .find(|(key, _)| *key == name)
        .and_then(|(_, value)| value.parse().ok())
}

fn route(source: &Source, path: &str, query: &str) -> Result<Option<Value>> {
    Ok(Some(match path {
        "/v1/health" => {
            let failed = source.failed.tags();
            json!({
                "status": if failed.is_empty() { "ok" } else { "degraded" },
                "run": source.telemetry.run_id().to_string(),
                "failed_nodes": failed,
            })
        }
        "/v1/usage" => {
            let usage = source.telemetry.usage()?;
            json!({
                "engine": usage.engine,
                "users": usage.users.iter().map(|(id, usage)| (id.to_string(), *usage)).collect::<BTreeMap<_, _>>(),
                "nodes": usage.nodes.iter().map(|(id, usage)| (id.to_string(), *usage)).collect::<BTreeMap<_, _>>(),
                "outbounds": usage.outbounds.iter().map(|(id, usage)| (id.to_string(), *usage)).collect::<BTreeMap<_, _>>(),
                "active_flows": usage.active_flows,
                "retained_records": usage.retained_records,
                "evicted_records": usage.evicted_records,
            })
        }
        "/v1/online" => json!(source.telemetry.online()?),
        "/v1/flows" => {
            let after = query_number(query, "after").unwrap_or(0);
            let limit = query_number(query, "limit").unwrap_or(1000);
            let records = source.telemetry.records(
                after,
                usize::try_from(limit).map_err(|_| Error::ResourceLimit)?,
            )?;
            json!(
                records
                    .iter()
                    .map(|record| StoredFlow::from_record(record, true))
                    .collect::<Vec<_>>()
            )
        }
        "/v1/stats" => json!({
            "engine": stats_json(&source.stats),
            "nodes": source.nodes.iter().map(|(tag, stats)| (tag.clone(), stats_json(stats))).collect::<BTreeMap<_, _>>(),
        }),
        _ => return Ok(None),
    }))
}

fn respond(source: &Source, request: &Request<Incoming>) -> Response<Full<Bytes>> {
    let reply = |status: StatusCode, body: Value| {
        Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body.to_string())))
            .expect("固定响应头合法")
    };
    if !authorized(
        source.secret.as_deref(),
        request
            .headers()
            .get(header::AUTHORIZATION)
            .map(|value| value.as_bytes()),
    ) {
        return reply(StatusCode::UNAUTHORIZED, json!({"error": "unauthorized"}));
    }
    if request.method() != Method::GET {
        return reply(
            StatusCode::METHOD_NOT_ALLOWED,
            json!({"error": "method not allowed"}),
        );
    }
    let uri = request.uri();
    match route(source, uri.path(), uri.query().unwrap_or("")) {
        Ok(Some(body)) => reply(StatusCode::OK, body),
        Ok(None) => reply(StatusCode::NOT_FOUND, json!({"error": "not found"})),
        Err(error) => reply(StatusCode::BAD_REQUEST, json!({"error": error.code()})),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_secret_must_match_exactly() {
        assert!(authorized(None, None));
        assert!(authorized(Some("abc"), Some(b"Bearer abc")));
        assert!(!authorized(Some("abc"), None));
        assert!(!authorized(Some("abc"), Some(b"Bearer abd")));
        assert!(!authorized(Some("abc"), Some(b"Bearer abcd")));
        assert!(!authorized(Some("abc"), Some(b"abc")));
    }

    #[test]
    fn query_numbers_ignore_other_keys() {
        assert_eq!(query_number("after=5&limit=9", "limit"), Some(9));
        assert_eq!(query_number("limit=x", "limit"), None);
        assert_eq!(query_number("", "limit"), None);
    }
}
