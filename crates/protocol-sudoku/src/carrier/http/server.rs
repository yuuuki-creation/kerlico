use super::{body::Body, codec::Mode, pull, query, session::Registry};
use crate::{
    carrier::ws::{self, WsIo},
    config::CarrierMode,
    handshake::EarlyServer,
    wire::kip,
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use bytes::Bytes;
use http::{Method, Request, Response, StatusCode, Version};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use kerlico_core::{BoxFuture, BoxStream, Error, Result, StreamLease};
use std::{sync::Arc, time::Duration};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{handshake::derive_accept_key, protocol::Role},
};

pub(crate) type UpgradedHandler = Arc<
    dyn Fn(BoxStream, Option<EarlyServer>, StreamLease) -> BoxFuture<'static, ()> + Send + Sync,
>;
pub(crate) type CoverHandler =
    Arc<dyn Fn(Method) -> BoxFuture<'static, Response<Body>> + Send + Sync>;
pub(crate) struct Handler {
    pub registry: Arc<Registry>,
    pub mode: CarrierMode,
    pub root: String,
    pub upgraded: UpgradedHandler,
    pub cover: Option<CoverHandler>,
}
pub(crate) fn response(status: StatusCode, bytes: impl Into<Bytes>) -> Response<Body> {
    let mut response = Response::new(Body::full(bytes));
    *response.status_mut() = status;
    response.headers_mut().insert(
        http::header::CACHE_CONTROL,
        http::HeaderValue::from_static("no-store"),
    );
    response
}
fn header<'a>(request: &'a Request<Incoming>, name: &str) -> Option<&'a str> {
    request.headers().get(name).and_then(|v| v.to_str().ok())
}
fn contains(request: &Request<Incoming>, name: &str, expected: &str) -> bool {
    request.headers().get_all(name).iter().any(|value| {
        value.to_str().ok().is_some_and(|value| {
            value.split(',').any(|word| word.trim().eq_ignore_ascii_case(expected))
        })
    })
}

impl Handler {
    pub async fn handle(&self, request: Request<Incoming>) -> Response<Body> {
        let permit = match self.registry.requests.clone().try_acquire_owned() {
            Ok(value) => value,
            Err(_) => return response(StatusCode::SERVICE_UNAVAILABLE, Bytes::new()),
        };
        if let Some(cover) = self.cover.as_ref() {
            let safe = matches!(*request.method(), Method::GET | Method::HEAD)
                && !request.headers().contains_key("x-sudoku-tunnel")
                && !request.headers().contains_key("upgrade")
                && !request
                    .headers()
                    .contains_key(http::header::TRANSFER_ENCODING)
                && request
                    .headers()
                    .get(http::header::CONTENT_LENGTH)
                    .is_none_or(|v| v.as_bytes() == b"0");
            if safe {
                let h1 = request.version() != Version::HTTP_2;
                let mut reply = cover(request.method().clone()).await;
                if h1 {
                    reply.headers_mut().insert(
                        http::header::CONNECTION,
                        http::HeaderValue::from_static("close"),
                    );
                }
                reply.body_mut()._request = Some(permit);
                return reply;
            }
        }
        let result = self.route(request).await;
        let mut response = match result {
            Ok(response) => response,
            Err(Error::ResourceLimit) => response(StatusCode::SERVICE_UNAVAILABLE, Bytes::new()),
            Err(Error::Rejected) => response(StatusCode::NOT_FOUND, Bytes::new()),
            Err(_) => response(StatusCode::BAD_REQUEST, Bytes::new()),
        };
        response.body_mut()._request = Some(permit);
        response
    }
    async fn route(&self, mut request: Request<Incoming>) -> Result<Response<Body>> {
        let path = request
            .uri()
            .path()
            .strip_prefix(&self.root)
            .ok_or(Error::Rejected)?
            .to_owned();
        if !path.starts_with('/') {
            return Err(Error::Rejected);
        }
        let query = query::parse(request.uri().query())?;
        let ws_upgrade = contains(&request, "upgrade", "websocket");
        if ws_upgrade {
            if !matches!(self.mode, CarrierMode::Ws | CarrierMode::Auto) || path != "/ws" {
                return Err(Error::Rejected);
            }
            return self.websocket(request, query).await;
        }
        let mode = match header(&request, "x-sudoku-tunnel") {
            Some("stream") if matches!(self.mode, CarrierMode::Stream | CarrierMode::Auto) => {
                Mode::Stream
            }
            Some("poll") if matches!(self.mode, CarrierMode::Poll | CarrierMode::Auto) => {
                Mode::Poll
            }
            _ => return Err(Error::Rejected),
        };
        match (request.method(), path.as_str()) {
            (&Method::GET, "/session") => {
                let early = query
                    .get("ed")
                    .map(|value| URL_SAFE_NO_PAD.decode(value).map_err(|_| crate::invalid()))
                    .transpose()?;
                let authorized = self.registry.authorize(mode, early.as_deref())?;
                let mut body = format!("token={}\n", authorized.token.value);
                if let Some(early) = authorized.early_response {
                    body.push_str(&format!("ed={}\n", URL_SAFE_NO_PAD.encode(early)));
                }
                body.push_str("cap=upload-seq");
                let mut reply = response(StatusCode::OK, body);
                reply.headers_mut().insert(
                    http::header::CONTENT_TYPE,
                    http::HeaderValue::from_static("application/octet-stream"),
                );
                Ok(reply)
            }
            (&Method::GET, "/stream") => {
                let token = self
                    .registry
                    .get(query.get("token").map_or("", String::as_str), mode)
                    .ok_or(Error::Rejected)?;
                let mut reply = Response::new(pull::start(token, &self.registry.scope));
                reply.headers_mut().insert(
                    http::header::CONTENT_TYPE,
                    http::HeaderValue::from_static(if mode == Mode::Poll {
                        "text/plain"
                    } else {
                        "application/octet-stream"
                    }),
                );
                reply.headers_mut().insert(
                    http::header::CACHE_CONTROL,
                    http::HeaderValue::from_static("no-store"),
                );
                reply.headers_mut().insert(
                    http::header::TRAILER,
                    http::HeaderValue::from_static("x-sudoku-stream-eof"),
                );
                Ok(reply)
            }
            (&Method::POST, "/api/v1/upload") => {
                let token = self
                    .registry
                    .get(query.get("token").map_or("", String::as_str), mode)
                    .ok_or(Error::Rejected)?;
                if query.get("close").is_some_and(|v| v == "1") {
                    self.registry.remove(&token.value);
                    return Ok(response(StatusCode::OK, Bytes::new()));
                }
                if query.get("fin").is_some_and(|v| v == "1") {
                    token.fin().await?;
                    return Ok(response(StatusCode::OK, Bytes::new()));
                }
                let _inflight = token
                    .upload_requests
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| Error::ResourceLimit)?;
                let sequence = query
                    .get("seq")
                    .map(|value| value.parse::<u64>().map_err(|_| crate::invalid()))
                    .transpose()?
                    .unwrap_or(0);
                let bytes =
                    tokio::time::timeout(Duration::from_secs(20), read_upload(&mut request))
                        .await
                        .map_err(|_| Error::Timeout)??;
                let bytes = mode.decode_upload(&bytes)?;
                match token.push(sequence, Bytes::from(bytes)).await {
                    Ok(()) => Ok(response(StatusCode::OK, Bytes::new())),
                    Err(Error::Protocol(_)) => Ok(response(StatusCode::CONFLICT, Bytes::new())),
                    Err(_) => Ok(response(StatusCode::GONE, Bytes::new())),
                }
            }
            _ => Ok(response(StatusCode::METHOD_NOT_ALLOWED, Bytes::new())),
        }
    }
}

impl Handler {
    async fn websocket(
        &self,
        mut request: Request<Incoming>,
        query: std::collections::BTreeMap<String, String>,
    ) -> Result<Response<Body>> {
        if request.method() != Method::GET
            || request.version() != Version::HTTP_11
            || !contains(&request, "connection", "upgrade")
            || header(&request, "sec-websocket-version") != Some("13")
        {
            return Err(crate::invalid());
        }
        let key = header(&request, "sec-websocket-key")
            .ok_or_else(crate::invalid)?
            .to_owned();
        if STANDARD.decode(&key).map_err(|_| crate::invalid())?.len() != 16 {
            return Err(crate::invalid());
        }
        let auth = header(&request, "authorization")
            .or_else(|| query.get("auth").map(String::as_str))
            .unwrap_or("");
        if !ws::verify(&self.registry.protocol.material.seed, auth, kip::now()?) {
            return Err(Error::Rejected);
        }
        if request
            .headers()
            .contains_key(http::header::TRANSFER_ENCODING)
            || request
                .headers()
                .get(http::header::CONTENT_LENGTH)
                .is_some_and(|v| v.as_bytes() != b"0")
        {
            return Err(crate::invalid());
        }
        let prepared = query
            .get("ed")
            .map(|bytes| URL_SAFE_NO_PAD.decode(bytes).map_err(|_| crate::invalid()))
            .transpose()?
            .map(|bytes| EarlyServer::prepare(self.registry.protocol.clone(), &bytes))
            .transpose()?;
        let lease = self.registry.context.stream_budget.try_acquire()?;
        let upgrade = hyper::upgrade::on(&mut request);
        let callback = self.upgraded.clone();
        let cancel = self.registry.scope.cancel.clone();
        let mut reply = response(StatusCode::SWITCHING_PROTOCOLS, Bytes::new());
        reply.headers_mut().insert(
            http::header::CONNECTION,
            http::HeaderValue::from_static("upgrade"),
        );
        reply.headers_mut().insert(
            http::header::UPGRADE,
            http::HeaderValue::from_static("websocket"),
        );
        reply.headers_mut().insert(
            "sec-websocket-accept",
            http::HeaderValue::from_str(&derive_accept_key(key.as_bytes()))
                .map_err(|_| crate::invalid())?,
        );
        if let Some(prepared) = prepared.as_ref() {
            reply.headers_mut().insert(
                ws::EARLY,
                http::HeaderValue::from_str(&URL_SAFE_NO_PAD.encode(&prepared.response))
                    .map_err(|_| crate::invalid())?,
            );
        }
        self.registry.scope.spawn(async move {
            let upgraded=tokio::select!{biased;_=cancel.cancelled()=>return,result=upgrade=>match result{Ok(value)=>value,Err(_)=>return}};
            let socket=Box::new(TokioIo::new(upgraded)) as BoxStream;let stream=WebSocketStream::from_raw_socket(socket,Role::Server,Some(ws::config())).await;callback(Box::new(WsIo::new(stream)),prepared,lease).await;
        });
        Ok(reply)
    }
}

async fn read_upload(request: &mut Request<Incoming>) -> Result<Vec<u8>> {
    const MAX: usize = 1024 * 1024;
    if header(request, "content-length")
        .and_then(|v| v.parse::<usize>().ok())
        .is_some_and(|size| size > MAX)
    {
        return Err(Error::ResourceLimit);
    }
    let mut bytes = Vec::new();
    while let Some(frame) = request.body_mut().frame().await {
        let frame = frame.map_err(|_| crate::invalid())?;
        if let Ok(data) = frame.into_data() {
            if bytes.len().saturating_add(data.len()) > MAX {
                return Err(Error::ResourceLimit);
            }
            bytes.extend_from_slice(&data);
        }
    }
    Ok(bytes)
}
