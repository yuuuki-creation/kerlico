//! The H3 authentication exchange and raw stream dispatch used by both Hy2 and VLESS.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request};
use tokio::sync::mpsc;
use tokio::time::timeout;

use crate::{auth, tcp::FRAME_TYPE};

mod congestion;
pub mod hop;
mod masked;
mod options;
mod socket;
pub use masked::MaskedSocket;
pub use options::{QuicCarrier, QuicOptions};
pub use socket::{block, endpoint, listen_socket, packet_endpoint, runtime, Duplex};

pub fn send_datagram(
    connection: &quinn::Connection,
    session: u32,
    packet: &AtomicU16,
    address: &str,
    payload: &[u8],
) -> io::Result<()> {
    use quinn::SendDatagramError;
    let Some(limit) = connection.max_datagram_size() else {
        return Ok(());
    };
    let id = || {
        packet
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| {
                Some(id.wrapping_add(1).max(1))
            })
            .expect("always advances the fragment ID")
    };
    let Ok(fragments) = crate::datagram::fragments(session, id, address, payload, limit) else {
        return Ok(());
    };
    for wire in fragments {
        match connection.send_datagram(wire.into()) {
            Ok(()) => (),
            Err(SendDatagramError::ConnectionLost(error)) => return Err(error.into()),
            Err(
                SendDatagramError::UnsupportedByPeer
                | SendDatagramError::Disabled
                | SendDatagramError::TooLarge,
            ) => return Ok(()),
        }
    }
    Ok(())
}

pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub type RequestStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type ResponseFuture = Pin<Box<dyn Future<Output = ()> + Send>>;
type Credentials<U> = dyn Fn(&[u8]) -> Option<U> + Send + Sync;
type Authenticated<U> = dyn Fn(&quinn::Connection, &U, u64) + Send + Sync;
type Fallback =
    dyn Fn(Request<()>, std::net::SocketAddr, RequestStream) -> ResponseFuture + Send + Sync;

pub struct Server<U> {
    pub authenticate: Arc<Credentials<U>>,
    pub on_authenticated: Arc<Authenticated<U>>,
    pub fallback: Arc<Fallback>,
    pub receive_rate: auth::ReceiveRate,
    pub udp: bool,
}

pub struct Tcp<U> {
    pub user: U,
    pub peer: std::net::SocketAddr,
    pub send: quinn::SendStream,
    pub recv: quinn::RecvStream,
}

impl<U: Clone + Send + Sync + 'static> Server<U> {
    pub async fn serve(
        self: Arc<Self>,
        connection: quinn::Connection,
        incoming: mpsc::Sender<Tcp<U>>,
    ) {
        let authenticated = Arc::new(OnceLock::new());
        let (http_requests, receiver) = mpsc::channel(128);
        let dispatch = tokio::spawn(dispatch(
            connection.clone(),
            incoming,
            http_requests,
            authenticated.clone(),
        ));
        let bidi = futures_util::stream::unfold(receiver, |mut receiver| async {
            receiver.recv().await.map(|streams| (Ok(streams), receiver))
        });
        let classified = h3_quinn::Connection::new_with_bidi_streams(connection.clone(), bidi);
        if let Ok(mut h3) = h3::server::Connection::new(classified).await {
            let peer = connection.remote_address();
            while let Ok(Some(request)) = h3.accept().await {
                let config = self.clone();
                let authenticated = authenticated.clone();
                let connection = connection.clone();
                tokio::spawn(async move {
                    let Ok(Ok((request, mut stream))) =
                        timeout(HANDSHAKE_TIMEOUT, request.resolve_request()).await
                    else {
                        return;
                    };
                    let mut accepted = false;
                    if let Some((password, rate)) = auth::credentials(&request) {
                        accepted = authenticated.get().is_some();
                        if !accepted {
                            if let Some(user) = (config.authenticate)(password) {
                                authenticated.get_or_init(|| {
                                    (config.on_authenticated)(&connection, &user, rate);
                                    user
                                });
                                accepted = true;
                            }
                        }
                    }
                    if accepted {
                        // The exchange only uses headers; do not consume a request body.
                        stream.stop_sending(h3::error::Code::H3_NO_ERROR);
                        let response = auth::padding().and_then(|padding| {
                            auth::response(config.udp, config.receive_rate)
                                .header(auth::PADDING, padding)
                                .header(http::header::DATE, date())
                                .body(())
                                .map_err(io::Error::other)
                        });
                        if let Ok(response) = response {
                            if stream.send_response(response).await.is_ok() {
                                let _ = stream.finish().await;
                            }
                        }
                    } else {
                        (config.fallback)(request, peer, stream).await;
                    }
                });
            }
        }
        dispatch.abort();
        connection.close(quinn::VarInt::from_u32(0x100), b"");
    }
}

pub fn date() -> http::HeaderValue {
    httpdate::fmt_http_date(std::time::SystemTime::now())
        .parse()
        .expect("HTTP date")
}

type Bidi = (quinn::SendStream, quinn::RecvStream, Bytes);

async fn dispatch<U: Clone + Send + Sync + 'static>(
    connection: quinn::Connection,
    incoming: mpsc::Sender<Tcp<U>>,
    h3: mpsc::Sender<Bidi>,
    authenticated: Arc<OnceLock<U>>,
) {
    let budget = Arc::new(tokio::sync::Semaphore::new(256));
    while let Ok((mut send, mut recv)) = connection.accept_bi().await {
        let incoming = incoming.clone();
        let h3 = h3.clone();
        let authenticated = authenticated.clone();
        let peer = connection.remote_address();
        let Ok(permit) = budget.clone().try_acquire_owned() else {
            let code = quinn::VarInt::from_u32(0x107);
            let _ = recv.stop(code);
            let _ = send.reset(code);
            continue;
        };
        tokio::spawn(async move {
            let _permit = permit;
            let Ok(Ok((kind, prefix))) = timeout(HANDSHAKE_TIMEOUT, classify(&mut recv)).await
            else {
                return;
            };
            if kind != FRAME_TYPE {
                let _ = h3.send((send, recv, prefix)).await;
            } else if let Some(user) = authenticated.get() {
                let _ = incoming
                    .send(Tcp {
                        user: user.clone(),
                        peer,
                        send,
                        recv,
                    })
                    .await;
            } else {
                let code = quinn::VarInt::from_u32(0x10e);
                let _ = recv.stop(code);
                let _ = send.reset(code);
            }
        });
    }
}

async fn classify(recv: &mut quinn::RecvStream) -> Result<(u64, Bytes), quinn::ReadExactError> {
    let mut bytes = [0; 8];
    recv.read_exact(&mut bytes[..1]).await?;
    let len = 1 << (bytes[0] >> 6);
    recv.read_exact(&mut bytes[1..len]).await?;
    let prefix = Bytes::copy_from_slice(&bytes[..len]);
    let kind = crate::read_varint(prefix.as_ref()).expect("full QUIC varint");
    Ok((kind, prefix))
}

pub fn request(password: &str, receive_rate: u64) -> io::Result<Request<()>> {
    let uri = http::Uri::builder()
        .scheme("https")
        .authority(auth::HOST)
        .path_and_query(auth::PATH)
        .build()
        .map_err(io::Error::other)?;
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(auth::AUTH, password)
        .header(auth::RATE, receive_rate.to_string())
        .header(auth::PADDING, auth::padding()?)
        .body(())
        .map_err(io::Error::other)
}

pub async fn client_authenticate(
    connection: &quinn::Connection,
    password: &str,
    receive_rate: u64,
) -> io::Result<(bool, auth::ReceiveRate)> {
    timeout(HANDSHAKE_TIMEOUT, async {
        let (mut driver, mut requests) =
            h3::client::new(h3_quinn::Connection::new(connection.clone()))
                .await
                .map_err(io::Error::other)?;
        let lifetime = connection.clone();
        let keepalive = requests.clone();
        // Keep the H3 control streams alive until the QUIC connection has closed.
        tokio::spawn(async move {
            let _requests = keepalive;
            tokio::select! { _ = driver.wait_idle() => (), _ = lifetime.closed() => () }
        });
        let mut stream = requests
            .send_request(request(password, receive_rate)?)
            .await
            .map_err(io::Error::other)?;
        stream.finish().await.map_err(io::Error::other)?;
        loop {
            let response = stream.recv_response().await.map_err(io::Error::other)?;
            if !response.status().is_informational() {
                return auth::parse_response(response.status(), response.headers());
            }
        }
    })
    .await
    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
}
