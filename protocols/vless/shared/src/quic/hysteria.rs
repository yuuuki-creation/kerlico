use super::{
    HANDSHAKE_TIMEOUT, HYSTERIA_AUTH, HYSTERIA_AUTH_OK, HYSTERIA_HOST, HYSTERIA_PADDING,
    HYSTERIA_PATH, HYSTERIA_RATE, HYSTERIA_STREAM, HysteriaIncoming, HysteriaMasquerade,
    QuicOptions, hysteria_padding, hysteria_pair,
};
use bytes::Bytes;
use futures_util::stream;
use http::{Method, Response};
use std::io;
use std::sync::{Arc, OnceLock};
use subtle::ConstantTimeEq;
use tokio::sync::mpsc;
use tokio::time::timeout;

pub(super) async fn serve(
    conn: quinn::Connection,
    incoming: mpsc::Sender<HysteriaIncoming>,
    auth: Arc<str>,
    options: Arc<QuicOptions>,
    masquerade: HysteriaMasquerade,
) {
    let authenticated = Arc::new(OnceLock::new());
    let (http_requests, receiver) = mpsc::channel(128);
    tokio::spawn(dispatch(conn.clone(), incoming, http_requests, authenticated.clone()));
    let bidi = stream::unfold(receiver, |mut receiver| async {
        receiver.recv().await.map(|streams| (Ok(streams), receiver))
    });
    let classified = h3_quinn::Connection::new_with_bidi_streams(conn.clone(), bidi);
    let Ok(mut h3) = h3::server::Connection::new(classified).await else {
        conn.close(quinn::VarInt::from_u32(0x101), b"");
        return;
    };
    let peer = conn.remote_address();
    while let Ok(Some(request)) = h3.accept().await {
        let auth = auth.clone();
        let options = options.clone();
        let masquerade = masquerade.clone();
        let authenticated = authenticated.clone();
        let conn = conn.clone();
        tokio::spawn(async move {
            let Ok(Ok((request, mut stream))) = timeout(HANDSHAKE_TIMEOUT, request.resolve_request()).await else {
                return;
            };
            let auth_request = request.method() == Method::POST
                && request.uri().authority().is_some_and(|host| host.as_str() == HYSTERIA_HOST)
                && request.uri().path() == HYSTERIA_PATH;
            let credentials_match = || request.headers().get(HYSTERIA_AUTH).is_some_and(|value| {
                bool::from(value.as_bytes().ct_eq(auth.as_bytes()))
            });
            if auth_request && (authenticated.get().is_some() || credentials_match()) {
                authenticated.get_or_init(|| {
                    let rate = request.headers().get(HYSTERIA_RATE)
                        .and_then(|value| value.to_str().ok())
                        .and_then(|value| value.parse().ok())
                        .unwrap_or(0);
                    options.authenticate(&conn, rate);
                });
                if let Ok(response) = auth_response(&options) {
                    if stream.send_response(response).await.is_ok() {
                        let _ = stream.finish().await;
                    }
                }
            } else {
                let _ = masquerade.serve(request, peer, stream).await;
            }
        });
    }
    conn.close(quinn::VarInt::from_u32(0x100), b"");
}

fn auth_response(options: &QuicOptions) -> io::Result<Response<()>> {
    Response::builder()
        .status(HYSTERIA_AUTH_OK)
        .header(http::header::DATE, super::masquerade::date())
        .header("hysteria-udp", "false")
        .header(HYSTERIA_RATE, options.receive_rate().to_string())
        .header(HYSTERIA_PADDING, hysteria_padding()?)
        .body(())
        .map_err(io::Error::other)
}

type BidiStream = (quinn::SendStream, quinn::RecvStream, Bytes);

async fn dispatch(
    conn: quinn::Connection,
    incoming: mpsc::Sender<HysteriaIncoming>,
    http_requests: mpsc::Sender<BidiStream>,
    authenticated: Arc<OnceLock<()>>,
) {
    let peer = conn.remote_address();
    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
        let incoming = incoming.clone();
        let http_requests = http_requests.clone();
        let authenticated = authenticated.clone();
        tokio::spawn(async move {
            let Ok(Ok((frame_type, prefix))) = timeout(HANDSHAKE_TIMEOUT, first_frame(&mut recv)).await else {
                return;
            };
            if frame_type != HYSTERIA_STREAM {
                let _ = http_requests.send((send, recv, prefix)).await;
            } else if authenticated.get().is_some() {
                let (read, write) = hysteria_pair(recv, send, None);
                let _ = incoming.send((peer, read, write)).await;
            } else {
                let code = quinn::VarInt::from_u32(0x10e);
                let _ = recv.stop(code);
                let _ = send.reset(code);
            }
        });
    }
}

async fn first_frame(recv: &mut quinn::RecvStream) -> Result<(u64, Bytes), quinn::ReadExactError> {
    let mut bytes = [0; 8];
    recv.read_exact(&mut bytes[..1]).await?;
    let len = 1 << (bytes[0] >> 6);
    recv.read_exact(&mut bytes[1..len]).await?;
    let prefix = Bytes::copy_from_slice(&bytes[..len]);
    bytes[0] &= 0x3f;
    let frame_type = u64::from_be_bytes(bytes) >> ((8 - len) * 8);
    Ok((frame_type, prefix))
}
