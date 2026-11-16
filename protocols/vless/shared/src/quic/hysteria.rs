use super::{HysteriaIncoming, HysteriaMasquerade, QuicOptions, hysteria_pair};
use kerlico_hy2::{auth::ReceiveRate, quic};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::sync::mpsc;

pub(super) async fn serve(
    conn: quinn::Connection,
    incoming: mpsc::Sender<HysteriaIncoming>,
    auth: Arc<str>,
    options: Arc<QuicOptions>,
    masquerade: HysteriaMasquerade,
) {
    let receive_rate = ReceiveRate::BytesPerSecond(options.receive_rate());
    let config = Arc::new(quic::Server {
        authenticate: Arc::new(move |password| bool::from(password.ct_eq(auth.as_bytes())).then_some(())),
        on_authenticated: Arc::new(move |conn, _, rate| options.authenticate(conn, rate)),
        fallback: Arc::new(move |request, peer, stream| {
            let masquerade = masquerade.clone();
            Box::pin(async move { let _ = masquerade.serve(request, peer, stream).await; })
        }),
        receive_rate,
        udp: false,
    });
    let (tx, mut rx) = mpsc::channel(128);
    tokio::select! {
        _ = config.serve(conn, tx) => {},
        _ = async {
            while let Some(quic::Tcp { peer, send, recv, .. }) = rx.recv().await {
                let (read, write) = hysteria_pair(recv, send, None);
                if incoming.send((peer, read, write)).await.is_err() { break; }
            }
        } => {},
    }
}
