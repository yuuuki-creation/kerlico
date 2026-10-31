use crate::{
    carrier::{
        Opened,
        endpoint::Endpoint,
        http::{client as split, codec::Mode, transport::HttpClient},
        raw, ws,
    },
    config::{CarrierMode, Multiplex, OutConfig, OutOptions},
    handshake::{self, EarlyClient, Negotiated},
    io::CancelIo,
    mux::Session,
    scope::Scope,
    udp,
    wire::{address, kip},
};
use kerlico_config::OutboundFactory;
use kerlico_core::{
    BoxFuture, BoxStream, CancellationToken, Capabilities, ConnectContext, DatagramAssociation,
    DatagramChannel, Destination, Error, Outbound, Result,
};
use serde_json::Value;
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{Mutex, OnceCell, OwnedSemaphorePermit, Semaphore},
};

pub struct SudokuFactory;
impl OutboundFactory for SudokuFactory {
    fn kind(&self) -> &'static str {
        "sudoku"
    }
    fn build(&self, value: &Value) -> Result<Arc<dyn Outbound>> {
        let options: OutOptions = serde_json::from_value(value.clone())
            .map_err(|_| Error::Config("Sudoku出站字段不合法".into()))?;
        Ok(Arc::new(Client::new(options.prepare()?)))
    }
}
struct Client {
    config: Arc<OutConfig>,
    endpoint: Arc<Endpoint>,
    scope: Arc<Scope>,
    http: OnceCell<Arc<HttpClient>>,
    pool: Mutex<Vec<Arc<Session>>>,
    flows: Arc<Semaphore>,
}
impl Drop for Client {
    fn drop(&mut self) {
        self.scope.cancel.cancel();
        self.scope.tasks.close();
    }
}
impl Client {
    fn new(config: OutConfig) -> Self {
        let endpoint = Arc::new(Endpoint::new(config.server.clone()));
        Self {
            config: Arc::new(config),
            endpoint,
            scope: Scope::new(&CancellationToken::new()),
            http: OnceCell::new(),
            pool: Mutex::new(Vec::new()),
            flows: Arc::new(Semaphore::new(128)),
        }
    }
    async fn http(&self) -> Arc<HttpClient> {
        if self.config.multiplex == Multiplex::Off {
            HttpClient::new(
                &self.config,
                self.endpoint.clone(),
                &self.scope.cancel,
                false,
            )
        } else {
            self.http
                .get_or_init(|| async {
                    HttpClient::new(
                        &self.config,
                        self.endpoint.clone(),
                        &self.scope.cancel,
                        true,
                    )
                })
                .await
                .clone()
        }
    }
    async fn finish(&self, early: EarlyClient, opened: Opened) -> Result<Negotiated> {
        if let Some(response) = opened.early_response {
            early.finish(opened.stream, &response)
        } else {
            handshake::client(
                opened.stream,
                &self.config.protocol,
                handshake::client_table(&self.config.protocol)?,
            )
            .await
        }
    }
    async fn mode(&self, mode: CarrierMode) -> Result<Negotiated> {
        match mode {
            CarrierMode::Raw | CarrierMode::Legacy => {
                let stream = raw::connect(&self.config, &self.endpoint).await?;
                handshake::client(
                    stream,
                    &self.config.protocol,
                    handshake::client_table(&self.config.protocol)?,
                )
                .await
            }
            CarrierMode::Ws => {
                let early = EarlyClient::new(self.config.protocol.clone())?;
                let opened = ws::connect(&self.config, &self.endpoint, &early).await?;
                self.finish(early, opened).await
            }
            CarrierMode::Stream | CarrierMode::Poll => {
                let early = EarlyClient::new(self.config.protocol.clone())?;
                let client = self.http().await;
                let opened = split::connect(
                    client,
                    &self.scope,
                    if mode == CarrierMode::Stream {
                        Mode::Stream
                    } else {
                        Mode::Poll
                    },
                    &early,
                    self.config.multiplex == Multiplex::Off,
                )
                .await?;
                self.finish(early, opened).await
            }
            CarrierMode::Auto => Err(Error::Unsupported("auto须在同一节点建立流程选择具体载体")),
        }
    }
    async fn negotiate(&self) -> Result<Negotiated> {
        if self.scope.cancel.is_cancelled() {
            return Err(Error::Cancelled);
        }
        if self.config.mask.mode != CarrierMode::Auto {
            return self.mode(self.config.mask.mode).await;
        }
        match self.mode(CarrierMode::Stream).await {
            Ok(value) => Ok(value),
            Err(Error::Io(_) | Error::Timeout | Error::Rejected)
                if !self.scope.cancel.is_cancelled() =>
            {
                self.mode(CarrierMode::Poll).await
            }
            Err(error) => Err(error),
        }
    }
    async fn session(&self) -> Result<Arc<Session>> {
        let mut pool = self.pool.lock().await;
        pool.retain(|s| !s.is_closed());
        if let Some(session) = pool.iter().find(|s| s.available()) {
            return Ok(session.clone());
        }
        if pool.len() >= self.config.max_pool {
            return Err(Error::ResourceLimit);
        }
        let mut negotiated = self.negotiate().await?;
        if negotiated.features & 2 == 0 {
            return Err(Error::Unsupported("对端未选择Sudoku session mux"));
        }
        kip::write(&mut negotiated.stream, kip::START_MUX, &[]).await?;
        let stream = Box::new(CancelIo::new(negotiated.stream, &self.scope.cancel)) as BoxStream;
        let session = Arc::new(Session::start(
            stream,
            &self.scope.cancel,
            self.config.max_streams,
            self.config.idle,
            None,
            false,
        ));
        pool.push(session.clone());
        Ok(session)
    }
    fn owned(
        &self,
        stream: BoxStream,
        context: &ConnectContext,
        permit: OwnedSemaphorePermit,
    ) -> BoxStream {
        Box::new(Owned {
            stream: Box::new(CancelIo::new(
                CancelIo::new(stream, &self.scope.cancel),
                &context.cancel,
            )),
            _permit: permit,
        })
    }
}
impl Outbound for Client {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            tcp: true,
            tcp_eof: self.config.multiplex == Multiplex::On
                || self.config.mask.mode != CarrierMode::Ws,
            udp: self.config.protocol.udp_enabled,
        }
    }
    fn supports_udp_association(&self) -> bool {
        self.config.protocol.udp_enabled
    }
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<BoxStream>> {
        Box::pin(async move {
            let permit = self
                .flows
                .clone()
                .try_acquire_owned()
                .map_err(|_| Error::ResourceLimit)?;
            context
                .run(async {
                    if self.config.multiplex == Multiplex::On {
                        let session = self.session().await?;
                        let stream = session.open(target, context).await?;
                        return Ok(self.owned(Box::new(stream), context, permit));
                    }
                    let mut negotiated = self.negotiate().await?;
                    if negotiated.features & 1 == 0 {
                        return Err(Error::Unsupported("对端未选择Sudoku TCP"));
                    }
                    kip::write(
                        &mut negotiated.stream,
                        kip::OPEN_TCP,
                        &address::encode(target),
                    )
                    .await?;
                    Ok(self.owned(negotiated.stream, context, permit))
                })
                .await
        })
    }
    fn associate_udp<'a>(
        &'a self,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramAssociation>> {
        Box::pin(async move {
            if !self.config.protocol.udp_enabled {
                return Err(Error::Unsupported("Sudoku配置未启用UoT"));
            }
            let permit = self
                .flows
                .clone()
                .try_acquire_owned()
                .map_err(|_| Error::ResourceLimit)?;
            context
                .run(async {
                    let mut negotiated = self.negotiate().await?;
                    if negotiated.features & 4 == 0 {
                        return Err(Error::Unsupported("对端未选择Sudoku UoT"));
                    }
                    kip::write(&mut negotiated.stream, kip::START_UOT, &[]).await?;
                    Ok(udp::association(
                        self.owned(negotiated.stream, context, permit),
                        &context.cancel,
                        udp::MAX_PACKET,
                        true,
                    ))
                })
                .await
        })
    }
    fn connect_udp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(async move {
            Ok(udp::fixed(
                self.associate_udp(context).await?,
                target.clone(),
            ))
        })
    }
}
struct Owned {
    stream: BoxStream,
    _permit: OwnedSemaphorePermit,
}
impl AsyncRead for Owned {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buffer)
    }
}
impl AsyncWrite for Owned {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}
