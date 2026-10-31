use crate::{stream, tls, wire};
use kerlico_core::{BoxFuture, BoxStream, ConnectContext, Destination, Result, StreamConnector};
use std::sync::Arc;
use tokio::net::TcpStream;
pub(crate) struct Connector {
    pub version: u8,
    pub strict: bool,
    pub key: Arc<[u8]>,
    pub settings: tls::Settings,
}
impl StreamConnector for Connector {
    fn tcp_eof(&self) -> bool {
        false
    }
    fn connect_tcp<'a>(
        &'a self,
        endpoint: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<BoxStream>> {
        Box::pin(async move {
            context
                .run(async {
                    let tcp =
                        TcpStream::connect((endpoint.host().as_str(), endpoint.port())).await?;
                    tcp.set_nodelay(true)?;
                    let outcome = tls::handshake(
                        Box::new(tcp),
                        &self.settings,
                        self.version,
                        self.strict,
                        self.key.clone(),
                    )
                    .await?;
                    if self.version == 1 {
                        return Ok(outcome.stream);
                    }
                    let (raw, capture) = if self.version == 2 {
                        let (raw, state) = crate::v2::wrap(outcome.stream, outcome.transcript);
                        (raw, Some(state))
                    } else {
                        (outcome.stream, None)
                    };
                    let (read, write) = if self.version == 2 {
                        (
                            stream::ReadMode::V2(Some(Box::new(outcome.session))),
                            stream::WriteMode::V2(capture),
                        )
                    } else {
                        let seed = outcome.random.ok_or_else(wire::error)?;
                        (
                            stream::ReadMode::V3 {
                                verify: Box::new(wire::directional(&self.key, &seed, b'S')),
                                ignore: outcome.ignore.map(Box::new),
                            },
                            stream::WriteMode::V3(wire::directional(&self.key, &seed, b'C')),
                        )
                    };
                    Ok(stream::wrap(
                        raw,
                        Vec::new(),
                        read,
                        write,
                        context.cancel.clone(),
                    ))
                })
                .await
        })
    }
}
