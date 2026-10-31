//! 与协议无关的目标访问；域名优先 IPv4，候选只在建立阶段切换。

use kerlico_core::{
    AccessService, Address, BoxFuture, BoxStream, Capabilities, ConnectContext,
    DatagramAssociation, DatagramAssociationSender, DatagramChannel, DatagramReceiver, Destination,
    Error, Outbound, Result,
};
use std::{collections::HashSet, sync::Arc, time::Duration};
use tokio::time::Instant;

pub struct Egress {
    outbound: Arc<dyn Outbound>,
}

struct ResolvedReceiver {
    inner: Box<dyn DatagramReceiver>,
    target: Destination,
}

struct ResolvedAssociationSender {
    inner: Box<dyn DatagramAssociationSender>,
    context: ConnectContext,
}

impl DatagramAssociationSender for ResolvedAssociationSender {
    fn send_to<'a>(
        &'a mut self,
        packet: &'a [u8],
        target: &'a Destination,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.context
                .run(async {
                    let targets = Egress::candidates(target).await?;
                    self.inner.send_to(packet, &targets[0]).await
                })
                .await
        })
    }
}

impl DatagramReceiver for ResolvedReceiver {
    fn peer_addr(&self) -> Option<Destination> {
        Some(self.target.clone())
    }
    fn recv(&mut self) -> BoxFuture<'_, Result<Option<Vec<u8>>>> {
        self.inner.recv()
    }
}

impl Egress {
    pub fn new(outbound: Arc<dyn Outbound>) -> Self {
        Self { outbound }
    }

    async fn candidates(target: &Destination) -> Result<Vec<Destination>> {
        if matches!(target.address(), Address::Ip(_)) {
            return Ok(vec![target.clone()]);
        }
        let mut seen = HashSet::new();
        let mut values: Vec<_> = tokio::net::lookup_host((target.host().as_str(), target.port()))
            .await?
            .filter(|s| seen.insert(s.ip()))
            .take(32)
            .map(|s| Destination::new(&s.ip().to_string(), s.port()))
            .collect::<Result<_>>()?;
        values.sort_by_key(|s| matches!(s.address(), Address::Ip(std::net::IpAddr::V6(_))));
        if values.is_empty() {
            return Err(Error::InvalidAddress);
        }
        Ok(values)
    }

    async fn tcp(&self, target: &Destination, context: &ConnectContext) -> Result<BoxStream> {
        let deadline = Instant::now() + context.timeout;
        context
            .run(async {
                let candidates = Self::candidates(target).await?;
                let mut last = Error::InvalidAddress;
                for (index, candidate) in candidates.iter().enumerate() {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        return Err(Error::Timeout);
                    }
                    let budget = if index + 1 < candidates.len() {
                        remaining.min(Duration::from_millis(1000))
                    } else {
                        remaining
                    };
                    let attempt = ConnectContext {
                        cancel: context.cancel.clone(),
                        timeout: budget,
                    };
                    match self.outbound.connect_tcp(candidate, &attempt).await {
                        Ok(stream) => return Ok(stream),
                        Err(error @ (Error::Io(_) | Error::Timeout)) => last = error,
                        Err(error) => return Err(error),
                    }
                }
                Err(last)
            })
            .await
    }

    async fn udp(&self, target: &Destination, context: &ConnectContext) -> Result<DatagramChannel> {
        let deadline = Instant::now() + context.timeout;
        context
            .run(async {
                let candidates = Self::candidates(target).await?;
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(Error::Timeout);
                }
                // 数据报建立不证明远端可达，固定首个候选后不靠收包超时重发。
                let channel = self
                    .outbound
                    .connect_udp(
                        &candidates[0],
                        &ConnectContext {
                            cancel: context.cancel.clone(),
                            timeout: remaining,
                        },
                    )
                    .await?;
                Ok(DatagramChannel {
                    sender: channel.sender,
                    receiver: Box::new(ResolvedReceiver {
                        inner: channel.receiver,
                        target: candidates[0].clone(),
                    }),
                })
            })
            .await
    }

    async fn association(&self, context: &ConnectContext) -> Result<DatagramAssociation> {
        context
            .run(async {
                let association = self.outbound.associate_udp(context).await?;
                Ok(DatagramAssociation {
                    sender: Box::new(ResolvedAssociationSender {
                        inner: association.sender,
                        context: context.clone(),
                    }),
                    receiver: association.receiver,
                })
            })
            .await
    }
}

impl Outbound for Egress {
    fn supports_udp_association(&self) -> bool {
        self.outbound.supports_udp_association()
    }
    fn associate_udp<'a>(
        &'a self,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramAssociation>> {
        Box::pin(self.association(context))
    }
    fn capabilities(&self) -> Capabilities {
        self.outbound.capabilities()
    }
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<BoxStream>> {
        Box::pin(self.tcp(target, context))
    }
    fn connect_udp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(self.udp(target, context))
    }
}
impl AccessService for Egress {
    fn supports_udp_association(&self) -> bool {
        self.outbound.supports_udp_association()
    }
    fn associate_udp<'a>(
        &'a self,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramAssociation>> {
        Box::pin(self.association(context))
    }
    fn connect_tcp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<BoxStream>> {
        Box::pin(self.tcp(target, context))
    }
    fn connect_udp<'a>(
        &'a self,
        target: &'a Destination,
        context: &'a ConnectContext,
    ) -> BoxFuture<'a, Result<DatagramChannel>> {
        Box::pin(self.udp(target, context))
    }
}
