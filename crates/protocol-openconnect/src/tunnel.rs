//! CONNECT 响应参数、DPD/keepalive 判定与 CSTP 数据泵。

use crate::{
    http::Response,
    wire::{self, FrameKind},
};
use bytes::BytesMut;
use kerlico_core::{CancellationToken, Error, Result, ServiceContext};
use kerlico_wireguard::ip::ClientTunnel;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf},
    time::{Instant, MissedTickBehavior},
};

const BYE_TIMEOUT: Duration = Duration::from_secs(1);
const READ_CHUNK: usize = 16 * 1024;
const BYE_PAYLOAD: &[u8] = b"\xb0Client disconnect";

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TunnelParams {
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
    pub mtu: usize,
    pub keepalive: Option<Duration>,
    pub dpd: Option<Duration>,
}
impl TunnelParams {
    pub fn parse(response: &Response) -> Result<Self> {
        let (mut ipv4, mut ipv6) = (None, None);
        let addresses = response
            .all("X-CSTP-Address")
            .chain(response.all("X-CSTP-Address-IP6"));
        for value in addresses {
            let literal = value.split('/').next().unwrap_or_default();
            match literal.parse::<IpAddr>() {
                Ok(IpAddr::V4(address)) => ipv4 = ipv4.or(Some(address)),
                Ok(IpAddr::V6(address)) => ipv6 = ipv6.or(Some(address)),
                Err(_) => return Err(Error::Protocol("OpenConnect 服务端分配的地址不合法")),
            }
        }
        if ipv4.is_none() && ipv6.is_none() {
            return Err(Error::Protocol("OpenConnect 服务端未分配隧道地址"));
        }
        let mtu = response
            .header("X-CSTP-MTU")
            .and_then(|value| value.parse::<usize>().ok())
            .ok_or(Error::Protocol("OpenConnect 服务端未提供有效 MTU"))?;
        Ok(Self {
            ipv4,
            ipv6,
            mtu,
            keepalive: seconds(response.header("X-CSTP-Keepalive")),
            dpd: seconds(response.header("X-CSTP-DPD")),
        })
    }
    pub fn addresses(&self) -> Vec<IpAddr> {
        self.ipv4
            .map(IpAddr::V4)
            .into_iter()
            .chain(self.ipv6.map(IpAddr::V6))
            .collect()
    }
    /// 不套用服务端推送的分流路由：选路交给 kerlico 路由规则，可达范围由服务端决定。
    pub fn allowed_ips(&self) -> Vec<String> {
        self.ipv4
            .map(|_| "0.0.0.0/0".to_owned())
            .into_iter()
            .chain(self.ipv6.map(|_| "::/0".to_owned()))
            .collect()
    }
}
fn seconds(value: Option<&str>) -> Option<Duration> {
    let seconds = value?.parse::<u32>().ok()?;
    (seconds > 0).then(|| Duration::from_secs(seconds.into()))
}

/// keepalive 只看发送静默，DPD 只看接收静默；未答复的探测按半周期重发，两周期无接收判定死亡。
pub(crate) struct Liveness {
    keepalive: Option<Duration>,
    dpd: Option<Duration>,
    last_sent: Instant,
    last_received: Instant,
    last_probe: Option<Instant>,
}
impl Liveness {
    pub fn new(keepalive: Option<Duration>, dpd: Option<Duration>, now: Instant) -> Self {
        Self {
            keepalive,
            dpd,
            last_sent: now,
            last_received: now,
            last_probe: None,
        }
    }
    pub fn received(&mut self, now: Instant) {
        self.last_received = now;
        self.last_probe = None;
    }
    pub fn sent(&mut self, now: Instant) {
        self.last_sent = now;
    }
    pub fn poll(&mut self, now: Instant) -> Result<Option<FrameKind>> {
        if let Some(dpd) = self.dpd {
            if now.duration_since(self.last_received) >= dpd * 2 {
                return Err(Error::Timeout);
            }
            let due = match self.last_probe {
                Some(probe) => probe + dpd / 2,
                None => self.last_received + dpd,
            };
            if now >= due {
                self.last_probe = Some(now);
                return Ok(Some(FrameKind::DpdRequest));
            }
        }
        if let Some(keepalive) = self.keepalive
            && now.duration_since(self.last_sent) >= keepalive
        {
            return Ok(Some(FrameKind::Keepalive));
        }
        Ok(None)
    }
}

struct Pump<'a, S> {
    reader: ReadHalf<S>,
    writer: WriteHalf<S>,
    received: BytesMut,
    pending: BytesMut,
    drain_owed: bool,
    tunnel: &'a ClientTunnel,
    host: &'a ServiceContext,
}

/// 被 select 取消时进度留在 `pending` 与 TLS 层，再次调用可继续。
async fn drain<W: AsyncWrite + Unpin>(writer: &mut W, pending: &mut BytesMut) -> Result<()> {
    writer.write_all_buf(pending).await?;
    writer.flush().await?;
    Ok(())
}

impl<S: AsyncRead + AsyncWrite> Pump<'_, S> {
    fn queue(&mut self, kind: FrameKind, payload: &[u8]) -> Result<()> {
        let before = self.pending.len();
        wire::encode(kind, payload, &mut self.pending)?;
        self.host
            .record_carrier((self.pending.len() - before) as u64, 0);
        self.drain_owed = true;
        Ok(())
    }

    /// 单任务同时推进收发：发送被 TCP 背压时仍继续读取，避免双方都写满时互相阻塞。
    async fn run(
        &mut self,
        params: &TunnelParams,
        idle_limit: Duration,
        cancel: &CancellationToken,
    ) -> Result<()> {
        let mut liveness = Liveness::new(params.keepalive, params.dpd, Instant::now());
        let mut ticker = tokio::time::interval(Duration::from_secs(1));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut last_active = Instant::now();
        let mut response_owed = false;
        let mut control_owed = None;
        loop {
            while let Some(frame) = wire::take_frame(&mut self.received)? {
                match frame.kind {
                    FrameKind::Data => {
                        // 单个 IP 包被丢弃不影响隧道，与物理网卡语义一致。
                        let _ = self.tunnel.receive(&frame.payload);
                    }
                    FrameKind::DpdRequest => response_owed = true,
                    FrameKind::Disconnect | FrameKind::Terminate => return Ok(()),
                    FrameKind::Compressed => {
                        return Err(Error::Protocol("OpenConnect 服务端发送了未协商的压缩帧"));
                    }
                    FrameKind::DpdResponse | FrameKind::Keepalive | FrameKind::Other(_) => {}
                }
            }
            if self.pending.is_empty() {
                let control = if std::mem::take(&mut response_owed) {
                    Some(FrameKind::DpdResponse)
                } else {
                    control_owed.take()
                };
                if let Some(kind) = control {
                    self.queue(kind, &[])?;
                    liveness.sent(Instant::now());
                }
            }
            self.received.reserve(READ_CHUNK);
            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                result = self.reader.read_buf(&mut self.received) => {
                    let count = result?;
                    if count == 0 {
                        return Err(Error::Protocol("OpenConnect 服务端提前关闭连接"));
                    }
                    self.host.record_carrier(0, count as u64);
                    liveness.received(Instant::now());
                }
                result = drain(&mut self.writer, &mut self.pending), if self.drain_owed => {
                    result?;
                    self.drain_owed = false;
                }
                packet = self.tunnel.next_packet(), if self.pending.is_empty() => {
                    self.queue(FrameKind::Data, &packet?)?;
                    liveness.sent(Instant::now());
                }
                _ = ticker.tick() => {
                    let now = Instant::now();
                    if self.tunnel.active_flows() > 0 {
                        last_active = now;
                    } else if now.duration_since(last_active) >= idle_limit {
                        return Ok(());
                    }
                    if let Some(kind) = liveness.poll(now)? {
                        control_owed = Some(kind);
                    }
                }
            }
        }
    }

    /// 补完已开始的帧再发送断开通知，让服务端立即释放会话。
    async fn say_goodbye(&mut self) -> Result<()> {
        self.writer.write_all_buf(&mut self.pending).await?;
        wire::encode(FrameKind::Disconnect, BYE_PAYLOAD, &mut self.pending)?;
        self.writer.write_all_buf(&mut self.pending).await?;
        self.writer.shutdown().await?;
        Ok(())
    }
}

/// 运行到隧道结束；任何结束原因都关闭 IP 数据面，现有流随之终止。
pub(crate) async fn run<S: AsyncRead + AsyncWrite + Send>(
    stream: S,
    received: BytesMut,
    params: TunnelParams,
    idle_limit: Duration,
    tunnel: ClientTunnel,
    host: ServiceContext,
    cancel: CancellationToken,
) {
    let (reader, writer) = tokio::io::split(stream);
    let mut pump = Pump {
        reader,
        writer,
        received,
        pending: BytesMut::new(),
        drain_owed: false,
        tunnel: &tunnel,
        host: &host,
    };
    let _ = pump.run(&params, idle_limit, &cancel).await;
    cancel.cancel();
    tunnel.close();
    let _ = tokio::time::timeout(BYE_TIMEOUT, pump.say_goodbye()).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::take_frame;
    use kerlico_core::{ConnectContext, Destination};
    use kerlico_wireguard::ip::{StackLimits, StackOptions};
    use tokio::io::DuplexStream;

    const OCSERV_CONNECTED: &str = "HTTP/1.1 200 CONNECTED\r\n\
        X-CSTP-Version: 1\r\n\
        X-CSTP-Server-Name: ocserv 1.1.6\r\n\
        X-CSTP-DPD: 30\r\n\
        X-CSTP-Address: 192.168.77.50\r\n\
        X-CSTP-Netmask: 255.255.255.0\r\n\
        X-CSTP-Address-IP6: fd77:77:0:8e4f:9a7c:c09f:b76e:58ef/64\r\n\
        X-CSTP-DNS: 192.168.77.1\r\n\
        X-CSTP-Keepalive: 20\r\n\
        X-CSTP-Idle-Timeout: none\r\n\
        X-CSTP-Rekey-Time: 172784\r\n\
        X-CSTP-Rekey-Method: ssl\r\n\
        X-CSTP-Base-MTU: 1500\r\n\
        X-CSTP-MTU: 1472\r\n\r\n";

    fn parsed(text: &str) -> Result<TunnelParams> {
        let mut buffer = BytesMut::from(text.as_bytes());
        TunnelParams::parse(&Response::parse(&mut buffer).unwrap().unwrap())
    }

    #[test]
    fn ocserv_connect_headers_produce_tunnel_parameters() {
        let params = parsed(OCSERV_CONNECTED).unwrap();
        assert_eq!(
            params,
            TunnelParams {
                ipv4: Some(Ipv4Addr::new(192, 168, 77, 50)),
                ipv6: Some("fd77:77:0:8e4f:9a7c:c09f:b76e:58ef".parse().unwrap()),
                mtu: 1472,
                keepalive: Some(Duration::from_secs(20)),
                dpd: Some(Duration::from_secs(30)),
            }
        );
        assert_eq!(params.allowed_ips(), ["0.0.0.0/0", "::/0"]);
    }

    #[test]
    fn missing_or_invalid_assignment_is_refused_and_ipv4_only_has_no_ipv6_route() {
        assert!(parsed("HTTP/1.1 200 CONNECTED\r\nX-CSTP-MTU: 1400\r\n\r\n").is_err());
        assert!(parsed("HTTP/1.1 200 CONNECTED\r\nX-CSTP-Address: 10.0.0.1\r\n\r\n").is_err());
        assert!(
            parsed("HTTP/1.1 200 CONNECTED\r\nX-CSTP-Address: nope\r\nX-CSTP-MTU: 1400\r\n\r\n")
                .is_err()
        );
        let params =
            parsed("HTTP/1.1 200 CONNECTED\r\nX-CSTP-Address: 10.0.0.1\r\nX-CSTP-MTU: 1400\r\nX-CSTP-Keepalive: 0\r\n\r\n")
                .unwrap();
        assert_eq!(params.allowed_ips(), ["0.0.0.0/0"]);
        assert_eq!(params.keepalive, None);
    }

    #[test]
    fn keepalive_tracks_send_silence_and_dpd_tracks_receive_silence() {
        let start = Instant::now();
        let second = Duration::from_secs(1);
        let mut live = Liveness::new(Some(second * 20), Some(second * 30), start);
        assert_eq!(live.poll(start + second * 19).unwrap(), None);
        assert_eq!(
            live.poll(start + second * 20).unwrap(),
            Some(FrameKind::Keepalive)
        );
        live.sent(start + second * 20);
        assert_eq!(
            live.poll(start + second * 30).unwrap(),
            Some(FrameKind::DpdRequest)
        );
        assert_eq!(live.poll(start + second * 31).unwrap(), None);
        assert_eq!(
            live.poll(start + second * 45).unwrap(),
            Some(FrameKind::DpdRequest)
        );
        live.received(start + second * 46);
        live.sent(start + second * 46);
        assert_eq!(live.poll(start + second * 47).unwrap(), None);
        assert!(matches!(
            live.poll(start + second * 106),
            Err(Error::Timeout)
        ));
    }

    async fn read_frame(peer: &mut DuplexStream, buffer: &mut BytesMut) -> wire::Frame {
        loop {
            if let Some(frame) = take_frame(buffer).unwrap() {
                return frame;
            }
            assert_ne!(peer.read_buf(buffer).await.unwrap(), 0);
        }
    }

    fn test_params(dpd: Option<Duration>) -> TunnelParams {
        TunnelParams {
            ipv4: Some(Ipv4Addr::new(10, 9, 0, 2)),
            ipv6: None,
            mtu: 1400,
            keepalive: None,
            dpd,
        }
    }

    fn test_tunnel(cancel: &CancellationToken) -> ClientTunnel {
        ClientTunnel::new(
            StackOptions {
                addresses: vec!["10.9.0.2".parse().unwrap()],
                allowed_ips: vec!["0.0.0.0/0".into()],
                mtu: 1400,
                limits: StackLimits::default(),
            },
            cancel.clone(),
        )
        .unwrap()
    }

    async fn session_ends_with_goodbye(dpd: Option<Duration>, idle_limit: Duration) {
        let (client, mut server) = tokio::io::duplex(65536);
        let cancel = CancellationToken::new();
        let pump = tokio::spawn(run(
            client,
            BytesMut::new(),
            test_params(dpd),
            idle_limit,
            test_tunnel(&cancel),
            ServiceContext::for_test(),
            cancel.clone(),
        ));
        let mut buffer = BytesMut::new();
        loop {
            match read_frame(&mut server, &mut buffer).await.kind {
                FrameKind::DpdRequest => {}
                FrameKind::Disconnect => break,
                other => panic!("unexpected frame {other:?}"),
            }
        }
        pump.await.unwrap();
        assert!(cancel.is_cancelled());
    }

    #[tokio::test]
    async fn silent_peer_is_probed_then_declared_dead() {
        session_ends_with_goodbye(Some(Duration::from_secs(1)), Duration::from_secs(300)).await;
    }

    #[tokio::test]
    async fn session_without_flows_closes_after_the_idle_limit() {
        session_ends_with_goodbye(None, Duration::from_secs(1)).await;
    }

    #[tokio::test]
    async fn pump_answers_dpd_frames_ip_packets_and_ends_on_server_terminate() {
        let (client, mut server) = tokio::io::duplex(65536);
        let cancel = CancellationToken::new();
        let tunnel = test_tunnel(&cancel);
        let mut datagrams = tunnel
            .connect_udp(
                &Destination::new("10.9.0.1", 53).unwrap(),
                &ConnectContext::new(Duration::from_secs(5)),
            )
            .unwrap();
        let host = ServiceContext::for_test();
        let pump = tokio::spawn(run(
            client,
            BytesMut::new(),
            test_params(None),
            Duration::from_secs(300),
            tunnel.clone(),
            host.clone(),
            cancel.clone(),
        ));
        let mut buffer = BytesMut::new();

        let mut outgoing = BytesMut::new();
        wire::encode(FrameKind::DpdRequest, &[], &mut outgoing).unwrap();
        server.write_all(&outgoing).await.unwrap();
        assert_eq!(
            read_frame(&mut server, &mut buffer).await.kind,
            FrameKind::DpdResponse
        );

        datagrams.sender.send(b"query").await.unwrap();
        let frame = read_frame(&mut server, &mut buffer).await;
        assert_eq!(frame.kind, FrameKind::Data);
        let packet = frame.payload;
        assert_eq!(packet[0] >> 4, 4);
        assert_eq!(&packet[packet.len() - 5..], b"query");

        let mut reply = packet.to_vec();
        reply.swap(12, 16);
        reply.swap(13, 17);
        reply.swap(14, 18);
        reply.swap(15, 19);
        reply.swap(20, 22);
        reply.swap(21, 23);
        let mut outgoing = BytesMut::new();
        wire::encode(FrameKind::Data, &reply, &mut outgoing).unwrap();
        server.write_all(&outgoing).await.unwrap();
        assert_eq!(
            datagrams.receiver.recv().await.unwrap().unwrap(),
            b"query".to_vec()
        );

        let mut outgoing = BytesMut::new();
        wire::encode(FrameKind::Terminate, &[], &mut outgoing).unwrap();
        server.write_all(&outgoing).await.unwrap();
        assert_eq!(
            read_frame(&mut server, &mut buffer).await.kind,
            FrameKind::Disconnect
        );
        pump.await.unwrap();
        assert!(cancel.is_cancelled());
        assert!(host.carrier_usage().sent_bytes > 0);
    }
}
