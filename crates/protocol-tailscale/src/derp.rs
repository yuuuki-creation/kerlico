//! DERP 客户端（上游 `derp` 协议 v2）：每个区域一个长连接任务，自动重连。

use crate::{
    config::Prepared,
    keys::{NodeKey, Secret},
    netmap::{DerpNode, DerpRegion},
};
use kerlico_core::{BoxStream, CancellationToken, Destination, Error, Result, ServiceContext};
use kerlico_net::TcpConnector;
use serde_json::json;
use std::time::Duration;
use tokio::{
    io::{
        AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader, ReadHalf,
        WriteHalf,
    },
    sync::mpsc,
    time::timeout,
};

const MAGIC: &[u8; 8] = b"DERP\xf0\x9f\x94\x91";
const FRAME_SERVER_KEY: u8 = 0x01;
const FRAME_CLIENT_INFO: u8 = 0x02;
const FRAME_SERVER_INFO: u8 = 0x03;
const FRAME_SEND_PACKET: u8 = 0x04;
const FRAME_RECV_PACKET: u8 = 0x05;
const FRAME_KEEP_ALIVE: u8 = 0x06;
const FRAME_NOTE_PREFERRED: u8 = 0x07;
const FRAME_PING: u8 = 0x12;
const FRAME_PONG: u8 = 0x13;
const MAX_FRAME: usize = 1024 * 1024 + 64;
const PROTOCOL_VERSION: u8 = 2;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// 服务端每 60 秒发保活；两个周期无帧视为断开。
const READ_TIMEOUT: Duration = Duration::from_secs(120);
const QUEUE: usize = 256;

async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<(u8, Vec<u8>)> {
    let mut header = [0; 5];
    reader.read_exact(&mut header).await?;
    let length = u32::from_be_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if length > MAX_FRAME {
        return Err(Error::Protocol("DERP帧过大"));
    }
    let mut payload = vec![0; length];
    reader.read_exact(&mut payload).await?;
    Ok((header[0], payload))
}
async fn write_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    kind: u8,
    parts: &[&[u8]],
) -> Result<()> {
    let length: usize = parts.iter().map(|part| part.len()).sum();
    let mut frame = Vec::with_capacity(5 + length);
    frame.push(kind);
    frame.extend_from_slice(&(length as u32).to_be_bytes());
    for part in parts {
        frame.extend_from_slice(part);
    }
    writer.write_all(&frame).await?;
    writer.flush().await?;
    Ok(())
}

pub struct Received {
    pub region: i32,
    pub source: NodeKey,
    pub packet: Vec<u8>,
}

/// 丢弃即结束该区域任务；写入队列满时按 IP 语义丢包。
pub struct RegionHandle {
    send: mpsc::Sender<(NodeKey, Vec<u8>)>,
    cancel: CancellationToken,
    region: DerpRegion,
}
impl RegionHandle {
    pub fn send(&self, destination: NodeKey, packet: Vec<u8>) {
        let _ = self.send.try_send((destination, packet));
    }
    pub fn region(&self) -> &DerpRegion {
        &self.region
    }
}
impl Drop for RegionHandle {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

pub fn spawn_region(
    host: &ServiceContext,
    prepared: &Prepared,
    region: DerpRegion,
    node_secret: Secret,
    preferred: bool,
    inbound: mpsc::Sender<Received>,
) -> Result<RegionHandle> {
    let (send, outgoing) = mpsc::channel(QUEUE);
    let cancel = host.cancel().child_token();
    let task = RegionTask {
        region: region.clone(),
        secret: node_secret,
        ca_pem: prepared.ca_pem.clone(),
        dialer: prepared.dialer.clone(),
        preferred,
        inbound,
        outgoing,
        host: host.clone(),
    };
    let stop = cancel.clone();
    host.spawn(async move {
        tokio::select! { biased;
            _ = stop.cancelled() => {}
            _ = task.run() => {}
        }
    })?;
    Ok(RegionHandle {
        send,
        cancel,
        region,
    })
}

struct RegionTask {
    region: DerpRegion,
    secret: Secret,
    ca_pem: Option<String>,
    dialer: kerlico_core::DialerOptions,
    preferred: bool,
    inbound: mpsc::Sender<Received>,
    outgoing: mpsc::Receiver<(NodeKey, Vec<u8>)>,
    host: ServiceContext,
}
impl RegionTask {
    async fn run(mut self) {
        let mut backoff = Duration::from_secs(1);
        loop {
            for node in self.region.nodes.clone() {
                if node.stun_only {
                    continue;
                }
                let dialed = timeout(HANDSHAKE_TIMEOUT, self.dial(&node)).await;
                if let Ok(Ok((reader, writer))) = dialed {
                    backoff = Duration::from_secs(1);
                    let _ = self.serve(reader, writer).await;
                    break;
                }
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(30));
        }
    }

    async fn dial(
        &self,
        node: &DerpNode,
    ) -> Result<(BufReader<ReadHalf<BoxStream>>, WriteHalf<BoxStream>)> {
        let port = node.tls_port().ok_or(Error::InvalidAddress)?;
        let name = if node.cert_name.is_empty() {
            &node.host_name
        } else {
            &node.cert_name
        };
        let connector = TcpConnector::tls(name, self.ca_pem.as_deref(), self.dialer.clone())?;
        let mut last = Error::InvalidAddress;
        let mut connected = None;
        for host in node.dial_hosts() {
            match connector.connect(&Destination::new(&host, port)?).await {
                Ok(stream) => {
                    connected = Some(stream);
                    break;
                }
                Err(error) => last = error,
            }
        }
        let stream = connected.ok_or(last)?;
        let (reader, mut writer) = tokio::io::split(stream);
        let mut reader = BufReader::new(reader);
        let request = format!(
            "GET /derp HTTP/1.1\r\nHost: {}\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n",
            node.host_name
        );
        writer.write_all(request.as_bytes()).await?;
        writer.flush().await?;
        read_upgrade(&mut reader).await?;
        client_handshake(&mut reader, &mut writer, &self.secret).await?;
        if self.preferred {
            write_frame(&mut writer, FRAME_NOTE_PREFERRED, &[&[1]]).await?;
        }
        Ok((reader, writer))
    }

    async fn serve(
        &mut self,
        mut reader: BufReader<ReadHalf<BoxStream>>,
        mut writer: WriteHalf<BoxStream>,
    ) -> Result<()> {
        let (pongs, mut pending_pongs) = mpsc::channel::<[u8; 8]>(8);
        let host = self.host.clone();
        let inbound = self.inbound.clone();
        let region = self.region.id;
        let receive = async move {
            loop {
                let (kind, payload) = timeout(READ_TIMEOUT, read_frame(&mut reader))
                    .await
                    .map_err(|_| Error::Timeout)??;
                host.record_carrier(0, payload.len() as u64 + 5);
                match kind {
                    FRAME_RECV_PACKET if payload.len() >= 32 => {
                        let source = NodeKey(payload[..32].try_into().expect("固定长度"));
                        let packet = payload[32..].to_vec();
                        // 数据面满载时丢包，不让单个区域阻塞读保活。
                        let _ = inbound.try_send(Received {
                            region,
                            source,
                            packet,
                        });
                    }
                    FRAME_PING if payload.len() >= 8 => {
                        let data: [u8; 8] = payload[..8].try_into().expect("固定长度");
                        let _ = pongs.try_send(data);
                    }
                    _ => {}
                }
            }
        };
        let host = self.host.clone();
        let outgoing = &mut self.outgoing;
        let transmit = async move {
            loop {
                tokio::select! {
                    data = pending_pongs.recv() => {
                        let Some(data) = data else { return Ok(()) };
                        write_frame(&mut writer, FRAME_PONG, &[&data]).await?;
                    }
                    item = outgoing.recv() => {
                        let Some((destination, packet)) = item else { return Ok(()) };
                        host.record_carrier(packet.len() as u64 + 37, 0);
                        write_frame(&mut writer, FRAME_SEND_PACKET, &[&destination.0, &packet]).await?;
                    }
                }
            }
        };
        tokio::select! {
            result = receive => result,
            result = transmit => result,
        }
    }
}

async fn read_upgrade<R: AsyncRead + Unpin>(reader: &mut BufReader<R>) -> Result<()> {
    let mut line = String::new();
    let mut total = 0;
    let mut first = true;
    loop {
        line.clear();
        let count = (&mut *reader).take(8192).read_line(&mut line).await?;
        total += count;
        if count == 0 || total > 16384 {
            return Err(Error::Protocol("DERP HTTP升级失败"));
        }
        if first {
            if line.split_ascii_whitespace().nth(1) != Some("101") {
                return Err(Error::Protocol("DERP HTTP升级失败"));
            }
            first = false;
        } else if line.trim_end().is_empty() {
            return Ok(());
        }
    }
}

async fn client_handshake<R, W>(reader: &mut R, writer: &mut W, secret: &Secret) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (kind, greeting) = read_frame(reader).await?;
    if kind != FRAME_SERVER_KEY || greeting.len() < 40 || &greeting[..8] != MAGIC {
        return Err(Error::Protocol("DERP服务端问候不合法"));
    }
    let server: [u8; 32] = greeting[8..40].try_into().expect("固定长度");
    let info = json!({"Version": PROTOCOL_VERSION, "CanAckPings": true}).to_string();
    let sealed = secret.seal(&server, info.as_bytes())?;
    write_frame(writer, FRAME_CLIENT_INFO, &[&secret.public(), &sealed]).await?;
    loop {
        let (kind, payload) = read_frame(reader).await?;
        match kind {
            FRAME_SERVER_INFO => {
                secret
                    .open(&server, &payload)
                    .ok_or(Error::Protocol("DERP服务端信息不合法"))?;
                return Ok(());
            }
            FRAME_PING | FRAME_KEEP_ALIVE => {}
            _ => return Err(Error::Protocol("DERP握手帧顺序不合法")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn handshake_matches_documented_frame_flow() {
        let client = Secret::generate();
        let server = Secret::generate();
        let client_public = client.public();
        let server_public = server.public();
        let (mut near, mut far) = duplex(4096);
        let peer = tokio::spawn(async move {
            let mut greeting = MAGIC.to_vec();
            greeting.extend_from_slice(&server_public);
            write_frame(&mut far, FRAME_SERVER_KEY, &[&greeting])
                .await
                .unwrap();
            let (kind, payload) = read_frame(&mut far).await.unwrap();
            assert_eq!(kind, FRAME_CLIENT_INFO);
            assert_eq!(payload[..32], client_public);
            let plain = server.open(&client_public, &payload[32..]).unwrap();
            let info: serde_json::Value = serde_json::from_slice(&plain).unwrap();
            assert_eq!(info["Version"], 2);
            let reply = server.seal(&client_public, b"{}").unwrap();
            write_frame(&mut far, FRAME_SERVER_INFO, &[&reply])
                .await
                .unwrap();
        });
        let (mut reader, mut writer) = tokio::io::split(&mut near);
        client_handshake(&mut reader, &mut writer, &client)
            .await
            .unwrap();
        peer.await.unwrap();
    }

    #[tokio::test]
    async fn frame_header_is_type_and_big_endian_length() {
        let (mut near, mut far) = duplex(64);
        write_frame(&mut near, FRAME_SEND_PACKET, &[b"ab", b"c"])
            .await
            .unwrap();
        let mut bytes = [0; 8];
        far.read_exact(&mut bytes).await.unwrap();
        assert_eq!(bytes, [4, 0, 0, 0, 3, b'a', b'b', b'c']);
    }

    #[tokio::test]
    async fn oversized_frame_is_rejected() {
        let (mut near, mut far) = duplex(64);
        near.write_all(&[5, 0xff, 0xff, 0xff, 0xff]).await.unwrap();
        assert!(read_frame(&mut far).await.is_err());
    }
}
