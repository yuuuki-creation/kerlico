//! `dns.listen`：同一地址上的 UDP 与 TCP DNS 服务，每个报文交给同一条管线。

use kerlico_core::{BoxFuture, Result};
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UdpSocket},
};

/// 把一个查询报文交换为应答；`Err` 表示不回应（如 `reject` 的丢弃方式）。
pub type Handler = Arc<dyn Fn(Vec<u8>) -> BoxFuture<'static, Result<Vec<u8>>> + Send + Sync>;

/// 绑定 UDP 与 TCP 套接字；端口为 0 时 TCP 复用 UDP 拿到的端口。
pub async fn bind(addr: std::net::SocketAddr) -> Result<(UdpSocket, TcpListener)> {
    let mut attempts = if addr.port() == 0 { 16 } else { 1 };
    loop {
        let udp = UdpSocket::bind(addr).await?;
        match TcpListener::bind(udp.local_addr()?).await {
            Ok(tcp) => return Ok((udp, tcp)),
            Err(e) if attempts == 1 => return Err(e.into()),
            Err(_) => attempts -= 1,
        }
    }
}

pub async fn serve_udp(socket: UdpSocket, handler: Handler) -> Result<()> {
    let socket = Arc::new(socket);
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, peer) = socket.recv_from(&mut buf).await?;
        let packet = buf[..n].to_vec();
        let socket = socket.clone();
        let handler = handler.clone();
        tokio::spawn(async move {
            if let Ok(reply) = handler(packet).await {
                let _ = socket.send_to(&reply, peer).await;
            }
        });
    }
}

pub async fn serve_tcp(listener: TcpListener, handler: Handler) -> Result<()> {
    loop {
        let (mut stream, _) = listener.accept().await?;
        let handler = handler.clone();
        tokio::spawn(async move {
            let mut len = [0u8; 2];
            while let Ok(Ok(_)) = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                stream.read_exact(&mut len),
            )
            .await
            {
                let mut query = vec![0u8; usize::from(u16::from_be_bytes(len))];
                if stream.read_exact(&mut query).await.is_err() {
                    break;
                }
                let Ok(reply) = handler(query).await else {
                    break;
                };
                let Ok(rlen) = u16::try_from(reply.len()) else {
                    break;
                };
                if stream.write_all(&rlen.to_be_bytes()).await.is_err()
                    || stream.write_all(&reply).await.is_err()
                {
                    break;
                }
            }
        });
    }
}
