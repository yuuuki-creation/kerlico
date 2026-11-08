//! Vision tunnel over an established REALITY TLS client session.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::protocol::{
    reality::{
        ClientSession,
        tls13::{ContentType, MAX_PLAINTEXT_LEN, MAX_TLS_RECORD_WIRE_LEN},
    },
    vless::{
        Destination, ResponseDecodeError, UserId, VisionCommand, VisionDecoder, VisionEncoder,
        VisionMode, decode_response, encode_vision_tcp_request,
    },
};

/// Vision / VLESS session failure.
#[derive(Debug)]
pub enum VisionTunnelError {
    /// VLESS request could not be encoded.
    Request,
    /// Vision framing failed.
    Vision,
    /// Record protection failed.
    Record,
    /// Peer closed before the VLESS response.
    ClosedBeforeResponse,
    /// Socket I/O failed.
    Io(io::Error),
}

impl std::fmt::Display for VisionTunnelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Vision tunnel failed")
    }
}

impl std::error::Error for VisionTunnelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

/// Bidirectional Vision tunnel to a destination through an entry.
pub struct VisionTunnel {
    stream: tokio::net::TcpStream,
    session: ClientSession,
    encoder: VisionEncoder,
    decoder: VisionDecoder,
    downlink: VisionMode,
    readable: Vec<u8>,
    readable_at: usize,
    encoder_done: bool,
}

impl VisionTunnel {
    /// Sends the Vision TCP request preamble and waits for the VLESS response.
    pub async fn connect(
        mut stream: tokio::net::TcpStream,
        mut session: ClientSession,
        user_id: UserId,
        destination: &Destination,
    ) -> Result<Self, VisionTunnelError> {
        let mut request = [0_u8; 512];
        let request_len = encode_vision_tcp_request(user_id, destination, &mut request)
            .map_err(|_| VisionTunnelError::Request)?;
        let mut encoder = VisionEncoder::new(user_id).map_err(|_| VisionTunnelError::Vision)?;
        let preamble = encoder
            .plan(0, VisionCommand::Continue, true)
            .map_err(|_| VisionTunnelError::Vision)?;
        let total = request_len
            .checked_add(preamble.wire_len())
            .filter(|n| *n <= MAX_PLAINTEXT_LEN)
            .ok_or(VisionTunnelError::Request)?;
        let mut frame = vec![0_u8; total];
        frame[..request_len].copy_from_slice(&request[..request_len]);
        encoder.assemble(&preamble, &[], &mut frame[request_len..]);
        encoder.commit(&preamble);

        let mut record = Vec::new();
        session
            .write_mut()
            .seal_into(ContentType::ApplicationData, &frame, 0, &mut record)
            .map_err(|_| VisionTunnelError::Record)?;
        stream
            .write_all(&record)
            .await
            .map_err(VisionTunnelError::Io)?;
        stream.flush().await.map_err(VisionTunnelError::Io)?;

        let mut tunnel = Self {
            stream,
            session,
            encoder,
            decoder: VisionDecoder::new(user_id),
            downlink: VisionMode::Framed,
            readable: Vec::with_capacity(MAX_PLAINTEXT_LEN),
            readable_at: 0,
            encoder_done: false,
        };
        tunnel.await_response().await?;
        Ok(tunnel)
    }

    async fn await_response(&mut self) -> Result<(), VisionTunnelError> {
        // First downlink record is `[VERSION, addons_len, …addons] || Vision…`.
        // Peel the VLESS response before any Vision decode.
        let mut response_buf = Vec::new();
        loop {
            let plaintext = self.read_raw_application().await?;
            if plaintext.is_empty() {
                continue;
            }
            response_buf.extend_from_slice(&plaintext);
            match decode_response(&response_buf) {
                Ok(decoded) => {
                    let payload = decoded.payload().to_vec();
                    self.readable.clear();
                    self.readable_at = 0;
                    if !payload.is_empty() {
                        self.ingest_plaintext(&payload)?;
                    }
                    return Ok(());
                }
                Err(ResponseDecodeError::Incomplete { .. }) => continue,
                Err(_) => return Err(VisionTunnelError::Request),
            }
        }
    }

    async fn read_and_open_record(&mut self) -> Result<(), VisionTunnelError> {
        let plaintext = self.read_raw_application().await?;
        if plaintext.is_empty() {
            return Ok(());
        }
        self.ingest_plaintext(&plaintext)
    }

    /// Opens one application-data record (or skips ChangeCipherSpec) and returns
    /// the plaintext bytes without Vision framing.
    async fn read_raw_application(&mut self) -> Result<Vec<u8>, VisionTunnelError> {
        loop {
            let mut header = [0_u8; 5];
            self.stream.read_exact(&mut header).await.map_err(|e| {
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    VisionTunnelError::ClosedBeforeResponse
                } else {
                    VisionTunnelError::Io(e)
                }
            })?;
            let body_len = usize::from(u16::from_be_bytes([header[3], header[4]]));
            if body_len + 5 > MAX_TLS_RECORD_WIRE_LEN {
                return Err(VisionTunnelError::Record);
            }
            let mut body = vec![0_u8; body_len];
            self.stream
                .read_exact(&mut body)
                .await
                .map_err(VisionTunnelError::Io)?;
            match header[0] {
                20 => continue,
                23 => {
                    let mut record = Vec::with_capacity(5 + body_len);
                    record.extend_from_slice(&header);
                    record.extend_from_slice(&body);
                    let opened = self
                        .session
                        .read_mut()
                        .open_in_place(&mut record)
                        .map_err(|_| VisionTunnelError::Record)?;
                    return Ok(opened.plaintext().to_vec());
                }
                _ => return Err(VisionTunnelError::Record),
            }
        }
    }

    fn ingest_plaintext(&mut self, plaintext: &[u8]) -> Result<(), VisionTunnelError> {
        match self.downlink {
            VisionMode::Direct | VisionMode::Raw => {
                self.readable.extend_from_slice(plaintext);
                Ok(())
            }
            VisionMode::Framed => {
                let mut staged = Vec::new();
                let mode = self
                    .decoder
                    .decode_append(plaintext, &mut staged)
                    .map_err(|_| VisionTunnelError::Vision)?;
                self.readable.extend_from_slice(&staged);
                self.downlink = mode;
                if matches!(mode, VisionMode::Direct) {
                    self.encoder_done = true;
                }
                Ok(())
            }
        }
    }

    /// Relays application bytes between a local SOCKS stream and this tunnel.
    pub async fn relay<S>(&mut self, local: &mut S) -> Result<(), VisionTunnelError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut local_buf = vec![0_u8; 16 * 1024];
        loop {
            tokio::select! {
                ready = self.poll_fill_readable() => {
                    ready?;
                    if self.readable_at < self.readable.len() {
                        let chunk = &self.readable[self.readable_at..];
                        local.write_all(chunk).await.map_err(VisionTunnelError::Io)?;
                        local.flush().await.map_err(VisionTunnelError::Io)?;
                        self.readable_at = self.readable.len();
                        if self.readable_at > 64 * 1024 {
                            self.readable.clear();
                            self.readable_at = 0;
                        }
                    }
                }
                read = local.read(&mut local_buf) => {
                    let n = read.map_err(VisionTunnelError::Io)?;
                    if n == 0 {
                        return Ok(());
                    }
                    self.write_application(&local_buf[..n]).await?;
                }
            }
        }
    }

    async fn poll_fill_readable(&mut self) -> Result<(), VisionTunnelError> {
        if self.readable_at < self.readable.len() {
            return Ok(());
        }
        self.read_and_open_record().await
    }

    async fn write_application(&mut self, payload: &[u8]) -> Result<(), VisionTunnelError> {
        if payload.is_empty() {
            return Ok(());
        }
        if self.encoder_done {
            return self.seal_and_send(payload).await;
        }
        let mut offset = 0;
        while offset < payload.len() {
            let want = (payload.len() - offset).min(8 * 1024);
            let planned = self.encoder.plan(want, VisionCommand::Continue, false);
            let Ok(plan) = planned else {
                self.encoder_done = true;
                return self.seal_and_send(&payload[offset..]).await;
            };
            let content = &payload[offset..offset + want];
            let mut frame = vec![0_u8; plan.wire_len()];
            self.encoder.assemble(&plan, content, &mut frame);
            self.encoder.commit(&plan);
            self.seal_and_send(&frame).await?;
            offset += want;
        }
        self.stream.flush().await.map_err(VisionTunnelError::Io)?;
        Ok(())
    }

    async fn seal_and_send(&mut self, plaintext: &[u8]) -> Result<(), VisionTunnelError> {
        let mut record = Vec::new();
        self.session
            .write_mut()
            .seal_into(ContentType::ApplicationData, plaintext, 0, &mut record)
            .map_err(|_| VisionTunnelError::Record)?;
        self.stream
            .write_all(&record)
            .await
            .map_err(VisionTunnelError::Io)?;
        Ok(())
    }
}
