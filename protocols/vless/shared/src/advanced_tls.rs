mod config;
mod ech;
mod ocsp;
pub use ech::{TlsNetwork, TlsNetworkRequest, TlsNetworkResponse};
pub(crate) mod fingerprint;
mod quic;
pub use quic::{advanced_quic_client_config, advanced_quic_server_config};

pub use config::{
    advanced_client_config, advanced_server_config, AdvancedTlsClientCache,
    AdvancedTlsClientConfig, AdvancedTlsOptions, AdvancedTlsServerConfig, TlsCertificate,
};

use boring2::ssl::{ErrorCode, NameType, Ssl, SslStream, SslVersion};
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::ops::{Deref, DerefMut};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex, MutexGuard, RwLock,
};

#[derive(Default)]
struct MemoryIo {
    input: VecDeque<u8>,
    output: Vec<u8>,
}

impl Read for MemoryIo {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if self.input.is_empty() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.input.read(bytes)
    }
}

impl Write for MemoryIo {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.output.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

type Core = Arc<Mutex<SslStream<MemoryIo>>>;

pub struct AdvancedTlsRead<R> {
    core: Core,
    control: Arc<ControlRelay>,
    inner: R,
    record: Vec<u8>,
    direct: bool,
    pending_error: Option<io::Error>,
}

pub struct AdvancedTlsWrite<W> {
    core: Core,
    state: Arc<Mutex<WriterState<W>>>,
    control: Arc<ControlRelay>,
}

struct WriterState<W> {
    inner: Option<W>,
    wire: Vec<u8>,
    sent: usize,
    retry: Option<Vec<u8>>,
    direct: bool,
}

trait ControlWriter: Send + Sync {
    fn flush_control(&self, core: &Core, pending: &AtomicBool) -> io::Result<()>;
}
struct ControlRelay {
    writer: RwLock<Arc<dyn ControlWriter>>,
    pending: AtomicBool,
}
impl ControlRelay {
    fn flush(&self, core: &Core) -> io::Result<()> {
        self.writer
            .read()
            .expect("TLS writer mapping")
            .flush_control(core, &self.pending)
    }
}

pub fn connect_advanced_tls_over<R: Read, W: Write + Send + 'static>(
    read: R,
    write: W,
    config: Arc<AdvancedTlsClientConfig>,
    name: &str,
) -> io::Result<(AdvancedTlsRead<R>, AdvancedTlsWrite<W>)> {
    let ssl = config.ssl(name)?;
    let (reader, writer) = handshake(read, write, ssl, false)?;
    let core = reader.core.lock().expect("TLS state");
    config.verify(core.ssl(), name)?;
    drop(core);
    Ok((reader, writer))
}

pub fn accept_advanced_tls_over<R: Read, W: Write + Send + 'static>(
    read: R,
    write: W,
    config: Arc<AdvancedTlsServerConfig>,
) -> io::Result<(AdvancedTlsRead<R>, AdvancedTlsWrite<W>)> {
    handshake(read, write, config.ssl()?, true)
}

fn handshake<R: Read, W: Write + Send + 'static>(
    mut read: R,
    mut write: W,
    ssl: Ssl,
    server: bool,
) -> io::Result<(AdvancedTlsRead<R>, AdvancedTlsWrite<W>)> {
    let mut core = SslStream::new(ssl, MemoryIo::default()).map_err(io::Error::other)?;
    let mut record = Vec::new();
    loop {
        let result = if server {
            core.accept()
        } else {
            core.connect()
        };
        write.write_all(&std::mem::take(&mut core.get_mut().output))?;
        write.flush()?;
        match result {
            Ok(()) => break,
            Err(error) if error.code() == ErrorCode::WANT_READ => {
                read_record(&mut read, &mut record)?;
                core.get_mut().input.extend(record.drain(..));
            }
            Err(error) => return Err(io::Error::other(error)),
        }
    }
    let core = Arc::new(Mutex::new(core));
    let state = Arc::new(Mutex::new(WriterState {
        inner: Some(write),
        wire: Vec::new(),
        sent: 0,
        retry: None,
        direct: false,
    }));
    let control = Arc::new(ControlRelay {
        writer: RwLock::new(state.clone()),
        pending: AtomicBool::new(false),
    });
    Ok((
        AdvancedTlsRead {
            core: core.clone(),
            control: control.clone(),
            inner: read,
            record,
            direct: false,
            pending_error: None,
        },
        AdvancedTlsWrite {
            core,
            state,
            control,
        },
    ))
}

fn read_record(read: &mut impl Read, record: &mut Vec<u8>) -> io::Result<()> {
    loop {
        let needed = if record.len() < 5 {
            5
        } else {
            5 + u16::from_be_bytes([record[3], record[4]]) as usize
        };
        if needed > 18437 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS record too large",
            ));
        }
        if record.len() == needed && needed >= 5 {
            return Ok(());
        }
        let mut buffer = [0; 16384];
        let limit = (needed - record.len()).min(buffer.len());
        match read.read(&mut buffer[..limit]) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "TLS peer closed without close_notify",
                ))
            }
            Ok(n) => record.extend_from_slice(&buffer[..n]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}

impl<R> AdvancedTlsRead<R> {
    pub fn inner_mut(&mut self) -> &mut R {
        &mut self.inner
    }
    pub fn map_inner<S>(self, map: impl FnOnce(R) -> S) -> AdvancedTlsRead<S> {
        AdvancedTlsRead {
            core: self.core,
            control: self.control,
            inner: map(self.inner),
            record: self.record,
            direct: self.direct,
            pending_error: self.pending_error,
        }
    }
    pub fn start_direct(&mut self) -> io::Result<()> {
        if !self.record.is_empty()
            || !self
                .core
                .lock()
                .expect("TLS state")
                .get_ref()
                .input
                .is_empty()
        {
            return Err(io::Error::other("partial TLS record"));
        }
        self.direct = true;
        Ok(())
    }
    pub fn needs_write(&self) -> bool {
        self.control.pending.load(Ordering::Acquire)
    }
    pub fn alpn(&self) -> Option<Vec<u8>> {
        self.core
            .lock()
            .expect("TLS state")
            .ssl()
            .selected_alpn_protocol()
            .map(<[u8]>::to_vec)
    }
    pub fn is_tls13(&self) -> bool {
        self.core.lock().expect("TLS state").ssl().version() == Some(SslVersion::TLS1_3)
    }
    /// Whether the negotiated version is below TLS 1.2, and the negotiated cipher suite id.
    pub fn h2_security(&self) -> (bool, u16) {
        let core = self.core.lock().expect("TLS state");
        let ssl = core.ssl();
        let old = matches!(ssl.version(), Some(version) if version == SslVersion::TLS1 || version == SslVersion::TLS1_1);
        (old, ssl.current_cipher().map_or(0, |cipher| cipher.protocol_id()))
    }
    pub fn protocol_version(&self) -> String {
        self.core
            .lock()
            .expect("TLS state")
            .ssl()
            .version_str()
            .to_string()
    }
    pub fn ech_accepted(&self) -> bool {
        self.core.lock().expect("TLS state").ssl().ech_accepted()
    }
    pub fn session_reused(&self) -> bool {
        self.core.lock().expect("TLS state").ssl().session_reused()
    }
    pub fn identity(&self) -> (String, String) {
        let core = self.core.lock().expect("TLS state");
        (
            core.ssl()
                .servername(NameType::HOST_NAME)
                .unwrap_or_default()
                .to_string(),
            String::from_utf8_lossy(core.ssl().selected_alpn_protocol().unwrap_or_default())
                .into_owned(),
        )
    }
}

impl<R: Read> Read for AdvancedTlsRead<R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if let Some(error) = self.pending_error.take() {
            return Err(error);
        }
        loop {
            if self.needs_write() {
                self.control.flush(&self.core)?;
            }
            let result = {
                let mut core = self.core.lock().expect("TLS state");
                // Decrypted bytes from the final padded Vision record precede DIRECT bytes.
                let result = if !self.direct || core.ssl().pending() > 0 {
                    Some(core.ssl_read(bytes))
                } else {
                    None
                };
                if !self.direct
                    && result.as_ref().is_some_and(|result| match result {
                        Ok(_) => true,
                        Err(error) => error.code() == ErrorCode::WANT_READ,
                    })
                {
                    if let Err(error) = core.flush_tls() {
                        if result.as_ref().is_some_and(Result::is_ok) {
                            self.pending_error = Some(io::Error::other(error));
                        } else {
                            return Err(io::Error::other(error));
                        }
                    }
                }
                if !core.get_ref().output.is_empty() {
                    self.control.pending.store(true, Ordering::Release);
                }
                result
            };
            if self.needs_write() {
                if let Err(error) = self.control.flush(&self.core) {
                    if let Some(Ok(n)) = result {
                        if !matches!(
                            error.kind(),
                            io::ErrorKind::WouldBlock
                                | io::ErrorKind::TimedOut
                                | io::ErrorKind::Interrupted
                        ) {
                            self.pending_error = Some(error);
                        }
                        return Ok(n);
                    }
                    return Err(error);
                }
            }
            match result {
                Some(Ok(n)) => return Ok(n),
                Some(Err(error)) if error.code() == ErrorCode::ZERO_RETURN => return Ok(0),
                Some(Err(error)) if error.code() == ErrorCode::WANT_READ => {}
                Some(Err(error)) => return Err(io::Error::other(error)),
                None => {}
            }
            if self.direct {
                return self.inner.read(bytes);
            }
            read_record(&mut self.inner, &mut self.record)?;
            self.core
                .lock()
                .expect("TLS state")
                .get_mut()
                .input
                .extend(self.record.drain(..));
        }
    }
}

impl<W> AdvancedTlsWrite<W> {
    pub fn inner_mut(&mut self) -> impl DerefMut<Target = W> + '_ {
        InnerGuard(self.state.lock().expect("TLS writer"))
    }
}

struct InnerGuard<'a, W>(MutexGuard<'a, WriterState<W>>);
impl<W> Deref for InnerGuard<'_, W> {
    type Target = W;
    fn deref(&self) -> &W {
        self.0.inner.as_ref().expect("TLS writer mapping")
    }
}
impl<W> DerefMut for InnerGuard<'_, W> {
    fn deref_mut(&mut self) -> &mut W {
        self.0.inner.as_mut().expect("TLS writer mapping")
    }
}

impl<W: Write + Send + 'static> AdvancedTlsWrite<W> {
    pub fn map_inner<S: Write + Send + 'static>(
        self,
        map: impl FnOnce(W) -> S,
    ) -> AdvancedTlsWrite<S> {
        let mut relay = self.control.writer.write().expect("TLS writer mapping");
        let mut old = self.state.lock().expect("TLS writer");
        let state = Arc::new(Mutex::new(WriterState {
            inner: Some(map(old.inner.take().expect("TLS writer"))),
            wire: std::mem::take(&mut old.wire),
            sent: old.sent,
            retry: old.retry.take(),
            direct: old.direct,
        }));
        *relay = state.clone();
        drop(old);
        drop(relay);
        AdvancedTlsWrite {
            core: self.core,
            state,
            control: self.control,
        }
    }
}

impl<W: Write + Send> AdvancedTlsWrite<W> {
    pub fn start_direct(&mut self) -> io::Result<()> {
        let mut state = self.state.lock().expect("TLS writer");
        if state.retry.is_some() {
            return Err(io::Error::other("TLS write must finish before DIRECT"));
        }
        state.flush_control(&self.core, &self.control.pending)?;
        state.direct = true;
        Ok(())
    }
}

impl<W: Write> WriterState<W> {
    fn drain(&mut self) -> io::Result<()> {
        while self.sent < self.wire.len() {
            match self
                .inner
                .as_mut()
                .expect("TLS writer mapping")
                .write(&self.wire[self.sent..])
            {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(n) => self.sent += n,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        self.wire.clear();
        self.sent = 0;
        Ok(())
    }
    fn flush_control(&mut self, core: &Core, pending: &AtomicBool) -> io::Result<()> {
        if self.direct {
            if pending.load(Ordering::Acquire) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "TLS control record after DIRECT",
                ));
            }
            return self.inner.as_mut().expect("TLS writer mapping").flush();
        }
        loop {
            let empty = {
                let mut core = core.lock().expect("TLS state");
                core.flush_tls().map_err(io::Error::other)?;
                self.wire.append(&mut core.get_mut().output);
                self.wire.is_empty()
            };
            if empty {
                self.inner.as_mut().expect("TLS writer mapping").flush()?;
                let core = core.lock().expect("TLS state");
                if core.get_ref().output.is_empty() {
                    pending.store(false, Ordering::Release);
                    return Ok(());
                }
                continue;
            }
            self.drain()?;
        }
    }
}

impl<W: Write + Send> ControlWriter for Mutex<WriterState<W>> {
    fn flush_control(&self, core: &Core, pending: &AtomicBool) -> io::Result<()> {
        self.lock()
            .expect("TLS writer")
            .flush_control(core, pending)
    }
}

impl<W: Write + Send> Write for AdvancedTlsWrite<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        let mut state = self.state.lock().expect("TLS writer");
        if state.direct {
            return state
                .inner
                .as_mut()
                .expect("TLS writer mapping")
                .write(bytes);
        }
        if let Some(retry) = &state.retry {
            if !bytes.starts_with(retry) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "TLS retry changed plaintext",
                ));
            }
            let n = retry.len();
            state.drain()?;
            state.retry = None;
            return Ok(n);
        }
        let n = {
            let mut core = self.core.lock().expect("TLS state");
            let n = core
                .ssl_write(&bytes[..bytes.len().min(16384)])
                .map_err(io::Error::other)?;
            state.wire.append(&mut core.get_mut().output);
            n
        };
        if let Err(error) = state.drain() {
            state.retry = Some(bytes[..n].to_vec());
            return Err(error);
        }
        if self.control.pending.load(Ordering::Acquire)
            && state
                .inner
                .as_mut()
                .expect("TLS writer mapping")
                .flush()
                .is_ok()
        {
            let core = self.core.lock().expect("TLS state");
            if core.get_ref().output.is_empty() {
                self.control.pending.store(false, Ordering::Release);
            }
        }
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.state
            .lock()
            .expect("TLS writer")
            .flush_control(&self.core, &self.control.pending)
    }
}

#[cfg(test)]
mod tests;
