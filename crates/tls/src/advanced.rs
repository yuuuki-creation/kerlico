mod config;
mod ech;
mod ocsp;
mod receive;
mod records;
pub use ech::{TlsNetwork, TlsNetworkRequest, TlsNetworkResponse};
pub mod fingerprint;
#[cfg(feature = "quic")]
mod quic;
#[cfg(feature = "quic")]
pub use quic::{advanced_quic_client_config, advanced_quic_server_config};

pub use config::{
    advanced_client_config, advanced_server_config, AdvancedTlsClientCache,
    AdvancedTlsClientConfig, AdvancedTlsOptions, AdvancedTlsServerConfig, TlsCertificate,
};

use boring2::ssl::{ErrorCode, NameType, ShutdownState, Ssl, SslStream, SslVersion};
use foreign_types::{ForeignType, ForeignTypeRef};
use std::collections::VecDeque;
use std::io::{self, IoSlice, Read, Write};
use std::ops::{Deref, DerefMut, Range};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex, MutexGuard, RwLock,
};

#[derive(Default)]
struct MemoryIo {
    input: VecDeque<u8>,
    record: Option<(Vec<u8>, Range<usize>)>,
    output: Vec<u8>,
    terminal_write: bool,
}

impl MemoryIo {
    fn reclaim_record(&mut self, wire: &mut Vec<u8>) {
        if let Some((buffer, remaining)) = self.record.take() {
            // If TLS did not consume the whole record, keep the residue ahead of
            // the next record while returning the read-ahead buffer to the reader.
            if !remaining.is_empty() {
                self.input.extend(&buffer[remaining]);
            }
            *wire = buffer;
        }
    }
}

impl Read for MemoryIo {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if !self.input.is_empty() {
            return self.input.read(bytes);
        }
        if let Some((wire, range)) = &mut self.record {
            let len = range.len().min(bytes.len());
            if len != 0 {
                bytes[..len].copy_from_slice(&wire[range.start..range.start + len]);
                range.start += len;
                return Ok(len);
            }
        }
        Err(io::ErrorKind::WouldBlock.into())
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

fn flush_open_tls(core: &mut SslStream<MemoryIo>) -> Result<(), boring2::ssl::Error> {
    // flush_tls uses SSL_write with an empty application buffer. Once the
    // write half has sent close_notify, that call is forbidden even though the
    // read half may still receive application bytes. Already sealed output is
    // drained by WriterState without creating another application write.
    if core.get_ref().terminal_write || core.get_shutdown().contains(ShutdownState::SENT) {
        Ok(())
    } else {
        core.flush_tls()
    }
}

/// The longest record accepted on the wire, header included.
const MAX_RECORD: usize = 18437;
/// The wire bytes a reader holds at most. Several full records fit, so one read from the socket
/// brings every record that already arrived.
const READ_AHEAD: usize = 4 * MAX_RECORD;
/// The plaintext one write seals at most. Its records leave in one write to the socket.
const WRITE_BATCH: usize = 4 * 16384;

pub struct AdvancedTlsRead<R> {
    core: Core,
    control: Arc<ControlRelay>,
    inner: R,
    /// `wire[head..tail]` arrived and was not handed to the TLS state yet. The state gets one
    /// whole record at a time, so it never holds bytes past a record: what follows the last
    /// record of a Vision stream stays here and is returned as it arrived.
    wire: Vec<u8>,
    head: usize,
    tail: usize,
    grow_read: bool,
    rx: Option<records::Receiver>,
    plaintext: VecDeque<Range<usize>>,
    closed: bool,
    session_cache: Option<Arc<AdvancedTlsClientConfig>>,
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
    connect_advanced_tls_configured(read, write, config, name, |_| Ok(()))
}

/// Runs the usual TLS handshake with a transport-specific first ClientHello mutation.
pub fn connect_advanced_tls_with_hello<R: Read, W: Write + Send + 'static>(
    read: R,
    write: W,
    config: Arc<AdvancedTlsClientConfig>,
    name: &str,
    callback: impl Fn(&[u8], &mut [u8; 32], &mut [u8]) -> bool + Send + Sync + 'static,
) -> io::Result<(AdvancedTlsRead<R>, AdvancedTlsWrite<W>)> {
    connect_advanced_tls_configured(read, write, config, name, |ssl| {
        ssl.set_client_hello_mutator(callback)
            .map_err(io::Error::other)
    })
}

/// Supplies public shares that will be reused by the TLS 1.2 ClientKeyExchange.
pub fn connect_advanced_tls_with_tls12_shares<R: Read, W: Write + Send + 'static>(
    read: R,
    write: W,
    config: Arc<AdvancedTlsClientConfig>,
    name: &str,
    groups: &[u16],
    callback: impl Fn(&[u8], &[Vec<u8>], &mut [u8]) -> bool + Send + Sync + 'static,
) -> io::Result<(AdvancedTlsRead<R>, AdvancedTlsWrite<W>)> {
    connect_advanced_tls_configured(read, write, config, name, |ssl| {
        let public = ssl.prepare_tls12_shares(groups).map_err(io::Error::other)?;
        ssl.set_client_hello_mutator(move |hello, _, session| callback(hello, &public, session))
            .map_err(io::Error::other)
    })
}

fn connect_advanced_tls_configured<R: Read, W: Write + Send + 'static>(
    read: R,
    write: W,
    config: Arc<AdvancedTlsClientConfig>,
    name: &str,
    configure: impl FnOnce(&mut Ssl) -> io::Result<()>,
) -> io::Result<(AdvancedTlsRead<R>, AdvancedTlsWrite<W>)> {
    let mut ssl = config.ssl(name)?;
    configure(&mut ssl)?;
    let (mut reader, writer) = handshake(read, write, ssl, false)?;
    let core = reader.core.lock().expect("TLS state");
    config.verify(core.ssl(), name)?;
    drop(core);
    reader.session_cache = Some(config);
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
    mut ssl: Ssl,
    server: bool,
) -> io::Result<(AdvancedTlsRead<R>, AdvancedTlsWrite<W>)> {
    let capture = records::capture(&mut ssl);
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
    let rx = records::Receiver::from_handshake(core.ssl(), capture)?;
    if rx.is_some() && (!core.get_ref().input.is_empty() || core.ssl().pending() != 0) {
        return Err(io::Error::other("TLS handshake left application data"));
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
            wire: Vec::new(),
            head: 0,
            tail: 0,
            grow_read: false,
            rx,
            plaintext: VecDeque::new(),
            closed: false,
            session_cache: None,
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
        if needed > MAX_RECORD {
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
            wire: self.wire,
            head: self.head,
            tail: self.tail,
            grow_read: self.grow_read,
            rx: self.rx,
            plaintext: self.plaintext,
            closed: self.closed,
            session_cache: self.session_cache,
            direct: self.direct,
            pending_error: self.pending_error,
        }
    }
    /// Ends the record layer. What the reader took from the wire past the last record is
    /// returned as it arrived.
    pub fn start_direct(&mut self) -> io::Result<()> {
        if !self
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
        (
            old,
            ssl.current_cipher()
                .map_or(0, |cipher| cipher.protocol_id()),
        )
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

    /// Authenticate one TLS record that was read by an outer carrier after
    /// the handshake. The record may contain TLS metadata, but no app data or
    /// message that requires a TLS reply.
    pub fn consume_tls_metadata(&mut self, record: &[u8]) -> io::Result<bool> {
        if self.direct
            || self.head != self.tail
            || !self.plaintext.is_empty()
            || record.len() > MAX_RECORD
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        if let Some(rx) = &mut self.rx {
            let mut record = record.to_vec();
            let (kind, len) = rx.open(&mut record)?;
            if kind == 23 {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let messages = rx.control(kind, &record[5..5 + len])?;
            if messages
                .iter()
                .any(|m| matches!(m, records::Message::KeyUpdate(true)))
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            self.process_messages(messages)?;
            return Ok(!self.closed);
        }
        let mut core = self.core.lock().expect("TLS state");
        core.get_mut().input.extend(record);
        let result = core.ssl_read(&mut [0; 1]);
        if !core.get_ref().input.is_empty() || !core.get_ref().output.is_empty() {
            return Err(io::ErrorKind::InvalidData.into());
        }
        match result {
            Err(error) if error.code() == ErrorCode::WANT_READ => Ok(true),
            Err(error) if error.code() == ErrorCode::ZERO_RETURN => Ok(false),
            Err(error) => Err(io::Error::other(error)),
            Ok(_) => Err(io::ErrorKind::InvalidData.into()),
        }
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
        if self.rx.is_some() && !self.direct {
            self.fill_tls13_records(1)?;
            return Ok(self.copy_plaintext(bytes));
        }
        if !self.plaintext.is_empty() {
            return Ok(self.copy_plaintext(bytes));
        }
        if let Some(error) = self.pending_error.take() {
            return Err(error);
        }
        loop {
            if self.needs_write() {
                if let Err(error) = self.control.flush(&self.core) {
                    self.core
                        .lock()
                        .expect("TLS state")
                        .get_mut()
                        .reclaim_record(&mut self.wire);
                    return Err(error);
                }
            }
            let result = {
                let mut core = self.core.lock().expect("TLS state");
                // Decrypted bytes from the final padded Vision record precede DIRECT bytes.
                let result = if !self.direct || core.ssl().pending() > 0 {
                    Some(core.ssl_read(bytes))
                } else {
                    None
                };
                let flushed = if !self.direct
                    && result.as_ref().is_some_and(|result| match result {
                        Ok(_) => true,
                        Err(error) => error.code() == ErrorCode::WANT_READ,
                    }) {
                    flush_open_tls(&mut core)
                } else {
                    Ok(())
                };
                core.get_mut().reclaim_record(&mut self.wire);
                if let Err(error) = flushed {
                    if result.as_ref().is_some_and(Result::is_ok) {
                        self.pending_error = Some(io::Error::other(error));
                    } else {
                        return Err(io::Error::other(error));
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
                if self.head == self.tail {
                    return self.inner.read(bytes);
                }
                let len = (self.tail - self.head).min(bytes.len());
                bytes[..len].copy_from_slice(&self.wire[self.head..self.head + len]);
                self.head += len;
                return Ok(len);
            }
            self.feed_record()?;
        }
    }
}

impl<R: Read> AdvancedTlsRead<R> {
    /// Hands the TLS state the next whole record, reading from the socket until it is there.
    /// A read takes whatever arrived, so the records behind it need no read of their own.
    fn feed_record(&mut self) -> io::Result<()> {
        loop {
            let have = self.tail - self.head;
            let needed = self.next_record_len()?;
            if have >= needed {
                let mut core = self.core.lock().expect("TLS state");
                let io = core.get_mut();
                let end = self.head + needed;
                debug_assert!(io.record.is_none());
                io.record = Some((std::mem::take(&mut self.wire), self.head..end));
                self.head = end;
                if self.head == self.tail {
                    self.head = 0;
                    self.tail = 0;
                }
                return Ok(());
            }
            self.read_wire()?;
        }
    }

    fn read_wire(&mut self) -> io::Result<()> {
        debug_assert!(self.plaintext.is_empty());
        if self.head == self.tail {
            self.head = 0;
            self.tail = 0;
        }
        loop {
            if self.grow_read && self.wire.len() < READ_AHEAD {
                self.wire
                    .resize((self.wire.len() * 2).clamp(4096, READ_AHEAD), 0);
            }
            self.grow_read = false;
            // Keep consuming the initialized tail before moving the small
            // incomplete record. Growing after a full socket read must not be
            // prevented merely because one complete TLS record was consumed.
            if self.head > 0 && self.wire.len() - self.tail < MAX_RECORD {
                self.wire.copy_within(self.head..self.tail, 0);
                self.tail -= self.head;
                self.head = 0;
            }
            if self.tail == self.wire.len() {
                // A reader that fills its buffer gets a larger one, so bulk traffic comes in few reads.
                let len = (self.wire.len() * 2).clamp(4096, READ_AHEAD);
                self.wire.resize(len, 0);
            }
            let available = self.wire.len() - self.tail;
            match self.inner.read(&mut self.wire[self.tail..]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "TLS peer closed without close_notify",
                    ))
                }
                Ok(len) => {
                    self.tail += len;
                    self.grow_read = len == available;
                    return Ok(());
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
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
    pub fn send_close_notify(&mut self) -> io::Result<()> {
        self.flush()?;
        let mut state = self.state.lock().expect("TLS writer");
        if state.direct {
            return Err(io::Error::other("TLS is no longer active"));
        }
        {
            let mut core = self.core.lock().expect("TLS state");
            match core.shutdown() {
                Ok(_) => {}
                Err(error) if error.code() == ErrorCode::WANT_READ => {}
                Err(error) => return Err(io::Error::other(error)),
            }
            state.take_output(&mut core.get_mut().output);
        }
        state.drain()
    }

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
    fn take_output(&mut self, output: &mut Vec<u8>) {
        if self.wire.is_empty() {
            if !output.is_empty() {
                std::mem::swap(&mut self.wire, output);
            }
        } else {
            self.wire.append(output);
        }
    }

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
                flush_open_tls(&mut core).map_err(io::Error::other)?;
                self.take_output(&mut core.get_mut().output);
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
        // A tail shorter than a record leaves with the batch, not in a write of its own.
        let limit = if bytes.len() < WRITE_BATCH + 16384 {
            bytes.len()
        } else {
            WRITE_BATCH
        };
        let n = {
            let mut core = self.core.lock().expect("TLS state");
            let n = core.ssl_write(&bytes[..limit]).map_err(io::Error::other)?;
            state.take_output(&mut core.get_mut().output);
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
