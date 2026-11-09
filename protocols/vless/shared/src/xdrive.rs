//! XDrive carries a byte stream through ordered objects in shared storage.

use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{self, Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::Deserialize;

#[cfg(test)]
mod backend_tests;
mod drive;
mod ring;
mod s3;
mod service_http;
mod template;

const MAX_SEGMENT_BYTES: usize = 16 * 1024 * 1024;
const TEMP_PREFIX: &str = ".xdrive-tmp-";

/// Security and endpoint override for HTTP-backed storage services.
#[derive(Clone, Default)]
pub struct XdriveHttpOptions {
    pub tls: Option<Arc<crate::AdvancedTlsClientConfig>>,
    pub quic: Option<crate::QuicClientCrypto>,
    pub masks: crate::finalmask::FinalMask,
    pub server_name: Option<String>,
    pub connect_to: Option<(String, u16)>,
}

#[derive(Deserialize, Default)]
#[serde(default, rename_all = "camelCase")]
struct Config {
    service: String,
    remote_folder: PathBuf,
    secrets: Vec<String>,
    template: serde_json::Value,
    s3: Option<s3::S3Config>,
    segment_bytes: usize,
    flush_interval_ms: u64,
    poll_interval_ms: u64,
    max_poll_interval_ms: u64,
    session_ttl_seconds: u64,
    concurrency: usize,
    eager_window_ms: u64,
    hole_timeout_ms: u64,
    xmux: serde_json::Value,
}

#[derive(Clone, Copy)]
struct Params {
    segment_bytes: usize,
    flush_interval: Duration,
    min_poll: Duration,
    max_poll: Duration,
    session_ttl: Duration,
    concurrency: usize,
    eager_window: Duration,
    hole_timeout: Duration,
}

impl From<&Config> for Params {
    fn from(config: &Config) -> Self {
        let poll = milliseconds(config.poll_interval_ms, 50);
        Self {
            segment_bytes: nonzero(config.segment_bytes, 512 * 1024).min(MAX_SEGMENT_BYTES),
            flush_interval: milliseconds(config.flush_interval_ms, 20),
            min_poll: poll,
            max_poll: milliseconds(config.max_poll_interval_ms, 500).max(poll),
            session_ttl: Duration::from_secs(nonzero(config.session_ttl_seconds, 300)),
            concurrency: nonzero(config.concurrency, 8).min(64),
            eager_window: milliseconds(config.eager_window_ms, 2_000),
            hole_timeout: milliseconds(config.hole_timeout_ms, 30_000),
        }
    }
}

fn nonzero<T: Default + PartialEq>(value: T, default: T) -> T {
    if value == T::default() {
        default
    } else {
        value
    }
}

fn milliseconds(value: u64, default: u64) -> Duration {
    Duration::from_millis(nonzero(value, default))
}

#[derive(Clone)]
pub struct Xdrive {
    storage: Arc<dyn Storage>,
    params: Params,
}

impl Xdrive {
    /// Reads the Xray `xdriveSettings` object. HTTP options apply to the storage connection.
    pub fn new(settings: &str, http: XdriveHttpOptions) -> io::Result<Self> {
        let config: Config = serde_json::from_str(settings).map_err(invalid)?;
        let storage: Arc<dyn Storage> = match config.service.as_str() {
            "local" => Arc::new(LocalStorage::new(&config.remote_folder)?),
            "template" => Arc::new(template::TemplateStorage::new(&config, http)?),
            "s3" => Arc::new(s3::S3Storage::new(&config, http)?),
            "google-drive" | "Google Drive" => Arc::new(drive::DriveStorage::new(&config, http)?),
            service => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("XDrive service {service}"),
                ))
            }
        };
        Ok(Self {
            storage,
            params: Params::from(&config),
        })
    }

    pub fn local(folder: impl AsRef<Path>) -> io::Result<Self> {
        Ok(Self {
            storage: Arc::new(LocalStorage::new(folder.as_ref())?),
            params: Params::from(&Config::default()),
        })
    }

    pub fn dial(&self) -> io::Result<(XdriveRead, XdriveWrite)> {
        let session = random_id()?;
        let announce = format!("sessions/{}-{session}", unix_nanos()?);
        let ring = self
            .storage
            .slots()
            .and_then(|slots| ring::Ring::make(slots, &session, self.params.concurrency).ok());
        let body = ring
            .as_ref()
            .map(serde_json::to_vec)
            .transpose()
            .map_err(invalid)?
            .unwrap_or_default();
        self.storage.put(&announce, &body)?;
        match self.open(&session, true, ring, None) {
            Ok(connection) => Ok(connection),
            Err(error) => {
                let _ = self.storage.delete(&announce);
                Err(error)
            }
        }
    }

    pub fn listen(&self) -> io::Result<XdriveListener> {
        Ok(XdriveListener {
            drive: self.clone(),
            handled: HashMap::new(),
            idle_since: HashMap::new(),
            active: Arc::new(Mutex::new(HashSet::new())),
            collected: Instant::now(),
        })
    }

    fn open(
        &self,
        session: &str,
        client: bool,
        ring: Option<ring::Ring>,
        guard: Option<Arc<ActiveSession>>,
    ) -> io::Result<(XdriveRead, XdriveWrite)> {
        let storage = self.storage.session().unwrap_or_else(|| self.storage.clone());
        let (write_source, read_source) = if let Some(ring) = ring {
            let (write, read) = ring.directions(client);
            (Medium::Slots(write), Medium::Slots(read))
        } else {
            let (write, read) = if client {
                ("c2s", "s2c")
            } else {
                ("s2c", "c2s")
            };
            (
                Medium::Segments(format!("streams/{session}/{write}")),
                Medium::Segments(format!("streams/{session}/{read}")),
            )
        };
        let read = XdriveRead::start(
            storage.clone(),
            read_source,
            self.params,
            guard.clone(),
        )?;
        let write = XdriveWrite::start(
            storage,
            write_source,
            self.params,
            read.worker.clone(),
            guard,
        )?;
        Ok((read, write))
    }
}

pub struct XdriveListener {
    drive: Xdrive,
    handled: HashMap<String, Instant>,
    idle_since: HashMap<String, Instant>,
    active: Arc<Mutex<HashSet<String>>>,
    collected: Instant,
}

impl XdriveListener {
    pub fn accept(&mut self) -> io::Result<(XdriveRead, XdriveWrite)> {
        let params = self.drive.params;
        let mut polling = Polling::new(params);
        loop {
            self.collect_if_due()?;
            if let Some(connection) = self.pending()? {
                return Ok(connection);
            }
            thread::sleep(polling.delay(false));
        }
    }

    fn pending(&mut self) -> io::Result<Option<(XdriveRead, XdriveWrite)>> {
        let now = unix_nanos()?;
        for entry in self.drive.storage.list("sessions")? {
            let name = format!("sessions/{}", entry.name);
            let Some((at, id)) = parse_announce(&entry.name) else {
                continue;
            };
            if now.saturating_sub(at) > self.drive.params.session_ttl.as_nanos() {
                self.drive.storage.delete(&name)?;
                if !self.active.lock().expect("XDrive sessions").contains(id) {
                    self.drive.storage.delete(&format!("streams/{id}"))?;
                }
                continue;
            }
            if self.handled.contains_key(id) {
                continue;
            }
            self.active
                .lock()
                .expect("XDrive sessions")
                .insert(id.into());
            let guard = Arc::new(ActiveSession {
                id: id.into(),
                active: self.active.clone(),
            });
            let ring = self
                .drive
                .storage
                .slots()
                .and_then(|_| entry.inline.as_deref())
                .and_then(ring::Ring::decode);
            let connection = self.drive.open(id, false, ring, Some(guard))?;
            self.handled.insert(id.into(), Instant::now());
            let _ = self.drive.storage.delete(&name);
            return Ok(Some(connection));
        }
        Ok(None)
    }

    fn collect_if_due(&mut self) -> io::Result<()> {
        let ttl = self.drive.params.session_ttl;
        if self.collected.elapsed() < ttl / 2 {
            return Ok(());
        }
        self.collected = Instant::now();
        let active = self.active.lock().expect("XDrive sessions").clone();
        let now = Instant::now();
        self.handled
            .retain(|id, at| active.contains(id) || now.duration_since(*at) < ttl);
        let mut present = HashSet::new();
        for entry in self.drive.storage.list("streams")? {
            if !valid_id(&entry.name) || active.contains(&entry.name) {
                continue;
            }
            let since = self.idle_since.entry(entry.name.clone()).or_insert(now);
            if now.duration_since(*since) >= ttl {
                self.drive
                    .storage
                    .delete(&format!("streams/{}", entry.name))?;
            } else {
                present.insert(entry.name);
            }
        }
        self.idle_since.retain(|id, _| present.contains(id));
        Ok(())
    }
}

struct ActiveSession {
    id: String,
    active: Arc<Mutex<HashSet<String>>>,
}

impl Drop for ActiveSession {
    fn drop(&mut self) {
        self.active
            .lock()
            .expect("XDrive sessions")
            .remove(&self.id);
    }
}

fn parse_announce(name: &str) -> Option<(u128, &str)> {
    let (stamp, id) = name.split_once('-')?;
    valid_id(id)
        .then(|| stamp.parse().ok().map(|at| (at, id)))
        .flatten()
}

fn valid_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn random_id() -> io::Result<String> {
    let mut bytes = [0; 16];
    getrandom::getrandom(&mut bytes).map_err(|error| io::Error::other(error.to_string()))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn unix_nanos() -> io::Result<u128> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .map_err(io::Error::other)
}

struct Entry {
    name: String,
    inline: Option<Vec<u8>>,
}

trait Storage: Send + Sync {
    fn session(&self) -> Option<Arc<dyn Storage>> { None }
    fn put(&self, name: &str, data: &[u8]) -> io::Result<()>;
    fn get(&self, name: &str) -> io::Result<Vec<u8>>;
    fn list(&self, prefix: &str) -> io::Result<Vec<Entry>>;
    fn delete(&self, name: &str) -> io::Result<()>;
    fn slots(&self) -> Option<&dyn ring::Slots> {
        None
    }
}

enum Medium {
    Segments(String),
    Slots(ring::Table),
}

struct LocalStorage(PathBuf);

impl LocalStorage {
    fn new(root: &Path) -> io::Result<Self> {
        if root.as_os_str().is_empty() {
            return Err(invalid("XDrive remoteFolder is empty"));
        }
        fs::create_dir_all(root)?;
        Ok(Self(root.canonicalize()?))
    }

    fn path(&self, name: &str) -> io::Result<PathBuf> {
        let mut path = self.0.clone();
        for component in name.split('/') {
            if component.is_empty()
                || component == "."
                || component == ".."
                || component.starts_with(TEMP_PREFIX)
                || !component
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            {
                return Err(invalid("XDrive object name"));
            }
            path.push(component);
            match fs::symlink_metadata(&path) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(invalid("XDrive object is a symlink"))
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        Ok(path)
    }
}

impl Storage for LocalStorage {
    fn put(&self, name: &str, data: &[u8]) -> io::Result<()> {
        let path = self.path(name)?;
        let dir = path.parent().expect("XDrive object parent");
        fs::create_dir_all(dir)?;
        let temporary = dir.join(format!("{TEMP_PREFIX}{}", random_id()?));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        let written = file.write_all(data);
        drop(file);
        let result = written.and_then(|_| fs::rename(&temporary, path));
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }

    fn get(&self, name: &str) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        fs::File::open(self.path(name)?)?
            .take((MAX_SEGMENT_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_SEGMENT_BYTES {
            return Err(invalid("XDrive segment too large"));
        }
        Ok(bytes)
    }

    fn list(&self, prefix: &str) -> io::Result<Vec<Entry>> {
        let listing = match fs::read_dir(self.path(prefix)?) {
            Ok(listing) => listing,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        let mut found = Vec::new();
        for entry in listing {
            let Ok(name) = entry?.file_name().into_string() else {
                continue;
            };
            if !name.starts_with(TEMP_PREFIX) {
                found.push(Entry { name, inline: None });
            }
        }
        Ok(found)
    }

    fn delete(&self, name: &str) -> io::Result<()> {
        let path = self.path(name)?;
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_dir() => fs::remove_dir_all(path),
            Ok(_) => fs::remove_file(path),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ObjectKind {
    Segment,
    End,
    Failed,
}

fn object(prefix: &str, seq: u64, kind: ObjectKind) -> String {
    let suffix = match kind {
        ObjectKind::Segment => "seg",
        ObjectKind::End => "end",
        ObjectKind::Failed => "err",
    };
    format!("{prefix}/{seq:09}.{suffix}")
}

fn parse_object(name: &str) -> Option<(u64, ObjectKind)> {
    let (seq, suffix) = name.rsplit_once('.')?;
    let kind = match suffix {
        "seg" => ObjectKind::Segment,
        "end" => ObjectKind::End,
        "err" => ObjectKind::Failed,
        _ => return None,
    };
    Some((seq.parse().ok()?, kind))
}

struct Polling {
    params: Params,
    last_active: Instant,
    current: Duration,
}

impl Polling {
    fn new(params: Params) -> Self {
        Self {
            params,
            last_active: Instant::now(),
            current: params.min_poll,
        }
    }

    fn delay(&mut self, active: bool) -> Duration {
        if active {
            self.last_active = Instant::now();
        }
        self.current = if self.last_active.elapsed() < self.params.eager_window {
            self.params.min_poll
        } else {
            self.current.saturating_mul(2).min(self.params.max_poll)
        };
        self.current
    }
}

pub struct XdriveRead {
    receiver: mpsc::Receiver<io::Result<Vec<u8>>>,
    buffered: Cursor<Vec<u8>>,
    timeout: Option<Duration>,
    quit: Arc<AtomicBool>,
    worker: thread::Thread,
}

impl XdriveRead {
    fn start(
        storage: Arc<dyn Storage>,
        medium: Medium,
        params: Params,
        guard: Option<Arc<ActiveSession>>,
    ) -> io::Result<Self> {
        let (send, receiver) = mpsc::sync_channel(params.concurrency);
        let quit = Arc::new(AtomicBool::new(false));
        let shutdown = quit.clone();
        let worker = thread::Builder::new().spawn(move || {
            let _guard = guard;
            let result = match medium {
                Medium::Segments(prefix) => {
                    read_objects(storage.as_ref(), &prefix, params, &send, &shutdown)
                }
                Medium::Slots(table) => ring::read(
                    storage.slots().expect("XDrive slots"),
                    &table,
                    params,
                    &send,
                    &shutdown,
                ),
            };
            if let Err(error) = result {
                let _ = send.send(Err(error));
            }
        })?;
        Ok(Self {
            receiver,
            buffered: Cursor::new(Vec::new()),
            timeout: None,
            quit,
            worker: worker.thread().clone(),
        })
    }

    pub fn set_timeout(&mut self, timeout: Option<Duration>) {
        self.timeout = timeout;
    }
}

impl Read for XdriveRead {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let deadline = deadline(self.timeout);
        loop {
            let copied = self.buffered.read(buf)?;
            if copied != 0 {
                return Ok(copied);
            }
            self.buffered = Cursor::new(match receive(&self.receiver, deadline)? {
                Some(result) => result?,
                None => return Ok(0),
            });
        }
    }
}

impl Drop for XdriveRead {
    fn drop(&mut self) {
        self.quit.store(true, Ordering::Relaxed);
        self.worker.unpark();
    }
}

fn read_objects(
    storage: &dyn Storage,
    prefix: &str,
    params: Params,
    output: &mpsc::SyncSender<io::Result<Vec<u8>>>,
    quit: &AtomicBool,
) -> io::Result<()> {
    let mut seq = 0;
    let mut hole = None;
    let mut polling = Polling::new(params);
    while !quit.load(Ordering::Relaxed) {
        let mut pending = HashMap::new();
        let mut ahead = false;
        for entry in storage.list(prefix)? {
            if let Some((index, kind)) = parse_object(&entry.name) {
                if index >= seq && pending.get(&index).is_none_or(|(prior, _)| kind > *prior) {
                    pending.insert(index, (kind, entry));
                }
                ahead |= index > seq;
            }
        }
        if ahead && !pending.contains_key(&seq) {
            if hole.get_or_insert_with(Instant::now).elapsed() >= params.hole_timeout {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("missing XDrive segment {seq}"),
                ));
            }
        } else {
            hole = None;
        }
        let mut advanced = false;
        while let Some((kind, entry)) = pending.remove(&seq) {
            let name = format!("{prefix}/{}", entry.name);
            match kind {
                ObjectKind::End => {
                    let _ = storage.delete(&name);
                    return Ok(());
                }
                ObjectKind::Failed => {
                    let _ = storage.delete(&name);
                    return Err(io::Error::other(format!(
                        "peer could not store XDrive segment {seq}"
                    )));
                }
                ObjectKind::Segment => {
                    let bytes = match entry.inline.map(Ok).unwrap_or_else(|| storage.get(&name)) {
                        Ok(bytes) => bytes,
                        Err(error) if error.kind() == io::ErrorKind::NotFound => break,
                        Err(error) => return Err(error),
                    };
                    if output.send(Ok(bytes)).is_err() {
                        return Ok(());
                    }
                    let _ = storage.delete(&name);
                    seq += 1;
                    advanced = true;
                }
            }
        }
        thread::park_timeout(polling.delay(advanced));
    }
    Ok(())
}

enum WriteItem {
    Data(Vec<u8>),
    Flush(mpsc::Sender<io::Result<()>>),
}

type WriteFailure = Arc<Mutex<Option<(io::ErrorKind, String)>>>;

pub struct XdriveWrite {
    sender: mpsc::SyncSender<WriteItem>,
    failure: WriteFailure,
    segment_bytes: usize,
    timeout: Option<Duration>,
}

impl XdriveWrite {
    fn start(
        storage: Arc<dyn Storage>,
        medium: Medium,
        params: Params,
        reader: thread::Thread,
        guard: Option<Arc<ActiveSession>>,
    ) -> io::Result<Self> {
        let (sender, receive) = mpsc::sync_channel(params.concurrency);
        let failure: WriteFailure = Arc::default();
        let recorded = failure.clone();
        thread::Builder::new().spawn(move || {
            let _guard = guard;
            let result = match medium {
                Medium::Segments(prefix) => {
                    write_chunks(params, &receive, &reader, |seq, kind, bytes| {
                        storage.put(&object(&prefix, seq, kind), bytes)
                    })
                }
                Medium::Slots(table) => {
                    let mut writer =
                        ring::Writer::new(storage.slots().expect("XDrive slots"), &table);
                    write_chunks(params, &receive, &reader, |seq, kind, bytes| {
                        writer.write(seq, kind, bytes)
                    })
                }
            };
            if let Err(error) = result {
                *recorded.lock().expect("XDrive writer") = Some((error.kind(), error.to_string()));
            }
        })?;
        Ok(Self {
            sender,
            failure,
            segment_bytes: params.segment_bytes,
            timeout: None,
        })
    }

    pub fn set_timeout(&mut self, timeout: Option<Duration>) {
        self.timeout = timeout;
    }

    fn failure(&self) -> Option<io::Error> {
        self.failure
            .lock()
            .expect("XDrive writer")
            .as_ref()
            .map(|(kind, text)| io::Error::new(*kind, text.clone()))
    }

    fn send(&self, mut item: WriteItem, deadline: Option<Instant>) -> io::Result<()> {
        loop {
            if let Some(error) = self.failure() {
                return Err(error);
            }
            match self.sender.try_send(item) {
                Ok(()) => return Ok(()),
                Err(mpsc::TrySendError::Disconnected(_)) => {
                    return Err(self.failure().unwrap_or_else(closed))
                }
                Err(mpsc::TrySendError::Full(pending)) => item = pending,
            }
            let wait = remaining(deadline)?
                .unwrap_or(Duration::from_millis(1))
                .min(Duration::from_millis(1));
            thread::sleep(wait);
        }
    }
}

impl Write for XdriveWrite {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let len = buf.len().min(self.segment_bytes);
        if len != 0 {
            self.send(WriteItem::Data(buf[..len].to_vec()), deadline(self.timeout))?;
        }
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        let deadline = deadline(self.timeout);
        let (reply, result) = mpsc::channel();
        self.send(WriteItem::Flush(reply), deadline)?;
        receive(&result, deadline)?.unwrap_or_else(|| Err(self.failure().unwrap_or_else(closed)))
    }
}

fn write_chunks(
    params: Params,
    input: &mpsc::Receiver<WriteItem>,
    reader: &thread::Thread,
    mut store: impl FnMut(u64, ObjectKind, &[u8]) -> io::Result<()>,
) -> io::Result<()> {
    let mut seq = 0;
    let mut bytes = Vec::new();
    let mut due = None;
    let flush = |store: &mut dyn FnMut(u64, ObjectKind, &[u8]) -> io::Result<()>,
                 seq: &mut u64,
                 bytes: &mut Vec<u8>,
                 len: usize|
     -> io::Result<()> {
        if len == 0 {
            return Ok(());
        }
        if let Err(error) = store(*seq, ObjectKind::Segment, &bytes[..len]) {
            let _ = store(*seq, ObjectKind::Failed, &[]);
            return Err(error);
        }
        bytes.drain(..len);
        *seq += 1;
        reader.unpark();
        Ok(())
    };
    loop {
        match receive(input, due) {
            Ok(Some(WriteItem::Data(data))) => {
                bytes.extend_from_slice(&data);
                if bytes.len() >= params.segment_bytes {
                    flush(&mut store, &mut seq, &mut bytes, params.segment_bytes)?;
                }
                if !bytes.is_empty() && due.is_none() {
                    due = deadline(Some(params.flush_interval));
                }
            }
            Ok(Some(WriteItem::Flush(reply))) => {
                let len = bytes.len();
                let result = flush(&mut store, &mut seq, &mut bytes, len);
                let report = result
                    .as_ref()
                    .map(|_| ())
                    .map_err(|error| io::Error::new(error.kind(), error.to_string()));
                let _ = reply.send(report);
                result?;
                due = None;
            }
            Ok(None) => {
                let len = bytes.len();
                flush(&mut store, &mut seq, &mut bytes, len)?;
                return store(seq, ObjectKind::End, &[]);
            }
            Err(error) if error.kind() == io::ErrorKind::TimedOut => {
                let len = bytes.len();
                flush(&mut store, &mut seq, &mut bytes, len)?;
                due = None;
            }
            Err(error) => return Err(error),
        }
    }
}

fn receive<T>(queue: &mpsc::Receiver<T>, deadline: Option<Instant>) -> io::Result<Option<T>> {
    match remaining(deadline)? {
        Some(wait) => match queue.recv_timeout(wait) {
            Ok(item) => Ok(Some(item)),
            Err(mpsc::RecvTimeoutError::Timeout) => Err(timed_out()),
            Err(mpsc::RecvTimeoutError::Disconnected) => Ok(None),
        },
        None => Ok(queue.recv().ok()),
    }
}

fn deadline(timeout: Option<Duration>) -> Option<Instant> {
    timeout.and_then(|value| Instant::now().checked_add(value))
}

fn remaining(deadline: Option<Instant>) -> io::Result<Option<Duration>> {
    deadline
        .map(|at| {
            at.checked_duration_since(Instant::now())
                .ok_or_else(timed_out)
        })
        .transpose()
}

fn invalid(message: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "XDrive deadline")
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "XDrive writer closed")
}

#[cfg(test)]
mod tests {
    use super::*;

    const WAIT: Duration = Duration::from_secs(3);
    const SESSION: &str = "0123456789abcdef0123456789abcdef";

    #[test]
    fn local_listener_exchanges_ordered_objects_and_close_markers() {
        let root = std::env::temp_dir().join(format!("kerlico-xdrive-{}", random_id().unwrap()));
        let config = serde_json::json!({
            "service": "local", "remoteFolder": root, "segmentBytes": 4,
            "pollIntervalMs": 5, "flushIntervalMs": 5,
        });
        let drive = Xdrive::new(&config.to_string(), XdriveHttpOptions::default()).unwrap();
        let mut listener = drive.listen().unwrap();
        let announced = root
            .join("sessions")
            .join(format!("{}-{SESSION}", unix_nanos().unwrap()));
        fs::create_dir_all(announced.parent().unwrap()).unwrap();
        fs::write(&announced, b"").unwrap();
        let (ready, received) = mpsc::channel();
        thread::spawn(move || ready.send(listener.accept()).unwrap());
        let (mut read, mut write) = received.recv_timeout(WAIT).unwrap().unwrap();
        read.set_timeout(Some(WAIT));
        write.set_timeout(Some(WAIT));
        assert!(!announced.exists());

        let upload = root.join(format!("streams/{SESSION}/c2s"));
        let download = root.join(format!("streams/{SESSION}/s2c"));
        fs::create_dir_all(&upload).unwrap();
        fs::write(upload.join("000000001.seg"), b"def").unwrap();
        read.set_timeout(Some(Duration::from_millis(35)));
        assert_eq!(
            read.read(&mut [0]).unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
        fs::write(upload.join("000000000.seg"), b"abc").unwrap();
        fs::write(upload.join("000000002.end"), b"").unwrap();
        read.set_timeout(Some(WAIT));
        let mut actual = Vec::new();
        read.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, b"abcdef");

        write.write_all(b"one-two").unwrap();
        write.flush().unwrap();
        assert_eq!(fs::read(download.join("000000000.seg")).unwrap(), b"one-");
        assert_eq!(fs::read(download.join("000000001.seg")).unwrap(), b"two");
        drop(write);
        let limit = Instant::now() + WAIT;
        while !download.join("000000002.end").is_file() && Instant::now() < limit {
            thread::sleep(Duration::from_millis(5));
        }
        assert!(download.join("000000002.end").is_file());
        fs::remove_dir_all(root).unwrap();
    }
}
