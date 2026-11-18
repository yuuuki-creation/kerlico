use super::*;
use std::io::Cursor;
use std::sync::atomic::{AtomicUsize, Ordering};

struct Capture(Arc<Mutex<Vec<u8>>>);
impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct AlertProbe {
    socket: TcpStream,
    calls: Arc<AtomicUsize>,
    blocked: bool,
}
impl Write for AlertProbe {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if self.blocked {
            Err(io::ErrorKind::WouldBlock.into())
        } else {
            self.socket.write(bytes)
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.socket.flush()
    }
}

struct QueuedWire {
    wire: Cursor<Vec<u8>>,
    requests: Arc<Mutex<Vec<usize>>>,
    empty_reads: Arc<AtomicUsize>,
    timeout_at: Option<usize>,
    timed_out: bool,
}

impl Read for QueuedWire {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        self.requests.lock().unwrap().push(out.len());
        let position = self.wire.position() as usize;
        if let Some(cut) = self.timeout_at.filter(|_| !self.timed_out) {
            if position == cut {
                self.timed_out = true;
                return Err(io::ErrorKind::TimedOut.into());
            }
            let len = out.len().min(cut - position);
            return self.wire.read(&mut out[..len]);
        }
        if position == self.wire.get_ref().len() {
            self.empty_reads.fetch_add(1, Ordering::Relaxed);
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.wire.read(out)
    }
}

#[test]
fn full_tls_reads_grow_bounded_storage_and_preserve_record_boundaries_and_errors() {
    for (version, borrowed, ready, record_sender) in [
        ("1.2", false, false, false),
        ("1.3", false, false, false),
        ("1.3", true, false, false),
        ("1.3", true, true, false),
        ("1.3", true, true, true),
    ] {
        for (timeout, corrupt) in [(false, false), (true, false), (false, true)] {
            let mut options = options();
            options.min_version = version.into();
            options.max_version = version.into();
            let server = advanced_server_config(&options).unwrap();
            let client = advanced_client_config(&options).unwrap();
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let address = listener.local_addr().unwrap();
            let accepting = thread::spawn(move || {
                let (socket, _) = listener.accept().unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                accept_advanced_tls_over(socket.try_clone().unwrap(), socket, server).unwrap()
            });
            let socket = TcpStream::connect(address).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let (mut client_read, write) =
                connect_advanced_tls_over(socket.try_clone().unwrap(), socket, client, "localhost")
                    .unwrap();
            let (read, mut server_write) = accepting.join().unwrap();
            if record_sender {
                server_write.request_record_sender();
                let pilot = vec![83; 32768];
                server_write.write_all(&pilot).unwrap();
                let mut observed = vec![0; pilot.len()];
                client_read.read_exact(&mut observed).unwrap();
                assert_eq!(observed, pilot);
                assert!(server_write.core.lock().unwrap().get_ref().sender.is_some());
            }
            let alert_writes = Arc::new(AtomicUsize::new(0));
            let mut server_write = server_write.map_inner(|socket| AlertProbe {
                socket,
                calls: alert_writes.clone(),
                blocked: corrupt && borrowed,
            });
            let captured = Arc::new(Mutex::new(Vec::new()));
            let mut write = write.map_inner(|_| Capture(captured.clone()));
            let payload: Vec<_> = (0..196_621).map(|i| (i % 251) as u8).collect();
            write.write_all(&payload).unwrap();
            write.flush().unwrap();
            let mut wire = captured.lock().unwrap().clone();
            if corrupt {
                *wire.last_mut().unwrap() ^= 1;
            }
            let requests = Arc::new(Mutex::new(Vec::new()));
            let empty_reads = Arc::new(AtomicUsize::new(0));
            let mut read = read.map_inner(|_| QueuedWire {
                wire: Cursor::new(wire),
                requests: requests.clone(),
                empty_reads: empty_reads.clone(),
                timeout_at: timeout.then_some(20_000),
                timed_out: false,
            });
            let mut actual = Vec::new();
            let mut buf = vec![0; 128 * 1024];
            let mut largest = 0;
            let mut timeouts = 0;
            let mut authentication_failed = false;
            while actual.len() < payload.len() {
                let result = if borrowed {
                    let result = if ready {
                        read.prepare_nonblocking_records()
                    } else {
                        read.prepare_buffered_records()
                    };
                    result.map(|()| {
                        let mut slices = [IoSlice::new(&[]); 16];
                        let count = read.buffered_records(&mut slices);
                        let total: usize = slices[..count].iter().map(|s| s.len()).sum();
                        if ready && total > 16_384 {
                            assert_eq!(count, 1, "ready records share one authenticated span");
                        }
                        let take = total.min(37_001);
                        let expected: Vec<_> = slices[..count]
                            .iter()
                            .flat_map(|s| s.iter().copied())
                            .take(take)
                            .collect();
                        // A second preparation must not move, reauthenticate or
                        // replace records still borrowed by the consumer.
                        let pointer = slices.first().map(|s| s.as_ptr());
                        read.prepare_buffered_records().unwrap();
                        let mut again = [IoSlice::new(&[]); 16];
                        assert_eq!(read.buffered_records(&mut again), count);
                        assert_eq!(again.first().map(|s| s.as_ptr()), pointer);
                        buf[..take].copy_from_slice(&expected);
                        read.consume_records(take);
                        if corrupt {
                            assert_eq!(
                                alert_writes.load(Ordering::Relaxed),
                                0,
                                "deliver valid bytes before attempting a later fatal alert"
                            );
                        }
                        take
                    })
                } else {
                    read.read(&mut buf)
                };
                match result {
                    Ok(0) => panic!("no close_notify was sent"),
                    Ok(n) => {
                        actual.extend_from_slice(&buf[..n]);
                        largest = largest.max(n);
                    }
                    Err(e) if e.kind() == io::ErrorKind::TimedOut => timeouts += 1,
                    Err(e) if corrupt => {
                        assert_ne!(e.kind(), io::ErrorKind::WouldBlock);
                        authentication_failed = true;
                        break;
                    }
                    Err(e) => panic!("unexpected read error: {e}"),
                }
                assert!(read.wire.len() <= if ready { 16 * MAX_RECORD } else { READ_AHEAD });
            }
            assert_eq!(actual, payload[..actual.len()]);
            if borrowed {
                assert!(
                    largest > 16_384,
                    "lend several authenticated records together"
                );
            } else {
                assert_eq!(
                    largest, 16_384,
                    "Vision must be able to switch after each record"
                );
            }
            assert!(
                requests.lock().unwrap().iter().any(|&n| n > 32_768),
                "full reads must grow past two-record storage"
            );
            if ready {
                assert_eq!(
                    empty_reads.load(Ordering::Relaxed),
                    usize::from(!corrupt),
                    "drain a nonblocking source until it would block"
                );
                assert_eq!(
                    timeouts, 0,
                    "deliver the prefix when the next ready read times out"
                );
                assert_eq!(read.inner.timed_out, timeout);
                assert!(
                    largest > 32_768,
                    "native batches must span several underlying reads"
                );
            } else {
                assert_eq!(
                    empty_reads.load(Ordering::Relaxed),
                    0,
                    "ready plaintext must not wait for another transport read"
                );
                assert_eq!(timeouts, usize::from(timeout));
            }
            assert_eq!(authentication_failed, corrupt);
            if corrupt {
                if borrowed {
                    assert!(
                        alert_writes.load(Ordering::Relaxed) != 0,
                        "borrowed TLS must attempt its deferred fatal alert"
                    );
                }
                if record_sender {
                    server_write.inner_mut().blocked = false;
                    server_write.flush().unwrap();
                    assert_eq!(
                        server_write.write(b"later").unwrap_err().kind(),
                        io::ErrorKind::BrokenPipe
                    );
                    assert_eq!(
                        client_read.read(&mut [0; 1]).unwrap_err().kind(),
                        io::ErrorKind::ConnectionAborted
                    );
                }
                assert!(actual.len() < payload.len());
                assert!(actual.len() >= payload.len() - 16_384);
            } else {
                assert_eq!(actual, payload);
                assert_eq!(
                    read.read(&mut buf).unwrap_err().kind(),
                    io::ErrorKind::WouldBlock
                );
            }
        }
    }
}

#[test]
fn rustls_suites_key_updates_and_half_close_keep_borrowed_records_in_order() {
    use rustls::crypto::ring::cipher_suite::{
        TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384, TLS13_CHACHA20_POLY1305_SHA256,
    };
    for (suite, small_fragments) in [
        TLS13_AES_128_GCM_SHA256,
        TLS13_AES_256_GCM_SHA384,
        TLS13_CHACHA20_POLY1305_SHA256,
    ]
    .into_iter()
    .flat_map(|suite| [(suite, false), (suite, true)])
    {
        let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut options = options();
        options.min_version = "1.3".into();
        options.certificates[0].certificate = identity.cert.pem();
        options.certificates[0].key = identity.key_pair.serialize_pem();
        let config = advanced_server_config(&options).unwrap();
        let mut provider = rustls::crypto::ring::default_provider();
        provider.cipher_suites = vec![suite];
        let mut roots = rustls::RootCertStore::empty();
        roots.add(identity.cert.der().clone()).unwrap();
        let client = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let payload: Vec<_> = (0..196_621).map(|i| (i % 251) as u8).collect();
        let expected = payload.clone();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let task = thread::spawn(move || {
            let (socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let control = socket.try_clone().unwrap();
            let (mut read, mut write) =
                accept_advanced_tls_over(socket.try_clone().unwrap(), socket, config).unwrap();
            if small_fragments {
                write
                    .core
                    .lock()
                    .unwrap()
                    .ssl_mut()
                    .set_max_send_fragment(512);
            }
            write.request_record_sender();
            write.write_all(&vec![83; 32768]).unwrap();
            {
                let mut core = write.core.lock().unwrap();
                assert_eq!(core.get_ref().sender.is_some(), !small_fragments);
                if let Some(sender) = core.get_mut().sender.as_mut() {
                    sender.test_update_interval = Some(2);
                }
            }
            // Force one real short write followed by WouldBlock. The retry must
            // keep previously sealed application and KeyUpdate records in order.
            struct ShortOnce(TcpStream, Option<usize>);
            impl Write for ShortOnce {
                fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                    match self.1 {
                        Some(0) => {
                            self.1 = None;
                            Err(io::ErrorKind::WouldBlock.into())
                        }
                        Some(left) => {
                            let n = self.0.write(&bytes[..left.min(bytes.len())])?;
                            self.1 = Some(left - n);
                            Ok(n)
                        }
                        None => self.0.write(bytes),
                    }
                }
                fn flush(&mut self) -> io::Result<()> {
                    self.0.flush()
                }
            }
            let mut write = write.map_inner(|socket| ShortOnce(socket, None));
            assert!(read.has_buffered_records());
            control.set_nonblocking(true).unwrap();
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let mut actual = Vec::new();
            loop {
                match read.prepare_nonblocking_records() {
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        assert!(std::time::Instant::now() < deadline);
                        thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    result => result.unwrap(),
                }
                let mut slices = [IoSlice::new(&[]); 16];
                let count = read.buffered_records(&mut slices);
                if count == 0 {
                    break;
                }
                assert_eq!(count, 1);
                let used: usize = slices[..count].iter().map(|s| s.len()).sum();
                for slice in &slices[..count] {
                    actual.extend_from_slice(slice);
                }
                read.consume_records(used);
            }
            assert_eq!(actual, expected);
            control.set_nonblocking(false).unwrap();
            let split = if small_fragments { actual.len() } else { 49153 };
            write.inner_mut().1 = Some(100);
            assert_eq!(
                write.write(&actual[..split]).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
            assert_eq!(
                write.write(b"wrong retry").unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
            write.write_all(&actual[..split]).unwrap();
            if !small_fragments {
                write
                    .core
                    .lock()
                    .unwrap()
                    .get_mut()
                    .sender
                    .as_mut()
                    .unwrap()
                    .test_update_interval = Some(8);
                let (capacity, regions) = AdvancedTlsWrite::<ShortOnce>::record_input_layout();
                let mut slab = vec![0; capacity];
                for source in actual[split..].chunks(8 * 16384) {
                    for (part, region) in source.chunks(16384).zip(&regions) {
                        slab[region.start..region.start + part.len()].copy_from_slice(part);
                    }
                    write.inner_mut().1 = Some(100);
                    let mut sealed = false;
                    assert_eq!(
                        write
                            .write_record_input(&mut slab, source.len(), &mut sealed)
                            .unwrap_err()
                            .kind(),
                        io::ErrorKind::WouldBlock
                    );
                    assert!(sealed);
                    // A control flush may deliver everything the writer staged.
                    // Its subsequent retry must never submit those bytes twice.
                    write.flush().unwrap();
                    write
                        .write_record_input(&mut slab, source.len(), &mut sealed)
                        .unwrap();
                    assert!(!sealed);
                }
            }
            write.send_close_notify().unwrap();
        });
        let socket = TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let conn = rustls::ClientConnection::new(
            Arc::new(client),
            rustls::pki_types::ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();
        let mut client = rustls::StreamOwned::new(conn, socket);
        let mut pilot = vec![0; 32768];
        client.read_exact(&mut pilot).unwrap();
        assert!(pilot.iter().all(|&byte| byte == 83));
        client.write_all(&payload[..100_003]).unwrap();
        client.flush().unwrap();
        client.conn.refresh_traffic_keys().unwrap();
        client.write_all(&payload[100_003..]).unwrap();
        client.conn.send_close_notify();
        client.flush().unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert_eq!(response, payload);
        task.join().unwrap();
    }
}
