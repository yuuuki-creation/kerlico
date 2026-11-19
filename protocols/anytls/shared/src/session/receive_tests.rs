use super::*;
use crate::padding::Scheme;

struct Fixture {
    stream: Stream,
    peer: TcpStream,
    tx: Tx,
    kernel: Mutex<Kernel>,
}

impl Fixture {
    fn new() -> Self {
        // Exercise the server's receive direction. The client receive direction
        // still has the server's post-handshake tickets waiting in the socket;
        // injecting later application records ahead of them would skip nonces.
        let (remote, local) = crate::tests::pair();
        local.tcp.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        let padding = SchemeCell::new(Scheme::default_scheme());
        let inner = Arc::new(Inner::new(Role::Client, local, padding, Parser::new(Role::Client, None)).unwrap());
        let core = Arc::new(Core::new(1, Parse::Data, Arc::downgrade(&inner)));
        inner.streams.lock().unwrap().insert(1, core.clone());
        let Wire::Records(wire) = remote.wire else { panic!("record fixture") };
        Self {
            stream: Stream { core, session: inner }, peer: remote.tcp,
            tx: Tx::new(Some(wire.tx), wire.pending, false), kernel: Mutex::new(wire.kernel),
        }
    }

    fn frame(&mut self, sid: u32, bytes: &[u8]) {
        self.tx.put(Out::Frames { cmd: CMD_PSH, sid, data: bytes }, &self.stream.session.padding, &self.kernel).unwrap();
    }

    fn queued_records(&mut self) -> std::ops::Range<usize> {
        // Feed genuine peer-encrypted TLS records into the receive cache so
        // record coalescing and partial application reads are deterministic.
        let mut slot = self.stream.session.rx.lock().unwrap();
        let reader = &mut slot.as_mut().unwrap().reader;
        assert_eq!(reader.start, reader.end);
        reader.start = 0;
        reader.end = self.tx.out.len();
        if reader.buf.len() < reader.end { reader.buf.resize(reader.end, 0); }
        reader.buf[..reader.end].copy_from_slice(&self.tx.out);
        self.tx.out.clear();
        let start = reader.buf.as_ptr() as usize;
        start..start + reader.end
    }
}

#[test]
fn borrowed_records_stay_in_receive_storage_and_other_streams_remain_readable() {
    let mut f = Fixture::new();
    let core = Arc::new(Core::new(2, Parse::Data, Arc::downgrade(&f.stream.session)));
    f.stream.session.streams.lock().unwrap().insert(2, core.clone());
    let other = Stream { core, session: f.stream.session.clone() };
    let first = vec![0x37; 20_000];
    let last = vec![0x82; 20_000];
    f.frame(1, &first);
    f.frame(2, b"other stream");
    f.frame(1, &last);
    let allocation = f.queued_records();
    let mut fallback = vec![0xa5; 65_536];
    let mut received = Vec::new();
    let n = f.stream.read_vectored_for(&mut fallback, Duration::from_secs(1), &mut |parts| {
        assert!(parts.len() >= 4);
        assert!(f.stream.session.rx.try_lock().unwrap().is_none(), "borrow owns the receive buffer");
        assert!(f.stream.core.rx.try_lock().unwrap().queue.is_empty(), "own payload never enters the queue");
        for part in parts {
            let at = part.as_ptr() as usize;
            assert!(allocation.start <= at && at + part.len() <= allocation.end);
            received.extend_from_slice(part);
        }
        let mut bytes = [0; 32];
        let n = other.read_for(&mut bytes, Duration::from_millis(50)).unwrap();
        assert_eq!(&bytes[..n], b"other stream");
    }).unwrap();
    assert_eq!(n, 40_000);
    assert_eq!(received, [first, last].concat());
    assert!(fallback.iter().all(|&byte| byte == 0xa5), "outbound scratch was not touched");
    drop(f.peer);
}

#[test]
fn a_new_receive_owner_preserves_the_previous_owners_queued_prefix() {
    let mut f = Fixture::new();
    f.stream.core.rx.lock().unwrap().queue.push(b"first ");
    f.frame(1, b"second");
    f.queued_records();
    {
        let mut slot = f.stream.session.rx.lock().unwrap();
        let mut direct = Direct::reader(1, 32);
        assert!(pump(&f.stream.session, slot.as_mut().unwrap(), &mut direct).unwrap());
        assert_eq!(direct.count, 0);
    }
    let mut data = [0; 12];
    assert_eq!(f.stream.read_for(&mut data, Duration::from_secs(1)).unwrap(), data.len());
    assert_eq!(&data, b"first second");
}

#[test]
fn a_resumed_plaintext_frame_stays_intact_when_the_socket_is_readable() {
    let mut f = Fixture::new();
    let inner = &f.stream.session;
    let mut slot = inner.rx.lock().unwrap();
    let side = slot.as_mut().unwrap();
    side.reader = Reader::stream(None);
    let mut pending = Vec::new();
    frame::push_data(&mut pending, 1, b"earlier");
    side.reader.buf[..pending.len()].copy_from_slice(&pending);
    side.reader.end = pending.len();
    side.pending = Some(0..pending.len());
    let mut next = Vec::new();
    frame::push_data(&mut next, 1, b"latest!");
    f.peer.write_all(&next).unwrap();
    let mut direct = Direct::reader(1, 32);
    assert!(pump(inner, side, &mut direct).unwrap());
    assert_eq!(direct.count, 1);
    assert_eq!(&side.reader.buf[direct.ranges[0].clone()], b"earlier");
}

#[test]
fn short_reads_and_borrowed_reads_share_one_ordered_cursor() {
    let mut f = Fixture::new();
    let payload: Vec<u8> = (0..65_000).map(|i| (i % 251) as u8).collect();
    f.frame(1, &payload);
    f.queued_records();
    let mut received = Vec::new();
    let mut part = [0; 113];
    let n = f.stream.read_for(&mut part, Duration::from_secs(1)).unwrap();
    received.extend_from_slice(&part[..n]);
    let mut scratch = [0; 997];
    while received.len() < payload.len() {
        let n = f.stream.read_vectored_for(&mut scratch, Duration::from_secs(1), &mut |parts| {
            for part in parts { received.extend_from_slice(part); }
        }).unwrap();
        assert!(n > 0 && n <= scratch.len());
    }
    assert_eq!(received, payload);
}

#[test]
fn tiny_records_over_the_vector_limit_keep_their_tail() {
    let mut f = Fixture::new();
    for byte in 0..80 { f.frame(1, &[byte]); }
    f.queued_records();
    let mut received = Vec::new();
    let mut scratch = [0; 256];
    let n = f.stream.read_vectored_for(&mut scratch, Duration::from_secs(1), &mut |parts| {
        assert_eq!(parts.len(), DIRECT_PARTS);
        for part in parts { received.extend_from_slice(part); }
    }).unwrap();
    assert_eq!(n, DIRECT_PARTS);
    let n = f.stream.read_for(&mut scratch, Duration::from_secs(1)).unwrap();
    received.extend_from_slice(&scratch[..n]);
    assert_eq!(received, (0..80).collect::<Vec<u8>>());
}

#[test]
fn authenticated_prefix_is_delivered_before_a_later_bad_record_closes_the_session() {
    let mut f = Fixture::new();
    let payload = vec![0x91; 20_000];
    f.frame(1, &payload);
    *f.tx.out.last_mut().unwrap() ^= 1;
    f.queued_records();
    let mut received = Vec::new();
    let mut scratch = [0; 32_768];
    let n = f.stream.read_vectored_for(&mut scratch, Duration::from_secs(1), &mut |parts| {
        for part in parts { received.extend_from_slice(part); }
    }).unwrap();
    assert_eq!(n, tls::MAX_PLAIN - HEADER);
    assert_eq!(received, payload[..n]);
    assert!(f.stream.session.closed.load(Ordering::Acquire));
    assert_eq!(f.stream.read_for(&mut scratch, Duration::from_secs(1)).unwrap(), 0);
}
