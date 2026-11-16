//! Byte vectors from the Go reference and sessions over loopback TLS.

use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::addr::{Family, Target};
use crate::frame::{self, CMD_FIN, CMD_PSH, CMD_SETTINGS, CMD_SYN};
use crate::padding::{Scheme, SchemeCell};
use crate::session::{Flow, Inbound, Opened, Session};
use crate::tls::{self, ClientTls, Established, MAX_PLAIN};
use crate::tx::{Out, Tx};
use crate::vectors::*;

pub(crate) fn certificate() -> (String, String) {
    let key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    (key.cert.pem(), key.key_pair.serialize_pem())
}

/// A finished handshake on both ends of a loopback connection.
pub(crate) fn pair() -> (Established, Established) {
    let (cert, key) = certificate();
    let server_config = tls::server_config(&cert, &key).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        // As the server crate and the client pool do; without it small frames wait for delayed ACKs.
        tcp.set_nodelay(true).unwrap();
        tls::accept(tcp, server_config).unwrap()
    });
    let client_config = tls::client_config(&ClientTls { insecure: true, ..ClientTls::default() }).unwrap();
    let tcp = TcpStream::connect(addr).unwrap();
    tcp.set_nodelay(true).unwrap();
    let mut client = tls::connect(tcp, client_config, "localhost").unwrap();
    // The held-back Finished goes now so that the server side completes.
    use std::io::Write;
    let tls::Wire::Records(records) = &mut client.wire else { panic!("kernel TLS") };
    client.tcp.write_all(&records.pending).unwrap();
    records.pending.clear();
    let server = server.join().unwrap();
    (client, server)
}

/// Opens the records of `out` with the peer's receive cipher.
fn open_all(link: &mut Established, out: &[u8]) -> Vec<Vec<u8>> {
    let tls::Wire::Records(wire) = &mut link.wire else { panic!("kernel TLS") };
    let mut records = Vec::new();
    let mut rest = out.to_vec();
    let mut at = 0;
    while at < rest.len() {
        let len = usize::from(u16::from_be_bytes([rest[at + 3], rest[at + 4]]));
        let (kind, plain) = wire.rx.open(&mut rest[at..at + 5 + len]).unwrap();
        assert_eq!(kind, 23);
        records.push(rest[at + 5..at + 5 + plain].to_vec());
        at += 5 + len;
    }
    records
}

#[test]
fn client_packets_match_mihomo_writes() {
    let (client, mut server) = pair();
    let padding = SchemeCell::new(Scheme::parse(VECTOR_SCHEME).unwrap());
    assert_eq!(padding.load().md5(), VECTOR_MD5);
    let tls::Wire::Records(wire) = client.wire else { panic!("kernel TLS") };
    let kernel = Mutex::new(wire.kernel);
    let mut tx = Tx::new(Some(wire.tx), Vec::new(), true);
    let settings = frame::string_map(&[("v", "2"), ("client", "kerlico-test"), ("padding-md5", VECTOR_MD5)]);
    let put = |tx: &mut Tx, cmd, sid, data: &[u8]| {
        tx.put(Out::Frames { cmd, sid, data }, &padding, &kernel).unwrap();
    };
    tx.buffering = true;
    put(&mut tx, CMD_SETTINGS, 0, &settings);
    put(&mut tx, CMD_SYN, 1, &[]);
    tx.buffering = false;
    let mut addr = Vec::new();
    Target::new("example.com", 443).encode(Family::Socks, &mut addr).unwrap();
    put(&mut tx, CMD_PSH, 1, &addr);
    put(&mut tx, CMD_PSH, 1, &pattern(50, 1));
    put(&mut tx, CMD_PSH, 1, &pattern(200, 2));
    put(&mut tx, CMD_PSH, 1, &pattern(5, 3));
    put(&mut tx, CMD_SYN, 2, &[]);
    put(&mut tx, CMD_PSH, 2, &pattern(70000, 4));
    put(&mut tx, CMD_FIN, 1, &[]);
    let records = open_all(&mut server, &tx.out);
    // Each Go write under 16384 bytes is one record; the big one is split at 16384 here (Go would
    // size its records differently, which only an observer of the ciphertext can see).
    for (index, expect) in CLIENT.iter().enumerate() {
        assert_eq!(hex(&records[index]), *expect, "write {index}");
    }
    assert_eq!(records[7].len(), CLIENT_SYN2_LEN);
    assert_eq!(&records[7][..7], &frame::header(CMD_SYN, 2, 0));
    assert_eq!(&records[7][7..14], &frame::header(0, 0, 286));
    assert!(records[7][14..].iter().all(|byte| *byte == 0));
    let big: Vec<u8> = records[8..records.len() - 1].concat();
    assert_eq!(big.len(), CLIENT_BIG_LEN);
    assert!(records[8..records.len() - 1].iter().all(|record| record.len() <= MAX_PLAIN));
    assert_eq!(hex(&Sha256::digest(&big)), CLIENT_BIG_SHA256);
    assert_eq!(hex(records.last().unwrap()), CLIENT_FIN);
}

#[test]
fn padding_only_packets_match_mihomo() {
    let (client, mut server) = pair();
    let padding = SchemeCell::new(Scheme::parse(VECTOR_SCHEME).unwrap());
    let tls::Wire::Records(wire) = client.wire else { panic!("kernel TLS") };
    let kernel = Mutex::new(wire.kernel);
    let mut tx = Tx::new(Some(wire.tx), Vec::new(), true);
    tx.write_padded_for_test(&[], &[20, crate::padding::CHECK, 30], &kernel);
    tx.write_padded_for_test(&[1, 2, 3, 4], &[9, 50], &kernel);
    let records = open_all(&mut server, &tx.out);
    let records: Vec<String> = records.iter().map(|record| hex(record)).collect();
    assert_eq!(records, PAD_ONLY);
    let _ = padding;
}

#[test]
fn auth_record_matches_mihomo() {
    let (client, mut server) = pair();
    let tls::Wire::Records(wire) = client.wire else { panic!("kernel TLS") };
    let kernel = Mutex::new(wire.kernel);
    let mut tx = Tx::new(Some(wire.tx), Vec::new(), true);
    tx.put_auth(&crate::password_hash("secret"), 30, &kernel).unwrap();
    let records = open_all(&mut server, &tx.out);
    assert_eq!(records.len(), 1);
    assert_eq!(hex(&records[0]), AUTH);
}

#[test]
fn uot_bytes_match_sing() {
    let mut request = vec![0u8];
    Target::new("1.2.3.4", 53).encode(Family::Socks, &mut request).unwrap();
    assert_eq!(hex(&request), UOT_REQUEST);
    let mut request = vec![1u8];
    Target::new("example.com", 53).encode(Family::Socks, &mut request).unwrap();
    assert_eq!(hex(&request), UOT_REQUEST_CONNECT);
    let mut packet = Vec::new();
    Target::new("2001:db8::1", 5353).encode(Family::Uot, &mut packet).unwrap();
    packet.extend_from_slice(&2u16.to_be_bytes());
    packet.extend_from_slice(b"v6");
    assert_eq!(hex(&packet), UOT_LAZY[1]);
    assert!(UOT_LAZY[0].starts_with(UOT_REQUEST));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

// ---------------------------------------------------------------------------------------------
// Sessions

struct Collect {
    users: Vec<[u8; 32]>,
    tx: Mutex<mpsc::Sender<Opened>>,
}

impl Inbound for Collect {
    fn authenticate(&self, hash: &[u8; 32]) -> bool {
        self.users.contains(hash)
    }
    fn open(&self, opened: Opened) {
        let _ = self.tx.lock().unwrap().send(opened);
    }
}

struct Rig {
    client: Session,
    opened: mpsc::Receiver<Opened>,
    server_scheme: SchemeCell,
    client_scheme: SchemeCell,
    done: mpsc::Receiver<()>,
}

fn rig(password: &str, server_scheme: &[u8]) -> Rig {
    let (client_link, server_link) = pair();
    let (tx, opened) = mpsc::channel();
    let inbound = Arc::new(Collect { users: vec![crate::password_hash("secret")], tx: Mutex::new(tx) });
    let server_scheme = SchemeCell::new(Scheme::parse(server_scheme).unwrap());
    let scheme = server_scheme.clone();
    let (done_tx, done) = mpsc::channel();
    thread::spawn(move || {
        let _ = Session::serve(server_link, scheme, inbound);
        let _ = done_tx.send(());
    });
    let client_scheme = SchemeCell::new(Scheme::default_scheme());
    let client = Session::client(client_link, client_scheme.clone(), "", &crate::password_hash(password)).unwrap();
    Rig { client, opened, server_scheme, client_scheme, done }
}

fn read_exact(stream: &crate::Stream, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let mut have = 0;
    while have < len {
        let n = stream.read_for(&mut out[have..], Duration::from_secs(10)).unwrap();
        assert!(n > 0, "early EOF at {have}");
        have += n;
    }
    out
}

fn open_to(session: &Session, host: &str, port: u16) -> crate::Stream {
    let stream = session.open_stream().unwrap();
    let mut addr = Vec::new();
    Target::new(host, port).encode(Family::Socks, &mut addr).unwrap();
    stream.write(&addr).unwrap();
    stream
}

fn echo(opened: Opened) {
    thread::spawn(move || match opened.flow {
        Flow::Tcp(stream) => {
            let mut buf = vec![0u8; 65536];
            loop {
                match stream.read_for(&mut buf, Duration::from_secs(10)) {
                    Ok(0) | Err(_) => return,
                    Ok(n) => {
                        if stream.write(&buf[..n]).is_err() {
                            return;
                        }
                    }
                }
            }
        }
        Flow::Udp(leg) => {
            let mut buf = vec![0u8; 65536];
            while let Ok(n) = leg.recv_for(&mut buf, Duration::from_secs(10)) {
                if leg.send(&buf[..n]).is_err() {
                    return;
                }
            }
        }
    });
}

#[test]
fn streams_carry_bytes_both_ways_and_close_with_fin() {
    let rig = rig("secret", crate::DEFAULT_SCHEME);
    let streams: Vec<_> = (0..4).map(|index| open_to(&rig.client, "example.com", 1000 + index)).collect();
    let mut targets = Vec::new();
    for _ in 0..4 {
        let opened = rig.opened.recv_timeout(Duration::from_secs(5)).unwrap();
        targets.push(opened.target.port);
        echo(opened);
    }
    targets.sort();
    assert_eq!(targets, vec![1000, 1001, 1002, 1003]);
    for _ in 0..100 {
        if rig.client.peer_version() == 2 {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(rig.client.peer_version(), 2, "cmdServerSettings arrived");
    let workers: Vec<_> = streams
        .into_iter()
        .enumerate()
        .map(|(index, stream)| {
            thread::spawn(move || {
                for round in 0..40 {
                    let block = pattern(32 * 1024 + round * 13, index as u8);
                    stream.write(&block).unwrap();
                    assert_eq!(read_exact(&stream, block.len()), block);
                }
                let big = pattern(3 << 20, 9);
                let reader = {
                    let len = big.len();
                    let stream = &stream;
                    thread::scope(|scope| {
                        let handle = scope.spawn(move || read_exact(stream, len));
                        stream.write(&big).unwrap();
                        handle.join().unwrap()
                    })
                };
                assert_eq!(Sha256::digest(&reader), Sha256::digest(&big));
                stream.close();
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
    // The echo threads see EOF from our FINs and drop their streams.
    thread::sleep(Duration::from_millis(200));
    assert_eq!(rig.client.stream_count(), 0);
    rig.client.close();
    rig.done.recv_timeout(Duration::from_secs(5)).unwrap();
}

/// A stream on a session whose previous stream ended a moment ago is answered at once: when the
/// last stream reader goes, the session's own thread reads again without waiting for a timer.
#[test]
fn a_reused_session_answers_the_next_stream_at_once() {
    let rig = rig("secret", crate::DEFAULT_SCHEME);
    let mut worst = Duration::ZERO;
    for round in 0..20u16 {
        let started = std::time::Instant::now();
        let stream = open_to(&rig.client, "example.com", 2000 + round);
        stream.write(b"ping").unwrap();
        let opened = rig.opened.recv_timeout(Duration::from_secs(5)).unwrap();
        let at_server = started.elapsed();
        echo(opened);
        assert_eq!(read_exact(&stream, 4), b"ping");
        let took = started.elapsed();
        if took > Duration::from_millis(50) {
            eprintln!("round {round}: stream reached the server after {at_server:?}, echo after {took:?}");
        }
        worst = worst.max(took);
        stream.close();
        thread::sleep(Duration::from_millis(10));
    }
    assert!(worst < Duration::from_millis(50), "slowest first echo {worst:?}");
}

#[test]
fn uot_fans_out_by_destination_and_preserves_reply_source() {
    let rig = rig("secret", crate::DEFAULT_SCHEME);
    let stream = open_to(&rig.client, crate::UOT_V2, 0);
    let mut first = vec![0u8];
    Target::new("10.0.0.1", 53).encode(Family::Socks, &mut first).unwrap();
    for (host, port, payload) in [("10.0.0.1", 53u16, &b"one"[..]), ("example.com", 5353, b""), ("10.0.0.1", 53, b"three")] {
        let mut packet = std::mem::take(&mut first);
        Target::new(host, port).encode(Family::Uot, &mut packet).unwrap();
        packet.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        packet.extend_from_slice(payload);
        stream.write(&packet).unwrap();
    }
    let mut legs = Vec::new();
    for _ in 0..2 {
        let opened = rig.opened.recv_timeout(Duration::from_secs(5)).unwrap();
        legs.push(opened);
    }
    let Flow::Udp(one) = &legs[0].flow else { panic!("udp") };
    let Flow::Udp(two) = &legs[1].flow else { panic!("udp") };
    assert!(Arc::ptr_eq(one.datagram_session().unwrap(), two.datagram_session().unwrap()));
    assert_eq!(one.target(), &Target::new("10.0.0.1", 53));
    assert_eq!(two.target(), &Target::new("example.com", 5353));
    let mut buf = [0u8; 64];
    let n = one.recv_for(&mut buf, Duration::from_secs(5)).unwrap();
    assert_eq!(&buf[..n], b"one");
    assert_eq!(two.recv_for(&mut buf, Duration::from_secs(5)).unwrap(), 0, "empty datagram");
    let n = one.recv_for(&mut buf, Duration::from_secs(5)).unwrap();
    assert_eq!(&buf[..n], b"three");
    let alternate = "[::1]:4053".parse().unwrap();
    let payload = vec![0xb4; usize::from(u16::MAX)];
    two.send_from(alternate, &payload).unwrap();
    let mut expect = Vec::new();
    Target::new("::1", 4053).encode(Family::Uot, &mut expect).unwrap();
    expect.extend_from_slice(&u16::MAX.to_be_bytes());
    expect.extend_from_slice(&payload);
    assert_eq!(read_exact(&stream, expect.len()), expect);
}

#[test]
fn server_scheme_replaces_the_client_scheme() {
    let custom = b"stop=3\n0=10-10\n1=200-200\n2=300-300";
    let rig = rig("secret", custom);
    let stream = open_to(&rig.client, "example.com", 80);
    let _opened = rig.opened.recv_timeout(Duration::from_secs(5)).unwrap();
    for _ in 0..100 {
        if rig.client_scheme.load().md5() == rig.server_scheme.load().md5() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(rig.client_scheme.load().raw(), custom);
    drop(stream);
}

#[test]
fn wrong_password_ends_the_session() {
    let rig = rig("wrong", crate::DEFAULT_SCHEME);
    let stream = open_to(&rig.client, "example.com", 80);
    rig.done.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(rig.opened.try_recv().is_err());
    let mut buf = [0u8; 8];
    let result = stream.read_for(&mut buf, Duration::from_secs(5));
    assert!(matches!(result, Ok(0) | Err(_)), "{result:?}");
    for _ in 0..100 {
        if rig.client.is_closed() {
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    assert!(rig.client.is_closed());
}
