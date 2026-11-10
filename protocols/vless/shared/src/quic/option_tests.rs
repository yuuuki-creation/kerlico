use super::*;
use super::tests::configs;
use bytes::BytesMut;
use http::StatusCode;
use quinn_proto::{ConnectionId, crypto, transport_parameters::TransportParameters};
use serde_json::json;
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::net::{TcpListener, TcpStream};
use std::time::Instant;

struct CapturingClient {
    crypto: Arc<dyn crypto::ClientConfig>,
    parameters: Arc<Mutex<Vec<u8>>>,
}

impl crypto::ClientConfig for CapturingClient {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        name: &str,
        parameters: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, quinn_proto::ConnectError> {
        parameters.write(&mut *self.parameters.lock().unwrap());
        self.crypto.clone().start_session(version, name, parameters)
    }
}

fn varint(bytes: &mut &[u8]) -> u64 {
    let count = 1 << (bytes[0] >> 6);
    let mut value = u64::from(bytes[0] & 63);
    for &byte in &bytes[1..count] {
        value = (value << 8) | u64::from(byte);
    }
    *bytes = &bytes[count..];
    value
}

fn initial(options: &QuicOptions) -> (Vec<u8>, BTreeMap<u64, Vec<u8>>, Arc<QuicServerConfig>) {
    let (client, server) = configs();
    let mut client = client.as_ref().clone();
    client.alpn_protocols = vec![b"h3".to_vec()];
    let parameters = Arc::new(Mutex::new(Vec::new()));
    let capture = CapturingClient {
        crypto: Arc::new(QuicClientConfig::try_from(client).unwrap()),
        parameters: parameters.clone(),
    };
    let mut endpoint = quinn_proto::Endpoint::new(Arc::new(options.endpoint(true)), None, true, None);
    let mut config = quinn_proto::ClientConfig::new(Arc::new(capture));
    config.transport_config(options.transport(QuicCarrier::Hysteria, true, 0).unwrap());
    options.configure_client(&mut config);
    let now = Instant::now();
    let (_, mut connection) = endpoint.connect(now, config, "127.0.0.1:443".parse().unwrap(), "localhost").unwrap();
    let mut packets = Vec::new();
    let transmit = connection.poll_transmit(now, 1, &mut packets).unwrap();
    assert_eq!(transmit.segment_size, None);
    let encoded = parameters.lock().unwrap();
    let mut encoded = encoded.as_slice();
    let mut fields = BTreeMap::new();
    while !encoded.is_empty() {
        let id = varint(&mut encoded);
        let len = varint(&mut encoded) as usize;
        assert!(fields.insert(id, encoded[..len].to_vec()).is_none());
        encoded = &encoded[len..];
    }
    let server = Arc::new(QuicServerConfig::try_from(server.as_ref().clone()).unwrap());
    (packets, fields, server)
}

#[test]
fn chrome_initial_advertises_chrome_and_shreds_crypto() {
    let (mut packet, params, server) = initial(&QuicOptions::default());
    assert_eq!(packet.len(), 1250);
    assert_eq!(packet[5], 8);
    assert_eq!(packet[14], 0);
    assert_eq!(params[&0xf], b"");
    for (id, expected) in [
        (0x1, 30_000),
        (0x3, 1472),
        (0x4, 15 * 1024 * 1024),
        (0x5, 6 * 1024 * 1024),
        (0x6, 6 * 1024 * 1024),
        (0x7, 6 * 1024 * 1024),
        (0x8, 100),
        (0x9, 103),
        (0x20, 65_536),
    ] {
        assert_eq!(varint(&mut params[&id].as_slice()), expected);
    }
    assert_eq!(params[&0x3128], b"ORIG");
    assert_eq!(&params[&0x11][..4], &1u32.to_be_bytes());
    assert!(params.keys().any(|&id| id >= 1 << 30 && id % 31 == 27));
    for id in [0xa, 0xb, 0xc, 0xe, 0x2ab2, 0xff04de1b] {
        assert!(!params.contains_key(&id), "{id:#x}");
    }

    let initial_dcid = ConnectionId::new(&packet[6..14]);
    let keys = crypto::ServerConfig::initial_keys(server.as_ref(), 1, &initial_dcid).unwrap();
    let mut body = &packet[15..];
    let token = varint(&mut body) as usize;
    body = &body[token..];
    let payload_size = varint(&mut body) as usize;
    let pn_offset = packet.len() - body.len();
    assert_eq!(pn_offset + payload_size, packet.len());
    keys.header.remote.decrypt(pn_offset, &mut packet);
    assert_eq!(packet[0] & 3, 0);
    assert_eq!(packet[pn_offset], 1);
    let header_len = pn_offset + 1;
    let mut payload = BytesMut::from(&packet[header_len..]);
    keys.packet.remote.decrypt(1, &packet[..header_len], &mut payload).unwrap();
    let mut bytes = payload.as_ref();
    let mut pings = 0;
    let mut crypto_frames = 0;
    while !bytes.is_empty() {
        match varint(&mut bytes) {
            0 => {}
            1 => pings += 1,
            6 => {
                let _offset = varint(&mut bytes);
                let length = varint(&mut bytes) as usize;
                bytes = &bytes[length..];
                crypto_frames += 1;
            }
            kind => panic!("unexpected Initial frame {kind}"),
        }
    }
    assert!((2..=10).contains(&pings));
    assert!(crypto_frames >= 3);
}

#[test]
fn disabling_chrome_applies_explicit_initial_windows() {
    let options = QuicOptions::parse(Some(&json!({
        "disableChromeParrot": true,
        "initStreamReceiveWindow": 65_536,
        "initConnectionReceiveWindow": 163_840,
        "maxStreamReceiveWindow": 131_072,
        "maxConnectionReceiveWindow": 327_680,
        "maxIdleTimeout": 8,
        "disableGSO": true,
        "disablePathMTUDiscovery": true,
    }))).unwrap();
    let (packet, params, _) = initial(&options);
    assert_ne!(packet[6 + usize::from(packet[5])], 0);
    assert_eq!(varint(&mut params[&0x1].as_slice()), 8000);
    assert_eq!(varint(&mut params[&0x4].as_slice()), 163_840);
    assert_eq!(varint(&mut params[&0x5].as_slice()), 65_536);
    assert!(!params.contains_key(&0x20));
    assert!(!params.contains_key(&0x3128));
}

#[test]
fn disables_stateless_resets_for_unknown_cids() {
    use quinn_proto::RandomConnectionIdGenerator;

    for disabled in [false, true] {
        let options = QuicOptions::parse(Some(&json!({"disableStatelessReset": disabled}))).unwrap();
        let mut config = options.endpoint(false);
        config.cid_generator(|| Box::new(RandomConnectionIdGenerator::new(8)));
        let mut endpoint = quinn_proto::Endpoint::new(Arc::new(config), None, true, None);
        let mut input = BytesMut::from(&[0x40; 100][..]);
        let mut response = Vec::new();
        let result = endpoint.handle(
            Instant::now(), "127.0.0.1:443".parse().unwrap(), None, None,
            input.split(), &mut response,
        );
        assert_eq!(matches!(result, Some(quinn_proto::DatagramEvent::Response(_))), !disabled);
        assert_eq!(response.is_empty(), disabled);
    }
}

fn hysteria_server(
    masq: HysteriaMasquerade,
    masks: &FinalMask,
) -> (HysteriaListener, Arc<ClientConfig>) {
    let (client, server) = configs();
    let mut server = server.as_ref().clone();
    server.alpn_protocols = vec![b"h3".to_vec()];
    let server = Arc::new(QuicServerConfig::try_from(server).unwrap());
    let listener = HysteriaListener::bind_crypto_with_masquerade(
        "127.0.0.1:0".parse().unwrap(), server, "secret", masks, masq,
    ).unwrap();
    (listener, client)
}

fn request(
    conn: &H3Conn,
    method: &str,
    path: &str,
    host: &str,
    headers: &[(&str, &str)],
    data: &[u8],
) -> H3Stream {
    let stream = conn.request(method, path, host, "https", headers, false).unwrap();
    stream.write(data).unwrap();
    stream.finish_write().unwrap();
    stream
}

#[test]
fn masquerade_and_rate_negotiation_share_a_quic_connection() {
    let masq = HysteriaMasquerade::parse(Some(r#"{"type":"string","content":"front page","statusCode":418,"headers":{"x-cover":"ok"}}"#)).unwrap();
    let server_masks = FinalMask::parse(r#"{"quicParams":{"brutalUp":"2 Mbps","brutalDown":"1 Mbps","brutalDisableLossCompensation":true}}"#).unwrap();
    let (listener, client) = hysteria_server(masq, &server_masks);
    let addr = listener.local_addr().unwrap();
    let conn = H3Conn::connect(addr, client, "localhost").unwrap();
    let mut hidden = request(&conn, "POST", HYSTERIA_PATH, HYSTERIA_HOST, &[(HYSTERIA_AUTH, "wrong")], b"");
    assert_eq!(hidden.response_status().unwrap(), 418);
    assert_eq!(hidden.header("x-cover").as_deref(), Some("ok"));
    let mut body = String::new();
    hidden.read_to_string(&mut body).unwrap();
    assert_eq!(body, "front page");

    let authenticated = request(&conn, "POST", HYSTERIA_PATH, HYSTERIA_HOST, &[(HYSTERIA_AUTH, "secret"), (HYSTERIA_RATE, "262144")], b"");
    assert_eq!(authenticated.response_status().unwrap(), HYSTERIA_AUTH_OK);
    assert_eq!(authenticated.header(HYSTERIA_RATE).as_deref(), Some("131072"));

    let client_options = QuicOptions::parse(Some(&json!({"brutalUp":"4 Mbps","brutalDown":"1 Mbps"}))).unwrap();
    let (mut read, mut write) = hysteria_stream(conn.clone(), "already authenticated", &client_options).unwrap();
    assert_eq!(conn.0.conn.congestion_state().metrics().pacing_rate, Some(1_048_576));
    let payload = vec![0x5a; 96 * 1024];
    let started = Instant::now();
    write.write_all(&payload).unwrap();
    write.finish().unwrap();
    let (_, mut received, mut output) = listener.accept().unwrap();
    let mut data = Vec::new();
    received.read_to_end(&mut data).unwrap();
    assert_eq!(data, payload);
    assert!(started.elapsed() >= Duration::from_millis(400));
    output.write_all(b"tunnel response").unwrap();
    output.finish().unwrap();
    let mut data = Vec::new();
    read.read_to_end(&mut data).unwrap();
    assert_eq!(data, b"tunnel response");

    let mut after_auth = request(&conn, "GET", "/still-http", "cover.example", &[], b"");
    assert_eq!(after_auth.response_status().unwrap(), 418);
    let mut body = String::new();
    after_auth.read_to_string(&mut body).unwrap();
    assert_eq!(body, "front page");
}

#[test]
fn masquerade_stops_an_unread_request_without_error_and_keeps_its_answer() {
    let masq = HysteriaMasquerade::parse(Some(r#"{"type":"string","content":"front page","statusCode":418}"#)).unwrap();
    let (listener, client) = hysteria_server(masq, &FinalMask::default());
    let conn = H3Conn::connect(listener.local_addr().unwrap(), client, "localhost").unwrap();
    let mut stream = conn.request("POST", "/upload", "cover.example", "https", &[], false).unwrap();
    assert_eq!(stream.response_status().unwrap(), 418);
    let mut body = String::new();
    stream.read_to_string(&mut body).unwrap();
    assert_eq!(body, "front page", "the server answers before the client sends its body");
    // Larger than any stream window, so the write ends only through the server's STOP_SENDING.
    let late = stream.write(&vec![0; 64 << 20]).unwrap_err();
    assert_eq!(peer_stopped(&late), Some(h3::error::Code::H3_NO_ERROR), "the server stops the unread request without error: {late:?}");
    stream.finish_write().expect("a request the server stopped counts as finished");
}

#[test]
fn masquerade_proxy_preserves_body_and_rewrites_forwarding_headers() {
    let origin = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let origin_addr = origin.local_addr().unwrap();
    let backend = std::thread::spawn(move || {
        let (stream, _) = origin.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(4))).unwrap();
        let mut read = BufReader::new(stream);
        let mut line = String::new();
        read.read_line(&mut line).unwrap();
        assert_eq!(line, "POST /base/path?origin=1&client=2 HTTP/1.1\r\n");
        let mut fields = BTreeMap::new();
        loop {
            line.clear();
            read.read_line(&mut line).unwrap();
            if line == "\r\n" { break; }
            let (name, value) = line.split_once(':').unwrap();
            fields.insert(name.to_ascii_lowercase(), value.trim().to_owned());
        }
        assert_eq!(fields["host"], "cover.example");
        assert_eq!(fields["x-forwarded-host"], "cover.example");
        assert_eq!(fields["x-forwarded-proto"], "https");
        assert_eq!(fields["x-forwarded-for"], "127.0.0.1");
        let mut data = [0; 7];
        read.read_exact(&mut data).unwrap();
        assert_eq!(&data, b"request");
        read.get_mut().write_all(
            b"HTTP/1.1 201 Created\r\nContent-Length: 8\r\nConnection: close\r\nX-Origin: proxy\r\n\r\nresponse",
        ).unwrap();
    });
    let config = json!({"type":"proxy","url":format!("http://{origin_addr}/base?origin=1"),"xForwarded":true});
    let masq = HysteriaMasquerade::parse(Some(&config.to_string())).unwrap().with_dialer(Arc::new(move |target| {
        let MasqueradeTarget::Tcp { host, port } = target else { panic!("TCP target") };
        assert_eq!(host, "127.0.0.1");
        assert_eq!(*port, origin_addr.port());
        TcpStream::connect(origin_addr).map(MasqueradeSocket::Tcp)
    }));
    let (listener, client) = hysteria_server(masq, &FinalMask::default());
    let conn = H3Conn::connect(listener.local_addr().unwrap(), client, "localhost").unwrap();
    let mut response = request(
        &conn, "POST", "/path?client=2", "cover.example",
        &[("content-length", "7"), ("x-forwarded-for", "203.0.113.4")], b"request",
    );
    assert_eq!(response.response_status().unwrap(), StatusCode::CREATED.as_u16());
    assert_eq!(response.header("x-origin").as_deref(), Some("proxy"));
    assert_eq!(response.header("connection"), None);
    let mut data = Vec::new();
    response.read_to_end(&mut data).unwrap();
    assert_eq!(data, b"response");
    backend.join().unwrap();
}

#[test]
fn masquerade_file_serves_an_index_and_byte_ranges() {
    let mut suffix = [0; 8];
    getrandom::getrandom(&mut suffix).unwrap();
    let dir = std::env::temp_dir().join(format!("kerlico-hysteria-{:x}", u64::from_ne_bytes(suffix)));
    std::fs::create_dir(&dir).unwrap();
    let index = dir.join("index.html");
    std::fs::write(&index, b"0123456789").unwrap();
    let config = json!({"type":"file","dir":dir});
    let masq = HysteriaMasquerade::parse(Some(&config.to_string())).unwrap();
    let (listener, client) = hysteria_server(masq, &FinalMask::default());
    let conn = H3Conn::connect(listener.local_addr().unwrap(), client, "localhost").unwrap();
    let mut ranged = request(&conn, "GET", "/", "cover.example", &[("range","bytes=2-5")], b"");
    assert_eq!(ranged.response_status().unwrap(), 206);
    assert_eq!(ranged.header("content-range").as_deref(), Some("bytes 2-5/10"));
    let mut body = Vec::new();
    ranged.read_to_end(&mut body).unwrap();
    assert_eq!(body, b"2345");

    let mut head = request(&conn, "HEAD", "/", "cover.example", &[], b"");
    assert_eq!(head.response_status().unwrap(), 200);
    assert_eq!(head.header("content-length").as_deref(), Some("10"));
    assert_eq!(head.read_to_end(&mut Vec::new()).unwrap(), 0);

    let redirect = request(&conn, "GET", "/index.html?x=1", "cover.example", &[], b"");
    assert_eq!(redirect.response_status().unwrap(), 301);
    assert_eq!(redirect.header("location").as_deref(), Some("./?x=1"));
    drop(listener);
    std::fs::remove_file(index).unwrap();
    std::fs::remove_dir(dir).unwrap();
}

#[test]
fn masquerade_https_verifies_certificates_unless_insecure() {
    let origin = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let origin_addr = origin.local_addr().unwrap();
    let (_, origin_tls) = configs();
    let backend = std::thread::spawn(move || {
        let (stream, _) = origin.accept().unwrap();
        let mut rejected = crate::accept_tls(stream, origin_tls.clone()).unwrap();
        assert!(matches!(rejected.read(&mut [0; 1]), Ok(0) | Err(_)));
        let (stream, _) = origin.accept().unwrap();
        let stream = crate::accept_tls(stream, origin_tls).unwrap();
        let mut stream = BufReader::new(stream);
        let mut request = String::new();
        loop {
            let mut line = String::new();
            assert_ne!(stream.read_line(&mut line).unwrap(), 0);
            if line == "\r\n" {
                break;
            }
            request.push_str(&line);
        }
        assert!(request.to_ascii_lowercase().contains(&format!("host: {origin_addr}\r\n")));
        stream.get_mut().write_all(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhttps",
        ).unwrap();
        stream.get_mut().flush().unwrap();
    });
    for insecure in [false, true] {
        let config = json!({
            "type": "proxy", "url": format!("https://{origin_addr}"),
            "insecure": insecure, "rewriteHost": true,
        });
        let masquerade = HysteriaMasquerade::parse(Some(&config.to_string())).unwrap()
            .with_dialer(Arc::new(move |_| TcpStream::connect(origin_addr).map(MasqueradeSocket::Tcp)));
        let (listener, client) = hysteria_server(masquerade, &FinalMask::default());
        let conn = H3Conn::connect(listener.local_addr().unwrap(), client, "localhost").unwrap();
        let mut response = request(&conn, "GET", "/", "cover.example", &[], b"");
        assert_eq!(response.response_status().unwrap(), if insecure { 200 } else { 502 });
        let mut body = String::new();
        response.read_to_string(&mut body).unwrap();
        assert_eq!(body, if insecure { "https" } else { "" });
    }
    backend.join().unwrap();
}

#[cfg(unix)]
#[test]
fn masquerade_proxy_reaches_a_unix_origin() {
    use std::os::unix::net::{UnixListener, UnixStream};

    let mut suffix = [0; 8];
    getrandom::getrandom(&mut suffix).unwrap();
    let path = std::env::temp_dir().join(format!("kerlico-masq-{:x}.sock", u64::from_ne_bytes(suffix)));
    let origin = UnixListener::bind(&path).unwrap();
    let backend = std::thread::spawn(move || {
        let (stream, _) = origin.accept().unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut stream = BufReader::new(stream);
        loop {
            let mut line = String::new();
            assert_ne!(stream.read_line(&mut line).unwrap(), 0);
            if line == "\r\n" {
                break;
            }
        }
        stream.get_mut().write_all(
            b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\nunix",
        ).unwrap();
    });
    let config = json!({"type":"proxy","url":format!("unix://{}", path.display())});
    let masquerade = HysteriaMasquerade::parse(Some(&config.to_string())).unwrap()
        .with_dialer(Arc::new(|target| {
            let MasqueradeTarget::Unix(path) = target else { panic!("Unix origin") };
            UnixStream::connect(path).map(MasqueradeSocket::Unix)
        }));
    let (listener, client) = hysteria_server(masquerade, &FinalMask::default());
    let conn = H3Conn::connect(listener.local_addr().unwrap(), client, "localhost").unwrap();
    let mut response = request(&conn, "GET", "/", "cover.example", &[], b"");
    assert_eq!(response.response_status().unwrap(), 200);
    let mut body = String::new();
    response.read_to_string(&mut body).unwrap();
    assert_eq!(body, "unix");
    backend.join().unwrap();
    std::fs::remove_file(path).unwrap();
}
