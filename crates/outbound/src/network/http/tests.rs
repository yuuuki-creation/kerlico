use super::*;
use kerlico_shared::runtime::NetworkDial;
use kerlico_shared::Transport;
use std::net::TcpListener;

fn request(peer: std::net::SocketAddr, tls: bool) -> HttpRequest {
    HttpRequest {
        url: format!(
            "{}://localhost:{}/metadata?key=1",
            if tls { "https" } else { "http" },
            peer.port()
        ),
        method: "POST".into(),
        headers: vec![("x-runtime".into(), "owned".into())],
        body: b"request body".to_vec(),
        http2: false,
        dial: NetworkDial::direct(peer, Transport::Tcp),
    }
}
fn reply(mut stream: impl Read + Write) {
    let mut request = Vec::new();
    loop {
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        request.push(byte[0]);
        if request.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let head = String::from_utf8(request).unwrap();
    assert!(head.starts_with("POST /metadata?key=1 HTTP/1.1\r\n"));
    assert!(head.contains("x-runtime: owned\r\n"));
    let mut body = [0; 12];
    stream.read_exact(&mut body).unwrap();
    assert_eq!(&body, b"request body");
    stream
        .write_all(
            b"HTTP/1.1 201 Created\r\nContent-Length: 8\r\nConnection: close\r\n\r\nmetadata",
        )
        .unwrap();
    stream.flush().unwrap();
}

#[test]
fn http_metadata_forwards_method_headers_and_body() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let peer = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        reply(listener.accept().unwrap().0);
    });
    let response = crate::Outbound::new()
        .exchange_http_transport(&request(peer, false), crate::Native { v4: true, v6: true })
        .unwrap();
    assert_eq!(
        response,
        HttpResponse {
            status: 201,
            body: b"metadata".to_vec()
        }
    );
    server.join().unwrap();
}

#[test]
fn h2_metadata_sends_body_and_consumes_response() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let peer = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let socket = listener.accept().unwrap().0;
        socket.set_nonblocking(true).unwrap();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let io = TokioIo::new(tokio::net::TcpStream::from_std(socket).unwrap());
                let service = hyper::service::service_fn(
                    |request: hyper::Request<hyper::body::Incoming>| async {
                        assert_eq!(request.method(), "POST");
                        assert_eq!(
                            request.uri().path_and_query().unwrap().as_str(),
                            "/metadata?key=1"
                        );
                        assert_eq!(request.headers()["x-runtime"], "owned");
                        assert_eq!(
                            request.into_body().collect().await.unwrap().to_bytes(),
                            b"request body"[..]
                        );
                        Ok::<_, std::convert::Infallible>(hyper::Response::new(Full::new(
                            Bytes::from_static(b"h2 metadata"),
                        )))
                    },
                );
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(io, service)
                    .await;
            });
    });
    let mut message = request(peer, false);
    message.http2 = true;
    let response = crate::Outbound::new()
        .exchange_http_transport(&message, crate::Native { v4: true, v6: true })
        .unwrap();
    assert_eq!(response.body, b"h2 metadata");
    server.join().unwrap();
}

#[test]
fn https_metadata_verifies_local_trust_and_reads_tls_response() {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = certified.cert.der().clone();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der());
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key.into())
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let config_client = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let peer = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        reply(rustls::StreamOwned::new(
            rustls::ServerConnection::new(Arc::new(config)).unwrap(),
            listener.accept().unwrap().0,
        ));
    });
    let response = exchange_with_tls(
        request(peer, true),
        NetworkConnection::Tcp(std::net::TcpStream::connect(peer).unwrap()),
        Some(Arc::new(config_client)),
    )
    .unwrap();
    assert_eq!(response.body, b"metadata");
    server.join().unwrap();
}
