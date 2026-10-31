use bytes::BytesMut;
use jls_proto::{ConnectionId, Side, crypto::ServerConfig as _};
use std::sync::Arc;
fn unhex(value: &str) -> Vec<u8> {
    let clean = value
        .chars()
        .filter(|value| !value.is_whitespace())
        .collect::<String>();
    (0..clean.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&clean[index..index + 2], 16).unwrap())
        .collect()
}
fn crypto() -> jls_proto::crypto::rustls::QuicServerConfig {
    let cert = rcgen::generate_simple_self_signed(vec!["example.com".into()]).unwrap();
    let key = rustls_jls::pki_types::PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let mut tls = rustls_jls::ServerConfig::builder_with_provider(Arc::new(
        rustls_jls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls_jls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![rustls_jls::pki_types::CertificateDer::from(
            cert.cert.der().to_vec(),
        )],
        key.into(),
    )
    .unwrap();
    tls.jls_config = rustls_jls::jls::JlsServerConfig::default()
        .enable(false)
        .into();
    jls_proto::crypto::rustls::QuicServerConfig::try_from(tls).unwrap()
}
#[test]
fn rfc9369_initial_keys_header_protection_and_retry_match_fixed_vectors() {
    let crypto = crypto();
    let cid = ConnectionId::new(&unhex("8394c8f03e515708"));
    let keys = crypto.initial_keys(0x6b3343cf, cid).unwrap();
    let mut client = unhex(include_str!("fixtures/rfc9369-client-initial.hex"));
    let original = client.clone();
    keys.header.remote.decrypt(18, &mut client);
    assert_eq!(
        &client[..22],
        unhex("d36b3343cf088394c8f03e5157080000449e00000002")
    );
    let mut payload = BytesMut::from(&client[22..]);
    keys.packet
        .remote
        .decrypt(2, &client[..22], &mut payload)
        .unwrap();
    assert_eq!(payload.len(), 1162);
    assert_eq!(&payload[..5], unhex("060040f101"));
    let mut round = client[..22].to_vec();
    round.extend_from_slice(&payload);
    round.extend([0; 16]);
    keys.packet.remote.encrypt(2, &mut round, 22);
    keys.header.remote.encrypt(18, &mut round);
    assert_eq!(round, original);
    let mut server = unhex(include_str!("fixtures/rfc9369-server-initial.hex"));
    let original = server.clone();
    keys.header.local.decrypt(18, &mut server);
    assert_eq!(
        &server[..20],
        unhex("d16b3343cf0008f067a5502a4262b50040750001")
    );
    let mut payload = BytesMut::from(&server[20..]);
    keys.packet
        .local
        .decrypt(1, &server[..20], &mut payload)
        .unwrap();
    assert_eq!(
        payload.as_ref(),
        unhex(
            "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf73988cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c940d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00020304"
        )
    );
    let mut round = server[..20].to_vec();
    round.extend_from_slice(&payload);
    round.extend([0; 16]);
    keys.packet.local.encrypt(1, &mut round, 20);
    keys.header.local.encrypt(18, &mut round);
    assert_eq!(round, original);
    let retry = unhex("cf6b3343cf0008f067a5502a4262b5746f6b656ec8646ce8bfe33952d955543665dcc7b6");
    assert_eq!(
        crypto
            .retry_tag(0x6b3343cf, cid, &retry[..retry.len() - 16])
            .as_slice(),
        &retry[retry.len() - 16..]
    );
}
#[test]
fn version_information_rejects_zero_duplicate_truncation_and_missing_client_choice() {
    use jls_proto::transport_parameters::TransportParameters;
    for bytes in [
        unhex("11080000000000000001"),
        unhex("11080000000100000000"),
        unhex("1108000000016b3343cf"),
        unhex("11076b3343cf6b3343"),
        unhex("11086b3343cf6b3343cf11086b3343cf6b3343cf"),
    ] {
        assert!(TransportParameters::read(Side::Server, &mut bytes.as_slice()).is_err());
    }
    let bytes = unhex("11086b3343cf6b3343cf");
    let params = TransportParameters::read(Side::Server, &mut bytes.as_slice()).unwrap();
    let mut round = Vec::new();
    params.write(&mut round);
    let parsed = TransportParameters::read(Side::Server, &mut round.as_slice()).unwrap();
    assert_eq!(params, parsed);
    let bytes = unhex("11046b3343cf");
    assert!(TransportParameters::read(Side::Client, &mut bytes.as_slice()).is_ok());
}
#[test]
fn v2_long_header_is_decoded_as_initial_before_any_tls_session_acceptance() {
    let mut endpoint_config = jls_proto::EndpointConfig::default();
    endpoint_config.supported_versions(vec![0x6b3343cf]);
    let server = jls_proto::ServerConfig::with_crypto(Arc::new(crypto()));
    let mut endpoint =
        jls_proto::Endpoint::new(Arc::new(endpoint_config), Some(Arc::new(server)), false);
    let bytes =
        BytesMut::from(unhex(include_str!("fixtures/rfc9369-client-initial.hex")).as_slice());
    let mut response = Vec::new();
    let event = endpoint.handle(
        std::time::Instant::now(),
        "127.0.0.1:45000".parse().unwrap(),
        None,
        None,
        bytes,
        &mut response,
    );
    match event {
        Some(jls_proto::DatagramEvent::NewConnection(incoming)) => {
            let _ = endpoint.refuse(incoming, &mut response);
        }
        _ => panic!("RFC9369 长头未识别为 Initial"),
    }
}

#[test]
fn client_initial_encoder_uses_version_specific_fixed_header_type() {
    for version in [1, 0x6b3343cf] {
        let roots = rustls_jls::RootCertStore::empty();
        let mut tls = rustls_jls::ClientConfig::builder_with_provider(Arc::new(
            rustls_jls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls_jls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        tls.jls_config = rustls_jls::jls::JlsClientConfig::default().enable(false);
        tls.resumption = rustls_jls::client::Resumption::disabled();
        let mut client = jls_proto::ClientConfig::new(Arc::new(
            jls_proto::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
        ));
        client.version(version);
        let mut endpoint_config = jls_proto::EndpointConfig::default();
        endpoint_config.supported_versions(vec![version]);
        let mut endpoint = jls_proto::Endpoint::new(Arc::new(endpoint_config), None, false);
        let now = std::time::Instant::now();
        let (_handle, mut connection) = endpoint
            .connect(
                now,
                client,
                "127.0.0.1:45000".parse().unwrap(),
                "example.com",
            )
            .unwrap();
        let mut packet = Vec::new();
        assert!(connection.poll_transmit(now, 1, &mut packet).is_some());
        assert_eq!(&packet[1..5], version.to_be_bytes());
        assert_eq!(packet[0] & 0x30, if version == 1 { 0 } else { 0x10 });
    }
}
