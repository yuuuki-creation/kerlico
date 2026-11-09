use super::*;
use crate::xhttp::read_http_head;

fn config(settings: &[(&str, &str)]) -> XhttpConfig {
    XhttpConfig::from_settings(|key| {
        settings
            .iter()
            .find_map(|(name, value)| (*name == key).then_some(*value))
    })
    .unwrap()
}

fn lookup<'a>(headers: &'a [(String, String)]) -> impl Fn(&str) -> Option<String> + 'a {
    move |key| {
        headers
            .iter()
            .find_map(|(name, value)| (name == key).then(|| value.clone()))
    }
}

#[test]
fn packet_metadata_preserves_base_query_and_chunks_header_payload() {
    let config = config(&[
        ("mode", "packet-up"),
        ("path", "path a/%2F?sort=two+words&sid=old"),
        ("uplinkHTTPMethod", "get"),
        ("sessionIDPlacement", "query"),
        ("sessionIDKey", "sid"),
        ("seqPlacement", "cookie"),
        ("seqKey", "n"),
        ("xPaddingObfsMode", "true"),
        ("xPaddingPlacement", "cookie"),
        ("xPaddingKey", "p"),
        ("xPaddingBytes", "4"),
        ("uplinkDataPlacement", "header"),
        ("uplinkDataKey", "X-Upload"),
        ("uplinkChunkSize", "32"),
    ]);
    let payload: Vec<u8> = (0..96).collect();
    let request = config
        .request(
            XhttpRequestKind::PacketUp {
                session: "ab +/=",
                seq: 41,
            },
            "example.org",
            "http",
            &payload,
        )
        .unwrap();
    assert_eq!(request.method, "GET");
    assert_eq!(
        request.target,
        "/path%20a/%252F?sid=ab+%2B%2F%3D&sort=two+words"
    );
    assert!(request.body.is_empty());
    assert_eq!(
        lookup(&request.headers)("cookie").as_deref(),
        Some("p=XXXX; n=41")
    );
    assert_eq!(lookup(&request.headers)("x-upload-0").unwrap().len(), 64);
    assert_eq!(lookup(&request.headers)("x-upload-1").unwrap().len(), 64);
    let mut wire = Vec::new();
    request.write_h1(&mut wire, "example.org").unwrap();
    let head = read_http_head(&mut wire.as_slice()).unwrap();
    assert_eq!(head.length, Some(0));
    assert_eq!(head.header("connection"), None);
    let kind = config
        .classify(&head.method, &head.target, |name| head.header(name))
        .unwrap();
    assert_eq!(
        kind,
        XhttpRequestKind::PacketUp {
            session: "ab +/=".to_owned(),
            seq: 41
        }
    );
    assert_eq!(
        config
            .packet_payload(head.rest.clone(), |name| head.header(name))
            .unwrap(),
        payload
    );
}

#[test]
fn auto_packet_decode_joins_header_cookie_and_body_in_wire_order() {
    let config = config(&[("scMaxEachPostBytes", "9")]);
    let header = |key: &str| match key {
        "x-data-0" => Some("YW".to_owned()),
        "x-data-1" => Some("Jj".to_owned()),
        "cookie" => Some("X-Data_0=ZGVm".to_owned()),
        _ => None,
    };
    assert_eq!(
        config.packet_payload(b"ghi".to_vec(), header).unwrap(),
        b"abcdefghi"
    );
    assert!(config.packet_payload(b"ghij".to_vec(), header).is_err());
}

#[test]
fn padding_placements_round_trip_with_hpack_length_validation() {
    for placement in ["header", "queryInHeader", "cookie", "query"] {
        let config = config(&[
            ("path", "/path"),
            ("sessionIDPlacement", "header"),
            ("seqPlacement", "query"),
            ("xPaddingObfsMode", "true"),
            ("xPaddingPlacement", placement),
            ("xPaddingKey", "cover"),
            ("xPaddingHeader", "X-Cover"),
            ("xPaddingMethod", "tokenish"),
            ("xPaddingBytes", "32"),
        ]);
        let request = config
            .request(
                XhttpRequestKind::Download { session: "abc" },
                "example.org",
                "https",
                &[],
            )
            .unwrap();
        assert!(!request.target.starts_with("/path/"));
        let kind = config
            .classify(&request.method, &request.target, lookup(&request.headers))
            .unwrap();
        assert_eq!(
            kind,
            XhttpRequestKind::Download {
                session: "abc".to_owned()
            }
        );
        let response = config
            .response_headers(&kind, "GET", lookup(&request.headers))
            .unwrap();
        let response = lookup(&response);
        let padding = match placement {
            "header" => response("x-cover").unwrap(),
            "queryInHeader" => response("x-cover")
                .unwrap()
                .strip_prefix("?cover=")
                .unwrap()
                .to_owned(),
            "cookie" => {
                assert_eq!(
                    response("access-control-allow-credentials").as_deref(),
                    Some("true")
                );
                response("set-cookie")
                    .unwrap()
                    .strip_prefix("cover=")
                    .unwrap()
                    .strip_suffix("; Path=/")
                    .unwrap()
                    .to_owned()
            }
            "query" => {
                assert_eq!(response("x-cover"), None);
                continue;
            }
            _ => unreachable!(),
        };
        assert!((30..=34).contains(&huffman_bits(&padding).div_ceil(8)));
    }
}

#[test]
fn legacy_referer_and_query_padding_and_options_preflight() {
    let config = config(&[("path", "/x"), ("xPaddingBytes", "5")]);
    let request = config
        .request(
            XhttpRequestKind::StreamUp { session: "abc" },
            "example.org",
            "http",
            &[],
        )
        .unwrap();
    assert_eq!(request.target, "/x/abc");
    assert_eq!(
        lookup(&request.headers)("referer").as_deref(),
        Some("http://example.org/x/?x_padding=XXXXX")
    );
    let target = "/x/abc?x_padding=XXXXX";
    assert_eq!(
        config.classify("POST", target, |_| None).unwrap(),
        XhttpRequestKind::StreamUp {
            session: "abc".to_owned()
        }
    );
    assert!(config.classify("GET", "/x/abc", |_| None).is_err());
    let preflight = |key: &str| (key == "access-control-request-method").then(|| "POST".to_owned());
    assert_eq!(
        config.classify("OPTIONS", "/x/", preflight).unwrap(),
        XhttpRequestKind::Preflight
    );
}

#[test]
fn streaming_close_header_and_xray_extra_precedence() {
    let config = config(&[
        ("host", "myhost"),
        ("path", "/x"),
        ("mode", "auto"),
        ("noGRPCHeader", "false"),
        (
            "extra",
            r#"{"path":"/ignored","mode":"packet-up","noGRPCHeader":true,"noSSEHeader":true,"uplinkHTTPMethod":"put","sessionIDTable":"hex","sessionIDLength":8,"downloadSettings":{"address":"download.example","port":443,"network":"xhttp"},"headers":{"User-Agent":"test"}}"#,
        ),
    ]);
    assert_eq!(config.host(), "myhost");
    assert_eq!(config.mode(false, false), XhttpMode::PacketUp);
    assert_eq!(config.mode(true, false), XhttpMode::StreamOne);
    assert_eq!(config.mode(true, true), XhttpMode::StreamUp);
    assert_eq!(
        config.download_settings().unwrap()["address"],
        "download.example"
    );
    let session = config.session_id().unwrap();
    assert_eq!(session.len(), 8);
    assert!(session
        .bytes()
        .all(|byte| b"0123456789abcdef".contains(&byte)));
    let request = config
        .request(
            XhttpRequestKind::StreamUp { session: &session },
            "myhost",
            "http",
            &[],
        )
        .unwrap();
    assert_eq!(request.method, "PUT");
    assert_eq!(request.target, format!("/x/{session}"));
    assert_eq!(lookup(&request.headers)("content-type"), None);
    let mut wire = Vec::new();
    request.write_h1(&mut wire, "myhost").unwrap();
    let head = read_http_head(&mut wire.as_slice()).unwrap();
    assert!(head.chunked);
    assert_eq!(head.header("connection").as_deref(), Some("close"));
    assert_eq!(head.header("user-agent").as_deref(), Some("test"));
}
