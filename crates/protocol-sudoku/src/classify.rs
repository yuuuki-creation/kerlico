use crate::{
    config::{CarrierMode, Protocol},
    handshake,
    io::Prefix,
};
use kerlico_core::{BoxStream, Error, Result};
use tokio::io::AsyncReadExt;

pub(crate) enum Classified {
    Raw(BoxStream),
    Legacy {
        stream: BoxStream,
        cover_method: Option<http::Method>,
    },
    Http {
        stream: BoxStream,
        h2: bool,
    },
}

fn looks(bytes: &[u8]) -> bool {
    [
        b"GET ".as_slice(),
        b"POST",
        b"HEAD",
        b"PUT ",
        b"CONN",
        b"OPTI",
        b"DELE",
        b"PATC",
        b"PRI ",
    ]
    .iter()
    .any(|prefix| bytes.starts_with(prefix))
}
pub(crate) async fn read(
    mut stream: BoxStream,
    protocol: &Protocol,
    mode: CarrierMode,
    root: &str,
    cover: bool,
    h2: bool,
) -> Result<Classified> {
    if h2 {
        return Ok(Classified::Http { stream, h2: true });
    }
    if mode == CarrierMode::Raw && !cover {
        return Ok(Classified::Raw(stream));
    }
    let mut bytes = Vec::new();
    let mut input = [0; 1024];
    loop {
        if bytes.len() >= 4 {
            if !looks(&bytes) || handshake::starts(protocol, &bytes) {
                return Ok(Classified::Raw(Box::new(Prefix {
                    inner: stream,
                    bytes,
                    used: 0,
                })));
            }
            const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
            if bytes.starts_with(PREFACE) {
                return Ok(Classified::Http {
                    stream: Box::new(Prefix {
                        inner: stream,
                        bytes,
                        used: 0,
                    }),
                    h2: true,
                });
            }
            if !PREFACE.starts_with(&bytes) {
                let mut fields = [httparse::EMPTY_HEADER; 64];
                let mut request = httparse::Request::new(&mut fields);
                match request.parse(&bytes) {
                    Ok(httparse::Status::Complete(length)) => {
                        let tunnel_label = request.headers.iter().any(|h| h.name.eq_ignore_ascii_case("x-sudoku-tunnel"));
                        let tunnel = tunnel_label || request.headers.iter().any(|h| h.name.eq_ignore_ascii_case("upgrade"));
                        let method = request.method.unwrap_or("");
                        let safe = matches!(method, "GET" | "HEAD")
                            && !tunnel
                            && !request.headers.iter().any(|h| {
                                h.name.eq_ignore_ascii_case("transfer-encoding")
                                    || h.name.eq_ignore_ascii_case("content-length")
                                        && h.value != b"0"
                            });
                        let cover_method = safe.then(|| {
                            if method == "HEAD" {
                                http::Method::HEAD
                            } else {
                                http::Method::GET
                            }
                        });
                        let legacy_probe = mode == CarrierMode::Auto
                            && safe
                            && method == "GET"
                            && request.path == Some(format!("{root}/").as_str());
                        if (mode == CarrierMode::Legacy && !tunnel_label) || legacy_probe {
                            let tail = bytes[length..].to_vec();
                            return Ok(Classified::Legacy {
                                stream: Box::new(Prefix {
                                    inner: stream,
                                    bytes: tail,
                                    used: 0,
                                }),
                                cover_method,
                            });
                        }
                        return Ok(Classified::Http {
                            stream: Box::new(Prefix {
                                inner: stream,
                                bytes,
                                used: 0,
                            }),
                            h2: false,
                        });
                    }
                    Ok(httparse::Status::Partial) => {}
                    Err(_) if handshake::possible(protocol, &bytes) => {}
                    Err(_) => return Err(crate::invalid()),
                }
            }
        }
        if bytes.len() >= 32 * 1024 {
            return Err(Error::ResourceLimit);
        }
        let available = input.len().min(32 * 1024 - bytes.len());
        let count = stream.read(&mut input[..available]).await?;
        if count == 0 {
            return Err(crate::invalid());
        }
        bytes.extend_from_slice(&input[..count]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NodeOptions;
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn auto_strips_only_the_exact_legacy_probe_and_keeps_api_headers() {
        let protocol = serde_json::from_value::<NodeOptions>(json!({"protocol":{"key":"synthetic-sudoku-classify"}})).unwrap().prepare().unwrap().protocol;
        for (method, path, framing, legacy) in [
            ("GET", "/gate/", "Content-Length: 0\r\n", true),
            ("GET", "/gate/session", "Content-Length: 0\r\n", false),
            ("GET", "/gate-other/", "Content-Length: 0\r\n", false),
            ("GET", "/gate/", "Content-Length: 1\r\n", false),
            ("GET", "/gate/", "Upgrade: websocket\r\n", false),
            ("HEAD", "/gate/", "Content-Length: 0\r\n", false),
        ] {
            let header = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\n{framing}\r\n");
            let tail = b"synthetic-preserved-tail";
            let (stream, mut peer) = tokio::io::duplex(1024);
            peer.write_all(header.as_bytes()).await.unwrap();peer.write_all(tail).await.unwrap();peer.shutdown().await.unwrap();
            let classified = read(Box::new(stream), &protocol, CarrierMode::Auto, "/gate", false, false).await.unwrap();
            let mut input = match classified {
                Classified::Legacy {stream, ..} if legacy => stream,
                Classified::Http {stream, h2:false} if !legacy => stream,
                _ => panic!("载体分类不符合边界: {method} {path}"),
            };
            let mut bytes = Vec::new();input.read_to_end(&mut bytes).await.unwrap();
            let expected = if legacy {tail.to_vec()} else {[header.as_bytes(), tail].concat()};assert_eq!(bytes, expected);
        }
    }

    #[tokio::test]
    async fn dedicated_legacy_authenticates_raw_kip_after_fake_post_or_upgrade_headers() {
        let protocol = serde_json::from_value::<NodeOptions>(json!({"protocol":{"key":"synthetic-sudoku-native-legacy"}})).unwrap().prepare().unwrap().protocol;
        for header in [
            "POST /api/v1/upload HTTP/1.1\r\nHost: localhost\r\nContent-Length: 10485760\r\n\r\n",
            "GET /ws HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: AAECAwQFBgcICQoLDA0ODw==\r\nSec-WebSocket-Version: 13\r\n\r\n",
        ] {
            let (mut client, server) = tokio::io::duplex(127);
            let connecting = async {
                client.write_all(header.as_bytes()).await.unwrap();client.flush().await.unwrap();
                handshake::client(Box::new(client), &protocol, handshake::client_table(&protocol).unwrap()).await
            };
            let accepting = async {
                let classified = read(Box::new(server), &protocol, CarrierMode::Legacy, "", false, false).await.unwrap();
                let Classified::Legacy {stream, ..} = classified else {panic!("专用legacy被误分流到实际HTTP/WS");};
                handshake::server(stream, &protocol).await
            };
            let (client, server) = tokio::time::timeout(std::time::Duration::from_secs(3), async{tokio::join!(connecting,accepting)}).await.unwrap();
            assert_eq!(client.unwrap().features, crate::wire::kip::FEATURES);
            assert_eq!(server.unwrap().features, crate::wire::kip::FEATURES);
        }
    }
}
