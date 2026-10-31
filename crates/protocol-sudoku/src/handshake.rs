use crate::{
    codec::{
        obfs::{Decoder, Encoder, ObfsStream},
        record::{Method, Receiver, RecordStream, Sender, UPDATE_BYTES},
        table::{Pair, Table},
    },
    config::Protocol,
    io::Prefix,
    key::{self, Keys},
    wire::kip,
};
use kerlico_core::{BoxStream, Error, Result};
use std::{sync::Arc, time::Instant};
use tokio::io::AsyncReadExt;
use x25519_dalek::StaticSecret;

pub(crate) struct Negotiated {
    pub stream: BoxStream,
    pub features: u32,
}
pub(crate) fn client_table(protocol: &Protocol) -> Result<Arc<Pair>> {
    let index = usize::from(key::random::<1>()?[0]) % protocol.client_tables.len();
    Ok(protocol.client_tables[index].clone())
}
fn obfs(stream: BoxStream, protocol: &Protocol, pair: &Pair, client: bool) -> Result<ObfsStream> {
    let (receive, transmit, rx_packed, tx_packed) = if client {
        (
            pair.down.clone(),
            pair.up.clone(),
            !protocol.pure_downlink,
            false,
        )
    } else {
        (
            pair.up.clone(),
            pair.down.clone(),
            false,
            !protocol.pure_downlink,
        )
    };
    ObfsStream::new(
        stream,
        receive,
        transmit,
        rx_packed,
        tx_packed,
        protocol.padding_min,
        protocol.padding_max,
    )
}
fn record(
    stream: BoxStream,
    protocol: &Protocol,
    pair: &Pair,
    client: bool,
    keys: &Keys,
) -> Result<RecordStream<ObfsStream>> {
    let (send, receive) = if client {
        (*keys.c2s, *keys.s2c)
    } else {
        (*keys.s2c, *keys.c2s)
    };
    RecordStream::new(
        obfs(stream, protocol, pair, client)?,
        protocol.method,
        send,
        receive,
    )
}
fn hello(protocol: &Protocol, pair: &Pair) -> Result<(kip::ClientHello, StaticSecret)> {
    let (secret, public) = key::exchange()?;
    Ok((
        kip::ClientHello {
            timestamp: kip::now()?,
            user_hash: protocol.material.user_hash,
            nonce: key::random()?,
            public,
            features: protocol.features(),
            table_hint: (protocol.client_tables.len() > 1).then_some(pair.hint),
        },
        secret,
    ))
}
fn resolve(protocol: &Protocol, probed: &Arc<Pair>, hello: &kip::ClientHello) -> Result<Arc<Pair>> {
    let Some(hint) = hello.table_hint else {
        return Ok(probed.clone());
    };
    if probed.hint == hint {
        return Ok(probed.clone());
    }
    let selected = protocol
        .server_tables
        .iter()
        .find(|p| p.hint == hint)
        .ok_or_else(crate::invalid)?;
    if !selected.up.layout.ascii || !probed.up.layout.ascii {
        return Err(crate::invalid());
    }
    Ok(selected.clone())
}
fn accept(
    protocol: &Protocol,
    pair: &Arc<Pair>,
    hello: &kip::ClientHello,
) -> Result<(Arc<Pair>, kip::ServerHello, Keys)> {
    let selected = resolve(protocol, pair, hello)?;
    let (secret, public) = key::exchange()?;
    let keys = key::session_keys(&protocol.material.seed, &secret, hello.public, hello.nonce)?;
    protocol
        .replay
        .lock()
        .unwrap()
        .allow(hello.nonce, Instant::now())?;
    Ok((
        selected,
        kip::ServerHello {
            nonce: hello.nonce,
            public,
            features: hello.features & protocol.features(),
        },
        keys,
    ))
}

pub(crate) async fn client(
    stream: BoxStream,
    protocol: &Protocol,
    pair: Arc<Pair>,
) -> Result<Negotiated> {
    let initial = key::initial_keys(&protocol.material.seed)?;
    let mut stream = record(stream, protocol, &pair, true, &initial)?;
    let (hello, secret) = hello(protocol, &pair)?;
    kip::write(&mut stream, kip::CLIENT_HELLO, &hello.encode()).await?;
    let message = kip::read(&mut stream).await?;
    if message.kind != kip::SERVER_HELLO {
        return Err(crate::invalid());
    }
    let response = kip::ServerHello::decode(&message.payload, hello.nonce, hello.features)?;
    let keys = key::session_keys(
        &protocol.material.seed,
        &secret,
        response.public,
        hello.nonce,
    )?;
    stream.rekey(*keys.c2s, *keys.s2c)?;
    Ok(Negotiated {
        stream: Box::new(stream),
        features: response.features,
    })
}

enum Inspection {
    NeedMore,
    Wrong,
    Hello,
}
pub(crate) fn starts(protocol: &Protocol, bytes: &[u8]) -> bool {
    protocol
        .server_tables
        .iter()
        .any(|pair| matches!(inspect(bytes, protocol, pair), Inspection::Hello))
}
pub(crate) fn possible(protocol: &Protocol, bytes: &[u8]) -> bool {
    protocol
        .server_tables
        .iter()
        .any(|pair| !matches!(inspect(bytes, protocol, pair), Inspection::Wrong))
}
fn message(plain: &[u8]) -> Result<Option<kip::Message>> {
    if plain.len() < 6 {
        return Ok(None);
    }
    if &plain[..3] != b"kip" {
        return Err(crate::invalid());
    }
    let length = usize::from(u16::from_be_bytes(plain[4..6].try_into().unwrap()));
    if length > 72 || !matches!(plain[3], kip::CLIENT_HELLO | kip::SERVER_HELLO) {
        return Err(crate::invalid());
    }
    if plain.len() < 6 + length {
        return Ok(None);
    }
    if plain.len() != 6 + length {
        return Err(crate::invalid());
    }
    Ok(Some(kip::Message {
        kind: plain[3],
        payload: plain[6..].to_vec(),
    }))
}
fn inspect(bytes: &[u8], protocol: &Protocol, pair: &Pair) -> Inspection {
    let Ok(initial) = key::initial_keys(&protocol.material.seed) else {
        return Inspection::Wrong;
    };
    let mut decoder = Decoder::new(pair.up.clone(), false);
    let mut receiver = Receiver::new(protocol.method, *initial.c2s);
    let mut frame = Vec::new();
    let mut plain = Vec::new();
    for &byte in bytes {
        let decoded = match decoder.push(byte) {
            Ok(v) => v,
            Err(_) => return Inspection::Wrong,
        };
        let Some(decoded) = decoded else {
            continue;
        };
        if protocol.method == Method::None {
            plain.push(decoded);
        } else {
            frame.push(decoded);
            if frame.len() < 2 {
                continue;
            }
            let length = usize::from(u16::from_be_bytes(frame[..2].try_into().unwrap()));
            if length < 28 {
                return Inspection::Wrong;
            }
            if frame.len() < length + 2 {
                continue;
            }
            match receiver.open(&frame[2..]) {
                Ok(value) => plain.extend(value),
                Err(_) => return Inspection::Wrong,
            };
            frame.clear();
        }
        match message(&plain) {
            Ok(Some(message)) => {
                return if message.kind == kip::CLIENT_HELLO
                    && kip::ClientHello::decode(&message.payload, kip::now().unwrap_or(0)).is_ok()
                {
                    Inspection::Hello
                } else {
                    Inspection::Wrong
                };
            }
            Ok(None) => {}
            Err(_) => return Inspection::Wrong,
        }
    }
    Inspection::NeedMore
}

pub(crate) async fn server(mut raw: BoxStream, protocol: &Protocol) -> Result<Negotiated> {
    let mut bytes = Vec::new();
    let mut chunk = [0; 4096];
    let probed = loop {
        let mut matched = None;
        let mut need_more = false;
        for pair in &protocol.server_tables {
            match inspect(&bytes, protocol, pair) {
                Inspection::Hello => {
                    matched = Some(pair.clone());
                    break;
                }
                Inspection::NeedMore => need_more = true,
                Inspection::Wrong => {}
            }
        }
        if let Some(pair) = matched {
            break pair;
        }
        if !need_more || bytes.len() >= 65536 {
            return Err(crate::invalid());
        }
        let length = (65536 - bytes.len()).min(chunk.len());
        let count = raw.read(&mut chunk[..length]).await?;
        if count == 0 {
            return Err(crate::invalid());
        }
        bytes.extend_from_slice(&chunk[..count]);
    };
    let initial = key::initial_keys(&protocol.material.seed)?;
    let raw = Box::new(Prefix {
        inner: raw,
        bytes,
        used: 0,
    }) as BoxStream;
    let mut stream = record(raw, protocol, &probed, false, &initial)?;
    let message = kip::read(&mut stream).await?;
    if message.kind != kip::CLIENT_HELLO {
        return Err(crate::invalid());
    }
    let hello = kip::ClientHello::decode(&message.payload, kip::now()?)?;
    let (selected, response, keys) = accept(protocol, &probed, &hello)?;
    stream.inner_mut().set_transmit_table(
        selected.down.clone(),
        !protocol.pure_downlink,
        protocol.padding_min,
        protocol.padding_max,
    )?;
    kip::write(&mut stream, kip::SERVER_HELLO, &response.encode()).await?;
    stream.rekey(*keys.s2c, *keys.c2s)?;
    Ok(Negotiated {
        stream: Box::new(stream),
        features: response.features,
    })
}

fn encode_initial(
    protocol: &Protocol,
    pair: &Pair,
    client: bool,
    kind: u8,
    payload: &[u8],
) -> Result<Vec<u8>> {
    let keys = key::initial_keys(&protocol.material.seed)?;
    let base = if client { *keys.c2s } else { *keys.s2c };
    let frame =
        Sender::new(protocol.method, base, UPDATE_BYTES)?.seal(&kip::encode(kind, payload)?)?;
    let table = if client {
        pair.up.clone()
    } else {
        pair.down.clone()
    };
    let mut encoder = Encoder::new(
        table,
        !client && !protocol.pure_downlink,
        protocol.padding_min,
        protocol.padding_max,
    )?;
    let mut encoded = Vec::new();
    encoder.encode(&frame, &mut encoded);
    Ok(encoded)
}
fn decode_initial(
    protocol: &Protocol,
    table: Arc<Table>,
    packed: bool,
    client: bool,
    bytes: &[u8],
) -> Result<kip::Message> {
    if bytes.len() > 65536 {
        return Err(Error::ResourceLimit);
    }
    let keys = key::initial_keys(&protocol.material.seed)?;
    let mut decoder = Decoder::new(table, packed);
    let mut raw = Vec::new();
    for &byte in bytes {
        if let Some(byte) = decoder.push(byte)? {
            raw.push(byte);
        }
    }
    decoder.finish()?;
    let plain = if protocol.method == Method::None {
        raw
    } else {
        let mut receiver =
            Receiver::new(protocol.method, if client { *keys.s2c } else { *keys.c2s });
        let mut plain = Vec::new();
        let mut offset = 0;
        while offset < raw.len() {
            if raw.len() - offset < 2 {
                return Err(crate::invalid());
            }
            let length = usize::from(u16::from_be_bytes(
                raw[offset..offset + 2].try_into().unwrap(),
            ));
            if raw.len() - offset < length + 2 {
                return Err(crate::invalid());
            }
            plain.extend(receiver.open(&raw[offset + 2..offset + 2 + length])?);
            offset += length + 2;
        }
        plain
    };
    message(&plain)?.ok_or_else(crate::invalid)
}

pub(crate) struct EarlyClient {
    pub request: Vec<u8>,
    pair: Arc<Pair>,
    protocol: Arc<Protocol>,
    hello: kip::ClientHello,
    secret: StaticSecret,
}
impl EarlyClient {
    pub fn new(protocol: Arc<Protocol>) -> Result<Self> {
        let pair = client_table(&protocol)?;
        let (hello, secret) = hello(&protocol, &pair)?;
        let request = encode_initial(&protocol, &pair, true, kip::CLIENT_HELLO, &hello.encode())?;
        Ok(Self {
            request,
            pair,
            protocol,
            hello,
            secret,
        })
    }
    pub fn finish(self, stream: BoxStream, response: &[u8]) -> Result<Negotiated> {
        let message = decode_initial(
            &self.protocol,
            self.pair.down.clone(),
            !self.protocol.pure_downlink,
            true,
            response,
        )?;
        if message.kind != kip::SERVER_HELLO {
            return Err(crate::invalid());
        }
        let response =
            kip::ServerHello::decode(&message.payload, self.hello.nonce, self.hello.features)?;
        let keys = key::session_keys(
            &self.protocol.material.seed,
            &self.secret,
            response.public,
            self.hello.nonce,
        )?;
        Ok(Negotiated {
            stream: Box::new(record(stream, &self.protocol, &self.pair, true, &keys)?),
            features: response.features,
        })
    }
}
pub(crate) struct EarlyServer {
    pub response: Vec<u8>,
    pub features: u32,
    pair: Arc<Pair>,
    protocol: Arc<Protocol>,
    keys: Keys,
}
impl EarlyServer {
    pub fn prepare(protocol: Arc<Protocol>, request: &[u8]) -> Result<Self> {
        for pair in &protocol.server_tables {
            let message = match decode_initial(&protocol, pair.up.clone(), false, false, request) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if message.kind != kip::CLIENT_HELLO {
                continue;
            }
            let hello = kip::ClientHello::decode(&message.payload, kip::now()?)?;
            let (selected, response, keys) = accept(&protocol, pair, &hello)?;
            let encoded = encode_initial(
                &protocol,
                &selected,
                false,
                kip::SERVER_HELLO,
                &response.encode(),
            )?;
            return Ok(Self {
                response: encoded,
                features: response.features,
                pair: selected,
                protocol,
                keys,
            });
        }
        Err(crate::invalid())
    }
    pub fn finish(self, stream: BoxStream) -> Result<Negotiated> {
        Ok(Negotiated {
            stream: Box::new(record(
                stream,
                &self.protocol,
                &self.pair,
                false,
                &self.keys,
            )?),
            features: self.features,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NodeOptions;
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    fn config(method: &str, mode: &str, pure: bool) -> Arc<Protocol> {
        let patterns = if mode == "prefer_ascii" {
            Vec::<String>::new()
        } else {
            vec!["xpxvvpvv".to_owned(), "vxpvxvvp".to_owned()]
        };
        serde_json::from_value::<NodeOptions>(json!({"protocol":{"key":"synthetic-sudoku-handshake-seed","aead":method,"allow_insecure":method=="none","table_type":mode,"custom_tables":patterns,"pure_downlink":pure}})).unwrap().prepare().unwrap().protocol
    }
    #[tokio::test]
    async fn complete_raw_role_table_and_downlink_matrix_keeps_bidirectional_eof() {
        for method in ["aes-128-gcm", "chacha20-poly1305", "none"] {
            for mode in [
                "prefer_ascii",
                "prefer_entropy",
                "up_ascii_down_entropy",
                "up_entropy_down_ascii",
            ] {
                for pure in [false, true] {
                    let protocol = config(method, mode, pure);
                    let (a, b) = tokio::io::duplex(127);
                    let server_cfg = protocol.clone();
                    let serving = tokio::spawn(async move {
                        let negotiated = server(Box::new(b), &server_cfg).await.unwrap();
                        assert_eq!(negotiated.features, kip::FEATURES);
                        let mut stream = negotiated.stream;
                        let message = kip::read(&mut stream).await.unwrap();
                        assert_eq!(message.kind, kip::OPEN_TCP);
                        assert_eq!(message.payload, b"intent");
                        let mut payload = Vec::new();
                        stream.read_to_end(&mut payload).await.unwrap();
                        assert_eq!(payload, vec![0x3a; 65537]);
                        stream.write_all(b"after-fin").await.unwrap();
                        stream.shutdown().await.unwrap();
                    });
                    let pair = client_table(&protocol).unwrap();
                    let mut stream = client(Box::new(a), &protocol, pair).await.unwrap().stream;
                    kip::write(&mut stream, kip::OPEN_TCP, b"intent")
                        .await
                        .unwrap();
                    stream.write_all(&vec![0x3a; 65537]).await.unwrap();
                    stream.shutdown().await.unwrap();
                    let mut reply = Vec::new();
                    stream.read_to_end(&mut reply).await.unwrap();
                    assert_eq!(&reply, b"after-fin");
                    serving.await.unwrap();
                }
            }
        }
    }
    #[tokio::test]
    async fn early_hello_rekeys_once_preserves_data_and_replay_domain() {
        for method in ["aes-128-gcm", "chacha20-poly1305", "none"] {
            for pure in [false, true] {
                let protocol = config(method, "up_ascii_down_entropy", pure);
                let client = EarlyClient::new(protocol.clone()).unwrap();
                let server = EarlyServer::prepare(protocol.clone(), &client.request).unwrap();
                assert!(EarlyServer::prepare(protocol.clone(), &client.request).is_err());
                let response = server.response.clone();
                let (a, b) = tokio::io::duplex(67);
                let mut client = client.finish(Box::new(a), &response).unwrap().stream;
                let mut server = server.finish(Box::new(b)).unwrap().stream;
                let peer = tokio::spawn(async move {
                    let mut data = [0; 5];
                    server.read_exact(&mut data).await.unwrap();
                    assert_eq!(&data, b"hello");
                    server.write_all(b"world").await.unwrap();
                    server.shutdown().await.unwrap();
                });
                client.write_all(b"hello").await.unwrap();
                client.flush().await.unwrap();
                let mut data = Vec::new();
                client.read_to_end(&mut data).await.unwrap();
                assert_eq!(&data, b"world");
                peer.await.unwrap();
            }
        }
    }
    #[test]
    fn altered_early_bytes_do_not_create_a_session_or_mix_seeds() {
        let protocol = config("chacha20-poly1305", "prefer_ascii", true);
        let client = EarlyClient::new(protocol.clone()).unwrap();
        let mut request = client.request.clone();
        request.truncate(request.len() / 2);
        assert!(EarlyServer::prepare(protocol.clone(), &request).is_err());
        let other = serde_json::from_value::<NodeOptions>(
            json!({"protocol":{"key":"synthetic-other-sudoku-seed","table_type":"prefer_ascii"}}),
        )
        .unwrap()
        .prepare()
        .unwrap()
        .protocol;
        assert!(EarlyServer::prepare(other, &client.request).is_err());
        let server = EarlyServer::prepare(protocol.clone(), &client.request).unwrap();
        let mut response = server.response.clone();
        response.truncate(response.len() / 2);
        let (a, _) = tokio::io::duplex(32);
        assert!(client.finish(Box::new(a), &response).is_err());
    }
}
