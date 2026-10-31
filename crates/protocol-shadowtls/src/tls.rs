//! 由既有 TLS 引擎完成真实握手，握手后明确脱离 TLS 业务加密。
use crate::{config, wire};
use hmac::Mac;
use kerlico_core::{BoxStream, Result};
use rand::RngCore;
use rustls::{
    ClientConfig, ClientConnection, RootCertStore,
    client::{
        ClientHelloContext, ClientHelloCustomizer, ClientHelloPlan, ClientHelloSessionId,
        FinalizesClientHello,
    },
};
use std::{
    io::Cursor,
    sync::{Arc, Mutex},
};
use tokio::io::AsyncWriteExt;

struct Signer {
    key: Arc<[u8]>,
    session: Mutex<Option<[u8; 32]>>,
}
impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ShadowTLSClientHelloSigner")
    }
}
impl FinalizesClientHello for Signer {
    fn finalize_client_hello(&self, bytes: &mut Vec<u8>) -> std::result::Result<(), rustls::Error> {
        if bytes.len() < 71 || bytes[0] != 1 || bytes[38] != 32 {
            return Err(rustls::Error::General(
                "ShadowTLS ClientHello 不合法".into(),
            ));
        }
        let mut cache = self
            .session
            .lock()
            .map_err(|_| rustls::Error::General("ShadowTLS 会话状态不可用".into()))?;
        let sid = if let Some(sid) = *cache {
            sid
        } else {
            let mut sid = [0; 32];
            rand::thread_rng().fill_bytes(&mut sid[..28]);
            let mut state = wire::hash(&self.key, &bytes[..39]);
            state.update(&sid);
            state.update(&bytes[71..]);
            sid[28..].copy_from_slice(&wire::sum::<4>(&state));
            *cache = Some(sid);
            sid
        };
        bytes[39..71].copy_from_slice(&sid);
        Ok(())
    }
}
#[derive(Debug)]
struct Customize {
    signer: Arc<Signer>,
}
impl ClientHelloCustomizer for Customize {
    fn build_client_hello_plan(
        &self,
        _context: ClientHelloContext<'_>,
    ) -> std::result::Result<Option<ClientHelloPlan>, rustls::Error> {
        Ok(Some(
            ClientHelloPlan::new()
                .with_session_id(ClientHelloSessionId::try_from(vec![0; 32])?)
                .with_finalizer(self.signer.clone()),
        ))
    }
}
pub(crate) struct Settings {
    pub config: ClientConfig,
    pub name: rustls::pki_types::ServerName<'static>,
}
pub(crate) fn settings(value: &config::Tls, version: u8, strict: bool) -> Result<Settings> {
    if version == 3 && strict && value.version == "1.2" {
        return Err(config::invalid());
    }
    let versions: Vec<_> = match (version, strict, value.version.as_str()) {
        (1, _, "auto" | "1.2") => vec![&rustls::version::TLS12],
        (3, true, "auto" | "1.3") => vec![&rustls::version::TLS13],
        (_, _, "1.2") => vec![&rustls::version::TLS12],
        (_, _, "1.3") => vec![&rustls::version::TLS13],
        (_, _, "auto") => vec![&rustls::version::TLS13, &rustls::version::TLS12],
        _ => return Err(config::invalid()),
    };
    let mut roots = RootCertStore::empty();
    if let Some(pem) = &value.ca_pem {
        if pem.len() > 1024 * 1024 {
            return Err(config::invalid());
        }
        let certs = rustls_pemfile::certs(&mut Cursor::new(pem.as_bytes()))
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| config::invalid())?;
        if certs.is_empty() {
            return Err(config::invalid());
        }
        for cert in certs {
            roots.add(cert).map_err(|_| config::invalid())?;
        }
    } else {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&versions)
            .map_err(|_| config::invalid())?
            .with_root_certificates(roots)
            .with_no_client_auth();
    config.resumption = rustls::client::Resumption::disabled();
    config.enable_early_data = false;
    if value.alpn.len() > 16 || value.alpn.iter().any(|p| p.is_empty() || p.len() > 255) {
        return Err(config::invalid());
    }
    config.alpn_protocols = value.alpn.iter().map(|p| p.as_bytes().to_vec()).collect();
    let name = rustls::pki_types::ServerName::try_from(value.server_name.clone())
        .map_err(|_| config::invalid())?;
    Ok(Settings { config, name })
}
pub(crate) struct Outcome {
    pub stream: BoxStream,
    pub session: ClientConnection,
    pub transcript: wire::Hash,
    pub random: Option<[u8; 32]>,
    pub ignore: Option<wire::Hash>,
}
async fn flush(session: &mut ClientConnection, stream: &mut BoxStream) -> Result<()> {
    while session.wants_write() {
        let mut bytes = Vec::new();
        session.write_tls(&mut bytes)?;
        stream.write_all(&bytes).await?;
    }
    stream.flush().await?;
    Ok(())
}
pub(crate) async fn handshake(
    mut stream: BoxStream,
    settings: &Settings,
    version: u8,
    strict: bool,
    key: Arc<[u8]>,
) -> Result<Outcome> {
    let mut config = settings.config.clone();
    if version == 3 {
        config.client_hello_customizer = Some(Arc::new(Customize {
            signer: Arc::new(Signer {
                key: key.clone(),
                session: Mutex::new(None),
            }),
        }));
    }
    let mut session = ClientConnection::new(Arc::new(config), settings.name.clone())
        .map_err(|_| wire::error())?;
    let mut transcript = wire::hash(&key, &[]);
    let mut random = None;
    let mut ignore = None;
    let mut authorized = false;
    let mut frames = 0;
    let mut bytes = 0;
    flush(&mut session, &mut stream).await?;
    while session.is_handshaking() {
        let mut record = wire::read(&mut stream).await?.ok_or_else(wire::error)?;
        frames += 1;
        bytes += record.len();
        if frames > 256 || bytes > 1024 * 1024 {
            return Err(wire::error());
        }
        transcript.update(&record);
        if version == 3 {
            if record[0] == wire::HANDSHAKE && record.get(5) == Some(&2) && random.is_none() {
                let (seed, tls13) = wire::server_hello(&record)?;
                if strict && !tls13 {
                    return Err(wire::error());
                }
                if !(tls13 && seed==wire::HRR_RANDOM) {
                    authorized = !tls13;
                    ignore = Some(wire::hash(&key, &seed));
                    random = Some(seed);
                }
            } else if record[0] == wire::APP {
                authorized = false;
                if let (Some(hash), Some(seed)) = (&mut ignore, &random)
                    && wire::verify(hash, &record[5..], false)
                {
                    let mut payload = record[9..].to_vec();
                    wire::xor(&key, seed, &mut payload);
                    record = wire::frame(wire::APP, &payload);
                    authorized = true;
                }
            }
        }
        session.read_tls(&mut Cursor::new(record))?;
        if session.process_new_packets().is_err() {
            let _ = flush(&mut session, &mut stream).await;
            return Err(wire::error());
        }
        flush(&mut session, &mut stream).await?;
    }
    if version == 3 && (!authorized || random.is_none()) {
        // 成功的真实 TLS 上只发掩护请求；内层地址和凭据尚未交给该连接。
        let mut noise = [0; 24];
        rand::thread_rng().fill_bytes(&mut noise);
        let cookie: String = noise.iter().map(|b| format!("{b:02x}")).collect();
        let request = format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nCookie: session={}\r\n\r\n",
            settings.name.to_str(),
            cookie
        );
        let _ = std::io::Write::write_all(&mut session.writer(), request.as_bytes());
        let _ = flush(&mut session, &mut stream).await;
        let _ = stream.shutdown().await;
        return Err(wire::error());
    }
    Ok(Outcome {
        stream,
        session,
        transcript,
        random,
        ignore,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signer_uses_the_real_message_and_keeps_session_id_on_retry() {
        let signer = Signer {
            key: Arc::from(b"tls-test-key".as_slice()),
            session: Mutex::new(None),
        };
        let mut message = vec![1, 0, 0, 67, 3, 3];
        message.extend_from_slice(&[8; 32]);
        message.push(32);
        message.extend_from_slice(&[0; 32]);
        signer.finalize_client_hello(&mut message).unwrap();
        let record = wire::frame(wire::HANDSHAKE, &message);
        assert!(wire::client_auth(&record, b"tls-test-key"));
        assert!(!wire::client_auth(&record, b"other-test-key"));
        let first = message[39..71].to_vec();
        message[6] ^= 1;
        signer.finalize_client_hello(&mut message).unwrap();
        assert_eq!(first, message[39..71]);
        assert!(!wire::client_auth(
            &wire::frame(wire::HANDSHAKE, &message),
            b"tls-test-key"
        ));
    }
}

#[cfg(test)]
pub(crate) fn signed_hello_for_replay_test(key:&[u8])->Vec<u8>{
    let mut config=ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider())).with_protocol_versions(&[&rustls::version::TLS13]).unwrap().with_root_certificates(RootCertStore::empty()).with_no_client_auth();
    config.resumption=rustls::client::Resumption::disabled();
    config.client_hello_customizer=Some(Arc::new(Customize{signer:Arc::new(Signer{key:Arc::from(key),session:Mutex::new(None)})}));
    let mut session=ClientConnection::new(Arc::new(config),"shadowtls.example.invalid".try_into().unwrap()).unwrap();let mut bytes=Vec::new();while session.wants_write(){session.write_tls(&mut bytes).unwrap();}
    let length=u16::from_be_bytes([bytes[3],bytes[4]]) as usize;bytes.truncate(5+length);bytes
}
