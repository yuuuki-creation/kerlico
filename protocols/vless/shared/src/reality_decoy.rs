use boring2::{
    hash::MessageDigest,
    pkey::{Id, PKey, Public},
    rsa::Padding,
    sign::{RsaPssSaltlen, Verifier},
    x509::X509,
};
use rustls::{
    client::{danger::ServerCertVerifier, WebPkiServerVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    RootCertStore,
};
use std::{io, sync::Arc};

pub struct RealityDecoyVerifier(Option<Arc<WebPkiServerVerifier>>);
impl RealityDecoyVerifier {
    pub fn system_roots() -> io::Result<Self> {
        let mut roots = RootCertStore::empty();
        roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
        if roots.is_empty() {
            return Ok(Self(None));
        }
        Self::from_roots(roots)
    }
    pub fn from_pem_roots(pem: &str) -> io::Result<Self> {
        let mut roots = RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut io::Cursor::new(pem.as_bytes())) {
            roots.add(cert?).map_err(io::Error::other)?;
        }
        Self::from_roots(roots)
    }
    fn from_roots(roots: RootCertStore) -> io::Result<Self> {
        WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .map(|verifier| Self(Some(verifier)))
        .map_err(io::Error::other)
    }
    pub(super) fn verify(&self, certificate: &[u8], name: &str) -> io::Result<PKey<Public>> {
        let chain = certificate_chain(certificate)?;
        let name = ServerName::try_from(name.to_string()).map_err(io::Error::other)?;
        self.0
            .as_ref()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "REALITY decoy has no trusted roots",
                )
            })?
            .verify_server_cert(&chain[0], &chain[1..], &name, &[], UnixTime::now())
            .map_err(io::Error::other)?;
        X509::from_der(&chain[0])
            .and_then(|cert| cert.public_key())
            .map_err(io::Error::other)
    }
}

fn certificate_chain(body: &[u8]) -> io::Result<Vec<CertificateDer<'static>>> {
    let context = *body.first().ok_or_else(invalid)? as usize;
    let body = body.get(1 + context..).ok_or_else(invalid)?;
    let length = body.get(..3).ok_or_else(invalid)?;
    let length = (length[0] as usize) << 16 | (length[1] as usize) << 8 | length[2] as usize;
    if length != body.len() - 3 {
        return Err(invalid());
    }
    let mut body = &body[3..];
    let mut chain = Vec::new();
    while !body.is_empty() {
        if body.len() < 3 || chain.len() >= 16 {
            return Err(invalid());
        }
        let length = (body[0] as usize) << 16 | (body[1] as usize) << 8 | body[2] as usize;
        let certificate = body.get(3..3 + length).ok_or_else(invalid)?;
        if certificate.is_empty() {
            return Err(invalid());
        }
        chain.push(CertificateDer::from(certificate.to_vec()));
        body = &body[3 + length..];
        let length = body.get(..2).ok_or_else(invalid)?;
        let length = u16::from_be_bytes([length[0], length[1]]) as usize;
        body = body.get(2 + length..).ok_or_else(invalid)?;
    }
    if chain.is_empty() {
        return Err(invalid());
    }
    Ok(chain)
}

pub(super) fn verify_signature(
    key: &PKey<Public>,
    transcript: &[u8],
    body: &[u8],
    hello: &[u8],
) -> io::Result<()> {
    if body.len() < 4 || u16::from_be_bytes([body[2], body[3]]) as usize != body.len() - 4 {
        return Err(invalid());
    }
    let scheme = u16::from_be_bytes([body[0], body[1]]);
    let mut extensions = crate::reality::client_extensions(hello).ok_or_else(invalid)?;
    let mut offered = false;
    while !extensions.is_empty() {
        let header = extensions.get(..4).ok_or_else(invalid)?;
        let length = u16::from_be_bytes([header[2], header[3]]) as usize;
        let data = extensions.get(4..4 + length).ok_or_else(invalid)?;
        if header[..2] == [0, 13] {
            offered = data.get(2..).is_some_and(|values| {
                values
                    .chunks_exact(2)
                    .any(|value| value == scheme.to_be_bytes())
            });
        }
        extensions = &extensions[4 + length..];
    }
    if !offered {
        return Err(invalid());
    }
    let (digest, expected) = match scheme {
        0x0403 => (Some(MessageDigest::sha256()), Id::EC),
        0x0503 => (Some(MessageDigest::sha384()), Id::EC),
        0x0603 => (Some(MessageDigest::sha512()), Id::EC),
        0x0804 => (Some(MessageDigest::sha256()), Id::RSA),
        0x0805 => (Some(MessageDigest::sha384()), Id::RSA),
        0x0806 => (Some(MessageDigest::sha512()), Id::RSA),
        0x0807 => (None, Id::ED25519),
        _ => return Err(invalid()),
    };
    if key.id() != expected {
        return Err(invalid());
    }
    let mut verifier = match digest {
        Some(digest) => Verifier::new(digest, key),
        None => Verifier::new_without_digest(key),
    }
    .map_err(io::Error::other)?;
    if expected == Id::RSA {
        verifier
            .set_rsa_padding(Padding::PKCS1_PSS)
            .map_err(io::Error::other)?;
        verifier
            .set_rsa_pss_saltlen(RsaPssSaltlen::DIGEST_LENGTH)
            .map_err(io::Error::other)?;
        verifier
            .set_rsa_mgf1_md(digest.unwrap())
            .map_err(io::Error::other)?;
    }
    let message = super::certificate_verify_input(transcript);
    if !verifier
        .verify_oneshot(&body[4..], &message)
        .map_err(io::Error::other)?
    {
        return Err(invalid());
    }
    Ok(())
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid REALITY decoy certificate or signature",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    #[test]
    fn only_pki_authenticated_decoy_returns_a_usable_tls_stream() {
        let mut params = rcgen::CertificateParams::new(Vec::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let authority_key = rcgen::KeyPair::generate().unwrap();
        let authority = params.self_signed(&authority_key).unwrap();
        let params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &authority, &authority_key).unwrap();
        let config = crate::server_config(
            &(cert.pem() + &authority.pem()),
            &key.serialize_pem(),
            &["h2".into()],
        )
        .unwrap();
        let (private, public) = crate::reality_pair();
        let offer =
            crate::reality_offer_fingerprint(&public, &[0; 8], "localhost", &[], "chrome").unwrap();
        let mut server = rustls::ServerConnection::new(config).unwrap();
        server.read_tls(&mut offer.record.as_slice()).unwrap();
        server.process_new_packets().unwrap();
        let mut wire = Vec::new();
        while server.wants_write() {
            server.write_tls(&mut wire).unwrap();
        }
        let verifier = RealityDecoyVerifier::from_pem_roots(&authority.pem()).unwrap();
        assert!(crate::read_server_flight_or_decoy(&mut wire.as_slice(), &offer, &public, None, &RealityDecoyVerifier(None), "localhost").is_err());
        assert!(crate::read_server_flight_or_decoy(
            &mut wire.as_slice(),
            &offer,
            &public,
            None,
            &verifier,
            "wrong.test"
        )
        .is_err());
        let other = rcgen::generate_simple_self_signed(vec!["other.test".into()]).unwrap();
        let untrusted = RealityDecoyVerifier::from_pem_roots(&other.cert.pem()).unwrap();
        assert!(crate::read_server_flight_or_decoy(
            &mut wire.as_slice(),
            &offer,
            &public,
            None,
            &untrusted,
            "localhost"
        )
        .is_err());
        let result = crate::read_server_flight_or_decoy(
            &mut wire.as_slice(),
            &offer,
            &public,
            None,
            &verifier,
            "localhost",
        )
        .unwrap();
        let authentic = crate::server_flight_with_auth(
            &offer.record,
            &private,
            &crate::RealityPolicy {
                short_ids: vec![[0; 8]],
                ..Default::default()
            },
            &["h2"],
            None,
        )
        .unwrap();
        assert!(matches!(
            crate::read_server_flight_or_decoy(
                &mut authentic.flight.as_slice(),
                &offer,
                &public,
                None,
                &RealityDecoyVerifier(None),
                "localhost"
            )
            .unwrap(),
            crate::RealityClientResult::Verified(_)
        ));
        let crate::RealityClientResult::Decoy(flight) = result else {
            panic!("ordinary certificate was accepted as REALITY")
        };
        server.read_tls(&mut flight.finished.as_slice()).unwrap();
        server.process_new_packets().unwrap();
        assert!(!server.is_handshaking());
        let mut encrypted = Vec::new();
        crate::reality_writer(&mut encrypted, flight.write)
            .write_all(b"decoy GET")
            .unwrap();
        server.read_tls(&mut encrypted.as_slice()).unwrap();
        server.process_new_packets().unwrap();
        let mut plain = [0; 9];
        server.reader().read_exact(&mut plain).unwrap();
        assert_eq!(&plain, b"decoy GET");
    }
}
