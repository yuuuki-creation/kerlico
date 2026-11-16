use super::{AdvancedTlsOptions, TlsCertificate, TlsNetwork, TlsNetworkRequest};
use boring2::{hash::MessageDigest, sign::Verifier, ssl::SslContextBuilder, x509::X509};
use der::{
    asn1::{Null, ObjectIdentifier, OctetString},
    Decode, Encode,
};
use sha1::{Digest, Sha1};
use std::{
    io,
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use x509_cert::{
    ext::pkix::{name::GeneralName, AuthorityInfoAccessSyntax},
    spki::AlgorithmIdentifierOwned,
    Certificate,
};
use x509_ocsp::{
    BasicOcspResponse, CertId, CertStatus, OcspRequest, OcspResponse, OcspResponseStatus, Request,
    ResponderId, TbsRequest,
};

const SHA1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.26");
const OCSP_BASIC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.1");
const OCSP_SIGNING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.9");

pub(super) fn configure(
    context: &mut SslContextBuilder,
    options: &AdvancedTlsOptions,
    entry: &TlsCertificate,
    chain: &[X509],
) -> io::Result<()> {
    if entry.ocsp_stapling == 0 || entry.one_time_loading {
        return Ok(());
    }
    let network = options
        .network_provider
        .clone()
        .ok_or_else(|| invalid("ocspStapling requires a TLS network provider"))?;
    let certificates = chain
        .iter()
        .map(|cert| parse_certificate(&cert.to_der().map_err(io::Error::other)?))
        .collect::<io::Result<Vec<_>>>()?;
    let leaf = certificates[0].clone();
    let issuer = certificates
        .into_iter()
        .skip(1)
        .find(|cert| signed_by(&leaf, cert).unwrap_or(false));
    let staple = Stapler {
        leaf,
        network,
        interval: Duration::from_secs(entry.ocsp_stapling),
        state: Mutex::new(Cache {
            issuer,
            attempt: None,
            response: None,
        }),
    };
    context
        .set_status_callback(move |ssl| {
            if let Some(bytes) = staple.response() {
                ssl.set_ocsp_status(&bytes)?;
                Ok(true)
            } else {
                Ok(false)
            }
        })
        .map_err(io::Error::other)
}

struct Stapler {
    leaf: Certificate,
    network: Arc<dyn TlsNetwork>,
    interval: Duration,
    state: Mutex<Cache>,
}
struct Cache {
    issuer: Option<Certificate>,
    attempt: Option<Instant>,
    response: Option<(u64, Vec<u8>)>,
}
impl Stapler {
    fn response(&self) -> Option<Vec<u8>> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        let mut state = self.state.lock().ok()?;
        if state
            .attempt
            .is_none_or(|attempt| attempt.elapsed() >= self.interval)
        {
            state.attempt = Some(Instant::now());
            if let Ok((expires, bytes)) = self.fetch(&mut state, now) {
                state.response = Some((expires, bytes));
            }
        }
        state
            .response
            .as_ref()
            .filter(|(expires, _)| *expires > now)
            .map(|(_, bytes)| bytes.clone())
    }

    fn fetch(&self, state: &mut Cache, now: u64) -> io::Result<(u64, Vec<u8>)> {
        if state.issuer.is_none() {
            for url in aia_urls(&self.leaf, "1.3.6.1.5.5.7.48.2")? {
                if let Ok(bytes) = self.http(url, "GET", Vec::new()) {
                    if let Ok(issuer) = parse_certificate(&bytes) {
                        if signed_by(&self.leaf, &issuer)? {
                            state.issuer = Some(issuer);
                            break;
                        }
                    }
                }
            }
        }
        let issuer = state
            .issuer
            .as_ref()
            .ok_or_else(|| invalid("OCSP issuer unavailable"))?;
        let request = OcspRequest {
            tbs_request: TbsRequest {
                request_list: vec![Request {
                    req_cert: cert_id(&self.leaf, issuer, SHA1)?,
                    single_request_extensions: None,
                }],
                ..Default::default()
            },
            optional_signature: None,
        }
        .to_der()
        .map_err(io::Error::other)?;
        for url in aia_urls(&self.leaf, "1.3.6.1.5.5.7.48.1")? {
            if let Ok(bytes) = self.http(url, "POST", request.clone()) {
                if let Ok(expires) = verify_response(&bytes, &self.leaf, issuer, now) {
                    return Ok((expires, bytes));
                }
            }
        }
        Err(invalid("no valid OCSP response"))
    }

    fn http(&self, url: String, method: &str, body: Vec<u8>) -> io::Result<Vec<u8>> {
        let parsed = url::Url::parse(&url).map_err(io::Error::other)?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(invalid("OCSP URL scheme"));
        }
        let headers = if method == "POST" {
            vec![
                ("content-type".into(), "application/ocsp-request".into()),
                ("accept".into(), "application/ocsp-response".into()),
            ]
        } else {
            Vec::new()
        };
        let response = self.network.exchange(&TlsNetworkRequest::Http {
            url,
            method: method.into(),
            headers,
            body,
            http2: false,
            socket_settings: None,
        })?;
        if response.status != 200 || response.body.len() > 4 * 1024 * 1024 {
            return Err(invalid("OCSP HTTP response"));
        }
        Ok(response.body)
    }
}

fn parse_certificate(bytes: &[u8]) -> io::Result<Certificate> {
    let bytes = if bytes.starts_with(b"-----BEGIN") {
        X509::from_pem(bytes)
            .and_then(|cert| cert.to_der())
            .map_err(io::Error::other)?
    } else {
        bytes.to_vec()
    };
    Certificate::from_der(&bytes).map_err(io::Error::other)
}

fn aia_urls(cert: &Certificate, method: &str) -> io::Result<Vec<String>> {
    let Some(extension) = cert
        .tbs_certificate
        .extensions
        .as_ref()
        .and_then(|extensions| {
            extensions
                .iter()
                .find(|extension| extension.extn_id.to_string() == "1.3.6.1.5.5.7.1.1")
        })
    else {
        return Ok(Vec::new());
    };
    let access = AuthorityInfoAccessSyntax::from_der(extension.extn_value.as_bytes())
        .map_err(io::Error::other)?;
    Ok(access
        .0
        .into_iter()
        .filter(|entry| entry.access_method.to_string() == method)
        .filter_map(|entry| match entry.access_location {
            GeneralName::UniformResourceIdentifier(url) => Some(url.to_string()),
            _ => None,
        })
        .collect())
}

fn digest(algorithm: ObjectIdentifier, bytes: &[u8]) -> io::Result<Vec<u8>> {
    let md = digest_algorithm(algorithm)?;
    boring2::hash::hash(md, bytes)
        .map(|hash| hash.to_vec())
        .map_err(io::Error::other)
}
fn digest_algorithm(algorithm: ObjectIdentifier) -> io::Result<MessageDigest> {
    match algorithm.to_string().as_str() {
        "1.3.14.3.2.26" => Ok(MessageDigest::sha1()),
        "2.16.840.1.101.3.4.2.1" => Ok(MessageDigest::sha256()),
        "2.16.840.1.101.3.4.2.2" => Ok(MessageDigest::sha384()),
        "2.16.840.1.101.3.4.2.3" => Ok(MessageDigest::sha512()),
        "2.16.840.1.101.3.4.2.4" => Ok(MessageDigest::sha224()),
        _ => Err(invalid("unsupported OCSP hash")),
    }
}
fn cert_id(
    leaf: &Certificate,
    issuer: &Certificate,
    algorithm: ObjectIdentifier,
) -> io::Result<CertId> {
    Ok(CertId {
        hash_algorithm: AlgorithmIdentifierOwned {
            oid: algorithm,
            parameters: Some(Null.into()),
        },
        issuer_name_hash: OctetString::new(digest(
            algorithm,
            &issuer
                .tbs_certificate
                .subject
                .to_der()
                .map_err(io::Error::other)?,
        )?)
        .map_err(io::Error::other)?,
        issuer_key_hash: OctetString::new(digest(
            algorithm,
            issuer
                .tbs_certificate
                .subject_public_key_info
                .subject_public_key
                .raw_bytes(),
        )?)
        .map_err(io::Error::other)?,
        serial_number: leaf.tbs_certificate.serial_number.clone(),
    })
}

fn verify_response(
    bytes: &[u8],
    leaf: &Certificate,
    issuer: &Certificate,
    now: u64,
) -> io::Result<u64> {
    let response = OcspResponse::from_der(bytes).map_err(io::Error::other)?;
    if response.response_status != OcspResponseStatus::Successful {
        return Err(invalid("OCSP unsuccessful status"));
    }
    let response = response
        .response_bytes
        .filter(|bytes| bytes.response_type == OCSP_BASIC)
        .ok_or_else(|| invalid("OCSP basic response missing"))?;
    let basic =
        BasicOcspResponse::from_der(response.response.as_bytes()).map_err(io::Error::other)?;
    let data = &basic.tbs_response_data;
    if data.produced_at.0.to_unix_duration().as_secs() > now.saturating_add(300)
        || has_critical(&data.response_extensions)
    {
        return Err(invalid("OCSP producedAt or critical extension"));
    }
    let signer = std::iter::once(issuer)
        .chain(basic.certs.iter().flatten())
        .find(|cert| {
            let matches = match &data.responder_id {
                ResponderId::ByName(name) => &cert.tbs_certificate.subject == name,
                ResponderId::ByKey(hash) => {
                    Sha1::digest(
                        cert.tbs_certificate
                            .subject_public_key_info
                            .subject_public_key
                            .raw_bytes(),
                    )
                    .as_slice()
                        == hash.as_bytes()
                }
            };
            matches && authorized_signer(cert, issuer, now).unwrap_or(false)
        })
        .ok_or_else(|| invalid("OCSP signer is not authorized by issuer"))?;
    verify_signature(&basic, signer)?;
    let mut matching = data
        .responses
        .iter()
        .filter(|response| response.cert_id.serial_number == leaf.tbs_certificate.serial_number);
    let response = matching
        .next()
        .ok_or_else(|| invalid("OCSP certificate absent"))?;
    if matching.next().is_some() {
        return Err(invalid("duplicate OCSP certificate"));
    }
    let expected = cert_id(leaf, issuer, response.cert_id.hash_algorithm.oid)?;
    if response.cert_id.issuer_name_hash != expected.issuer_name_hash
        || response.cert_id.issuer_key_hash != expected.issuer_key_hash
        || !matches!(response.cert_status, CertStatus::Good(_))
        || has_critical(&response.single_extensions)
    {
        return Err(invalid("OCSP certificate status or issuer mismatch"));
    }
    let this = response.this_update.0.to_unix_duration().as_secs();
    let expires = response
        .next_update
        .map(|time| time.0.to_unix_duration().as_secs())
        .unwrap_or_else(|| this.saturating_add(86400));
    if this > now.saturating_add(300) || expires <= now || expires < this {
        return Err(invalid("OCSP response is stale or not yet valid"));
    }
    Ok(expires)
}

fn has_critical(extensions: &Option<x509_cert::ext::Extensions>) -> bool {
    extensions
        .iter()
        .flatten()
        .any(|extension| extension.critical)
}

fn signed_by(cert: &Certificate, issuer: &Certificate) -> io::Result<bool> {
    if cert.tbs_certificate.issuer != issuer.tbs_certificate.subject {
        return Ok(false);
    }
    let cert =
        X509::from_der(&cert.to_der().map_err(io::Error::other)?).map_err(io::Error::other)?;
    let issuer =
        X509::from_der(&issuer.to_der().map_err(io::Error::other)?).map_err(io::Error::other)?;
    let issuer_key = issuer.public_key().map_err(io::Error::other)?;
    cert.verify(&issuer_key).map_err(io::Error::other)
}

fn authorized_signer(cert: &Certificate, issuer: &Certificate, now: u64) -> io::Result<bool> {
    if cert
        .tbs_certificate
        .validity
        .not_before
        .to_unix_duration()
        .as_secs()
        > now
        || cert
            .tbs_certificate
            .validity
            .not_after
            .to_unix_duration()
            .as_secs()
            < now
    {
        return Ok(false);
    }
    if cert == issuer {
        return Ok(true);
    }
    if !signed_by(cert, issuer)? {
        return Ok(false);
    }
    let Some(eku) = cert
        .tbs_certificate
        .extensions
        .as_ref()
        .and_then(|extensions| {
            extensions
                .iter()
                .find(|extension| extension.extn_id.to_string() == "2.5.29.37")
        })
    else {
        return Ok(false);
    };
    Ok(Vec::<ObjectIdentifier>::from_der(eku.extn_value.as_bytes())
        .map_err(io::Error::other)?
        .contains(&OCSP_SIGNING))
}

#[derive(der::Sequence)]
struct PssParameters {
    #[asn1(context_specific = "0", tag_mode = "EXPLICIT", optional = "true")]
    hash: Option<AlgorithmIdentifierOwned>,
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT", optional = "true")]
    mask: Option<AlgorithmIdentifierOwned>,
    #[asn1(context_specific = "2", tag_mode = "EXPLICIT", optional = "true")]
    salt: Option<u32>,
    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    trailer: Option<u32>,
}

fn verify_signature(response: &BasicOcspResponse, signer: &Certificate) -> io::Result<()> {
    use boring2::{rsa::Padding, sign::RsaPssSaltlen};
    let signer =
        X509::from_der(&signer.to_der().map_err(io::Error::other)?).map_err(io::Error::other)?;
    let key = signer.public_key().map_err(io::Error::other)?;
    let pss = if response.signature_algorithm.oid.to_string() == "1.2.840.113549.1.1.10" {
        Some(
            PssParameters::from_der(
                &response
                    .signature_algorithm
                    .parameters
                    .as_ref()
                    .ok_or_else(|| invalid("OCSP RSA-PSS parameters"))?
                    .to_der()
                    .map_err(io::Error::other)?,
            )
            .map_err(io::Error::other)?,
        )
    } else {
        None
    };
    let md = match response.signature_algorithm.oid.to_string().as_str() {
        "1.2.840.113549.1.1.5" | "1.2.840.10045.4.1" => Some(MessageDigest::sha1()),
        "1.2.840.113549.1.1.14" | "1.2.840.10045.4.3.1" => Some(MessageDigest::sha224()),
        "1.2.840.113549.1.1.11" | "1.2.840.10045.4.3.2" => Some(MessageDigest::sha256()),
        "1.2.840.113549.1.1.12" | "1.2.840.10045.4.3.3" => Some(MessageDigest::sha384()),
        "1.2.840.113549.1.1.13" | "1.2.840.10045.4.3.4" => Some(MessageDigest::sha512()),
        "1.2.840.113549.1.1.10" => Some(digest_algorithm(
            pss.as_ref()
                .unwrap()
                .hash
                .as_ref()
                .map(|hash| hash.oid)
                .unwrap_or(SHA1),
        )?),
        "1.3.101.112" => None,
        _ => return Err(invalid("unsupported OCSP signature algorithm")),
    };
    let mut verifier = match md {
        Some(md) => Verifier::new(md, &key),
        None => Verifier::new_without_digest(&key),
    }
    .map_err(io::Error::other)?;
    if let Some(parameters) = pss {
        if parameters.trailer.unwrap_or(1) != 1 {
            return Err(invalid("OCSP RSA-PSS trailer"));
        }
        let mask_hash = if let Some(mask) = parameters.mask {
            if mask.oid.to_string() != "1.2.840.113549.1.1.8" {
                return Err(invalid("OCSP RSA-PSS mask"));
            }
            AlgorithmIdentifierOwned::from_der(
                &mask
                    .parameters
                    .ok_or_else(|| invalid("OCSP RSA-PSS MGF hash"))?
                    .to_der()
                    .map_err(io::Error::other)?,
            )
            .map_err(io::Error::other)?
            .oid
        } else {
            SHA1
        };
        verifier
            .set_rsa_padding(Padding::PKCS1_PSS)
            .map_err(io::Error::other)?;
        verifier
            .set_rsa_mgf1_md(digest_algorithm(mask_hash)?)
            .map_err(io::Error::other)?;
        verifier
            .set_rsa_pss_saltlen(RsaPssSaltlen::custom(
                i32::try_from(parameters.salt.unwrap_or(20)).map_err(io::Error::other)?,
            ))
            .map_err(io::Error::other)?;
    }
    let signature = response
        .signature
        .as_bytes()
        .ok_or_else(|| invalid("OCSP signature bits"))?;
    let data = response
        .tbs_response_data
        .to_der()
        .map_err(io::Error::other)?;
    if !verifier
        .verify_oneshot(signature, &data)
        .map_err(io::Error::other)?
    {
        return Err(invalid("OCSP signature verification failed"));
    }
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use boring2::{pkey::PKey, sign::Signer};
    use der::asn1::{BitString, Ia5String};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use x509_cert::ext::pkix::AccessDescription;
    use x509_ocsp::{OcspGeneralizedTime, ResponseData, SingleResponse};

    struct Fixture {
        options: AdvancedTlsOptions,
        leaf: Certificate,
        issuer: Certificate,
        issuer_key: String,
        now: u64,
    }
    impl Fixture {
        fn new() -> Self {
            let mut ca = rcgen::CertificateParams::new(vec!["OCSP test CA".into()]).unwrap();
            ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let ca_key = rcgen::KeyPair::generate().unwrap();
            let ca = ca.self_signed(&ca_key).unwrap();
            let access = AuthorityInfoAccessSyntax(vec![
                AccessDescription {
                    access_method: "1.3.6.1.5.5.7.48.1".parse().unwrap(),
                    access_location: GeneralName::UniformResourceIdentifier(
                        Ia5String::new("http://ocsp.test/status").unwrap(),
                    ),
                },
                AccessDescription {
                    access_method: "1.3.6.1.5.5.7.48.2".parse().unwrap(),
                    access_location: GeneralName::UniformResourceIdentifier(
                        Ia5String::new("http://ocsp.test/issuer").unwrap(),
                    ),
                },
            ]);
            let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
            params
                .custom_extensions
                .push(rcgen::CustomExtension::from_oid_content(
                    &[1, 3, 6, 1, 5, 5, 7, 1, 1],
                    access.to_der().unwrap(),
                ));
            let key = rcgen::KeyPair::generate().unwrap();
            let leaf = params.signed_by(&key, &ca, &ca_key).unwrap();
            let mut options = super::super::tests::options();
            options.certificates = vec![TlsCertificate {
                certificate: leaf.pem() + &ca.pem(),
                key: key.serialize_pem(),
                ocsp_stapling: 3600,
                ..Default::default()
            }];
            Self {
                options,
                leaf: parse_certificate(leaf.der()).unwrap(),
                issuer: parse_certificate(ca.der()).unwrap(),
                issuer_key: ca_key.serialize_pem(),
                now: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            }
        }
        fn response(&self, status: CertStatus, expires: u64) -> Vec<u8> {
            let time = |seconds| {
                OcspGeneralizedTime::try_from(UNIX_EPOCH + Duration::from_secs(seconds)).unwrap()
            };
            let mut response = BasicOcspResponse {
                tbs_response_data: ResponseData {
                    version: Default::default(),
                    responder_id: ResponderId::ByName(self.issuer.tbs_certificate.subject.clone()),
                    produced_at: time(self.now),
                    responses: vec![SingleResponse {
                        cert_id: cert_id(&self.leaf, &self.issuer, SHA1).unwrap(),
                        cert_status: status,
                        this_update: time(self.now - 60),
                        next_update: Some(time(expires)),
                        single_extensions: None,
                    }],
                    response_extensions: None,
                },
                signature_algorithm: AlgorithmIdentifierOwned {
                    oid: "1.2.840.10045.4.3.2".parse().unwrap(),
                    parameters: None,
                },
                signature: BitString::from_bytes(&[]).unwrap(),
                certs: None,
            };
            let key = PKey::private_key_from_pem(self.issuer_key.as_bytes()).unwrap();
            let signature = Signer::new(MessageDigest::sha256(), &key)
                .unwrap()
                .sign_oneshot_to_vec(&response.tbs_response_data.to_der().unwrap())
                .unwrap();
            response.signature = BitString::from_bytes(&signature).unwrap();
            OcspResponse::successful(response)
                .unwrap()
                .to_der()
                .unwrap()
        }
    }

    #[derive(Debug)]
    struct Network {
        response: Vec<u8>,
        issuer: Vec<u8>,
        requests: AtomicUsize,
        issuer_requests: AtomicUsize,
    }
    impl TlsNetwork for Network {
        fn exchange(
            &self,
            request: &TlsNetworkRequest,
        ) -> io::Result<super::super::TlsNetworkResponse> {
            let TlsNetworkRequest::Http {
                method,
                url,
                body,
                headers,
                ..
            } = request
            else {
                panic!("OCSP used DNS callback")
            };
            let body = if method == "GET" {
                assert!(url.ends_with("/issuer"));
                self.issuer_requests.fetch_add(1, Ordering::Relaxed);
                self.issuer.clone()
            } else {
                assert_eq!(method, "POST");
                assert!(
                    headers.contains(&("content-type".into(), "application/ocsp-request".into()))
                );
                let request = OcspRequest::from_der(body).unwrap();
                assert_eq!(request.tbs_request.request_list.len(), 1);
                self.requests.fetch_add(1, Ordering::Relaxed);
                self.response.clone()
            };
            Ok(super::super::TlsNetworkResponse { status: 200, body })
        }
    }

    #[test]
    fn ocsp_signatures_status_expiry_and_issuer_are_verified() {
        let fixture = Fixture::new();
        let valid = fixture.response(CertStatus::Good(Null), fixture.now + 3600);
        assert_eq!(
            verify_response(&valid, &fixture.leaf, &fixture.issuer, fixture.now).unwrap(),
            fixture.now + 3600
        );
        assert!(verify_response(
            &fixture.response(CertStatus::Good(Null), fixture.now - 1),
            &fixture.leaf,
            &fixture.issuer,
            fixture.now
        )
        .is_err());
        assert!(verify_response(
            &fixture.response(CertStatus::Unknown(Null), fixture.now + 3600),
            &fixture.leaf,
            &fixture.issuer,
            fixture.now
        )
        .is_err());
        let unrelated = Fixture::new();
        assert!(verify_response(&valid, &fixture.leaf, &unrelated.issuer, fixture.now).is_err());
        let mut tampered = valid;
        let end = tampered.len() - 1;
        tampered[end] ^= 1;
        assert!(verify_response(&tampered, &fixture.leaf, &fixture.issuer, fixture.now).is_err());
    }

    #[test]
    fn verified_ocsp_is_stapled_over_tls_and_cached_with_issuer_fetch() {
        for fetch_issuer in [false, true] {
            let mut fixture = Fixture::new();
            if fetch_issuer {
                fixture.options.certificates[0].certificate = String::from_utf8(
                    X509::from_der(&fixture.leaf.to_der().unwrap())
                        .unwrap()
                        .to_pem()
                        .unwrap(),
                )
                .unwrap();
            }
            let response = fixture.response(CertStatus::Good(Null), fixture.now + 3600);
            let network = Arc::new(Network {
                response: response.clone(),
                issuer: fixture.issuer.to_der().unwrap(),
                requests: AtomicUsize::new(0),
                issuer_requests: AtomicUsize::new(0),
            });
            fixture.options.network_provider = Some(network.clone());
            let config = super::super::advanced_server_config(&fixture.options).unwrap();
            for _ in 0..2 {
                let (_, staple) = super::super::tests::peer_identity(config.clone());
                assert_eq!(staple.as_deref(), Some(response.as_slice()));
            }
            assert_eq!(network.requests.load(Ordering::Relaxed), 1);
            assert_eq!(
                network.issuer_requests.load(Ordering::Relaxed),
                usize::from(fetch_issuer)
            );
        }
    }
}
