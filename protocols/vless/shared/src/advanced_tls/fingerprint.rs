use super::AdvancedTlsOptions;
use boring2::ssl::{
    CertificateCompressionAlgorithm as Compression, CertificateCompressor, ClientHelloShape,
    EchGreaseShape, ExtensionType, GreaseLists, Padding, SslConnectorBuilder, SslOptions, SslRef,
    SslSession, SslSignatureAlgorithm, SslVersion, UnknownValues,
};
use std::collections::HashMap;
use std::io::{self, Write};
use std::sync::{LazyLock, OnceLock};

// Wire fields captured from the pinned Xray 26.10.31 binary (uTLS aa6edf4b11af).
// Randoms, session IDs, keys and ECH ciphertext are intentionally absent.
static PROFILES: LazyLock<HashMap<String, Profile>> = LazyLock::new(|| {
    serde_json::from_str(include_str!("fingerprints.json")).expect("pinned ClientHello profiles")
});

#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub(crate) struct Profile {
    pub session_id_length: usize,
    pub ciphers: Vec<u16>,
    pub extensions: Vec<Extension>,
    #[serde(default)]
    pub(super) shuffle: bool,
}

#[derive(Clone, Default, serde::Deserialize, serde::Serialize)]
pub(crate) struct Extension {
    pub id: u16,
    #[serde(default)]
    data: String,
    #[serde(default)]
    pub values: Vec<u16>,
    #[serde(default)]
    pub shares: Vec<(u16, usize)>,
    #[serde(default)]
    kdf: u16,
    #[serde(default)]
    aead: u16,
    #[serde(default)]
    enc_length: usize,
    #[serde(default)]
    payload_length: usize,
}

pub(super) fn chrome_quic(alpn: &[String]) -> Profile {
    // apernet/quic-go 184d081eef3e chromeQUICClientHelloSpec, not a TCP preset.
    let mut protocols = vec![0, 0];
    for protocol in alpn {
        protocols.push(protocol.len() as u8);
        protocols.extend_from_slice(protocol.as_bytes());
    }
    let length = (protocols.len() - 2) as u16;
    protocols[..2].copy_from_slice(&length.to_be_bytes());
    let alps = protocols.iter().map(|byte| format!("{byte:02x}")).collect();
    Profile {
        session_id_length: 0,
        ciphers: vec![0x1301, 0x1302, 0x1303],
        extensions: vec![
            Extension {
                id: 0,
                ..Default::default()
            },
            Extension {
                id: 10,
                values: vec![0x11ec, 29, 23, 24],
                ..Default::default()
            },
            Extension {
                id: 13,
                values: vec![
                    0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
                ],
                ..Default::default()
            },
            Extension {
                id: 16,
                ..Default::default()
            },
            Extension {
                id: 27,
                data: "020002".into(),
                ..Default::default()
            },
            Extension {
                id: 43,
                values: vec![0x0304],
                ..Default::default()
            },
            Extension {
                id: 45,
                data: "0101".into(),
                ..Default::default()
            },
            Extension {
                id: 51,
                shares: vec![(0x11ec, 1216), (29, 32)],
                ..Default::default()
            },
            Extension {
                id: 57,
                ..Default::default()
            },
            Extension {
                id: 17613,
                data: alps,
                ..Default::default()
            },
            Extension {
                id: 65037,
                kdf: 1,
                aead: 1,
                enc_length: 32,
                payload_length: 144,
                ..Default::default()
            },
        ],
        shuffle: true,
    }
}

pub(crate) fn resolve(name: &str) -> io::Result<Option<Profile>> {
    let name = if name.is_empty() { "chrome" } else { name };
    if name == "unsafe" {
        return Ok(None);
    }
    static RANDOM: OnceLock<String> = OnceLock::new();
    static RANDOMIZED: OnceLock<Profile> = OnceLock::new();
    static RANDOMIZED_NO_ALPN: OnceLock<Profile> = OnceLock::new();
    let mut profile = if name == "random" {
        let choices = [
            "hellofirefox_120",
            "hellofirefox_148",
            "hellochrome_120",
            "hellochrome_131",
            "hellochrome_133",
            "helloios_13",
            "helloios_14",
            "helloedge_106",
            "hellosafari_26_3",
            "hello360_11_0",
            "helloqq_11_1",
        ];
        let selected = match RANDOM.get() {
            Some(selected) => selected,
            None => {
                let _ = RANDOM.set(choices[random(choices.len())?].to_string());
                RANDOM.get().expect("random fingerprint initialized")
            }
        };
        resolve(selected)?.expect("fixed random profile")
    } else if matches!(name, "randomized" | "randomizednoalpn") {
        let cache = if name == "randomized" {
            &RANDOMIZED
        } else {
            &RANDOMIZED_NO_ALPN
        };
        if cache.get().is_none() {
            let _ = cache.set(randomized(name)?);
        }
        cache
            .get()
            .expect("randomized fingerprint initialized")
            .clone()
    } else if matches!(
        name,
        "randomized"
            | "randomizednoalpn"
            | "hellorandomized"
            | "hellorandomizedalpn"
            | "hellorandomizednoalpn"
    ) {
        randomized(name)?
    } else {
        PROFILES.get(name).cloned().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "unknown or session-only TLS fingerprint",
            )
        })?
    };
    profile.shuffle = matches!(
        name,
        "chrome"
            | "hellochrome_auto"
            | "hellochrome_106_shuffle"
            | "hellochrome_115_pq"
            | "hellochrome_120"
            | "hellochrome_131"
            | "hellochrome_133"
            | "hellochrome_120_pq"
    ) || profile.shuffle;
    Ok(Some(profile))
}

pub(super) fn configure_profile(
    builder: &mut SslConnectorBuilder,
    options: &AdvancedTlsOptions,
    profile: &Profile,
) -> io::Result<()> {
    builder
        .set_raw_cipher_list(&profile.ciphers)
        .map_err(io::Error::other)?;
    if profile.extensions.iter().any(|e| e.id == 35) {
        builder.clear_options(SslOptions::NO_TICKET);
    }
    if profile.extensions.iter().any(|e| e.id == 13172) {
        unsafe {
            boring_sys::SSL_CTX_set_next_proto_select_cb(
                builder.as_ptr(),
                Some(select_npn),
                std::ptr::null_mut(),
            );
        }
    }
    if options.max_version.is_empty() && !profile.extensions.iter().any(|e| e.id == 43) {
        builder
            .set_max_proto_version(Some(SslVersion::TLS1_2))
            .map_err(io::Error::other)?;
    }
    if options.min_version.is_empty() {
        let min = profile
            .extensions
            .iter()
            .find(|e| e.id == 43)
            .and_then(|e| {
                e.values
                    .iter()
                    .copied()
                    .filter(|v| (0x301..=0x304).contains(v))
                    .min()
            })
            .unwrap_or(0x301);
        builder
            .set_min_proto_version(Some(match min {
                0x301 => SslVersion::TLS1,
                0x302 => SslVersion::TLS1_1,
                0x303 => SslVersion::TLS1_2,
                _ => SslVersion::TLS1_3,
            }))
            .map_err(io::Error::other)?;
    }
    builder
        .add_certificate_compression_algorithm(Zlib)
        .map_err(io::Error::other)?;
    builder
        .add_certificate_compression_algorithm(Brotli)
        .map_err(io::Error::other)?;
    builder
        .add_certificate_compression_algorithm(Zstd)
        .map_err(io::Error::other)?;
    Ok(())
}

pub(crate) fn reality_hello(
    profile: &Profile,
    random_bytes: &[u8; 32],
    name: &str,
    protocols: &[String],
    mut key: impl FnMut(u16) -> io::Result<Vec<u8>>,
) -> io::Result<Vec<u8>> {
    if !profile
        .extensions
        .iter()
        .any(|extension| extension.id == 43 && extension.values.contains(&0x304))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "REALITY fingerprint must support TLS 1.3",
        ));
    }
    let grease_cipher = (random(16)? as u16) * 0x1010 + 0x0a0a;
    let grease_group = (random(16)? as u16) * 0x1010 + 0x0a0a;
    let grease_version = (random(16)? as u16) * 0x1010 + 0x0a0a;
    let grease_first = (random(16)? as u16) * 0x1010 + 0x0a0a;
    let grease_second = if grease_first == 0xfafa {
        0x0a0a
    } else {
        grease_first + 0x1010
    };
    let mut hello = vec![1, 0, 0, 0, 3, 3];
    hello.extend_from_slice(random_bytes);
    hello.push(32);
    hello.extend_from_slice(&[0; 32]);
    hello.extend_from_slice(&((profile.ciphers.len() * 2) as u16).to_be_bytes());
    for &cipher in &profile.ciphers {
        hello.extend_from_slice(
            &(if cipher == 0x0a0a {
                grease_cipher
            } else {
                cipher
            })
            .to_be_bytes(),
        );
    }
    hello.extend_from_slice(&[1, 0]);
    let length_at = hello.len();
    hello.extend_from_slice(&[0, 0]);
    let start = hello.len();
    let mut extensions = profile.extensions.clone();
    if profile.shuffle {
        shuffle_extensions(&mut extensions, |extension| extension.id)?;
    }
    let mut padding_at = None;
    let mut grease_count = 0;
    for extension in &extensions {
        let mut id = extension.id;
        let mut body = hex(&extension.data)?;
        match id {
            0 => {
                let bytes = name.as_bytes();
                body = ((bytes.len() + 3) as u16).to_be_bytes().to_vec();
                body.push(0);
                body.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
                body.extend_from_slice(bytes);
            }
            10 | 13 | 43 => {
                body.clear();
                let values: Vec<_> = extension
                    .values
                    .iter()
                    .map(|&value| {
                        if value == 0x0a0a {
                            if id == 10 {
                                grease_group
                            } else {
                                grease_version
                            }
                        } else {
                            value
                        }
                    })
                    .collect();
                if id == 43 {
                    body.push((values.len() * 2) as u8);
                } else {
                    body.extend_from_slice(&((values.len() * 2) as u16).to_be_bytes());
                }
                for value in values {
                    body.extend_from_slice(&value.to_be_bytes());
                }
            }
            16 if !protocols.is_empty() => {
                body = vec![0, 0];
                for protocol in protocols {
                    if protocol.is_empty() || protocol.len() > 255 {
                        return Err(io::Error::other("REALITY ALPN"));
                    }
                    body.push(protocol.len() as u8);
                    body.extend_from_slice(protocol.as_bytes());
                }
                let n = (body.len() - 2) as u16;
                body[..2].copy_from_slice(&n.to_be_bytes());
            }
            21 => {
                padding_at = Some(hello.len());
                continue;
            }
            51 => {
                body = vec![0, 0];
                for &(group, _) in &extension.shares {
                    let bytes = if group == 0x0a0a {
                        vec![0]
                    } else {
                        key(group)?
                    };
                    let group = if group == 0x0a0a { grease_group } else { group };
                    body.extend_from_slice(&group.to_be_bytes());
                    body.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
                    body.extend(bytes);
                }
                let n = (body.len() - 2) as u16;
                body[..2].copy_from_slice(&n.to_be_bytes());
            }
            65037 => {
                let payload = if profile.shuffle {
                    [144, 176, 208, 240][random(4)?]
                } else {
                    extension.payload_length
                };
                let aead = if payload == 239 {
                    [1u16, 3][random(2)?]
                } else {
                    extension.aead
                };
                body = vec![0];
                body.extend_from_slice(&extension.kdf.to_be_bytes());
                body.extend_from_slice(&aead.to_be_bytes());
                body.push(random(256)? as u8);
                body.extend_from_slice(&32u16.to_be_bytes());
                let mut encapsulated = vec![0; 32];
                getrandom::getrandom(&mut encapsulated)
                    .map_err(|e| io::Error::other(e.to_string()))?;
                body.extend(encapsulated);
                body.extend_from_slice(&(payload as u16).to_be_bytes());
                let mut cipher = vec![0; payload];
                getrandom::getrandom(&mut cipher).map_err(|e| io::Error::other(e.to_string()))?;
                body.extend(cipher);
            }
            0x0a0a => {
                id = if grease_count == 0 {
                    grease_first
                } else {
                    grease_second
                };
                grease_count += 1;
            }
            _ => {}
        }
        hello.extend_from_slice(&id.to_be_bytes());
        hello.extend_from_slice(&(body.len() as u16).to_be_bytes());
        hello.extend(body);
    }
    if let Some(position) = padding_at {
        if (256..512).contains(&hello.len()) {
            let size = (512 - hello.len()).max(4);
            let mut padding = vec![0; size];
            padding[..2].copy_from_slice(&21u16.to_be_bytes());
            padding[2..4].copy_from_slice(&((size - 4) as u16).to_be_bytes());
            hello.splice(position..position, padding);
        }
    }
    let length = (hello.len() - start) as u16;
    hello[length_at..length_at + 2].copy_from_slice(&length.to_be_bytes());
    let length = (hello.len() - 4) as u32;
    hello[1..4].copy_from_slice(&length.to_be_bytes()[1..]);
    Ok(hello)
}

pub(super) fn configure_connection(
    ssl: &mut SslRef,
    profile: Option<&Profile>,
    options: &AdvancedTlsOptions,
) -> io::Result<()> {
    let Some(profile) = profile else {
        return Ok(());
    };
    if !profile.extensions.iter().any(|e| e.id == 16) {
        ssl.set_alpn_protos(&[]).map_err(io::Error::other)?;
    }
    let mut shape = ClientHelloShape::new()
        .with_unknown_values(UnknownValues::Preserve)
        .with_grease_lists(GreaseLists::empty())
        .with_padding(if profile.extensions.iter().any(|e| e.id == 21) {
            Padding::Native
        } else {
            Padding::Off
        })
        .with_legacy_extensions(true)
        .with_ec_point_formats(profile.extensions.iter().any(|e| e.id == 11))
        .with_omit_psk_key_exchange_modes(!profile.extensions.iter().any(|e| e.id == 45));
    shape.set_omit_extended_master_secret(!profile.extensions.iter().any(|e| e.id == 23));
    shape.set_omit_renegotiation_info(!profile.extensions.iter().any(|e| e.id == 65281));
    let mut compression = Vec::new();
    let mut order = Vec::new();
    let mut grease = 0;
    for extension in &profile.extensions {
        let mut id = extension.id;
        if id == 0x0a0a {
            id += grease * 0x1010;
            grease += 1;
        }
        order.push(id);
        let data = hex(&extension.data)?;
        match id {
            0 => {}
            5 => ssl.enable_ocsp_stapling(),
            10 => {
                if options.curve_preferences.is_empty() {
                    ssl.set_raw_supported_groups(&extension.values)
                        .map_err(io::Error::other)?;
                }
            }
            13 => ssl
                .set_raw_signature_algorithms(&extension.values)
                .map_err(io::Error::other)?,
            16 if options.alpn.is_empty() => {
                ssl.set_alpn_protos(
                    data.get(2..)
                        .ok_or_else(|| io::Error::other("profile ALPN"))?,
                )
                .map_err(io::Error::other)?;
            }
            18 => ssl.enable_signed_cert_timestamps(),
            27 => {
                for algorithm in data.get(1..).unwrap_or_default().as_chunks::<2>().0 {
                    compression.push(match u16::from_be_bytes([algorithm[0], algorithm[1]]) {
                        1 => Compression::ZLIB,
                        2 => Compression::BROTLI,
                        3 => Compression::ZSTD,
                        _ => return Err(io::Error::other("profile certificate compression")),
                    });
                }
            }
            28 => ssl
                .set_record_size_limit(u16::from_be_bytes(
                    data.try_into()
                        .map_err(|_| io::Error::other("profile record limit"))?,
                ))
                .map_err(io::Error::other)?,
            34 => {
                let schemes: Vec<_> = data
                    .get(2..)
                    .unwrap_or_default()
                    .as_chunks::<2>().0.iter()
                    .map(|v| SslSignatureAlgorithm::from(u16::from_be_bytes([v[0], v[1]])))
                    .collect();
                ssl.set_delegated_credential_schemes(&schemes)
                    .map_err(io::Error::other)?;
            }
            43 => {
                let versions: Vec<_> = extension
                    .values
                    .iter()
                    .copied()
                    .filter(|&version| options.ech_config_list.is_empty() || version >= 0x0304)
                    .collect();
                ssl.set_raw_supported_versions(&versions)
                    .map_err(io::Error::other)?;
            }
            51 => {
                if options.curve_preferences.is_empty() {
                    ssl.set_raw_key_shares(
                        &extension
                            .shares
                            .iter()
                            .map(|&(id, _)| id)
                            .collect::<Vec<_>>(),
                    )
                    .map_err(io::Error::other)?;
                }
            }
            17513 | 17613 => {
                ssl.set_alps_use_new_codepoint(id == 17613);
                let mut protocols = data
                    .get(2..)
                    .ok_or_else(|| io::Error::other("profile ALPS"))?;
                while let Some((&length, rest)) = protocols.split_first() {
                    let protocol = rest
                        .get(..length as usize)
                        .ok_or_else(|| io::Error::other("profile ALPS protocol"))?;
                    ssl.add_application_settings(protocol)
                        .map_err(io::Error::other)?;
                    protocols = &rest[length as usize..];
                }
            }
            30032 => {
                let group =
                    boring2::ec::EcGroup::from_curve_name(boring2::nid::Nid::X9_62_PRIME256V1)
                        .map_err(io::Error::other)?;
                let key = boring2::pkey::PKey::from_ec_key(
                    boring2::ec::EcKey::generate(&group).map_err(io::Error::other)?,
                )
                .map_err(io::Error::other)?;
                ssl.set_tls_channel_id(&key).map_err(io::Error::other)?;
            }
            65037 => {
                ssl.set_enable_ech_grease(true);
                let payload = if profile.shuffle {
                    [144, 176, 208, 240][random(4)?]
                } else {
                    extension.payload_length
                };
                let aead = if extension.payload_length == 239 {
                    [1, 3][random(2)?]
                } else {
                    extension.aead
                };
                shape.set_ech_grease(Some(
                    EchGreaseShape::from_wire(extension.kdf, aead, extension.enc_length, payload)
                        .map_err(io::Error::other)?,
                ));
            }
            11 | 16 | 21 | 23 | 35 | 45 | 57 | 13172 | 65281 => {}
            _ => {
                shape.set_extension_body(ExtensionType::from(id), data);
            }
        }
    }
    if profile.shuffle {
        shuffle_extensions(&mut order, |&id| id)?;
    }
    ssl.set_certificate_compression_algorithms(&compression)
        .map_err(io::Error::other)?;
    ssl.set_client_hello_shape(&shape)
        .map_err(io::Error::other)?;
    ssl.set_extension_order(&order).map_err(io::Error::other)?;
    if profile.session_id_length == 32 && !profile.extensions.iter().any(|e| e.id == 43) {
        legacy_compatibility_id(ssl)?;
    }
    Ok(())
}

unsafe extern "C" fn select_npn(
    _ssl: *mut boring_sys::SSL,
    out: *mut *mut u8,
    out_len: *mut u8,
    input: *const u8,
    input_len: u32,
    _arg: *mut std::ffi::c_void,
) -> std::ffi::c_int {
    const PROTOCOLS: &[u8] = b"\x02h2\x08http/1.1";
    unsafe {
        boring_sys::SSL_select_next_proto(
            out,
            out_len,
            input,
            input_len,
            PROTOCOLS.as_ptr(),
            PROTOCOLS.len() as u32,
        );
    }
    0
}

fn legacy_compatibility_id(ssl: &mut SslRef) -> io::Result<()> {
    // uTLS sends a random compatibility ID even in TLS 1.2-only profiles.
    // An unshared random secret ensures this ID can never authenticate a resumed
    // session; a server must perform the normal certificate-authenticated handshake.
    fn der(tag: u8, bytes: &[u8]) -> Vec<u8> {
        let mut value = vec![tag, bytes.len() as u8];
        value.extend_from_slice(bytes);
        value
    }
    let mut random = [0; 80];
    getrandom::getrandom(&mut random).map_err(|error| io::Error::other(error.to_string()))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_secs();
    let bytes = now.to_be_bytes();
    let start = bytes.iter().position(|&byte| byte != 0).unwrap_or(7);
    let mut body = vec![2, 1, 1, 2, 2, 3, 3, 4, 2, 0xc0, 0x2f];
    body.extend(der(4, &random[..32]));
    body.extend(der(4, &random[32..]));
    body.extend(der(0xa1, &der(2, &bytes[start..])));
    body.extend_from_slice(&[0xa2, 4, 2, 2, 0x1c, 0x20, 0xb6, 3, 1, 1, 0]);
    let session = SslSession::from_der(&der(0x30, &body)).map_err(io::Error::other)?;
    unsafe { ssl.set_session(&session).map_err(io::Error::other) }
}

fn randomized(name: &str) -> io::Result<Profile> {
    let mut seed = [0; 32];
    getrandom::getrandom(&mut seed).map_err(|error| io::Error::other(error.to_string()))?;
    Ok(randomized_seeded(name, &seed))
}

fn randomized_seeded(name: &str, seed: &[u8; 32]) -> Profile {
    // uTLS aa6edf4b11af generateRandomizedSpec and Go math/rand compatibility.
    let mut random = ProfileRandom::new(seed);
    let alpn = if name.ends_with("noalpn") {
        false
    } else if name == "hellorandomized" {
        random.coin(0.7)
    } else {
        true
    };
    let cipher_ids = [
        0xcca8, 0xcca9, 0xc02f, 0xc02b, 0xc030, 0xc02c, 0xc027, 0xc013, 0xc023, 0xc009, 0xc014,
        0xc00a, 0x9c, 0x9d, 0x3c, 0x2f, 0x35, 0xc012, 0xa, 0x5, 0xc011, 0xc007,
    ];
    let permutation = random.permutation(cipher_ids.len());
    let mut ciphers: Vec<_> = cipher_ids.into_iter().enumerate().collect();
    ciphers.sort_by_key(|&(i, _)| (matches!(i, 7 | 9 | 10 | 11 | 15..=21), permutation[i]));
    let mut ciphers: Vec<_> = ciphers.into_iter().map(|(_, id)| id).collect();
    let tls13 = random.coin(if name.starts_with("hello") { 0.4 } else { 1.0 });
    let minimum = if tls13 {
        [0x301, 0x303][random.intn(2)]
    } else {
        0x301
    };
    if tls13 {
        let mut modern = vec![0x1301, 0x1302, 0x1303];
        random.shuffle(&mut modern);
        modern.extend(ciphers);
        ciphers = modern;
        ciphers.retain(|id| ![0x5, 0xc011, 0xc007].contains(id));
    }
    let initial_length = ciphers.len();
    let mut index = 1;
    while index < ciphers.len() {
        if random.coin(0.4 * index as f64 / initial_length as f64) {
            ciphers.remove(index);
        } else {
            index += 1;
        }
    }
    let mut signatures = vec![0x0403, 0x0401, 0x0503, 0x0501, 0x0201, 0x0601];
    if random.coin(0.63) {
        signatures.push(0x0203);
    }
    if random.coin(0.59) {
        signatures.push(0x0603);
    }
    if random.coin(0.51) || tls13 {
        signatures.push(0x0804);
        if random.coin(0.9) {
            signatures.extend([0x0805, 0x0806]);
        }
    }
    random.shuffle(&mut signatures);
    let mut groups = Vec::new();
    if random.coin(0.71) && tls13 {
        groups.push(0x11ec);
    }
    if random.coin(0.71) || tls13 {
        groups.push(29);
    }
    groups.extend([23, 24]);
    if random.coin(0.46) {
        groups.push(25);
    }
    let ext = |id, data: &str| Extension {
        id,
        data: data.into(),
        ..Default::default()
    };
    let mut extensions = vec![
        ext(0, ""),
        ext(35, ""),
        Extension {
            id: 13,
            values: signatures,
            ..Default::default()
        },
        ext(11, "0100"),
        Extension {
            id: 10,
            values: groups,
            ..Default::default()
        },
    ];
    if alpn {
        extensions.push(ext(16, "000c02683208687474702f312e31"));
    }
    if random.coin(0.62) || tls13 {
        extensions.push(ext(21, ""));
    }
    if random.coin(0.74) {
        extensions.push(ext(5, "0100000000"));
    }
    if random.coin(0.46) {
        extensions.push(ext(18, ""));
    }
    if random.coin(0.75) {
        extensions.push(ext(65281, "00"));
    }
    if random.coin(0.77) {
        extensions.push(ext(23, ""));
    }
    if tls13 {
        let mut shares = vec![(29, 32)];
        if random.coin(0.0) {
            shares = vec![(23, 65)];
        } else {
            if random.coin(0.5) {
                shares.push((23, 65));
            }
            if random.coin(0.5) {
                shares.insert(0, (0x11ec, 1216));
            }
        }
        extensions.push(Extension {
            id: 51,
            shares,
            ..Default::default()
        });
        extensions.push(ext(45, "0101"));
        extensions.push(Extension {
            id: 43,
            values: (minimum..=0x304).rev().collect(),
            ..Default::default()
        });
        if alpn {
            let mut salted = [0; 32];
            hkdf::Hkdf::<sha3::Sha3_256>::new(Some(b"ALPS"), seed)
                .expand(&[], &mut salted)
                .expect("profile HKDF");
            if ProfileRandom::new(&salted).coin(0.33) {
                extensions.push(ext(17513, "0003026832"));
            }
        }
    }
    random.shuffle(&mut extensions);
    Profile {
        session_id_length: 32,
        ciphers,
        extensions,
        shuffle: false,
    }
}

struct ProfileRandom(sha3::Shake256Reader);
impl ProfileRandom {
    fn new(seed: &[u8; 32]) -> Self {
        use sha3::digest::{ExtendableOutput, Update};
        let mut shake = sha3::Shake256::default();
        shake.update(seed);
        Self(shake.finalize_xof())
    }
    fn int63(&mut self) -> u64 {
        use sha3::digest::XofReader;
        let mut bytes = [0; 8];
        self.0.read(&mut bytes);
        u64::from_be_bytes(bytes) & i64::MAX as u64
    }
    fn coin(&mut self, weight: f64) -> bool {
        self.int63() as f64 / i64::MAX as f64 > 1.0 - weight
    }
    fn intn(&mut self, n: usize) -> usize {
        if n.is_power_of_two() {
            return (self.int63() >> 32) as usize & (n - 1);
        }
        let max = (1u64 << 31) - 1 - (1u64 << 31) % n as u64;
        loop {
            let v = self.int63() >> 32;
            if v <= max {
                return (v % n as u64) as usize;
            }
        }
    }
    fn permutation(&mut self, n: usize) -> Vec<usize> {
        let mut items = vec![0; n];
        for i in 0..n {
            let j = self.intn(i + 1);
            items[i] = items[j];
            items[j] = i;
        }
        items
    }
    fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            let n = (i + 1) as u32;
            let mut product = (self.int63() >> 31) * (n as u64);
            if (product as u32) < n {
                let threshold = n.wrapping_neg() % n;
                while (product as u32) < threshold {
                    product = (self.int63() >> 31) * (n as u64);
                }
            }
            items.swap(i, (product >> 32) as usize);
        }
    }
}

fn random(limit: usize) -> io::Result<usize> {
    let mut bytes = [0; 8];
    getrandom::getrandom(&mut bytes).map_err(|error| io::Error::other(error.to_string()))?;
    Ok((u64::from_le_bytes(bytes) % limit as u64) as usize)
}

fn shuffle_extensions<T>(items: &mut [T], id: impl Fn(&T) -> u16) -> io::Result<()> {
    let movable: Vec<_> = items
        .iter()
        .enumerate()
        .filter_map(|(index, extension)| {
            let id = id(extension);
            (!(matches!(id, 21 | 41) || id & 0x0f0f == 0x0a0a && id >> 8 == id & 255))
                .then_some(index)
        })
        .collect();
    for i in (1..movable.len()).rev() {
        items.swap(movable[i], movable[random(i + 1)?]);
    }
    Ok(())
}

fn hex(value: &str) -> io::Result<Vec<u8>> {
    value
        .as_bytes()
        .as_chunks::<2>().0.iter()
        .map(|pair| {
            let high = (pair[0] as char)
                .to_digit(16)
                .ok_or_else(|| io::Error::other("profile hex"))?;
            let low = (pair[1] as char)
                .to_digit(16)
                .ok_or_else(|| io::Error::other("profile hex"))?;
            Ok(((high << 4) | low) as u8)
        })
        .collect()
}

struct Zlib;
impl CertificateCompressor for Zlib {
    const ALGORITHM: Compression = Compression::ZLIB;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;
    fn decompress<W: Write>(&self, input: &[u8], output: &mut W) -> io::Result<()> {
        io::copy(&mut flate2::read::ZlibDecoder::new(input), output).map(|_| ())
    }
}
struct Brotli;
impl CertificateCompressor for Brotli {
    const ALGORITHM: Compression = Compression::BROTLI;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;
    fn decompress<W: Write>(&self, input: &[u8], output: &mut W) -> io::Result<()> {
        brotli::BrotliDecompress(&mut &*input, output)
    }
}
struct Zstd;
impl CertificateCompressor for Zstd {
    const ALGORITHM: Compression = Compression::ZSTD;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;
    fn decompress<W: Write>(&self, input: &[u8], output: &mut W) -> io::Result<()> {
        zstd::stream::copy_decode(input, output)
    }
}

#[cfg(test)]
#[test]
fn randomized_specs_match_seeded_utls() {
    let references: HashMap<String, Profile> =
        serde_json::from_str(include_str!("randomized-fixtures.json")).unwrap();
    for (name, expected) in references {
        let (name, seed) = name.rsplit_once('-').unwrap();
        let actual = randomized_seeded(name, &[seed.parse::<u8>().unwrap(); 32]);
        assert_eq!(actual.ciphers, expected.ciphers, "{name}-{seed} ciphers");
        let expected_ids: Vec<_> = expected.extensions.iter().map(|e| e.id).collect();
        let actual_ids: Vec<_> = actual
            .extensions
            .iter()
            .filter(|e| e.id != 21 || expected_ids.contains(&21))
            .map(|e| e.id)
            .collect();
        assert_eq!(actual_ids, expected_ids, "{name}-{seed} extensions");
        for extension in &actual.extensions {
            if let Some(reference) = expected.extensions.iter().find(|e| e.id == extension.id) {
                assert_eq!(
                    extension.values, reference.values,
                    "{name}-{seed} {} values",
                    extension.id
                );
                assert_eq!(
                    extension.shares, reference.shares,
                    "{name}-{seed} {} shares",
                    extension.id
                );
                assert_eq!(
                    extension.data, reference.data,
                    "{name}-{seed} {} data",
                    extension.id
                );
            }
        }
        let options = AdvancedTlsOptions::default();
        let mut builder =
            boring2::ssl::SslConnector::no_default_verify_builder(boring2::ssl::SslMethod::tls())
                .unwrap();
        configure_profile(&mut builder, &options, &actual).unwrap();
        let mut config = builder.build().configure().unwrap();
        config.set_verify_hostname(false);
        let mut ssl = config.into_ssl(Some("example.com")).unwrap();
        configure_connection(&mut ssl, Some(&actual), &options).unwrap();
        let mut connection = boring2::ssl::SslStream::new(ssl, super::MemoryIo::default()).unwrap();
        assert_eq!(
            connection.connect().unwrap_err().code(),
            boring2::ssl::ErrorCode::WANT_READ
        );
        let bytes = &connection.get_ref().output[5..];
        let word = |p: usize| u16::from_be_bytes([bytes[p], bytes[p + 1]]) as usize;
        let mut p = 39 + bytes[38] as usize;
        p += 2 + word(p);
        p += 1 + bytes[p] as usize;
        p += 2;
        let mut wire_ids = Vec::new();
        while p < bytes.len() {
            let id = word(p) as u16;
            let length = word(p + 2);
            wire_ids.push(id);
            if id == 51 {
                let mut q = p + 6;
                let mut shares = Vec::new();
                while q < p + 4 + length {
                    let group = word(q) as u16;
                    let n = word(q + 2);
                    shares.push((group, n));
                    q += 4 + n;
                }
                assert_eq!(
                    shares,
                    expected
                        .extensions
                        .iter()
                        .find(|e| e.id == 51)
                        .unwrap()
                        .shares,
                    "{name}-{seed} wire shares"
                );
            }
            p += 4 + length;
        }
        assert_eq!(wire_ids, expected_ids, "{name}-{seed} wire extensions");
    }
}
