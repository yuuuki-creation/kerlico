//! 固定Go同包导出与Rust生产原语对照；缺fixture必须失败，不能静默跳过。
use crate::{
    codec::record::{Method, Receiver, Sender},
    key, udp,
    wire::{address, kip},
};
use kerlico_core::{CancellationToken, Destination};
use serde_json::Value;
use std::{path::PathBuf, time::Duration};
use tokio::io::AsyncWriteExt;
use x25519_dalek::StaticSecret;

fn fixture() -> Value {
    let path = std::env::var_os("KERLICO_SUDOKU_VECTORS")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../tools/sudoku_interop/fixtures/mihomo-crypto.json")
        });
    let bytes = std::fs::read(path)
        .expect("缺少Go独立fixture；先在worker运行tools/sudoku_interop/export_vectors.py");
    let value: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        value["fixed_commit"],
        "3f27ef39f8c96bbfbc8b0b9bb10f5c9ef60149d8"
    );
    assert_eq!(value["network_connections"], 0);
    value
}
fn bytes(value: &Value, name: &str) -> Vec<u8> {
    key::unhex(value[name].as_str().unwrap()).unwrap()
}

#[test]
fn independent_go_initial_session_hkdf_and_direction_separation() {
    let value = fixture();
    let kdf = &value["control"]["kdf"];
    let seed = kdf["seed"].as_str().unwrap();
    let initial = key::initial_keys(seed).unwrap();
    assert_eq!(&initial.c2s[..], bytes(kdf, "initial_c2s_hex"));
    assert_eq!(&initial.s2c[..], bytes(kdf, "initial_s2c_hex"));
    assert_ne!(initial.c2s, initial.s2c);
    let private =
        StaticSecret::from(<[u8; 32]>::try_from(bytes(kdf, "client_private_hex")).unwrap());
    let public = bytes(kdf, "server_public_hex").try_into().unwrap();
    let nonce = bytes(kdf, "nonce_hex").try_into().unwrap();
    let session = key::session_keys(seed, &private, public, nonce).unwrap();
    assert_eq!(&session.c2s[..], bytes(kdf, "session_c2s_hex"));
    assert_eq!(&session.s2c[..], bytes(kdf, "session_s2c_hex"));
    assert_ne!(session.c2s, session.s2c);
    assert_ne!(session.c2s, initial.c2s);
}

#[test]
fn independent_go_aead_epoch_sequence_replay_mac_and_direction_vectors() {
    let fixture = fixture();
    for vector in fixture["records"].as_array().unwrap() {
        let method = match vector["method"].as_str().unwrap() {
            "aes-128-gcm" => Method::Aes,
            "chacha20-poly1305" => Method::ChaCha,
            _ => panic!("未知方法"),
        };
        let base: [u8; 32] = bytes(vector, "base_hex").try_into().unwrap();
        let frames = vector["frames"].as_array().unwrap();
        let mut receiver = Receiver::new(method, base);
        for frame in frames {
            let wire = bytes(frame, "wire_hex");
            assert_eq!(
                usize::from(u16::from_be_bytes(wire[..2].try_into().unwrap())),
                wire.len() - 2
            );
            assert_eq!(
                receiver.open(&wire[2..]).unwrap(),
                bytes(frame, "plain_hex")
            );
        }
        assert!(receiver.open(&bytes(&frames[3], "wire_hex")[2..]).is_err());
        let mut jump = Receiver::new(method, base);
        jump.open(&bytes(&frames[0], "wire_hex")[2..]).unwrap();
        assert!(
            jump.open(&bytes(vector, "jump_nine_wire_hex")[2..])
                .is_err()
        );
        let mut mac = Receiver::new(method, base);
        assert!(mac.open(&bytes(vector, "bad_mac_wire_hex")[2..]).is_err());
        let mut wrong = Receiver::new(method, [0x38; 32]);
        assert!(wrong.open(&bytes(&frames[0], "wire_hex")[2..]).is_err());
        let mut sender = Sender::new(method, base, 32).unwrap();
        let first = sender.seal(&[0; 17]).unwrap();
        let second = sender.seal(&[0; 17]).unwrap();
        let third = sender.seal(&[0; 17]).unwrap();
        assert_eq!(&first[2..6], &second[2..6]);
        assert_eq!(
            u32::from_be_bytes(third[2..6].try_into().unwrap()),
            u32::from_be_bytes(first[2..6].try_into().unwrap()) + 1
        );
    }
}

#[tokio::test]
async fn independent_go_kip_hello_address_and_uot_vectors() {
    let value = fixture();
    let control = &value["control"];
    for item in control["kip"].as_array().unwrap() {
        let kind = item["kind"].as_u64().unwrap() as u8;
        let payload = bytes(item, "payload_hex");
        let wire = bytes(item, "wire_hex");
        assert_eq!(kip::encode(kind, &payload).unwrap(), wire);
        let message = kip::read(&mut wire.as_slice()).await.unwrap();
        assert_eq!(message.kind, kind);
        assert_eq!(message.payload, payload);
        if kind == kip::CLIENT_HELLO {
            let hello = kip::ClientHello::decode(&payload, 1000).unwrap();
            assert_eq!(hello.table_hint, Some(0x10203040));
            assert_eq!(hello.encode(), payload);
        }
        if kind == kip::SERVER_HELLO {
            let nonce = bytes(&control["kdf"], "nonce_hex").try_into().unwrap();
            let hello = kip::ServerHello::decode(&payload, nonce, kip::FEATURES).unwrap();
            assert_eq!(hello.encode(), payload);
        }
    }
    for item in control["uot"].as_array().unwrap() {
        let expected = item["address"].as_str().unwrap();
        let (host, port) = expected.rsplit_once(':').unwrap();
        let target =
            Destination::new(host.trim_matches(['[', ']']), port.parse().unwrap()).unwrap();
        let wire = bytes(item, "wire_hex");
        let plain = bytes(item, "payload_hex");
        let (decoded, used) = address::decode(&wire[4..]).unwrap();
        assert_eq!(decoded, target);
        assert_eq!(
            used,
            usize::from(u16::from_be_bytes(wire[..2].try_into().unwrap()))
        );
        let (reader, mut writer) = tokio::io::duplex(32);
        let cancel = CancellationToken::new();
        let mut association = udp::association(Box::new(reader), &cancel, 65507, false);
        let sent = tokio::spawn(async move {
            writer.write_all(&wire).await.unwrap();
        });
        let got = tokio::time::timeout(Duration::from_secs(3), association.receiver.recv_from())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(got, (target, plain));
        sent.await.unwrap();
    }
    assert_eq!(control["reference_uot_accepts_65508"], true);
}
