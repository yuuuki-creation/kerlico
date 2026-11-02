mod crypto;
mod packet;
mod runtime;

use base64::{Engine, engine::general_purpose::STANDARD};
use boringtun::x25519::{PublicKey, StaticSecret};
use serde_json::{Value, json};

fn private(number: u8) -> String {
    STANDARD.encode([number; 32])
}
fn public(number: u8) -> String {
    STANDARD.encode(PublicKey::from(&StaticSecret::from([number; 32])).as_bytes())
}
fn tunnel(number: u8, last: u8) -> Value {
    json!({"private_key": private(number), "addresses": [format!("10.77.0.{last}"), format!("fd77::{last}")], "mtu": 1280})
}
fn peer(number: u8, last: Option<u8>, psk: Option<u8>) -> Value {
    let allowed = last.map_or_else(
        || vec!["0.0.0.0/0".to_owned(), "::/0".to_owned()],
        |last| vec![format!("10.77.0.{last}/32"), format!("fd77::{last}/128")],
    );
    let mut value = json!({"public_key": public(number), "allowed_ips": allowed});
    if let Some(psk) = psk {
        value["preshared_key"] = json!(private(psk));
    }
    value
}
