//! Shared transport TLS, independent of any proxy protocol.

pub mod advanced;
pub mod tls;

pub use tls::{client_config, server_config};

use std::io;

pub fn string_list(text: &str) -> io::Result<Vec<String>> {
    if text.trim_start().starts_with('[') {
        serde_json::from_str(text).map_err(io::Error::other)
    } else if text.is_empty() {
        Ok(Vec::new())
    } else {
        Ok(text.split(',').map(|part| part.trim().to_string()).collect())
    }
}
