use std::io;

use serde::Deserialize;
use serde_json::Value;

use super::{settings, Range};

pub(super) use kerlico_hy2::obfs::Salamander;

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
struct Config {
    password: String,
    packet_size: Range,
}

pub(super) fn parse(value: Value) -> io::Result<Salamander> {
    let config: Config = settings(value)?;
    let Range { min, max } = config.packet_size;
    Salamander::new(&config.password, (max != 0).then_some((min as usize, max as usize)))
}
