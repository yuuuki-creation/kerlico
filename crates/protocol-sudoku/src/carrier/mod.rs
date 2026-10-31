pub(crate) mod endpoint;
pub(crate) mod http;
pub(crate) mod raw;
pub(crate) mod tls;
pub(crate) mod ws;

pub(crate) struct Opened {
    pub stream: kerlico_core::BoxStream,
    pub early_response: Option<Vec<u8>>,
}
