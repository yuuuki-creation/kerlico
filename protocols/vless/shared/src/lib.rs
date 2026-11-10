//! VLESS header, UUID mapping, and UDP length prefix.

mod encrypt;
mod config;
pub mod runtime;
mod proxy;
mod transport;
mod response;
mod quic;
mod raw_http;
pub mod xdrive;
pub mod xmux;
pub mod finalmask;
mod reality;
mod reality_tls;
mod reality_rate;
mod reality_spider;
pub use reality_rate::{RealityRateLimit, RealityRateLimitedRead, RealityRateLimitedWrite};
pub use reality_spider::{RealitySpiderConfig, run_reality_spider};
pub use reality_tls::{RealityTargetShape, server_flight_with_target, RealityDecoyVerifier, RealityClientFlight, RealityClientResult, read_server_flight_or_decoy};
mod grpc;
mod kcp;
mod header;
mod mux;
mod http;
mod go_json;
mod h2_params;
mod tls;
mod upgrade;
mod uuid;
mod vision;
mod xhttp;
mod ws;

pub use encrypt::{accept_native, accept_encrypted, client_key, connect_native, connect_encrypted, encode_key, native_pair, server_key, EncReader, EncWriter, NfsKey, Pad};
pub use proxy::{accept_proxy, TrustedForwardedFor};
pub use transport::{mask_network, mask_tcp, mask_tcp_at, MaskedRead, MaskedWrite};
pub use reality::{auth_key, decode_reality_key, decode_short_id, encode_reality_key, open_session, read_tls_record, read_client_hello, reality_accept, reality_offer_hybrid, reality_offer_hybrid_with_alpn, reality_pair, seal_session};
pub use reality_tls::{client_keys, read_client_finished, read_server_flight, read_server_flight_with_alpn, reader as reality_reader, server_flight, server_flight_with_alpn, take_flight, writer as reality_writer, AppReader, AppWriter, RealityDuplex, ServerHello};
pub use grpc::{grpc_path, GrpcConnection, GrpcOptions, GrpcStream};
pub use kcp::{kcp_mask, KcpIo, KcpMask, KcpOptions, Session};
pub use http::{goaway_frame, H2Conn, H2Limits, H2Request, H2Stream, HttpIo, SharedHttp, HTTP2_PREFACE, INADEQUATE_SECURITY};
pub use h2_params::{h2_tls_rejection, H2Params};
pub use header::{decode_request, decode_response, encode_request, encode_response, Addr, Command, Request, Response};
pub use mux::{control_frame, control_keep, control_state, decode_mux, encode_mux, heartbeat_due, session_frame, xudp_global_id, MuxFrame, MuxUplink, DATA, END, KEEP, KEEPALIVE, NEW};
pub use header::{decode_udp, encode_udp, HeaderError, UdpFraming};
pub use tls::{accept_tls, accept_tls_split, accept_tls_over, client_config, client_config_pinned, client_config_versions, connect_tls, connect_tls_split, connect_tls_over, server_config, server_config_versions, ClientConfig, ServerConfig, TlsConfigError, TlsLink, TlsRead, TlsWrite};
pub use upgrade::{
    header_value, host_matches, normalize_path, take_upgrade_request, take_upgrade_response, upgrade_request,
    upgrade_pair, upgrade_response, UpgradeConfig, UpgradeError, UpgradeRead, UpgradeWrite,
};
pub use raw_http::{HttpPrefaceRead, RawHttpConfig, RawHttpWrite};
pub use ws::{accept_value, encode_frame, switch_response, switch_response_with_early_data, FrameDecoder, WsIo, WsSignal, websocket_pair, WsRead, WsWrite};
pub use upgrade::{early_data_limit, upgrade_request_with_early_data, decode_websocket_early_data};
pub use uuid::{parse_id, UuidError};
pub use vision::{Vision, VisionIo, VisionTransport, vision_pair};
pub use response::ResponseReader;
pub use config::{string_list, private_peer, reverse_tag};
pub use reality::{RealityPolicy, reality_accept_with_policy, decode_reality_version};
pub use reality_tls::{RealityMldsa65Signer, RealityMldsa65Verifier, server_flight_with_auth, read_server_flight_with_auth};
pub use quic::{HysteriaMasquerade, MasqueradeDialer, MasqueradeSocket, MasqueradeTarget, QuicCarrier, QuicOptions, H3Conn, H3Listener, H3Stream, HysteriaListener, HysteriaRead, HysteriaWrite, connect_hysteria, connect_hysteria_masked, connect_hysteria_crypto_masked};
pub use xhttp::{
    new_session, read_http_head, read_http_head_with_limit, read_http_request, read_packet_ack,
    read_response_head, session_path, split_session, write_chunk, write_chunked_ok, write_empty_ok,
    write_get, write_post, write_stream_post, write_xhttp_response, ChunkPair, ChunkReader, ChunkWriter, HttpHead,
    XhttpBodyWriter, XhttpConfig, XhttpDownload, XhttpMode, XhttpRequest, XhttpRequestKind,
};

mod advanced_tls;
mod tls_async;
pub use advanced_tls::{advanced_client_config, advanced_server_config, accept_advanced_tls_over, connect_advanced_tls_over, AdvancedTlsClientCache, AdvancedTlsClientConfig, AdvancedTlsServerConfig, AdvancedTlsOptions, TlsCertificate, AdvancedTlsRead, AdvancedTlsWrite};
pub use reality::{RealityOffer, reality_offer_fingerprint};
pub use reality_tls::read_server_flight_for_offer;

pub use advanced_tls::{advanced_quic_client_config, advanced_quic_server_config};

pub type QuicClientCrypto = std::sync::Arc<dyn quinn::crypto::ClientConfig>;
pub type QuicServerCrypto = std::sync::Arc<dyn quinn::crypto::ServerConfig>;

pub use advanced_tls::{TlsNetwork, TlsNetworkRequest, TlsNetworkResponse};

pub mod socket;
