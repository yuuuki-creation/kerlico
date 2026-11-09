use super::congestion::{BbrProfile, BrutalConfig, bbr};
use quinn::congestion::{ControllerFactory, NewRenoConfig};
use quinn::{ClientConfig, Connection, EndpointConfig, MtuDiscoveryConfig, TransportConfig, VarInt};
use quinn_proto::{ConnectionIdGenerator, RandomConnectionIdGenerator};
use serde::Deserialize;
use serde_json::Value;
use std::io;
use std::sync::Arc;
use std::time::Duration;

const MIB: u64 = 1024 * 1024;
const MAX_STREAMS: u64 = 1 << 60;
const HYSTERIA_DATAGRAM: u32 = 1200;

/// QUIC consumers with distinct Xray defaults and congestion negotiation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QuicCarrier {
    Xhttp,
    Xdrive,
    Dns,
    Hysteria,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum Congestion {
    #[default]
    Default,
    Reno,
    Bbr,
    Brutal,
    ForceBrutal,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct RawOptions {
    congestion: String,
    debug: bool,
    bbr_profile: String,
    brutal_up: String,
    brutal_down: String,
    brutal_disable_loss_compensation: bool,
    init_stream_receive_window: u64,
    max_stream_receive_window: u64,
    init_connection_receive_window: u64,
    max_connection_receive_window: u64,
    max_idle_timeout: u64,
    keep_alive_period: u64,
    #[serde(rename = "disablePathMTUDiscovery")]
    disable_path_mtu_discovery: bool,
    disable_chrome_parrot: bool,
    #[serde(rename = "disableGSO")]
    disable_gso: bool,
    max_incoming_streams: u64,
    disable_stateless_reset: bool,
}

/// Parsed `finalmask.quicParams`. Rates are stored as bytes per second, as in Hysteria auth.
#[derive(Clone, Debug, Default)]
pub struct QuicOptions {
    raw: RawOptions,
    congestion: Congestion,
    bbr_profile: BbrProfile,
    brutal_up: u64,
    brutal_down: u64,
}

impl QuicOptions {
    pub fn parse(value: Option<&Value>) -> io::Result<Self> {
        let Some(value) = value else {
            return Ok(Self::default());
        };
        let mut fields = value.as_object().cloned().ok_or_else(|| invalid("quicParams must be an object"))?;
        fields.retain(|_, value| !value.is_null());
        let raw: RawOptions = serde_json::from_value(Value::Object(fields)).map_err(invalid)?;
        let congestion = match raw.congestion.to_ascii_lowercase().as_str() {
            "" => Congestion::Default,
            "reno" => Congestion::Reno,
            "bbr" => Congestion::Bbr,
            "brutal" => Congestion::Brutal,
            "force-brutal" => Congestion::ForceBrutal,
            _ => return Err(invalid("unknown QUIC congestion control")),
        };
        let bbr_profile = BbrProfile::parse(&raw.bbr_profile)?;
        let brutal_up = bandwidth(&raw.brutal_up)?;
        let brutal_down = bandwidth(&raw.brutal_down)?;
        if congestion == Congestion::ForceBrutal && brutal_up == 0 {
            return Err(invalid("force-brutal requires brutalUp"));
        }
        for (name, window) in [
            ("initStreamReceiveWindow", raw.init_stream_receive_window),
            ("maxStreamReceiveWindow", raw.max_stream_receive_window),
            ("initConnectionReceiveWindow", raw.init_connection_receive_window),
            ("maxConnectionReceiveWindow", raw.max_connection_receive_window),
        ] {
            if window != 0 && window < 16_384 {
                return Err(invalid(format!("{name} must be at least 16384")));
            }
        }
        if raw.max_idle_timeout != 0 && !(4..=120).contains(&raw.max_idle_timeout) {
            return Err(invalid("maxIdleTimeout must be between 4 and 120"));
        }
        if raw.keep_alive_period != 0 && !(2..=60).contains(&raw.keep_alive_period) {
            return Err(invalid("keepAlivePeriod must be between 2 and 60"));
        }
        if raw.max_incoming_streams != 0 && raw.max_incoming_streams < 8 {
            return Err(invalid("maxIncomingStreams must be at least 8"));
        }
        Ok(Self { raw, congestion, bbr_profile, brutal_up, brutal_down })
    }

    pub fn chrome_parrot(&self, client: bool) -> bool {
        client && !self.raw.disable_chrome_parrot
    }

    pub fn receive_rate(&self) -> u64 {
        self.brutal_down
    }

    pub fn endpoint(&self, client: bool) -> EndpointConfig {
        let mut config = EndpointConfig::default();
        let chrome = self.chrome_parrot(client);
        config.send_stateless_reset(!client && !self.raw.disable_stateless_reset)
            .grease_quic_bit(false);
        config.max_udp_payload_size(if chrome { 1472 } else { 1452 }).expect("QUIC payload size");
        if chrome {
            config.cid_generator(|| Box::new(RandomConnectionIdGenerator::new(0)))
                .supported_versions(vec![1]);
        }
        config
    }

    pub fn configure_client(&self, config: &mut ClientConfig) {
        if self.chrome_parrot(true) {
            config
                .initial_dst_cid_provider(Arc::new(|| RandomConnectionIdGenerator::new(8).generate_cid()))
                .token_store(Arc::new(quinn_proto::NoneTokenStore));
        }
    }

    pub fn transport(
        &self,
        carrier: QuicCarrier,
        client: bool,
        xmux_keepalive: i64,
    ) -> io::Result<Arc<TransportConfig>> {
        let chrome = self.chrome_parrot(client);
        let hy = carrier == QuicCarrier::Hysteria;
        let (initial_stream, maximum_stream, initial_connection, maximum_connection) = if hy {
            (8 * MIB, 8 * MIB, 20 * MIB, 20 * MIB)
        } else {
            (2 * MIB, 6 * MIB, 3 * MIB, 15 * MIB)
        };
        let initial_stream = if chrome { 6 * MIB } else {
            configured(self.raw.init_stream_receive_window, initial_stream)
        };
        let initial_connection = if chrome { 15 * MIB } else {
            configured(self.raw.init_connection_receive_window, initial_connection)
        };
        let maximum_stream = configured(self.raw.max_stream_receive_window, maximum_stream).max(initial_stream);
        let maximum_connection = configured(self.raw.max_connection_receive_window, maximum_connection).max(initial_connection);
        let default_idle = if carrier == QuicCarrier::Xhttp && client { 300 } else { 30 };
        let idle = if chrome { 30 } else { configured(self.raw.max_idle_timeout, default_idle) };
        let default_bidi = match (carrier, client) {
            (QuicCarrier::Hysteria, false) => 1024,
            (QuicCarrier::Xhttp, true) => 0,
            _ => 100,
        };
        let bidi = if chrome || carrier == QuicCarrier::Dns || hy && client {
            100
        } else {
            configured(self.raw.max_incoming_streams, default_bidi).min(MAX_STREAMS)
        };
        let uni = if chrome { 103 } else { 100 };
        let keepalive = if !client {
            0
        } else {
            let default = match (carrier, xmux_keepalive) {
                (QuicCarrier::Xhttp, 0) => 10,
                (QuicCarrier::Xhttp | QuicCarrier::Xdrive, value) => value.max(0) as u64,
                _ => 0,
            };
            configured(self.raw.keep_alive_period, default)
        };
        let datagram = if chrome {
            Some(65_536u32.into())
        } else if hy && !client {
            Some(HYSTERIA_DATAGRAM.into())
        } else {
            None
        };
        let mut config = TransportConfig::default();
        config
            .chrome_parrot(chrome)
            .immediate_peer_rebinding(hy && !client)
            .bound_keep_alive_interval(true)
            .initial_mtu(if chrome { 1250 } else { 1280 })
            .max_idle_timeout(Some(VarInt::from_u64(idle * 1000).map_err(invalid)?.into()))
            .keep_alive_interval((keepalive != 0).then(|| Duration::from_secs(keepalive)))
            .max_concurrent_bidi_streams(VarInt::from_u64(bidi).map_err(invalid)?)
            .max_concurrent_uni_streams(VarInt::from_u32(uni))
            .stream_receive_window(VarInt::from_u64(initial_stream).map_err(invalid)?)
            .receive_window(VarInt::from_u64(initial_connection).map_err(invalid)?)
            .receive_window_limits(clamp_varint(maximum_stream), clamp_varint(maximum_connection))
            .allow_spin(false)
            .datagram_receive_buffer_size((chrome || hy).then_some(1024 * 1024))
            .datagram_parameters(datagram, (hy && !client).then_some(HYSTERIA_DATAGRAM.into()))
            .enable_segmentation_offload(!self.raw.disable_gso)
            .congestion_controller_factory(self.controller(carrier)?);
        let mtud = cfg!(any(target_os = "linux", target_os = "windows", target_os = "macos"))
            && !self.raw.disable_path_mtu_discovery;
        let mut discovery = MtuDiscoveryConfig::default();
        discovery.upper_bound(1452);
        config.mtu_discovery_config(mtud.then_some(discovery));
        Ok(Arc::new(config))
    }

    fn controller(&self, carrier: QuicCarrier) -> io::Result<Arc<dyn ControllerFactory + Send + Sync>> {
        if carrier == QuicCarrier::Hysteria {
            // Hysteria selects its application congestion controller after authentication.
            return Ok(Arc::new(NewRenoConfig::default()));
        }
        match self.congestion {
            Congestion::Reno => Ok(Arc::new(NewRenoConfig::default())),
            Congestion::Default if carrier == QuicCarrier::Dns => Ok(Arc::new(NewRenoConfig::default())),
            Congestion::Default | Congestion::Bbr => Ok(bbr(self.bbr_profile, self.raw.debug)),
            Congestion::ForceBrutal if carrier != QuicCarrier::Xdrive => Ok(self.brutal(self.brutal_up)),
            Congestion::ForceBrutal | Congestion::Brutal => Err(invalid("unsupported congestion control on this HTTP/3 carrier")),
        }
    }

    pub fn authenticate(&self, conn: &Connection, peer_receive_rate: u64) {
        let factory = match self.congestion {
            Congestion::Reno => return,
            Congestion::ForceBrutal => self.brutal(self.brutal_up),
            Congestion::Default | Congestion::Brutal if self.brutal_up != 0 && peer_receive_rate != 0 => {
                self.brutal(self.brutal_up.min(peer_receive_rate))
            }
            _ => bbr(self.bbr_profile, self.raw.debug),
        };
        conn.set_congestion_controller(factory);
    }

    fn brutal(&self, rate: u64) -> Arc<dyn ControllerFactory + Send + Sync> {
        Arc::new(BrutalConfig::new(rate, !self.raw.brutal_disable_loss_compensation, self.raw.debug))
    }
}

fn configured(value: u64, default: u64) -> u64 {
    if value == 0 { default } else { value }
}

fn clamp_varint(value: u64) -> VarInt {
    VarInt::from_u64(value).unwrap_or(VarInt::MAX)
}

fn bandwidth(value: &str) -> io::Result<u64> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(0);
    }
    let index = value.find(|c: char| !c.is_ascii_digit() && c != '.').unwrap_or(value.len());
    let bits = value[..index].parse::<f64>().map_err(invalid)?;
    let multiplier = match value[index..].trim().to_ascii_lowercase().as_str() {
        "" | "b" | "bps" => 1u64,
        "k" | "kb" | "kbps" => 1 << 10,
        "m" | "mb" | "mbps" => 1 << 20,
        "g" | "gb" | "gbps" => 1 << 30,
        "t" | "tb" | "tbps" => 1 << 40,
        _ => return Err(invalid("unsupported QUIC bandwidth unit")),
    };
    let bits = bits * multiplier as f64;
    if !bits.is_finite() || bits >= u64::MAX as f64 {
        return Err(invalid("QUIC bandwidth is out of range"));
    }
    let bytes = bits as u64 / 8;
    if bytes != 0 && bytes < 65_536 {
        return Err(invalid("Brutal bandwidth must be at least 65536 bytes per second"));
    }
    Ok(bytes)
}

fn invalid(error: impl ToString) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
}
