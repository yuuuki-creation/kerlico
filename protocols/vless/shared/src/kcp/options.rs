use serde::Deserialize;
use std::io;
use std::time::Duration;

const MIB: u32 = 1024 * 1024;
const DATA_HEADER: u32 = 18;
const ACK_HEADER: u32 = 17;
const MAX_UDP_PAYLOAD: u32 = 65_507;

/// mKCP's packet sizes, data flush interval, and packet budgets.
#[derive(Clone, Copy, Debug)]
pub struct KcpOptions {
    pub(super) data_payload: usize,
    pub(super) ack_entries: usize,
    pub(super) send_flight: u32,
    pub(super) receive_window: u32,
    pub(super) send_queue: usize,
    pub(super) cwnd_multiplier: u32,
    interval: Duration,
}

#[derive(Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Parameters {
    mtu: u32,
    tti: u32,
    uplink_capacity: u32,
    downlink_capacity: u32,
    cwnd_multiplier: u32,
    max_sending_window: u32,
}

impl Default for Parameters {
    fn default() -> Self {
        Self {
            mtu: 1350,
            tti: 50,
            uplink_capacity: 5,
            downlink_capacity: 20,
            cwnd_multiplier: 1,
            max_sending_window: 2 * MIB,
        }
    }
}

impl Default for KcpOptions {
    fn default() -> Self {
        Parameters::default().options().expect("default mKCP options")
    }
}

impl KcpOptions {
    /// Read Kerlico's transport settings. Flat fields override the corresponding kcpSettings values.
    pub fn from_settings<'a>(mut value: impl FnMut(&str) -> Option<&'a str>) -> io::Result<Self> {
        let mut config = Parameters::default();
        if let Some(json) = value("kcpSettings") {
            if let Some(mut fields) = serde_json::from_str::<Option<serde_json::Map<String, serde_json::Value>>>(json)
                .map_err(invalid)?
            {
                fields.retain(|_, value| !value.is_null());
                config = serde_json::from_value(serde_json::Value::Object(fields)).map_err(invalid)?;
            }
        }
        for (key, parameter) in [
            ("mtu", &mut config.mtu),
            ("tti", &mut config.tti),
            ("uplinkCapacity", &mut config.uplink_capacity),
            ("downlinkCapacity", &mut config.downlink_capacity),
            ("cwndMultiplier", &mut config.cwnd_multiplier),
            ("maxSendingWindow", &mut config.max_sending_window),
        ] {
            if let Some(text) = value(key) {
                *parameter = text.parse().map_err(invalid)?;
            }
        }
        config.options()
    }

    pub fn interval(&self) -> Duration {
        self.interval
    }

    pub fn poll_interval(&self) -> Duration {
        (self.interval / 2).min(Duration::from_millis(50))
    }
}

impl Parameters {
    fn options(self) -> io::Result<KcpOptions> {
        if self.mtu < 21 {
            return Err(invalid("mKCP mtu must be at least 21"));
        }
        if !(10..=1000).contains(&self.tti) {
            return Err(invalid("mKCP tti must be between 10 and 1000 milliseconds"));
        }
        if self.cwnd_multiplier == 0 {
            return Err(invalid("mKCP cwndMultiplier must be at least 1"));
        }
        let queue = self.max_sending_window / self.mtu;
        if queue == 0 {
            return Err(invalid("mKCP maxSendingWindow must be at least mtu"));
        }
        let packets_per_tick = |capacity: u32| {
            (capacity.wrapping_mul(MIB) / self.mtu / (1000 / self.tti)).max(8)
        };
        let wire_mtu = self.mtu.min(MAX_UDP_PAYLOAD);
        Ok(KcpOptions {
            data_payload: (wire_mtu - DATA_HEADER) as usize,
            ack_entries: ((wire_mtu - ACK_HEADER) / 4).min(128) as usize,
            send_flight: packets_per_tick(self.uplink_capacity),
            receive_window: packets_per_tick(self.downlink_capacity),
            send_queue: queue as usize + 1,
            cwnd_multiplier: self.cwnd_multiplier,
            interval: Duration::from_millis(self.tti.into()),
        })
    }
}

fn invalid(error: impl ToString) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
}
