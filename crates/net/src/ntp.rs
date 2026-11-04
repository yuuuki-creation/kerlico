//! 内置 SNTP/NTPv4 时间同步客户端（RFC 5905）与进程内单调时钟偏移校准。

use kerlico_core::{Address, Destination, Error, Result};
use std::{
    net::SocketAddr,
    sync::atomic::{AtomicI64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::net::UdpSocket;

/// 1900-01-01 至 1970-01-01 的秒数差。
pub const NTP_UNIX_EPOCH_DIFF_SECS: u64 = 2_208_988_800;

static NTP_OFFSET_MS: AtomicI64 = AtomicI64::new(0);

/// 获取当前已校准的时钟偏移量（毫秒，正值表示远端 NTP 时间超前于本机系统时钟）。
pub fn ntp_offset_ms() -> i64 {
    NTP_OFFSET_MS.load(Ordering::Relaxed)
}

/// 更新进程内全局 NTP 时钟偏移量（毫秒）。
pub fn set_ntp_offset_ms(offset_ms: i64) {
    NTP_OFFSET_MS.store(offset_ms, Ordering::Relaxed);
}

/// 返回校准后的当前 Unix 毫秒时间戳。
pub fn calibrated_unix_ms() -> u64 {
    let local_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64;
    local_ms.saturating_add(ntp_offset_ms()).max(0) as u64
}

/// 构造 48 字节 SNTPv4 客户端请求报文（LI=0, VN=4, Mode=3 Client）。
pub fn encode_ntp_request(originate_unix_ms: u64) -> [u8; 48] {
    let mut pkt = [0u8; 48];
    pkt[0] = 0b00_100_011; // LI = 0, VN = 4, Mode = 3 (Client)
    let (secs, frac) = unix_ms_to_ntp_timestamp(originate_unix_ms);
    pkt[40..44].copy_from_slice(&secs.to_be_bytes());
    pkt[44..48].copy_from_slice(&frac.to_be_bytes());
    pkt
}

/// 解析 48 字节 SNTPv4 服务端响应报文并计算相对本机的时钟偏移（毫秒）。
///
/// 采用标准四时间戳公式：`theta = ((T2 - T1) + (T3 - T4)) / 2`
pub fn decode_ntp_response(pkt: &[u8], t1_unix_ms: u64, t4_unix_ms: u64) -> Result<i64> {
    if pkt.len() < 48 {
        return Err(Error::Protocol("NTP 响应报文长度不足 48 字节"));
    }
    let mode = pkt[0] & 0x07;
    let stratum = pkt[1];
    if (mode != 4 && mode != 5) || stratum == 0 || stratum >= 16 {
        return Err(Error::Protocol("NTP 响应模式或 Stratum 不合法"));
    }
    let rx_secs = u32::from_be_bytes([pkt[32], pkt[33], pkt[34], pkt[35]]);
    let rx_frac = u32::from_be_bytes([pkt[36], pkt[37], pkt[38], pkt[39]]);
    let tx_secs = u32::from_be_bytes([pkt[40], pkt[41], pkt[42], pkt[43]]);
    let tx_frac = u32::from_be_bytes([pkt[44], pkt[45], pkt[46], pkt[47]]);

    let t2_ms = ntp_timestamp_to_unix_ms(rx_secs, rx_frac)? as i64;
    let t3_ms = ntp_timestamp_to_unix_ms(tx_secs, tx_frac)? as i64;
    let t1_ms = t1_unix_ms as i64;
    let t4_ms = t4_unix_ms as i64;

    let offset = ((t2_ms - t1_ms) + (t3_ms - t4_ms)) / 2;
    Ok(offset)
}

pub fn unix_ms_to_ntp_timestamp(unix_ms: u64) -> (u32, u32) {
    let unix_secs = unix_ms / 1000;
    let rem_ms = unix_ms % 1000;
    let ntp_secs = unix_secs.wrapping_add(NTP_UNIX_EPOCH_DIFF_SECS) as u32;
    let ntp_frac = ((rem_ms << 32) / 1000) as u32;
    (ntp_secs, ntp_frac)
}

pub fn ntp_timestamp_to_unix_ms(ntp_secs: u32, ntp_frac: u32) -> Result<u64> {
    let secs = u64::from(ntp_secs);
    if secs < NTP_UNIX_EPOCH_DIFF_SECS {
        return Err(Error::Protocol("NTP 时间戳早于 Unix 纪元"));
    }
    let unix_secs = secs - NTP_UNIX_EPOCH_DIFF_SECS;
    let rem_ms = (u64::from(ntp_frac) * 1000) >> 32;
    Ok(unix_secs * 1000 + rem_ms)
}

/// 向指定 NTP 服务器发起一次 UDP 同步查询并更新全局偏移量。
pub async fn sync_once_udp(server: &Destination, timeout: Duration) -> Result<i64> {
    let addr: SocketAddr = match server.address() {
        Address::Ip(ip) => SocketAddr::new(*ip, server.port()),
        Address::Domain(host) => tokio::net::lookup_host((host.as_str(), server.port()))
            .await?
            .next()
            .ok_or_else(|| {
                Error::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "未解析出 NTP 目标地址",
                ))
            })?,
    };
    let bind_addr: SocketAddr = if addr.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0u16; 8], 0))
    };
    let sock = UdpSocket::bind(bind_addr).await?;
    let t1 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let req = encode_ntp_request(t1);
    tokio::time::timeout(timeout, sock.send_to(&req, addr))
        .await
        .map_err(|_| Error::Timeout)??;
    let mut buf = [0u8; 64];
    let (n, _) = tokio::time::timeout(timeout, sock.recv_from(&mut buf))
        .await
        .map_err(|_| Error::Timeout)??;
    let t4 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let offset = decode_ntp_response(&buf[..n], t1, t4)?;
    set_ntp_offset_ms(offset);
    Ok(offset)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ntp_request_and_response_round_trip_offset() {
        let t1 = 1_700_000_000_000u64;
        let req = encode_ntp_request(t1);
        assert_eq!(req[0], 0x23);

        // Simulate server ahead by +2500ms with 20ms network RTT
        let t2 = t1 + 10 + 2500;
        let t3 = t2 + 2;
        let t4 = t1 + 22;

        let mut resp = [0u8; 48];
        resp[0] = 0b00_100_100; // Mode = 4 (Server)
        resp[1] = 2; // Stratum = 2
        let (rx_s, rx_f) = unix_ms_to_ntp_timestamp(t2);
        let (tx_s, tx_f) = unix_ms_to_ntp_timestamp(t3);
        resp[32..36].copy_from_slice(&rx_s.to_be_bytes());
        resp[36..40].copy_from_slice(&rx_f.to_be_bytes());
        resp[40..44].copy_from_slice(&tx_s.to_be_bytes());
        resp[44..48].copy_from_slice(&tx_f.to_be_bytes());

        let offset = decode_ntp_response(&resp, t1, t4).expect("decode ntp");
        assert!((offset - 2500).abs() <= 2, "offset={offset}");
    }
}
