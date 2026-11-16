use super::handshake::{b2s_hash, b2s_keyed_mac_16, b2s_keyed_mac_16_2, b2s_mac_24};
use crate::noise::handshake::{LABEL_COOKIE, LABEL_MAC1};
use crate::noise::{HandshakeInit, HandshakeResponse, Packet, Tunn, TunnResult, WireGuardError};

#[cfg(feature = "mock-instant")]
use mock_instant::Instant;
use portable_atomic::{AtomicU64, Ordering};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::time::Duration;

#[cfg(not(feature = "mock-instant"))]
use crate::sleepyinstant::Instant;

use aead::generic_array::GenericArray;
use aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305};
use parking_lot::Mutex;
use rand_core::{OsRng, RngCore};
use ring::constant_time::verify_slices_are_equal;

const COOKIE_REFRESH: u64 = 120;
const COOKIE_SIZE: usize = 16;
const COOKIE_NONCE_SIZE: usize = 24;

/// How often should reset count in seconds
const RESET_PERIOD: u64 = 1;
const SOURCE_INTERVAL: Duration = Duration::from_millis(50);
const SOURCE_BURST: Duration = Duration::from_millis(250);
const SOURCE_IDLE: Duration = Duration::from_secs(1);
const MAX_SOURCES: usize = 65_536;

type Cookie = [u8; COOKIE_SIZE];

/// A parsed packet that has passed the interface's handshake MAC checks.
pub struct VerifiedPacket<'a>(pub(super) Packet<'a>);

impl<'a> VerifiedPacket<'a> {
    pub fn packet(&self) -> &Packet<'a> {
        &self.0
    }
}

struct SourceBucket {
    last_seen: Duration,
    credit: Duration,
}

#[derive(Default)]
struct SourceRates(HashMap<IpAddr, SourceBucket>);

impl SourceRates {
    fn allow(&mut self, address: IpAddr, now: Duration) -> bool {
        let source = match address.to_canonical() {
            IpAddr::V4(ip) => IpAddr::V4(ip),
            IpAddr::V6(ip) => {
                let prefix = u128::from(ip) & (u128::MAX << 64);
                IpAddr::V6(Ipv6Addr::from(prefix))
            }
        };
        if let Some(bucket) = self.0.get_mut(&source) {
            let elapsed = now.saturating_sub(bucket.last_seen);
            bucket.last_seen = now;
            bucket.credit = bucket.credit.saturating_add(elapsed).min(SOURCE_BURST);
            if bucket.credit < SOURCE_INTERVAL {
                return false;
            }
            bucket.credit -= SOURCE_INTERVAL;
            return true;
        }
        if self.0.len() >= MAX_SOURCES {
            return false;
        }
        self.0.insert(
            source,
            SourceBucket {
                last_seen: now,
                credit: SOURCE_BURST - SOURCE_INTERVAL,
            },
        );
        true
    }

    fn expire(&mut self, now: Duration) {
        self.0
            .retain(|_, bucket| now.saturating_sub(bucket.last_seen) <= SOURCE_IDLE);
        if self.0.is_empty() {
            self.0.shrink_to_fit();
        }
    }
}

/// Validates handshake MACs and admits cookie-authenticated sources under load.
/// Cookie epochs and unique reply nonces are derived from independently seeded keys.
pub struct RateLimiter {
    /// The key we use to derive the nonce
    nonce_key: [u8; 32],
    /// The key we use to derive the cookie
    secret_key: [u8; 16],
    start_time: Instant,
    /// A single 64 bit counter (should suffice for many years)
    nonce_ctr: AtomicU64,
    mac1_key: [u8; 32],
    cookie_key: Key,
    limit: u64,
    /// The counter since last reset
    count: AtomicU64,
    /// The time last reset was performed on this rate limiter
    last_reset: Mutex<Instant>,
    sources: Mutex<SourceRates>,
}

impl RateLimiter {
    pub fn new(public_key: &crate::x25519::PublicKey, limit: u64) -> Self {
        let mut secret_key = [0u8; 16];
        OsRng.fill_bytes(&mut secret_key);
        RateLimiter {
            nonce_key: Self::rand_bytes(),
            secret_key,
            start_time: Instant::now(),
            nonce_ctr: AtomicU64::new(0),
            mac1_key: b2s_hash(LABEL_MAC1, public_key.as_bytes()),
            cookie_key: b2s_hash(LABEL_COOKIE, public_key.as_bytes()).into(),
            limit,
            count: AtomicU64::new(0),
            last_reset: Mutex::new(Instant::now()),
            sources: Mutex::default(),
        }
    }

    fn rand_bytes() -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }

    /// Reset packet count (ideally should be called with a period of 1 second)
    pub fn reset_count(&self) {
        // The rate limiter is not very accurate, but at the scale we care about it doesn't matter much
        let mut last_reset_time = self.last_reset.lock();
        let current_time = Instant::now();
        if current_time.duration_since(*last_reset_time).as_secs() >= RESET_PERIOD {
            self.count.store(0, Ordering::SeqCst);
            *last_reset_time = current_time;
            self.sources.lock().expire(self.start_time.elapsed());
        }
    }

    /// Bind the cookie to the source IP and UDP port as in the Linux implementation.
    fn current_cookie(&self, addr: SocketAddr) -> Cookie {
        let mut endpoint = [0u8; 18];
        let ip_len = match addr.ip().to_canonical() {
            IpAddr::V4(ip) => {
                endpoint[..4].copy_from_slice(&ip.octets());
                4
            }
            IpAddr::V6(ip) => {
                endpoint[..16].copy_from_slice(&ip.octets());
                16
            }
        };
        endpoint[ip_len..ip_len + 2].copy_from_slice(&addr.port().to_be_bytes());
        let cur_counter = Instant::now().duration_since(self.start_time).as_secs() / COOKIE_REFRESH;
        b2s_keyed_mac_16_2(
            &self.secret_key,
            &cur_counter.to_le_bytes(),
            &endpoint[..ip_len + 2],
        )
    }

    fn nonce(&self) -> [u8; COOKIE_NONCE_SIZE] {
        let ctr = self.nonce_ctr.fetch_add(1, Ordering::Relaxed);

        b2s_mac_24(&self.nonce_key, &ctr.to_le_bytes())
    }

    fn is_under_load(&self) -> bool {
        self.count.fetch_add(1, Ordering::SeqCst) >= self.limit
    }

    pub(crate) fn format_cookie_reply<'a>(
        &self,
        idx: u32,
        cookie: Cookie,
        mac1: &[u8],
        dst: &'a mut [u8],
    ) -> Result<&'a mut [u8], WireGuardError> {
        if dst.len() < super::COOKIE_REPLY_SZ {
            return Err(WireGuardError::DestinationBufferTooSmall);
        }

        let (message_type, rest) = dst.split_at_mut(4);
        let (receiver_index, rest) = rest.split_at_mut(4);
        let (nonce, rest) = rest.split_at_mut(24);
        let (encrypted_cookie, _) = rest.split_at_mut(16 + 16);

        // msg.message_type = 3
        // msg.reserved_zero = { 0, 0, 0 }
        message_type.copy_from_slice(&super::COOKIE_REPLY.to_le_bytes());
        // msg.receiver_index = little_endian(initiator.sender_index)
        receiver_index.copy_from_slice(&idx.to_le_bytes());
        nonce.copy_from_slice(&self.nonce()[..]);

        let cipher = XChaCha20Poly1305::new(&self.cookie_key);

        let iv = GenericArray::from_slice(nonce);

        encrypted_cookie[..16].copy_from_slice(&cookie);
        let tag = cipher
            .encrypt_in_place_detached(iv, mac1, &mut encrypted_cookie[..16])
            .map_err(|_| WireGuardError::DestinationBufferTooSmall)?;

        encrypted_cookie[16..].copy_from_slice(&tag);

        Ok(&mut dst[..super::COOKIE_REPLY_SZ])
    }

    /// Verify the MAC fields on the datagram, and apply rate limiting if needed
    pub fn verify_packet<'a, 'b>(
        &self,
        src_addr: Option<SocketAddr>,
        src: &'a [u8],
        dst: &'b mut [u8],
    ) -> Result<VerifiedPacket<'a>, TunnResult<'b>> {
        let packet = Tunn::parse_incoming_packet(src)?;

        // Verify and rate limit handshake messages only
        if let Packet::HandshakeInit(HandshakeInit { sender_idx, .. })
        | Packet::HandshakeResponse(HandshakeResponse { sender_idx, .. }) = packet
        {
            let (msg, macs) = src.split_at(src.len() - 32);
            let (mac1, mac2) = macs.split_at(16);

            let computed_mac1 = b2s_keyed_mac_16(&self.mac1_key, msg);
            verify_slices_are_equal(&computed_mac1[..16], mac1)
                .map_err(|_| TunnResult::Err(WireGuardError::InvalidMac))?;

            if self.is_under_load() {
                let addr = match src_addr {
                    None => return Err(TunnResult::Err(WireGuardError::UnderLoad)),
                    Some(addr) => addr,
                };

                // Only given an address can we validate mac2
                let cookie = self.current_cookie(addr);
                let computed_mac2 = b2s_keyed_mac_16_2(&cookie, msg, mac1);

                if verify_slices_are_equal(&computed_mac2[..16], mac2).is_err() {
                    let cookie_packet = self
                        .format_cookie_reply(sender_idx, cookie, mac1, dst)
                        .map_err(TunnResult::Err)?;
                    return Err(TunnResult::WriteToNetwork(cookie_packet));
                }
                // A valid cookie proves the endpoint; rate-limit before doing Noise DH.
                if !self
                    .sources
                    .lock()
                    .allow(addr.ip(), self.start_time.elapsed())
                {
                    return Err(TunnResult::Err(WireGuardError::UnderLoad));
                }
            }
        }

        Ok(VerifiedPacket(packet))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_rates_share_prefixes_and_refill() {
        let mut rates = SourceRates::default();
        let ip4 = "192.0.2.1".parse().unwrap();
        let mapped = "::ffff:192.0.2.1".parse().unwrap();
        let ip6 = "2001:db8:1::123".parse().unwrap();
        let ip6_same_prefix = "2001:db8:1::456".parse().unwrap();
        for _ in 0..5 {
            assert!(rates.allow(ip4, Duration::ZERO));
            assert!(rates.allow(ip6, Duration::ZERO));
        }
        assert!(!rates.allow(mapped, Duration::ZERO));
        assert!(!rates.allow(ip6_same_prefix, Duration::ZERO));
        assert!(rates.allow("192.0.2.2".parse().unwrap(), Duration::ZERO));
        assert!(rates.allow("2001:db8:2::123".parse().unwrap(), Duration::ZERO));
        assert!(!rates.allow(ip6_same_prefix, Duration::from_millis(49)));
        let next = Duration::from_millis(50);
        assert!(rates.allow(ip6_same_prefix, next));
        assert!(!rates.allow(ip6, next));
        rates.expire(Duration::from_secs(1) + next);
        assert_eq!(rates.0.len(), 1);
        rates.expire(Duration::from_secs(2));
        assert!(rates.0.is_empty());
    }

    #[cfg(feature = "mock-instant")]
    #[test]
    fn valid_cookie_cannot_exceed_source_budget() {
        use crate::x25519::{PublicKey, StaticSecret};

        let public = PublicKey::from(&StaticSecret::from([42; 32]));
        for (first, same, other) in [
            ("192.0.2.1:3000", "192.0.2.1:3001", "192.0.2.2:3000"),
            (
                "[2001:db8:1::1]:3000",
                "[2001:db8:1::2]:3001",
                "[2001:db8:2::1]:3000",
            ),
        ] {
            let limiter = RateLimiter::new(&public, 0);
            let issue = |source, index| {
                let mut peer = Tunn::new(
                    StaticSecret::from([99; 32]),
                    public,
                    None,
                    None,
                    index,
                    None,
                );
                let mut out = [0; 256];
                let mut challenge = [0; 64];
                let TunnResult::WriteToNetwork(init) =
                    peer.format_handshake_initiation(&mut out, false)
                else {
                    panic!("expected initiation");
                };
                let Err(TunnResult::WriteToNetwork(cookie)) =
                    limiter.verify_packet(Some(source), init, &mut challenge)
                else {
                    panic!("expected cookie challenge");
                };
                assert!(matches!(
                    peer.decapsulate(None, cookie, &mut out),
                    TunnResult::Done
                ));
                let TunnResult::WriteToNetwork(retry) =
                    peer.format_handshake_initiation(&mut out, true)
                else {
                    panic!("expected initiation with MAC2");
                };
                retry.to_vec()
            };
            let (first, same, other) = (
                first.parse().unwrap(),
                same.parse().unwrap(),
                other.parse().unwrap(),
            );
            let (initial, rebound, unrelated) = (issue(first, 1), issue(same, 2), issue(other, 3));
            let mut reply = [0; 64];
            for _ in 0..5 {
                assert!(limiter
                    .verify_packet(Some(first), &initial, &mut reply)
                    .is_ok());
            }
            assert!(matches!(
                limiter.verify_packet(Some(same), &rebound, &mut reply),
                Err(TunnResult::Err(WireGuardError::UnderLoad))
            ));
            assert!(limiter
                .verify_packet(Some(other), &unrelated, &mut reply)
                .is_ok());
            mock_instant::MockClock::advance(SOURCE_INTERVAL);
            assert!(limiter
                .verify_packet(Some(same), &rebound, &mut reply)
                .is_ok());
            assert!(matches!(
                limiter.verify_packet(Some(first), &initial, &mut reply),
                Err(TunnResult::Err(WireGuardError::UnderLoad))
            ));
        }
    }
}
