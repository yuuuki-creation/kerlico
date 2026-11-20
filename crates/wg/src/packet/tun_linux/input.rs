//! Split one TUN superpacket into the initialized slots in which it will be sealed.
use super::{multishot::Multishot, SendBatch};
use std::io;
use std::task::{ready, Context, Poll};
use tun_rs::{AsyncDevice, VirtioNetHdr, VIRTIO_NET_HDR_LEN};

const HEAD: usize = 16;
const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;
const OVERFLOW_BYTES: usize = 8 << 20;
const RAW_CAPACITY: usize = 65536 + VIRTIO_NET_HDR_LEN;

pub(super) struct Input {
    raw: Vec<u8>,
    sizes: Vec<usize>,
    next: usize,
    start: usize,
    stride: usize,
}
pub(super) struct Slot {
    pub start: usize,
    pub stride: usize,
    pub ip_len: usize,
}
impl Input {
    pub(super) fn new() -> Self {
        Self {
            raw: if cfg!(test) {
                vec![0; RAW_CAPACITY]
            } else {
                Vec::new()
            },
            sizes: Vec::new(),
            next: 0,
            start: 0,
            stride: 0,
        }
    }
    pub(super) fn discard(&mut self) {
        self.sizes.clear();
        self.next = 0;
    }
    pub(super) fn poll_slot(
        &mut self,
        cx: &mut Context<'_>,
        tun: &AsyncDevice,
        reads: &mut Option<Multishot>,
        batches: &mut SendBatch,
        mtu: usize,
    ) -> Poll<io::Result<Option<Slot>>> {
        if self.next == self.sizes.len() {
            let mut prepared = false;
            if let Some(reader) = reads.as_mut() {
                match ready!(reader.poll_packet(cx, |raw| {
                    self.prepare_slice(raw, tun.tcp_gso(), batches, mtu)
                })) {
                    Ok(result) => {
                        result?;
                        prepared = true;
                    }
                    Err(error)
                        if matches!(
                            error.raw_os_error(),
                            Some(libc::EINVAL | libc::ENOSYS | libc::EOPNOTSUPP | libc::EPERM)
                        ) =>
                    {
                        *reads = None;
                    }
                    Err(error) => return Poll::Ready(Err(error)),
                }
            }
            if !prepared {
                self.raw.resize(RAW_CAPACITY, 0);
                let n = ready!(tun.poll_recv(cx, &mut self.raw))?;
                if n == 0 {
                    return Poll::Ready(Ok(None));
                }
                self.prepare(n, tun.tcp_gso(), batches, mtu)?;
            }
            debug_assert!(!self.sizes.is_empty());
        }
        let index = self.next;
        self.next += 1;
        Poll::Ready(Ok(Some(Slot {
            start: self.start + index * self.stride,
            stride: self.stride,
            ip_len: self.sizes[index],
        })))
    }
    fn prepare(
        &mut self,
        len: usize,
        with_header: bool,
        batches: &mut SendBatch,
        mtu: usize,
    ) -> io::Result<()> {
        let mut raw = std::mem::take(&mut self.raw);
        let result = self.prepare_slice(&mut raw[..len], with_header, batches, mtu);
        self.raw = raw;
        result
    }

    fn prepare_slice(
        &mut self,
        raw: &mut [u8],
        with_header: bool,
        batches: &mut SendBatch,
        mtu: usize,
    ) -> io::Result<()> {
        let (mut hdr, ip) = if with_header {
            let (header, ip) = raw
                .split_at_mut_checked(VIRTIO_NET_HDR_LEN)
                .ok_or_else(invalid)?;
            (VirtioNetHdr::decode(header)?, ip)
        } else {
            (VirtioNetHdr::default(), raw)
        };
        if ip.is_empty() {
            return Err(invalid());
        }
        self.next = 0;
        if hdr.gso_type != 0 {
            let is_v6 = match ip[0] >> 4 {
                4 => false,
                6 => true,
                _ => return Err(invalid()),
            };
            let transport = usize::from(hdr.csum_start);
            // The forwarded skb can report its first full fragment as hdr_len. Derive the
            // transport header size from the actual packet, as tun-rs does for recv_multiple.
            let transport_len = match hdr.gso_type & !0x80 {
                tun_rs::VIRTIO_NET_HDR_GSO_TCPV4 | tun_rs::VIRTIO_NET_HDR_GSO_TCPV6 => {
                    let n = usize::from(*ip.get(transport + 12).ok_or_else(invalid)? >> 4) * 4;
                    if !(20..=60).contains(&n) {
                        return Err(invalid());
                    }
                    n
                }
                tun_rs::VIRTIO_NET_HDR_GSO_UDP_L4 => 8,
                _ => return Err(invalid()),
            };
            let header_len = transport + transport_len;
            hdr.hdr_len = header_len.try_into().map_err(|_| invalid())?;
            let data_len = ip.len().checked_sub(header_len).ok_or_else(invalid)?;
            let split = usize::from(hdr.gso_size);
            if split == 0 {
                return Err(invalid());
            }
            let count = data_len.div_ceil(split);
            let largest = header_len + data_len.min(split);
            if count
                .saturating_sub(tun_rs::IDEAL_BATCH_SIZE)
                .saturating_mul(largest)
                > OVERFLOW_BYTES
            {
                return Err(invalid());
            }
            self.stride = stride(largest, mtu);
            self.sizes.resize(count, 0);
            let (start, bytes) = batches.reserve_tun(self.stride * count);
            self.start = start;
            let mut slots: Vec<_> = bytes.chunks_exact_mut(self.stride).collect();
            let n = tun_rs::gso_split(ip, hdr, &mut slots, &mut self.sizes, HEAD, is_v6)?;
            self.sizes.truncate(n);
            if n != 0 {
                return Ok(());
            }
        }
        if hdr.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM != 0 {
            let first = usize::from(hdr.csum_start);
            let i = first + usize::from(hdr.csum_offset);
            let field: &mut [u8; 2] = ip
                .get_mut(i..i + 2)
                .ok_or_else(invalid)?
                .try_into()
                .unwrap();
            let pseudo = u16::from_be_bytes(*field);
            *field = [0; 2];
            let checksum = !tun_rs::checksum(&ip[first..], u64::from(pseudo));
            ip[i..i + 2].copy_from_slice(&checksum.to_be_bytes());
        }
        self.stride = stride(ip.len(), mtu);
        let (start, slot) = batches.reserve_tun(self.stride);
        self.start = start;
        slot[HEAD..HEAD + ip.len()].copy_from_slice(ip);
        self.sizes.clear();
        self.sizes.push(ip.len());

        Ok(())
    }
}
fn stride(n: usize, mtu: usize) -> usize {
    let padded = if n <= mtu {
        n.next_multiple_of(16).min(mtu)
    } else {
        n
    };
    (padded + 32).max(148)
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid TUN segmentation metadata",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn header_only_tcp_is_delivered_and_does_not_end_the_tun_reader() {
        let mut input = Input::new();
        let mut batches = SendBatch::default();
        let mut packet = [0u8; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&40u16.to_be_bytes());
        packet[9] = 6;
        packet[32] = 0x50;
        packet[33] = 0x10;
        let mut header = [0; VIRTIO_NET_HDR_LEN];
        header[1] = tun_rs::VIRTIO_NET_HDR_GSO_TCPV4;
        header[2..4].copy_from_slice(&40u16.to_ne_bytes());
        header[4..6].copy_from_slice(&1100u16.to_ne_bytes());
        header[6..8].copy_from_slice(&20u16.to_ne_bytes());
        header[8..10].copy_from_slice(&16u16.to_ne_bytes());
        input.raw[..header.len()].copy_from_slice(&header);
        input.raw[header.len()..header.len() + packet.len()].copy_from_slice(&packet);
        input
            .prepare(header.len() + packet.len(), true, &mut batches, 1200)
            .unwrap();
        assert_eq!(input.sizes, [40]);
        let (_, slot) = batches.reserve_tun(input.stride);
        assert_eq!(&slot[HEAD..HEAD + 40], &packet);
    }
    #[test]
    fn tcp_gso_uses_wire_slots_and_accepts_a_forwarded_header_length() {
        let mut input = Input::new();
        let mut batches = SendBatch::default();
        let mut ip = vec![0u8; 40 + 2 * 1100 + 83];
        ip[0] = 0x45;
        ip[9] = 6;
        ip[12..20].copy_from_slice(&[192, 0, 2, 1, 192, 0, 2, 2]);
        ip[32] = 0x50;
        for (i, b) in ip[40..].iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }
        let mut meta = [0u8; VIRTIO_NET_HDR_LEN];
        meta[0] = 1;
        meta[1] = tun_rs::VIRTIO_NET_HDR_GSO_TCPV4;
        meta[2..4].copy_from_slice(&(ip.len() as u16).to_ne_bytes());
        meta[4..6].copy_from_slice(&1100u16.to_ne_bytes());
        meta[6..8].copy_from_slice(&20u16.to_ne_bytes());
        meta[8..10].copy_from_slice(&16u16.to_ne_bytes());
        input.raw[..meta.len()].copy_from_slice(&meta);
        input.raw[meta.len()..meta.len() + ip.len()].copy_from_slice(&ip);
        input
            .prepare(meta.len() + ip.len(), true, &mut batches, 1200)
            .unwrap();
        assert_eq!(input.sizes, [1140, 1140, 123]);
        let step = input.stride;
        let (_, slots) = batches.reserve_tun(3 * step);
        let mut all = Vec::new();
        for (i, s) in slots.chunks_exact(step).enumerate() {
            let frame = &s[HEAD..HEAD + input.sizes[i]];
            assert_eq!(
                usize::from(u16::from_be_bytes(frame[2..4].try_into().unwrap())),
                frame.len()
            );
            assert_eq!(
                u32::from_be_bytes(frame[24..28].try_into().unwrap()),
                (1100 * i) as u32
            );
            all.extend_from_slice(&frame[40..]);
        }
        assert_eq!(all, &ip[40..]);
    }
    #[test]
    fn udp_v6_segments_preserve_extension_headers_payload_and_checksum() {
        let mut input = Input::new();
        let mut batch = SendBatch::default();
        let payload: Vec<u8> = (0..733).map(|n| (n % 251) as u8).collect();
        let mut ip = vec![0u8; 56 + payload.len()];
        ip[0] = 0x60;
        ip[4..6].copy_from_slice(&((16 + payload.len()) as u16).to_be_bytes());
        ip[6] = 60; // IPv6 destination options precede UDP.
        ip[7] = 64;
        ip[8..24].copy_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
        ip[24..40].copy_from_slice(
            &"2001:db8::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        ip[40] = 17;
        ip[48..50].copy_from_slice(&5123u16.to_be_bytes());
        ip[50..52].copy_from_slice(&8241u16.to_be_bytes());
        ip[52..54].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        ip[56..].copy_from_slice(&payload);
        let mut header = [0; VIRTIO_NET_HDR_LEN];
        header[0] = VIRTIO_NET_HDR_F_NEEDS_CSUM;
        header[1] = tun_rs::VIRTIO_NET_HDR_GSO_UDP_L4;
        header[2..4].copy_from_slice(&56u16.to_ne_bytes());
        header[4..6].copy_from_slice(&350u16.to_ne_bytes());
        header[6..8].copy_from_slice(&48u16.to_ne_bytes());
        header[8..10].copy_from_slice(&6u16.to_ne_bytes());
        input.raw[..header.len()].copy_from_slice(&header);
        input.raw[header.len()..header.len() + ip.len()].copy_from_slice(&ip);
        input
            .prepare(header.len() + ip.len(), true, &mut batch, 1200)
            .unwrap();
        assert_eq!(input.sizes, [406, 406, 89]);
        let (_, slots) = batch.reserve_tun(input.stride * 3);
        let mut all = Vec::new();
        for (slot, &len) in slots.chunks_exact(input.stride).zip(&input.sizes) {
            let packet = &slot[HEAD..HEAD + len];
            let udp = &packet[48..];
            assert_eq!(&packet[40..52], &ip[40..52]);
            assert_eq!(
                usize::from(u16::from_be_bytes([packet[4], packet[5]])),
                len - 40
            );
            assert_eq!(usize::from(u16::from_be_bytes([udp[4], udp[5]])), udp.len());
            let mut covered = packet[8..40].to_vec();
            covered.extend_from_slice(&(udp.len() as u32).to_be_bytes());
            covered.extend_from_slice(&[0, 0, 0, 17]);
            covered.extend_from_slice(udp);
            covered.push(0);
            let mut sum: u32 = covered
                .chunks_exact(2)
                .map(|p| u32::from(u16::from_be_bytes([p[0], p[1]])))
                .sum();
            while sum >> 16 != 0 {
                sum = (sum & 0xffff) + (sum >> 16);
            }
            assert_eq!(sum, 0xffff);
            all.extend_from_slice(&udp[8..]);
        }
        assert_eq!(all, payload);
    }
}
