use super::{invalid_record, seal_record_padded, server_share, Suite, Traffic};
use std::io::{self, Read};

/// xtls/reality reads at most this many bytes of the target's answer (`size` in `tls.go`).
const LIMIT: usize = 17 * 1024;

/// How `Server` in xtls/reality ends an authenticated connection whose target answer cannot be used.
#[derive(Debug, Eq, PartialEq)]
pub enum RealityTargetFailure {
    /// The target closed, errored or timed out, or sent a malformed record after a valid
    /// ServerHello. xtls/reality closes the client.
    Close,
    /// The target's first bytes are not a usable ServerHello. xtls/reality writes the bytes
    /// it read to the client and relays both directions from then on.
    Forward,
}

/// The target's actual first TLS flight, before REALITY replaces authenticated data.
pub struct RealityTargetShape {
    hello: Vec<u8>,
    original: Vec<u8>,
    lengths: Vec<usize>,
    ticket: Option<usize>,
    pub(super) suite: Suite,
    pub(super) group: u16,
}

impl RealityTargetShape {
    /// Follows the read loop of `Server` in xtls/reality: the lengths of the ServerHello, the
    /// ChangeCipherSpec and the encrypted handshake records, then the length of a record that
    /// has already arrived behind the Finished (the target's NewSessionTicket).
    ///
    /// `captured` receives every byte read, including bytes consumed before a failure. On
    /// `Forward` the owner writes them to the client before relaying.
    pub fn read_from<R: Read>(
        reader: &mut R,
        client_hello: &[u8],
        captured: &mut Vec<u8>,
    ) -> Result<Self, RealityTargetFailure> {
        use RealityTargetFailure::{Close, Forward};
        let session = client_hello.get(44..76).ok_or(Close)?;
        let start = captured.len();
        let mut chunk = vec![0; LIMIT];
        // Total record lengths by slot: ServerHello, ChangeCipherSpec, EncryptedExtensions,
        // Certificate, CertificateVerify, Finished, then the NewSessionTicket.
        let mut lengths: Vec<usize> = Vec::new();
        let mut hello = Vec::new();
        let mut parsed = None;
        let mut ticket = None;
        // Bytes of the slots recorded so far, and the length of the record being waited for.
        let mut taken = 0;
        let mut pending = 0;
        'read: loop {
            let count = loop {
                match reader.read(&mut chunk) {
                    Ok(0) => return Err(Close),
                    Ok(count) => break count,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(_) => return Err(Close),
                }
            };
            captured.extend_from_slice(&chunk[..count]);
            let saved = &captured[start..];
            // Until the ServerHello is recorded a bad answer is relayed, afterwards the client is closed.
            let bad = |lengths: &[usize]| if lengths.is_empty() { Forward } else { Close };
            // xtls/reality counts the bytes it has not recorded yet, not everything it has read.
            if saved.len() - taken > LIMIT {
                return Err(bad(&lengths));
            }
            loop {
                let slot = lengths.len();
                let rest = &saved[taken..];
                if slot == 6 && rest.is_empty() {
                    break 'read;
                }
                if pending == 0 && rest.len() > 5 {
                    if rest[1..3] != [3, 3]
                        || (slot == 0 && (rest[0] != 22 || rest[5] != 2))
                        || (slot == 1 && (rest[0] != 20 || rest[5] != 1))
                        || (slot > 1 && rest[0] != 23)
                    {
                        return Err(bad(&lengths));
                    }
                    pending = 5 + u16::from_be_bytes([rest[3], rest[4]]) as usize;
                }
                if pending > LIMIT || (slot == 1 && pending > 0 && pending != 6) {
                    return Err(bad(&lengths));
                }
                if slot == 2 && pending > 512 {
                    // The target's handshake travels in one record; REALITY pads its own to that.
                    lengths.push(pending);
                    break 'read;
                }
                if slot == 6 && pending > 0 {
                    ticket = Some(pending);
                    break 'read;
                }
                if pending == 0 || rest.len() < pending {
                    continue 'read;
                }
                if slot == 0 {
                    let (suite, group, share) =
                        server_share(&rest[5..pending], session).ok_or(Forward)?;
                    if !matches!((group, share.len()), (0x001d, 32) | (0x11ec, 1120)) {
                        return Err(Forward);
                    }
                    hello = rest[5..pending].to_vec();
                    parsed = Some((suite, group));
                }
                lengths.push(pending);
                taken += pending;
                pending = 0;
            }
        }
        let (suite, group) = parsed.ok_or(Close)?;
        Ok(Self {
            hello,
            original: captured[start..].to_vec(),
            lengths,
            ticket,
            suite,
            group,
        })
    }

    pub fn original_flight(&self) -> &[u8] {
        &self.original
    }
    pub fn record_lengths(&self) -> &[usize] {
        &self.lengths
    }

    /// Total length of the record behind the target's Finished, when the target's handshake used
    /// separate records and that record had already arrived.
    pub fn ticket_length(&self) -> Option<usize> {
        self.ticket
    }

    pub(super) fn replace_share(&self, session: &[u8], new_share: &[u8]) -> io::Result<Vec<u8>> {
        let (_, _, old_share) = server_share(&self.hello, session).ok_or_else(invalid_record)?;
        if old_share.len() != new_share.len() {
            return Err(invalid_record());
        }
        // The validated parser returned a slice of this public TLS message.
        let start = old_share.as_ptr() as usize - self.hello.as_ptr() as usize;
        let mut hello = self.hello.clone();
        hello[start..start + new_share.len()].copy_from_slice(new_share);
        Ok(hello)
    }

    pub(super) fn seal_messages(
        &self,
        keys: &Traffic,
        messages: &[Vec<u8>; 4],
    ) -> io::Result<Vec<u8>> {
        let combined;
        let messages: Vec<&[u8]> = if self.lengths.len() == 3 {
            combined = messages.concat();
            vec![&combined]
        } else {
            messages.iter().map(Vec::as_slice).collect()
        };
        let mut result = Vec::new();
        for (sequence, (&length, message)) in self.lengths[2..].iter().zip(messages).enumerate() {
            let padding = length.checked_sub(message.len() + 22).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "REALITY target record is too small for authentication",
                )
            })?;
            result.extend(seal_record_padded(
                keys,
                sequence as u64,
                22,
                message,
                padding,
            ));
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The target's answer to `offer`, produced by a rustls server that sends a large certificate.
    fn target_flight(offer: &crate::RealityOffer) -> Vec<u8> {
        let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        params
            .custom_extensions
            .push(rcgen::CustomExtension::from_oid_content(
                &[1, 3, 6, 1, 4, 1, 32473, 2],
                vec![0; 4096],
            ));
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let config =
            crate::server_config(&cert.pem(), &key.serialize_pem(), &["h2".into()]).unwrap();
        let mut tls = rustls::ServerConnection::new(config).unwrap();
        tls.read_tls(&mut offer.record.as_slice()).unwrap();
        tls.process_new_packets().unwrap();
        let mut flight = Vec::new();
        while tls.wants_write() {
            tls.write_tls(&mut flight).unwrap();
        }
        flight
    }

    fn offer() -> ([u8; 32], [u8; 32], crate::RealityOffer) {
        let (private, public) = crate::reality_pair();
        let offer =
            crate::reality_offer_fingerprint(&public, &[0; 8], "localhost", &[], "chrome").unwrap();
        (private, public, offer)
    }

    /// Splits `bytes` into the complete TLS records it holds, as total lengths.
    fn record_lengths(mut bytes: &[u8]) -> Vec<usize> {
        let mut lengths = Vec::new();
        while !bytes.is_empty() {
            let length = 5 + u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
            lengths.push(length);
            bytes = &bytes[length..];
        }
        lengths
    }

    /// An application-data record of the given total length whose content is not decrypted.
    fn filler_record(length: usize) -> Vec<u8> {
        let mut record = vec![23, 3, 3];
        record.extend_from_slice(&((length - 5) as u16).to_be_bytes());
        record.resize(length, 0x5a);
        record
    }

    #[test]
    fn target_flight_lengths_and_hello_are_preserved_with_valid_authentication() {
        let (private, public, offer) = offer();
        let flight = target_flight(&offer);
        let mut captured = Vec::new();
        let shape =
            RealityTargetShape::read_from(&mut flight.as_slice(), &offer.record, &mut captured)
                .unwrap();
        assert_eq!(shape.original_flight(), captured);
        assert_eq!(shape.ticket_length(), None);
        let policy = crate::RealityPolicy {
            short_ids: vec![[0; 8]],
            ..Default::default()
        };
        let actual = super::super::server_flight_with_target(
            &offer.record,
            &private,
            &policy,
            &["h2"],
            None,
            &shape,
        )
        .unwrap();
        assert_eq!(record_lengths(&actual.flight), shape.record_lengths());
        let (_, _, finished, protocol) = crate::read_server_flight_for_offer(
            &mut actual.flight.as_slice(),
            &offer,
            &public,
            None,
        )
        .unwrap();
        assert_eq!(protocol.as_deref(), Some(b"h2".as_slice()));
        crate::read_client_finished(&mut finished.as_slice(), &actual.handshake, &actual.expect)
            .unwrap();
        let mut malformed = Vec::new();
        assert_eq!(
            RealityTargetShape::read_from(&mut &flight[..10], &offer.record, &mut malformed).err(),
            Some(RealityTargetFailure::Close),
            "a target that stops after a partial first record closes the client"
        );
        assert_eq!(malformed, flight[..10]);
    }

    #[test]
    fn a_record_that_already_followed_the_finished_is_recorded() {
        let (private, public, offer) = offer();
        // The target's ServerHello and ChangeCipherSpec are real; its encrypted handshake is four
        // separate records, as OpenSSL and Go send them, and a ticket record follows the Finished.
        let real = target_flight(&offer);
        let head = record_lengths(&real)[0] + 6;
        let mut flight = real[..head].to_vec();
        for length in [60, 700, 120, 80, 251] {
            flight.extend(filler_record(length));
        }
        let shape =
            RealityTargetShape::read_from(&mut flight.as_slice(), &offer.record, &mut Vec::new())
                .unwrap();
        assert_eq!(shape.ticket_length(), Some(251));
        let policy = crate::RealityPolicy {
            short_ids: vec![[0; 8]],
            ..Default::default()
        };
        let actual = super::super::server_flight_with_target(
            &offer.record,
            &private,
            &policy,
            &["h2"],
            None,
            &shape,
        )
        .unwrap();
        assert_eq!(
            record_lengths(&actual.flight),
            [record_lengths(&real)[0], 6, 60, 700, 120, 80, 251],
            "the server answers with a record as long as the ticket"
        );
        assert_eq!(actual.server_sequence(), 1);
        // The stand-in is empty application data sealed with the server's application key.
        let (_, server_application) = actual.application_keys();
        let ticket = &actual.flight[actual.flight.len() - 251..];
        let plain = super::super::open_record(&server_application, 0, ticket).unwrap();
        assert_eq!(super::super::split_inner(&plain), Some((23, &[][..])));
        // The client still completes the handshake and reads that record as empty data.
        let (_, _, finished, _) = crate::read_server_flight_for_offer(
            &mut actual.flight.as_slice(),
            &offer,
            &public,
            None,
        )
        .unwrap();
        crate::read_client_finished(&mut finished.as_slice(), &actual.handshake, &actual.expect)
            .unwrap();
    }

    #[test]
    fn a_coalesced_handshake_has_no_ticket_slot() {
        let (_, _, offer) = offer();
        let mut flight = target_flight(&offer);
        assert_eq!(record_lengths(&flight).len(), 3, "rustls sends one large handshake record");
        flight.extend(filler_record(251));
        let shape =
            RealityTargetShape::read_from(&mut flight.as_slice(), &offer.record, &mut Vec::new())
                .unwrap();
        assert_eq!(shape.record_lengths().len(), 3);
        assert_eq!(shape.ticket_length(), None);
    }

    #[test]
    fn a_target_without_a_ticket_in_the_flight_records_none() {
        let (_, _, offer) = offer();
        let flight = target_flight(&offer);
        let shape =
            RealityTargetShape::read_from(&mut flight.as_slice(), &offer.record, &mut Vec::new())
                .unwrap();
        assert_eq!(shape.ticket_length(), None);
    }

    #[test]
    fn an_unusable_server_hello_is_relayed_and_a_later_bad_record_closes() {
        let (_, _, offer) = offer();
        let flight = target_flight(&offer);
        // Not TLS at all: relayed, with every byte the target sent.
        let mut captured = Vec::new();
        let plain = b"HTTP/1.1 400 Bad Request\r\n\r\n";
        assert_eq!(
            RealityTargetShape::read_from(&mut plain.as_slice(), &offer.record, &mut captured).err(),
            Some(RealityTargetFailure::Forward)
        );
        assert_eq!(captured, plain);
        // An alert instead of a ServerHello is relayed too.
        let mut captured = Vec::new();
        let alert = [21, 3, 3, 0, 2, 2, 40];
        assert_eq!(
            RealityTargetShape::read_from(&mut alert.as_slice(), &offer.record, &mut captured).err(),
            Some(RealityTargetFailure::Forward)
        );
        assert_eq!(captured, alert);
        // A target that sends nothing, or stops inside the ServerHello, closes the client.
        let mut captured = Vec::new();
        assert_eq!(
            RealityTargetShape::read_from(&mut io::empty(), &offer.record, &mut captured).err(),
            Some(RealityTargetFailure::Close)
        );
        // A valid ServerHello followed by something other than a ChangeCipherSpec closes the client.
        let hello_len = record_lengths(&flight)[0];
        let mut broken = flight[..hello_len].to_vec();
        broken.extend_from_slice(&[22, 3, 3, 0, 2, 1, 1]);
        assert_eq!(
            RealityTargetShape::read_from(&mut broken.as_slice(), &offer.record, &mut Vec::new())
                .err(),
            Some(RealityTargetFailure::Close)
        );
    }
}
