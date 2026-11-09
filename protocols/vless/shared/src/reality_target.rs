use super::{invalid_record, seal_record_padded, server_share, Suite, Traffic};
use std::io::{self, Read};

/// The target's actual first TLS flight, before REALITY replaces authenticated data.
pub struct RealityTargetShape {
    hello: Vec<u8>,
    original: Vec<u8>,
    lengths: Vec<usize>,
    pub(super) suite: Suite,
    pub(super) group: u16,
}

impl RealityTargetShape {
    /// `captured` receives every byte read, including bytes consumed before an error.
    /// The owner can prefix them to the target stream when it chooses fallback.
    pub fn read_from<R: Read>(
        reader: &mut R,
        client_hello: &[u8],
        captured: &mut Vec<u8>,
    ) -> io::Result<Self> {
        let session = client_hello.get(44..76).ok_or_else(invalid_record)?;
        let start = captured.len();
        let hello = read_record(reader, captured)?;
        if hello[0] != 22 || hello.get(5) != Some(&2) {
            return Err(invalid_record());
        }
        let (suite, group, share) =
            server_share(&hello[5..], session).ok_or_else(invalid_record)?;
        if !matches!((group, share.len()), (0x001d, 32) | (0x11ec, 1120)) {
            return Err(invalid_record());
        }
        let ccs = read_record(reader, captured)?;
        if ccs != [20, 3, 3, 0, 1, 1] {
            return Err(invalid_record());
        }
        let first = read_record(reader, captured)?;
        if first[0] != 23 {
            return Err(invalid_record());
        }
        let mut lengths = vec![hello.len(), ccs.len(), first.len()];
        if first.len() <= 512 {
            for _ in 0..3 {
                let record = read_record(reader, captured)?;
                if record[0] != 23 {
                    return Err(invalid_record());
                }
                lengths.push(record.len());
            }
        }
        Ok(Self {
            hello: hello[5..].to_vec(),
            original: captured[start..].to_vec(),
            lengths,
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

fn read_record<R: Read>(reader: &mut R, captured: &mut Vec<u8>) -> io::Result<Vec<u8>> {
    let start = captured.len();
    read_bytes(reader, captured, 5)?;
    let header = &captured[start..];
    let length = u16::from_be_bytes([header[3], header[4]]) as usize;
    if header[1..3] != [3, 3] || length == 0 || length + 5 > 17 * 1024 {
        return Err(invalid_record());
    }
    read_bytes(reader, captured, length)?;
    Ok(captured[start..].to_vec())
}

fn read_bytes<R: Read>(reader: &mut R, captured: &mut Vec<u8>, count: usize) -> io::Result<()> {
    let end = captured.len() + count;
    let mut buffer = [0; 4096];
    while captured.len() < end {
        let count = (end - captured.len()).min(buffer.len());
        match reader.read(&mut buffer[..count]) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => captured.extend_from_slice(&buffer[..n]),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn target_flight_lengths_and_hello_are_preserved_with_valid_authentication() {
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
        let (private, public) = crate::reality_pair();
        let offer =
            crate::reality_offer_fingerprint(&public, &[0; 8], "localhost", &[], "chrome").unwrap();
        let mut tls = rustls::ServerConnection::new(config).unwrap();
        tls.read_tls(&mut offer.record.as_slice()).unwrap();
        tls.process_new_packets().unwrap();
        let mut flight = Vec::new();
        while tls.wants_write() {
            tls.write_tls(&mut flight).unwrap();
        }
        let mut captured = Vec::new();
        let shape =
            RealityTargetShape::read_from(&mut flight.as_slice(), &offer.record, &mut captured)
                .unwrap();
        assert_eq!(shape.original_flight(), captured);
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
        let mut bytes = actual.flight.as_slice();
        let mut lengths = Vec::new();
        while !bytes.is_empty() {
            let length = 5 + u16::from_be_bytes([bytes[3], bytes[4]]) as usize;
            lengths.push(length);
            bytes = &bytes[length..];
        }
        assert_eq!(lengths, shape.record_lengths());
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
        assert!(
            RealityTargetShape::read_from(&mut &flight[..10], &offer.record, &mut malformed)
                .is_err()
        );
        assert_eq!(malformed, flight[..10]);
    }
}
