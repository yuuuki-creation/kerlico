use std::io::{self, Read, Write};
use std::net::TcpStream;

use subtle::ConstantTimeEq;

use super::{
    attach, hello_extensions, invalid, mask_server_record, record, sized, take, Config,
    Established, Nonce, Transition,
};

const CCS: &[u8] = &[20, 3, 3, 0, 1, 1];
pub(super) const CURVES: [u16; 3] = [29, 23, 24]; // X25519, P-256, P-384

pub(super) struct ClientHello<'a> {
    sid: &'a [u8],
    ticket: &'a [u8],
}

pub(super) fn client_hello(frame: &[u8]) -> Option<ClientHello<'_>> {
    if frame.first() != Some(&22) {
        return None;
    }
    parse_hello(frame.get(5..)?)
}

fn parse_hello(hello: &[u8]) -> Option<ClientHello<'_>> {
    if hello.get(4..6)? != [3, 3] || hello.get(38) != Some(&32) {
        return None;
    }
    let mut extensions = hello_extensions(hello)?;
    let mut ticket = &[][..];
    while !extensions.is_empty() {
        let id = take(&mut extensions, 2)?;
        let value = sized(&mut extensions, 2)?;
        if id == [0, 35] {
            ticket = value;
        }
    }
    Some(ClientHello {
        sid: hello.get(39..71)?,
        ticket,
    })
}

pub(super) fn tag_hello(
    key: &[u8; 32],
    hello: &[u8],
    shares: &[Vec<u8>],
    session: &mut [u8],
) -> bool {
    let Some(parsed) = parse_hello(hello) else {
        return false;
    };
    if session.len() != 32 || shares.len() != CURVES.len() {
        return false;
    }
    let layout: &[usize] = if parsed.ticket.is_empty() {
        &[0, 11, 22, 32]
    } else {
        &[0, 8, 16, 24, 32]
    };
    for (value, bounds) in shares
        .iter()
        .map(Vec::as_slice)
        .chain([parsed.ticket])
        .zip(layout.windows(2))
    {
        session[bounds[0]..bounds[1]]
            .copy_from_slice(&blake3::keyed_hash(key, value).as_bytes()[..bounds[1] - bounds[0]]);
    }
    true
}

impl ClientHello<'_> {
    fn proof(&self, slot: usize, candidate: &[u8], key: &[u8; 32]) -> bool {
        let layout: &[usize] = if self.ticket.is_empty() {
            &[0, 11, 22, 32]
        } else {
            &[0, 8, 16, 24, 32]
        };
        let Some((&start, &end)) = layout.get(slot).zip(layout.get(slot + 1)) else {
            return false;
        };
        bool::from(
            blake3::keyed_hash(key, candidate).as_bytes()[..end - start]
                .ct_eq(&self.sid[start..end]),
        )
    }
}

/// Reads complete TLS messages even when a target combines or fragments its handshake records.
#[derive(Default)]
pub(super) struct Messages(Vec<u8>);

impl Messages {
    pub(super) fn feed(&mut self, frame: &[u8], mut msg: impl FnMut(u8, &[u8])) -> io::Result<()> {
        if frame.first() != Some(&22) || frame.len() < 5 {
            return Err(invalid("RestLS TLS 1.2 handshake record"));
        }
        self.0.extend_from_slice(&frame[5..]);
        let mut pos = 0;
        while let Some(header) = self.0.get(pos..pos + 4) {
            let len = u32::from_be_bytes([0, header[1], header[2], header[3]]) as usize;
            if len > 512 * 1024 {
                return Err(invalid("RestLS TLS handshake message too long"));
            }
            let Some(body) = self.0.get(pos + 4..pos + 4 + len) else {
                break;
            };
            msg(header[0], body);
            pos += 4 + len;
        }
        self.0.drain(..pos);
        Ok(())
    }
}

pub(super) fn server_hello(body: &[u8]) -> Option<([u8; 32], bool)> {
    if body.get(..2)? != [3, 3] {
        return None;
    }
    let random = body.get(2..34)?.try_into().ok()?;
    let mut after = body.get(34..)?;
    sized(&mut after, 1)?;
    let cipher = u16::from_be_bytes(take(&mut after, 2)?.try_into().ok()?);
    Some((random, matches!(cipher, 0xc02b | 0xc02c | 0xc02f | 0xc030)))
}

pub(super) fn accept(
    mut client: TcpStream,
    mut target: TcpStream,
    auth: ClientHello<'_>,
    server: Vec<u8>,
    config: &Config,
    fallback: impl FnOnce(&TcpStream, &TcpStream) -> io::Result<()>,
) -> io::Result<Option<Established>> {
    let mut messages = Messages::default();
    let mut identity = None;
    let mut curve = None;
    let mut frame = server;
    let resumed = loop {
        if frame == CCS {
            break true;
        }
        if frame[0] != 22 {
            fallback(&client, &target)?;
            return Ok(None);
        }
        let mut done = false;
        messages.feed(&frame, |kind, body| match kind {
            2 => identity = server_hello(body),
            12 => {
                if let Some([3, hi, lo]) = body.get(..3) {
                    curve = CURVES
                        .iter()
                        .position(|&curve| curve == u16::from_be_bytes([*hi, *lo]));
                }
            }
            14 => done = true,
            _ => (),
        })?;
        if done {
            break false;
        }
        frame = record(&mut target)?;
        client.write_all(&frame)?;
    };
    let Some((random, gcm)) = identity else {
        fallback(&client, &target)?;
        return Ok(None);
    };
    let proof = if resumed {
        auth.proof(3, auth.ticket, &config.key)
    } else {
        curve.is_some()
    };
    if !proof {
        fallback(&client, &target)?;
        return Ok(None);
    }

    if !resumed {
        let slot = curve.expect("selected RestLS curve");
        let mut messages = Messages::default();
        let mut authenticated = false;
        loop {
            let frame = record(&mut client)?;
            target.write_all(&frame)?;
            if frame == CCS {
                if !authenticated {
                    fallback(&client, &target)?;
                    return Ok(None);
                }
                break;
            }
            if frame[0] != 22 {
                fallback(&client, &target)?;
                return Ok(None);
            }
            let mut mismatch = false;
            messages.feed(&frame, |kind, mut body| {
                if kind == 16 {
                    authenticated = sized(&mut body, 1)
                        .is_some_and(|key| body.is_empty() && auth.proof(slot, key, &config.key));
                    mismatch = !authenticated;
                }
            })?;
            if mismatch {
                fallback(&client, &target)?;
                return Ok(None);
            }
        }
        relay_finished(&mut client, &mut target)?;
        // NewSessionTicket, when present in TLS 1.2, precedes the server CCS.
        loop {
            let frame = record(&mut target)?;
            client.write_all(&frame)?;
            if frame == CCS {
                break;
            }
            if frame[0] != 22 {
                return Err(invalid("RestLS server CCS is missing"));
            }
        }
    }
    let mut finished = record(&mut target)?;
    if finished[0] != 22 || finished.len() < (if gcm { 21 } else { 13 }) {
        return Err(invalid("RestLS TLS 1.2 ServerFinished is missing"));
    }
    let sequence = gcm && finished[5..13] == [0; 8];
    mask_server_record(&mut finished, &config.key, &random, sequence);
    client.write_all(&finished)?;
    let read_finish = if resumed {
        let ccs = record(&mut client)?;
        if ccs != CCS {
            return Err(invalid("RestLS client CCS is missing"));
        }
        target.write_all(&ccs)?;
        relay_finished(&mut client, &mut target)?
    } else {
        Vec::new()
    };
    let read_nonce = if gcm {
        Nonce::ExplicitSequence
    } else {
        Nonce::Implicit
    };
    let write_nonce = if sequence {
        Nonce::ExplicitSequence
    } else {
        Nonce::Implicit
    };
    attach(
        client,
        config.clone(),
        random,
        Transition {
            read_nonce,
            write_nonce,
            read_finish,
            ..Default::default()
        },
    )
    .map(Some)
}

fn relay_finished(client: &mut impl Read, target: &mut impl Write) -> io::Result<Vec<u8>> {
    let finished = record(client)?;
    target.write_all(&finished)?;
    if finished[0] != 22 {
        return Err(invalid("RestLS TLS 1.2 ClientFinished is missing"));
    }
    Ok(finished)
}
