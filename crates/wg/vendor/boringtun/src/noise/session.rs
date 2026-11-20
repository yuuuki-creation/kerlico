// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::{DataHeader, PacketData};
use crate::noise::errors::WireGuardError;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};

pub struct Session {
    pub(crate) receiving_index: u32,
    sending_index: u32,
    receiver: LessSafeKey,
    sender: LessSafeKey,
    // Packet processing holds an exclusive borrow of this session.
    sending_key_counter: u64,
    receiving_key_counter: ReceivingKeyCounterValidator,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Session: {}<- ->{}",
            self.receiving_index, self.sending_index
        )
    }
}

/// Where encrypted data resides in a data packet
const DATA_OFFSET: usize = 16;
/// The overhead of the AEAD
const AEAD_SIZE: usize = 16;

// Receiving buffer constants
const WORD_SIZE: u64 = 64;
const N_WORDS: u64 = 128;
const N_BITS: u64 = WORD_SIZE * N_WORDS;
const REPLAY_WINDOW: u64 = N_BITS - WORD_SIZE;
const REJECT_AFTER_MESSAGES: u64 = u64::MAX - REPLAY_WINDOW - 1;

#[derive(Debug, Clone)]
struct ReceivingKeyCounterValidator {
    /// In order to avoid replays while allowing for some reordering of the packets, we keep a
    /// bitmap of received packets, and the value of the highest counter
    next: u64,
    /// Used to estimate packet loss
    receive_cnt: u64,
    bitmap: [u64; N_WORDS as usize],
}

impl Default for ReceivingKeyCounterValidator {
    fn default() -> Self {
        Self {
            next: 0,
            receive_cnt: 0,
            bitmap: [0; N_WORDS as usize],
        }
    }
}

impl ReceivingKeyCounterValidator {
    #[inline(always)]
    fn set_bit(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        self.bitmap[word] |= 1 << bit;
    }

    /// Returns true if bit is set, false otherwise
    #[inline(always)]
    fn check_bit(&self, idx: u64) -> bool {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        ((self.bitmap[word] >> bit) & 1) == 1
    }

    /// Returns true if the counter was not yet received, and is not too far back
    #[inline(always)]
    fn will_accept(&self, counter: u64) -> Result<(), WireGuardError> {
        if counter >= REJECT_AFTER_MESSAGES {
            return Err(WireGuardError::InvalidCounter);
        }
        if counter >= self.next {
            // As long as the counter is growing no replay took place for sure
            return Ok(());
        }
        if self.next - 1 - counter > REPLAY_WINDOW {
            // Drop if too far back
            return Err(WireGuardError::InvalidCounter);
        }
        if !self.check_bit(counter) {
            Ok(())
        } else {
            Err(WireGuardError::DuplicateCounter)
        }
    }

    /// Rejects replays before authentication and records only authenticated packets.
    #[inline(always)]
    fn authenticate<T>(
        &mut self,
        counter: u64,
        authenticate: impl FnOnce() -> Result<T, WireGuardError>,
    ) -> Result<T, WireGuardError> {
        self.will_accept(counter)?;
        let plaintext = authenticate()?;
        if counter >= self.next {
            let old_word = self.next.saturating_sub(1) / WORD_SIZE;
            let new_word = counter / WORD_SIZE;
            if new_word - old_word >= N_WORDS {
                self.bitmap.fill(0);
            } else {
                for word in old_word + 1..=new_word {
                    self.bitmap[(word % N_WORDS) as usize] = 0;
                }
            }
            self.next = counter + 1;
        }
        self.set_bit(counter);
        self.receive_cnt += 1;
        Ok(plaintext)
    }
}

impl Session {
    pub(super) fn new(
        local_index: u32,
        peer_index: u32,
        receiving_key: [u8; 32],
        sending_key: [u8; 32],
    ) -> Session {
        Session {
            receiving_index: local_index,
            sending_index: peer_index,
            receiver: LessSafeKey::new(
                UnboundKey::new(&CHACHA20_POLY1305, &receiving_key).unwrap(),
            ),
            sender: LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &sending_key).unwrap()),
            sending_key_counter: 0,
            receiving_key_counter: ReceivingKeyCounterValidator::default(),
        }
    }

    pub(super) fn local_index(&self) -> usize {
        self.receiving_index as usize
    }

    /// The plaintext is already in the data region, following the 16-byte header.
    /// dst - pre-allocated space to hold the encapsulating UDP packet to send over the network
    /// returns the size of the formatted packet
    pub(super) fn format_packet_data<'a>(
        &mut self,
        plain_len: usize,
        dst: &'a mut [u8],
    ) -> &'a mut [u8] {
        if dst.len() < plain_len + super::DATA_OVERHEAD_SZ {
            panic!("The destination buffer is too small");
        }

        let sending_key_counter = self.sending_key_counter;
        self.sending_key_counter = sending_key_counter.wrapping_add(1);

        let (message_type, rest) = dst.split_at_mut(4);
        let (receiver_index, rest) = rest.split_at_mut(4);
        let (counter, data) = rest.split_at_mut(8);

        message_type.copy_from_slice(&super::DATA.to_le_bytes());
        receiver_index.copy_from_slice(&self.sending_index.to_le_bytes());
        counter.copy_from_slice(&sending_key_counter.to_le_bytes());

        // TODO: spec requires padding to 16 bytes, but actually works fine without it
        let n = {
            let mut nonce = [0u8; 12];
            nonce[4..12].copy_from_slice(&sending_key_counter.to_le_bytes());
            self.sender
                .seal_in_place_separate_tag(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::from(&[]),
                    &mut data[..plain_len],
                )
                .map(|tag| {
                    data[plain_len..plain_len + AEAD_SIZE].copy_from_slice(tag.as_ref());
                    plain_len + AEAD_SIZE
                })
                .unwrap()
        };

        &mut dst[..DATA_OFFSET + n]
    }

    /// packet - a data packet we received from the network
    /// dst - pre-allocated space to hold the encapsulated IP packet, to send to the interface
    ///       dst will always take less space than src
    /// return the size of the encapsulated packet on success
    pub(super) fn receive_packet_data<'a>(
        &mut self,
        packet: PacketData,
        dst: &'a mut [u8],
    ) -> Result<&'a mut [u8], WireGuardError> {
        let ct_len = packet.encrypted_encapsulated_packet.len();
        if dst.len() < ct_len {
            // This is a very incorrect use of the library, therefore panic and not error
            panic!("The destination buffer is too small");
        }
        self.open_data(
            packet.header(),
            Some(packet.encrypted_encapsulated_packet),
            &mut dst[..ct_len],
        )
    }

    pub(super) fn open_data<'a>(
        &mut self,
        header: DataHeader,
        source: Option<&[u8]>,
        dst: &'a mut [u8],
    ) -> Result<&'a mut [u8], WireGuardError> {
        if header.receiver_idx != self.receiving_index {
            return Err(WireGuardError::WrongIndex);
        }
        let receiver = &self.receiver;
        self.receiving_key_counter
            .authenticate(header.counter, move || {
                let mut nonce = [0u8; 12];
                nonce[4..12].copy_from_slice(&header.counter.to_le_bytes());
                if let Some(source) = source {
                    dst.copy_from_slice(source);
                }
                receiver
                    .open_in_place(Nonce::assume_unique_for_key(nonce), Aad::from(&[]), dst)
                    .map_err(|_| WireGuardError::InvalidAeadTag)
            })
    }

    /// Returns the estimated downstream packet loss for this session
    pub(super) fn current_packet_cnt(&self) -> (u64, u64) {
        (
            self.receiving_key_counter.next,
            self.receiving_key_counter.receive_cnt,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_replay_counter() {
        let mut c: ReceivingKeyCounterValidator = Default::default();
        let verified = || Ok(());

        assert!(c.authenticate(0, verified).is_ok());
        assert!(matches!(
            c.authenticate::<()>(0, || panic!("attempted to authenticate a replay")),
            Err(WireGuardError::DuplicateCounter)
        ));
        assert!(c.authenticate(1, verified).is_ok());
        assert!(c.authenticate(1, verified).is_err());
        assert!(c.authenticate(63, verified).is_ok());
        assert!(c.authenticate(63, verified).is_err());
        assert!(c.authenticate(15, verified).is_ok());
        assert!(c.authenticate(15, verified).is_err());

        for i in 64..N_BITS + 128 {
            assert!(c.authenticate(i, verified).is_ok());
            assert!(c.authenticate(i, verified).is_err());
        }

        assert!(c.authenticate(N_BITS * 3, verified).is_ok());
        let oldest = N_BITS * 3 - REPLAY_WINDOW;
        for i in 0..oldest {
            assert!(matches!(
                c.will_accept(i),
                Err(WireGuardError::InvalidCounter)
            ));
            assert!(c.authenticate(i, verified).is_err());
        }
        for i in oldest..N_BITS * 3 {
            assert!(c.will_accept(i).is_ok());
        }
        assert!(matches!(
            c.will_accept(N_BITS * 3),
            Err(WireGuardError::DuplicateCounter)
        ));

        for i in (oldest..N_BITS * 3).rev() {
            assert!(c.authenticate(i, verified).is_ok());
            assert!(c.authenticate(i, verified).is_err());
        }

        assert!(c.authenticate(N_BITS * 3 + 70, verified).is_ok());
        assert!(c.authenticate(N_BITS * 3 + 71, verified).is_ok());
        assert!(c.authenticate(N_BITS * 3 + 72, verified).is_ok());
        assert!(c.authenticate(N_BITS * 3 + 72 + 125, verified).is_ok());
        assert!(c.authenticate(N_BITS * 3 + 63, verified).is_ok());

        assert!(c.authenticate(N_BITS * 3 + 70, verified).is_err());
        assert!(c.authenticate(N_BITS * 3 + 71, verified).is_err());
        assert!(c.authenticate(N_BITS * 3 + 72, verified).is_err());
        assert!(c.will_accept(REJECT_AFTER_MESSAGES).is_err());
        assert!(c.authenticate(u64::MAX, verified).is_err());
    }
}
