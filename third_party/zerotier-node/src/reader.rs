// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// (c) ZeroTier, Inc.
// https://www.zerotier.com/
//
// Translated to Rust from ZeroTierOne tag 1.16.2: node/Buffer.hpp (bounds-checked big-endian reads).

pub(crate) struct Reader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, position: 0 }
    }
    pub(crate) fn position(&self) -> usize {
        self.position
    }
    pub(crate) fn remaining(&self) -> usize {
        self.data.len() - self.position
    }
    pub(crate) fn rest(&self) -> &'a [u8] {
        &self.data[self.position..]
    }
    pub(crate) fn skip(&mut self, count: usize) -> Option<()> {
        self.bytes(count).map(|_| ())
    }
    pub(crate) fn bytes(&mut self, count: usize) -> Option<&'a [u8]> {
        let end = self.position.checked_add(count)?;
        let value = self.data.get(self.position..end)?;
        self.position = end;
        Some(value)
    }
    pub(crate) fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.bytes(N)?.try_into().ok()
    }
    pub(crate) fn u8(&mut self) -> Option<u8> {
        Some(self.array::<1>()?[0])
    }
    pub(crate) fn u16(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes(self.array()?))
    }
    pub(crate) fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.array()?))
    }
    pub(crate) fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.array()?))
    }
}
