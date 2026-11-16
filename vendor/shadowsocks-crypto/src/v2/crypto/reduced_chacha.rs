//! SIP022 reduced-round ChaCha with RustCrypto's existing AEAD types.

use chacha20poly1305::aead::{array::typenum::Unsigned, AeadInOut, Key, KeyInit, Nonce, Tag};

pub type ChaCha12Poly1305 = Reduced<chacha20poly1305::ChaCha12Poly1305>;
pub type XChaCha12Poly1305 = Reduced<chacha20poly1305::XChaCha12Poly1305>;

pub struct Reduced<A>(A);

impl<A: AeadInOut + KeyInit> Reduced<A> {
    pub fn new(key: &[u8]) -> Self {
        Self(A::new(&Key::<A>::try_from(key).expect("ChaCha key")))
    }

    pub fn key_size() -> usize {
        A::KeySize::to_usize()
    }

    pub fn nonce_size() -> usize {
        A::NonceSize::to_usize()
    }

    pub fn tag_size() -> usize {
        A::TagSize::to_usize()
    }

    pub fn encrypt(&self, nonce: &[u8], packet: &mut [u8]) {
        let nonce = Nonce::<A>::try_from(nonce).expect("ChaCha nonce");
        let (payload, tag) = packet.split_at_mut(packet.len() - Self::tag_size());
        let auth = self
            .0
            .encrypt_inout_detached(&nonce, &[], payload.into())
            .expect("ChaCha encrypt");
        tag.copy_from_slice(auth.as_slice());
    }

    pub fn decrypt(&self, nonce: &[u8], packet: &mut [u8]) -> bool {
        let Ok(nonce) = Nonce::<A>::try_from(nonce) else {
            return false;
        };
        let Some(len) = packet.len().checked_sub(Self::tag_size()) else {
            return false;
        };
        let (payload, tag) = packet.split_at_mut(len);
        let Ok(tag) = Tag::<A>::try_from(&*tag) else {
            return false;
        };
        self.0
            .decrypt_inout_detached(&nonce, &[], payload.into(), &tag)
            .is_ok()
    }
}
