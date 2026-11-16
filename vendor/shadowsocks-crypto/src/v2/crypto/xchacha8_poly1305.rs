pub use chacha20poly1305::XChaCha8Poly1305 as CryptoXChaCha8Poly1305;

pub type XChaCha8Poly1305 = super::reduced_chacha::Reduced<CryptoXChaCha8Poly1305>;
