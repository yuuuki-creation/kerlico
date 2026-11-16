pub use chacha20poly1305::ChaCha8Poly1305 as CryptoChaCha8Poly1305;

pub type ChaCha8Poly1305 = super::reduced_chacha::Reduced<CryptoChaCha8Poly1305>;
