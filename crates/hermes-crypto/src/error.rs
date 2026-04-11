use std::fmt;

#[derive(Debug)]
pub enum CryptoError {
    HkdfExpand,
    InvalidHmacKey,
    MaxSkipExceeded,
    InvalidState(&'static str),
    Aead,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HkdfExpand => write!(f, "HKDF-SHA256 expand exceeded output limit"),
            Self::InvalidHmacKey => write!(f, "HMAC-SHA256 rejected the provided key"),
            Self::MaxSkipExceeded => write!(
                f,
                "requested message skip exceeds MAX_SKIP limit of 100"
            ),
            Self::InvalidState(context) => {
                write!(f, "ratchet state invariant violated: {context}")
            }
            Self::Aead => write!(f, "XChaCha20-Poly1305 encryption or decryption failed"),
        }
    }
}

impl std::error::Error for CryptoError {}
