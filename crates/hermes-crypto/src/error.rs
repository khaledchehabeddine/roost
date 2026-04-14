use std::fmt;

#[derive(Debug)]
pub enum CryptoError {
    Aead,
    HkdfExpand,
    InvalidHmacKey,
    InvalidState(&'static str),
    MaxSkipExceeded,
    MaxSkippedKeysExceeded,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aead => write!(f, "XChaCha20-Poly1305 encryption or decryption failed"),
            Self::HkdfExpand => write!(f, "HKDF-SHA256 expand exceeded output limit"),
            Self::InvalidHmacKey => write!(f, "HMAC-SHA256 rejected the provided key"),
            Self::InvalidState(context) => {
                write!(f, "ratchet state invariant violated: {context}")
            }
            Self::MaxSkipExceeded => write!(f, "requested message skip exceeds ratchet step limit"),
            Self::MaxSkippedKeysExceeded => {
                write!(f, "cached skipped message keys total exceeds global limit")
            }
        }
    }
}

impl std::error::Error for CryptoError {}
