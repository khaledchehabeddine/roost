use std::fmt;

#[derive(Debug)]
pub enum CryptoError {
    HkdfExpand,
    InvalidHmacKey,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HkdfExpand => write!(f, "HKDF-SHA256 expand exceeded output limit"),
            Self::InvalidHmacKey => write!(f, "HMAC-SHA256 rejected the provided key"),
        }
    }
}

impl std::error::Error for CryptoError {}
