use std::fmt;

/// Errors that can occur during cryptographic operations.
#[derive(Debug)]
pub enum CryptoError {
    /// HKDF expansion failed (e.g. requested output length exceeded the algorithm limit).
    HkdfExpand,
    /// HMAC key was rejected (should never occur with SHA-256, which accepts any key length).
    InvalidHmacKey,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HkdfExpand => write!(f, "HKDF-SHA256 expansion failed: output length exceeded algorithm limit"),
            Self::InvalidHmacKey => write!(f, "HMAC-SHA256 rejected the provided key"),
        }
    }
}

impl std::error::Error for CryptoError {}
