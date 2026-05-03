use std::fmt;

/// An error returned by cryptographic operations.
#[derive(Debug)]
pub enum CryptoError {
    /// XChaCha20-Poly1305 encryption or decryption failed.
    Aead,
    /// Handshake envelope targets a different signed pre-key than the local one.
    HandshakeSignedPreKeyMismatch,
    /// HKDF-SHA256 rejected the requested output length.
    HkdfExpand,
    /// HMAC-SHA256 rejected a chain-key input.
    InvalidHmacKey,
    /// Ratchet state violated an internal invariant.
    InvalidState(&'static str),
    /// Message header asks to skip too many messages in one ratchet step.
    MaxSkipExceeded,
    /// Accepting the message would exceed the skipped-key cache limit.
    MaxSkippedKeysExceeded,
    /// Persisted ratchet state bytes failed to decode.
    RatchetStateDecode,
    /// Ratchet state failed to encode for persistence.
    RatchetStateEncode,
    /// Ed25519 signature verification failed.
    SignatureInvalid,
    /// Persisted ratchet state uses a format version this build does not understand.
    UnsupportedRatchetVersion(u8),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aead => write!(f, "xchacha20-poly1305 encryption or decryption failed"),
            Self::HandshakeSignedPreKeyMismatch => write!(
                f,
                "handshake envelope signed pre-key reference does not match local signed pre-key"
            ),
            Self::HkdfExpand => write!(f, "hkdf-sha256 expand exceeded output limit"),
            Self::InvalidHmacKey => write!(f, "hmac-sha256 rejected the provided key"),
            Self::InvalidState(context) => {
                write!(f, "ratchet state invariant violated: {context}")
            }
            Self::MaxSkipExceeded => write!(f, "requested message skip exceeds ratchet step limit"),
            Self::MaxSkippedKeysExceeded => {
                write!(f, "cached skipped message keys total exceeds global limit")
            }
            Self::RatchetStateDecode => write!(f, "ratchet state bytes failed to decode"),
            Self::RatchetStateEncode => write!(f, "ratchet state failed to encode"),
            Self::SignatureInvalid => write!(f, "ed25519 signature verification failed"),
            Self::UnsupportedRatchetVersion(v) => {
                write!(f, "unsupported ratchet state format version: {v}")
            }
        }
    }
}

impl std::error::Error for CryptoError {}
