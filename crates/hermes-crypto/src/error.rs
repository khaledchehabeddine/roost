use std::fmt;

/// Errors returned by the cryptographic primitives — handshake, ratchet, signing, and serde.
#[derive(Debug)]
pub enum CryptoError {
    /// XChaCha20-Poly1305 encryption or decryption failed (tampered ciphertext, wrong key, or
    /// wrong associated data).
    Aead,
    /// The handshake envelope's signed pre-key reference does not match the local signed pre-key.
    HandshakeSignedPreKeyMismatch,
    /// HKDF-SHA256 `expand` exceeded its output-length limit.
    HkdfExpand,
    /// HMAC-SHA256 rejected the provided key (zero-length or otherwise invalid).
    InvalidHmacKey,
    /// A ratchet state invariant was violated. Inner string describes which one.
    InvalidState(&'static str),
    /// A message skip exceeded the per-step `MAX_SKIP` limit.
    MaxSkipExceeded,
    /// The skipped-key cache exceeded the global `MAX_SKIPPED_KEYS_TOTAL` limit.
    MaxSkippedKeysExceeded,
    /// Persisted ratchet state bytes failed to decode (corrupt or truncated).
    RatchetStateDecode,
    /// Ratchet state failed to encode (allocation or serde failure).
    RatchetStateEncode,
    /// Ed25519 signature verification failed.
    SignatureInvalid,
    /// Persisted ratchet state has a version this build does not understand. Inner byte is the
    /// stored version.
    UnsupportedRatchetVersion(u8),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aead => write!(f, "XChaCha20-Poly1305 encryption or decryption failed"),
            Self::HandshakeSignedPreKeyMismatch => write!(
                f,
                "handshake envelope signed pre-key reference does not match local signed pre-key"
            ),
            Self::HkdfExpand => write!(f, "HKDF-SHA256 expand exceeded output limit"),
            Self::InvalidHmacKey => write!(f, "HMAC-SHA256 rejected the provided key"),
            Self::InvalidState(context) => {
                write!(f, "ratchet state invariant violated: {context}")
            }
            Self::MaxSkipExceeded => write!(f, "requested message skip exceeds ratchet step limit"),
            Self::MaxSkippedKeysExceeded => {
                write!(f, "cached skipped message keys total exceeds global limit")
            }
            Self::RatchetStateDecode => write!(f, "ratchet state bytes failed to decode"),
            Self::RatchetStateEncode => write!(f, "ratchet state failed to encode"),
            Self::SignatureInvalid => write!(f, "Ed25519 signature verification failed"),
            Self::UnsupportedRatchetVersion(v) => {
                write!(f, "unsupported ratchet state format version: {v}")
            }
        }
    }
}

impl std::error::Error for CryptoError {}
