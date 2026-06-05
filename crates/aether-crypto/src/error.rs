use std::fmt;

/// An error returned by cryptographic operations.
#[non_exhaustive]
#[derive(Debug)]
pub enum CryptoError {
    /// XChaCha20-Poly1305 encryption or decryption failed.
    Aead,
    /// Handshake envelope bytes failed to decode.
    HandshakeEnvelopeDecode,
    /// Handshake envelope failed to encode.
    HandshakeEnvelopeEncode,
    /// Handshake envelope targets a different signed pre-key than the local one.
    HandshakeSignedPreKeyMismatch,
    /// HKDF-SHA256 rejected the requested output length.
    HkdfExpand,
    /// HMAC-SHA256 rejected a chain-key input.
    InvalidHmacKey,
    /// A public key or signature failed length or canonical-encoding validation.
    InvalidKeyEncoding,
    /// An X25519 exchange produced a non-contributory shared secret.
    NonContributorySharedSecret,
    /// Ratchet state violated an internal invariant.
    InvalidState(&'static str),
    /// Message header asks to skip too many messages in one ratchet step.
    MaxSkipExceeded,
    /// Persisted ratchet state exceeds the skipped-key cache limit.
    MaxSkippedKeysExceeded,
    /// Handshake envelope names a one-time pre-key that was not supplied.
    MissingOneTimePreKey,
    /// Handshake envelope one-time pre-key reference does not match the local one.
    OneTimePreKeyMismatch,
    /// Persisted ratchet state bytes failed to decode.
    RatchetStateDecode,
    /// Ratchet state failed to encode for persistence.
    RatchetStateEncode,
    /// Ed25519 signature verification or sealed sender proof validation failed.
    SignatureInvalid,
    /// Pre-key material belongs to a superseded discovery-key epoch.
    StalePreKey,
    /// Persisted ratchet state uses a format version this build does not understand.
    UnsupportedRatchetVersion(u8),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Aead => write!(f, "xchacha20-poly1305 encryption or decryption failed"),
            Self::HandshakeEnvelopeDecode => write!(f, "handshake envelope bytes failed to decode"),
            Self::HandshakeEnvelopeEncode => write!(f, "handshake envelope failed to encode"),
            Self::HandshakeSignedPreKeyMismatch => write!(
                f,
                "handshake envelope signed pre-key reference does not match local signed pre-key"
            ),
            Self::HkdfExpand => write!(f, "hkdf-sha256 expand exceeded output limit"),
            Self::InvalidHmacKey => write!(f, "hmac-sha256 rejected the provided key"),
            Self::InvalidKeyEncoding => write!(f, "public key or signature encoding is invalid"),
            Self::InvalidState(context) => {
                write!(f, "ratchet state invariant violated: {context}")
            }
            Self::MaxSkipExceeded => write!(f, "requested message skip exceeds ratchet step limit"),
            Self::MaxSkippedKeysExceeded => {
                write!(f, "cached skipped message keys total exceeds global limit")
            }
            Self::MissingOneTimePreKey => write!(f, "handshake one-time pre-key is missing"),
            Self::NonContributorySharedSecret => {
                write!(f, "x25519 shared secret was non-contributory")
            }
            Self::OneTimePreKeyMismatch => write!(
                f,
                "handshake envelope one-time pre-key reference does not match local one-time pre-key"
            ),
            Self::RatchetStateDecode => write!(f, "ratchet state bytes failed to decode"),
            Self::RatchetStateEncode => write!(f, "ratchet state failed to encode"),
            Self::SignatureInvalid => {
                write!(f, "signature or sealed sender proof verification failed")
            }
            Self::StalePreKey => write!(f, "pre-key belongs to a superseded discovery-key epoch"),
            Self::UnsupportedRatchetVersion(v) => {
                write!(f, "unsupported ratchet state format version: {v}")
            }
        }
    }
}

impl std::error::Error for CryptoError {}
