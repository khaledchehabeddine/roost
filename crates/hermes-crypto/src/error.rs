use std::fmt;

/// Errors returned by the cryptographic primitives — handshake, ratchet, signing, and serde.
#[derive(Debug)]
pub enum CryptoError {
    /// XChaCha20-Poly1305 encryption or decryption failed (tampered ciphertext, wrong key, or
    /// wrong associated data).
    ///
    /// Recovery: drop the message; never recover plaintext from a failed AEAD.
    Aead,
    /// The handshake envelope's signed pre-key reference does not match the local signed
    /// pre-key.
    ///
    /// Recovery: drop the envelope. Either the peer is talking to an outdated bundle or the
    /// envelope is forged. If recently rotated, return the fresh bundle and let the peer retry.
    HandshakeSignedPreKeyMismatch,
    /// HKDF-SHA256 `expand` exceeded its output-length limit.
    ///
    /// Recovery: surface as an internal error; the input parameters are constants in this
    /// crate, so this should not occur in production.
    HkdfExpand,
    /// HMAC-SHA256 rejected the provided key (zero-length or otherwise invalid).
    ///
    /// Recovery: surface as an internal error. Indicates a bug in chain-key initialization.
    InvalidHmacKey,
    /// A ratchet state invariant was violated. Inner string describes which one.
    ///
    /// Recovery: drop the message. The ratchet state is in an unexpected shape — typically a
    /// peer sending before they're allowed to. Treat as adversarial.
    InvalidState(&'static str),
    /// A message skip exceeded the per-step `MAX_SKIP` limit.
    ///
    /// Recovery: drop the message. A peer asking to skip more than the limit is either lossy
    /// or attacker-influenced; the protocol does not allow recovery.
    MaxSkipExceeded,
    /// The skipped-key cache exceeded the global `MAX_SKIPPED_KEYS_TOTAL` limit.
    ///
    /// Recovery: drop the message. The cache is at capacity; accepting more would risk memory
    /// exhaustion.
    MaxSkippedKeysExceeded,
    /// Persisted ratchet state bytes failed to decode (corrupt or truncated).
    ///
    /// Recovery: discard the persisted blob and re-establish the session. The local state is
    /// lost; the peer will see a new ratchet public key and resync.
    RatchetStateDecode,
    /// Ratchet state failed to encode (allocation or serde failure).
    ///
    /// Recovery: surface as an internal error; not reachable with the current state layout.
    RatchetStateEncode,
    /// Ed25519 signature verification failed.
    ///
    /// Recovery: drop the bundle. The signed pre-key is forged or its identity verifying key
    /// is wrong.
    SignatureInvalid,
    /// Persisted ratchet state has a version this build does not understand. Inner byte is the
    /// stored version.
    ///
    /// Recovery: discard the persisted blob and re-establish the session. The build is older
    /// than the writer, or the blob is from a future incompatible release.
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
