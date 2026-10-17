mod dh;
mod identity;
mod signing;

use roost_protocol::{
    PUBLIC_KEY_LEN, SignatureError, is_valid_x25519_public_key, parse_ed25519_verifying_key_bytes,
};

pub use dh::{KeyPair, PublicKey, generate_key_pair};
pub(crate) use dh::{contributory_diffie_hellman, generate_static_secret};
pub use identity::{PublicIdentityKey, sign_identity_key_binding, verify_public_identity_key};
// Shared by both binding directions; not part of the public surface.
pub(crate) use identity::identity_key_binding_payload;
pub use signing::{Signature, SigningKeyPair, VerifyingKey, generate_signing_key_pair};

/// An error returned while generating a Discovery Key or signed pre-key.
#[derive(Debug, thiserror::Error)]
pub enum KeyGenerationError {
    /// The random number generator failed.
    #[error("randomness failed")]
    Randomness(#[source] rand::Error),
    /// Signing the new key failed.
    #[error("signing the new key failed")]
    Signature(#[from] SignatureError),
}

/// An error returned while parsing or verifying a public key.
#[derive(Debug, thiserror::Error)]
pub enum PublicKeyError {
    /// A public key or signature failed length or canonical-encoding validation.
    #[error("public key or signature encoding is invalid")]
    InvalidKeyEncoding,
    /// A binding signature failed context framing or verification.
    #[error("public key signature failed")]
    Signature(#[from] SignatureError),
}

/// Parses a canonical X25519 public key that isn't a low-order point.
pub(crate) fn parse_public_key(bytes: &[u8]) -> Result<PublicKey, PublicKeyError> {
    let bytes: [u8; PUBLIC_KEY_LEN] = bytes
        .try_into()
        .map_err(|_| PublicKeyError::InvalidKeyEncoding)?;
    if !is_valid_x25519_public_key(&bytes) {
        return Err(PublicKeyError::InvalidKeyEncoding);
    }
    Ok(PublicKey::from(bytes))
}

/// Parses a canonical Ed25519 verifying key that isn't weak.
pub(crate) fn parse_verifying_key(bytes: &[u8]) -> Result<VerifyingKey, PublicKeyError> {
    let bytes: [u8; PUBLIC_KEY_LEN] = bytes
        .try_into()
        .map_err(|_| PublicKeyError::InvalidKeyEncoding)?;
    parse_ed25519_verifying_key_bytes(&bytes).ok_or(PublicKeyError::InvalidKeyEncoding)
}

/// Parses a 64-byte Ed25519 signature.
pub(crate) fn parse_signature(bytes: &[u8]) -> Result<Signature, PublicKeyError> {
    let bytes: [u8; Signature::BYTE_SIZE] = bytes
        .try_into()
        .map_err(|_| PublicKeyError::InvalidKeyEncoding)?;
    Ok(Signature::from_bytes(&bytes))
}
