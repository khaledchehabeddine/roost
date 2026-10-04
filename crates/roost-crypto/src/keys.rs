mod dh;
mod identity;
mod signing;

use roost_protocol::SignatureError;
use std::error::Error;
use std::fmt;

pub use dh::{KeyPair, PublicKey, SharedSecret, generate_key_pair};
pub use identity::{PublicIdentityKey, sign_identity_key_binding, verify_public_identity_key};
pub(crate) use roost_protocol::is_valid_x25519_public_key;
pub(crate) use roost_protocol::parse_ed25519_verifying_key_bytes;
// Shared by both binding directions; not part of the public surface.
pub(crate) use identity::identity_key_binding_payload;
pub(crate) use roost_protocol::verify_with_context;
pub use signing::{Signature, SigningKeyPair, VerifyingKey, generate_signing_key_pair};

/// An error returned while parsing or verifying a public key.
#[derive(Debug)]
pub enum PublicKeyError {
    /// A public key or signature failed length or canonical-encoding validation.
    InvalidKeyEncoding,
    /// A binding signature failed context framing or verification.
    Signature(SignatureError),
}

impl fmt::Display for PublicKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyEncoding => write!(f, "public key or signature encoding is invalid"),
            Self::Signature(e) => write!(f, "public key signature failed: {e}"),
        }
    }
}

impl Error for PublicKeyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidKeyEncoding => None,
            Self::Signature(e) => Some(e),
        }
    }
}

impl From<SignatureError> for PublicKeyError {
    fn from(error: SignatureError) -> Self {
        Self::Signature(error)
    }
}
