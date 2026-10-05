mod dh;
mod identity;
mod signing;

use roost_protocol::SignatureError;

pub use dh::{KeyPair, PublicKey, SharedSecret, generate_key_pair};
pub use identity::{PublicIdentityKey, sign_identity_key_binding, verify_public_identity_key};
pub(crate) use roost_protocol::is_valid_x25519_public_key;
pub(crate) use roost_protocol::parse_ed25519_verifying_key_bytes;
// Shared by both binding directions; not part of the public surface.
pub(crate) use identity::identity_key_binding_payload;
pub(crate) use roost_protocol::verify_with_context;
pub use signing::{Signature, SigningKeyPair, VerifyingKey, generate_signing_key_pair};

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
