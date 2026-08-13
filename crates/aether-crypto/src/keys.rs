mod dh;
mod encoding;
mod identity;
mod signing;

pub use dh::{KeyPair, PublicKey, SharedSecret, generate_key_pair};
pub use encoding::parse_ed25519_verifying_key_bytes;
pub(crate) use encoding::validate_x25519_public_key;
pub use identity::{IdentityKeyBundle, sign_identity_key_binding, verify_identity_key_bundle};
// Shared by both binding directions; not part of the public surface.
pub(crate) use identity::identity_key_binding_payload;
pub use signing::{
    Signature, SigningKeyPair, VerifyingKey, generate_signing_key_pair, verify_with_context,
};
