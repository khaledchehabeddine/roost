use super::dh::PublicKey;
use super::signing::{Signature, SigningKeyPair, VerifyingKey};
use super::{PublicKeyError, parse_public_key, parse_signature, parse_verifying_key};
use roost_protocol::{
    PUBLIC_KEY_LEN, SignatureError, is_valid_x25519_public_key, parse_ed25519_verifying_key_bytes,
    verify_with_context,
};

const IDENTITY_KEY_BINDING_CONTEXT: &[u8] = b"RoostIKBinding-v1:";

/// Public identity key material plus the binding signature for its X25519 half.
#[derive(Clone, Debug)]
pub struct PublicIdentityKey {
    /// X25519 public key agreement half.
    pub public_key: PublicKey,
    /// Ed25519 verifying key identity half.
    pub verifying_key: VerifyingKey,
    /// Ed25519 signature binding the X25519 half to the verifying key.
    pub binding_signature: Signature,
}

impl PublicIdentityKey {
    /// Builds a public identity key from received boundary bytes.
    pub fn from_bytes(
        public_key: &[u8],
        verifying_key: &[u8],
        binding_signature: &[u8],
    ) -> Result<Self, PublicKeyError> {
        Ok(Self {
            public_key: parse_public_key(public_key)?,
            verifying_key: parse_verifying_key(verifying_key)?,
            binding_signature: parse_signature(binding_signature)?,
        })
    }
}

/// Signs the IK X25519 half with the IK Ed25519 signing key.
pub fn sign_identity_key_binding(
    signing_key: &SigningKeyPair,
    public_key: &PublicKey,
) -> Result<Signature, SignatureError> {
    signing_key.sign_with_context(
        IDENTITY_KEY_BINDING_CONTEXT,
        &identity_key_binding_payload(public_key, &signing_key.verifying),
    )
}

/// Verifies that an IK Ed25519 key owns its X25519 public half.
pub fn verify_public_identity_key(bundle: &PublicIdentityKey) -> Result<(), PublicKeyError> {
    if !is_valid_x25519_public_key(bundle.public_key.as_bytes()) {
        return Err(PublicKeyError::InvalidKeyEncoding);
    }
    let verifying_key_bytes = bundle.verifying_key.to_bytes();
    parse_ed25519_verifying_key_bytes(&verifying_key_bytes)
        .ok_or(PublicKeyError::InvalidKeyEncoding)?;
    verify_with_context(
        &bundle.verifying_key,
        IDENTITY_KEY_BINDING_CONTEXT,
        &identity_key_binding_payload(&bundle.public_key, &bundle.verifying_key),
        &bundle.binding_signature,
    )
    .map_err(Into::into)
}

/// Returns the identity key's two public halves, the bytes both binding directions cover.
///
/// The IK self-binding signs these under `RoostIKBinding-v1:`, and a discovery key signs the same
/// bytes under `RoostDKToIK-v1:`. Only the context separates the two, so both
/// directions must derive the payload here rather than rebuilding it.
pub(crate) fn identity_key_binding_payload(
    public_key: &PublicKey,
    verifying_key: &VerifyingKey,
) -> [u8; 2 * PUBLIC_KEY_LEN] {
    let mut payload = [0u8; 2 * PUBLIC_KEY_LEN];
    payload[..PUBLIC_KEY_LEN].copy_from_slice(public_key.as_bytes());
    payload[PUBLIC_KEY_LEN..].copy_from_slice(verifying_key.as_bytes());
    payload
}
