use super::KeyBundleError;
use super::dh::PublicKey;
use super::signing::{Signature, SigningKeyPair, VerifyingKey};
use roost_protocol::{SignatureError, verify_with_context};
use roost_protocol::{is_valid_x25519_public_key, parse_ed25519_verifying_key_bytes};

const IDENTITY_KEY_BINDING_CONTEXT: &[u8] = b"AetherIKBinding-v1:";
const PUBLIC_KEY_LEN: usize = 32;
const SIGNATURE_LEN: usize = 64;

/// Public Identity Key material plus the binding signature for its X25519 half.
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
    /// Builds a public Identity Key from received boundary bytes.
    pub fn from_bytes(
        public_key: &[u8],
        verifying_key: &[u8],
        binding_signature: &[u8],
    ) -> Result<Self, KeyBundleError> {
        let public_key: [u8; PUBLIC_KEY_LEN] = public_key
            .try_into()
            .map_err(|_| KeyBundleError::InvalidKeyEncoding)?;
        if !is_valid_x25519_public_key(&public_key) {
            return Err(KeyBundleError::InvalidKeyEncoding);
        }
        let verifying_key: [u8; PUBLIC_KEY_LEN] = verifying_key
            .try_into()
            .map_err(|_| KeyBundleError::InvalidKeyEncoding)?;
        let verifying_key = parse_ed25519_verifying_key_bytes(&verifying_key)
            .ok_or(KeyBundleError::InvalidKeyEncoding)?;
        let binding_signature: [u8; SIGNATURE_LEN] = binding_signature
            .try_into()
            .map_err(|_| KeyBundleError::InvalidKeyEncoding)?;
        Ok(Self {
            public_key: PublicKey::from(public_key),
            verifying_key,
            binding_signature: Signature::from_bytes(&binding_signature),
        })
    }

    /// Returns the canonical IK encoding used in X3DH and Safety Number transcripts.
    #[must_use]
    pub fn canonical_encoding(&self) -> [u8; roost_protocol::IDENTITY_KEY_ENCODING_LEN] {
        roost_protocol::identity_key_encoding(
            self.public_key.as_bytes(),
            self.verifying_key.as_bytes(),
        )
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
pub fn verify_identity_key_bundle(bundle: &PublicIdentityKey) -> Result<(), KeyBundleError> {
    if !is_valid_x25519_public_key(bundle.public_key.as_bytes()) {
        return Err(KeyBundleError::InvalidKeyEncoding);
    }
    let verifying_key_bytes = bundle.verifying_key.to_bytes();
    parse_ed25519_verifying_key_bytes(&verifying_key_bytes)
        .ok_or(KeyBundleError::InvalidKeyEncoding)?;
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
/// The IK self-binding signs these under `AetherIKBinding-v1:`, and a discovery key signs the same
/// bytes under `AetherDKToIK-v1:`. Only the context separates the two, so both
/// directions must derive the payload here rather than rebuilding it.
pub(crate) fn identity_key_binding_payload(
    public_key: &PublicKey,
    verifying_key: &VerifyingKey,
) -> [u8; 64] {
    let mut payload = [0u8; 64];
    payload[..PUBLIC_KEY_LEN].copy_from_slice(public_key.as_bytes());
    payload[PUBLIC_KEY_LEN..].copy_from_slice(verifying_key.as_bytes());
    payload
}
