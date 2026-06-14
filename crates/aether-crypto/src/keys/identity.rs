use super::dh::PublicKey;
use super::encoding::{parse_ed25519_verifying_key_bytes, validate_x25519_public_key};
use super::signing::{Signature, SigningKeyPair, VerifyingKey, verify_with_context};
use crate::CryptoError;

const IDENTITY_KEY_DOMAIN_TAG: &[u8] = b"AetherIK-v1:";
const IDENTITY_KEY_BINDING_CONTEXT: &[u8] = b"AetherIKBinding-v1:";
const PUBLIC_KEY_LEN: usize = 32;
const SIGNATURE_LEN: usize = 64;
const IDENTITY_KEY_ENCODING_LEN: usize = IDENTITY_KEY_DOMAIN_TAG.len() + PUBLIC_KEY_LEN * 2;

/// Public Identity Key material plus the binding signature for its X25519 half.
#[derive(Clone, Debug)]
pub struct IdentityKeyBundle {
    /// X25519 public key agreement half.
    pub public_key: PublicKey,
    /// Ed25519 verifying key identity half.
    pub verifying_key: VerifyingKey,
    /// Ed25519 signature binding the X25519 half to the verifying key.
    pub binding_signature: Signature,
}

impl IdentityKeyBundle {
    /// Builds an Identity Key bundle from received boundary bytes.
    ///
    /// # Errors
    /// - [`CryptoError::InvalidKeyEncoding`] if either key or the signature has the wrong length
    ///   or non-canonical encoding.
    pub fn from_bytes(
        public_key: &[u8],
        verifying_key: &[u8],
        binding_signature: &[u8],
    ) -> Result<Self, CryptoError> {
        let public_key: [u8; PUBLIC_KEY_LEN] = public_key
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyEncoding)?;
        if !validate_x25519_public_key(&public_key) {
            return Err(CryptoError::InvalidKeyEncoding);
        }
        let verifying_key: [u8; PUBLIC_KEY_LEN] = verifying_key
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyEncoding)?;
        let verifying_key = parse_ed25519_verifying_key_bytes(&verifying_key)
            .ok_or(CryptoError::InvalidKeyEncoding)?;
        let binding_signature: [u8; SIGNATURE_LEN] = binding_signature
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyEncoding)?;
        Ok(Self {
            public_key: PublicKey::from(public_key),
            verifying_key,
            binding_signature: Signature::from_bytes(&binding_signature),
        })
    }

    /// Returns the canonical IK encoding used in X3DH and Safety Number transcripts.
    #[must_use]
    pub fn canonical_encoding(&self) -> [u8; IDENTITY_KEY_ENCODING_LEN] {
        let mut encoding = [0u8; IDENTITY_KEY_ENCODING_LEN];
        let mut offset = 0;
        encoding[offset..offset + IDENTITY_KEY_DOMAIN_TAG.len()]
            .copy_from_slice(IDENTITY_KEY_DOMAIN_TAG);
        offset += IDENTITY_KEY_DOMAIN_TAG.len();
        encoding[offset..offset + PUBLIC_KEY_LEN].copy_from_slice(self.public_key.as_bytes());
        offset += PUBLIC_KEY_LEN;
        encoding[offset..offset + PUBLIC_KEY_LEN].copy_from_slice(self.verifying_key.as_bytes());
        encoding
    }
}

/// Signs the IK X25519 half with the IK Ed25519 signing key.
pub fn sign_identity_key_binding(
    signing_key: &SigningKeyPair,
    public_key: &PublicKey,
) -> Result<Signature, CryptoError> {
    signing_key.sign_with_context(
        IDENTITY_KEY_BINDING_CONTEXT,
        &identity_key_binding_payload(public_key, &signing_key.verifying),
    )
}

/// Verifies that an IK Ed25519 key owns its X25519 public half.
pub fn verify_identity_key_bundle(bundle: &IdentityKeyBundle) -> Result<(), CryptoError> {
    if !validate_x25519_public_key(bundle.public_key.as_bytes()) {
        return Err(CryptoError::InvalidKeyEncoding);
    }
    let verifying_key_bytes = bundle.verifying_key.to_bytes();
    parse_ed25519_verifying_key_bytes(&verifying_key_bytes)
        .ok_or(CryptoError::InvalidKeyEncoding)?;
    verify_with_context(
        &bundle.verifying_key,
        IDENTITY_KEY_BINDING_CONTEXT,
        &identity_key_binding_payload(&bundle.public_key, &bundle.verifying_key),
        &bundle.binding_signature,
    )
}

fn identity_key_binding_payload(public_key: &PublicKey, verifying_key: &VerifyingKey) -> [u8; 64] {
    let mut payload = [0u8; 64];
    payload[..PUBLIC_KEY_LEN].copy_from_slice(public_key.as_bytes());
    payload[PUBLIC_KEY_LEN..].copy_from_slice(verifying_key.as_bytes());
    payload
}
