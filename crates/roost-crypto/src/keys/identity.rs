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

/// Signs the identity key's X25519 half with its Ed25519 signing key.
pub fn sign_identity_key_binding(
    signing_key: &SigningKeyPair,
    public_key: &PublicKey,
) -> Result<Signature, SignatureError> {
    signing_key.sign_with_context(
        IDENTITY_KEY_BINDING_CONTEXT,
        &identity_key_binding_payload(public_key, &signing_key.verifying),
    )
}

/// Verifies that an identity key's Ed25519 half signed its X25519 half.
pub fn verify_public_identity_key(identity_key: &PublicIdentityKey) -> Result<(), PublicKeyError> {
    if !is_valid_x25519_public_key(identity_key.public_key.as_bytes()) {
        return Err(PublicKeyError::InvalidKeyEncoding);
    }
    let verifying_key_bytes = identity_key.verifying_key.to_bytes();
    parse_ed25519_verifying_key_bytes(&verifying_key_bytes)
        .ok_or(PublicKeyError::InvalidKeyEncoding)?;
    verify_with_context(
        &identity_key.verifying_key,
        IDENTITY_KEY_BINDING_CONTEXT,
        &identity_key_binding_payload(&identity_key.public_key, &identity_key.verifying_key),
        &identity_key.binding_signature,
    )
    .map_err(Into::into)
}

/// Returns the identity key's two public halves, the bytes both binding directions cover.
///
/// The identity key signs these under `RoostIKBinding-v1:`, and a discovery key signs the same
/// bytes under `RoostDKToIK-v1:`. Only the label separates the two, so both directions must build
/// the payload here.
pub(crate) fn identity_key_binding_payload(
    public_key: &PublicKey,
    verifying_key: &VerifyingKey,
) -> [u8; 2 * PUBLIC_KEY_LEN] {
    let mut payload = [0u8; 2 * PUBLIC_KEY_LEN];
    payload[..PUBLIC_KEY_LEN].copy_from_slice(public_key.as_bytes());
    payload[PUBLIC_KEY_LEN..].copy_from_slice(verifying_key.as_bytes());
    payload
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::dh::KeyPair;
    use crate::keys::signing::generate_signing_key_pair;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn identity_key_binding_rejects_swapped_x25519_half() {
        let mut rng = ChaCha20Rng::from_seed([0x15; 32]);
        let signing_key = generate_signing_key_pair(&mut rng);
        let agreement_key = KeyPair::from_secret_bytes(&[0x44; 32]);
        let other_agreement_key = KeyPair::from_secret_bytes(&[0x45; 32]);
        let signature = sign_identity_key_binding(&signing_key, &agreement_key.public).unwrap();

        let tampered = PublicIdentityKey {
            public_key: other_agreement_key.public,
            verifying_key: signing_key.verifying,
            binding_signature: signature,
        };

        assert!(matches!(
            verify_public_identity_key(&tampered),
            Err(PublicKeyError::Signature(SignatureError::SignatureInvalid))
        ));
    }

    #[test]
    fn identity_key_binding_rejects_swapped_ed25519_half() {
        let mut rng = ChaCha20Rng::from_seed([0x16; 32]);
        let signing_key = generate_signing_key_pair(&mut rng);
        let other_signing_key = generate_signing_key_pair(&mut rng);
        let agreement_key = KeyPair::from_secret_bytes(&[0x46; 32]);
        let signature = sign_identity_key_binding(&signing_key, &agreement_key.public).unwrap();

        let tampered = PublicIdentityKey {
            public_key: agreement_key.public,
            verifying_key: other_signing_key.verifying,
            binding_signature: signature,
        };

        assert!(matches!(
            verify_public_identity_key(&tampered),
            Err(PublicKeyError::Signature(SignatureError::SignatureInvalid))
        ));
    }
}
