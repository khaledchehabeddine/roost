//! Provides Ed25519 signing key-pair generation and signatures over caller-supplied bytes.
//!
//! Re-exports [`Signature`] and [`VerifyingKey`] so callers do not depend on `ed25519_dalek`
//! directly. This module does not define a transport-authentication layout; callers provide the
//! exact bytes and domain-separation context they want signed.

pub use ed25519_dalek::{Signature, VerifyingKey};

use ed25519_dalek::SigningKey;
use rand::{CryptoRng, RngCore};
use roost_protocol::SignatureError;
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// An Ed25519 key pair for signing.
///
/// The signing key stays private and zeroed on drop. Use [`Self::to_signing_bytes`] only when
/// storing the key pair.
#[derive(ZeroizeOnDrop)]
pub struct SigningKeyPair {
    /// Public verifying key shared with peers.
    #[zeroize(skip)]
    pub verifying: VerifyingKey,
    signing: SigningKey,
}

impl SigningKeyPair {
    /// Signs `message` bytes as provided with this key pair.
    ///
    /// Ed25519 signing is deterministic, so identical inputs produce identical signatures. Callers
    /// using raw signing own any domain separation.
    pub fn sign(&self, message: &[u8]) -> Signature {
        use ed25519_dalek::Signer;
        self.signing.sign(message)
    }

    /// Signs `context || message` with this key pair.
    ///
    /// `context` must be a non-empty domain separator naming the signature purpose. Both inputs are
    /// caller-supplied bytes; this helper does not define a transport signing layout.
    /// Contexts used with the same key must be prefix-free: no context may be a prefix of another.
    /// This method inserts no delimiter or length prefix and does not enforce that requirement.
    pub fn sign_with_context(
        &self,
        context: &[u8],
        message: &[u8],
    ) -> Result<Signature, SignatureError> {
        if context.is_empty() {
            return Err(SignatureError::InvalidSignatureContext);
        }
        Ok(self.sign(&roost_protocol::contextual_message(context, message)?))
    }

    /// Returns this key pair's signing bytes for secure storage.
    ///
    /// The returned bytes are wrapped in [`Zeroizing`] so they are scrubbed when dropped.
    pub fn to_signing_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing.to_bytes())
    }

    /// Restores a [`SigningKeyPair`] from stored signing key bytes.
    pub fn from_signing_bytes(bytes: [u8; 32]) -> Self {
        let signing = SigningKey::from_bytes(&bytes);
        let verifying = signing.verifying_key();
        SigningKeyPair { verifying, signing }
    }
}

/// Generates a fresh Ed25519 key pair using `rng`.
#[must_use]
pub fn generate_signing_key_pair<R: RngCore + CryptoRng>(rng: &mut R) -> SigningKeyPair {
    let signing = SigningKey::generate(&mut *rng);
    let verifying = signing.verifying_key();
    SigningKeyPair { signing, verifying }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        KeyPair, PublicIdentityKey, PublicKeyError, sign_identity_key_binding,
        verify_public_identity_key,
    };
    use ed25519_dalek::Verifier;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use roost_protocol::verify_with_context;

    fn generated_key_pair() -> SigningKeyPair {
        generate_signing_key_pair(&mut ChaCha20Rng::from_seed([3u8; 32]))
    }

    #[test]
    fn signing_key_pair_verifying_round_trip() {
        let key_pair = generated_key_pair();
        let recovered = VerifyingKey::from_bytes(&key_pair.verifying.to_bytes()).unwrap();
        assert_eq!(key_pair.verifying.as_bytes(), recovered.as_bytes());
    }

    #[test]
    fn signing_key_pair_round_trip_via_signing_bytes() {
        let key_pair = generated_key_pair();
        let restored = SigningKeyPair::from_signing_bytes(*key_pair.to_signing_bytes());
        assert_eq!(key_pair.verifying.as_bytes(), restored.verifying.as_bytes());
    }

    #[test]
    fn signing_key_pair_zeroizes_on_drop() {
        fn assert_zeroizes_on_drop<T: zeroize::ZeroizeOnDrop>() {}

        assert_zeroizes_on_drop::<SigningKeyPair>();
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let key_pair = generated_key_pair();
        let message = b"roost test message";
        let signature = key_pair.sign(message);
        assert!(key_pair.verifying.verify(message, &signature).is_ok());
    }

    #[test]
    fn signature_invalid_for_different_message() {
        let key_pair = generated_key_pair();
        let signature = key_pair.sign(b"message one");
        assert!(matches!(
            key_pair.verifying.verify(b"message two", &signature),
            Err(ed25519_dalek::SignatureError { .. })
        ));
    }

    #[test]
    fn context_signature_rejects_wrong_context() {
        let key_pair = generated_key_pair();
        let message = b"context-bound message";
        let signature = key_pair
            .sign_with_context(b"AetherTest-v1:first", message)
            .unwrap();

        assert!(matches!(
            verify_with_context(
                &key_pair.verifying,
                b"AetherTest-v1:second",
                message,
                &signature,
            ),
            Err(SignatureError::SignatureInvalid)
        ));
    }

    #[test]
    fn identity_key_binding_rejects_swapped_x25519_half() {
        let mut rng = ChaCha20Rng::from_seed([0x15; 32]);
        let signing_key = generate_signing_key_pair(&mut rng);
        let agreement_key = KeyPair::from_secret_bytes([0x44; 32]);
        let other_agreement_key = KeyPair::from_secret_bytes([0x45; 32]);
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
        let agreement_key = KeyPair::from_secret_bytes([0x46; 32]);
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
