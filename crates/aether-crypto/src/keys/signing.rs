//! Provides Ed25519 signing key-pair generation and signatures.
//!
//! Re-exports [`Signature`] and [`VerifyingKey`] so callers do not depend on `ed25519_dalek`
//! directly.

pub use ed25519_dalek::{Signature, VerifyingKey};

use ed25519_dalek::SigningKey;
use rand::{CryptoRng, RngCore};
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
    /// Signs `message` with this key pair.
    ///
    /// Ed25519 signing is deterministic, so identical inputs produce identical signatures.
    pub fn sign(&self, message: &[u8]) -> Signature {
        use ed25519_dalek::Signer;
        self.signing.sign(message)
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
    use ed25519_dalek::Verifier;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    const ED25519_RFC8032_TEST1_KAT_SECRET_HEX: &str =
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const ED25519_RFC8032_TEST1_KAT_EXPECTED_VERIFYING_HEX: &str =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const ED25519_RFC8032_TEST1_KAT_EXPECTED_SIGNATURE_HEX: &str = "e5564300c360ac729086e2cc806e828a\
         84877f1eb8e5d974d873e06522490155\
         5fb8821590a33bacc61e39701cf9b46b\
         d25bf5f0595bbe24655141438e7a100b";

    const ED25519_RFC8032_TEST2_KAT_SECRET_HEX: &str =
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb";
    const ED25519_RFC8032_TEST2_KAT_EXPECTED_VERIFYING_HEX: &str =
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
    const ED25519_RFC8032_TEST2_KAT_EXPECTED_SIGNATURE_HEX: &str = "92a009a9f0d4cab8720e820b5f642540\
         a2b27b5416503f8fb3762223ebdb69da\
         085ac1e43e15996e458f3613d0f11d8c\
         387b2eaeb4302aeeb00d291612bb0c00";

    fn hex32(hex: &str) -> [u8; 32] {
        hex::decode(hex).unwrap().try_into().unwrap()
    }

    fn hex64(hex: &str) -> [u8; 64] {
        hex::decode(hex).unwrap().try_into().unwrap()
    }

    fn generated_key_pair() -> SigningKeyPair {
        generate_signing_key_pair(&mut ChaCha20Rng::from_seed([3u8; 32]))
    }

    /// Known-answer test for Ed25519 with an empty message.
    ///
    /// Source: RFC 8032 section 7.1 Ed25519 test vector 1
    ///
    /// Inputs:
    /// - `secret = ED25519_RFC8032_TEST1_KAT_SECRET_HEX`
    /// - `message = b""`
    ///
    /// Derivation:
    /// ```text
    /// verifying_key = Ed25519-VerifyingKey(secret)
    /// signature = Ed25519-Sign(secret, message)
    /// verify(verifying_key, message, signature)
    /// ```
    ///
    /// Output:
    /// - `verifying_key = ED25519_RFC8032_TEST1_KAT_EXPECTED_VERIFYING_HEX`
    /// - `signature = ED25519_RFC8032_TEST1_KAT_EXPECTED_SIGNATURE_HEX`
    #[test]
    fn ed25519_rfc8032_empty_message_known_answer() {
        let secret = hex32(ED25519_RFC8032_TEST1_KAT_SECRET_HEX);
        let expected_verifying = hex32(ED25519_RFC8032_TEST1_KAT_EXPECTED_VERIFYING_HEX);
        let message: [u8; 0] = [];
        let expected_signature_bytes = hex64(ED25519_RFC8032_TEST1_KAT_EXPECTED_SIGNATURE_HEX);
        let expected_signature = Signature::from_bytes(&expected_signature_bytes);

        let key_pair = SigningKeyPair::from_signing_bytes(secret);
        assert_eq!(key_pair.verifying.as_bytes(), &expected_verifying);

        let signature = key_pair.sign(&message);
        assert_eq!(signature.to_bytes(), expected_signature_bytes);
        assert!(
            key_pair
                .verifying
                .verify(&message, &expected_signature)
                .is_ok()
        );
    }

    /// Known-answer test for Ed25519 with a single-byte message.
    ///
    /// Source: RFC 8032 section 7.1 Ed25519 test vector 2
    ///
    /// Inputs:
    /// - `secret = ED25519_RFC8032_TEST2_KAT_SECRET_HEX`
    /// - `message = [0x72]`
    ///
    /// Derivation:
    /// ```text
    /// verifying_key = Ed25519-VerifyingKey(secret)
    /// signature = Ed25519-Sign(secret, message)
    /// verify(verifying_key, message, signature)
    /// ```
    ///
    /// Output:
    /// - `verifying_key = ED25519_RFC8032_TEST2_KAT_EXPECTED_VERIFYING_HEX`
    /// - `signature = ED25519_RFC8032_TEST2_KAT_EXPECTED_SIGNATURE_HEX`
    #[test]
    fn ed25519_rfc8032_single_byte_message_known_answer() {
        let secret = hex32(ED25519_RFC8032_TEST2_KAT_SECRET_HEX);
        let expected_verifying = hex32(ED25519_RFC8032_TEST2_KAT_EXPECTED_VERIFYING_HEX);
        let message: [u8; 1] = [0x72];
        let expected_signature_bytes = hex64(ED25519_RFC8032_TEST2_KAT_EXPECTED_SIGNATURE_HEX);
        let expected_signature = Signature::from_bytes(&expected_signature_bytes);

        let key_pair = SigningKeyPair::from_signing_bytes(secret);
        assert_eq!(key_pair.verifying.as_bytes(), &expected_verifying);

        let signature = key_pair.sign(&message);
        assert_eq!(signature.to_bytes(), expected_signature_bytes);
        assert!(
            key_pair
                .verifying
                .verify(&message, &expected_signature)
                .is_ok()
        );
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
    fn sign_and_verify_round_trip() {
        let key_pair = generated_key_pair();
        let message = b"aether test message";
        let signature = key_pair.sign(message);
        assert!(key_pair.verifying.verify(message, &signature).is_ok());
    }

    #[test]
    fn signature_invalid_for_different_message() {
        let key_pair = generated_key_pair();
        let signature = key_pair.sign(b"message one");
        assert!(
            key_pair
                .verifying
                .verify(b"message two", &signature)
                .is_err()
        );
    }
}
