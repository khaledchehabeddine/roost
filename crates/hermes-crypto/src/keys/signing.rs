//! Ed25519 signing key pair. Re-exports [`Signature`] and [`VerifyingKey`] from `ed25519_dalek`
//! so consumers don't depend on the upstream crate directly.

pub use ed25519_dalek::{Signature, VerifyingKey};

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use zeroize::Zeroizing;

/// An Ed25519 key pair for signing.
///
/// `signing` is private for the same reason as `KeyPair::secret` — moving it out would break
/// zeroize-on-drop.
pub struct SigningKeyPair {
    pub verifying: VerifyingKey,
    signing: SigningKey,
}

impl SigningKeyPair {
    /// Signs `message` with this pair's Ed25519 signing key. Deterministic — identical inputs
    /// produce identical signatures.
    pub fn sign(&self, message: &[u8]) -> Signature {
        use ed25519_dalek::Signer;
        self.signing.sign(message)
    }

    /// Exports the signing key bytes for secure storage.
    ///
    /// Wrapped in [`Zeroizing`] so the bytes are scrubbed from memory when dropped.
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

/// Generates a fresh Ed25519 key pair using the OS CSPRNG.
#[must_use]
pub fn generate_signing_key_pair() -> SigningKeyPair {
    let signing = SigningKey::generate(&mut OsRng);
    let verifying = signing.verifying_key();
    SigningKeyPair { signing, verifying }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Verifier;

    fn hex32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    fn hex64(s: &str) -> [u8; 64] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    /// RFC 8032 §7.1 Ed25519 test vector with empty message.
    /// <https://www.rfc-editor.org/rfc/rfc8032#section-7.1>
    #[test]
    fn ed25519_rfc8032_test1_vector() {
        let secret = hex32("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let expected_public =
            hex32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        let message: [u8; 0] = [];
        let expected_signature = hex64(
            "e5564300c360ac729086e2cc806e828a\
             84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46b\
             d25bf5f0595bbe24655141438e7a100b",
        );

        let kp = SigningKeyPair::from_signing_bytes(secret);
        assert_eq!(kp.verifying.as_bytes(), &expected_public);

        let signature = kp.sign(&message);
        assert_eq!(signature.to_bytes(), expected_signature);
        assert!(kp.verifying.verify(&message, &signature).is_ok());
    }

    /// RFC 8032 §7.1 Ed25519 test vector with single-byte message.
    /// <https://www.rfc-editor.org/rfc/rfc8032#section-7.1>
    #[test]
    fn ed25519_rfc8032_test2_vector() {
        let secret = hex32("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
        let expected_public =
            hex32("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
        let message: [u8; 1] = [0x72];
        let expected_signature = hex64(
            "92a009a9f0d4cab8720e820b5f642540\
             a2b27b5416503f8fb3762223ebdb69da\
             085ac1e43e15996e458f3613d0f11d8c\
             387b2eaeb4302aeeb00d291612bb0c00",
        );

        let kp = SigningKeyPair::from_signing_bytes(secret);
        assert_eq!(kp.verifying.as_bytes(), &expected_public);

        let signature = kp.sign(&message);
        assert_eq!(signature.to_bytes(), expected_signature);
        assert!(kp.verifying.verify(&message, &signature).is_ok());
    }

    #[test]
    fn signing_key_pair_verifying_round_trip() {
        let kp = generate_signing_key_pair();
        let recovered = VerifyingKey::from_bytes(&kp.verifying.to_bytes()).unwrap();
        assert_eq!(kp.verifying.as_bytes(), recovered.as_bytes());
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let kp = generate_signing_key_pair();
        let message = b"hermes test message";
        let signature = kp.sign(message);
        assert!(kp.verifying.verify(message, &signature).is_ok());
    }

    #[test]
    fn signature_invalid_for_different_message() {
        let kp = generate_signing_key_pair();
        let signature = kp.sign(b"message one");
        assert!(kp.verifying.verify(b"message two", &signature).is_err());
    }

    #[test]
    fn signing_key_pair_round_trip_via_signing_bytes() {
        let kp = generate_signing_key_pair();
        let restored = SigningKeyPair::from_signing_bytes(*kp.to_signing_bytes());
        assert_eq!(kp.verifying.as_bytes(), restored.verifying.as_bytes());
    }
}
