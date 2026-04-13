use ed25519_dalek::SigningKey;
pub use ed25519_dalek::{Signature, VerifyingKey};
use rand::rngs::OsRng;
use x25519_dalek::StaticSecret;
pub use x25519_dalek::{PublicKey, SharedSecret};
use zeroize::Zeroizing;

/// An X25519 key pair for Diffie–Hellman key exchange.
///
/// The public key is derived deterministically from the secret — they are not generated
/// independently. `StaticSecret` is used (vs. `EphemeralSecret`) because this key pair represents a
/// long-lived identity key that must survive across sessions.
///
/// The secret field is private to prevent callers from moving it out, which would fire
/// zeroize-on-drop at the moved-from location rather than the final location.
pub struct KeyPair {
    pub public: PublicKey,
    secret: StaticSecret,
}

impl KeyPair {
    /// Performs an X25519 Diffie–Hellman exchange with the given public key.
    pub fn diffie_hellman(&self, their_public: &PublicKey) -> SharedSecret {
        self.secret.diffie_hellman(their_public)
    }

    /// Exports the secret key bytes for secure storage.
    ///
    /// Wrapped in [`Zeroizing`] so the bytes are scrubbed from memory when dropped.
    pub fn to_secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.secret.to_bytes())
    }

    /// Restores a [`KeyPair`] from stored secret key bytes.
    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        KeyPair { public, secret }
    }
}

/// An Ed25519 key pair for signing.
///
/// `signing` is private for the same reason as `KeyPair::secret` — moving it out would break
/// zeroize-on-drop.
pub struct SigningKeyPair {
    pub verifying: VerifyingKey,
    signing: SigningKey,
}

impl SigningKeyPair {
    /// Signs `message` and returns the Ed25519 signature.
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

/// Generates a fresh X25519 key pair using the OS CSPRNG.
#[must_use]
pub fn generate_key_pair() -> KeyPair {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    KeyPair { public, secret }
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

    // --- RFC 7748 §6.1: X25519 test vector ---
    // https://www.rfc-editor.org/rfc/rfc7748#section-6.1

    #[test]
    fn x25519_rfc7748_vector() {
        let alice_secret: [u8; 32] =
            hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
                .try_into()
                .unwrap();
        let alice_public_expected: [u8; 32] =
            hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
                .try_into()
                .unwrap();
        let bob_secret: [u8; 32] =
            hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
                .try_into()
                .unwrap();
        let bob_public_expected: [u8; 32] =
            hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
                .try_into()
                .unwrap();
        let shared_expected: [u8; 32] =
            hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
                .try_into()
                .unwrap();

        let alice = KeyPair::from_secret_bytes(alice_secret);
        let bob = KeyPair::from_secret_bytes(bob_secret);

        assert_eq!(alice.public.as_bytes(), &alice_public_expected);
        assert_eq!(bob.public.as_bytes(), &bob_public_expected);

        let shared = alice.diffie_hellman(&bob.public);
        assert_eq!(shared.as_bytes(), &shared_expected);
    }

    // --- RFC 8032 §7.1: Ed25519 test vector ---
    // https://www.rfc-editor.org/rfc/rfc8032#section-7.1

    #[test]
    fn ed25519_rfc8032_test1_empty_message() {
        let secret: [u8; 32] =
            hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .try_into()
                .unwrap();
        let expected_public: [u8; 32] =
            hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .try_into()
                .unwrap();
        let message: [u8; 0] = [];
        let expected_signature: [u8; 64] = hex("e5564300c360ac729086e2cc806e828a\
             84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46b\
             d25bf5f0595bbe24655141438e7a100b")
        .try_into()
        .unwrap();

        let kp = SigningKeyPair::from_signing_bytes(secret);
        assert_eq!(kp.verifying.as_bytes(), &expected_public);

        let signature = kp.sign(&message);
        assert_eq!(signature.to_bytes(), expected_signature);
        assert!(kp.verifying.verify(&message, &signature).is_ok());
    }

    #[test]
    fn ed25519_rfc8032_test2_vector() {
        let secret: [u8; 32] =
            hex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
                .try_into()
                .unwrap();
        let expected_public: [u8; 32] =
            hex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
                .try_into()
                .unwrap();
        let message: [u8; 1] = [0x72];
        let expected_signature: [u8; 64] = hex("92a009a9f0d4cab8720e820b5f642540\
             a2b27b5416503f8fb3762223ebdb69da\
             085ac1e43e15996e458f3613d0f11d8c\
             387b2eaeb4302aeeb00d291612bb0c00")
        .try_into()
        .unwrap();

        let kp = SigningKeyPair::from_signing_bytes(secret);
        assert_eq!(kp.verifying.as_bytes(), &expected_public);

        let signature = kp.sign(&message);
        assert_eq!(signature.to_bytes(), expected_signature);
        assert!(kp.verifying.verify(&message, &signature).is_ok());
    }

    #[test]
    fn key_pairs_are_unique() {
        let kp1 = generate_key_pair();
        let kp2 = generate_key_pair();
        assert_ne!(kp1.public.as_bytes(), kp2.public.as_bytes());
    }

    #[test]
    fn key_pair_public_round_trip() {
        let kp = generate_key_pair();
        let recovered = PublicKey::from(*kp.public.as_bytes());
        assert_eq!(kp.public.as_bytes(), recovered.as_bytes());
    }

    #[test]
    fn diffie_hellman_agreement_is_symmetric() {
        let alice = generate_key_pair();
        let bob = generate_key_pair();
        let alice_shared = alice.diffie_hellman(&bob.public);
        let bob_shared = bob.diffie_hellman(&alice.public);
        assert_eq!(alice_shared.as_bytes(), bob_shared.as_bytes());
    }

    #[test]
    fn signing_key_pairs_are_unique() {
        let kp1 = generate_signing_key_pair();
        let kp2 = generate_signing_key_pair();
        assert_ne!(kp1.verifying.as_bytes(), kp2.verifying.as_bytes());
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
    fn key_pair_round_trip_via_secret_bytes() {
        let kp = generate_key_pair();
        let restored = KeyPair::from_secret_bytes(*kp.to_secret_bytes());
        assert_eq!(kp.public.as_bytes(), restored.public.as_bytes());
    }

    #[test]
    fn signing_key_pair_round_trip_via_signing_bytes() {
        let kp = generate_signing_key_pair();
        let restored = SigningKeyPair::from_signing_bytes(*kp.to_signing_bytes());
        assert_eq!(kp.verifying.as_bytes(), restored.verifying.as_bytes());
    }

    fn hex(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }
}
