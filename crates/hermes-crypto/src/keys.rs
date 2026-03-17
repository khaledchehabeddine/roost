use ed25519_dalek::SigningKey;
pub use ed25519_dalek::{Signature, VerifyingKey};
use rand::rngs::OsRng;
use x25519_dalek::StaticSecret;
pub use x25519_dalek::{PublicKey, SharedSecret};

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
}
