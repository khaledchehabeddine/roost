pub use x25519_dalek::{PublicKey, SharedSecret};

use rand::rngs::OsRng;
use x25519_dalek::StaticSecret;
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

/// Generates a fresh X25519 key pair using the OS CSPRNG.
#[must_use]
pub fn generate_key_pair() -> KeyPair {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    KeyPair { public, secret }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }

    /// RFC 7748 §6.1 X25519 test vector.
    /// <https://www.rfc-editor.org/rfc/rfc7748#section-6.1>
    #[test]
    fn x25519_rfc7748_vector() {
        let alice_secret =
            hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let alice_public_expected =
            hex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        let bob_secret = hex32("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        let bob_public_expected =
            hex32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        let shared_expected =
            hex32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

        let alice = KeyPair::from_secret_bytes(alice_secret);
        let bob = KeyPair::from_secret_bytes(bob_secret);

        assert_eq!(alice.public.as_bytes(), &alice_public_expected);
        assert_eq!(bob.public.as_bytes(), &bob_public_expected);

        let shared = alice.diffie_hellman(&bob.public);
        assert_eq!(shared.as_bytes(), &shared_expected);
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
    fn key_pair_round_trip_via_secret_bytes() {
        let kp = generate_key_pair();
        let restored = KeyPair::from_secret_bytes(*kp.to_secret_bytes());
        assert_eq!(kp.public.as_bytes(), restored.public.as_bytes());
    }
}
