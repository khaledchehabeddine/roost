//! Provides X25519 key-pair generation and shared-secret derivation.
//!
//! Re-exports [`PublicKey`] and [`SharedSecret`] so callers do not depend on `x25519_dalek`
//! directly.

pub use x25519_dalek::{PublicKey, SharedSecret};

use rand::{CryptoRng, RngCore};
use x25519_dalek::StaticSecret;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// An X25519 key pair for Diffie-Hellman key exchange.
///
/// The secret key stays private. Use [`Self::to_secret_bytes`] only when storing the key pair.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KeyPair {
    /// Public key shared with peers for X25519 Diffie-Hellman.
    #[zeroize(skip)]
    pub public: PublicKey,
    secret: StaticSecret,
}

impl KeyPair {
    /// Derives a shared secret with `peer_public`.
    pub fn diffie_hellman(&self, peer_public: &PublicKey) -> SharedSecret {
        self.secret.diffie_hellman(peer_public)
    }

    /// Returns this key pair's secret bytes for secure storage.
    ///
    /// The returned bytes are wrapped in [`Zeroizing`] so they are scrubbed when dropped.
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

/// Generates a fresh X25519 key pair using `rng`.
#[must_use]
pub fn generate_key_pair<R: RngCore + CryptoRng>(rng: &mut R) -> KeyPair {
    let secret = StaticSecret::random_from_rng(&mut *rng);
    let public = PublicKey::from(&secret);
    KeyPair { public, secret }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    const X25519_RFC7748_KAT_ALICE_SECRET_HEX: &str =
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    const X25519_RFC7748_KAT_BOB_SECRET_HEX: &str =
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
    const X25519_RFC7748_KAT_EXPECTED_ALICE_PUBLIC_HEX: &str =
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    const X25519_RFC7748_KAT_EXPECTED_BOB_PUBLIC_HEX: &str =
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
    const X25519_RFC7748_KAT_EXPECTED_SHARED_SECRET_HEX: &str =
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";

    fn hex32(hex: &str) -> [u8; 32] {
        hex::decode(hex).unwrap().try_into().unwrap()
    }

    /// Known-answer test for X25519.
    ///
    /// Source: RFC 7748 section 6.1 X25519 test vector
    ///
    /// Inputs:
    /// - `alice_secret = X25519_RFC7748_KAT_ALICE_SECRET_HEX`
    /// - `bob_secret = X25519_RFC7748_KAT_BOB_SECRET_HEX`
    ///
    /// Derivation:
    /// ```text
    /// alice_public = X25519_BASEPOINT(alice_secret)
    /// bob_public = X25519_BASEPOINT(bob_secret)
    /// shared_secret = X25519(alice_secret, bob_public)
    /// ```
    ///
    /// Output:
    /// - `alice_public = X25519_RFC7748_KAT_EXPECTED_ALICE_PUBLIC_HEX`
    /// - `bob_public = X25519_RFC7748_KAT_EXPECTED_BOB_PUBLIC_HEX`
    /// - `shared_secret = X25519_RFC7748_KAT_EXPECTED_SHARED_SECRET_HEX`
    #[test]
    fn x25519_rfc7748_vector() {
        let alice_secret = hex32(X25519_RFC7748_KAT_ALICE_SECRET_HEX);
        let bob_secret = hex32(X25519_RFC7748_KAT_BOB_SECRET_HEX);
        let expected_alice_public = hex32(X25519_RFC7748_KAT_EXPECTED_ALICE_PUBLIC_HEX);
        let expected_bob_public = hex32(X25519_RFC7748_KAT_EXPECTED_BOB_PUBLIC_HEX);
        let expected_shared_secret = hex32(X25519_RFC7748_KAT_EXPECTED_SHARED_SECRET_HEX);

        let alice = KeyPair::from_secret_bytes(alice_secret);
        let bob = KeyPair::from_secret_bytes(bob_secret);
        assert_eq!(alice.public.as_bytes(), &expected_alice_public);
        assert_eq!(bob.public.as_bytes(), &expected_bob_public);

        let shared_secret = alice.diffie_hellman(&bob.public);
        assert_eq!(shared_secret.as_bytes(), &expected_shared_secret);
    }

    #[test]
    fn key_pair_public_round_trip() {
        let key_pair = generate_key_pair(&mut ChaCha20Rng::from_seed([1u8; 32]));
        let recovered = PublicKey::from(*key_pair.public.as_bytes());
        assert_eq!(key_pair.public.as_bytes(), recovered.as_bytes());
    }

    #[test]
    fn key_pair_round_trip_via_secret_bytes() {
        let key_pair = generate_key_pair(&mut ChaCha20Rng::from_seed([1u8; 32]));
        let restored = KeyPair::from_secret_bytes(*key_pair.to_secret_bytes());
        assert_eq!(key_pair.public.as_bytes(), restored.public.as_bytes());
    }

    #[test]
    fn key_pair_zeroizes_on_drop() {
        fn assert_zeroizes_on_drop<T: zeroize::ZeroizeOnDrop>() {}

        assert_zeroizes_on_drop::<KeyPair>();
    }

    #[test]
    fn diffie_hellman_agreement_is_symmetric() {
        let mut rng = ChaCha20Rng::from_seed([2u8; 32]);
        let alice = generate_key_pair(&mut rng);
        let bob = generate_key_pair(&mut rng);

        let alice_shared_secret = alice.diffie_hellman(&bob.public);
        let bob_shared_secret = bob.diffie_hellman(&alice.public);
        assert_eq!(alice_shared_secret.as_bytes(), bob_shared_secret.as_bytes());
    }
}
