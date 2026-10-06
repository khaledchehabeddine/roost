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
