use crate::keys::{PublicKeyError, contributory_diffie_hellman, parse_public_key};
use rand::{CryptoRng, RngCore};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// A single-use X25519 prekey bound to a discovery-key epoch.
#[derive(ZeroizeOnDrop)]
pub struct OneTimePreKey {
    #[zeroize(skip)]
    id: u64,
    secret_key: StaticSecret,
    #[zeroize(skip)]
    public_key: PublicKey,
    #[zeroize(skip)]
    epoch: u32,
}

impl OneTimePreKey {
    /// Restores a one-time prekey from secret bytes and stored metadata.
    pub fn from_secret_bytes(id: u64, secret: &[u8; 32], epoch: u32) -> Self {
        let secret_key = StaticSecret::from(*secret);
        let public_key = PublicKey::from(&secret_key);
        Self {
            id,
            secret_key,
            public_key,
            epoch,
        }
    }

    /// Returns the X25519 public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Derives a shared secret with `peer`, or `None` when `peer` forces a known one.
    pub(crate) fn diffie_hellman(&self, peer: &PublicKey) -> Option<SharedSecret> {
        contributory_diffie_hellman(&self.secret_key, peer)
    }

    /// Exports the one-time prekey's secret bytes for secure persistence.
    pub fn to_secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.secret_key.to_bytes())
    }

    /// Returns the public form of this one-time prekey for distribution to peers.
    pub fn public(&self) -> PublicOneTimePreKey {
        PublicOneTimePreKey {
            id: self.id,
            public_key: self.public_key,
            epoch: self.epoch,
        }
    }
}

/// Public one-time prekey material distributed to peers.
#[derive(Clone)]
pub struct PublicOneTimePreKey {
    /// Caller-assigned identifier used by the responder to consume the matching secret key.
    pub id: u64,
    /// X25519 public key used during X3DH root-key derivation.
    pub public_key: PublicKey,
    /// Discovery-key epoch this prekey was produced under.
    pub epoch: u32,
}

impl PublicOneTimePreKey {
    /// Builds a public one-time prekey from received wire bytes.
    ///
    /// This checks only the key's encoding. [`initiate_handshake`](crate::initiate_handshake)
    /// rejects a prekey from another epoch than the bundle's discovery key.
    pub fn from_bytes(id: u64, public_key: &[u8], epoch: u32) -> Result<Self, PublicKeyError> {
        Ok(Self {
            id,
            public_key: parse_public_key(public_key)?,
            epoch,
        })
    }
}

/// Generates a one-time prekey using `rng`.
#[must_use]
pub fn generate_one_time_prekey<R: RngCore + CryptoRng>(
    rng: &mut R,
    id: u64,
    epoch: u32,
) -> OneTimePreKey {
    let secret_key = StaticSecret::random_from_rng(&mut *rng);
    let public_key = PublicKey::from(&secret_key);
    OneTimePreKey {
        id,
        secret_key,
        public_key,
        epoch,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn public_from_bytes_rejects_wrong_public_key_length() {
        assert!(matches!(
            PublicOneTimePreKey::from_bytes(9, &[0u8; 31], 3),
            Err(PublicKeyError::InvalidKeyEncoding)
        ));
    }

    #[test]
    fn from_secret_bytes_restores_diffie_hellman_secret() {
        let mut rng = ChaCha20Rng::from_seed([0x55u8; 32]);
        let original = generate_one_time_prekey(&mut rng, 9, 3);
        let peer = generate_one_time_prekey(&mut rng, 10, 3);
        let restored = OneTimePreKey::from_secret_bytes(9, &original.to_secret_bytes(), 3);
        assert_eq!(
            original
                .diffie_hellman(peer.public_key())
                .unwrap()
                .as_bytes(),
            restored
                .diffie_hellman(peer.public_key())
                .unwrap()
                .as_bytes()
        );
    }
}
