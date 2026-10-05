//! Provides one-time X25519 pre-keys for X3DH.

use crate::keys::PublicKeyError;
use crate::keys::is_valid_x25519_public_key;
use rand::{CryptoRng, RngCore};
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// A single-use X25519 pre-key bound to a discovery-key epoch.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct OneTimePreKey {
    #[zeroize(skip)]
    id: u64,
    secret_key: StaticSecret,
    #[zeroize(skip)]
    public_key: PublicKey,
    #[zeroize(skip)]
    epoch: u32,
    #[zeroize(skip)]
    created_at_secs: u64,
}

impl OneTimePreKey {
    /// Restores a one-time pre-key from secret bytes and stored metadata.
    pub fn from_secret_bytes(id: u64, secret: [u8; 32], epoch: u32, created_at_secs: u64) -> Self {
        let secret_key = StaticSecret::from(secret);
        let public_key = PublicKey::from(&secret_key);
        Self {
            id,
            secret_key,
            public_key,
            epoch,
            created_at_secs,
        }
    }

    /// Returns the caller-assigned pre-key identifier.
    pub fn id(&self) -> u64 {
        self.id
    }

    /// Returns the X25519 public key.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Returns the discovery-key epoch this pre-key was produced under.
    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    /// Returns the Unix timestamp (seconds) when this pre-key was generated.
    pub fn created_at_secs(&self) -> u64 {
        self.created_at_secs
    }

    /// Performs an X25519 Diffie-Hellman exchange between this pre-key's secret and `peer`.
    pub fn diffie_hellman(&self, peer: &PublicKey) -> SharedSecret {
        self.secret_key.diffie_hellman(peer)
    }

    /// Exports the one-time pre-key's secret bytes for secure persistence.
    pub fn to_secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.secret_key.to_bytes())
    }

    /// Returns the public form of this one-time pre-key for distribution to peers.
    pub fn public(&self) -> PublicOneTimePreKey {
        PublicOneTimePreKey {
            id: self.id,
            public_key: self.public_key,
            epoch: self.epoch,
            created_at_secs: self.created_at_secs,
        }
    }
}

/// Public one-time pre-key material distributed to peers.
#[derive(Clone, Debug)]
pub struct PublicOneTimePreKey {
    /// Caller-assigned identifier used by the responder to consume the matching secret key.
    pub id: u64,
    /// X25519 public key used during X3DH root-key derivation.
    pub public_key: PublicKey,
    /// Discovery-key epoch this pre-key was produced under.
    pub epoch: u32,
    /// Unix timestamp in seconds when this pre-key was generated.
    pub created_at_secs: u64,
}

impl PublicOneTimePreKey {
    /// Builds a public one-time pre-key from received wire bytes.
    ///
    /// This validates byte lengths only. The epoch must still match the public discovery key used
    /// for session establishment.
    pub fn from_bytes(
        id: u64,
        public_key: &[u8],
        epoch: u32,
        created_at_secs: u64,
    ) -> Result<Self, PublicKeyError> {
        let public_key_bytes: [u8; 32] = public_key
            .try_into()
            .map_err(|_| PublicKeyError::InvalidKeyEncoding)?;
        if !is_valid_x25519_public_key(&public_key_bytes) {
            return Err(PublicKeyError::InvalidKeyEncoding);
        }
        Ok(Self {
            id,
            public_key: PublicKey::from(public_key_bytes),
            epoch,
            created_at_secs,
        })
    }
}

/// Generates a one-time pre-key using `rng`.
#[must_use]
pub fn generate_one_time_prekey<R: RngCore + CryptoRng>(
    rng: &mut R,
    id: u64,
    epoch: u32,
    created_at_secs: u64,
) -> OneTimePreKey {
    let secret_key = StaticSecret::random_from_rng(&mut *rng);
    let public_key = PublicKey::from(&secret_key);
    OneTimePreKey {
        id,
        secret_key,
        public_key,
        epoch,
        created_at_secs,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn public_fields_match_one_time_prekey() {
        let mut rng = ChaCha20Rng::from_seed([0x54u8; 32]);
        let one_time_prekey = generate_one_time_prekey(&mut rng, 9, 3, 1_700_000_000);
        let bundle = one_time_prekey.public();
        assert_eq!(bundle.id, one_time_prekey.id());
        assert_eq!(
            bundle.public_key.as_bytes(),
            one_time_prekey.public_key().as_bytes()
        );
        assert_eq!(bundle.epoch, one_time_prekey.epoch());
        assert_eq!(bundle.created_at_secs, one_time_prekey.created_at_secs());
    }

    #[test]
    fn public_from_bytes_round_trip_preserves_fields() {
        let mut rng = ChaCha20Rng::from_seed([0x54u8; 32]);
        let one_time_prekey = generate_one_time_prekey(&mut rng, 9, 3, 1_700_000_000);
        let bundle = one_time_prekey.public();

        let parsed = PublicOneTimePreKey::from_bytes(
            bundle.id,
            bundle.public_key.as_bytes(),
            bundle.epoch,
            bundle.created_at_secs,
        )
        .unwrap();

        assert_eq!(parsed.id, bundle.id);
        assert_eq!(parsed.public_key.as_bytes(), bundle.public_key.as_bytes());
        assert_eq!(parsed.epoch, bundle.epoch);
        assert_eq!(parsed.created_at_secs, bundle.created_at_secs);
    }

    #[test]
    fn public_from_bytes_rejects_wrong_public_key_length() {
        assert!(matches!(
            PublicOneTimePreKey::from_bytes(9, &[0u8; 31], 3, 1_700_000_000),
            Err(PublicKeyError::InvalidKeyEncoding)
        ));
    }

    #[test]
    fn from_secret_bytes_restores_diffie_hellman_secret() {
        let mut rng = ChaCha20Rng::from_seed([0x55u8; 32]);
        let original = generate_one_time_prekey(&mut rng, 9, 3, 1_700_000_000);
        let peer = generate_one_time_prekey(&mut rng, 10, 3, 1_700_000_000);
        let restored = OneTimePreKey::from_secret_bytes(
            original.id(),
            *original.to_secret_bytes(),
            original.epoch(),
            original.created_at_secs(),
        );
        assert_eq!(
            original.diffie_hellman(peer.public_key()).as_bytes(),
            restored.diffie_hellman(peer.public_key()).as_bytes()
        );
    }
}
