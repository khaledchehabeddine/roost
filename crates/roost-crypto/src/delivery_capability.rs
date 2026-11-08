use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use zeroize::{ZeroizeOnDrop, Zeroizing};

const VERIFIER_LABEL: &[u8] = b"RoostDeliveryVerifier-v1:";

const CAPABILITY_LEN: usize = 32;
const VERIFIER_LEN: usize = 32;

/// A recipient-wide bearer secret authorizing delivery to one inbox until it rotates.
///
/// It isn't `Clone`, `Debug`, or `Serialize`, because a copy that reaches a log leaks delivery
/// authorization.
#[derive(ZeroizeOnDrop)]
pub struct RecipientDeliveryCapability([u8; CAPABILITY_LEN]);

impl RecipientDeliveryCapability {
    /// Restores a capability from bytes the app previously persisted.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; CAPABILITY_LEN]) -> Self {
        RecipientDeliveryCapability(*bytes)
    }

    /// Exports the capability's secret bytes for the app to persist.
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<[u8; CAPABILITY_LEN]> {
        Zeroizing::new(self.0)
    }

    /// Derives the public verifier registered with the relay.
    ///
    /// The verifier is SHA-256 over a label and the capability. Register the verifier, never the
    /// capability itself.
    #[must_use]
    pub fn verifier(&self) -> RecipientDeliveryVerifier {
        let mut hasher = Sha256::new();
        hasher.update(VERIFIER_LABEL);
        hasher.update(self.0);
        RecipientDeliveryVerifier(hasher.finalize().into())
    }
}

/// The public SHA-256 commitment to a [`RecipientDeliveryCapability`].
///
/// The relay stores it in place of the capability.
#[derive(Clone, Copy, Debug)]
pub struct RecipientDeliveryVerifier([u8; VERIFIER_LEN]);

impl RecipientDeliveryVerifier {
    /// Returns the canonical verifier bytes for registration.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; VERIFIER_LEN] {
        &self.0
    }
}

/// Generates a fresh 32-byte recipient delivery capability from `rng`.
///
/// Production code must pass `OsRng`.
#[must_use]
pub fn generate_recipient_delivery_capability<R: RngCore + CryptoRng>(
    rng: &mut R,
) -> RecipientDeliveryCapability {
    let mut bytes = Zeroizing::new([0u8; CAPABILITY_LEN]);
    rng.fill_bytes(bytes.as_mut());
    RecipientDeliveryCapability(*bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn seeded_rng() -> ChaCha20Rng {
        ChaCha20Rng::from_seed([9u8; 32])
    }

    #[test]
    fn capability_round_trips_through_secret_bytes() {
        let mut rng = seeded_rng();
        let original = generate_recipient_delivery_capability(&mut rng);
        let restored = RecipientDeliveryCapability::from_bytes(&original.to_bytes());
        assert_eq!(*restored.to_bytes(), *original.to_bytes());
        assert_eq!(
            restored.verifier().as_bytes(),
            original.verifier().as_bytes()
        );
    }

    #[test]
    fn capability_zeroizes_on_drop() {
        fn assert_zeroizes_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        assert_zeroizes_on_drop::<RecipientDeliveryCapability>();
    }
}
