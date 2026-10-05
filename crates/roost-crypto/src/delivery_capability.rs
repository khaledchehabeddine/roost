//! Provides the recipient delivery capability and its public verifier.
//!
//! The capability is a recipient-wide bearer secret: every currently authorized contact holds the
//! same value, so it identifies the recipient's inbox generation rather than an individual sender.
//! Aether generates one and hands it to the caller, but never registers, validates, or
//! transmits it — the caller registers only the verifier.

use rand::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};
use subtle::{Choice, ConstantTimeEq};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

// Domain string for the verifier derivation. Unlike signature contexts such as `AetherDK-v1:`,
// this is lowercase-kebab with no trailing colon, because Relay derives the same verifier from
// these exact bytes.
const VERIFIER_DOMAIN: &[u8] = b"aether-recipient-delivery-capability-v1";
// Single separator byte between the domain string and the capability.
const VERIFIER_SEPARATOR: [u8; 1] = [0x00];

const CAPABILITY_LEN: usize = 32;
const VERIFIER_LEN: usize = 32;

/// A recipient-wide bearer secret authorizing delivery to one inbox generation.
///
/// Secret-bearing: hold it only as long as needed and persist it through platform secure storage.
/// Deliberately not `Clone`, `Debug`, or `Serialize` — a bearer secret that reaches a log or an
/// unintended copy is a delivery-authorization leak.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RecipientDeliveryCapability([u8; CAPABILITY_LEN]);

impl RecipientDeliveryCapability {
    /// Restores a capability from bytes the host previously persisted.
    #[must_use]
    pub fn from_bytes(bytes: [u8; CAPABILITY_LEN]) -> Self {
        RecipientDeliveryCapability(bytes)
    }

    /// Exports the capability's secret bytes for host persistence.
    ///
    /// The returned bytes are wrapped in [`Zeroizing`] so they are scrubbed when dropped.
    #[must_use]
    pub fn to_bytes(&self) -> Zeroizing<[u8; CAPABILITY_LEN]> {
        Zeroizing::new(self.0)
    }

    /// Derives the public verifier registered with the relay.
    ///
    /// SHA-256 over the domain string, one `0x00` separator byte, and the capability. Register the
    /// result; never the capability itself.
    #[must_use]
    pub fn verifier(&self) -> RecipientDeliveryVerifier {
        let mut hasher = Sha256::new();
        hasher.update(VERIFIER_DOMAIN);
        hasher.update(VERIFIER_SEPARATOR);
        hasher.update(self.0);
        RecipientDeliveryVerifier(hasher.finalize().into())
    }
}

/// The public SHA-256 commitment to a [`RecipientDeliveryCapability`].
///
/// Safe to publish: the relay stores this so the bearer secret itself never reaches it.
#[derive(Clone, Copy, Debug)]
pub struct RecipientDeliveryVerifier([u8; VERIFIER_LEN]);

impl RecipientDeliveryVerifier {
    /// Rebuilds a verifier from its canonical bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; VERIFIER_LEN]) -> Self {
        RecipientDeliveryVerifier(bytes)
    }

    /// Returns the canonical verifier bytes for registration.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; VERIFIER_LEN] {
        &self.0
    }
}

impl ConstantTimeEq for RecipientDeliveryVerifier {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

// Equality routes through ConstantTimeEq: a verifier is a hash, and the crypto rules bar `==` on
// hashes regardless of whether this particular comparison is secret-dependent.
impl PartialEq for RecipientDeliveryVerifier {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for RecipientDeliveryVerifier {}

/// Generates a fresh 32-byte recipient delivery capability from `rng`.
///
/// Production callers must pass an OS CSPRNG.
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
    fn distinct_capabilities_produce_distinct_verifiers() {
        let first = RecipientDeliveryCapability::from_bytes([0x42u8; 32]);
        let second = RecipientDeliveryCapability::from_bytes([0x43u8; 32]);

        assert_ne!(first.verifier(), second.verifier());
    }

    #[test]
    fn verifier_derivation_is_deterministic() {
        let capability = RecipientDeliveryCapability::from_bytes([0x42u8; 32]);

        assert_eq!(capability.verifier(), capability.verifier());
    }

    #[test]
    fn generated_capabilities_are_32_bytes_and_differ_between_draws() {
        let mut rng = seeded_rng();

        let first = generate_recipient_delivery_capability(&mut rng);
        let second = generate_recipient_delivery_capability(&mut rng);

        assert_eq!(first.to_bytes().len(), 32);
        assert_ne!(*first.to_bytes(), *second.to_bytes());
    }

    /// The host persists the capability and restores it later, so the round trip must
    /// preserve the exact bytes and therefore the verifier the relay already holds.
    #[test]
    fn capability_round_trips_through_secret_bytes() {
        let mut rng = seeded_rng();
        let original = generate_recipient_delivery_capability(&mut rng);

        let restored = RecipientDeliveryCapability::from_bytes(*original.to_bytes());

        assert_eq!(*restored.to_bytes(), *original.to_bytes());
        assert_eq!(restored.verifier(), original.verifier());
    }

    #[test]
    fn capability_zeroizes_on_drop() {
        fn assert_zeroizes_on_drop<T: zeroize::ZeroizeOnDrop>() {}

        assert_zeroizes_on_drop::<RecipientDeliveryCapability>();
    }
}
