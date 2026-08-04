use crate::clock::Clock;
use crate::identity::{IdentityError, IdentityManager};
use crate::storage::{SecureStorage, StorageError};
use aether_crypto::{
    DiscoveryKey, DiscoveryKeyBundle, RecipientDeliveryCapability, Signature, SigningKeyPair,
    generate_discovery_key, generate_recipient_delivery_capability, verify_discovery_key_bundle,
};
use rand::{CryptoRng, RngCore};
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use zeroize::Zeroizing;

const DISCOVERY_KEY: &str = "discovery/current";
// Version 2 added the recipient delivery capability. A version 1 blob is rejected by the length
// check in `checked_blob` before the version byte is even read; it predates the inbox generation
// model and has no capability to migrate, so the host must reset and re-register.
const DISCOVERY_KEY_VERSION: u8 = 2;
// Blob layout: version (1) | generation (4) | x25519 secret (32) | ed25519 secret (32) |
// identity signature (64) | created_at (8) | delivery capability (32).
const DISCOVERY_KEY_BLOB_LEN: usize = 1 + 4 + 32 + 32 + 64 + 8 + 32;
const CAPABILITY_OFFSET: usize = 141;
// Identity creation starts at inbox generation 1 (AE-IDN-07).
const FIRST_INBOX_GENERATION: u32 = 1;

/// Errors returned by discovery-key operations.
#[derive(Debug)]
pub enum DiscoveryKeyError {
    /// The system clock is before the Unix epoch.
    Clock,
    /// The stored discovery key's signature does not verify against the identity key.
    Corrupt,
    /// Loading the identity for discovery-key signing or verification returned an
    /// [`IdentityError`].
    Identity(IdentityError),
    /// Stored discovery-key data is malformed.
    InvalidData(String),
    /// The internal storage lock was poisoned by a panicked thread.
    LockPoisoned,
    /// No discovery key is stored.
    NotFound,
    /// The underlying [`SecureStorage`] returned an error.
    Storage(StorageError),
}

impl fmt::Display for DiscoveryKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DiscoveryKeyError::Clock => write!(f, "system clock is before Unix epoch"),
            DiscoveryKeyError::Corrupt => {
                write!(
                    f,
                    "stored discovery-key signature does not match the identity key"
                )
            }
            DiscoveryKeyError::Identity(e) => write!(f, "identity: {e}"),
            DiscoveryKeyError::InvalidData(reason) => {
                write!(f, "invalid discovery-key data: {reason}")
            }
            DiscoveryKeyError::LockPoisoned => write!(f, "internal lock poisoned"),
            DiscoveryKeyError::NotFound => write!(f, "no discovery key stored"),
            DiscoveryKeyError::Storage(e) => write!(f, "storage: {e}"),
        }
    }
}

impl Error for DiscoveryKeyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            DiscoveryKeyError::Identity(e) => Some(e),
            DiscoveryKeyError::Storage(e) => Some(e),
            _ => None,
        }
    }
}

impl From<IdentityError> for DiscoveryKeyError {
    fn from(e: IdentityError) -> Self {
        DiscoveryKeyError::Identity(e)
    }
}

impl From<StorageError> for DiscoveryKeyError {
    fn from(e: StorageError) -> Self {
        DiscoveryKeyError::Storage(e)
    }
}

pub(crate) enum DiscoveryKeyStatus {
    Absent,
    Present { epoch: u32 },
    Malformed,
}

// Manages discovery key generation, rotation, verification, and persistence.
pub(crate) struct DiscoveryKeyManager {
    storage: Arc<Mutex<Box<dyn SecureStorage>>>,
    identity: Arc<IdentityManager>,
    clock: Arc<dyn Clock>,
}

impl DiscoveryKeyManager {
    pub(crate) fn new(
        storage: Arc<Mutex<Box<dyn SecureStorage>>>,
        identity: Arc<IdentityManager>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        DiscoveryKeyManager {
            storage,
            identity,
            clock,
        }
    }

    // Loads the discovery key and verifies its signature against the identity key.
    pub(crate) fn current(&self) -> Result<DiscoveryKey, DiscoveryKeyError> {
        let discovery_key = self.load_stored()?;
        let identity = self.identity.load_identity()?;
        verify_discovery_key_bundle(&discovery_key.bundle(), identity.verifying_key())
            .map_err(|_| DiscoveryKeyError::Corrupt)?;
        Ok(discovery_key)
    }

    // Returns the discovery-key bundle to distribute to peers, verified against the identity key.
    pub(crate) fn current_bundle(&self) -> Result<DiscoveryKeyBundle, DiscoveryKeyError> {
        Ok(self.current()?.bundle())
    }

    // Returns the DK→IK binding for `discovery_key` against the stored identity (AE-KEY-04).
    //
    // Recomputed per call rather than persisted. The signature covers only the identity's two
    // public halves — no epoch, no timestamp — so it holds nothing time-varying, and Ed25519 is
    // deterministic, which makes every recomputation byte-identical. Storing it would grow the
    // discovery-key blob and force a version bump to record a value already derivable from it.
    pub(crate) fn identity_binding(
        &self,
        discovery_key: &DiscoveryKey,
    ) -> Result<Signature, DiscoveryKeyError> {
        let identity = self.identity.load_identity()?;
        discovery_key
            .sign_identity_binding(&identity.identity_key_bundle()?)
            .map_err(|e| {
                DiscoveryKeyError::InvalidData(format!("discovery-to-identity binding: {e}"))
            })
    }

    pub(crate) fn stored_status(&self) -> Result<DiscoveryKeyStatus, DiscoveryKeyError> {
        let Some(raw) = self.load_raw()? else {
            return Ok(DiscoveryKeyStatus::Absent);
        };
        Ok(match checked_blob(&raw) {
            Ok(blob) => DiscoveryKeyStatus::Present {
                epoch: read_epoch(blob),
            },
            Err(_) => DiscoveryKeyStatus::Malformed,
        })
    }

    // The next epoch increments the stored one, recovering a signature-mismatched key. A malformed
    // blob returns `InvalidData` until cleared with `reset`.
    pub(crate) fn rotate_now<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<DiscoveryKey, DiscoveryKeyError> {
        let identity = self.identity.load_identity()?;
        let epoch = match self.stored_status()? {
            DiscoveryKeyStatus::Absent => FIRST_INBOX_GENERATION,
            DiscoveryKeyStatus::Present { epoch } => epoch.saturating_add(1),
            DiscoveryKeyStatus::Malformed => {
                return Err(DiscoveryKeyError::InvalidData(
                    "stored discovery key is malformed, must reset before rotating".into(),
                ));
            }
        };
        let now = self.now_secs()?;
        let discovery_key = generate_discovery_key(rng, identity.signing_key_pair(), epoch, now);
        // The capability rotates with the discovery key because both belong to one inbox
        // generation (AE-IDN-07), and they are written in one store so they cannot diverge.
        let capability = generate_recipient_delivery_capability(rng);
        let blob = encode_discovery_key(&discovery_key, &capability);
        let mut storage = self.lock_storage()?;
        storage.store(DISCOVERY_KEY, &*blob)?;
        Ok(discovery_key)
    }

    // Returns the recipient delivery capability bound to the current inbox generation (AE-IDN-06).
    //
    // Secret-bearing: the caller presents it to authorized contacts and never registers it. Only
    // its verifier (AE-IDN-10) is registered with the relay.
    pub(crate) fn current_capability(
        &self,
    ) -> Result<RecipientDeliveryCapability, DiscoveryKeyError> {
        let raw = self.load_raw()?.ok_or(DiscoveryKeyError::NotFound)?;
        Ok(decode_capability(checked_blob(&raw)?))
    }

    // Use `KeyStore::reset` to clear signed pre-key state before discovery key and identity.
    pub(crate) fn reset(&self) -> Result<(), DiscoveryKeyError> {
        let mut storage = self.lock_storage()?;
        Ok(storage.delete(DISCOVERY_KEY)?)
    }

    // Returns the verbatim stored discovery-key blob for inclusion in an encrypted backup.
    pub(crate) fn export_blob(&self) -> Result<Zeroizing<Vec<u8>>, DiscoveryKeyError> {
        let raw = self.load_raw()?.ok_or(DiscoveryKeyError::NotFound)?;
        checked_blob(&raw)?;
        Ok(raw)
    }

    // Validates a discovery-key blob's structure without storing it, so a malformed backup aborts
    // an import before any existing key material is cleared.
    #[cfg(test)]
    pub(crate) fn validate_blob(blob: &[u8]) -> Result<(), DiscoveryKeyError> {
        checked_blob(blob).map(|_| ())
    }

    // Validates that a discovery-key blob is structurally valid and signed by the restored
    // identity key before an encrypted-backup import mutates storage.
    pub(crate) fn validate_blob_for_identity(
        blob: &[u8],
        identity_key: &[u8; 64],
    ) -> Result<(), DiscoveryKeyError> {
        let discovery_key = decode_discovery_key(checked_blob(blob)?);
        let mut signing_secret = Zeroizing::new([0u8; 32]);
        signing_secret.copy_from_slice(&identity_key[32..]);
        let identity_signing = SigningKeyPair::from_signing_bytes(*signing_secret);
        verify_discovery_key_bundle(&discovery_key.bundle(), &identity_signing.verifying)
            .map_err(|_| DiscoveryKeyError::Corrupt)?;
        Ok(())
    }

    // Restores a discovery-key blob verbatim with a single store, preserving its epoch lineage and
    // identity signature. The signature is re-verified against the identity key on the next read.
    pub(crate) fn restore_from_blob(&self, blob: &[u8]) -> Result<(), DiscoveryKeyError> {
        checked_blob(blob)?;
        let mut storage = self.lock_storage()?;
        Ok(storage.store(DISCOVERY_KEY, blob)?)
    }

    fn load_stored(&self) -> Result<DiscoveryKey, DiscoveryKeyError> {
        let raw = self.load_raw()?.ok_or(DiscoveryKeyError::NotFound)?;
        Ok(decode_discovery_key(checked_blob(&raw)?))
    }

    // Reads the raw stored blob and drops the storage guard before returning, so the caller can
    // then load the identity without deadlock.
    fn load_raw(&self) -> Result<Option<Zeroizing<Vec<u8>>>, DiscoveryKeyError> {
        Ok(self.lock_storage()?.load(DISCOVERY_KEY)?)
    }

    fn lock_storage(&self) -> Result<MutexGuard<'_, Box<dyn SecureStorage>>, DiscoveryKeyError> {
        self.storage
            .lock()
            .map_err(|_| DiscoveryKeyError::LockPoisoned)
    }

    fn now_secs(&self) -> Result<u64, DiscoveryKeyError> {
        self.clock
            .now_unix_secs()
            .map_err(|_| DiscoveryKeyError::Clock)
    }
}

fn checked_blob(raw: &[u8]) -> Result<&[u8; DISCOVERY_KEY_BLOB_LEN], DiscoveryKeyError> {
    let blob: &[u8; DISCOVERY_KEY_BLOB_LEN] = raw.try_into().map_err(|_| {
        DiscoveryKeyError::InvalidData(format!(
            "expected {DISCOVERY_KEY_BLOB_LEN} bytes, got {}",
            raw.len()
        ))
    })?;
    if blob[0] != DISCOVERY_KEY_VERSION {
        return Err(DiscoveryKeyError::InvalidData(format!(
            "unsupported discovery key format version: {}",
            blob[0]
        )));
    }
    Ok(blob)
}

fn encode_discovery_key(
    discovery_key: &DiscoveryKey,
    capability: &RecipientDeliveryCapability,
) -> Zeroizing<[u8; DISCOVERY_KEY_BLOB_LEN]> {
    let mut blob = Zeroizing::new([0u8; DISCOVERY_KEY_BLOB_LEN]);
    blob[0] = DISCOVERY_KEY_VERSION;
    blob[1..5].copy_from_slice(&discovery_key.epoch().to_be_bytes());
    blob[5..37].copy_from_slice(&*discovery_key.key_agreement_secret_bytes());
    blob[37..69].copy_from_slice(&*discovery_key.signing_secret_bytes());
    blob[69..133].copy_from_slice(&discovery_key.identity_signature().to_bytes());
    blob[133..CAPABILITY_OFFSET].copy_from_slice(&discovery_key.created_at().to_be_bytes());
    blob[CAPABILITY_OFFSET..DISCOVERY_KEY_BLOB_LEN].copy_from_slice(&*capability.to_bytes());
    blob
}

fn decode_capability(blob: &[u8; DISCOVERY_KEY_BLOB_LEN]) -> RecipientDeliveryCapability {
    let mut capability = Zeroizing::new([0u8; 32]);
    capability.copy_from_slice(&blob[CAPABILITY_OFFSET..DISCOVERY_KEY_BLOB_LEN]);
    RecipientDeliveryCapability::from_bytes(*capability)
}

fn decode_discovery_key(blob: &[u8; DISCOVERY_KEY_BLOB_LEN]) -> DiscoveryKey {
    let mut key_agreement_secret = [0u8; 32];
    key_agreement_secret.copy_from_slice(&blob[5..37]);
    let mut signing_secret = [0u8; 32];
    signing_secret.copy_from_slice(&blob[37..69]);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&blob[69..133]);
    let epoch = read_epoch(blob);
    let mut created_at_bytes = [0u8; 8];
    created_at_bytes.copy_from_slice(&blob[133..CAPABILITY_OFFSET]);
    DiscoveryKey::from_secret_bytes(
        key_agreement_secret,
        signing_secret,
        epoch,
        u64::from_be_bytes(created_at_bytes),
        signature,
    )
}

#[cfg(fuzzing)]
#[allow(missing_docs)]
pub fn fuzz_decode_discovery_key_blob(raw: &[u8]) -> Result<(), DiscoveryKeyError> {
    let blob = checked_blob(raw)?;
    let _ = decode_discovery_key(blob);
    Ok(())
}

fn read_epoch(blob: &[u8; DISCOVERY_KEY_BLOB_LEN]) -> u32 {
    let mut epoch_bytes = [0u8; 4];
    epoch_bytes.copy_from_slice(&blob[1..5]);
    u32::from_be_bytes(epoch_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::ManualClock;
    use crate::storage::InMemorySecureStorage;
    use rand::rngs::OsRng;

    const FIXED_NOW: u64 = 1_700_000_000;

    struct DiscoveryKeySetup {
        identity: Arc<IdentityManager>,
        manager: DiscoveryKeyManager,
    }

    fn shared_storage() -> Arc<Mutex<Box<dyn SecureStorage>>> {
        Arc::new(Mutex::new(Box::new(InMemorySecureStorage::new())))
    }

    fn setup_with_identity() -> DiscoveryKeySetup {
        let storage = shared_storage();
        let identity = Arc::new(IdentityManager::new(Arc::clone(&storage)));
        identity.generate_identity(&mut OsRng).unwrap();
        let discovery = DiscoveryKeyManager::new(
            storage,
            Arc::clone(&identity),
            Arc::new(ManualClock::new(FIXED_NOW)),
        );
        DiscoveryKeySetup {
            identity,
            manager: discovery,
        }
    }

    fn manager_without_identity() -> DiscoveryKeyManager {
        let storage = shared_storage();
        let identity = Arc::new(IdentityManager::new(Arc::clone(&storage)));
        DiscoveryKeyManager::new(storage, identity, Arc::new(ManualClock::new(FIXED_NOW)))
    }

    #[test]
    fn current_without_stored_discovery_key_returns_not_found() {
        let discovery = setup_with_identity().manager;
        assert!(matches!(
            discovery.current(),
            Err(DiscoveryKeyError::NotFound)
        ));
    }

    #[test]
    fn current_returns_invalid_data_for_malformed_blob() {
        let discovery = setup_with_identity().manager;
        discovery
            .lock_storage()
            .unwrap()
            .store(DISCOVERY_KEY, &[0xAAu8; 50])
            .unwrap();
        assert!(matches!(
            discovery.current(),
            Err(DiscoveryKeyError::InvalidData(_))
        ));
    }

    #[test]
    fn current_returns_corrupt_for_tampered_signature() {
        let discovery = setup_with_identity().manager;
        discovery.rotate_now(&mut OsRng).unwrap();
        // Flip a byte inside the stored signature region.
        let mut blob = discovery
            .lock_storage()
            .unwrap()
            .load(DISCOVERY_KEY)
            .unwrap()
            .unwrap()
            .to_vec();
        blob[69] ^= 0x01;
        discovery
            .lock_storage()
            .unwrap()
            .store(DISCOVERY_KEY, &blob)
            .unwrap();
        assert!(matches!(
            discovery.current(),
            Err(DiscoveryKeyError::Corrupt)
        ));
    }

    #[test]
    fn stored_status_reports_absent_present_and_malformed() {
        let discovery = setup_with_identity().manager;
        assert!(matches!(
            discovery.stored_status().unwrap(),
            DiscoveryKeyStatus::Absent
        ));
        discovery.rotate_now(&mut OsRng).unwrap();
        assert!(matches!(
            discovery.stored_status().unwrap(),
            DiscoveryKeyStatus::Present { epoch: 1 }
        ));
        discovery
            .lock_storage()
            .unwrap()
            .store(DISCOVERY_KEY, &[0xAAu8; 50])
            .unwrap();
        assert!(matches!(
            discovery.stored_status().unwrap(),
            DiscoveryKeyStatus::Malformed
        ));
    }

    #[test]
    fn rotate_now_establishes_generation_one_and_verifies() {
        let DiscoveryKeySetup {
            identity,
            manager: discovery,
        } = setup_with_identity();
        let rotated = discovery.rotate_now(&mut OsRng).unwrap();
        // Identity creation starts at inbox generation 1, not 0 (AE-IDN-07).
        assert_eq!(rotated.epoch(), 1);
        let bundle = discovery.current_bundle().unwrap();
        assert_eq!(bundle.epoch, 1);
        let loaded_identity = identity.load_identity().unwrap();
        assert!(verify_discovery_key_bundle(&bundle, loaded_identity.verifying_key()).is_ok());
    }

    /// The discovery key and the delivery capability share one generation, so rotation must
    /// replace both (AE-IDN-07). A rotation that advanced the generation while leaving the
    /// capability intact would leave a blocked contact still able to deliver (AE-BLK-08).
    #[test]
    fn rotation_replaces_the_delivery_capability() {
        let discovery = setup_with_identity().manager;
        discovery.rotate_now(&mut OsRng).unwrap();
        let before = *discovery.current_capability().unwrap().to_bytes();

        discovery.rotate_now(&mut OsRng).unwrap();
        let after = *discovery.current_capability().unwrap().to_bytes();

        assert_ne!(before, after);
    }

    #[test]
    fn capability_survives_a_reload() {
        let discovery = setup_with_identity().manager;
        discovery.rotate_now(&mut OsRng).unwrap();

        let first = *discovery.current_capability().unwrap().to_bytes();
        let second = *discovery.current_capability().unwrap().to_bytes();

        assert_eq!(first, second);
    }

    #[test]
    fn rotate_now_advances_the_generation() {
        let discovery = setup_with_identity().manager;
        assert_eq!(discovery.rotate_now(&mut OsRng).unwrap().epoch(), 1);
        assert_eq!(discovery.rotate_now(&mut OsRng).unwrap().epoch(), 2);
        assert_eq!(discovery.rotate_now(&mut OsRng).unwrap().epoch(), 3);
    }

    #[test]
    fn rotate_now_recovers_from_tampered_signature_preserving_epoch() {
        let discovery = setup_with_identity().manager;
        // Reach generation 2 first, so recovery to 3 proves the stored value is read, not reset.
        discovery.rotate_now(&mut OsRng).unwrap();
        let rotated = discovery.rotate_now(&mut OsRng).unwrap();
        assert_eq!(rotated.epoch(), 2);

        // Corrupt the signature of the generation-2 key.
        let mut blob = discovery
            .lock_storage()
            .unwrap()
            .load(DISCOVERY_KEY)
            .unwrap()
            .unwrap()
            .to_vec();
        blob[69] ^= 0x01;
        discovery
            .lock_storage()
            .unwrap()
            .store(DISCOVERY_KEY, &blob)
            .unwrap();
        assert!(matches!(
            discovery.current(),
            Err(DiscoveryKeyError::Corrupt)
        ));

        let recovered = discovery.rotate_now(&mut OsRng).unwrap();
        assert_eq!(recovered.epoch(), 3);
        assert!(discovery.current().is_ok());
    }

    #[test]
    fn rotate_now_rejects_malformed_blob() {
        let discovery = setup_with_identity().manager;
        discovery
            .lock_storage()
            .unwrap()
            .store(DISCOVERY_KEY, &[0xAAu8; 50])
            .unwrap();
        assert!(matches!(
            discovery.rotate_now(&mut OsRng),
            Err(DiscoveryKeyError::InvalidData(_))
        ));
    }

    #[test]
    fn rotate_now_without_identity_returns_identity_error() {
        let discovery = manager_without_identity();
        assert!(matches!(
            discovery.rotate_now(&mut OsRng),
            Err(DiscoveryKeyError::Identity(IdentityError::NotFound))
        ));
    }

    #[test]
    fn reset_clears_malformed_blob_then_rotation_starts_at_zero() {
        let discovery = setup_with_identity().manager;
        discovery
            .lock_storage()
            .unwrap()
            .store(DISCOVERY_KEY, &[0xAAu8; 50])
            .unwrap();
        discovery.reset().unwrap();
        assert_eq!(discovery.rotate_now(&mut OsRng).unwrap().epoch(), 1);
    }

    #[test]
    fn encode_decode_round_trip() {
        let identity = setup_with_identity().identity;
        let loaded = identity.load_identity().unwrap();
        let original = generate_discovery_key(&mut OsRng, loaded.signing_key_pair(), 9, FIXED_NOW);
        let capability = generate_recipient_delivery_capability(&mut OsRng);
        let blob = encode_discovery_key(&original, &capability);
        assert_eq!(blob.len(), DISCOVERY_KEY_BLOB_LEN);
        let restored = decode_discovery_key(&blob);
        assert_eq!(
            *decode_capability(&blob).to_bytes(),
            *capability.to_bytes(),
            "the capability must survive the same round trip as the key"
        );
        assert_eq!(
            original.public_key().as_bytes(),
            restored.public_key().as_bytes()
        );
        assert_eq!(
            original.verifying_key().as_bytes(),
            restored.verifying_key().as_bytes(),
        );
        assert_eq!(
            original.identity_signature().to_bytes(),
            restored.identity_signature().to_bytes()
        );
        assert_eq!(restored.epoch(), 9);
        assert_eq!(restored.created_at(), FIXED_NOW);
    }

    #[test]
    fn export_blob_without_stored_key_returns_not_found() {
        let discovery = setup_with_identity().manager;
        assert!(matches!(
            discovery.export_blob(),
            Err(DiscoveryKeyError::NotFound)
        ));
    }

    #[test]
    fn export_then_restore_blob_preserves_epoch_and_verifies() {
        let discovery = setup_with_identity().manager;
        discovery.rotate_now(&mut OsRng).unwrap();
        let exported = discovery.rotate_now(&mut OsRng).unwrap();
        assert_eq!(exported.epoch(), 2);
        let blob = discovery.export_blob().unwrap();

        discovery.reset().unwrap();
        discovery.restore_from_blob(&blob).unwrap();

        let restored = discovery.current().unwrap();
        assert_eq!(restored.epoch(), 2);
        assert_eq!(
            restored.public_key().as_bytes(),
            exported.public_key().as_bytes()
        );
    }

    #[test]
    fn validate_blob_accepts_stored_blob_and_rejects_malformed() {
        let discovery = setup_with_identity().manager;
        discovery.rotate_now(&mut OsRng).unwrap();
        let blob = discovery.export_blob().unwrap();
        assert!(DiscoveryKeyManager::validate_blob(&blob).is_ok());
        assert!(matches!(
            DiscoveryKeyManager::validate_blob(&[0xAAu8; 50]),
            Err(DiscoveryKeyError::InvalidData(_))
        ));
    }

    #[test]
    fn restore_from_blob_rejects_malformed_blob() {
        let discovery = setup_with_identity().manager;
        assert!(matches!(
            discovery.restore_from_blob(&[0xAAu8; 50]),
            Err(DiscoveryKeyError::InvalidData(_))
        ));
    }
}
