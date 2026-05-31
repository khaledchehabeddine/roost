use crate::clock::Clock;
use crate::identity::{IdentityError, IdentityManager};
use crate::storage::{SecureStorage, StorageError};
use aether_crypto::{
    DiscoveryKey, DiscoveryKeyBundle, generate_discovery_key, verify_discovery_key_bundle,
};
use rand::{CryptoRng, RngCore};
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use zeroize::Zeroizing;

const DISCOVERY_KEY_KEY: &str = "discovery/current";
const DISCOVERY_KEY_VERSION: u8 = 1;
// Blob layout: version (1) | epoch (4) | x25519 secret (32) | ed25519 secret (32) |
// identity signature (64) | created_at (8).
const DISCOVERY_KEY_BLOB_LEN: usize = 1 + 4 + 32 + 32 + 64 + 8;

/// Errors returned by discovery-key operations.
#[derive(Debug)]
pub enum DiscoveryKeyError {
    /// The system clock is before the Unix epoch.
    Clock,
    /// The stored discovery key's signature does not verify against the identity key.
    Corrupt,
    /// The rotation epoch counter cannot advance without overflowing.
    EpochExhausted,
    /// Loading the identity for discovery-key signing or verification returned an [`IdentityError`].
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
                    "stored discovery key signature does not match the identity key"
                )
            }
            DiscoveryKeyError::EpochExhausted => {
                write!(f, "discovery key epoch counter is exhausted")
            }
            DiscoveryKeyError::Identity(e) => write!(f, "identity: {e}"),
            DiscoveryKeyError::InvalidData(reason) => {
                write!(f, "invalid discovery key data: {reason}")
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

// The storage state of the discovery key, derived from length and version only (no signature check).
pub(crate) enum DiscoveryKeyStatus {
    // No discovery key is stored.
    Absent,
    // A well-formed discovery key is stored at this epoch.
    Present(u32),
    // A discovery key is stored but its bytes are malformed.
    Malformed,
}

// Manages discovery-key generation, rotation, verification, and persistence.
//
// Storage-lock discipline: the storage mutex is shared with the identity and signed-pre-key
// managers and is not reentrant, so no method holds the storage guard across an `IdentityManager`
// call. Each method scopes its guard to a single load or store, then loads the identity separately.
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

    // Reports whether a discovery key is absent, present (well-formed), or malformed, without
    // verifying its signature. Used for rotation epoch selection and first-launch recovery.
    pub(crate) fn stored_status(&self) -> Result<DiscoveryKeyStatus, DiscoveryKeyError> {
        let raw = {
            let storage = self.lock_storage()?;
            storage.load(DISCOVERY_KEY_KEY)?
        };
        let Some(raw) = raw else {
            return Ok(DiscoveryKeyStatus::Absent);
        };
        match checked_blob(&raw) {
            Ok(blob) => Ok(DiscoveryKeyStatus::Present(read_epoch(blob))),
            Err(_) => Ok(DiscoveryKeyStatus::Malformed),
        }
    }

    // Generates a fresh discovery key signed by the identity key and stores it.
    //
    // The next epoch is read from the stored key (no signature check), so a signature-mismatched
    // discovery key is recovered with its epoch preserved and incremented. A malformed stored key
    // returns `InvalidData` and must be cleared with `reset` first.
    pub(crate) fn rotate_now<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<DiscoveryKey, DiscoveryKeyError> {
        let identity = self.identity.load_identity()?;
        let now = self.now_secs()?;
        let epoch = match self.stored_status()? {
            DiscoveryKeyStatus::Absent => 0,
            DiscoveryKeyStatus::Present(current) => current
                .checked_add(1)
                .ok_or(DiscoveryKeyError::EpochExhausted)?,
            DiscoveryKeyStatus::Malformed => {
                return Err(DiscoveryKeyError::InvalidData(
                    "stored discovery key is malformed; reset before rotating".into(),
                ));
            }
        };
        let discovery_key = generate_discovery_key(rng, identity.signing_key_pair(), epoch, now);
        let blob = encode_discovery_key(&discovery_key);
        {
            let mut storage = self.lock_storage()?;
            storage.store(DISCOVERY_KEY_KEY, &*blob)?;
        }
        Ok(discovery_key)
    }

    // Use `KeyStore::reset` so the identity, discovery key, and signed pre-key are cleared together.
    pub(crate) fn reset(&self) -> Result<(), DiscoveryKeyError> {
        let mut storage = self.lock_storage()?;
        Ok(storage.delete(DISCOVERY_KEY_KEY)?)
    }

    // Loads and decodes the stored discovery key without verifying its signature. The storage guard
    // is released before returning, so callers may then load the identity safely.
    fn load_stored(&self) -> Result<DiscoveryKey, DiscoveryKeyError> {
        let raw = {
            let storage = self.lock_storage()?;
            storage.load(DISCOVERY_KEY_KEY)?
        };
        let raw = raw.ok_or(DiscoveryKeyError::NotFound)?;
        Ok(decode_discovery_key(checked_blob(&raw)?))
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

fn encode_discovery_key(discovery_key: &DiscoveryKey) -> Zeroizing<[u8; DISCOVERY_KEY_BLOB_LEN]> {
    let mut blob = Zeroizing::new([0u8; DISCOVERY_KEY_BLOB_LEN]);
    blob[0] = DISCOVERY_KEY_VERSION;
    blob[1..5].copy_from_slice(&discovery_key.epoch().to_be_bytes());
    blob[5..37].copy_from_slice(&*discovery_key.key_agreement_secret_bytes());
    blob[37..69].copy_from_slice(&*discovery_key.signing_secret_bytes());
    blob[69..133].copy_from_slice(&discovery_key.identity_signature().to_bytes());
    blob[133..DISCOVERY_KEY_BLOB_LEN].copy_from_slice(&discovery_key.created_at().to_be_bytes());
    blob
}

fn decode_discovery_key(blob: &[u8; DISCOVERY_KEY_BLOB_LEN]) -> DiscoveryKey {
    let epoch = read_epoch(blob);
    let mut key_agreement_secret = [0u8; 32];
    key_agreement_secret.copy_from_slice(&blob[5..37]);
    let mut signing_secret = [0u8; 32];
    signing_secret.copy_from_slice(&blob[37..69]);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&blob[69..133]);
    let mut created_at_bytes = [0u8; 8];
    created_at_bytes.copy_from_slice(&blob[133..DISCOVERY_KEY_BLOB_LEN]);
    DiscoveryKey::from_parts(
        key_agreement_secret,
        signing_secret,
        signature,
        epoch,
        u64::from_be_bytes(created_at_bytes),
    )
}

fn read_epoch(blob: &[u8; DISCOVERY_KEY_BLOB_LEN]) -> u32 {
    let mut epoch_bytes = [0u8; 4];
    epoch_bytes.copy_from_slice(&blob[1..5]);
    u32::from_be_bytes(epoch_bytes)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::ManualClock;
    use crate::storage::InMemorySecureStorage;
    use rand::rngs::OsRng;

    const FIXED_NOW: u64 = 1_700_000_000;

    fn shared_storage() -> Arc<Mutex<Box<dyn SecureStorage>>> {
        Arc::new(Mutex::new(Box::new(InMemorySecureStorage::new())))
    }

    fn manager_with_identity() -> (Arc<IdentityManager>, DiscoveryKeyManager) {
        let storage = shared_storage();
        let identity = Arc::new(IdentityManager::new(Arc::clone(&storage)));
        identity.generate_identity(&mut OsRng).unwrap();
        let discovery = DiscoveryKeyManager::new(
            storage,
            Arc::clone(&identity),
            Arc::new(ManualClock::new(FIXED_NOW)),
        );
        (identity, discovery)
    }

    fn manager_without_identity() -> DiscoveryKeyManager {
        let storage = shared_storage();
        let identity = Arc::new(IdentityManager::new(Arc::clone(&storage)));
        DiscoveryKeyManager::new(storage, identity, Arc::new(ManualClock::new(FIXED_NOW)))
    }

    #[test]
    fn rotate_now_establishes_epoch_zero_and_verifies() {
        let (identity, discovery) = manager_with_identity();
        let rotated = discovery.rotate_now(&mut OsRng).unwrap();
        assert_eq!(rotated.epoch(), 0);
        let bundle = discovery.current_bundle().unwrap();
        assert_eq!(bundle.epoch, 0);
        let loaded_identity = identity.load_identity().unwrap();
        assert!(verify_discovery_key_bundle(&bundle, loaded_identity.verifying_key()).is_ok());
    }

    #[test]
    fn rotate_now_advances_epoch() {
        let (_identity, discovery) = manager_with_identity();
        assert_eq!(discovery.rotate_now(&mut OsRng).unwrap().epoch(), 0);
        assert_eq!(discovery.rotate_now(&mut OsRng).unwrap().epoch(), 1);
        assert_eq!(discovery.rotate_now(&mut OsRng).unwrap().epoch(), 2);
    }

    #[test]
    fn current_without_stored_key_returns_not_found() {
        let (_identity, discovery) = manager_with_identity();
        assert!(matches!(
            discovery.current(),
            Err(DiscoveryKeyError::NotFound)
        ));
    }

    #[test]
    fn current_returns_invalid_data_for_malformed_blob() {
        let (_identity, discovery) = manager_with_identity();
        discovery
            .storage
            .lock()
            .unwrap()
            .store(DISCOVERY_KEY_KEY, &[0xAAu8; 50])
            .unwrap();
        assert!(matches!(
            discovery.current(),
            Err(DiscoveryKeyError::InvalidData(_))
        ));
    }

    #[test]
    fn current_returns_corrupt_for_tampered_signature() {
        let (_identity, discovery) = manager_with_identity();
        discovery.rotate_now(&mut OsRng).unwrap();
        // Flip a byte inside the stored signature region; the blob stays well-formed.
        let mut blob = discovery
            .storage
            .lock()
            .unwrap()
            .load(DISCOVERY_KEY_KEY)
            .unwrap()
            .unwrap()
            .to_vec();
        blob[69] ^= 0x01;
        discovery
            .storage
            .lock()
            .unwrap()
            .store(DISCOVERY_KEY_KEY, &blob)
            .unwrap();
        assert!(matches!(
            discovery.current(),
            Err(DiscoveryKeyError::Corrupt)
        ));
    }

    #[test]
    fn rotate_now_recovers_from_tampered_signature_preserving_epoch() {
        let (_identity, discovery) = manager_with_identity();
        discovery.rotate_now(&mut OsRng).unwrap();
        let rotated = discovery.rotate_now(&mut OsRng).unwrap();
        assert_eq!(rotated.epoch(), 1);

        // Corrupt the signature of the epoch-1 key.
        let mut blob = discovery
            .storage
            .lock()
            .unwrap()
            .load(DISCOVERY_KEY_KEY)
            .unwrap()
            .unwrap()
            .to_vec();
        blob[69] ^= 0x01;
        discovery
            .storage
            .lock()
            .unwrap()
            .store(DISCOVERY_KEY_KEY, &blob)
            .unwrap();
        assert!(matches!(
            discovery.current(),
            Err(DiscoveryKeyError::Corrupt)
        ));

        // Rotation recovers: the well-formed (if unverifiable) epoch is read and incremented.
        let recovered = discovery.rotate_now(&mut OsRng).unwrap();
        assert_eq!(recovered.epoch(), 2);
        assert!(discovery.current().is_ok());
    }

    #[test]
    fn rotate_now_rejects_malformed_blob() {
        let (_identity, discovery) = manager_with_identity();
        discovery
            .storage
            .lock()
            .unwrap()
            .store(DISCOVERY_KEY_KEY, &[0xAAu8; 50])
            .unwrap();
        assert!(matches!(
            discovery.rotate_now(&mut OsRng),
            Err(DiscoveryKeyError::InvalidData(_))
        ));
    }

    #[test]
    fn reset_clears_malformed_blob_then_rotation_starts_at_zero() {
        let (_identity, discovery) = manager_with_identity();
        discovery
            .storage
            .lock()
            .unwrap()
            .store(DISCOVERY_KEY_KEY, &[0xAAu8; 50])
            .unwrap();
        discovery.reset().unwrap();
        assert_eq!(discovery.rotate_now(&mut OsRng).unwrap().epoch(), 0);
    }

    #[test]
    fn rotate_now_rejects_exhausted_epoch() {
        let (identity, discovery) = manager_with_identity();
        // Store a well-formed discovery key at the maximum epoch.
        let loaded = identity.load_identity().unwrap();
        let max_epoch_key =
            generate_discovery_key(&mut OsRng, loaded.signing_key_pair(), u32::MAX, FIXED_NOW);
        let blob = encode_discovery_key(&max_epoch_key);
        discovery
            .storage
            .lock()
            .unwrap()
            .store(DISCOVERY_KEY_KEY, &*blob)
            .unwrap();
        assert!(matches!(
            discovery.rotate_now(&mut OsRng),
            Err(DiscoveryKeyError::EpochExhausted)
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
    fn stored_status_reports_absent_present_and_malformed() {
        let (_identity, discovery) = manager_with_identity();
        assert!(matches!(
            discovery.stored_status().unwrap(),
            DiscoveryKeyStatus::Absent
        ));
        discovery.rotate_now(&mut OsRng).unwrap();
        assert!(matches!(
            discovery.stored_status().unwrap(),
            DiscoveryKeyStatus::Present(0)
        ));
        discovery
            .storage
            .lock()
            .unwrap()
            .store(DISCOVERY_KEY_KEY, &[0xAAu8; 50])
            .unwrap();
        assert!(matches!(
            discovery.stored_status().unwrap(),
            DiscoveryKeyStatus::Malformed
        ));
    }

    #[test]
    fn encode_decode_round_trip() {
        let (identity, _discovery) = manager_with_identity();
        let loaded = identity.load_identity().unwrap();
        let original = generate_discovery_key(&mut OsRng, loaded.signing_key_pair(), 9, FIXED_NOW);
        let blob = encode_discovery_key(&original);
        assert_eq!(blob.len(), DISCOVERY_KEY_BLOB_LEN);
        let restored = decode_discovery_key(&blob);
        assert_eq!(
            restored.public_key().as_bytes(),
            original.public_key().as_bytes()
        );
        assert_eq!(
            restored.verifying_key().as_bytes(),
            original.verifying_key().as_bytes()
        );
        assert_eq!(restored.epoch(), 9);
        assert_eq!(restored.created_at(), FIXED_NOW);
        assert_eq!(
            restored.identity_signature().to_bytes(),
            original.identity_signature().to_bytes()
        );
    }

    #[test]
    fn persistence_round_trip_via_two_managers() {
        let storage = shared_storage();
        let identity = Arc::new(IdentityManager::new(Arc::clone(&storage)));
        identity.generate_identity(&mut OsRng).unwrap();

        let manager_a = DiscoveryKeyManager::new(
            Arc::clone(&storage),
            Arc::clone(&identity),
            Arc::new(ManualClock::new(FIXED_NOW)),
        );
        manager_a.rotate_now(&mut OsRng).unwrap();
        let first = manager_a.current_bundle().unwrap();
        drop(manager_a);

        let manager_b =
            DiscoveryKeyManager::new(storage, identity, Arc::new(ManualClock::new(FIXED_NOW)));
        let second = manager_b.current_bundle().unwrap();
        assert_eq!(first.public_key.as_bytes(), second.public_key.as_bytes());
        assert_eq!(first.epoch, second.epoch);
    }

    #[test]
    fn rotation_is_deterministic_under_seed_and_clock() {
        // Same seed + clock must yield a byte-identical bundle; a different seed must not.
        fn rotate(seed: [u8; 32]) -> ([u8; 32], [u8; 32], u32, u64) {
            use crate::test_support::Sandbox;

            let mut sandbox = Sandbox::new(seed, FIXED_NOW);
            let (identity, discovery, _signed_prekey) = sandbox.managers();
            identity.generate_identity(&mut sandbox.rng).unwrap();
            let bundle = discovery.rotate_now(&mut sandbox.rng).unwrap().bundle();
            (
                *bundle.public_key.as_bytes(),
                bundle.verifying_key.to_bytes(),
                bundle.epoch,
                bundle.created_at,
            )
        }

        assert_eq!(rotate([3u8; 32]), rotate([3u8; 32]));
        assert_ne!(rotate([3u8; 32]).0, rotate([4u8; 32]).0);
    }
}
