use crate::clock::Clock;
use crate::discovery_key::{DiscoveryKeyError, DiscoveryKeyManager};
use crate::storage::{SecureStorage, StorageError};
use aether_crypto::{SignedPreKey, SignedPreKeyBundle, generate_signed_prekey_for_discovery_key};
use rand::{CryptoRng, RngCore};
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use zeroize::Zeroizing;

pub(crate) const SIGNED_PREKEY_ROTATION_WINDOW_DAYS: u64 = 7;

const SIGNED_PREKEY_KEY: &str = "prekey/signed";
const SIGNED_PREKEY_VERSION: u8 = 1;
// Blob layout: version (1 byte) | secret (32 bytes) | signature (64 bytes) | created_at (8 bytes).
const SIGNED_PREKEY_BLOB_LEN: usize = 1 + 32 + 64 + 8;
const SECONDS_PER_DAY: u64 = 86_400;
// Rotate far-future timestamps so clock manipulation cannot freeze rotation forever.
const FUTURE_TIMESTAMP_TOLERANCE_SECS: u64 = 30 * SECONDS_PER_DAY;

/// Errors returned by signed-pre-key operations.
#[derive(Debug)]
pub enum SignedPreKeyError {
    /// The system clock is before the Unix epoch.
    Clock,
    /// Loading the discovery key for signed-pre-key rotation returned a [`DiscoveryKeyError`].
    Discovery(DiscoveryKeyError),
    /// Stored signed-pre-key data is malformed.
    InvalidData(String),
    /// The internal storage lock was poisoned by a panicked thread.
    LockPoisoned,
    /// No signed pre-key is stored.
    NotFound,
    /// The underlying [`SecureStorage`] returned an error.
    Storage(StorageError),
}

impl fmt::Display for SignedPreKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SignedPreKeyError::Clock => write!(f, "system clock is before Unix epoch"),
            SignedPreKeyError::Discovery(e) => write!(f, "discovery key: {e}"),
            SignedPreKeyError::InvalidData(reason) => {
                write!(f, "invalid signed pre-key data: {reason}")
            }
            SignedPreKeyError::LockPoisoned => write!(f, "internal lock poisoned"),
            SignedPreKeyError::NotFound => write!(f, "no signed pre-key stored"),
            SignedPreKeyError::Storage(e) => write!(f, "storage: {e}"),
        }
    }
}

impl Error for SignedPreKeyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            SignedPreKeyError::Discovery(e) => Some(e),
            SignedPreKeyError::Storage(e) => Some(e),
            _ => None,
        }
    }
}

impl From<DiscoveryKeyError> for SignedPreKeyError {
    fn from(e: DiscoveryKeyError) -> Self {
        SignedPreKeyError::Discovery(e)
    }
}

impl From<StorageError> for SignedPreKeyError {
    fn from(e: StorageError) -> Self {
        SignedPreKeyError::Storage(e)
    }
}

// Manages signed-pre-key generation, rotation, and persistence.
pub(crate) struct SignedPreKeyManager {
    storage: Arc<Mutex<Box<dyn SecureStorage>>>,
    discovery: Arc<DiscoveryKeyManager>,
    clock: Arc<dyn Clock>,
}

impl SignedPreKeyManager {
    pub(crate) fn new(
        storage: Arc<Mutex<Box<dyn SecureStorage>>>,
        discovery: Arc<DiscoveryKeyManager>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        SignedPreKeyManager {
            storage,
            discovery,
            clock,
        }
    }

    // Loads the secret signed pre-key from storage.
    pub(crate) fn current(&self) -> Result<SignedPreKey, SignedPreKeyError> {
        let storage = self.lock_storage()?;
        let raw = storage
            .load(SIGNED_PREKEY_KEY)?
            .ok_or(SignedPreKeyError::NotFound)?;
        Ok(decode_signed_prekey(checked_blob(&raw)?))
    }

    // Returns the signed-pre-key bundle to distribute to peers.
    pub(crate) fn current_bundle(&self) -> Result<SignedPreKeyBundle, SignedPreKeyError> {
        Ok(self.current()?.bundle())
    }

    // Rotates missing, stale, and far-future signed pre-keys. Slightly future timestamps stay
    // valid to tolerate clock skew.
    pub(crate) fn rotate_if_stale<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<Option<SignedPreKey>, SignedPreKeyError> {
        let now = self.now_secs()?;
        let needs_rotation = match self.read_stored_created_at()? {
            None => true,
            Some(timestamp) if timestamp > now + FUTURE_TIMESTAMP_TOLERANCE_SECS => true,
            Some(timestamp) if timestamp > now => false,
            Some(timestamp) => {
                now - timestamp > SIGNED_PREKEY_ROTATION_WINDOW_DAYS * SECONDS_PER_DAY
            }
        };
        if needs_rotation {
            Ok(Some(self.rotate_now(rng)?))
        } else {
            Ok(None)
        }
    }

    // Use `KeyStore::reset` so the identity and signed pre-key are cleared together.
    pub(crate) fn reset(&self) -> Result<(), SignedPreKeyError> {
        let mut storage = self.lock_storage()?;
        Ok(storage.delete(SIGNED_PREKEY_KEY)?)
    }

    // Forces an immediate signed-pre-key rotation.
    pub(crate) fn rotate_now<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<SignedPreKey, SignedPreKeyError> {
        let discovery_key = self.discovery.current()?;
        let now = self.now_secs()?;
        let signed_prekey = generate_signed_prekey_for_discovery_key(rng, &discovery_key, now);
        let blob = encode_signed_prekey(&signed_prekey);
        let mut storage = self.lock_storage()?;
        storage.store(SIGNED_PREKEY_KEY, &*blob)?;
        Ok(signed_prekey)
    }

    fn read_stored_created_at(&self) -> Result<Option<u64>, SignedPreKeyError> {
        let storage = self.lock_storage()?;
        let Some(raw) = storage.load(SIGNED_PREKEY_KEY)? else {
            return Ok(None);
        };
        let blob = checked_blob(&raw)?;
        let mut timestamp_bytes = [0u8; 8];
        timestamp_bytes.copy_from_slice(&blob[97..SIGNED_PREKEY_BLOB_LEN]);
        Ok(Some(u64::from_be_bytes(timestamp_bytes)))
    }

    fn lock_storage(&self) -> Result<MutexGuard<'_, Box<dyn SecureStorage>>, SignedPreKeyError> {
        self.storage
            .lock()
            .map_err(|_| SignedPreKeyError::LockPoisoned)
    }

    fn now_secs(&self) -> Result<u64, SignedPreKeyError> {
        self.clock
            .now_unix_secs()
            .map_err(|_| SignedPreKeyError::Clock)
    }
}

fn encode_signed_prekey(signed_prekey: &SignedPreKey) -> Zeroizing<[u8; SIGNED_PREKEY_BLOB_LEN]> {
    let mut blob = Zeroizing::new([0u8; SIGNED_PREKEY_BLOB_LEN]);
    blob[0] = SIGNED_PREKEY_VERSION;
    blob[1..33].copy_from_slice(&*signed_prekey.to_secret_bytes());
    blob[33..97].copy_from_slice(&signed_prekey.signature().to_bytes());
    blob[97..SIGNED_PREKEY_BLOB_LEN].copy_from_slice(&signed_prekey.created_at().to_be_bytes());
    blob
}

fn decode_signed_prekey(blob: &[u8; SIGNED_PREKEY_BLOB_LEN]) -> SignedPreKey {
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&blob[1..33]);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&blob[33..97]);
    let mut timestamp_bytes = [0u8; 8];
    timestamp_bytes.copy_from_slice(&blob[97..SIGNED_PREKEY_BLOB_LEN]);
    let created_at = u64::from_be_bytes(timestamp_bytes);
    SignedPreKey::from_secret_bytes(secret, signature, created_at)
}

fn checked_blob(raw: &[u8]) -> Result<&[u8; SIGNED_PREKEY_BLOB_LEN], SignedPreKeyError> {
    let blob: &[u8; SIGNED_PREKEY_BLOB_LEN] = raw.try_into().map_err(|_| {
        SignedPreKeyError::InvalidData(format!(
            "expected {SIGNED_PREKEY_BLOB_LEN} bytes, got {}",
            raw.len()
        ))
    })?;
    if blob[0] != SIGNED_PREKEY_VERSION {
        return Err(SignedPreKeyError::InvalidData(format!(
            "unsupported signed pre-key format version: {}",
            blob[0]
        )));
    }
    Ok(blob)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::ManualClock;
    use crate::identity::IdentityManager;
    use crate::storage::InMemorySecureStorage;
    use aether_crypto::{generate_signed_prekey, generate_signing_key_pair, verify_bundle};
    use rand::rngs::OsRng;

    const FIXED_NOW: u64 = 1_700_000_000;

    fn shared_storage() -> Arc<Mutex<Box<dyn SecureStorage>>> {
        Arc::new(Mutex::new(Box::new(InMemorySecureStorage::new())))
    }

    // Identity + established discovery key (epoch 0) + signed-pre-key manager, sharing storage.
    fn manager_with_discovery() -> (Arc<DiscoveryKeyManager>, SignedPreKeyManager) {
        let storage = shared_storage();
        let identity = Arc::new(IdentityManager::new(Arc::clone(&storage)));
        identity.generate_identity(&mut OsRng).unwrap();
        let discovery = Arc::new(DiscoveryKeyManager::new(
            Arc::clone(&storage),
            identity,
            Arc::new(ManualClock::new(FIXED_NOW)),
        ));
        discovery.rotate_now(&mut OsRng).unwrap();
        let signed_prekey = SignedPreKeyManager::new(
            storage,
            Arc::clone(&discovery),
            Arc::new(ManualClock::new(FIXED_NOW)),
        );
        (discovery, signed_prekey)
    }

    // A signed-pre-key manager whose discovery manager has no identity and no discovery key.
    fn manager_without_discovery_key() -> SignedPreKeyManager {
        let storage = shared_storage();
        let identity = Arc::new(IdentityManager::new(Arc::clone(&storage)));
        let discovery = Arc::new(DiscoveryKeyManager::new(
            Arc::clone(&storage),
            identity,
            Arc::new(ManualClock::new(FIXED_NOW)),
        ));
        SignedPreKeyManager::new(storage, discovery, Arc::new(ManualClock::new(FIXED_NOW)))
    }

    #[test]
    fn current_without_stored_signed_prekey_returns_not_found() {
        let (_discovery, manager) = manager_with_discovery();
        assert!(matches!(
            manager.current(),
            Err(SignedPreKeyError::NotFound)
        ));
    }

    #[test]
    fn current_returns_invalid_data_for_corrupt_blob() {
        let (_discovery, manager) = manager_with_discovery();
        manager
            .storage
            .lock()
            .unwrap()
            .store(SIGNED_PREKEY_KEY, &[0xAAu8; 50])
            .unwrap();
        assert!(matches!(
            manager.current(),
            Err(SignedPreKeyError::InvalidData(_))
        ));
    }

    #[test]
    fn current_bundle_does_not_require_discovery_key() {
        let manager = manager_without_discovery_key();
        let signing_key = generate_signing_key_pair(&mut OsRng);
        let signed_prekey = generate_signed_prekey(&mut OsRng, &signing_key, FIXED_NOW);
        let blob = encode_signed_prekey(&signed_prekey);
        manager
            .storage
            .lock()
            .unwrap()
            .store(SIGNED_PREKEY_KEY, &*blob)
            .unwrap();

        let bundle = manager.current_bundle().unwrap();
        assert_eq!(
            bundle.public_key.as_bytes(),
            signed_prekey.public().as_bytes()
        );
    }

    #[test]
    fn rotate_if_stale_seeds_first_signed_prekey() {
        let (discovery, manager) = manager_with_discovery();
        let rotated = manager
            .rotate_if_stale(&mut OsRng)
            .unwrap()
            .expect("first call must rotate");
        let bundle = manager.current_bundle().unwrap();
        assert_eq!(
            rotated.public().as_bytes(),
            bundle.public_key.as_bytes(),
            "returned signed pre-key must match persisted bundle",
        );
        // The signed pre-key is signed by the discovery key, not the identity key.
        let discovery_bundle = discovery.current_bundle().unwrap();
        assert!(verify_bundle(&bundle, &discovery_bundle.verifying_key).is_ok());
    }

    #[test]
    fn rotate_if_stale_keeps_fresh_signed_prekey() {
        let (_discovery, manager) = manager_with_discovery();
        assert!(manager.rotate_if_stale(&mut OsRng).unwrap().is_some());
        let initial_public_key = manager.current_bundle().unwrap().public_key;
        let second_rotation = manager.rotate_if_stale(&mut OsRng).unwrap();
        assert!(
            second_rotation.is_none(),
            "fresh signed pre-key must not rotate"
        );
        let current_public_key = manager.current_bundle().unwrap().public_key;
        assert_eq!(initial_public_key.as_bytes(), current_public_key.as_bytes());
    }

    #[test]
    fn rotate_if_stale_replaces_backdated_signed_prekey() {
        let (_discovery, manager) = manager_with_discovery();
        manager.rotate_if_stale(&mut OsRng).unwrap();
        let original_public_key = manager.current_bundle().unwrap().public_key;

        // The signer is irrelevant here; rotation staleness only reads the stored `created_at`.
        let signing_key = generate_signing_key_pair(&mut OsRng);
        let backdated_timestamp =
            FIXED_NOW - (SIGNED_PREKEY_ROTATION_WINDOW_DAYS + 1) * SECONDS_PER_DAY;
        let stale_signed_prekey =
            generate_signed_prekey(&mut OsRng, &signing_key, backdated_timestamp);
        let blob = encode_signed_prekey(&stale_signed_prekey);
        manager
            .storage
            .lock()
            .unwrap()
            .store(SIGNED_PREKEY_KEY, &*blob)
            .unwrap();

        let rotated = manager
            .rotate_if_stale(&mut OsRng)
            .unwrap()
            .expect("backdated signed pre-key must trigger rotation");
        let rotated_public_key = manager.current_bundle().unwrap().public_key;
        assert_eq!(
            rotated.public().as_bytes(),
            rotated_public_key.as_bytes(),
            "returned signed pre-key must match persisted bundle",
        );
        assert_ne!(
            rotated_public_key.as_bytes(),
            stale_signed_prekey.public().as_bytes()
        );
        assert_ne!(
            rotated_public_key.as_bytes(),
            original_public_key.as_bytes()
        );
    }

    #[test]
    fn future_created_at_does_not_rotate() {
        let (_discovery, manager) = manager_with_discovery();
        let signing_key = generate_signing_key_pair(&mut OsRng);
        let timestamp = FIXED_NOW + 100_000;
        let signed_prekey = generate_signed_prekey(&mut OsRng, &signing_key, timestamp);
        let blob = encode_signed_prekey(&signed_prekey);
        manager
            .storage
            .lock()
            .unwrap()
            .store(SIGNED_PREKEY_KEY, &*blob)
            .unwrap();

        manager.rotate_if_stale(&mut OsRng).unwrap();
        let public_key = manager.current_bundle().unwrap().public_key;
        assert_eq!(public_key.as_bytes(), signed_prekey.public().as_bytes());
    }

    #[test]
    fn far_future_created_at_triggers_rotation() {
        let (_discovery, manager) = manager_with_discovery();
        let signing_key = generate_signing_key_pair(&mut OsRng);
        let timestamp = FIXED_NOW + FUTURE_TIMESTAMP_TOLERANCE_SECS * 10;
        let signed_prekey = generate_signed_prekey(&mut OsRng, &signing_key, timestamp);
        let blob = encode_signed_prekey(&signed_prekey);
        manager
            .storage
            .lock()
            .unwrap()
            .store(SIGNED_PREKEY_KEY, &*blob)
            .unwrap();

        manager.rotate_if_stale(&mut OsRng).unwrap();
        let public_key = manager.current_bundle().unwrap().public_key;
        assert_ne!(public_key.as_bytes(), signed_prekey.public().as_bytes());
    }

    #[test]
    fn rotate_if_stale_rejects_unsupported_version() {
        let (_discovery, manager) = manager_with_discovery();
        let mut blob = [0u8; SIGNED_PREKEY_BLOB_LEN];
        blob[0] = 99;
        manager
            .storage
            .lock()
            .unwrap()
            .store(SIGNED_PREKEY_KEY, &blob)
            .unwrap();
        assert!(matches!(
            manager.rotate_if_stale(&mut OsRng),
            Err(SignedPreKeyError::InvalidData(reason)) if reason.contains("version")
        ));
    }

    #[test]
    fn rotate_if_stale_without_discovery_key_returns_not_found() {
        let manager = manager_without_discovery_key();
        assert!(matches!(
            manager.rotate_if_stale(&mut OsRng),
            Err(SignedPreKeyError::Discovery(DiscoveryKeyError::NotFound))
        ));
    }

    #[test]
    fn rotate_now_without_discovery_key_returns_not_found() {
        let manager = manager_without_discovery_key();
        assert!(matches!(
            manager.rotate_now(&mut OsRng),
            Err(SignedPreKeyError::Discovery(DiscoveryKeyError::NotFound))
        ));
    }

    #[test]
    fn encode_decode_signed_prekey_round_trip() {
        let identity_signing_key = generate_signing_key_pair(&mut OsRng);
        let original = generate_signed_prekey(&mut OsRng, &identity_signing_key, FIXED_NOW);
        let blob = encode_signed_prekey(&original);
        assert_eq!(blob.len(), SIGNED_PREKEY_BLOB_LEN);
        let restored = decode_signed_prekey(&blob);
        assert_eq!(restored.public().as_bytes(), original.public().as_bytes());
        assert_eq!(
            restored.signature().to_bytes(),
            original.signature().to_bytes()
        );
        assert_eq!(restored.created_at(), original.created_at());
    }

    #[test]
    fn checked_blob_rejects_short_blob() {
        assert!(matches!(
            checked_blob(&[0u8; 50]),
            Err(SignedPreKeyError::InvalidData(_))
        ));
    }

    #[test]
    fn checked_blob_rejects_long_blob() {
        assert!(matches!(
            checked_blob(&[0u8; 200]),
            Err(SignedPreKeyError::InvalidData(_))
        ));
    }

    #[test]
    fn checked_blob_rejects_unsupported_version() {
        let mut blob = [0u8; SIGNED_PREKEY_BLOB_LEN];
        blob[0] = 99;
        assert!(matches!(
            checked_blob(&blob),
            Err(SignedPreKeyError::InvalidData(reason)) if reason.contains("version")
        ));
    }

    #[test]
    fn persistence_round_trip_via_two_managers() {
        let storage = shared_storage();
        let identity = Arc::new(IdentityManager::new(Arc::clone(&storage)));
        identity.generate_identity(&mut OsRng).unwrap();
        let discovery = Arc::new(DiscoveryKeyManager::new(
            Arc::clone(&storage),
            identity,
            Arc::new(ManualClock::new(FIXED_NOW)),
        ));
        discovery.rotate_now(&mut OsRng).unwrap();

        let manager_a = SignedPreKeyManager::new(
            Arc::clone(&storage),
            Arc::clone(&discovery),
            Arc::new(ManualClock::new(FIXED_NOW)),
        );
        manager_a.rotate_if_stale(&mut OsRng).unwrap();
        let first_public_key = manager_a.current_bundle().unwrap().public_key;
        drop(manager_a);

        let manager_b =
            SignedPreKeyManager::new(storage, discovery, Arc::new(ManualClock::new(FIXED_NOW)));
        let second_public_key = manager_b.current_bundle().unwrap().public_key;
        assert_eq!(first_public_key.as_bytes(), second_public_key.as_bytes());
    }

    #[test]
    fn rotation_is_deterministic_under_seed_and_clock() {
        // Same seed + clock must yield a byte-identical bundle (public key, signature, created_at)
        // and a different seed must not.
        fn rotate(seed: [u8; 32]) -> ([u8; 32], [u8; 64], u64) {
            use crate::test_support::Sandbox;

            let mut sandbox = Sandbox::new(seed, FIXED_NOW);
            let (identity, discovery, signed_prekey) = sandbox.managers();
            identity.generate_identity(&mut sandbox.rng).unwrap();
            discovery.rotate_now(&mut sandbox.rng).unwrap();
            let bundle = signed_prekey.rotate_now(&mut sandbox.rng).unwrap().bundle();
            (
                *bundle.public_key.as_bytes(),
                bundle.signature.to_bytes(),
                bundle.created_at,
            )
        }

        assert_eq!(rotate([7u8; 32]), rotate([7u8; 32]));
        assert_ne!(rotate([7u8; 32]).0, rotate([8u8; 32]).0);
    }
}
