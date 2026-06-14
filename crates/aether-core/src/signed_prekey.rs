use crate::clock::Clock;
use crate::discovery_key::{DiscoveryKeyError, DiscoveryKeyManager};
use crate::storage::{SecureStorage, StorageError};
use aether_crypto::{SignedPreKey, SignedPreKeyBundle, generate_signed_prekey_for_discovery_key};
use rand::{CryptoRng, RngCore};
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub(crate) const SIGNED_PREKEY_ROTATION_WINDOW_DAYS: u64 = 7;

const SIGNED_PREKEY_KEY: &str = "prekey/signed";
const SIGNED_PREKEY_VERSION_V1: u8 = 1;
const SIGNED_PREKEY_VERSION_V2: u8 = 2;
const SIGNED_PREKEY_VERSION: u8 = 3;
// Record layout: secret (32) | signature (64) | epoch (4) | created_at (8).
const SIGNED_PREKEY_RECORD_LEN: usize = 32 + 64 + 4 + 8;
// V1 blob layout: version (1) | current record.
const SIGNED_PREKEY_V1_BLOB_LEN: usize = 1 + SIGNED_PREKEY_RECORD_LEN;
// V2 blob layout: version (1) | current record | retained flag (1) | retained record.
const SIGNED_PREKEY_V2_BLOB_LEN: usize =
    1 + SIGNED_PREKEY_RECORD_LEN + 1 + SIGNED_PREKEY_RECORD_LEN;
// V3 blob layout: version (1) | current record | retained flag (1) | retained record | superseded_at (8).
const SIGNED_PREKEY_BLOB_LEN: usize = SIGNED_PREKEY_V2_BLOB_LEN + 8;
const SECONDS_PER_DAY: u64 = 86_400;
const SIGNED_PREKEY_GRACE_WINDOW_SECS: u64 = SIGNED_PREKEY_ROTATION_WINDOW_DAYS * SECONDS_PER_DAY;
// Rotate far-future timestamps so clock manipulation cannot freeze rotation forever.
const FUTURE_TIMESTAMP_TOLERANCE_SECS: u64 = 30 * SECONDS_PER_DAY;

/// Errors returned by signed-pre-key operations.
#[derive(Debug)]
pub enum SignedPreKeyError {
    /// The system clock is before the Unix epoch.
    Clock,
    /// The stored signed pre-key's signature does not verify against the current discovery key.
    Corrupt,
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
            SignedPreKeyError::Corrupt => {
                write!(
                    f,
                    "stored signed pre-key signature does not match the discovery key"
                )
            }
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

#[derive(Zeroize, ZeroizeOnDrop)]
struct StoredSignedPreKeys {
    current: SignedPreKey,
    retained: Option<RetainedSignedPreKey>,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct RetainedSignedPreKey {
    prekey: SignedPreKey,
    superseded_at: u64,
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
        let now = self.now_secs()?;
        let store = self.load_store(now)?;
        Ok(store.current.clone_for_storage())
    }

    // Returns the signed-pre-key bundle to distribute to peers.
    pub(crate) fn current_bundle(&self) -> Result<SignedPreKeyBundle, SignedPreKeyError> {
        Ok(self.current()?.bundle())
    }

    #[allow(dead_code)]
    pub(crate) fn prekey_for_public_key(
        &self,
        epoch: u32,
        public_key: &[u8; 32],
    ) -> Result<SignedPreKey, SignedPreKeyError> {
        let now = self.now_secs()?;
        let store = self.load_store(now)?;
        matching_prekey(&store.current, epoch, public_key)
            .or_else(|| {
                store
                    .retained
                    .as_ref()
                    .and_then(|retained| matching_prekey(&retained.prekey, epoch, public_key))
            })
            .ok_or(SignedPreKeyError::NotFound)
    }

    // Rotates missing, stale, and far-future signed pre-keys. Slightly future timestamps stay
    // valid to tolerate clock skew.
    pub(crate) fn rotate_if_stale<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<Option<SignedPreKey>, SignedPreKeyError> {
        let now = self.now_secs()?;
        let needs_rotation = match self.read_stored_created_at(now)? {
            None => true,
            Some(timestamp) if timestamp > now + FUTURE_TIMESTAMP_TOLERANCE_SECS => true,
            Some(timestamp) if timestamp > now => false,
            Some(timestamp) => now - timestamp > SIGNED_PREKEY_GRACE_WINDOW_SECS,
        };
        if needs_rotation {
            Ok(Some(self.rotate_now_at(rng, now)?))
        } else {
            Ok(None)
        }
    }

    // Clears only the signed pre-key. `KeyStore::reset` coordinates the full key lifecycle.
    pub(crate) fn reset(&self) -> Result<(), SignedPreKeyError> {
        let mut storage = self.lock_storage()?;
        Ok(storage.delete(SIGNED_PREKEY_KEY)?)
    }

    // Forces an immediate signed-pre-key rotation.
    pub(crate) fn rotate_now<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<SignedPreKey, SignedPreKeyError> {
        let now = self.now_secs()?;
        self.rotate_now_at(rng, now)
    }

    fn rotate_now_at<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        now: u64,
    ) -> Result<SignedPreKey, SignedPreKeyError> {
        let discovery_key = self.discovery.current()?;
        let previous = self.load_store_optional(now)?;
        let signed_prekey = generate_signed_prekey_for_discovery_key(rng, &discovery_key, now);
        let retained = previous.and_then(|store| {
            (store.current.epoch() == discovery_key.epoch()).then_some(RetainedSignedPreKey {
                prekey: store.current.clone_for_storage(),
                superseded_at: now,
            })
        });
        let blob = encode_signed_prekey_store(&StoredSignedPreKeys {
            current: signed_prekey.clone_for_storage(),
            retained,
        });
        let mut storage = self.lock_storage()?;
        storage.store(SIGNED_PREKEY_KEY, &blob)?;
        Ok(signed_prekey)
    }

    fn load_store(&self, now: u64) -> Result<StoredSignedPreKeys, SignedPreKeyError> {
        self.load_store_optional(now)?
            .ok_or(SignedPreKeyError::NotFound)
    }

    fn load_store_optional(
        &self,
        now: u64,
    ) -> Result<Option<StoredSignedPreKeys>, SignedPreKeyError> {
        let mut storage = self.lock_storage()?;
        let Some(raw) = storage.load(SIGNED_PREKEY_KEY)? else {
            return Ok(None);
        };
        let mut store = decode_signed_prekey_store(&raw)?;
        if store
            .retained
            .as_ref()
            .is_some_and(|retained| retained_prekey_expired(retained, now))
        {
            store.retained = None;
            let blob = encode_signed_prekey_store(&store);
            storage.store(SIGNED_PREKEY_KEY, &blob)?;
        }
        Ok(Some(store))
    }

    fn read_stored_created_at(&self, now: u64) -> Result<Option<u64>, SignedPreKeyError> {
        Ok(self
            .load_store_optional(now)?
            .map(|store| store.current.created_at()))
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

trait CloneForSignedPreKeyStorage {
    fn clone_for_storage(&self) -> SignedPreKey;
}

impl CloneForSignedPreKeyStorage for SignedPreKey {
    fn clone_for_storage(&self) -> SignedPreKey {
        SignedPreKey::from_secret_bytes(
            *self.to_secret_bytes(),
            self.signature().to_bytes(),
            self.epoch(),
            self.created_at(),
        )
    }
}

#[allow(dead_code)]
fn matching_prekey(
    prekey: &SignedPreKey,
    epoch: u32,
    public_key: &[u8; 32],
) -> Option<SignedPreKey> {
    let matches_epoch = prekey.epoch() == epoch;
    let matches_public_key: bool = prekey.public().as_bytes().ct_eq(public_key).into();
    (matches_epoch && matches_public_key).then(|| prekey.clone_for_storage())
}

fn retained_prekey_expired(retained: &RetainedSignedPreKey, now: u64) -> bool {
    if retained.superseded_at > now + FUTURE_TIMESTAMP_TOLERANCE_SECS {
        return true;
    }
    now.saturating_sub(retained.superseded_at) > SIGNED_PREKEY_GRACE_WINDOW_SECS
}

fn encode_signed_prekey_store(store: &StoredSignedPreKeys) -> Zeroizing<Vec<u8>> {
    let mut blob = Zeroizing::new(Vec::with_capacity(SIGNED_PREKEY_BLOB_LEN));
    blob.push(SIGNED_PREKEY_VERSION);
    encode_signed_prekey_record(&mut blob, &store.current);
    if let Some(retained) = &store.retained {
        blob.push(1);
        encode_signed_prekey_record(&mut blob, &retained.prekey);
        blob.extend_from_slice(&retained.superseded_at.to_be_bytes());
    } else {
        blob.push(0);
        blob.resize(SIGNED_PREKEY_BLOB_LEN, 0);
    }
    blob
}

#[cfg(test)]
fn encode_signed_prekey(signed_prekey: &SignedPreKey) -> Zeroizing<Vec<u8>> {
    encode_signed_prekey_store(&StoredSignedPreKeys {
        current: signed_prekey.clone_for_storage(),
        retained: None,
    })
}

fn encode_signed_prekey_record(blob: &mut Vec<u8>, signed_prekey: &SignedPreKey) {
    blob.extend_from_slice(&*signed_prekey.to_secret_bytes());
    blob.extend_from_slice(&signed_prekey.signature().to_bytes());
    blob.extend_from_slice(&signed_prekey.epoch().to_be_bytes());
    blob.extend_from_slice(&signed_prekey.created_at().to_be_bytes());
}

fn decode_signed_prekey_record(record: &[u8]) -> SignedPreKey {
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&record[..32]);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&record[32..96]);
    let mut epoch_bytes = [0u8; 4];
    epoch_bytes.copy_from_slice(&record[96..100]);
    let mut timestamp_bytes = [0u8; 8];
    timestamp_bytes.copy_from_slice(&record[100..SIGNED_PREKEY_RECORD_LEN]);
    let epoch = u32::from_be_bytes(epoch_bytes);
    let created_at = u64::from_be_bytes(timestamp_bytes);
    SignedPreKey::from_secret_bytes(secret, signature, epoch, created_at)
}

fn decode_signed_prekey_store(raw: &[u8]) -> Result<StoredSignedPreKeys, SignedPreKeyError> {
    match raw.first().copied() {
        Some(SIGNED_PREKEY_VERSION_V1) => decode_signed_prekey_store_v1(raw),
        Some(SIGNED_PREKEY_VERSION_V2) => decode_signed_prekey_store_v2(raw),
        Some(SIGNED_PREKEY_VERSION) => decode_signed_prekey_store_v3(raw),
        Some(version) => Err(SignedPreKeyError::InvalidData(format!(
            "unsupported signed pre-key format version: {version}"
        ))),
        None => Err(SignedPreKeyError::InvalidData(
            "expected signed pre-key version byte, got empty blob".into(),
        )),
    }
}

fn decode_signed_prekey_store_v1(raw: &[u8]) -> Result<StoredSignedPreKeys, SignedPreKeyError> {
    if raw.len() != SIGNED_PREKEY_V1_BLOB_LEN {
        return Err(SignedPreKeyError::InvalidData(format!(
            "expected {SIGNED_PREKEY_V1_BLOB_LEN} bytes, got {}",
            raw.len()
        )));
    }
    Ok(StoredSignedPreKeys {
        current: decode_signed_prekey_record(&raw[1..SIGNED_PREKEY_V1_BLOB_LEN]),
        retained: None,
    })
}

fn decode_signed_prekey_store_v2(raw: &[u8]) -> Result<StoredSignedPreKeys, SignedPreKeyError> {
    if raw.len() != SIGNED_PREKEY_V2_BLOB_LEN {
        return Err(SignedPreKeyError::InvalidData(format!(
            "expected {SIGNED_PREKEY_V2_BLOB_LEN} bytes, got {}",
            raw.len()
        )));
    }
    let current_end = 1 + SIGNED_PREKEY_RECORD_LEN;
    let current = decode_signed_prekey_record(&raw[1..current_end]);
    let retained = match raw[current_end] {
        0 => None,
        1 => {
            let retained_start = current_end + 1;
            let prekey =
                decode_signed_prekey_record(&raw[retained_start..SIGNED_PREKEY_V2_BLOB_LEN]);
            Some(RetainedSignedPreKey {
                superseded_at: prekey.created_at(),
                prekey,
            })
        }
        flag => {
            return Err(SignedPreKeyError::InvalidData(format!(
                "invalid retained signed pre-key flag: {flag}"
            )));
        }
    };
    Ok(StoredSignedPreKeys { current, retained })
}

fn decode_signed_prekey_store_v3(raw: &[u8]) -> Result<StoredSignedPreKeys, SignedPreKeyError> {
    if raw.len() != SIGNED_PREKEY_BLOB_LEN {
        return Err(SignedPreKeyError::InvalidData(format!(
            "expected {SIGNED_PREKEY_BLOB_LEN} bytes, got {}",
            raw.len()
        )));
    }
    let current_end = 1 + SIGNED_PREKEY_RECORD_LEN;
    let current = decode_signed_prekey_record(&raw[1..current_end]);
    let retained = match raw[current_end] {
        0 => None,
        1 => {
            let retained_start = current_end + 1;
            let retained_end = retained_start + SIGNED_PREKEY_RECORD_LEN;
            let prekey = decode_signed_prekey_record(&raw[retained_start..retained_end]);
            let mut superseded_at_bytes = [0u8; 8];
            superseded_at_bytes.copy_from_slice(&raw[retained_end..SIGNED_PREKEY_BLOB_LEN]);
            Some(RetainedSignedPreKey {
                prekey,
                superseded_at: u64::from_be_bytes(superseded_at_bytes),
            })
        }
        flag => {
            return Err(SignedPreKeyError::InvalidData(format!(
                "invalid retained signed pre-key flag: {flag}"
            )));
        }
    };
    Ok(StoredSignedPreKeys { current, retained })
}

#[cfg(test)]
fn checked_blob(raw: &[u8]) -> Result<StoredSignedPreKeys, SignedPreKeyError> {
    decode_signed_prekey_store(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::ManualClock;
    use crate::identity::IdentityManager;
    use crate::storage::InMemorySecureStorage;
    use aether_crypto::{
        generate_signed_prekey, generate_signed_prekey_for_discovery_key,
        generate_signing_key_pair, verify_signed_prekey_bundle,
    };
    use rand::rngs::OsRng;

    const FIXED_NOW: u64 = 1_700_000_000;
    const FIXED_EPOCH: u32 = 3;

    struct SignedPreKeySetup {
        discovery: Arc<DiscoveryKeyManager>,
        manager: SignedPreKeyManager,
    }

    fn shared_storage() -> Arc<Mutex<Box<dyn SecureStorage>>> {
        Arc::new(Mutex::new(Box::new(InMemorySecureStorage::new())))
    }

    fn setup_with_discovery_key() -> SignedPreKeySetup {
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
        SignedPreKeySetup {
            discovery,
            manager: signed_prekey,
        }
    }

    fn manager_at(setup: &SignedPreKeySetup, now: u64) -> SignedPreKeyManager {
        SignedPreKeyManager::new(
            Arc::clone(&setup.manager.storage),
            Arc::clone(&setup.discovery),
            Arc::new(ManualClock::new(now)),
        )
    }

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

    fn store_signed_prekey_with_created_at(
        manager: &SignedPreKeyManager,
        created_at: u64,
    ) -> SignedPreKey {
        let signing_key = generate_signing_key_pair(&mut OsRng);
        let signed_prekey =
            generate_signed_prekey(&mut OsRng, &signing_key, FIXED_EPOCH, created_at);
        let blob = encode_signed_prekey(&signed_prekey);
        manager
            .storage
            .lock()
            .unwrap()
            .store(SIGNED_PREKEY_KEY, &blob)
            .unwrap();
        signed_prekey
    }

    fn store_current_discovery_signed_prekey_with_created_at(
        setup: &SignedPreKeySetup,
        created_at: u64,
    ) -> SignedPreKey {
        let discovery_key = setup.discovery.current().unwrap();
        let signed_prekey =
            generate_signed_prekey_for_discovery_key(&mut OsRng, &discovery_key, created_at);
        let blob = encode_signed_prekey(&signed_prekey);
        setup
            .manager
            .storage
            .lock()
            .unwrap()
            .store(SIGNED_PREKEY_KEY, &blob)
            .unwrap();
        signed_prekey
    }

    #[test]
    fn current_without_stored_signed_prekey_returns_not_found() {
        let manager = setup_with_discovery_key().manager;
        assert!(matches!(
            manager.current(),
            Err(SignedPreKeyError::NotFound)
        ));
    }

    #[test]
    fn current_returns_invalid_data_for_corrupt_blob() {
        let manager = setup_with_discovery_key().manager;
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
        let signed_prekey = store_signed_prekey_with_created_at(&manager, FIXED_NOW);
        let bundle = manager.current_bundle().unwrap();
        assert_eq!(
            bundle.public_key.as_bytes(),
            signed_prekey.public().as_bytes()
        );
    }

    #[test]
    fn rotate_if_stale_seeds_first_signed_prekey_under_discovery_key() {
        let SignedPreKeySetup { discovery, manager } = setup_with_discovery_key();
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
        let discovery_bundle = discovery.current_bundle().unwrap();
        assert!(verify_signed_prekey_bundle(&bundle, &discovery_bundle.verifying_key).is_ok());
    }

    #[test]
    fn rotate_if_stale_keeps_fresh_signed_prekey() {
        let manager = setup_with_discovery_key().manager;
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
        let manager = setup_with_discovery_key().manager;
        manager.rotate_if_stale(&mut OsRng).unwrap();
        let backdated_timestamp =
            FIXED_NOW - (SIGNED_PREKEY_ROTATION_WINDOW_DAYS + 1) * SECONDS_PER_DAY;
        let stale_signed_prekey =
            store_signed_prekey_with_created_at(&manager, backdated_timestamp);
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
    }

    #[test]
    fn rotate_if_stale_retains_backdated_prekey_for_grace_after_supersession() {
        let setup = setup_with_discovery_key();
        let backdated_timestamp =
            FIXED_NOW - (SIGNED_PREKEY_ROTATION_WINDOW_DAYS + 1) * SECONDS_PER_DAY;
        let stale_signed_prekey =
            store_current_discovery_signed_prekey_with_created_at(&setup, backdated_timestamp);

        setup
            .manager
            .rotate_if_stale(&mut OsRng)
            .unwrap()
            .expect("backdated signed pre-key must trigger rotation");

        let retained = manager_at(&setup, FIXED_NOW + SECONDS_PER_DAY)
            .prekey_for_public_key(
                stale_signed_prekey.epoch(),
                stale_signed_prekey.public().as_bytes(),
            )
            .unwrap();
        assert_eq!(
            retained.public().as_bytes(),
            stale_signed_prekey.public().as_bytes()
        );

        let expired = manager_at(
            &setup,
            FIXED_NOW + SIGNED_PREKEY_ROTATION_WINDOW_DAYS * SECONDS_PER_DAY + 1,
        );
        assert!(matches!(
            expired.prekey_for_public_key(
                stale_signed_prekey.epoch(),
                stale_signed_prekey.public().as_bytes()
            ),
            Err(SignedPreKeyError::NotFound)
        ));
    }

    #[test]
    fn rotate_if_stale_keeps_slightly_future_signed_prekey() {
        let manager = setup_with_discovery_key().manager;
        let signed_prekey = store_signed_prekey_with_created_at(&manager, FIXED_NOW + 100_000);
        assert!(manager.rotate_if_stale(&mut OsRng).unwrap().is_none());
        let public_key = manager.current_bundle().unwrap().public_key;
        assert_eq!(public_key.as_bytes(), signed_prekey.public().as_bytes());
    }

    #[test]
    fn rotate_if_stale_replaces_far_future_signed_prekey() {
        let manager = setup_with_discovery_key().manager;
        let signed_prekey = store_signed_prekey_with_created_at(
            &manager,
            FIXED_NOW + FUTURE_TIMESTAMP_TOLERANCE_SECS * 10,
        );
        let rotated = manager
            .rotate_if_stale(&mut OsRng)
            .unwrap()
            .expect("far-future signed pre-key must trigger rotation");
        let public_key = manager.current_bundle().unwrap().public_key;
        assert_eq!(public_key.as_bytes(), rotated.public().as_bytes());
        assert_ne!(public_key.as_bytes(), signed_prekey.public().as_bytes());
    }

    #[test]
    fn rotate_now_retains_immediately_superseded_prekey_inside_grace() {
        let setup = setup_with_discovery_key();
        let first = setup.manager.rotate_now(&mut OsRng).unwrap();
        let second = setup.manager.rotate_now(&mut OsRng).unwrap();

        let retained = setup
            .manager
            .prekey_for_public_key(first.epoch(), first.public().as_bytes())
            .unwrap();
        let current = setup.manager.current().unwrap();

        assert_eq!(retained.public().as_bytes(), first.public().as_bytes());
        assert_eq!(current.public().as_bytes(), second.public().as_bytes());
    }

    #[test]
    fn rotate_now_retains_only_immediately_superseded_prekey() {
        let setup = setup_with_discovery_key();
        let first = setup.manager.rotate_now(&mut OsRng).unwrap();
        let second = setup.manager.rotate_now(&mut OsRng).unwrap();
        let third = setup.manager.rotate_now(&mut OsRng).unwrap();

        assert!(matches!(
            setup
                .manager
                .prekey_for_public_key(first.epoch(), first.public().as_bytes()),
            Err(SignedPreKeyError::NotFound)
        ));
        assert!(
            setup
                .manager
                .prekey_for_public_key(second.epoch(), second.public().as_bytes())
                .is_ok()
        );
        assert_eq!(
            setup.manager.current().unwrap().public().as_bytes(),
            third.public().as_bytes()
        );
    }

    #[test]
    fn retained_prekey_expires_after_grace_window() {
        let setup = setup_with_discovery_key();
        let first = setup.manager.rotate_now(&mut OsRng).unwrap();
        setup.manager.rotate_now(&mut OsRng).unwrap();
        let expired = manager_at(
            &setup,
            FIXED_NOW + SIGNED_PREKEY_ROTATION_WINDOW_DAYS * SECONDS_PER_DAY + 1,
        );

        assert!(matches!(
            expired.prekey_for_public_key(first.epoch(), first.public().as_bytes()),
            Err(SignedPreKeyError::NotFound)
        ));
        assert!(matches!(
            setup
                .manager
                .prekey_for_public_key(first.epoch(), first.public().as_bytes()),
            Err(SignedPreKeyError::NotFound)
        ));
    }

    #[test]
    fn rotate_if_stale_rejects_unsupported_version() {
        let manager = setup_with_discovery_key().manager;
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
        let original =
            generate_signed_prekey(&mut OsRng, &identity_signing_key, FIXED_EPOCH, FIXED_NOW);
        let blob = encode_signed_prekey(&original);
        assert_eq!(blob.len(), SIGNED_PREKEY_BLOB_LEN);
        let store = decode_signed_prekey_store(&blob).unwrap();
        let restored = store.current.clone_for_storage();
        assert_eq!(restored.public().as_bytes(), original.public().as_bytes());
        assert_eq!(
            restored.signature().to_bytes(),
            original.signature().to_bytes()
        );
        assert_eq!(restored.epoch(), original.epoch());
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
}
