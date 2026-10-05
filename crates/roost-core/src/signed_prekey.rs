use crate::discovery_key::{DiscoveryKeyError, DiscoveryKeyManager};
use crate::prekey_state::INBOX_ROTATION_REQUIRED_MARKER;
use crate::storage::{SecureStorage, StorageError};
use rand::{CryptoRng, RngCore};
use roost_crypto::{PublicSignedPreKey, SignedPreKey, generate_signed_prekey_for_discovery_key};
use roost_protocol::{SignatureError, from_unix_secs, to_unix_secs};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const SIGNED_PREKEY_KEY: &str = "prekey/signed";
const SIGNED_PREKEY_VERSION: u8 = 4;
// Record layout: id (8) | secret (32) | signature (64) | epoch (4) | created_at (8).
const SIGNED_PREKEY_RECORD_LEN: usize = 8 + 32 + 64 + 4 + 8;
// Retained record layout: record | superseded_at (8).
const RETAINED_SIGNED_PREKEY_RECORD_LEN: usize = SIGNED_PREKEY_RECORD_LEN + 8;
// Header layout: version (1) | next_id (8) | current record | retained count (1).
const SIGNED_PREKEY_HEADER_LEN: usize = 1 + 8 + SIGNED_PREKEY_RECORD_LEN + 1;
const MAX_RETAINED_SIGNED_PREKEYS: usize = 5;
const SECONDS_PER_DAY: u64 = 86_400;
const SIGNED_PREKEY_ROTATION_WINDOW: Duration = Duration::from_secs(7 * SECONDS_PER_DAY);
const SIGNED_PREKEY_RETENTION_WINDOW: Duration = Duration::from_secs(30 * SECONDS_PER_DAY);
// Treat far-future timestamps as expired so clock manipulation cannot freeze rotation forever.
const FUTURE_TIMESTAMP_TOLERANCE: Duration = Duration::from_secs(30 * SECONDS_PER_DAY);

/// Errors returned by signed-pre-key operations.
#[derive(Debug, thiserror::Error)]
pub enum SignedPreKeyError {
    /// Stored data uses an unsupported format version.
    #[error("unsupported stored format version: {0}")]
    UnsupportedVersion(u8),
    /// The system clock is before the Unix epoch.
    #[error("system clock is before Unix epoch")]
    Clock,
    /// The stored signed pre-key's signature does not verify against the current discovery key.
    #[error("stored signed pre-key signature does not match the discovery key")]
    Corrupt,
    /// Loading the discovery key for signed-pre-key rotation returned a [`DiscoveryKeyError`].
    #[error("loading the discovery key failed")]
    Discovery(#[from] DiscoveryKeyError),
    /// Backup restoration requires a new inbox generation before prekeys may be used.
    #[error("inbox rotation required before using restored pre-key state")]
    InboxRotationRequired,
    /// A stored signed-pre-key blob is shorter than its format requires.
    #[error("signed pre-key blob is {len} bytes, shorter than {min_len}")]
    BlobTooShort {
        /// Stored length in bytes.
        len: usize,
        /// Shortest accepted length in bytes.
        min_len: usize,
    },
    /// The stored retained signed pre-keys repeat an identifier.
    #[error("duplicate retained signed pre-key identifier {0}")]
    DuplicateRetainedId(u64),
    /// Every signed-pre-key identifier in this epoch has been used.
    #[error("signed pre-key identifier space exhausted")]
    IdentifiersExhausted,
    /// A stored signed-pre-key blob has the wrong length for its contents.
    #[error("signed pre-key blob is {actual} bytes, expected {expected}")]
    InvalidBlobLength {
        /// Expected length in bytes.
        expected: usize,
        /// Stored length in bytes.
        actual: usize,
    },
    /// The stored next identifier doesn't follow the current signed pre-key's identifier.
    #[error(
        "next signed pre-key identifier {next_id} does not follow current identifier {current_id}"
    )]
    NextIdMismatch {
        /// Stored next identifier.
        next_id: u64,
        /// Current signed pre-key's identifier.
        current_id: u64,
    },
    /// Rotating would discard a retained signed pre-key that hasn't expired.
    #[error("retained signed pre-key capacity of {max} reached")]
    RetainedCapacityReached {
        /// Largest number of retained signed pre-keys.
        max: usize,
    },
    /// A stored retained signed pre-key belongs to a different epoch than the current one.
    #[error(
        "retained signed pre-key epoch {retained_epoch} differs from current epoch {current_epoch}"
    )]
    RetainedEpochMismatch {
        /// Retained signed pre-key's epoch.
        retained_epoch: u32,
        /// Current signed pre-key's epoch.
        current_epoch: u32,
    },
    /// A stored retained signed pre-key isn't older than the current one.
    #[error(
        "retained signed pre-key identifier {retained_id} is not older than current identifier \
         {current_id}"
    )]
    RetainedIdNotOlder {
        /// Retained signed pre-key's identifier.
        retained_id: u64,
        /// Current signed pre-key's identifier.
        current_id: u64,
    },
    /// Signing a new signed pre-key with the discovery key failed.
    #[error("signing the signed pre-key failed")]
    SignedPreKeySignature(#[source] SignatureError),
    /// More retained signed pre-keys are stored than the limit allows.
    #[error("{count} retained signed pre-keys exceed the limit of {max}")]
    TooManyRetained {
        /// Stored count.
        count: usize,
        /// Largest accepted count.
        max: usize,
    },
    /// The internal storage lock was poisoned by a panicked thread.
    #[error("internal lock poisoned")]
    LockPoisoned,
    /// No signed pre-key is stored.
    #[error("no signed pre-key stored")]
    NotFound,
    /// The underlying [`SecureStorage`] returned an error.
    #[error("signed pre-key storage failed")]
    Storage(#[from] StorageError),
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct StoredSignedPreKeys {
    #[zeroize(skip)]
    next_id: u64,
    current: SignedPreKey,
    retained: Vec<RetainedSignedPreKey>,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct RetainedSignedPreKey {
    prekey: SignedPreKey,
    #[zeroize(skip)]
    superseded_at_secs: u64,
}

// Manages signed-pre-key generation, rotation, and persistence.
pub(crate) struct SignedPreKeyManager {
    storage: Arc<Mutex<Box<dyn SecureStorage>>>,
    discovery: Arc<DiscoveryKeyManager>,
}

impl SignedPreKeyManager {
    pub(crate) fn new(
        storage: Arc<Mutex<Box<dyn SecureStorage>>>,
        discovery: Arc<DiscoveryKeyManager>,
    ) -> Self {
        SignedPreKeyManager { storage, discovery }
    }

    // Loads the secret signed pre-key from storage, pruning retained keys expired at `now`.
    pub(crate) fn current(&self, now: SystemTime) -> Result<SignedPreKey, SignedPreKeyError> {
        let store = self.load_store(now)?;
        Ok(store.current.clone_for_storage())
    }

    // Returns the public signed pre-key to distribute to peers.
    pub(crate) fn current_public(
        &self,
        now: SystemTime,
    ) -> Result<PublicSignedPreKey, SignedPreKeyError> {
        Ok(self.current(now)?.public())
    }

    pub(crate) fn prekey_for_reference(
        &self,
        epoch: u32,
        id: u64,
        public_key: &[u8; 32],
        now: SystemTime,
    ) -> Result<SignedPreKey, SignedPreKeyError> {
        let store = self.load_store(now)?;
        matching_prekey(&store.current, epoch, id, public_key)
            .or_else(|| {
                store
                    .retained
                    .iter()
                    .find_map(|retained| matching_prekey(&retained.prekey, epoch, id, public_key))
            })
            .ok_or(SignedPreKeyError::NotFound)
    }

    // Rotates missing, stale, and far-future signed pre-keys. Slightly future timestamps stay
    // valid to tolerate clock skew.
    pub(crate) fn rotate_if_stale<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        now: SystemTime,
    ) -> Result<Option<SignedPreKey>, SignedPreKeyError> {
        let needs_rotation = self.load_store_optional(now)?.is_none_or(|store| {
            is_expired(
                store.current.created_at_secs(),
                now,
                SIGNED_PREKEY_ROTATION_WINDOW,
            )
        });
        if needs_rotation {
            Ok(Some(self.rotate_now(rng, now)?))
        } else {
            Ok(None)
        }
    }

    // Clears only the signed prekey. `KeyStore::prepare_identity_deletion` coordinates the full key lifecycle.
    pub(crate) fn reset(&self) -> Result<(), SignedPreKeyError> {
        let mut storage = self.lock_storage()?;
        Ok(storage.delete(SIGNED_PREKEY_KEY)?)
    }

    pub(crate) fn mark_inbox_rotation_required(&self) -> Result<(), SignedPreKeyError> {
        let mut storage = self.lock_storage()?;
        Ok(storage.store(SIGNED_PREKEY_KEY, INBOX_ROTATION_REQUIRED_MARKER)?)
    }

    // Forces an immediate signed-pre-key rotation.
    pub(crate) fn rotate_now<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        now: SystemTime,
    ) -> Result<SignedPreKey, SignedPreKeyError> {
        let now_secs = to_unix_secs(now).ok_or(SignedPreKeyError::Clock)?;
        let discovery_key = self.discovery.current()?;
        let previous = self.load_store_optional(now)?;
        let same_epoch = previous
            .as_ref()
            .is_some_and(|store| store.current.epoch() == discovery_key.epoch());
        let next_id = previous
            .as_ref()
            .filter(|_| same_epoch)
            .map_or(0, |store| store.next_id);
        let following_id = next_id
            .checked_add(1)
            .ok_or(SignedPreKeyError::IdentifiersExhausted)?;
        let signed_prekey =
            generate_signed_prekey_for_discovery_key(rng, &discovery_key, next_id, now_secs)
                .map_err(SignedPreKeyError::SignedPreKeySignature)?;
        let mut retained = Vec::new();
        if let Some(mut store) = previous.filter(|_| same_epoch) {
            retained = std::mem::take(&mut store.retained);
            if retained.len() == MAX_RETAINED_SIGNED_PREKEYS {
                return Err(SignedPreKeyError::RetainedCapacityReached {
                    max: MAX_RETAINED_SIGNED_PREKEYS,
                });
            }
            retained.push(RetainedSignedPreKey {
                prekey: store.current.clone_for_storage(),
                superseded_at_secs: now_secs,
            });
        }
        let blob = encode_signed_prekey_store(&StoredSignedPreKeys {
            next_id: following_id,
            current: signed_prekey.clone_for_storage(),
            retained,
        });
        let mut storage = self.lock_storage()?;
        storage.store(SIGNED_PREKEY_KEY, &blob)?;
        Ok(signed_prekey)
    }

    fn load_store(&self, now: SystemTime) -> Result<StoredSignedPreKeys, SignedPreKeyError> {
        self.load_store_optional(now)?
            .ok_or(SignedPreKeyError::NotFound)
    }

    fn load_store_optional(
        &self,
        now: SystemTime,
    ) -> Result<Option<StoredSignedPreKeys>, SignedPreKeyError> {
        let mut storage = self.lock_storage()?;
        let Some(raw) = storage.load(SIGNED_PREKEY_KEY)? else {
            return Ok(None);
        };
        let mut store = decode_signed_prekey_store(&raw)?;
        let retained_count = store.retained.len();
        store.retained.retain(|retained| {
            !is_expired(
                retained.superseded_at_secs,
                now,
                SIGNED_PREKEY_RETENTION_WINDOW,
            )
        });
        if retained_count != store.retained.len() {
            let blob = encode_signed_prekey_store(&store);
            storage.store(SIGNED_PREKEY_KEY, &blob)?;
        }
        Ok(Some(store))
    }

    fn lock_storage(&self) -> Result<MutexGuard<'_, Box<dyn SecureStorage>>, SignedPreKeyError> {
        self.storage
            .lock()
            .map_err(|_| SignedPreKeyError::LockPoisoned)
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
            self.id(),
            self.epoch(),
            self.created_at_secs(),
        )
    }
}

#[allow(dead_code)]
fn matching_prekey(
    prekey: &SignedPreKey,
    epoch: u32,
    id: u64,
    public_key: &[u8; 32],
) -> Option<SignedPreKey> {
    let matches_epoch = prekey.epoch() == epoch;
    let matches_id = prekey.id() == id;
    let matches_public_key: bool = prekey.public_key().as_bytes().ct_eq(public_key).into();
    (matches_epoch && matches_id && matches_public_key).then(|| prekey.clone_for_storage())
}

// Returns whether a stored Unix-seconds timestamp is at least `window` old at `now`. Timestamps
// more than `FUTURE_TIMESTAMP_TOLERANCE` ahead also count as expired.
fn is_expired(timestamp_secs: u64, now: SystemTime, window: Duration) -> bool {
    let Some(timestamp) = from_unix_secs(timestamp_secs) else {
        return true;
    };
    match now.duration_since(timestamp) {
        Ok(age) => age >= window,
        Err(ahead) => ahead.duration() > FUTURE_TIMESTAMP_TOLERANCE,
    }
}

fn encode_signed_prekey_store(store: &StoredSignedPreKeys) -> Zeroizing<Vec<u8>> {
    let mut blob = Zeroizing::new(Vec::with_capacity(
        SIGNED_PREKEY_HEADER_LEN + store.retained.len() * RETAINED_SIGNED_PREKEY_RECORD_LEN,
    ));
    blob.push(SIGNED_PREKEY_VERSION);
    blob.extend_from_slice(&store.next_id.to_be_bytes());
    encode_signed_prekey_record(&mut blob, &store.current);
    blob.push(store.retained.len() as u8);
    for retained in &store.retained {
        encode_signed_prekey_record(&mut blob, &retained.prekey);
        blob.extend_from_slice(&retained.superseded_at_secs.to_be_bytes());
    }
    blob
}

#[cfg(test)]
fn encode_signed_prekey(signed_prekey: &SignedPreKey) -> Zeroizing<Vec<u8>> {
    encode_signed_prekey_store(&StoredSignedPreKeys {
        next_id: signed_prekey.id().saturating_add(1),
        current: signed_prekey.clone_for_storage(),
        retained: Vec::new(),
    })
}

fn encode_signed_prekey_record(blob: &mut Vec<u8>, signed_prekey: &SignedPreKey) {
    blob.extend_from_slice(&signed_prekey.id().to_be_bytes());
    blob.extend_from_slice(&*signed_prekey.to_secret_bytes());
    blob.extend_from_slice(&signed_prekey.signature().to_bytes());
    blob.extend_from_slice(&signed_prekey.epoch().to_be_bytes());
    blob.extend_from_slice(&signed_prekey.created_at_secs().to_be_bytes());
}

fn decode_signed_prekey_record(record: &[u8]) -> SignedPreKey {
    let mut id_bytes = [0u8; 8];
    id_bytes.copy_from_slice(&record[..8]);
    let mut secret = Zeroizing::new([0u8; 32]);
    secret.copy_from_slice(&record[8..40]);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&record[40..104]);
    let mut epoch_bytes = [0u8; 4];
    epoch_bytes.copy_from_slice(&record[104..108]);
    let mut created_at_bytes = [0u8; 8];
    created_at_bytes.copy_from_slice(&record[108..SIGNED_PREKEY_RECORD_LEN]);
    SignedPreKey::from_secret_bytes(
        *secret,
        signature,
        u64::from_be_bytes(id_bytes),
        u32::from_be_bytes(epoch_bytes),
        u64::from_be_bytes(created_at_bytes),
    )
}

fn decode_signed_prekey_store(raw: &[u8]) -> Result<StoredSignedPreKeys, SignedPreKeyError> {
    if raw == INBOX_ROTATION_REQUIRED_MARKER {
        return Err(SignedPreKeyError::InboxRotationRequired);
    }
    match raw.first().copied() {
        Some(SIGNED_PREKEY_VERSION) => {}
        Some(version) => return Err(SignedPreKeyError::UnsupportedVersion(version)),
        None => return Err(SignedPreKeyError::BlobTooShort { len: 0, min_len: 1 }),
    }
    let store = decode_signed_prekey_store_body(raw)?;
    validate_signed_prekey_store(store.next_id, &store.current, &store.retained)?;
    Ok(store)
}

fn decode_signed_prekey_store_body(raw: &[u8]) -> Result<StoredSignedPreKeys, SignedPreKeyError> {
    if raw.len() < SIGNED_PREKEY_HEADER_LEN {
        return Err(SignedPreKeyError::BlobTooShort {
            len: raw.len(),
            min_len: SIGNED_PREKEY_HEADER_LEN,
        });
    }
    let mut next_id_bytes = [0u8; 8];
    next_id_bytes.copy_from_slice(&raw[1..9]);
    let next_id = u64::from_be_bytes(next_id_bytes);
    let current_end = 9 + SIGNED_PREKEY_RECORD_LEN;
    let current = decode_signed_prekey_record(&raw[9..current_end]);
    let retained_count = usize::from(raw[current_end]);
    if retained_count > MAX_RETAINED_SIGNED_PREKEYS {
        return Err(SignedPreKeyError::TooManyRetained {
            count: retained_count,
            max: MAX_RETAINED_SIGNED_PREKEYS,
        });
    }
    let expected_len =
        SIGNED_PREKEY_HEADER_LEN + retained_count * RETAINED_SIGNED_PREKEY_RECORD_LEN;
    if raw.len() != expected_len {
        return Err(SignedPreKeyError::InvalidBlobLength {
            expected: expected_len,
            actual: raw.len(),
        });
    }
    let mut retained = Vec::with_capacity(retained_count);
    let mut offset = SIGNED_PREKEY_HEADER_LEN;
    for _ in 0..retained_count {
        let prekey_end = offset + SIGNED_PREKEY_RECORD_LEN;
        let prekey = decode_signed_prekey_record(&raw[offset..prekey_end]);
        let superseded_at_end = prekey_end + 8;
        let mut superseded_at_bytes = [0u8; 8];
        superseded_at_bytes.copy_from_slice(&raw[prekey_end..superseded_at_end]);
        retained.push(RetainedSignedPreKey {
            prekey,
            superseded_at_secs: u64::from_be_bytes(superseded_at_bytes),
        });
        offset = superseded_at_end;
    }
    Ok(StoredSignedPreKeys {
        next_id,
        current,
        retained,
    })
}

fn validate_signed_prekey_store(
    next_id: u64,
    current: &SignedPreKey,
    retained: &[RetainedSignedPreKey],
) -> Result<(), SignedPreKeyError> {
    if current.id().checked_add(1) != Some(next_id) {
        return Err(SignedPreKeyError::NextIdMismatch {
            next_id,
            current_id: current.id(),
        });
    }
    for (index, entry) in retained.iter().enumerate() {
        if entry.prekey.epoch() != current.epoch() {
            return Err(SignedPreKeyError::RetainedEpochMismatch {
                retained_epoch: entry.prekey.epoch(),
                current_epoch: current.epoch(),
            });
        }
        if entry.prekey.id() >= current.id() {
            return Err(SignedPreKeyError::RetainedIdNotOlder {
                retained_id: entry.prekey.id(),
                current_id: current.id(),
            });
        }
        if retained[..index]
            .iter()
            .any(|other| other.prekey.id() == entry.prekey.id())
        {
            return Err(SignedPreKeyError::DuplicateRetainedId(entry.prekey.id()));
        }
    }
    Ok(())
}

#[cfg(test)]
fn checked_blob(raw: &[u8]) -> Result<StoredSignedPreKeys, SignedPreKeyError> {
    decode_signed_prekey_store(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityManager;
    use crate::storage::InMemorySecureStorage;
    use rand::rngs::OsRng;
    use roost_crypto::{
        generate_signed_prekey, generate_signed_prekey_for_discovery_key,
        generate_signing_key_pair, verify_public_signed_prekey,
    };
    use roost_protocol::from_unix_secs;

    const FIXED_NOW: u64 = 1_700_000_000;
    const FIXED_EPOCH: u32 = 3;
    const SIGNED_PREKEY_ROTATION_WINDOW_SECS: u64 = SIGNED_PREKEY_ROTATION_WINDOW.as_secs();
    const SIGNED_PREKEY_RETENTION_WINDOW_SECS: u64 = SIGNED_PREKEY_RETENTION_WINDOW.as_secs();
    const FUTURE_TIMESTAMP_TOLERANCE_SECS: u64 = FUTURE_TIMESTAMP_TOLERANCE.as_secs();

    fn at(secs: u64) -> SystemTime {
        from_unix_secs(secs).unwrap()
    }

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
        let discovery = Arc::new(DiscoveryKeyManager::new(Arc::clone(&storage), identity));
        discovery.rotate_now(&mut OsRng, at(FIXED_NOW)).unwrap();
        let signed_prekey = SignedPreKeyManager::new(storage, Arc::clone(&discovery));
        SignedPreKeySetup {
            discovery,
            manager: signed_prekey,
        }
    }

    fn manager_without_discovery_key() -> SignedPreKeyManager {
        let storage = shared_storage();
        let identity = Arc::new(IdentityManager::new(Arc::clone(&storage)));
        let discovery = Arc::new(DiscoveryKeyManager::new(Arc::clone(&storage), identity));
        SignedPreKeyManager::new(storage, discovery)
    }

    fn store_signed_prekey_with_created_at(
        manager: &SignedPreKeyManager,
        created_at_secs: u64,
    ) -> SignedPreKey {
        let signing_key = generate_signing_key_pair(&mut OsRng);
        let signed_prekey =
            generate_signed_prekey(&mut OsRng, &signing_key, 0, FIXED_EPOCH, created_at_secs)
                .unwrap();
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
        created_at_secs: u64,
    ) -> SignedPreKey {
        let discovery_key = setup.discovery.current().unwrap();
        let signed_prekey = generate_signed_prekey_for_discovery_key(
            &mut OsRng,
            &discovery_key,
            0,
            created_at_secs,
        )
        .unwrap();
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
            manager.current(at(FIXED_NOW)),
            Err(SignedPreKeyError::NotFound)
        ));
    }

    #[test]
    fn current_rejects_unsupported_stored_version() {
        let manager = setup_with_discovery_key().manager;
        manager
            .storage
            .lock()
            .unwrap()
            .store(SIGNED_PREKEY_KEY, &[0xAAu8; 50])
            .unwrap();
        assert!(matches!(
            manager.current(at(FIXED_NOW)),
            Err(SignedPreKeyError::UnsupportedVersion(0xaa))
        ));
    }

    #[test]
    fn current_public_does_not_require_discovery_key() {
        let manager = manager_without_discovery_key();
        let signed_prekey = store_signed_prekey_with_created_at(&manager, FIXED_NOW);
        let bundle = manager.current_public(at(FIXED_NOW)).unwrap();
        assert_eq!(
            bundle.public_key.as_bytes(),
            signed_prekey.public_key().as_bytes()
        );
    }

    #[test]
    fn rotate_if_stale_seeds_first_signed_prekey_under_discovery_key() {
        let SignedPreKeySetup { discovery, manager } = setup_with_discovery_key();
        let rotated = manager
            .rotate_if_stale(&mut OsRng, at(FIXED_NOW))
            .unwrap()
            .expect("first call must rotate");
        let bundle = manager.current_public(at(FIXED_NOW)).unwrap();
        assert_eq!(
            rotated.public_key().as_bytes(),
            bundle.public_key.as_bytes(),
            "returned signed pre-key must match persisted bundle",
        );
        let public_discovery_key = discovery.current_public().unwrap();
        assert!(verify_public_signed_prekey(&bundle, &public_discovery_key.verifying_key).is_ok());
    }

    #[test]
    fn rotate_if_stale_keeps_fresh_signed_prekey() {
        let manager = setup_with_discovery_key().manager;
        assert!(
            manager
                .rotate_if_stale(&mut OsRng, at(FIXED_NOW))
                .unwrap()
                .is_some()
        );
        let initial_public_key = manager.current_public(at(FIXED_NOW)).unwrap().public_key;
        let second_rotation = manager.rotate_if_stale(&mut OsRng, at(FIXED_NOW)).unwrap();
        assert!(
            second_rotation.is_none(),
            "fresh signed pre-key must not rotate"
        );
        let current_public_key = manager.current_public(at(FIXED_NOW)).unwrap().public_key;
        assert_eq!(initial_public_key.as_bytes(), current_public_key.as_bytes());
    }

    #[test]
    fn rotate_if_stale_replaces_backdated_signed_prekey() {
        let manager = setup_with_discovery_key().manager;
        manager.rotate_if_stale(&mut OsRng, at(FIXED_NOW)).unwrap();
        let backdated_created_at_secs =
            FIXED_NOW - (SIGNED_PREKEY_ROTATION_WINDOW_SECS + SECONDS_PER_DAY);
        let stale_signed_prekey =
            store_signed_prekey_with_created_at(&manager, backdated_created_at_secs);
        let rotated = manager
            .rotate_if_stale(&mut OsRng, at(FIXED_NOW))
            .unwrap()
            .expect("backdated signed pre-key must trigger rotation");
        let rotated_public_key = manager.current_public(at(FIXED_NOW)).unwrap().public_key;
        assert_eq!(
            rotated.public_key().as_bytes(),
            rotated_public_key.as_bytes(),
            "returned signed pre-key must match persisted bundle",
        );
        assert_ne!(
            rotated_public_key.as_bytes(),
            stale_signed_prekey.public_key().as_bytes()
        );
    }

    #[test]
    fn rotate_if_stale_rotates_at_weekly_boundary() {
        let setup = setup_with_discovery_key();
        let created_at_secs = FIXED_NOW - SIGNED_PREKEY_ROTATION_WINDOW_SECS;
        let stale = store_current_discovery_signed_prekey_with_created_at(&setup, created_at_secs);

        let rotated = setup
            .manager
            .rotate_if_stale(&mut OsRng, at(FIXED_NOW))
            .unwrap()
            .expect("weekly boundary must rotate");

        assert_ne!(
            rotated.public_key().as_bytes(),
            stale.public_key().as_bytes()
        );
        assert_eq!(rotated.id(), stale.id() + 1);
    }

    #[test]
    fn rotate_if_stale_retains_backdated_prekey_for_thirty_days_after_supersession() {
        let setup = setup_with_discovery_key();
        let backdated_created_at_secs =
            FIXED_NOW - (SIGNED_PREKEY_ROTATION_WINDOW_SECS + SECONDS_PER_DAY);
        let stale_signed_prekey = store_current_discovery_signed_prekey_with_created_at(
            &setup,
            backdated_created_at_secs,
        );

        setup
            .manager
            .rotate_if_stale(&mut OsRng, at(FIXED_NOW))
            .unwrap()
            .expect("backdated signed pre-key must trigger rotation");

        let retained = setup
            .manager
            .prekey_for_reference(
                stale_signed_prekey.epoch(),
                stale_signed_prekey.id(),
                stale_signed_prekey.public_key().as_bytes(),
                at(FIXED_NOW + SECONDS_PER_DAY),
            )
            .unwrap();
        assert_eq!(
            retained.public_key().as_bytes(),
            stale_signed_prekey.public_key().as_bytes()
        );

        assert!(matches!(
            setup.manager.prekey_for_reference(
                stale_signed_prekey.epoch(),
                stale_signed_prekey.id(),
                stale_signed_prekey.public_key().as_bytes(),
                at(FIXED_NOW + SIGNED_PREKEY_RETENTION_WINDOW_SECS)
            ),
            Err(SignedPreKeyError::NotFound)
        ));
    }

    #[test]
    fn rotate_if_stale_keeps_slightly_future_signed_prekey() {
        let manager = setup_with_discovery_key().manager;
        let signed_prekey = store_signed_prekey_with_created_at(&manager, FIXED_NOW + 100_000);
        assert!(
            manager
                .rotate_if_stale(&mut OsRng, at(FIXED_NOW))
                .unwrap()
                .is_none()
        );
        let public_key = manager.current_public(at(FIXED_NOW)).unwrap().public_key;
        assert_eq!(public_key.as_bytes(), signed_prekey.public_key().as_bytes());
    }

    #[test]
    fn rotate_if_stale_replaces_far_future_signed_prekey() {
        let manager = setup_with_discovery_key().manager;
        let signed_prekey = store_signed_prekey_with_created_at(
            &manager,
            FIXED_NOW + FUTURE_TIMESTAMP_TOLERANCE_SECS * 10,
        );
        let rotated = manager
            .rotate_if_stale(&mut OsRng, at(FIXED_NOW))
            .unwrap()
            .expect("far-future signed pre-key must trigger rotation");
        let public_key = manager.current_public(at(FIXED_NOW)).unwrap().public_key;
        assert_eq!(public_key.as_bytes(), rotated.public_key().as_bytes());
        assert_ne!(public_key.as_bytes(), signed_prekey.public_key().as_bytes());
    }

    #[test]
    fn rotate_now_retains_immediately_superseded_prekey_inside_retention_window() {
        let setup = setup_with_discovery_key();
        let first = setup.manager.rotate_now(&mut OsRng, at(FIXED_NOW)).unwrap();
        let second = setup.manager.rotate_now(&mut OsRng, at(FIXED_NOW)).unwrap();

        let retained = setup
            .manager
            .prekey_for_reference(
                first.epoch(),
                first.id(),
                first.public_key().as_bytes(),
                at(FIXED_NOW),
            )
            .unwrap();
        let current = setup.manager.current(at(FIXED_NOW)).unwrap();

        assert_eq!(
            retained.public_key().as_bytes(),
            first.public_key().as_bytes()
        );
        assert_eq!(
            current.public_key().as_bytes(),
            second.public_key().as_bytes()
        );
    }

    #[test]
    fn rotate_now_retains_multiple_superseded_prekeys() {
        let setup = setup_with_discovery_key();
        let first = setup.manager.rotate_now(&mut OsRng, at(FIXED_NOW)).unwrap();
        let second = setup.manager.rotate_now(&mut OsRng, at(FIXED_NOW)).unwrap();
        let third = setup.manager.rotate_now(&mut OsRng, at(FIXED_NOW)).unwrap();

        assert!(
            setup
                .manager
                .prekey_for_reference(
                    first.epoch(),
                    first.id(),
                    first.public_key().as_bytes(),
                    at(FIXED_NOW)
                )
                .is_ok()
        );
        assert!(
            setup
                .manager
                .prekey_for_reference(
                    second.epoch(),
                    second.id(),
                    second.public_key().as_bytes(),
                    at(FIXED_NOW)
                )
                .is_ok()
        );
        assert_eq!(
            setup
                .manager
                .current(at(FIXED_NOW))
                .unwrap()
                .public_key()
                .as_bytes(),
            third.public_key().as_bytes()
        );
    }

    #[test]
    fn retained_prekey_expires_at_thirty_day_boundary() {
        let setup = setup_with_discovery_key();
        let first = setup.manager.rotate_now(&mut OsRng, at(FIXED_NOW)).unwrap();
        setup.manager.rotate_now(&mut OsRng, at(FIXED_NOW)).unwrap();
        assert!(
            setup
                .manager
                .prekey_for_reference(
                    first.epoch(),
                    first.id(),
                    first.public_key().as_bytes(),
                    at(FIXED_NOW + SIGNED_PREKEY_RETENTION_WINDOW_SECS - 1)
                )
                .is_ok()
        );

        assert!(matches!(
            setup.manager.prekey_for_reference(
                first.epoch(),
                first.id(),
                first.public_key().as_bytes(),
                at(FIXED_NOW + SIGNED_PREKEY_RETENTION_WINDOW_SECS)
            ),
            Err(SignedPreKeyError::NotFound)
        ));
        assert!(matches!(
            setup.manager.prekey_for_reference(
                first.epoch(),
                first.id(),
                first.public_key().as_bytes(),
                at(FIXED_NOW)
            ),
            Err(SignedPreKeyError::NotFound)
        ));
    }

    #[test]
    fn prekey_lookup_rejects_wrong_id_for_matching_public_key() {
        let setup = setup_with_discovery_key();
        let prekey = setup.manager.rotate_now(&mut OsRng, at(FIXED_NOW)).unwrap();

        assert!(matches!(
            setup.manager.prekey_for_reference(
                prekey.epoch(),
                prekey.id() + 1,
                prekey.public_key().as_bytes(),
                at(FIXED_NOW)
            ),
            Err(SignedPreKeyError::NotFound)
        ));
    }

    #[test]
    fn rotate_now_refuses_to_discard_unexpired_retained_prekeys() {
        let setup = setup_with_discovery_key();
        for _ in 0..=MAX_RETAINED_SIGNED_PREKEYS {
            setup.manager.rotate_now(&mut OsRng, at(FIXED_NOW)).unwrap();
        }
        let current = setup.manager.current(at(FIXED_NOW)).unwrap();

        assert!(matches!(
            setup.manager.rotate_now(&mut OsRng, at(FIXED_NOW)),
            Err(SignedPreKeyError::RetainedCapacityReached {
                max: MAX_RETAINED_SIGNED_PREKEYS
            })
        ));
        assert_eq!(
            setup.manager.current(at(FIXED_NOW)).unwrap().id(),
            current.id()
        );
    }

    #[test]
    fn rotate_if_stale_rejects_unsupported_version() {
        let manager = setup_with_discovery_key().manager;
        let mut blob = [0u8; SIGNED_PREKEY_HEADER_LEN];
        blob[0] = 99;
        manager
            .storage
            .lock()
            .unwrap()
            .store(SIGNED_PREKEY_KEY, &blob)
            .unwrap();
        assert!(matches!(
            manager.rotate_if_stale(&mut OsRng, at(FIXED_NOW)),
            Err(SignedPreKeyError::UnsupportedVersion(_))
        ));
    }

    #[test]
    fn rotate_if_stale_without_discovery_key_returns_not_found() {
        let manager = manager_without_discovery_key();
        assert!(matches!(
            manager.rotate_if_stale(&mut OsRng, at(FIXED_NOW)),
            Err(SignedPreKeyError::Discovery(DiscoveryKeyError::NotFound))
        ));
    }

    #[test]
    fn rotate_now_without_discovery_key_returns_not_found() {
        let manager = manager_without_discovery_key();
        assert!(matches!(
            manager.rotate_now(&mut OsRng, at(FIXED_NOW)),
            Err(SignedPreKeyError::Discovery(DiscoveryKeyError::NotFound))
        ));
    }

    #[test]
    fn encode_decode_signed_prekey_round_trip() {
        let identity_signing_key = generate_signing_key_pair(&mut OsRng);
        let original =
            generate_signed_prekey(&mut OsRng, &identity_signing_key, 0, FIXED_EPOCH, FIXED_NOW)
                .unwrap();
        let blob = encode_signed_prekey(&original);
        assert_eq!(blob.len(), SIGNED_PREKEY_HEADER_LEN);
        let store = decode_signed_prekey_store(&blob).unwrap();
        let restored = store.current.clone_for_storage();
        assert_eq!(
            restored.public_key().as_bytes(),
            original.public_key().as_bytes()
        );
        assert_eq!(
            restored.signature().to_bytes(),
            original.signature().to_bytes()
        );
        assert_eq!(restored.epoch(), original.epoch());
        assert_eq!(restored.created_at_secs(), original.created_at_secs());
    }

    #[test]
    fn rotation_rejects_exhausted_signed_prekey_id_space() {
        let setup = setup_with_discovery_key();
        let discovery_key = setup.discovery.current().unwrap();
        let current = generate_signed_prekey_for_discovery_key(
            &mut OsRng,
            &discovery_key,
            u64::MAX - 1,
            FIXED_NOW,
        )
        .unwrap();
        let blob = encode_signed_prekey_store(&StoredSignedPreKeys {
            next_id: u64::MAX,
            current,
            retained: Vec::new(),
        });
        setup
            .manager
            .storage
            .lock()
            .unwrap()
            .store(SIGNED_PREKEY_KEY, &blob)
            .unwrap();

        assert!(matches!(
            setup.manager.rotate_now(&mut OsRng, at(FIXED_NOW)),
            Err(SignedPreKeyError::IdentifiersExhausted)
        ));
        assert_eq!(
            setup.manager.current(at(FIXED_NOW)).unwrap().id(),
            u64::MAX - 1
        );
    }

    #[test]
    fn checked_blob_rejects_short_blob() {
        assert!(matches!(
            checked_blob(&[SIGNED_PREKEY_VERSION; 50]),
            Err(SignedPreKeyError::BlobTooShort {
                len: 50,
                min_len: SIGNED_PREKEY_HEADER_LEN
            })
        ));
    }

    #[test]
    fn checked_blob_rejects_long_blob() {
        // The retained-count byte reads as 4, so the length must fit four retained records.
        assert!(matches!(
            checked_blob(&[SIGNED_PREKEY_VERSION; 200]),
            Err(SignedPreKeyError::InvalidBlobLength { expected, actual: 200 })
                if expected == SIGNED_PREKEY_HEADER_LEN + 4 * RETAINED_SIGNED_PREKEY_RECORD_LEN
        ));
    }

    #[test]
    fn checked_blob_rejects_unsupported_version() {
        let mut blob = [0u8; SIGNED_PREKEY_HEADER_LEN];
        blob[0] = 99;
        assert!(matches!(
            checked_blob(&blob),
            Err(SignedPreKeyError::UnsupportedVersion(_))
        ));
    }
}
