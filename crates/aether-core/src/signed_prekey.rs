use crate::clock::Clock;
use crate::discovery_key::{DiscoveryKeyError, DiscoveryKeyManager};
use crate::prekey_state::INBOX_ROTATION_REQUIRED_MARKER;
use crate::storage::{SecureStorage, StorageError};
use aether_crypto::{SignedPreKey, SignedPreKeyBundle, generate_signed_prekey_for_discovery_key};
use rand::{CryptoRng, RngCore};
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub(crate) const SIGNED_PREKEY_ROTATION_WINDOW_DAYS: u64 = 7;
pub(crate) const SIGNED_PREKEY_RETENTION_WINDOW_DAYS: u64 = 30;

const SIGNED_PREKEY_KEY: &str = "prekey/signed";
const SIGNED_PREKEY_VERSION_V1: u8 = 1;
const SIGNED_PREKEY_VERSION_V2: u8 = 2;
const SIGNED_PREKEY_VERSION_V3: u8 = 3;
const SIGNED_PREKEY_VERSION: u8 = 4;
// Record layout: secret (32) | signature (64) | epoch (4) | created_at (8).
const LEGACY_SIGNED_PREKEY_RECORD_LEN: usize = 32 + 64 + 4 + 8;
// V1 blob layout: version (1) | current record.
const SIGNED_PREKEY_V1_BLOB_LEN: usize = 1 + LEGACY_SIGNED_PREKEY_RECORD_LEN;
// V2 blob layout: version (1) | current record | retained flag (1) | retained record.
const SIGNED_PREKEY_V2_BLOB_LEN: usize =
    1 + LEGACY_SIGNED_PREKEY_RECORD_LEN + 1 + LEGACY_SIGNED_PREKEY_RECORD_LEN;
// V3 blob layout: version (1) | current record | retained flag (1) | retained record | superseded_at (8).
const SIGNED_PREKEY_V3_BLOB_LEN: usize = SIGNED_PREKEY_V2_BLOB_LEN + 8;
// V4 record layout: id (8) | legacy record.
const SIGNED_PREKEY_RECORD_LEN: usize = 8 + LEGACY_SIGNED_PREKEY_RECORD_LEN;
const RETAINED_SIGNED_PREKEY_RECORD_LEN: usize = SIGNED_PREKEY_RECORD_LEN + 8;
const SIGNED_PREKEY_V4_HEADER_LEN: usize = 1 + 8 + SIGNED_PREKEY_RECORD_LEN + 1;
const MAX_RETAINED_SIGNED_PREKEYS: usize = 5;
const SECONDS_PER_DAY: u64 = 86_400;
const SIGNED_PREKEY_ROTATION_WINDOW_SECS: u64 =
    SIGNED_PREKEY_ROTATION_WINDOW_DAYS * SECONDS_PER_DAY;
const SIGNED_PREKEY_RETENTION_WINDOW_SECS: u64 =
    SIGNED_PREKEY_RETENTION_WINDOW_DAYS * SECONDS_PER_DAY;
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
    /// Backup restoration requires a new inbox generation before prekeys may be used.
    InboxRotationRequired,
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
            SignedPreKeyError::InboxRotationRequired => {
                write!(
                    f,
                    "inbox rotation required before using restored pre-key state"
                )
            }
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
    #[zeroize(skip)]
    next_id: u64,
    current: SignedPreKey,
    retained: Vec<RetainedSignedPreKey>,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct RetainedSignedPreKey {
    prekey: SignedPreKey,
    #[zeroize(skip)]
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

    pub(crate) fn prekey_for_reference(
        &self,
        epoch: u32,
        id: u64,
        public_key: &[u8; 32],
    ) -> Result<SignedPreKey, SignedPreKeyError> {
        let now = self.now_secs()?;
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

    pub(crate) fn current_prekey_for_public_key(
        &self,
        epoch: u32,
        public_key: &[u8; 32],
    ) -> Result<SignedPreKey, SignedPreKeyError> {
        let now = self.now_secs()?;
        let store = self.load_store(now)?;
        matching_prekey_public_key(&store.current, epoch, public_key)
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
            Some(timestamp) if timestamp > now.saturating_add(FUTURE_TIMESTAMP_TOLERANCE_SECS) => {
                true
            }
            Some(timestamp) if timestamp > now => false,
            Some(timestamp) => now - timestamp >= SIGNED_PREKEY_ROTATION_WINDOW_SECS,
        };
        if needs_rotation {
            Ok(Some(self.rotate_now_at(rng, now)?))
        } else {
            Ok(None)
        }
    }

    // Clears only the signed prekey. `KeyStore::prepare_reset` coordinates the full key lifecycle.
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
        let same_epoch = previous
            .as_ref()
            .is_some_and(|store| store.current.epoch() == discovery_key.epoch());
        let next_id = previous
            .as_ref()
            .filter(|_| same_epoch)
            .map_or(0, |store| store.next_id);
        let following_id = next_id.checked_add(1).ok_or_else(|| {
            SignedPreKeyError::InvalidData("signed pre-key identifier space exhausted".into())
        })?;
        let signed_prekey =
            generate_signed_prekey_for_discovery_key(rng, &discovery_key, next_id, now);
        let mut retained = Vec::new();
        if let Some(mut store) = previous.filter(|_| same_epoch) {
            retained = std::mem::take(&mut store.retained);
            if retained.len() == MAX_RETAINED_SIGNED_PREKEYS {
                return Err(SignedPreKeyError::InvalidData(
                    "retained signed pre-key capacity reached".into(),
                ));
            }
            retained.push(RetainedSignedPreKey {
                prekey: store.current.clone_for_storage(),
                superseded_at: now,
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
        let is_legacy = raw.first().copied() != Some(SIGNED_PREKEY_VERSION);
        let mut store = decode_signed_prekey_store(&raw)?;
        let retained_count = store.retained.len();
        store
            .retained
            .retain(|retained| !retained_prekey_expired(retained, now));
        if is_legacy || retained_count != store.retained.len() {
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
            self.id(),
            self.epoch(),
            self.created_at(),
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
    let matches_public_key: bool = prekey.public().as_bytes().ct_eq(public_key).into();
    (matches_epoch && matches_id && matches_public_key).then(|| prekey.clone_for_storage())
}

fn matching_prekey_public_key(
    prekey: &SignedPreKey,
    epoch: u32,
    public_key: &[u8; 32],
) -> Option<SignedPreKey> {
    let matches_epoch = prekey.epoch() == epoch;
    let matches_public_key: bool = prekey.public().as_bytes().ct_eq(public_key).into();
    (matches_epoch && matches_public_key).then(|| prekey.clone_for_storage())
}

fn retained_prekey_expired(retained: &RetainedSignedPreKey, now: u64) -> bool {
    if retained.superseded_at > now.saturating_add(FUTURE_TIMESTAMP_TOLERANCE_SECS) {
        return true;
    }
    now.saturating_sub(retained.superseded_at) >= SIGNED_PREKEY_RETENTION_WINDOW_SECS
}

fn encode_signed_prekey_store(store: &StoredSignedPreKeys) -> Zeroizing<Vec<u8>> {
    let mut blob = Zeroizing::new(Vec::with_capacity(
        SIGNED_PREKEY_V4_HEADER_LEN + store.retained.len() * RETAINED_SIGNED_PREKEY_RECORD_LEN,
    ));
    blob.push(SIGNED_PREKEY_VERSION);
    blob.extend_from_slice(&store.next_id.to_be_bytes());
    encode_signed_prekey_record(&mut blob, &store.current);
    blob.push(store.retained.len() as u8);
    for retained in &store.retained {
        encode_signed_prekey_record(&mut blob, &retained.prekey);
        blob.extend_from_slice(&retained.superseded_at.to_be_bytes());
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
    blob.extend_from_slice(&signed_prekey.created_at().to_be_bytes());
}

fn decode_signed_prekey_record(record: &[u8]) -> SignedPreKey {
    let mut id_bytes = [0u8; 8];
    id_bytes.copy_from_slice(&record[..8]);
    decode_legacy_signed_prekey_record(&record[8..], u64::from_be_bytes(id_bytes))
}

fn decode_legacy_signed_prekey_record(record: &[u8], id: u64) -> SignedPreKey {
    let mut secret = [0u8; 32];
    secret.copy_from_slice(&record[..32]);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&record[32..96]);
    let mut epoch_bytes = [0u8; 4];
    epoch_bytes.copy_from_slice(&record[96..100]);
    let mut timestamp_bytes = [0u8; 8];
    timestamp_bytes.copy_from_slice(&record[100..LEGACY_SIGNED_PREKEY_RECORD_LEN]);
    let epoch = u32::from_be_bytes(epoch_bytes);
    let created_at = u64::from_be_bytes(timestamp_bytes);
    SignedPreKey::from_secret_bytes(secret, signature, id, epoch, created_at)
}

fn decode_signed_prekey_store(raw: &[u8]) -> Result<StoredSignedPreKeys, SignedPreKeyError> {
    if raw == INBOX_ROTATION_REQUIRED_MARKER {
        return Err(SignedPreKeyError::InboxRotationRequired);
    }
    let store = match raw.first().copied() {
        Some(SIGNED_PREKEY_VERSION_V1) => decode_signed_prekey_store_v1(raw),
        Some(SIGNED_PREKEY_VERSION_V2) => decode_signed_prekey_store_v2(raw),
        Some(SIGNED_PREKEY_VERSION_V3) => decode_signed_prekey_store_v3(raw),
        Some(SIGNED_PREKEY_VERSION) => decode_signed_prekey_store_v4(raw),
        Some(version) => Err(SignedPreKeyError::InvalidData(format!(
            "unsupported signed pre-key format version: {version}"
        ))),
        None => Err(SignedPreKeyError::InvalidData(
            "expected signed pre-key version byte, got empty blob".into(),
        )),
    }?;
    validate_signed_prekey_store(store.next_id, &store.current, &store.retained)?;
    Ok(store)
}

fn decode_signed_prekey_store_v1(raw: &[u8]) -> Result<StoredSignedPreKeys, SignedPreKeyError> {
    if raw.len() != SIGNED_PREKEY_V1_BLOB_LEN {
        return Err(SignedPreKeyError::InvalidData(format!(
            "expected {SIGNED_PREKEY_V1_BLOB_LEN} bytes, got {}",
            raw.len()
        )));
    }
    Ok(StoredSignedPreKeys {
        next_id: 1,
        current: decode_legacy_signed_prekey_record(&raw[1..SIGNED_PREKEY_V1_BLOB_LEN], 0),
        retained: Vec::new(),
    })
}

fn decode_signed_prekey_store_v2(raw: &[u8]) -> Result<StoredSignedPreKeys, SignedPreKeyError> {
    if raw.len() != SIGNED_PREKEY_V2_BLOB_LEN {
        return Err(SignedPreKeyError::InvalidData(format!(
            "expected {SIGNED_PREKEY_V2_BLOB_LEN} bytes, got {}",
            raw.len()
        )));
    }
    let current_end = 1 + LEGACY_SIGNED_PREKEY_RECORD_LEN;
    let retained_flag = raw[current_end];
    let has_retained = match retained_flag {
        0 => false,
        1 => true,
        flag => {
            return Err(SignedPreKeyError::InvalidData(format!(
                "invalid retained signed pre-key flag: {flag}"
            )));
        }
    };
    let current = decode_legacy_signed_prekey_record(&raw[1..current_end], u64::from(has_retained));
    let retained = if has_retained {
        let retained_start = current_end + 1;
        let prekey =
            decode_legacy_signed_prekey_record(&raw[retained_start..SIGNED_PREKEY_V2_BLOB_LEN], 0);
        vec![RetainedSignedPreKey {
            superseded_at: current.created_at(),
            prekey,
        }]
    } else {
        Vec::new()
    };
    Ok(StoredSignedPreKeys {
        next_id: if has_retained { 2 } else { 1 },
        current,
        retained,
    })
}

fn decode_signed_prekey_store_v3(raw: &[u8]) -> Result<StoredSignedPreKeys, SignedPreKeyError> {
    if raw.len() != SIGNED_PREKEY_V3_BLOB_LEN {
        return Err(SignedPreKeyError::InvalidData(format!(
            "expected {SIGNED_PREKEY_V3_BLOB_LEN} bytes, got {}",
            raw.len()
        )));
    }
    let current_end = 1 + LEGACY_SIGNED_PREKEY_RECORD_LEN;
    let retained = match raw[current_end] {
        0 => Vec::new(),
        1 => {
            let retained_start = current_end + 1;
            let retained_end = retained_start + LEGACY_SIGNED_PREKEY_RECORD_LEN;
            let prekey = decode_legacy_signed_prekey_record(&raw[retained_start..retained_end], 0);
            let mut superseded_at_bytes = [0u8; 8];
            superseded_at_bytes.copy_from_slice(&raw[retained_end..SIGNED_PREKEY_V3_BLOB_LEN]);
            vec![RetainedSignedPreKey {
                prekey,
                superseded_at: u64::from_be_bytes(superseded_at_bytes),
            }]
        }
        flag => {
            return Err(SignedPreKeyError::InvalidData(format!(
                "invalid retained signed pre-key flag: {flag}"
            )));
        }
    };
    let has_retained = !retained.is_empty();
    Ok(StoredSignedPreKeys {
        next_id: if has_retained { 2 } else { 1 },
        current: decode_legacy_signed_prekey_record(&raw[1..current_end], has_retained.into()),
        retained,
    })
}

fn decode_signed_prekey_store_v4(raw: &[u8]) -> Result<StoredSignedPreKeys, SignedPreKeyError> {
    if raw.len() < SIGNED_PREKEY_V4_HEADER_LEN {
        return Err(SignedPreKeyError::InvalidData(format!(
            "expected at least {SIGNED_PREKEY_V4_HEADER_LEN} bytes, got {}",
            raw.len()
        )));
    }
    let mut next_id_bytes = [0u8; 8];
    next_id_bytes.copy_from_slice(&raw[1..9]);
    let next_id = u64::from_be_bytes(next_id_bytes);
    let current_end = 9 + SIGNED_PREKEY_RECORD_LEN;
    let current = decode_signed_prekey_record(&raw[9..current_end]);
    let retained_count = usize::from(raw[current_end]);
    if retained_count > MAX_RETAINED_SIGNED_PREKEYS {
        return Err(SignedPreKeyError::InvalidData(format!(
            "retained signed pre-key count {retained_count} exceeds {MAX_RETAINED_SIGNED_PREKEYS}"
        )));
    }
    let expected_len =
        SIGNED_PREKEY_V4_HEADER_LEN + retained_count * RETAINED_SIGNED_PREKEY_RECORD_LEN;
    if raw.len() != expected_len {
        return Err(SignedPreKeyError::InvalidData(format!(
            "expected {expected_len} bytes for {retained_count} retained signed pre-keys, got {}",
            raw.len()
        )));
    }
    let mut retained = Vec::with_capacity(retained_count);
    let mut offset = SIGNED_PREKEY_V4_HEADER_LEN;
    for _ in 0..retained_count {
        let prekey_end = offset + SIGNED_PREKEY_RECORD_LEN;
        let prekey = decode_signed_prekey_record(&raw[offset..prekey_end]);
        let superseded_at_end = prekey_end + 8;
        let mut superseded_at_bytes = [0u8; 8];
        superseded_at_bytes.copy_from_slice(&raw[prekey_end..superseded_at_end]);
        retained.push(RetainedSignedPreKey {
            prekey,
            superseded_at: u64::from_be_bytes(superseded_at_bytes),
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
        return Err(SignedPreKeyError::InvalidData(
            "next identifier does not follow current signed pre-key identifier".into(),
        ));
    }
    for (index, entry) in retained.iter().enumerate() {
        if entry.prekey.epoch() != current.epoch() {
            return Err(SignedPreKeyError::InvalidData(
                "retained signed pre-key epoch differs from current epoch".into(),
            ));
        }
        if entry.prekey.id() >= current.id() {
            return Err(SignedPreKeyError::InvalidData(
                "retained signed pre-key identifier is not older than current identifier".into(),
            ));
        }
        if retained[..index]
            .iter()
            .any(|other| other.prekey.id() == entry.prekey.id())
        {
            return Err(SignedPreKeyError::InvalidData(
                "duplicate retained signed pre-key identifier".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
fn checked_blob(raw: &[u8]) -> Result<StoredSignedPreKeys, SignedPreKeyError> {
    decode_signed_prekey_store(raw)
}

#[cfg(fuzzing)]
#[allow(missing_docs)]
pub fn fuzz_decode_signed_prekey_blob(raw: &[u8]) -> Result<(), SignedPreKeyError> {
    let _ = decode_signed_prekey_store(raw)?;
    Ok(())
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
            generate_signed_prekey(&mut OsRng, &signing_key, 0, FIXED_EPOCH, created_at);
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
            generate_signed_prekey_for_discovery_key(&mut OsRng, &discovery_key, 0, created_at);
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

    fn encode_legacy_record(blob: &mut Vec<u8>, prekey: &SignedPreKey) {
        blob.extend_from_slice(&*prekey.to_secret_bytes());
        blob.extend_from_slice(&prekey.signature().to_bytes());
        blob.extend_from_slice(&prekey.epoch().to_be_bytes());
        blob.extend_from_slice(&prekey.created_at().to_be_bytes());
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
    fn rotate_if_stale_rotates_at_weekly_boundary() {
        let setup = setup_with_discovery_key();
        let created_at = FIXED_NOW - SIGNED_PREKEY_ROTATION_WINDOW_SECS;
        let stale = store_current_discovery_signed_prekey_with_created_at(&setup, created_at);

        let rotated = setup
            .manager
            .rotate_if_stale(&mut OsRng)
            .unwrap()
            .expect("weekly boundary must rotate");

        assert_ne!(rotated.public().as_bytes(), stale.public().as_bytes());
        assert_eq!(rotated.id(), stale.id() + 1);
    }

    #[test]
    fn rotate_if_stale_retains_backdated_prekey_for_thirty_days_after_supersession() {
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
            .prekey_for_reference(
                stale_signed_prekey.epoch(),
                stale_signed_prekey.id(),
                stale_signed_prekey.public().as_bytes(),
            )
            .unwrap();
        assert_eq!(
            retained.public().as_bytes(),
            stale_signed_prekey.public().as_bytes()
        );

        let expired = manager_at(&setup, FIXED_NOW + SIGNED_PREKEY_RETENTION_WINDOW_SECS);
        assert!(matches!(
            expired.prekey_for_reference(
                stale_signed_prekey.epoch(),
                stale_signed_prekey.id(),
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
    fn rotate_now_retains_immediately_superseded_prekey_inside_retention_window() {
        let setup = setup_with_discovery_key();
        let first = setup.manager.rotate_now(&mut OsRng).unwrap();
        let second = setup.manager.rotate_now(&mut OsRng).unwrap();

        let retained = setup
            .manager
            .prekey_for_reference(first.epoch(), first.id(), first.public().as_bytes())
            .unwrap();
        let current = setup.manager.current().unwrap();

        assert_eq!(retained.public().as_bytes(), first.public().as_bytes());
        assert_eq!(current.public().as_bytes(), second.public().as_bytes());
    }

    #[test]
    fn rotate_now_retains_multiple_superseded_prekeys() {
        let setup = setup_with_discovery_key();
        let first = setup.manager.rotate_now(&mut OsRng).unwrap();
        let second = setup.manager.rotate_now(&mut OsRng).unwrap();
        let third = setup.manager.rotate_now(&mut OsRng).unwrap();

        assert!(
            setup
                .manager
                .prekey_for_reference(first.epoch(), first.id(), first.public().as_bytes())
                .is_ok()
        );
        assert!(
            setup
                .manager
                .prekey_for_reference(second.epoch(), second.id(), second.public().as_bytes())
                .is_ok()
        );
        assert_eq!(
            setup.manager.current().unwrap().public().as_bytes(),
            third.public().as_bytes()
        );
    }

    #[test]
    fn retained_prekey_expires_at_thirty_day_boundary() {
        let setup = setup_with_discovery_key();
        let first = setup.manager.rotate_now(&mut OsRng).unwrap();
        setup.manager.rotate_now(&mut OsRng).unwrap();
        let before_expiry = manager_at(&setup, FIXED_NOW + SIGNED_PREKEY_RETENTION_WINDOW_SECS - 1);
        assert!(
            before_expiry
                .prekey_for_reference(first.epoch(), first.id(), first.public().as_bytes())
                .is_ok()
        );
        let expired = manager_at(&setup, FIXED_NOW + SIGNED_PREKEY_RETENTION_WINDOW_SECS);

        assert!(matches!(
            expired.prekey_for_reference(first.epoch(), first.id(), first.public().as_bytes()),
            Err(SignedPreKeyError::NotFound)
        ));
        assert!(matches!(
            setup.manager.prekey_for_reference(
                first.epoch(),
                first.id(),
                first.public().as_bytes()
            ),
            Err(SignedPreKeyError::NotFound)
        ));
    }

    #[test]
    fn prekey_lookup_rejects_wrong_identifier_for_matching_public_key() {
        let setup = setup_with_discovery_key();
        let prekey = setup.manager.rotate_now(&mut OsRng).unwrap();

        assert!(matches!(
            setup.manager.prekey_for_reference(
                prekey.epoch(),
                prekey.id() + 1,
                prekey.public().as_bytes(),
            ),
            Err(SignedPreKeyError::NotFound)
        ));
    }

    #[test]
    fn rotate_now_refuses_to_discard_unexpired_retained_prekeys() {
        let setup = setup_with_discovery_key();
        for _ in 0..=MAX_RETAINED_SIGNED_PREKEYS {
            setup.manager.rotate_now(&mut OsRng).unwrap();
        }
        let current = setup.manager.current().unwrap();

        assert!(matches!(
            setup.manager.rotate_now(&mut OsRng),
            Err(SignedPreKeyError::InvalidData(reason)) if reason.contains("capacity")
        ));
        assert_eq!(setup.manager.current().unwrap().id(), current.id());
    }

    #[test]
    fn rotate_if_stale_rejects_unsupported_version() {
        let manager = setup_with_discovery_key().manager;
        let mut blob = [0u8; SIGNED_PREKEY_V4_HEADER_LEN];
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
            generate_signed_prekey(&mut OsRng, &identity_signing_key, 0, FIXED_EPOCH, FIXED_NOW);
        let blob = encode_signed_prekey(&original);
        assert_eq!(blob.len(), SIGNED_PREKEY_V4_HEADER_LEN);
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
    fn version_three_store_migrates_retained_and_current_identifiers() {
        let signing_key = generate_signing_key_pair(&mut OsRng);
        let retained = generate_signed_prekey(
            &mut OsRng,
            &signing_key,
            99,
            FIXED_EPOCH,
            FIXED_NOW - SECONDS_PER_DAY,
        );
        let current = generate_signed_prekey(&mut OsRng, &signing_key, 100, FIXED_EPOCH, FIXED_NOW);
        let mut blob = Vec::with_capacity(SIGNED_PREKEY_V3_BLOB_LEN);
        blob.push(SIGNED_PREKEY_VERSION_V3);
        encode_legacy_record(&mut blob, &current);
        blob.push(1);
        encode_legacy_record(&mut blob, &retained);
        blob.extend_from_slice(&FIXED_NOW.to_be_bytes());

        let migrated = decode_signed_prekey_store(&blob).unwrap();
        assert_eq!(migrated.next_id, 2);
        assert_eq!(migrated.current.id(), 1);
        assert_eq!(migrated.retained.len(), 1);
        assert_eq!(migrated.retained[0].prekey.id(), 0);
        assert!(decode_signed_prekey_store(&encode_signed_prekey_store(&migrated)).is_ok());
    }

    #[test]
    fn version_two_store_retains_key_for_thirty_days_from_current_key_creation() {
        let signing_key = generate_signing_key_pair(&mut OsRng);
        let retained = generate_signed_prekey(
            &mut OsRng,
            &signing_key,
            99,
            FIXED_EPOCH,
            FIXED_NOW - SIGNED_PREKEY_ROTATION_WINDOW_SECS,
        );
        let current = generate_signed_prekey(&mut OsRng, &signing_key, 100, FIXED_EPOCH, FIXED_NOW);
        let mut blob = Vec::with_capacity(SIGNED_PREKEY_V2_BLOB_LEN);
        blob.push(SIGNED_PREKEY_VERSION_V2);
        encode_legacy_record(&mut blob, &current);
        blob.push(1);
        encode_legacy_record(&mut blob, &retained);

        let migrated = decode_signed_prekey_store(&blob).unwrap();
        let migrated_retained = &migrated.retained[0];

        assert_eq!(migrated_retained.superseded_at, FIXED_NOW);
        assert!(!retained_prekey_expired(
            migrated_retained,
            FIXED_NOW + SIGNED_PREKEY_RETENTION_WINDOW_SECS - 1,
        ));
        assert!(retained_prekey_expired(
            migrated_retained,
            FIXED_NOW + SIGNED_PREKEY_RETENTION_WINDOW_SECS,
        ));
    }

    #[test]
    fn legacy_store_rejects_retained_key_from_different_epoch_before_migration() {
        let signing_key = generate_signing_key_pair(&mut OsRng);
        let current = generate_signed_prekey(&mut OsRng, &signing_key, 1, FIXED_EPOCH, FIXED_NOW);
        let retained = generate_signed_prekey(
            &mut OsRng,
            &signing_key,
            0,
            FIXED_EPOCH + 1,
            FIXED_NOW - SECONDS_PER_DAY,
        );
        let mut version_two = Vec::with_capacity(SIGNED_PREKEY_V2_BLOB_LEN);
        version_two.push(SIGNED_PREKEY_VERSION_V2);
        encode_legacy_record(&mut version_two, &current);
        version_two.push(1);
        encode_legacy_record(&mut version_two, &retained);
        let mut version_three = version_two.clone();
        version_three[0] = SIGNED_PREKEY_VERSION_V3;
        version_three.extend_from_slice(&FIXED_NOW.to_be_bytes());

        for blob in [version_two, version_three] {
            assert!(matches!(
                decode_signed_prekey_store(&blob),
                Err(SignedPreKeyError::InvalidData(reason)) if reason.contains("epoch")
            ));
        }
    }

    #[test]
    fn rotation_rejects_exhausted_signed_prekey_identifier_space() {
        let setup = setup_with_discovery_key();
        let discovery_key = setup.discovery.current().unwrap();
        let current = generate_signed_prekey_for_discovery_key(
            &mut OsRng,
            &discovery_key,
            u64::MAX - 1,
            FIXED_NOW,
        );
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
            setup.manager.rotate_now(&mut OsRng),
            Err(SignedPreKeyError::InvalidData(reason)) if reason.contains("exhausted")
        ));
        assert_eq!(setup.manager.current().unwrap().id(), u64::MAX - 1);
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
        let mut blob = [0u8; SIGNED_PREKEY_V4_HEADER_LEN];
        blob[0] = 99;
        assert!(matches!(
            checked_blob(&blob),
            Err(SignedPreKeyError::InvalidData(reason)) if reason.contains("version")
        ));
    }
}
