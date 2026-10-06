use crate::discovery_key::{DiscoveryKeyError, DiscoveryKeyManager};
use crate::prekey_state::INBOX_ROTATION_REQUIRED_MARKER;
use crate::storage::{SecureStorage, StorageError};
use rand::{CryptoRng, RngCore};
use roost_crypto::{OneTimePreKey, PublicOneTimePreKey, generate_one_time_prekey};
use roost_protocol::to_unix_secs;
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::SystemTime;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub(crate) const ONE_TIME_PREKEY_POOL_TARGET: usize = 100;
pub(crate) const ONE_TIME_PREKEY_REPLENISH_THRESHOLD: usize = 25;
const MAX_ONE_TIME_PREKEYS: usize = ONE_TIME_PREKEY_POOL_TARGET;

const ONE_TIME_PREKEY_POOL_KEY: &str = "prekey/one-time-pool";
const ONE_TIME_PREKEY_POOL_VERSION: u8 = 1;
// Header layout: version (1) | epoch (4) | next_id (8) | count (2).
const ONE_TIME_PREKEY_POOL_HEADER_LEN: usize = 1 + 4 + 8 + 2;
// Entry layout: id (8) | secret (32) | created_at (8).
const ONE_TIME_PREKEY_ENTRY_LEN: usize = 8 + 32 + 8;

/// Errors returned by one-time-pre-key operations.
#[derive(Debug, thiserror::Error)]
pub enum OneTimePreKeyError {
    /// Stored data uses an unsupported format version.
    #[error("unsupported stored format version: {0}")]
    UnsupportedVersion(u8),
    /// The system clock is before the Unix epoch.
    #[error("system clock is before Unix epoch")]
    Clock,
    /// Loading the discovery key returned a [`DiscoveryKeyError`].
    #[error("loading the discovery key failed")]
    Discovery(#[from] DiscoveryKeyError),
    /// Backup restoration requires an inbox rotation before prekeys may be used.
    #[error("inbox rotation required before using restored pre-key state")]
    InboxRotationRequired,
    /// A requested batch doesn't fit the pool's free slots.
    #[error("one-time pre-key batch of {requested} exceeds the {available} free slots")]
    BatchExceedsCapacity {
        /// Requested batch size.
        requested: usize,
        /// Free slots in the pool.
        available: usize,
    },
    /// The stored pool is shorter than its header.
    #[error("one-time pre-key pool is {len} bytes, shorter than {min_len}")]
    BlobTooShort {
        /// Stored length in bytes.
        len: usize,
        /// Shortest accepted length in bytes.
        min_len: usize,
    },
    /// The stored pool repeats an identifier.
    #[error("duplicate one-time pre-key identifier {0}")]
    DuplicateId(u64),
    /// Every one-time-pre-key identifier has been used.
    #[error("one-time pre-key identifier space exhausted")]
    IdentifiersExhausted,
    /// A stored one-time pre-key's identifier isn't below the pool's next identifier.
    #[error("one-time pre-key identifier {id} is not below next identifier {next_id}")]
    IdNotBelowNextId {
        /// Stored identifier.
        id: u64,
        /// Pool's next identifier.
        next_id: u64,
    },
    /// The stored pool's length doesn't match its entry count.
    #[error("one-time pre-key pool is {actual} bytes, expected {expected}")]
    InvalidBlobLength {
        /// Expected length in bytes.
        expected: usize,
        /// Stored length in bytes.
        actual: usize,
    },
    /// The internal storage lock was poisoned by a panicked thread.
    #[error("internal lock poisoned")]
    LockPoisoned,
    /// The requested one-time pre-key is absent or already consumed.
    #[error("one-time pre-key not found")]
    NotFound,
    /// The requested one-time pre-key belongs to another discovery-key epoch.
    #[error("one-time pre-key belongs to a superseded discovery-key epoch")]
    StaleEpoch,
    /// The stored pool holds more one-time pre-keys than the limit allows.
    #[error("{count} stored one-time pre-keys exceed the limit of {max}")]
    TooManyPreKeys {
        /// Stored count.
        count: usize,
        /// Largest accepted count.
        max: usize,
    },
    /// The underlying [`SecureStorage`] returned an error.
    #[error("one-time pre-key storage failed")]
    Storage(#[from] StorageError),
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct OneTimePreKeyEntry {
    #[zeroize(skip)]
    id: u64,
    secret: [u8; 32],
    #[zeroize(skip)]
    created_at_secs: u64,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct OneTimePreKeyPool {
    #[zeroize(skip)]
    epoch: u32,
    #[zeroize(skip)]
    next_id: u64,
    entries: Vec<OneTimePreKeyEntry>,
}

// Manages one-time-pre-key pool generation, consumption, and persistence.
pub(crate) struct OneTimePreKeyManager {
    storage: Arc<Mutex<Box<dyn SecureStorage>>>,
    discovery: Arc<DiscoveryKeyManager>,
}

impl OneTimePreKeyManager {
    pub(crate) fn new(
        storage: Arc<Mutex<Box<dyn SecureStorage>>>,
        discovery: Arc<DiscoveryKeyManager>,
    ) -> Self {
        Self { storage, discovery }
    }

    pub(crate) fn replenish<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        now: SystemTime,
    ) -> Result<Vec<PublicOneTimePreKey>, OneTimePreKeyError> {
        let discovery_key = self.discovery.current()?;
        let epoch = discovery_key.epoch();
        let now_secs = to_unix_secs(now).ok_or(OneTimePreKeyError::Clock)?;
        let mut storage = self.lock_storage()?;
        let mut pool = current_epoch_pool(storage.as_mut(), epoch)?;
        if pool.entries.len() > ONE_TIME_PREKEY_REPLENISH_THRESHOLD {
            return Ok(Vec::new());
        }

        let needed = ONE_TIME_PREKEY_POOL_TARGET - pool.entries.len();
        let bundles = append_batch(rng, &mut pool, needed, epoch, now_secs)?;
        let blob = encode_pool(&pool);
        storage.store(ONE_TIME_PREKEY_POOL_KEY, &blob)?;
        Ok(bundles)
    }

    pub(crate) fn generate_batch<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        batch_size: usize,
        now: SystemTime,
    ) -> Result<Vec<PublicOneTimePreKey>, OneTimePreKeyError> {
        let discovery_key = self.discovery.current()?;
        let epoch = discovery_key.epoch();
        let now_secs = to_unix_secs(now).ok_or(OneTimePreKeyError::Clock)?;
        let mut storage = self.lock_storage()?;
        let mut pool = current_epoch_pool(storage.as_mut(), epoch)?;
        let bundles = append_batch(rng, &mut pool, batch_size, epoch, now_secs)?;
        let blob = encode_pool(&pool);
        storage.store(ONE_TIME_PREKEY_POOL_KEY, &blob)?;
        Ok(bundles)
    }

    #[allow(dead_code)]
    pub(crate) fn consume_one_time_prekey(
        &self,
        epoch: u32,
        id: u64,
    ) -> Result<OneTimePreKey, OneTimePreKeyError> {
        let mut storage = self.lock_storage()?;
        let raw = storage
            .load(ONE_TIME_PREKEY_POOL_KEY)?
            .ok_or(OneTimePreKeyError::NotFound)?;
        let mut pool = decode_pool(&raw)?;
        if pool.epoch != epoch {
            return Err(OneTimePreKeyError::StaleEpoch);
        }
        let index = pool
            .entries
            .iter()
            .position(|entry| entry.id == id)
            .ok_or(OneTimePreKeyError::NotFound)?;
        let entry = pool.entries.remove(index);
        let prekey = OneTimePreKey::from_secret_bytes(
            entry.id,
            entry.secret,
            pool.epoch,
            entry.created_at_secs,
        );
        let blob = encode_pool(&pool);
        storage.store(ONE_TIME_PREKEY_POOL_KEY, &blob)?;
        Ok(prekey)
    }

    pub(crate) fn one_time_prekey_for_public_key(
        &self,
        epoch: u32,
        id: u64,
        public_key: &[u8; 32],
    ) -> Result<OneTimePreKey, OneTimePreKeyError> {
        let storage = self.lock_storage()?;
        let raw = storage
            .load(ONE_TIME_PREKEY_POOL_KEY)?
            .ok_or(OneTimePreKeyError::NotFound)?;
        let pool = decode_pool(&raw)?;
        if pool.epoch != epoch {
            return Err(OneTimePreKeyError::StaleEpoch);
        }
        let entry = pool
            .entries
            .iter()
            .find(|entry| entry.id == id)
            .ok_or(OneTimePreKeyError::NotFound)?;
        let prekey = OneTimePreKey::from_secret_bytes(
            entry.id,
            entry.secret,
            pool.epoch,
            entry.created_at_secs,
        );
        let public_matches = prekey.public_key().as_bytes().ct_eq(public_key).unwrap_u8() == 1;
        if public_matches {
            Ok(prekey)
        } else {
            Err(OneTimePreKeyError::NotFound)
        }
    }

    pub(crate) fn reset(&self) -> Result<(), OneTimePreKeyError> {
        let mut storage = self.lock_storage()?;
        Ok(storage.delete(ONE_TIME_PREKEY_POOL_KEY)?)
    }

    pub(crate) fn mark_inbox_rotation_required(&self) -> Result<(), OneTimePreKeyError> {
        let mut storage = self.lock_storage()?;
        Ok(storage.store(ONE_TIME_PREKEY_POOL_KEY, INBOX_ROTATION_REQUIRED_MARKER)?)
    }

    fn lock_storage(&self) -> Result<MutexGuard<'_, Box<dyn SecureStorage>>, OneTimePreKeyError> {
        self.storage
            .lock()
            .map_err(|_| OneTimePreKeyError::LockPoisoned)
    }
}

fn empty_pool(epoch: u32) -> OneTimePreKeyPool {
    OneTimePreKeyPool {
        epoch,
        next_id: 0,
        entries: Vec::new(),
    }
}

fn current_epoch_pool(
    storage: &mut dyn SecureStorage,
    epoch: u32,
) -> Result<OneTimePreKeyPool, OneTimePreKeyError> {
    let pool = match storage.load(ONE_TIME_PREKEY_POOL_KEY)? {
        Some(raw) => decode_pool(&raw)?,
        None => empty_pool(epoch),
    };
    if pool.epoch == epoch {
        Ok(pool)
    } else {
        Ok(empty_pool(epoch))
    }
}

fn append_batch<R: RngCore + CryptoRng>(
    rng: &mut R,
    pool: &mut OneTimePreKeyPool,
    batch_size: usize,
    epoch: u32,
    created_at_secs: u64,
) -> Result<Vec<PublicOneTimePreKey>, OneTimePreKeyError> {
    let available = MAX_ONE_TIME_PREKEYS - pool.entries.len();
    if batch_size > available {
        return Err(OneTimePreKeyError::BatchExceedsCapacity {
            requested: batch_size,
            available,
        });
    }

    let mut bundles = Vec::with_capacity(batch_size);
    for _ in 0..batch_size {
        let id = pool.next_id;
        // A corrupt stored counter can still overflow.
        pool.next_id = pool
            .next_id
            .checked_add(1)
            .ok_or(OneTimePreKeyError::IdentifiersExhausted)?;
        let one_time_prekey = generate_one_time_prekey(rng, id, epoch, created_at_secs);
        pool.entries.push(OneTimePreKeyEntry {
            id,
            secret: *one_time_prekey.to_secret_bytes(),
            created_at_secs,
        });
        bundles.push(one_time_prekey.public());
    }
    Ok(bundles)
}

fn encode_pool(pool: &OneTimePreKeyPool) -> Zeroizing<Vec<u8>> {
    let mut blob = Zeroizing::new(Vec::with_capacity(
        ONE_TIME_PREKEY_POOL_HEADER_LEN + pool.entries.len() * ONE_TIME_PREKEY_ENTRY_LEN,
    ));
    blob.push(ONE_TIME_PREKEY_POOL_VERSION);
    blob.extend_from_slice(&pool.epoch.to_be_bytes());
    blob.extend_from_slice(&pool.next_id.to_be_bytes());
    let count = pool.entries.len() as u16;
    blob.extend_from_slice(&count.to_be_bytes());
    for entry in &pool.entries {
        blob.extend_from_slice(&entry.id.to_be_bytes());
        blob.extend_from_slice(&entry.secret);
        blob.extend_from_slice(&entry.created_at_secs.to_be_bytes());
    }
    blob
}

fn decode_pool(raw: &[u8]) -> Result<OneTimePreKeyPool, OneTimePreKeyError> {
    if raw == INBOX_ROTATION_REQUIRED_MARKER {
        return Err(OneTimePreKeyError::InboxRotationRequired);
    }
    if raw.len() < ONE_TIME_PREKEY_POOL_HEADER_LEN {
        return Err(OneTimePreKeyError::BlobTooShort {
            len: raw.len(),
            min_len: ONE_TIME_PREKEY_POOL_HEADER_LEN,
        });
    }
    if raw[0] != ONE_TIME_PREKEY_POOL_VERSION {
        return Err(OneTimePreKeyError::UnsupportedVersion(raw[0]));
    }
    let mut count_bytes = [0u8; 2];
    count_bytes.copy_from_slice(&raw[13..15]);
    let count = u16::from_be_bytes(count_bytes) as usize;
    if count > MAX_ONE_TIME_PREKEYS {
        return Err(OneTimePreKeyError::TooManyPreKeys {
            count,
            max: MAX_ONE_TIME_PREKEYS,
        });
    }
    let expected_len = ONE_TIME_PREKEY_POOL_HEADER_LEN + count * ONE_TIME_PREKEY_ENTRY_LEN;
    if raw.len() != expected_len {
        return Err(OneTimePreKeyError::InvalidBlobLength {
            expected: expected_len,
            actual: raw.len(),
        });
    }

    let mut epoch_bytes = [0u8; 4];
    epoch_bytes.copy_from_slice(&raw[1..5]);
    let epoch = u32::from_be_bytes(epoch_bytes);
    let mut next_id_bytes = [0u8; 8];
    next_id_bytes.copy_from_slice(&raw[5..13]);
    let next_id = u64::from_be_bytes(next_id_bytes);
    let mut entries = Vec::with_capacity(count);
    let mut ids = BTreeSet::new();
    let mut offset = ONE_TIME_PREKEY_POOL_HEADER_LEN;
    for _ in 0..count {
        let mut id_bytes = [0u8; 8];
        id_bytes.copy_from_slice(&raw[offset..offset + 8]);
        let id = u64::from_be_bytes(id_bytes);
        if id >= next_id {
            return Err(OneTimePreKeyError::IdNotBelowNextId { id, next_id });
        }
        if !ids.insert(id) {
            return Err(OneTimePreKeyError::DuplicateId(id));
        }
        offset += 8;
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&raw[offset..offset + 32]);
        offset += 32;
        let mut created_at_bytes = [0u8; 8];
        created_at_bytes.copy_from_slice(&raw[offset..offset + 8]);
        let created_at_secs = u64::from_be_bytes(created_at_bytes);
        offset += 8;
        entries.push(OneTimePreKeyEntry {
            id,
            secret,
            created_at_secs,
        });
    }
    Ok(OneTimePreKeyPool {
        epoch,
        next_id,
        entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityManager;
    use crate::storage::InMemorySecureStorage;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use roost_protocol::from_unix_secs;
    use std::time::SystemTime;

    const FIXED_NOW: u64 = 1_700_000_000;

    fn fixed_now() -> SystemTime {
        from_unix_secs(FIXED_NOW).unwrap()
    }

    struct OneTimePreKeySetup {
        discovery: Arc<DiscoveryKeyManager>,
        manager: OneTimePreKeyManager,
    }

    fn shared_storage() -> Arc<Mutex<Box<dyn SecureStorage>>> {
        Arc::new(Mutex::new(Box::new(InMemorySecureStorage::new())))
    }

    fn setup_with_discovery_key() -> OneTimePreKeySetup {
        let mut rng = ChaCha20Rng::from_seed([0xd0; 32]);
        let storage = shared_storage();
        let identity = Arc::new(IdentityManager::new(Arc::clone(&storage)));
        identity.generate_identity(&mut rng).unwrap();
        let discovery = Arc::new(DiscoveryKeyManager::new(Arc::clone(&storage), identity));
        discovery.rotate_now(&mut rng, fixed_now()).unwrap();
        let manager = OneTimePreKeyManager::new(storage, Arc::clone(&discovery));
        OneTimePreKeySetup { discovery, manager }
    }

    fn encoded_pool_header(next_id: u64, count: u16) -> Vec<u8> {
        let mut raw = Vec::with_capacity(
            ONE_TIME_PREKEY_POOL_HEADER_LEN + count as usize * ONE_TIME_PREKEY_ENTRY_LEN,
        );
        raw.push(ONE_TIME_PREKEY_POOL_VERSION);
        raw.extend_from_slice(&7u32.to_be_bytes());
        raw.extend_from_slice(&next_id.to_be_bytes());
        raw.extend_from_slice(&count.to_be_bytes());
        raw
    }

    fn encoded_entry(id: u64, created_at_secs: u64) -> [u8; ONE_TIME_PREKEY_ENTRY_LEN] {
        let mut entry = [0u8; ONE_TIME_PREKEY_ENTRY_LEN];
        entry[..8].copy_from_slice(&id.to_be_bytes());
        entry[8..40].copy_from_slice(&[id as u8; 32]);
        entry[40..].copy_from_slice(&created_at_secs.to_be_bytes());
        entry
    }

    #[test]
    fn replenish_creates_initial_pool() {
        let mut rng = ChaCha20Rng::from_seed([0xd1; 32]);
        let OneTimePreKeySetup { discovery, manager } = setup_with_discovery_key();
        let bundles = manager.replenish(&mut rng, fixed_now()).unwrap();
        assert_eq!(bundles.len(), ONE_TIME_PREKEY_POOL_TARGET);
        assert!(
            bundles
                .iter()
                .all(|bundle| bundle.epoch == discovery.current().unwrap().epoch())
        );
    }

    #[test]
    fn consume_one_time_prekey_consumes_secret_once() {
        let mut rng = ChaCha20Rng::from_seed([0xd2; 32]);
        let OneTimePreKeySetup { discovery, manager } = setup_with_discovery_key();
        let bundle = manager.replenish(&mut rng, fixed_now()).unwrap().remove(0);
        let prekey = manager
            .consume_one_time_prekey(discovery.current().unwrap().epoch(), bundle.id)
            .unwrap();
        assert_eq!(prekey.id(), bundle.id);
        assert!(matches!(
            manager.consume_one_time_prekey(discovery.current().unwrap().epoch(), bundle.id),
            Err(OneTimePreKeyError::NotFound)
        ));
    }

    #[test]
    fn generate_batch_creates_exact_caller_size_under_current_epoch() {
        let mut rng = ChaCha20Rng::from_seed([0xd3; 32]);
        let OneTimePreKeySetup { discovery, manager } = setup_with_discovery_key();
        let first = manager.generate_batch(&mut rng, 3, fixed_now()).unwrap();
        let second = manager.generate_batch(&mut rng, 2, fixed_now()).unwrap();
        let epoch = discovery.current().unwrap().epoch();

        assert_eq!(first.len(), 3);
        assert_eq!(second.len(), 2);
        assert!(
            first
                .iter()
                .chain(&second)
                .all(|bundle| bundle.epoch == epoch)
        );
        assert_eq!(
            first
                .iter()
                .chain(&second)
                .map(|bundle| bundle.id)
                .collect::<Vec<_>>(),
            vec![0, 1, 2, 3, 4]
        );
    }

    #[test]
    fn generate_batch_rejects_capacity_overflow_without_mutating_pool() {
        let mut rng = ChaCha20Rng::from_seed([0xd4; 32]);
        let OneTimePreKeySetup { discovery, manager } = setup_with_discovery_key();
        let full_batch = manager
            .generate_batch(&mut rng, ONE_TIME_PREKEY_POOL_TARGET, fixed_now())
            .unwrap();
        let epoch = discovery.current().unwrap().epoch();

        assert!(matches!(
            manager.generate_batch(&mut rng, 1, fixed_now()),
            Err(OneTimePreKeyError::BatchExceedsCapacity {
                requested: 1,
                available: 0
            })
        ));
        assert_eq!(
            manager
                .consume_one_time_prekey(epoch, full_batch[0].id)
                .unwrap()
                .id(),
            0
        );
    }

    #[test]
    fn generate_batch_rejects_id_overflow_without_mutating_pool() {
        let mut rng = ChaCha20Rng::from_seed([0xd5; 32]);
        let OneTimePreKeySetup { discovery, manager } = setup_with_discovery_key();
        let epoch = discovery.current().unwrap().epoch();
        let mut raw = encoded_pool_header(u64::MAX, 0);
        raw[1..5].copy_from_slice(&epoch.to_be_bytes());
        manager
            .storage
            .lock()
            .unwrap()
            .store(ONE_TIME_PREKEY_POOL_KEY, &raw)
            .unwrap();

        assert!(matches!(
            manager.generate_batch(&mut rng, 1, fixed_now()),
            Err(OneTimePreKeyError::IdentifiersExhausted)
        ));
        assert_eq!(
            manager
                .storage
                .lock()
                .unwrap()
                .load(ONE_TIME_PREKEY_POOL_KEY)
                .unwrap()
                .unwrap()
                .as_slice(),
            raw
        );
    }

    #[test]
    fn decode_pool_rejects_over_cap_count() {
        let mut raw = vec![0u8; ONE_TIME_PREKEY_POOL_HEADER_LEN];
        raw[0] = ONE_TIME_PREKEY_POOL_VERSION;
        raw[13..15].copy_from_slice(&(MAX_ONE_TIME_PREKEYS as u16 + 1).to_be_bytes());
        raw.resize(
            ONE_TIME_PREKEY_POOL_HEADER_LEN
                + (MAX_ONE_TIME_PREKEYS + 1) * ONE_TIME_PREKEY_ENTRY_LEN,
            0,
        );
        assert!(matches!(
            decode_pool(&raw),
            Err(OneTimePreKeyError::TooManyPreKeys { count, max: MAX_ONE_TIME_PREKEYS })
                if count == MAX_ONE_TIME_PREKEYS + 1
        ));
    }

    #[test]
    fn decode_pool_rejects_length_mismatch() {
        let mut raw = vec![0u8; ONE_TIME_PREKEY_POOL_HEADER_LEN];
        raw[0] = ONE_TIME_PREKEY_POOL_VERSION;
        raw[13..15].copy_from_slice(&1u16.to_be_bytes());
        assert!(matches!(
            decode_pool(&raw),
            Err(OneTimePreKeyError::InvalidBlobLength {
                expected,
                actual: ONE_TIME_PREKEY_POOL_HEADER_LEN,
            }) if expected == ONE_TIME_PREKEY_POOL_HEADER_LEN + ONE_TIME_PREKEY_ENTRY_LEN
        ));
    }

    #[test]
    fn decode_pool_rejects_duplicate_ids() {
        let mut raw = encoded_pool_header(3, 2);
        raw.extend_from_slice(&encoded_entry(0, 1));
        raw.extend_from_slice(&encoded_entry(0, 2));
        assert!(matches!(
            decode_pool(&raw),
            Err(OneTimePreKeyError::DuplicateId(0))
        ));
    }

    #[test]
    fn decode_pool_rejects_entry_id_not_less_than_next_id() {
        let mut raw = encoded_pool_header(1, 1);
        raw.extend_from_slice(&encoded_entry(1, 1));
        assert!(matches!(
            decode_pool(&raw),
            Err(OneTimePreKeyError::IdNotBelowNextId { id: 1, next_id: 1 })
        ));
    }
}
