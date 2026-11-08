use crate::discovery_key::{DiscoveryKeyError, DiscoveryKeyManager};
use crate::storage::{SecureStorage, StorageError};
use crate::stored_data::{
    StoredDataError, decode_versioned, deserialize_bounded, encode_versioned,
};
use rand::{CryptoRng, RngCore};
use roost_crypto::{OneTimePreKey, PublicOneTimePreKey, generate_one_time_prekey};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex, MutexGuard};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub(crate) const ONE_TIME_PREKEY_POOL_TARGET: usize = 100;
pub(crate) const ONE_TIME_PREKEY_REPLENISH_THRESHOLD: usize = 25;

const ONE_TIME_PREKEYS: &str = "prekey/one-time-pool";
const ONE_TIME_PREKEYS_VERSION: u8 = 1;

/// Errors returned by one-time prekey operations.
#[derive(Debug, thiserror::Error)]
pub enum OneTimePreKeyError {
    /// A requested batch doesn't fit the pool's free slots.
    #[error("one-time prekey batch of {requested} exceeds the {available} free slots")]
    BatchExceedsCapacity {
        /// Requested batch size.
        requested: usize,
        /// Free slots in the pool.
        available: usize,
    },
    /// Loading the discovery key failed.
    #[error("loading the discovery key failed")]
    Discovery(#[from] DiscoveryKeyError),
    /// Every one-time prekey identifier has been used.
    #[error("one-time prekey identifier space exhausted")]
    IdentifiersExhausted,
    /// Backup restoration requires an inbox rotation before prekeys may be used.
    #[error("inbox rotation required before using restored prekey state")]
    InboxRotationRequired,
    /// The internal storage lock was poisoned by a panicked thread.
    #[error("internal lock poisoned")]
    LockPoisoned,
    /// The pool holds no one-time prekey with the requested ID, or the one it holds has another
    /// public key.
    #[error("one-time prekey not found")]
    NotFound,
    /// The requested one-time prekey belongs to another discovery key epoch than the pool.
    #[error("one-time prekey epoch {epoch} differs from the pool's epoch {pool_epoch}")]
    StaleEpoch {
        /// Requested epoch.
        epoch: u32,
        /// Epoch of the stored pool.
        pool_epoch: u32,
    },
    /// The underlying [`SecureStorage`] returned an error.
    #[error("one-time prekey storage failed")]
    Storage(#[from] StorageError),
    /// The pool failed to encode, or the stored one is malformed or uses an unknown version.
    #[error("one-time prekey pool failed to encode or decode")]
    StoredData(#[from] StoredDataError),
    /// A session already used the requested one-time prekey.
    #[error("one-time prekey {id} was already used")]
    Used {
        /// The used one-time prekey's identifier.
        id: u64,
    },
}

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

    // Refills a pool at or below the threshold up to its target, and returns the new prekeys.
    pub(crate) fn replenish<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<Vec<PublicOneTimePreKey>, OneTimePreKeyError> {
        self.append(rng, |pool| {
            if pool.entries.len() > ONE_TIME_PREKEY_REPLENISH_THRESHOLD {
                0
            } else {
                ONE_TIME_PREKEY_POOL_TARGET - pool.entries.len()
            }
        })
    }

    pub(crate) fn generate_batch<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        batch_size: usize,
    ) -> Result<Vec<PublicOneTimePreKey>, OneTimePreKeyError> {
        self.append(rng, |_| batch_size)
    }

    // Removes the one-time prekey `id` of `epoch` from the pool and returns it.
    pub(crate) fn consume_one_time_prekey(
        &self,
        epoch: u32,
        id: u64,
    ) -> Result<OneTimePreKey, OneTimePreKeyError> {
        let mut storage = self.lock_storage()?;
        let mut pool = load_pool(&**storage)?.ok_or(OneTimePreKeyError::NotFound)?;
        check_epoch(&pool, epoch)?;
        let index = pool
            .entries
            .iter()
            .position(|entry| entry.id == id)
            .ok_or(OneTimePreKeyError::NotFound)?;
        let prekey = pool.entries.remove(index).to_prekey(pool.epoch);
        store_pool(&mut **storage, pool)?;
        Ok(prekey)
    }

    pub(crate) fn one_time_prekey_for_public_key(
        &self,
        epoch: u32,
        id: u64,
        public_key: &[u8; 32],
    ) -> Result<OneTimePreKey, OneTimePreKeyError> {
        let pool = load_pool(&**self.lock_storage()?)?.ok_or(OneTimePreKeyError::NotFound)?;
        check_epoch(&pool, epoch)?;
        let prekey = pool
            .entries
            .iter()
            .find(|entry| entry.id == id)
            .ok_or(if id < pool.next_id {
                OneTimePreKeyError::Used { id }
            } else {
                OneTimePreKeyError::NotFound
            })?
            .to_prekey(pool.epoch);
        if bool::from(prekey.public_key().as_bytes().ct_eq(public_key)) {
            Ok(prekey)
        } else {
            Err(OneTimePreKeyError::NotFound)
        }
    }

    pub(crate) fn reset(&self) -> Result<(), OneTimePreKeyError> {
        Ok(self.lock_storage()?.delete(ONE_TIME_PREKEYS)?)
    }

    pub(crate) fn mark_inbox_rotation_required(&self) -> Result<(), OneTimePreKeyError> {
        let entry = encode_versioned(
            ONE_TIME_PREKEYS_VERSION,
            &OneTimePreKeysWire::InboxRotationRequired,
        )?;
        Ok(self.lock_storage()?.store(ONE_TIME_PREKEYS, &entry)?)
    }

    // Appends as many prekeys as `count` asks for to the stored pool, or to a new pool for the
    // current epoch, and returns the new prekeys.
    fn append<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        count: impl FnOnce(&OneTimePreKeyPoolWire) -> usize,
    ) -> Result<Vec<PublicOneTimePreKey>, OneTimePreKeyError> {
        let epoch = self.discovery.current()?.epoch();
        let mut storage = self.lock_storage()?;
        // Every inbox rotation deletes the pool, so a stored pool belongs to the current epoch.
        let mut pool = match load_pool(&**storage)? {
            Some(stored) => with_room(stored),
            None => OneTimePreKeyPoolWire {
                epoch,
                next_id: 0,
                entries: Vec::with_capacity(ONE_TIME_PREKEY_POOL_TARGET),
            },
        };
        let count = count(&pool);
        if count == 0 {
            return Ok(Vec::new());
        }
        let prekeys = append_batch(rng, &mut pool, count)?;
        store_pool(&mut **storage, pool)?;
        Ok(prekeys)
    }

    fn lock_storage(&self) -> Result<MutexGuard<'_, Box<dyn SecureStorage>>, OneTimePreKeyError> {
        self.storage
            .lock()
            .map_err(|_| OneTimePreKeyError::LockPoisoned)
    }
}

fn check_epoch(pool: &OneTimePreKeyPoolWire, epoch: u32) -> Result<(), OneTimePreKeyError> {
    if pool.epoch == epoch {
        Ok(())
    } else {
        Err(OneTimePreKeyError::StaleEpoch {
            epoch,
            pool_epoch: pool.epoch,
        })
    }
}

// Moves the pool's prekeys into a list with room for the most it holds, so appending never
// reallocates and leaves secrets in freed memory.
fn with_room(mut pool: OneTimePreKeyPoolWire) -> OneTimePreKeyPoolWire {
    let mut entries = Vec::with_capacity(ONE_TIME_PREKEY_POOL_TARGET);
    entries.append(&mut pool.entries);
    OneTimePreKeyPoolWire {
        epoch: pool.epoch,
        next_id: pool.next_id,
        entries,
    }
}

fn append_batch<R: RngCore + CryptoRng>(
    rng: &mut R,
    pool: &mut OneTimePreKeyPoolWire,
    batch_size: usize,
) -> Result<Vec<PublicOneTimePreKey>, OneTimePreKeyError> {
    let available = ONE_TIME_PREKEY_POOL_TARGET - pool.entries.len();
    if batch_size > available {
        return Err(OneTimePreKeyError::BatchExceedsCapacity {
            requested: batch_size,
            available,
        });
    }

    let mut prekeys = Vec::with_capacity(batch_size);
    for _ in 0..batch_size {
        let id = pool.next_id;
        // A corrupt stored counter can still overflow.
        pool.next_id = pool
            .next_id
            .checked_add(1)
            .ok_or(OneTimePreKeyError::IdentifiersExhausted)?;
        let one_time_prekey = generate_one_time_prekey(rng, id, pool.epoch);
        pool.entries.push(OneTimePreKeyWire {
            id,
            secret: *one_time_prekey.to_secret_bytes(),
        });
        prekeys.push(one_time_prekey.public());
    }
    Ok(prekeys)
}

fn load_pool(
    storage: &dyn SecureStorage,
) -> Result<Option<OneTimePreKeyPoolWire>, OneTimePreKeyError> {
    let Some(entry) = storage.load(ONE_TIME_PREKEYS)? else {
        return Ok(None);
    };
    match decode_versioned(ONE_TIME_PREKEYS_VERSION, &entry)? {
        OneTimePreKeysWire::InboxRotationRequired => Err(OneTimePreKeyError::InboxRotationRequired),
        OneTimePreKeysWire::Pool(pool) => Ok(Some(pool)),
    }
}

fn store_pool(
    storage: &mut dyn SecureStorage,
    pool: OneTimePreKeyPoolWire,
) -> Result<(), OneTimePreKeyError> {
    let entry = encode_versioned(ONE_TIME_PREKEYS_VERSION, &OneTimePreKeysWire::Pool(pool))?;
    Ok(storage.store(ONE_TIME_PREKEYS, &entry)?)
}

#[derive(Deserialize, Serialize)]
enum OneTimePreKeysWire {
    // A restored backup left these prekeys unusable until an inbox rotation replaces them.
    InboxRotationRequired,
    Pool(OneTimePreKeyPoolWire),
}

#[derive(Deserialize, Serialize, ZeroizeOnDrop)]
struct OneTimePreKeyPoolWire {
    #[zeroize(skip)]
    epoch: u32,
    #[zeroize(skip)]
    next_id: u64,
    #[serde(deserialize_with = "deserialize_bounded::<_, _, ONE_TIME_PREKEY_POOL_TARGET>")]
    entries: Vec<OneTimePreKeyWire>,
}

#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
struct OneTimePreKeyWire {
    #[zeroize(skip)]
    id: u64,
    secret: [u8; 32],
}

impl OneTimePreKeyWire {
    fn to_prekey(&self, epoch: u32) -> OneTimePreKey {
        OneTimePreKey::from_secret_bytes(self.id, &self.secret, epoch)
    }
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

    fn entry(id: u64) -> OneTimePreKeyWire {
        OneTimePreKeyWire {
            id,
            secret: [id as u8; 32],
        }
    }

    fn store(manager: &OneTimePreKeyManager, pool: OneTimePreKeyPoolWire) {
        store_pool(&mut **manager.lock_storage().unwrap(), pool).unwrap();
    }

    fn stored(manager: &OneTimePreKeyManager) -> Vec<u8> {
        manager
            .lock_storage()
            .unwrap()
            .load(ONE_TIME_PREKEYS)
            .unwrap()
            .unwrap()
            .to_vec()
    }

    #[test]
    fn replenish_creates_initial_pool() {
        let mut rng = ChaCha20Rng::from_seed([0xd1; 32]);
        let OneTimePreKeySetup { discovery, manager } = setup_with_discovery_key();
        let bundles = manager.replenish(&mut rng).unwrap();
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
        let bundle = manager.replenish(&mut rng).unwrap().remove(0);
        let epoch = discovery.current().unwrap().epoch();
        let prekey = manager.consume_one_time_prekey(epoch, bundle.id).unwrap();
        assert_eq!(prekey.public().id, bundle.id);
        assert_eq!(prekey.public_key().as_bytes(), bundle.public_key.as_bytes());
        assert!(matches!(
            manager.consume_one_time_prekey(epoch, bundle.id),
            Err(OneTimePreKeyError::NotFound)
        ));
    }

    #[test]
    fn a_prekey_from_another_epoch_is_refused() {
        let mut rng = ChaCha20Rng::from_seed([0xd6; 32]);
        let OneTimePreKeySetup { discovery, manager } = setup_with_discovery_key();
        let bundle = manager.replenish(&mut rng).unwrap().remove(0);
        let epoch = discovery.current().unwrap().epoch();
        let before = stored(&manager);

        assert!(matches!(
            manager.consume_one_time_prekey(epoch + 1, bundle.id),
            Err(OneTimePreKeyError::StaleEpoch { epoch: requested, pool_epoch })
                if requested == epoch + 1 && pool_epoch == epoch
        ));
        assert_eq!(stored(&manager), before);
    }

    #[test]
    fn generate_batch_creates_the_requested_number_under_the_current_epoch() {
        let mut rng = ChaCha20Rng::from_seed([0xd3; 32]);
        let OneTimePreKeySetup { discovery, manager } = setup_with_discovery_key();
        let first = manager.generate_batch(&mut rng, 3).unwrap();
        let second = manager.generate_batch(&mut rng, 2).unwrap();
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
        let OneTimePreKeySetup { manager, .. } = setup_with_discovery_key();
        manager
            .generate_batch(&mut rng, ONE_TIME_PREKEY_POOL_TARGET)
            .unwrap();
        let before = stored(&manager);

        assert!(matches!(
            manager.generate_batch(&mut rng, 1),
            Err(OneTimePreKeyError::BatchExceedsCapacity {
                requested: 1,
                available: 0
            })
        ));
        assert_eq!(stored(&manager), before);
    }

    #[test]
    fn generate_batch_rejects_id_overflow_without_mutating_pool() {
        let mut rng = ChaCha20Rng::from_seed([0xd5; 32]);
        let OneTimePreKeySetup { discovery, manager } = setup_with_discovery_key();
        store(
            &manager,
            OneTimePreKeyPoolWire {
                epoch: discovery.current().unwrap().epoch(),
                next_id: u64::MAX,
                entries: Vec::new(),
            },
        );
        let before = stored(&manager);

        assert!(matches!(
            manager.generate_batch(&mut rng, 1),
            Err(OneTimePreKeyError::IdentifiersExhausted)
        ));
        assert_eq!(stored(&manager), before);
    }

    #[test]
    fn marked_one_time_prekeys_require_an_inbox_rotation() {
        let mut rng = ChaCha20Rng::from_seed([0xd7; 32]);
        let OneTimePreKeySetup { manager, .. } = setup_with_discovery_key();
        manager.replenish(&mut rng).unwrap();

        manager.mark_inbox_rotation_required().unwrap();

        assert!(matches!(
            manager.consume_one_time_prekey(1, 0),
            Err(OneTimePreKeyError::InboxRotationRequired)
        ));
        assert!(matches!(
            manager.replenish(&mut rng),
            Err(OneTimePreKeyError::InboxRotationRequired)
        ));
    }

    #[test]
    fn a_pool_with_an_unknown_version_is_refused() {
        let OneTimePreKeySetup { manager, .. } = setup_with_discovery_key();
        manager
            .lock_storage()
            .unwrap()
            .store(ONE_TIME_PREKEYS, &[ONE_TIME_PREKEYS_VERSION + 1])
            .unwrap();

        assert!(matches!(
            manager.consume_one_time_prekey(1, 0),
            Err(OneTimePreKeyError::StoredData(StoredDataError::UnsupportedVersion { version }))
                if version == ONE_TIME_PREKEYS_VERSION + 1
        ));
    }

    #[test]
    fn a_pool_over_its_limit_is_refused() {
        let OneTimePreKeySetup { manager, .. } = setup_with_discovery_key();
        store(
            &manager,
            OneTimePreKeyPoolWire {
                epoch: 1,
                next_id: ONE_TIME_PREKEY_POOL_TARGET as u64 + 1,
                entries: (0..=ONE_TIME_PREKEY_POOL_TARGET as u64)
                    .map(entry)
                    .collect(),
            },
        );

        assert!(matches!(
            manager.consume_one_time_prekey(1, 0),
            Err(OneTimePreKeyError::StoredData(StoredDataError::Decode(_)))
        ));
    }
}
