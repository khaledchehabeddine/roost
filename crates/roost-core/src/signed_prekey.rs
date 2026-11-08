use crate::discovery_key::{DiscoveryKeyError, DiscoveryKeyManager};
use crate::retention::{RELAY_HOLD_TIME, SECONDS_PER_DAY, is_expired};
use crate::storage::{SecureStorage, StorageError};
use crate::stored_data::{
    SignatureWire, StoredDataError, decode_versioned, deserialize_bounded, encode_versioned,
    signature_from_wire, signature_to_wire,
};
use rand::{CryptoRng, RngCore};
use roost_crypto::{
    PublicKeyError, PublicSignedPreKey, SignedPreKey, generate_signed_prekey_for_discovery_key,
};
use roost_protocol::{SignatureError, to_unix_secs};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

const SIGNED_PREKEYS: &str = "prekey/signed";
const SIGNED_PREKEYS_VERSION: u8 = 1;
const MAX_RETAINED_SIGNED_PREKEYS: usize = 5;
const SIGNED_PREKEY_ROTATION_WINDOW: Duration = Duration::from_secs(7 * SECONDS_PER_DAY);

/// Errors returned by signed prekey operations.
#[derive(Debug, thiserror::Error)]
pub enum SignedPreKeyError {
    /// The system clock is before the Unix epoch.
    #[error("system clock is before Unix epoch")]
    Clock,
    /// The stored signed prekey's signature does not verify against the current discovery key.
    #[error("stored signed prekey signature does not match the discovery key")]
    Corrupt(#[source] PublicKeyError),
    /// Loading the discovery key failed.
    #[error("loading the discovery key failed")]
    Discovery(#[from] DiscoveryKeyError),
    /// Backup restoration requires an inbox rotation before prekeys may be used.
    #[error("inbox rotation required before using restored prekey state")]
    InboxRotationRequired,
    /// Every signed prekey identifier in this epoch has been used.
    #[error("signed prekey identifier space exhausted")]
    IdentifiersExhausted,
    /// The internal storage lock was poisoned by a panicked thread.
    #[error("internal lock poisoned")]
    LockPoisoned,
    /// No signed prekey is stored, or none matches the requested one.
    #[error("no signed prekey stored")]
    NotFound,
    /// Rotating would discard a retained signed prekey that hasn't expired.
    #[error("retained signed prekey capacity of {max} reached")]
    RetainedCapacityReached {
        /// Largest number of retained signed prekeys.
        max: usize,
    },
    /// Signing a new signed prekey with the discovery key failed.
    #[error("signing the signed prekey failed")]
    SignedPreKeySignature(#[source] SignatureError),
    /// The underlying [`SecureStorage`] returned an error.
    #[error("signed prekey storage failed")]
    Storage(#[from] StorageError),
    /// The signed prekey entry failed to encode, or the stored one is malformed or uses an unknown
    /// version.
    #[error("signed prekey entry failed to encode or decode")]
    StoredData(#[from] StoredDataError),
}

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

    pub(crate) fn current(&self, now: SystemTime) -> Result<SignedPreKey, SignedPreKeyError> {
        Ok(self.load_store(now)?.current.to_prekey())
    }

    pub(crate) fn current_public(
        &self,
        now: SystemTime,
    ) -> Result<PublicSignedPreKey, SignedPreKeyError> {
        Ok(self.current(now)?.public())
    }

    // Returns every signed prekey still held: the current one and each retained one.
    pub(crate) fn held_public(
        &self,
        now: SystemTime,
    ) -> Result<Vec<PublicSignedPreKey>, SignedPreKeyError> {
        let store = self.load_store(now)?;
        Ok(std::iter::once(&store.current)
            .chain(store.retained.iter().map(|retained| &retained.prekey))
            .map(|prekey| prekey.to_prekey().public())
            .collect())
    }

    // Returns the signed prekey a first message names by its public key, and whether it is the
    // current one rather than one kept after a rotation.
    pub(crate) fn prekey_for_first_message(
        &self,
        epoch: u32,
        public_key: &[u8; 32],
        now: SystemTime,
    ) -> Result<(SignedPreKey, bool), SignedPreKeyError> {
        let store = self.load_store(now)?;
        if let Some(current) = store.current.matching(epoch, public_key) {
            return Ok((current, true));
        }
        store
            .retained
            .iter()
            .find_map(|retained| retained.prekey.matching(epoch, public_key))
            .map(|retained| (retained, false))
            .ok_or(SignedPreKeyError::NotFound)
    }

    // Rotates missing, stale, and far-future signed prekeys. Slightly future timestamps stay
    // valid to tolerate clock skew.
    pub(crate) fn rotate_if_stale<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        now: SystemTime,
    ) -> Result<Option<SignedPreKey>, SignedPreKeyError> {
        let needs_rotation = self.load_store_optional(now)?.is_none_or(|store| {
            is_expired(
                store.current.created_at_secs,
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

    // Deletes the signed prekeys. `KeyStore::prepare_identity_deletion` also deletes the keys
    // that signed them.
    pub(crate) fn reset(&self) -> Result<(), SignedPreKeyError> {
        Ok(self.lock_storage()?.delete(SIGNED_PREKEYS)?)
    }

    pub(crate) fn mark_inbox_rotation_required(&self) -> Result<(), SignedPreKeyError> {
        let entry = encode_versioned(
            SIGNED_PREKEYS_VERSION,
            &SignedPreKeysWire::InboxRotationRequired,
        )?;
        Ok(self.lock_storage()?.store(SIGNED_PREKEYS, &entry)?)
    }

    pub(crate) fn rotate_now<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        now: SystemTime,
    ) -> Result<SignedPreKey, SignedPreKeyError> {
        let now_secs = to_unix_secs(now).ok_or(SignedPreKeyError::Clock)?;
        let discovery_key = self.discovery.current()?;
        let previous = self
            .load_store_optional(now)?
            .filter(|store| store.current.epoch == discovery_key.epoch());
        let id = match &previous {
            Some(store) => store
                .current
                .id
                .checked_add(1)
                .ok_or(SignedPreKeyError::IdentifiersExhausted)?,
            None => 0,
        };
        let signed_prekey =
            generate_signed_prekey_for_discovery_key(rng, &discovery_key, id, now_secs)
                .map_err(SignedPreKeyError::SignedPreKeySignature)?;
        // Room for every retained key, so the list of secrets never reallocates.
        let mut retained = Vec::with_capacity(MAX_RETAINED_SIGNED_PREKEYS);
        if let Some(mut store) = previous {
            if store.retained.len() == MAX_RETAINED_SIGNED_PREKEYS {
                return Err(SignedPreKeyError::RetainedCapacityReached {
                    max: MAX_RETAINED_SIGNED_PREKEYS,
                });
            }
            retained.append(&mut store.retained);
            retained.push(RetainedSignedPreKeyWire {
                prekey: std::mem::take(&mut store.current),
                superseded_at_secs: now_secs,
            });
        }
        let entry = encode_versioned(
            SIGNED_PREKEYS_VERSION,
            &SignedPreKeysWire::Stored(StoredSignedPreKeysWire {
                current: SignedPreKeyWire::from_prekey(&signed_prekey),
                retained,
            }),
        )?;
        self.lock_storage()?.store(SIGNED_PREKEYS, &entry)?;
        Ok(signed_prekey)
    }

    fn load_store(&self, now: SystemTime) -> Result<StoredSignedPreKeysWire, SignedPreKeyError> {
        self.load_store_optional(now)?
            .ok_or(SignedPreKeyError::NotFound)
    }

    // Leaves out retained keys expired at `now` without deleting them, so only a rotation, which
    // runs inside a prepared operation, removes them from storage.
    fn load_store_optional(
        &self,
        now: SystemTime,
    ) -> Result<Option<StoredSignedPreKeysWire>, SignedPreKeyError> {
        let Some(entry) = self.lock_storage()?.load(SIGNED_PREKEYS)? else {
            return Ok(None);
        };
        let mut store = match decode_versioned(SIGNED_PREKEYS_VERSION, &entry)? {
            SignedPreKeysWire::InboxRotationRequired => {
                return Err(SignedPreKeyError::InboxRotationRequired);
            }
            SignedPreKeysWire::Stored(store) => store,
        };
        store
            .retained
            .retain(|retained| !is_expired(retained.superseded_at_secs, now, RELAY_HOLD_TIME));
        Ok(Some(store))
    }

    fn lock_storage(&self) -> Result<MutexGuard<'_, Box<dyn SecureStorage>>, SignedPreKeyError> {
        self.storage
            .lock()
            .map_err(|_| SignedPreKeyError::LockPoisoned)
    }
}

#[derive(Deserialize, Serialize)]
enum SignedPreKeysWire {
    // A restored backup left these prekeys unusable until an inbox rotation replaces them.
    InboxRotationRequired,
    Stored(StoredSignedPreKeysWire),
}

#[derive(Deserialize, Serialize, ZeroizeOnDrop)]
struct StoredSignedPreKeysWire {
    current: SignedPreKeyWire,
    #[serde(deserialize_with = "deserialize_bounded::<_, _, MAX_RETAINED_SIGNED_PREKEYS>")]
    retained: Vec<RetainedSignedPreKeyWire>,
}

#[derive(Default, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
struct SignedPreKeyWire {
    #[zeroize(skip)]
    id: u64,
    secret: [u8; 32],
    #[zeroize(skip)]
    signature: SignatureWire,
    #[zeroize(skip)]
    epoch: u32,
    #[zeroize(skip)]
    created_at_secs: u64,
}

impl SignedPreKeyWire {
    fn from_prekey(prekey: &SignedPreKey) -> Self {
        Self {
            id: prekey.id(),
            secret: *prekey.to_secret_bytes(),
            signature: signature_to_wire(&prekey.signature().to_bytes()),
            epoch: prekey.epoch(),
            created_at_secs: prekey.created_at_secs(),
        }
    }

    fn to_prekey(&self) -> SignedPreKey {
        SignedPreKey::from_secret_bytes(
            &self.secret,
            signature_from_wire(&self.signature),
            self.id,
            self.epoch,
            self.created_at_secs,
        )
    }

    // Returns this prekey when it belongs to `epoch` and has `public_key`.
    fn matching(&self, epoch: u32, public_key: &[u8; 32]) -> Option<SignedPreKey> {
        (self.epoch == epoch)
            .then(|| self.to_prekey())
            .filter(|prekey| bool::from(prekey.public_key().as_bytes().ct_eq(public_key)))
    }
}

// A signed prekey a rotation replaced, kept while the relay may still hold first messages for it.
#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
struct RetainedSignedPreKeyWire {
    prekey: SignedPreKeyWire,
    #[zeroize(skip)]
    superseded_at_secs: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::IdentityManager;
    use crate::storage::InMemorySecureStorage;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use roost_crypto::{
        generate_discovery_key, generate_signed_prekey_for_discovery_key, generate_signing_key_pair,
    };
    use roost_protocol::from_unix_secs;

    const FIXED_NOW: u64 = 1_700_000_000;
    const FIXED_EPOCH: u32 = 3;
    const SIGNED_PREKEY_ROTATION_WINDOW_SECS: u64 = SIGNED_PREKEY_ROTATION_WINDOW.as_secs();
    const SIGNED_PREKEY_RETENTION_WINDOW_SECS: u64 = RELAY_HOLD_TIME.as_secs();

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
        let mut rng = ChaCha20Rng::from_seed([0x90; 32]);
        let storage = shared_storage();
        let identity = Arc::new(IdentityManager::new(Arc::clone(&storage)));
        identity.generate_identity(&mut rng).unwrap();
        let discovery = Arc::new(DiscoveryKeyManager::new(Arc::clone(&storage), identity));
        discovery.rotate_now(&mut rng, at(FIXED_NOW)).unwrap();
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

    fn store_only(manager: &SignedPreKeyManager, current: &SignedPreKey) {
        let store = StoredSignedPreKeysWire {
            current: SignedPreKeyWire::from_prekey(current),
            retained: Vec::new(),
        };
        let entry =
            encode_versioned(SIGNED_PREKEYS_VERSION, &SignedPreKeysWire::Stored(store)).unwrap();
        manager
            .lock_storage()
            .unwrap()
            .store(SIGNED_PREKEYS, &entry)
            .unwrap();
    }

    fn store_signed_prekey_with_created_at(
        manager: &SignedPreKeyManager,
        created_at_secs: u64,
    ) -> SignedPreKey {
        let mut rng = ChaCha20Rng::from_seed([0x91; 32]);
        let signing_key = generate_signing_key_pair(&mut rng);
        let discovery_key =
            generate_discovery_key(&mut rng, &signing_key, FIXED_EPOCH, FIXED_NOW).unwrap();
        let signed_prekey =
            generate_signed_prekey_for_discovery_key(&mut rng, &discovery_key, 0, created_at_secs)
                .unwrap();
        store_only(manager, &signed_prekey);
        signed_prekey
    }

    fn store_current_discovery_signed_prekey_with_created_at(
        setup: &SignedPreKeySetup,
        created_at_secs: u64,
    ) -> SignedPreKey {
        let mut rng = ChaCha20Rng::from_seed([0x92; 32]);
        let discovery_key = setup.discovery.current().unwrap();
        let signed_prekey =
            generate_signed_prekey_for_discovery_key(&mut rng, &discovery_key, 0, created_at_secs)
                .unwrap();
        store_only(&setup.manager, &signed_prekey);
        signed_prekey
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
    fn rotate_if_stale_rotates_at_weekly_boundary() {
        let mut rng = ChaCha20Rng::from_seed([0x96; 32]);
        let setup = setup_with_discovery_key();
        let created_at_secs = FIXED_NOW - SIGNED_PREKEY_ROTATION_WINDOW_SECS;
        let stale = store_current_discovery_signed_prekey_with_created_at(&setup, created_at_secs);

        let rotated = setup
            .manager
            .rotate_if_stale(&mut rng, at(FIXED_NOW))
            .unwrap()
            .expect("weekly boundary must rotate");

        assert_ne!(
            rotated.public_key().as_bytes(),
            stale.public_key().as_bytes()
        );
        assert_eq!(rotated.id(), stale.id() + 1);
    }

    #[test]
    fn rotate_if_stale_keeps_slightly_future_signed_prekey() {
        let mut rng = ChaCha20Rng::from_seed([0x98; 32]);
        let manager = setup_with_discovery_key().manager;
        let signed_prekey = store_signed_prekey_with_created_at(&manager, FIXED_NOW + 100_000);
        assert!(
            manager
                .rotate_if_stale(&mut rng, at(FIXED_NOW))
                .unwrap()
                .is_none()
        );
        let public_key = manager.current_public(at(FIXED_NOW)).unwrap().public_key;
        assert_eq!(public_key.as_bytes(), signed_prekey.public_key().as_bytes());
    }

    #[test]
    fn rotate_if_stale_replaces_far_future_signed_prekey() {
        let mut rng = ChaCha20Rng::from_seed([0x99; 32]);
        let manager = setup_with_discovery_key().manager;
        let signed_prekey =
            store_signed_prekey_with_created_at(&manager, FIXED_NOW + 300 * SECONDS_PER_DAY);
        let rotated = manager
            .rotate_if_stale(&mut rng, at(FIXED_NOW))
            .unwrap()
            .expect("far-future signed prekey must trigger rotation");
        let public_key = manager.current_public(at(FIXED_NOW)).unwrap().public_key;
        assert_eq!(public_key.as_bytes(), rotated.public_key().as_bytes());
        assert_ne!(public_key.as_bytes(), signed_prekey.public_key().as_bytes());
    }

    #[test]
    fn rotate_now_stores_the_prekey_it_returns() {
        let mut rng = ChaCha20Rng::from_seed([0x9a; 32]);
        let setup = setup_with_discovery_key();
        let rotated = setup.manager.rotate_now(&mut rng, at(FIXED_NOW)).unwrap();
        let current = setup.manager.current(at(FIXED_NOW)).unwrap();

        assert_eq!(current.to_secret_bytes(), rotated.to_secret_bytes());
        assert_eq!(
            current.signature().to_bytes(),
            rotated.signature().to_bytes()
        );
        assert_eq!(current.id(), rotated.id());
        assert_eq!(current.epoch(), rotated.epoch());
        assert_eq!(current.created_at_secs(), FIXED_NOW);
    }

    #[test]
    fn rotate_now_retains_multiple_superseded_prekeys() {
        let mut rng = ChaCha20Rng::from_seed([0x9b; 32]);
        let setup = setup_with_discovery_key();
        let first = setup.manager.rotate_now(&mut rng, at(FIXED_NOW)).unwrap();
        let second = setup.manager.rotate_now(&mut rng, at(FIXED_NOW)).unwrap();
        let third = setup.manager.rotate_now(&mut rng, at(FIXED_NOW)).unwrap();

        for superseded in [&first, &second] {
            let (prekey, is_current) = setup
                .manager
                .prekey_for_first_message(
                    superseded.epoch(),
                    superseded.public_key().as_bytes(),
                    at(FIXED_NOW),
                )
                .unwrap();
            assert!(!is_current);
            assert_eq!(prekey.id(), superseded.id());
        }
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
        let mut rng = ChaCha20Rng::from_seed([0x9c; 32]);
        let setup = setup_with_discovery_key();
        let first = setup.manager.rotate_now(&mut rng, at(FIXED_NOW)).unwrap();
        setup.manager.rotate_now(&mut rng, at(FIXED_NOW)).unwrap();
        setup
            .manager
            .prekey_for_first_message(
                first.epoch(),
                first.public_key().as_bytes(),
                at(FIXED_NOW + SIGNED_PREKEY_RETENTION_WINDOW_SECS - 1),
            )
            .unwrap();

        assert!(matches!(
            setup.manager.prekey_for_first_message(
                first.epoch(),
                first.public_key().as_bytes(),
                at(FIXED_NOW + SIGNED_PREKEY_RETENTION_WINDOW_SECS)
            ),
            Err(SignedPreKeyError::NotFound)
        ));
    }

    #[test]
    fn reading_keeps_an_expired_prekey_until_a_rotation_deletes_it() {
        let mut rng = ChaCha20Rng::from_seed([0x9c; 32]);
        let setup = setup_with_discovery_key();
        let first = setup.manager.rotate_now(&mut rng, at(FIXED_NOW)).unwrap();
        setup.manager.rotate_now(&mut rng, at(FIXED_NOW)).unwrap();
        let expired = at(FIXED_NOW + SIGNED_PREKEY_RETENTION_WINDOW_SECS);
        let find = |now| {
            setup.manager.prekey_for_first_message(
                first.epoch(),
                first.public_key().as_bytes(),
                now,
            )
        };
        assert!(matches!(find(expired), Err(SignedPreKeyError::NotFound)));

        find(at(FIXED_NOW)).unwrap();
        setup.manager.rotate_now(&mut rng, expired).unwrap();
        assert!(matches!(
            find(at(FIXED_NOW)),
            Err(SignedPreKeyError::NotFound)
        ));
    }

    #[test]
    fn rotate_now_refuses_to_discard_unexpired_retained_prekeys() {
        let mut rng = ChaCha20Rng::from_seed([0x9e; 32]);
        let setup = setup_with_discovery_key();
        for _ in 0..=MAX_RETAINED_SIGNED_PREKEYS {
            setup.manager.rotate_now(&mut rng, at(FIXED_NOW)).unwrap();
        }
        let current = setup.manager.current(at(FIXED_NOW)).unwrap();

        assert!(matches!(
            setup.manager.rotate_now(&mut rng, at(FIXED_NOW)),
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
    fn rotate_if_stale_without_discovery_key_returns_not_found() {
        let mut rng = ChaCha20Rng::from_seed([0xa0; 32]);
        let manager = manager_without_discovery_key();
        assert!(matches!(
            manager.rotate_if_stale(&mut rng, at(FIXED_NOW)),
            Err(SignedPreKeyError::Discovery(DiscoveryKeyError::NotFound))
        ));
    }

    #[test]
    fn rotation_rejects_exhausted_signed_prekey_id_space() {
        let mut rng = ChaCha20Rng::from_seed([0xa3; 32]);
        let setup = setup_with_discovery_key();
        let discovery_key = setup.discovery.current().unwrap();
        let current =
            generate_signed_prekey_for_discovery_key(&mut rng, &discovery_key, u64::MAX, FIXED_NOW)
                .unwrap();
        store_only(&setup.manager, &current);

        assert!(matches!(
            setup.manager.rotate_now(&mut rng, at(FIXED_NOW)),
            Err(SignedPreKeyError::IdentifiersExhausted)
        ));
        assert_eq!(setup.manager.current(at(FIXED_NOW)).unwrap().id(), u64::MAX);
    }

    #[test]
    fn marked_signed_prekeys_require_an_inbox_rotation() {
        let mut rng = ChaCha20Rng::from_seed([0xa4; 32]);
        let setup = setup_with_discovery_key();
        setup.manager.rotate_now(&mut rng, at(FIXED_NOW)).unwrap();

        setup.manager.mark_inbox_rotation_required().unwrap();

        assert!(matches!(
            setup.manager.current(at(FIXED_NOW)),
            Err(SignedPreKeyError::InboxRotationRequired)
        ));
        assert!(matches!(
            setup.manager.rotate_now(&mut rng, at(FIXED_NOW)),
            Err(SignedPreKeyError::InboxRotationRequired)
        ));
    }

    #[test]
    fn stored_signed_prekeys_with_an_unknown_version_are_refused() {
        let manager = setup_with_discovery_key().manager;
        manager
            .lock_storage()
            .unwrap()
            .store(SIGNED_PREKEYS, &[SIGNED_PREKEYS_VERSION + 1])
            .unwrap();

        assert!(matches!(
            manager.current(at(FIXED_NOW)),
            Err(SignedPreKeyError::StoredData(StoredDataError::UnsupportedVersion { version }))
                if version == SIGNED_PREKEYS_VERSION + 1
        ));
    }
}
