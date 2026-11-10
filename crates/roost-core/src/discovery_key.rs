use crate::identity::{IdentityError, IdentityManager};
use crate::retention::{RELAY_HOLD_TIME, is_expired};
use crate::storage::{SecureStorage, StorageError};
use crate::stored_data::{
    SignatureWire, StoredDataError, decode_versioned, deserialize_bounded, encode_versioned,
    signature_from_wire, signature_to_wire,
};
use rand::{CryptoRng, RngCore};
use roost_crypto::{
    DiscoveryKey, PublicKeyError, RecipientDeliveryCapability, Signature, VerifyingKey,
    generate_discovery_key, generate_recipient_delivery_capability, verify_public_discovery_key,
};
use roost_protocol::{SignatureError, to_unix_secs};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::SystemTime;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const DISCOVERY_KEY: &str = "discovery/current";
const PREVIOUS_DISCOVERY_KEYS: &str = "discovery/previous";
const DISCOVERY_KEY_VERSION: u8 = 1;
const PREVIOUS_DISCOVERY_KEYS_VERSION: u8 = 1;
const FIRST_EPOCH: u32 = 1;
// Enough for several blocks close together to keep each other's queued messages readable.
const MAX_PREVIOUS_DISCOVERY_KEYS: usize = 5;

/// Errors returned by discovery key operations.
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryKeyError {
    /// The system clock is before the Unix epoch.
    #[error("system clock is before Unix epoch")]
    Clock,
    /// The stored discovery key's signature does not verify against the identity key.
    #[error("stored discovery key signature does not match the identity key")]
    Corrupt(#[source] PublicKeyError),
    /// Signing a new discovery key with the identity key failed.
    #[error("signing the discovery key failed")]
    DiscoveryKeySignature(#[source] SignatureError),
    /// Loading the identity failed.
    #[error("loading the identity failed")]
    Identity(#[from] IdentityError),
    /// Signing the discovery-to-identity binding failed.
    #[error("signing the discovery-to-identity binding failed")]
    IdentityBindingSignature(#[source] SignatureError),
    /// The internal storage lock was poisoned by a panicked thread.
    #[error("internal lock poisoned")]
    LockPoisoned,
    /// No discovery key is stored.
    #[error("no discovery key stored")]
    NotFound,
    /// The underlying [`SecureStorage`] returned an error.
    #[error("discovery key storage failed")]
    Storage(#[from] StorageError),
    /// A discovery key entry failed to encode, or the stored one is malformed or uses an unknown
    /// version and must be reset before a rotation replaces it.
    #[error("discovery key entry failed to encode or decode")]
    StoredData(#[from] StoredDataError),
}

pub(crate) struct DiscoveryKeyManager {
    storage: Arc<Mutex<Box<dyn SecureStorage>>>,
    identity: Arc<IdentityManager>,
}

impl DiscoveryKeyManager {
    pub(crate) fn new(
        storage: Arc<Mutex<Box<dyn SecureStorage>>>,
        identity: Arc<IdentityManager>,
    ) -> Self {
        DiscoveryKeyManager { storage, identity }
    }

    // Loads the discovery key and verifies its signature against the identity key.
    pub(crate) fn current(&self) -> Result<DiscoveryKey, DiscoveryKeyError> {
        let current = self.load_current()?;
        let identity = self.identity.load_identity()?;
        current
            .discovery_key
            .to_verified_key(identity.verifying_key())
            .map_err(DiscoveryKeyError::Corrupt)
    }

    // Returns the delivery capability of the current epoch's inbox.
    //
    // The caller sends it only to authorized contacts and registers only its verifier with the
    // relay.
    pub(crate) fn current_capability(
        &self,
    ) -> Result<RecipientDeliveryCapability, DiscoveryKeyError> {
        Ok(RecipientDeliveryCapability::from_bytes(
            &self.load_current()?.delivery_capability,
        ))
    }

    // Returns the signature of `discovery_key` over the stored identity's public halves.
    //
    // Recomputed per call rather than persisted. It covers no epoch or timestamp, and Ed25519 is
    // deterministic, so every recomputation is byte-identical.
    pub(crate) fn identity_binding(
        &self,
        discovery_key: &DiscoveryKey,
    ) -> Result<Signature, DiscoveryKeyError> {
        let identity = self.identity.load_identity()?;
        discovery_key
            .sign_identity_binding(&identity.public()?)
            .map_err(DiscoveryKeyError::IdentityBindingSignature)
    }

    // Replaces the discovery key and delivery capability with new ones at the next epoch.
    //
    // The new key is dated at `now`, but at least one second after a replaced key the identity
    // signed, because contacts keep the key with the later date. A key whose signature doesn't
    // verify is still replaced, but a malformed entry must be reset first. The replaced key joins
    // the previous keys, which drop any past the relay's queue time and then the oldest past the
    // limit.
    pub(crate) fn rotate_now<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        now: SystemTime,
    ) -> Result<DiscoveryKey, DiscoveryKeyError> {
        let identity = self.identity.load_identity()?;
        let now_secs = to_unix_secs(now).ok_or(DiscoveryKeyError::Clock)?;
        let replaced = self.load_current_optional()?;
        let (epoch, created_at_secs) = match &replaced {
            None => (FIRST_EPOCH, now_secs),
            Some(current) => {
                // A date the identity didn't sign may be corrupt, so it can't hold back later keys.
                let after_replaced_secs = match current
                    .discovery_key
                    .to_verified_key(identity.verifying_key())
                {
                    Ok(replaced_key) => replaced_key.created_at_secs().saturating_add(1),
                    Err(PublicKeyError::Signature(_)) => now_secs,
                    Err(error) => return Err(DiscoveryKeyError::Corrupt(error)),
                };
                (
                    current.discovery_key.epoch.saturating_add(1),
                    now_secs.max(after_replaced_secs),
                )
            }
        };
        let discovery_key =
            generate_discovery_key(rng, identity.signing_key_pair(), epoch, created_at_secs)
                .map_err(DiscoveryKeyError::DiscoveryKeySignature)?;
        // The capability rotates with the discovery key because both belong to one epoch, and
        // they are written in one entry so they cannot diverge.
        let capability = generate_recipient_delivery_capability(rng);
        let entry = encode_versioned(
            DISCOVERY_KEY_VERSION,
            &CurrentDiscoveryKeyWire {
                discovery_key: DiscoveryKeyWire::from_key(&discovery_key),
                delivery_capability: *capability.to_bytes(),
            },
        )?;
        if let Some(mut replaced) = replaced {
            let mut previous = self.load_previous()?;
            previous.retain(|previous| !is_expired(previous.retired_at_secs, now, RELAY_HOLD_TIME));
            previous.push(PreviousDiscoveryKeyWire {
                discovery_key: std::mem::take(&mut replaced.discovery_key),
                retired_at_secs: now_secs,
            });
            let excess = previous.len().saturating_sub(MAX_PREVIOUS_DISCOVERY_KEYS);
            previous.drain(..excess);
            self.store_previous(&previous)?;
        }
        self.lock_storage()?.store(DISCOVERY_KEY, &entry)?;
        Ok(discovery_key)
    }

    // Returns the previous discovery key with X25519 public key `public_key`, if the relay may
    // still hold messages for it at `now`.
    //
    // Reading leaves expired keys in place, so only a prepared operation deletes them.
    pub(crate) fn previous_key(
        &self,
        public_key: &[u8; 32],
        now: SystemTime,
    ) -> Result<Option<DiscoveryKey>, DiscoveryKeyError> {
        Ok(self
            .load_previous()?
            .iter()
            .filter(|previous| !is_expired(previous.retired_at_secs, now, RELAY_HOLD_TIME))
            .map(|previous| previous.discovery_key.to_key())
            .find(|discovery_key| discovery_key.public_key().as_bytes() == public_key))
    }

    // Deletes the previous discovery keys the relay can no longer hold messages for at `now`.
    pub(crate) fn delete_expired_previous(&self, now: SystemTime) -> Result<(), DiscoveryKeyError> {
        let mut previous = self.load_previous()?;
        let count = previous.len();
        previous.retain(|previous| !is_expired(previous.retired_at_secs, now, RELAY_HOLD_TIME));
        if previous.len() == count {
            return Ok(());
        }
        self.store_previous(&previous)
    }

    // Deletes the discovery key and every previous one. `KeyStore::prepare_identity_deletion` first
    // deletes the prekeys the discovery key signed.
    pub(crate) fn reset(&self) -> Result<(), DiscoveryKeyError> {
        let mut storage = self.lock_storage()?;
        storage.delete(PREVIOUS_DISCOVERY_KEYS)?;
        Ok(storage.delete(DISCOVERY_KEY)?)
    }

    // Returns the stored discovery key entry verbatim, for an encrypted backup.
    pub(crate) fn export_entry(&self) -> Result<Zeroizing<Vec<u8>>, DiscoveryKeyError> {
        let entry = self
            .lock_storage()?
            .load(DISCOVERY_KEY)?
            .ok_or(DiscoveryKeyError::NotFound)?;
        decode_current(&entry)?;
        Ok(entry)
    }

    pub(crate) fn validate_entry_for_identity(
        entry: &[u8],
        identity_verifying_key: &VerifyingKey,
    ) -> Result<(), DiscoveryKeyError> {
        decode_current(entry)?
            .discovery_key
            .to_verified_key(identity_verifying_key)
            .map_err(DiscoveryKeyError::Corrupt)?;
        Ok(())
    }

    // Restores a discovery key entry from a backup verbatim with a single store, keeping its epoch
    // lineage and identity signature. The caller validates it first.
    pub(crate) fn restore_entry(&self, entry: &[u8]) -> Result<(), DiscoveryKeyError> {
        Ok(self.lock_storage()?.store(DISCOVERY_KEY, entry)?)
    }

    fn load_current(&self) -> Result<CurrentDiscoveryKeyWire, DiscoveryKeyError> {
        self.load_current_optional()?
            .ok_or(DiscoveryKeyError::NotFound)
    }

    // Drops the storage guard before returning, so the caller can then load the identity.
    fn load_current_optional(&self) -> Result<Option<CurrentDiscoveryKeyWire>, DiscoveryKeyError> {
        let Some(entry) = self.lock_storage()?.load(DISCOVERY_KEY)? else {
            return Ok(None);
        };
        Ok(Some(decode_current(&entry)?))
    }

    // Returns the previous keys in a list with room for the key a rotation retires, so it never
    // reallocates and leaves secrets in freed memory.
    fn load_previous(&self) -> Result<Zeroizing<Vec<PreviousDiscoveryKeyWire>>, DiscoveryKeyError> {
        let mut previous = Zeroizing::new(Vec::with_capacity(MAX_PREVIOUS_DISCOVERY_KEYS + 1));
        if let Some(entry) = self.lock_storage()?.load(PREVIOUS_DISCOVERY_KEYS)? {
            let mut decoded: DecodedPreviousDiscoveryKeysWire =
                decode_versioned(PREVIOUS_DISCOVERY_KEYS_VERSION, &entry)?;
            previous.append(&mut decoded.keys);
        }
        Ok(previous)
    }

    fn store_previous(
        &self,
        previous: &[PreviousDiscoveryKeyWire],
    ) -> Result<(), DiscoveryKeyError> {
        let mut storage = self.lock_storage()?;
        if previous.is_empty() {
            return Ok(storage.delete(PREVIOUS_DISCOVERY_KEYS)?);
        }
        let entry = encode_versioned(
            PREVIOUS_DISCOVERY_KEYS_VERSION,
            &PreviousDiscoveryKeysWire { keys: previous },
        )?;
        Ok(storage.store(PREVIOUS_DISCOVERY_KEYS, &entry)?)
    }

    fn lock_storage(&self) -> Result<MutexGuard<'_, Box<dyn SecureStorage>>, DiscoveryKeyError> {
        self.storage
            .lock()
            .map_err(|_| DiscoveryKeyError::LockPoisoned)
    }
}

fn decode_current(entry: &[u8]) -> Result<CurrentDiscoveryKeyWire, DiscoveryKeyError> {
    Ok(decode_versioned(DISCOVERY_KEY_VERSION, entry)?)
}

// A discovery key's secrets and signed fields, as the current entry and each previous one hold
// them.
#[derive(Default, Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
struct DiscoveryKeyWire {
    #[zeroize(skip)]
    epoch: u32,
    agreement_secret: [u8; 32],
    signing_secret: [u8; 32],
    #[zeroize(skip)]
    identity_signature: SignatureWire,
    #[zeroize(skip)]
    created_at_secs: u64,
}

impl DiscoveryKeyWire {
    fn from_key(discovery_key: &DiscoveryKey) -> Self {
        Self {
            epoch: discovery_key.epoch(),
            agreement_secret: *discovery_key.key_agreement_secret_bytes(),
            signing_secret: *discovery_key.signing_secret_bytes(),
            identity_signature: signature_to_wire(&discovery_key.identity_signature().to_bytes()),
            created_at_secs: discovery_key.created_at_secs(),
        }
    }

    fn to_key(&self) -> DiscoveryKey {
        DiscoveryKey::from_secret_bytes(
            &self.agreement_secret,
            &self.signing_secret,
            self.epoch,
            self.created_at_secs,
            signature_from_wire(&self.identity_signature),
        )
    }

    fn to_verified_key(
        &self,
        identity_verifying_key: &VerifyingKey,
    ) -> Result<DiscoveryKey, PublicKeyError> {
        let discovery_key = self.to_key();
        verify_public_discovery_key(&discovery_key.public(), identity_verifying_key)?;
        Ok(discovery_key)
    }
}

#[derive(Deserialize, Serialize, ZeroizeOnDrop)]
struct CurrentDiscoveryKeyWire {
    discovery_key: DiscoveryKeyWire,
    delivery_capability: [u8; 32],
}

// A discovery key a rotation replaced, kept only to open messages already sealed to it. Its
// capability isn't kept, since the relay refuses it once the new inbox is registered.
#[derive(Deserialize, Serialize, Zeroize, ZeroizeOnDrop)]
struct PreviousDiscoveryKeyWire {
    discovery_key: DiscoveryKeyWire,
    #[zeroize(skip)]
    retired_at_secs: u64,
}

#[derive(Serialize)]
struct PreviousDiscoveryKeysWire<'a> {
    keys: &'a [PreviousDiscoveryKeyWire],
}

#[derive(Deserialize, ZeroizeOnDrop)]
struct DecodedPreviousDiscoveryKeysWire {
    #[serde(deserialize_with = "deserialize_bounded::<_, _, MAX_PREVIOUS_DISCOVERY_KEYS>")]
    keys: Vec<PreviousDiscoveryKeyWire>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::retention::SECONDS_PER_DAY;
    use crate::storage::InMemorySecureStorage;
    use crate::{ContactDiscoveryKey, is_newer_discovery_key};
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use roost_protocol::{SignatureError, from_unix_secs};
    use std::time::Duration;

    const FIXED_NOW: u64 = 1_700_000_000;

    fn fixed_now() -> SystemTime {
        from_unix_secs(FIXED_NOW).unwrap()
    }

    fn shared_storage() -> Arc<Mutex<Box<dyn SecureStorage>>> {
        Arc::new(Mutex::new(Box::new(InMemorySecureStorage::new())))
    }

    fn manager_with_identity() -> DiscoveryKeyManager {
        let mut rng = ChaCha20Rng::from_seed([0xb0; 32]);
        let storage = shared_storage();
        let identity = Arc::new(IdentityManager::new(Arc::clone(&storage)));
        identity.generate_identity(&mut rng).unwrap();
        DiscoveryKeyManager::new(storage, identity)
    }

    fn manager_without_identity() -> DiscoveryKeyManager {
        let storage = shared_storage();
        let identity = Arc::new(IdentityManager::new(Arc::clone(&storage)));
        DiscoveryKeyManager::new(storage, identity)
    }

    fn stored(discovery: &DiscoveryKeyManager, key: &str) -> Option<Zeroizing<Vec<u8>>> {
        discovery.lock_storage().unwrap().load(key).unwrap()
    }

    fn store(discovery: &DiscoveryKeyManager, key: &str, entry: &[u8]) {
        discovery.lock_storage().unwrap().store(key, entry).unwrap();
    }

    #[test]
    fn a_malformed_discovery_key_entry_is_refused_by_each_reader() {
        let mut rng = ChaCha20Rng::from_seed([0xb8; 32]);
        let discovery = manager_with_identity();
        let malformed = [DISCOVERY_KEY_VERSION, 0xAA];
        let is_malformed = |result| {
            matches!(
                result,
                Err(DiscoveryKeyError::StoredData(StoredDataError::Decode(_)))
            )
        };
        let identity = discovery.identity.load_identity().unwrap();
        assert!(is_malformed(
            DiscoveryKeyManager::validate_entry_for_identity(&malformed, identity.verifying_key())
        ));
        store(&discovery, DISCOVERY_KEY, &malformed);

        assert!(is_malformed(discovery.current().map(|_| ())));
        assert!(is_malformed(
            discovery.rotate_now(&mut rng, fixed_now()).map(|_| ())
        ));
        assert_eq!(
            stored(&discovery, DISCOVERY_KEY).unwrap().as_slice(),
            malformed
        );
    }

    #[test]
    fn a_discovery_key_entry_with_an_unknown_version_is_refused() {
        let mut rng = ChaCha20Rng::from_seed([0xb1; 32]);
        let discovery = manager_with_identity();
        discovery.rotate_now(&mut rng, fixed_now()).unwrap();
        let mut entry = stored(&discovery, DISCOVERY_KEY).unwrap();
        entry[0] = DISCOVERY_KEY_VERSION + 1;
        store(&discovery, DISCOVERY_KEY, &entry);

        assert!(matches!(
            discovery.current(),
            Err(DiscoveryKeyError::StoredData(StoredDataError::UnsupportedVersion { version }))
                if version == DISCOVERY_KEY_VERSION + 1
        ));
    }

    #[test]
    fn rotate_now_stores_the_key_and_capability_it_returns() {
        let mut rng = ChaCha20Rng::from_seed([0xbe; 32]);
        let discovery = manager_with_identity();
        let rotated = discovery.rotate_now(&mut rng, fixed_now()).unwrap();
        let current = discovery.current().unwrap();
        let capability = discovery.current_capability().unwrap();

        assert_eq!(
            current.key_agreement_secret_bytes(),
            rotated.key_agreement_secret_bytes()
        );
        assert_eq!(
            current.signing_secret_bytes(),
            rotated.signing_secret_bytes()
        );
        assert_eq!(
            current.identity_signature().to_bytes(),
            rotated.identity_signature().to_bytes()
        );
        assert_eq!(current.epoch(), rotated.epoch());
        assert_eq!(current.created_at_secs(), FIXED_NOW);
        assert_ne!(*capability.to_bytes(), [0; 32]);
        discovery.rotate_now(&mut rng, fixed_now()).unwrap();
        assert_ne!(
            discovery.current_capability().unwrap().to_bytes(),
            capability.to_bytes()
        );
    }

    #[test]
    fn rotate_now_dates_each_key_after_the_one_it_replaces_when_the_clock_moved_back() {
        let mut rng = ChaCha20Rng::from_seed([0xc0; 32]);
        let discovery = manager_with_identity();
        let fast_clock_secs = FIXED_NOW + SECONDS_PER_DAY;
        let fast = discovery
            .rotate_now(&mut rng, from_unix_secs(fast_clock_secs).unwrap())
            .unwrap();
        assert_eq!(fast.created_at_secs(), fast_clock_secs);

        let corrected = discovery.rotate_now(&mut rng, fixed_now()).unwrap();
        assert_eq!(corrected.created_at_secs(), fast_clock_secs + 1);
        assert_eq!(corrected.epoch(), fast.epoch() + 1);
        assert!(is_newer_discovery_key(
            &ContactDiscoveryKey::from(&corrected.public()),
            &ContactDiscoveryKey::from(&fast.public()),
        ));
        let caught_up_secs = fast_clock_secs + 60;
        let caught_up = discovery
            .rotate_now(&mut rng, from_unix_secs(caught_up_secs).unwrap())
            .unwrap();
        assert_eq!(caught_up.created_at_secs(), caught_up_secs);
    }

    #[test]
    fn rotate_now_ignores_a_replaced_date_the_identity_didnt_sign() {
        let mut rng = ChaCha20Rng::from_seed([0xc1; 32]);
        let discovery = manager_with_identity();
        discovery.rotate_now(&mut rng, fixed_now()).unwrap();
        let mut current = discovery.load_current().unwrap();
        current.discovery_key.created_at_secs = u64::MAX;
        store(
            &discovery,
            DISCOVERY_KEY,
            &encode_versioned(DISCOVERY_KEY_VERSION, &current).unwrap(),
        );

        let rotated = discovery.rotate_now(&mut rng, fixed_now()).unwrap();
        assert_eq!(rotated.created_at_secs(), FIXED_NOW);
        discovery.current().unwrap();
    }

    fn is_kept(discovery: &DiscoveryKeyManager, key: &DiscoveryKey, now: SystemTime) -> bool {
        discovery
            .previous_key(key.public_key().as_bytes(), now)
            .unwrap()
            .is_some()
    }

    #[test]
    fn previous_keys_open_queued_messages_until_the_relays_queue_time_passes() {
        let mut rng = ChaCha20Rng::from_seed([0xbb; 32]);
        let discovery = manager_with_identity();
        let first = discovery.rotate_now(&mut rng, fixed_now()).unwrap();
        let current = discovery.rotate_now(&mut rng, fixed_now()).unwrap();
        let window = RELAY_HOLD_TIME;
        let last_moment = fixed_now() + window - Duration::from_secs(1);
        assert!(is_kept(&discovery, &first, last_moment));
        assert!(!is_kept(&discovery, &first, fixed_now() + window));
        assert!(!is_kept(&discovery, &current, fixed_now()));
    }

    #[test]
    fn a_rotation_drops_expired_keys_then_the_oldest_past_the_limit() {
        let mut rng = ChaCha20Rng::from_seed([0xbc; 32]);
        let discovery = manager_with_identity();
        let expired = discovery.rotate_now(&mut rng, fixed_now()).unwrap();
        let later = fixed_now() + RELAY_HOLD_TIME;
        let mut retired = Vec::new();
        retired.push(discovery.rotate_now(&mut rng, fixed_now()).unwrap());
        for _ in 0..=MAX_PREVIOUS_DISCOVERY_KEYS {
            retired.push(discovery.rotate_now(&mut rng, later).unwrap());
        }

        // The last rotation's key is current, and the one before the kept ones was evicted.
        let (evicted, rest) = retired.split_first().unwrap();
        let (kept, _current) = rest.split_at(MAX_PREVIOUS_DISCOVERY_KEYS);

        assert!(!is_kept(&discovery, &expired, later));
        assert!(!is_kept(&discovery, evicted, later));
        assert!(kept.iter().all(|key| is_kept(&discovery, key, later)));
    }

    #[test]
    fn delete_expired_previous_keeps_only_unexpired_keys() {
        let mut rng = ChaCha20Rng::from_seed([0xbf; 32]);
        let discovery = manager_with_identity();
        let window = RELAY_HOLD_TIME;
        let expired = discovery.rotate_now(&mut rng, fixed_now()).unwrap();
        let unexpired = discovery.rotate_now(&mut rng, fixed_now()).unwrap();
        discovery
            .rotate_now(&mut rng, fixed_now() + window / 2)
            .unwrap();

        discovery
            .delete_expired_previous(fixed_now() + window)
            .unwrap();

        // Reading at the earlier time would still find the expired key, had it stayed stored.
        assert!(!is_kept(&discovery, &expired, fixed_now()));
        assert!(is_kept(&discovery, &unexpired, fixed_now() + window));
    }

    #[test]
    fn reset_forgets_previous_keys() {
        let mut rng = ChaCha20Rng::from_seed([0xbd; 32]);
        let discovery = manager_with_identity();
        let first = discovery.rotate_now(&mut rng, fixed_now()).unwrap();
        discovery.rotate_now(&mut rng, fixed_now()).unwrap();
        discovery.reset().unwrap();
        assert!(!is_kept(&discovery, &first, fixed_now()));
    }

    #[test]
    fn previous_keys_with_an_unknown_version_are_refused() {
        let discovery = manager_with_identity();
        store(
            &discovery,
            PREVIOUS_DISCOVERY_KEYS,
            &[PREVIOUS_DISCOVERY_KEYS_VERSION + 1, 0],
        );

        assert!(matches!(
            discovery.previous_key(&[9; 32], fixed_now()),
            Err(DiscoveryKeyError::StoredData(StoredDataError::UnsupportedVersion { version }))
                if version == PREVIOUS_DISCOVERY_KEYS_VERSION + 1
        ));
    }

    #[test]
    fn rotate_now_recovers_from_tampered_signature_preserving_epoch() {
        let mut rng = ChaCha20Rng::from_seed([0xb7; 32]);
        let discovery = manager_with_identity();
        // Reach epoch 2 first, so recovery to 3 proves the stored value is read, not reset.
        discovery.rotate_now(&mut rng, fixed_now()).unwrap();
        let rotated = discovery.rotate_now(&mut rng, fixed_now()).unwrap();
        assert_eq!(rotated.epoch(), 2);

        let mut current = discovery.load_current().unwrap();
        current.discovery_key.identity_signature[0][0] ^= 0x01;
        store(
            &discovery,
            DISCOVERY_KEY,
            &encode_versioned(DISCOVERY_KEY_VERSION, &current).unwrap(),
        );
        assert!(matches!(
            discovery.current(),
            Err(DiscoveryKeyError::Corrupt(PublicKeyError::Signature(
                SignatureError::SignatureInvalid
            )))
        ));

        let recovered = discovery.rotate_now(&mut rng, fixed_now()).unwrap();
        assert_eq!(recovered.epoch(), 3);
        discovery.current().unwrap();
    }

    #[test]
    fn rotate_now_without_identity_returns_identity_error() {
        let mut rng = ChaCha20Rng::from_seed([0xb9; 32]);
        let discovery = manager_without_identity();
        assert!(matches!(
            discovery.rotate_now(&mut rng, fixed_now()),
            Err(DiscoveryKeyError::Identity(IdentityError::NotFound))
        ));
    }

    #[test]
    fn reset_clears_malformed_entry_then_rotation_starts_at_the_first_epoch() {
        let mut rng = ChaCha20Rng::from_seed([0xba; 32]);
        let discovery = manager_with_identity();
        store(&discovery, DISCOVERY_KEY, &[0xAAu8; 50]);
        discovery.reset().unwrap();
        assert_eq!(
            discovery.rotate_now(&mut rng, fixed_now()).unwrap().epoch(),
            FIRST_EPOCH
        );
    }

    #[test]
    fn export_entry_without_stored_key_returns_not_found() {
        let discovery = manager_with_identity();
        assert!(matches!(
            discovery.export_entry(),
            Err(DiscoveryKeyError::NotFound)
        ));
    }
}
