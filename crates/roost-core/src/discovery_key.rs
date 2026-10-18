use crate::identity::{IdentityError, IdentityManager};
use crate::storage::{SecureStorage, StorageError};
use rand::{CryptoRng, RngCore};
use roost_crypto::{
    DiscoveryKey, PublicDiscoveryKey, RecipientDeliveryCapability, Signature, SigningKeyPair,
    generate_discovery_key, generate_recipient_delivery_capability, verify_public_discovery_key,
};
use roost_protocol::{SignatureError, to_unix_secs};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime};
use zeroize::Zeroizing;

const DISCOVERY_KEY: &str = "discovery/current";
const PREVIOUS_DISCOVERY_KEYS: &str = "discovery/previous";
// Version 2 added the recipient delivery capability. A version 1 blob is rejected by the length
// check in `checked_blob` before the version byte is even read; it has no capability to migrate,
// so the host must reset and re-register.
const DISCOVERY_KEY_VERSION: u8 = 2;
// Blob layout: version (1) | epoch (4) | x25519 secret (32) | ed25519 secret (32) |
// identity signature (64) | created_at (8) | delivery capability (32).
const DISCOVERY_KEY_BLOB_LEN: usize = 1 + 4 + 32 + 32 + 64 + 8 + 32;
const CAPABILITY_OFFSET: usize = 141;
// Identity creation starts at epoch 1.
const FIRST_EPOCH: u32 = 1;
const PREVIOUS_DISCOVERY_KEYS_VERSION: u8 = 1;
// Blob layout: version (1) | count (1) | that many records.
const PREVIOUS_DISCOVERY_KEYS_HEADER_LEN: usize = 2;
// Record layout: the current blob's fields after its version and before its capability, which
// the Relay refuses once the new inbox is registered, then retired_at (8).
const PREVIOUS_DISCOVERY_KEY_RECORD_LEN: usize = CAPABILITY_OFFSET - 1 + 8;
// Enough for several blocks close together to keep each other's queued Messages readable.
const MAX_PREVIOUS_DISCOVERY_KEYS: usize = 5;
// How long the Relay may hold a queued Message.
const PREVIOUS_DISCOVERY_KEY_RETENTION_WINDOW: Duration = Duration::from_secs(30 * 86_400);

/// Errors returned by discovery-key operations.
#[derive(Debug, thiserror::Error)]
pub enum DiscoveryKeyError {
    /// Stored data uses an unsupported format version.
    #[error("unsupported stored format version: {0}")]
    UnsupportedVersion(u8),
    /// The system clock is before the Unix epoch.
    #[error("system clock is before Unix epoch")]
    Clock,
    /// The stored discovery key's signature does not verify against the identity key.
    #[error("stored discovery-key signature does not match the identity key")]
    Corrupt,
    /// Loading the identity for discovery-key signing or verification returned an
    /// [`IdentityError`].
    #[error("loading the identity failed")]
    Identity(#[from] IdentityError),
    /// Signing the discovery-to-identity binding failed.
    #[error("signing the discovery-to-identity binding failed")]
    IdentityBindingSignature(#[source] SignatureError),
    /// A discovery-key blob has the wrong length.
    #[error("discovery-key blob is {actual} bytes, expected {expected}")]
    InvalidBlobLength {
        /// Expected length in bytes.
        expected: usize,
        /// Supplied length in bytes.
        actual: usize,
    },
    /// The stored discovery key is malformed and must be reset before a new one replaces it.
    #[error("stored discovery key is malformed")]
    Malformed,
    /// Signing a new discovery key with the identity key failed.
    #[error("signing the discovery key failed")]
    DiscoveryKeySignature(#[source] SignatureError),
    /// The internal storage lock was poisoned by a panicked thread.
    #[error("internal lock poisoned")]
    LockPoisoned,
    /// No discovery key is stored.
    #[error("no discovery key stored")]
    NotFound,
    /// The stored previous discovery keys number more than Roost keeps.
    #[error("{count} previous discovery keys stored, more than {max}")]
    TooManyPreviousKeys {
        /// Number of keys the stored blob declares.
        count: usize,
        /// Most previous keys Roost keeps.
        max: usize,
    },
    /// The underlying [`SecureStorage`] returned an error.
    #[error("discovery-key storage failed")]
    Storage(#[from] StorageError),
}

// A Discovery Key a rotation replaced, kept only to open Messages already sealed to it.
struct PreviousDiscoveryKey {
    discovery_key: DiscoveryKey,
    retired_at_secs: u64,
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
        let discovery_key = self.load_stored()?;
        let identity = self.identity.load_identity()?;
        verify_public_discovery_key(&discovery_key.public(), identity.verifying_key())
            .map_err(|_| DiscoveryKeyError::Corrupt)?;
        Ok(discovery_key)
    }

    // Returns the public discovery key to distribute to peers, verified against the identity key.
    pub(crate) fn current_public(&self) -> Result<PublicDiscoveryKey, DiscoveryKeyError> {
        Ok(self.current()?.public())
    }

    // Returns the DK→IK binding for `discovery_key` against the stored identity.
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
            .sign_identity_binding(&identity.public()?)
            .map_err(DiscoveryKeyError::IdentityBindingSignature)
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
    // blob returns `InvalidData` until cleared with `reset`. The replaced key joins the previous
    // keys, which drop any past the Relay's queue time and then the oldest past the limit.
    pub(crate) fn rotate_now<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        now: SystemTime,
    ) -> Result<DiscoveryKey, DiscoveryKeyError> {
        let identity = self.identity.load_identity()?;
        let now_secs = to_unix_secs(now).ok_or(DiscoveryKeyError::Clock)?;
        let (epoch, previous) = match self.stored_status()? {
            DiscoveryKeyStatus::Absent => (FIRST_EPOCH, None),
            DiscoveryKeyStatus::Present { epoch } => (
                epoch.saturating_add(1),
                Some(self.retire_current(now_secs)?),
            ),
            DiscoveryKeyStatus::Malformed => return Err(DiscoveryKeyError::Malformed),
        };
        let discovery_key =
            generate_discovery_key(rng, identity.signing_key_pair(), epoch, now_secs)
                .map_err(DiscoveryKeyError::DiscoveryKeySignature)?;
        // The capability rotates with the discovery key because both belong to one epoch, and
        // they are written in one store so they cannot diverge.
        let capability = generate_recipient_delivery_capability(rng);
        let blob = encode_discovery_key(&discovery_key, &capability);
        let mut storage = self.lock_storage()?;
        if let Some(previous) = previous {
            storage.store(
                PREVIOUS_DISCOVERY_KEYS,
                &encode_previous_discovery_keys(&previous)?,
            )?;
        }
        storage.store(DISCOVERY_KEY, &*blob)?;
        Ok(discovery_key)
    }

    // Returns the previous Discovery Key with X25519 public key `public_key`, if the Relay may
    // still hold Messages for it at `now`.
    //
    // Reading leaves expired keys in place, so only a rotation deletes them.
    pub(crate) fn previous_key(
        &self,
        public_key: &[u8; 32],
        now: SystemTime,
    ) -> Result<Option<DiscoveryKey>, DiscoveryKeyError> {
        let now_secs = to_unix_secs(now).ok_or(DiscoveryKeyError::Clock)?;
        Ok(self
            .load_previous()?
            .into_iter()
            .find(|previous| {
                previous.discovery_key.public_key().as_bytes() == public_key
                    && is_retained(previous.retired_at_secs, now_secs)
            })
            .map(|previous| previous.discovery_key))
    }

    // Returns the previous keys with the current one retired at `now_secs` added.
    fn retire_current(
        &self,
        now_secs: u64,
    ) -> Result<Vec<PreviousDiscoveryKey>, DiscoveryKeyError> {
        let mut previous = self.load_previous()?;
        previous.retain(|previous| is_retained(previous.retired_at_secs, now_secs));
        previous.push(PreviousDiscoveryKey {
            discovery_key: self.load_stored()?,
            retired_at_secs: now_secs,
        });
        let excess = previous.len().saturating_sub(MAX_PREVIOUS_DISCOVERY_KEYS);
        previous.drain(..excess);
        Ok(previous)
    }

    fn load_previous(&self) -> Result<Vec<PreviousDiscoveryKey>, DiscoveryKeyError> {
        match self.lock_storage()?.load(PREVIOUS_DISCOVERY_KEYS)? {
            Some(raw) => decode_previous_discovery_keys(&raw),
            None => Ok(Vec::with_capacity(1)),
        }
    }

    // Returns the recipient delivery capability bound to the current epoch.
    //
    // Secret-bearing: the caller presents it to authorized contacts and never registers it. Only
    // its verifier is registered with the relay.
    pub(crate) fn current_capability(
        &self,
    ) -> Result<RecipientDeliveryCapability, DiscoveryKeyError> {
        let raw = self.load_raw()?.ok_or(DiscoveryKeyError::NotFound)?;
        Ok(decode_capability(checked_blob(&raw)?))
    }

    // Use `KeyStore::prepare_identity_deletion` to clear signed-prekey state before discovery key and identity.
    pub(crate) fn reset(&self) -> Result<(), DiscoveryKeyError> {
        let mut storage = self.lock_storage()?;
        storage.delete(PREVIOUS_DISCOVERY_KEYS)?;
        Ok(storage.delete(DISCOVERY_KEY)?)
    }

    // Returns the verbatim stored discovery-key blob for inclusion in an encrypted backup.
    pub(crate) fn export_blob(&self) -> Result<Zeroizing<Vec<u8>>, DiscoveryKeyError> {
        let raw = self.load_raw()?.ok_or(DiscoveryKeyError::NotFound)?;
        checked_blob(&raw)?;
        Ok(raw)
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
        verify_public_discovery_key(&discovery_key.public(), &identity_signing.verifying)
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
}

fn checked_blob(raw: &[u8]) -> Result<&[u8; DISCOVERY_KEY_BLOB_LEN], DiscoveryKeyError> {
    let blob: &[u8; DISCOVERY_KEY_BLOB_LEN] =
        raw.try_into()
            .map_err(|_| DiscoveryKeyError::InvalidBlobLength {
                expected: DISCOVERY_KEY_BLOB_LEN,
                actual: raw.len(),
            })?;
    if blob[0] != DISCOVERY_KEY_VERSION {
        return Err(DiscoveryKeyError::UnsupportedVersion(blob[0]));
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
    blob[133..CAPABILITY_OFFSET].copy_from_slice(&discovery_key.created_at_secs().to_be_bytes());
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

// Returns whether a key retired at `retired_at_secs` may still open queued Messages at `now_secs`.
fn is_retained(retired_at_secs: u64, now_secs: u64) -> bool {
    now_secs.saturating_sub(retired_at_secs) < PREVIOUS_DISCOVERY_KEY_RETENTION_WINDOW.as_secs()
}

fn encode_previous_discovery_keys(
    previous: &[PreviousDiscoveryKey],
) -> Result<Zeroizing<Vec<u8>>, DiscoveryKeyError> {
    let count = u8::try_from(previous.len())
        .ok()
        .filter(|count| usize::from(*count) <= MAX_PREVIOUS_DISCOVERY_KEYS)
        .ok_or(DiscoveryKeyError::TooManyPreviousKeys {
            count: previous.len(),
            max: MAX_PREVIOUS_DISCOVERY_KEYS,
        })?;
    let mut blob = Zeroizing::new(Vec::with_capacity(
        PREVIOUS_DISCOVERY_KEYS_HEADER_LEN + previous.len() * PREVIOUS_DISCOVERY_KEY_RECORD_LEN,
    ));
    blob.push(PREVIOUS_DISCOVERY_KEYS_VERSION);
    blob.push(count);
    for previous in previous {
        // The capability isn't kept, so encode with a zero one and leave it out.
        let encoded = encode_discovery_key(
            &previous.discovery_key,
            &RecipientDeliveryCapability::from_bytes([0; 32]),
        );
        blob.extend_from_slice(&encoded[1..CAPABILITY_OFFSET]);
        blob.extend_from_slice(&previous.retired_at_secs.to_be_bytes());
    }
    Ok(blob)
}

fn decode_previous_discovery_keys(
    raw: &[u8],
) -> Result<Vec<PreviousDiscoveryKey>, DiscoveryKeyError> {
    let (&[version, count], records) = raw
        .split_first_chunk::<PREVIOUS_DISCOVERY_KEYS_HEADER_LEN>()
        .ok_or(DiscoveryKeyError::InvalidBlobLength {
            expected: PREVIOUS_DISCOVERY_KEYS_HEADER_LEN,
            actual: raw.len(),
        })?;
    if version != PREVIOUS_DISCOVERY_KEYS_VERSION {
        return Err(DiscoveryKeyError::UnsupportedVersion(version));
    }
    let count = usize::from(count);
    if count > MAX_PREVIOUS_DISCOVERY_KEYS {
        return Err(DiscoveryKeyError::TooManyPreviousKeys {
            count,
            max: MAX_PREVIOUS_DISCOVERY_KEYS,
        });
    }
    let expected = PREVIOUS_DISCOVERY_KEYS_HEADER_LEN + count * PREVIOUS_DISCOVERY_KEY_RECORD_LEN;
    if raw.len() != expected {
        return Err(DiscoveryKeyError::InvalidBlobLength {
            expected,
            actual: raw.len(),
        });
    }
    // Room for the key a rotation retires, so the list of secrets never reallocates.
    let mut previous = Vec::with_capacity(MAX_PREVIOUS_DISCOVERY_KEYS + 1);
    for record in records.as_chunks::<PREVIOUS_DISCOVERY_KEY_RECORD_LEN>().0 {
        let mut blob = Zeroizing::new([0u8; DISCOVERY_KEY_BLOB_LEN]);
        blob[1..CAPABILITY_OFFSET].copy_from_slice(&record[..CAPABILITY_OFFSET - 1]);
        let mut retired_at = [0u8; 8];
        retired_at.copy_from_slice(&record[CAPABILITY_OFFSET - 1..]);
        previous.push(PreviousDiscoveryKey {
            discovery_key: decode_discovery_key(&blob),
            retired_at_secs: u64::from_be_bytes(retired_at),
        });
    }
    Ok(previous)
}

fn read_epoch(blob: &[u8; DISCOVERY_KEY_BLOB_LEN]) -> u32 {
    let mut epoch_bytes = [0u8; 4];
    epoch_bytes.copy_from_slice(&blob[1..5]);
    u32::from_be_bytes(epoch_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::InMemorySecureStorage;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use roost_protocol::from_unix_secs;
    use std::time::SystemTime;

    const FIXED_NOW: u64 = 1_700_000_000;

    fn fixed_now() -> SystemTime {
        from_unix_secs(FIXED_NOW).unwrap()
    }

    struct DiscoveryKeySetup {
        identity: Arc<IdentityManager>,
        manager: DiscoveryKeyManager,
    }

    fn shared_storage() -> Arc<Mutex<Box<dyn SecureStorage>>> {
        Arc::new(Mutex::new(Box::new(InMemorySecureStorage::new())))
    }

    fn setup_with_identity() -> DiscoveryKeySetup {
        let mut rng = ChaCha20Rng::from_seed([0xb0; 32]);
        let storage = shared_storage();
        let identity = Arc::new(IdentityManager::new(Arc::clone(&storage)));
        identity.generate_identity(&mut rng).unwrap();
        let discovery = DiscoveryKeyManager::new(storage, Arc::clone(&identity));
        DiscoveryKeySetup {
            identity,
            manager: discovery,
        }
    }

    fn manager_without_identity() -> DiscoveryKeyManager {
        let storage = shared_storage();
        let identity = Arc::new(IdentityManager::new(Arc::clone(&storage)));
        DiscoveryKeyManager::new(storage, identity)
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
    fn a_discovery_key_blob_of_the_wrong_length_is_refused_by_each_reader() {
        let mut rng = ChaCha20Rng::from_seed([0xb8; 32]);
        let discovery = setup_with_identity().manager;
        let malformed = [0xAAu8; 50];
        let wrong_length = |result| {
            matches!(
                result,
                Err(DiscoveryKeyError::InvalidBlobLength {
                    expected: DISCOVERY_KEY_BLOB_LEN,
                    actual: 50
                })
            )
        };
        assert!(wrong_length(discovery.restore_from_blob(&malformed)));
        discovery
            .lock_storage()
            .unwrap()
            .store(DISCOVERY_KEY, &malformed)
            .unwrap();

        assert!(wrong_length(discovery.current().map(|_| ())));
        assert!(matches!(
            discovery.stored_status().unwrap(),
            DiscoveryKeyStatus::Malformed
        ));
        assert!(matches!(
            discovery.rotate_now(&mut rng, fixed_now()),
            Err(DiscoveryKeyError::Malformed)
        ));
    }

    #[test]
    fn stored_status_reports_absent_and_present() {
        let mut rng = ChaCha20Rng::from_seed([0xb2; 32]);
        let discovery = setup_with_identity().manager;
        assert!(matches!(
            discovery.stored_status().unwrap(),
            DiscoveryKeyStatus::Absent
        ));
        discovery.rotate_now(&mut rng, fixed_now()).unwrap();
        assert!(matches!(
            discovery.stored_status().unwrap(),
            DiscoveryKeyStatus::Present { epoch: 1 }
        ));
    }

    #[test]
    fn rotate_now_advances_the_epoch() {
        let mut rng = ChaCha20Rng::from_seed([0xb6; 32]);
        let discovery = setup_with_identity().manager;
        assert_eq!(
            discovery.rotate_now(&mut rng, fixed_now()).unwrap().epoch(),
            1
        );
        assert_eq!(
            discovery.rotate_now(&mut rng, fixed_now()).unwrap().epoch(),
            2
        );
        assert_eq!(
            discovery.rotate_now(&mut rng, fixed_now()).unwrap().epoch(),
            3
        );
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
        let discovery = setup_with_identity().manager;
        let first = discovery.rotate_now(&mut rng, fixed_now()).unwrap();
        let current = discovery.rotate_now(&mut rng, fixed_now()).unwrap();
        let window = PREVIOUS_DISCOVERY_KEY_RETENTION_WINDOW;

        let last_moment = fixed_now() + window - Duration::from_secs(1);
        assert!(is_kept(&discovery, &first, last_moment));
        assert!(!is_kept(&discovery, &first, fixed_now() + window));
        assert!(!is_kept(&discovery, &current, fixed_now()));
    }

    #[test]
    fn a_rotation_drops_expired_keys_then_the_oldest_past_the_limit() {
        let mut rng = ChaCha20Rng::from_seed([0xbc; 32]);
        let discovery = setup_with_identity().manager;
        let expired = discovery.rotate_now(&mut rng, fixed_now()).unwrap();
        let later = fixed_now() + PREVIOUS_DISCOVERY_KEY_RETENTION_WINDOW;
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
    fn reset_forgets_previous_keys() {
        let mut rng = ChaCha20Rng::from_seed([0xbd; 32]);
        let discovery = setup_with_identity().manager;
        let first = discovery.rotate_now(&mut rng, fixed_now()).unwrap();
        discovery.rotate_now(&mut rng, fixed_now()).unwrap();

        discovery.reset().unwrap();

        assert!(!is_kept(&discovery, &first, fixed_now()));
    }

    #[test]
    fn previous_keys_with_an_unknown_version_are_refused() {
        let discovery = setup_with_identity().manager;
        discovery
            .lock_storage()
            .unwrap()
            .store(PREVIOUS_DISCOVERY_KEYS, &[2, 0])
            .unwrap();

        assert!(matches!(
            discovery.previous_key(&[9; 32], fixed_now()),
            Err(DiscoveryKeyError::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn rotate_now_recovers_from_tampered_signature_preserving_epoch() {
        let mut rng = ChaCha20Rng::from_seed([0xb7; 32]);
        let discovery = setup_with_identity().manager;
        // Reach epoch 2 first, so recovery to 3 proves the stored value is read, not reset.
        discovery.rotate_now(&mut rng, fixed_now()).unwrap();
        let rotated = discovery.rotate_now(&mut rng, fixed_now()).unwrap();
        assert_eq!(rotated.epoch(), 2);

        // Corrupt the signature of the epoch-2 key.
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

        let recovered = discovery.rotate_now(&mut rng, fixed_now()).unwrap();
        assert_eq!(recovered.epoch(), 3);
        assert!(discovery.current().is_ok());
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
    fn reset_clears_malformed_blob_then_rotation_starts_at_zero() {
        let mut rng = ChaCha20Rng::from_seed([0xba; 32]);
        let discovery = setup_with_identity().manager;
        discovery
            .lock_storage()
            .unwrap()
            .store(DISCOVERY_KEY, &[0xAAu8; 50])
            .unwrap();
        discovery.reset().unwrap();
        assert_eq!(
            discovery.rotate_now(&mut rng, fixed_now()).unwrap().epoch(),
            1
        );
    }

    #[test]
    fn encode_decode_round_trip() {
        let mut rng = ChaCha20Rng::from_seed([0xbb; 32]);
        let identity = setup_with_identity().identity;
        let loaded = identity.load_identity().unwrap();
        let original =
            generate_discovery_key(&mut rng, loaded.signing_key_pair(), 9, FIXED_NOW).unwrap();
        let capability = generate_recipient_delivery_capability(&mut rng);
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
            original.public().verifying_key.as_bytes(),
            restored.public().verifying_key.as_bytes(),
        );
        assert_eq!(
            original.identity_signature().to_bytes(),
            restored.identity_signature().to_bytes()
        );
        assert_eq!(restored.epoch(), 9);
        assert_eq!(restored.created_at_secs(), FIXED_NOW);
    }

    #[test]
    fn export_blob_without_stored_key_returns_not_found() {
        let discovery = setup_with_identity().manager;
        assert!(matches!(
            discovery.export_blob(),
            Err(DiscoveryKeyError::NotFound)
        ));
    }
}
