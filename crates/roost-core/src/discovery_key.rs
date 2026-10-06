use crate::identity::{IdentityError, IdentityManager};
use crate::storage::{SecureStorage, StorageError};
use rand::{CryptoRng, RngCore};
use roost_crypto::{
    DiscoveryKey, PublicDiscoveryKey, RecipientDeliveryCapability, Signature, SigningKeyPair,
    generate_discovery_key, generate_recipient_delivery_capability, verify_public_discovery_key,
};
use roost_protocol::{SignatureError, to_unix_secs};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::SystemTime;
use zeroize::Zeroizing;

const DISCOVERY_KEY: &str = "discovery/current";
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
    /// The underlying [`SecureStorage`] returned an error.
    #[error("discovery-key storage failed")]
    Storage(#[from] StorageError),
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
    // blob returns `InvalidData` until cleared with `reset`.
    pub(crate) fn rotate_now<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        now: SystemTime,
    ) -> Result<DiscoveryKey, DiscoveryKeyError> {
        let identity = self.identity.load_identity()?;
        let epoch = match self.stored_status()? {
            DiscoveryKeyStatus::Absent => FIRST_EPOCH,
            DiscoveryKeyStatus::Present { epoch } => epoch.saturating_add(1),
            DiscoveryKeyStatus::Malformed => return Err(DiscoveryKeyError::Malformed),
        };
        let now_secs = to_unix_secs(now).ok_or(DiscoveryKeyError::Clock)?;
        let discovery_key =
            generate_discovery_key(rng, identity.signing_key_pair(), epoch, now_secs)
                .map_err(DiscoveryKeyError::DiscoveryKeySignature)?;
        // The capability rotates with the discovery key because both belong to one epoch, and
        // they are written in one store so they cannot diverge.
        let capability = generate_recipient_delivery_capability(rng);
        let blob = encode_discovery_key(&discovery_key, &capability);
        let mut storage = self.lock_storage()?;
        storage.store(DISCOVERY_KEY, &*blob)?;
        Ok(discovery_key)
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
        Ok(storage.delete(DISCOVERY_KEY)?)
    }

    // Returns the verbatim stored discovery-key blob for inclusion in an encrypted backup.
    pub(crate) fn export_blob(&self) -> Result<Zeroizing<Vec<u8>>, DiscoveryKeyError> {
        let raw = self.load_raw()?.ok_or(DiscoveryKeyError::NotFound)?;
        checked_blob(&raw)?;
        Ok(raw)
    }

    // Validates a discovery-key blob's structure without storing it, so a malformed backup aborts
    // an import before any existing key material is cleared.
    #[cfg(test)]
    pub(crate) fn validate_blob(blob: &[u8]) -> Result<(), DiscoveryKeyError> {
        checked_blob(blob).map(|_| ())
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
    fn current_rejects_blob_of_wrong_length() {
        let discovery = setup_with_identity().manager;
        discovery
            .lock_storage()
            .unwrap()
            .store(DISCOVERY_KEY, &[0xAAu8; 50])
            .unwrap();
        assert!(matches!(
            discovery.current(),
            Err(DiscoveryKeyError::InvalidBlobLength {
                expected: DISCOVERY_KEY_BLOB_LEN,
                actual: 50
            })
        ));
    }

    #[test]
    fn current_returns_corrupt_for_tampered_signature() {
        let mut rng = ChaCha20Rng::from_seed([0xb1; 32]);
        let discovery = setup_with_identity().manager;
        discovery.rotate_now(&mut rng, fixed_now()).unwrap();
        // Flip a byte inside the stored signature region.
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
    }

    #[test]
    fn stored_status_reports_absent_present_and_malformed() {
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
        discovery
            .lock_storage()
            .unwrap()
            .store(DISCOVERY_KEY, &[0xAAu8; 50])
            .unwrap();
        assert!(matches!(
            discovery.stored_status().unwrap(),
            DiscoveryKeyStatus::Malformed
        ));
    }

    #[test]
    fn rotate_now_establishes_epoch_one_and_verifies() {
        let mut rng = ChaCha20Rng::from_seed([0xb3; 32]);
        let DiscoveryKeySetup {
            identity,
            manager: discovery,
        } = setup_with_identity();
        let rotated = discovery.rotate_now(&mut rng, fixed_now()).unwrap();
        // Identity creation starts at epoch 1, not 0.
        assert_eq!(rotated.epoch(), 1);
        let bundle = discovery.current_public().unwrap();
        assert_eq!(bundle.epoch, 1);
        let loaded_identity = identity.load_identity().unwrap();
        assert!(verify_public_discovery_key(&bundle, loaded_identity.verifying_key()).is_ok());
    }

    /// The discovery key and the delivery capability share one epoch, so rotation must
    /// replace both. A rotation that advanced the epoch while leaving the
    /// capability intact would leave a blocked contact still able to deliver.
    #[test]
    fn rotation_replaces_the_delivery_capability() {
        let mut rng = ChaCha20Rng::from_seed([0xb4; 32]);
        let discovery = setup_with_identity().manager;
        discovery.rotate_now(&mut rng, fixed_now()).unwrap();
        let before = *discovery.current_capability().unwrap().to_bytes();

        discovery.rotate_now(&mut rng, fixed_now()).unwrap();
        let after = *discovery.current_capability().unwrap().to_bytes();

        assert_ne!(before, after);
    }

    #[test]
    fn capability_survives_a_reload() {
        let mut rng = ChaCha20Rng::from_seed([0xb5; 32]);
        let discovery = setup_with_identity().manager;
        discovery.rotate_now(&mut rng, fixed_now()).unwrap();

        let first = *discovery.current_capability().unwrap().to_bytes();
        let second = *discovery.current_capability().unwrap().to_bytes();

        assert_eq!(first, second);
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
    fn rotate_now_rejects_malformed_blob() {
        let mut rng = ChaCha20Rng::from_seed([0xb8; 32]);
        let discovery = setup_with_identity().manager;
        discovery
            .lock_storage()
            .unwrap()
            .store(DISCOVERY_KEY, &[0xAAu8; 50])
            .unwrap();
        assert!(matches!(
            discovery.rotate_now(&mut rng, fixed_now()),
            Err(DiscoveryKeyError::Malformed)
        ));
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
            original.verifying_key().as_bytes(),
            restored.verifying_key().as_bytes(),
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

    #[test]
    fn export_then_restore_blob_preserves_epoch_and_verifies() {
        let mut rng = ChaCha20Rng::from_seed([0xbc; 32]);
        let discovery = setup_with_identity().manager;
        discovery.rotate_now(&mut rng, fixed_now()).unwrap();
        let exported = discovery.rotate_now(&mut rng, fixed_now()).unwrap();
        assert_eq!(exported.epoch(), 2);
        let blob = discovery.export_blob().unwrap();

        discovery.reset().unwrap();
        discovery.restore_from_blob(&blob).unwrap();

        let restored = discovery.current().unwrap();
        assert_eq!(restored.epoch(), 2);
        assert_eq!(
            restored.public_key().as_bytes(),
            exported.public_key().as_bytes()
        );
    }

    #[test]
    fn validate_blob_accepts_stored_blob_and_rejects_malformed() {
        let mut rng = ChaCha20Rng::from_seed([0xbd; 32]);
        let discovery = setup_with_identity().manager;
        discovery.rotate_now(&mut rng, fixed_now()).unwrap();
        let blob = discovery.export_blob().unwrap();
        assert!(DiscoveryKeyManager::validate_blob(&blob).is_ok());
        assert!(matches!(
            DiscoveryKeyManager::validate_blob(&[0xAAu8; 50]),
            Err(DiscoveryKeyError::InvalidBlobLength {
                expected: DISCOVERY_KEY_BLOB_LEN,
                actual: 50
            })
        ));
    }

    #[test]
    fn restore_from_blob_rejects_malformed_blob() {
        let discovery = setup_with_identity().manager;
        assert!(matches!(
            discovery.restore_from_blob(&[0xAAu8; 50]),
            Err(DiscoveryKeyError::InvalidBlobLength {
                expected: DISCOVERY_KEY_BLOB_LEN,
                actual: 50
            })
        ));
    }
}
