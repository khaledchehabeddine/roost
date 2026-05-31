use crate::clock::{Clock, SystemClock};
use crate::discovery_key::{DiscoveryKeyError, DiscoveryKeyManager, DiscoveryKeyStatus};
use crate::identity::{Identity, IdentityError, IdentityManager};
use crate::signed_prekey::{SignedPreKeyError, SignedPreKeyManager};
use crate::storage::SecureStorage;
use aether_crypto::{DiscoveryKeyBundle, SignedPreKeyBundle};
use rand::rngs::OsRng;
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex};

/// Errors returned by [`KeyStore`] operations.
#[derive(Debug)]
pub enum KeyStoreError {
    /// A discovery-key operation failed.
    Discovery(DiscoveryKeyError),
    /// An identity-layer operation failed.
    Identity(IdentityError),
    /// A signed-pre-key operation failed.
    SignedPreKey(SignedPreKeyError),
}

impl fmt::Display for KeyStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyStoreError::Discovery(e) => write!(f, "discovery key: {e}"),
            KeyStoreError::Identity(e) => write!(f, "identity: {e}"),
            KeyStoreError::SignedPreKey(e) => write!(f, "signed pre-key: {e}"),
        }
    }
}

impl Error for KeyStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            KeyStoreError::Discovery(e) => Some(e),
            KeyStoreError::Identity(e) => Some(e),
            KeyStoreError::SignedPreKey(e) => Some(e),
        }
    }
}

impl From<IdentityError> for KeyStoreError {
    fn from(e: IdentityError) -> Self {
        KeyStoreError::Identity(e)
    }
}

impl From<SignedPreKeyError> for KeyStoreError {
    fn from(e: SignedPreKeyError) -> Self {
        KeyStoreError::SignedPreKey(e)
    }
}

impl From<DiscoveryKeyError> for KeyStoreError {
    fn from(e: DiscoveryKeyError) -> Self {
        KeyStoreError::Discovery(e)
    }
}

/// The discovery-key bundle and signed-pre-key bundle produced by a single discovery-key rotation.
///
/// Verify [`Self::discovery_key`] against the identity verifying key, then verify
/// [`Self::signed_prekey`] against the discovery key's verifying key.
#[derive(Clone, Debug)]
pub struct DiscoveryKeyRotationBundle {
    /// The freshly generated discovery-key bundle.
    pub discovery_key: DiscoveryKeyBundle,
    /// The freshly generated signed pre-key, signed by the new discovery key.
    pub signed_prekey: SignedPreKeyBundle,
}

struct KeyStoreInner {
    identity: Arc<IdentityManager>,
    discovery: Arc<DiscoveryKeyManager>,
    signed_prekey: Arc<SignedPreKeyManager>,
}

/// Facade over identity and signed-pre-key managers sharing the same [`SecureStorage`].
///
/// Clones share the same underlying storage and synchronization.
#[derive(Clone)]
pub struct KeyStore(Arc<KeyStoreInner>);

impl KeyStore {
    /// Creates a keystore backed by `storage`, reading time from the system clock.
    pub fn new(storage: Box<dyn SecureStorage>) -> Self {
        Self::with_clock(storage, Arc::new(SystemClock))
    }

    // Creates a keystore backed by `storage`, reading time from `clock`.
    pub(crate) fn with_clock(storage: Box<dyn SecureStorage>, clock: Arc<dyn Clock>) -> Self {
        let storage = Arc::new(Mutex::new(storage));
        let identity = Arc::new(IdentityManager::new(Arc::clone(&storage)));
        let discovery = Arc::new(DiscoveryKeyManager::new(
            Arc::clone(&storage),
            Arc::clone(&identity),
            Arc::clone(&clock),
        ));
        let signed_prekey = Arc::new(SignedPreKeyManager::new(
            storage,
            Arc::clone(&discovery),
            clock,
        ));
        KeyStore(Arc::new(KeyStoreInner {
            identity,
            discovery,
            signed_prekey,
        }))
    }

    /// Generates a fresh [`Identity`] and its first discovery key (epoch 0), persisting both.
    ///
    /// Storage is not transactional, so a prior call that stored the identity but failed before the
    /// discovery key leaves an identity with no discovery key. A later call completes the discovery
    /// key and succeeds rather than erroring. A malformed stored discovery key must be cleared with
    /// [`Self::reset`] first.
    ///
    /// # Errors
    /// - [`KeyStoreError::Identity`] (`AlreadyExists`) if a complete identity and discovery key exist.
    /// - [`KeyStoreError::Discovery`] (`InvalidData`) if a stored discovery key is malformed.
    /// - [`KeyStoreError::Discovery`] (`Clock`) if the system clock is before the Unix epoch.
    /// - [`KeyStoreError::Identity`] | [`KeyStoreError::Discovery`] (`LockPoisoned` | `Storage`) on
    ///   storage failures.
    pub fn generate_identity(&self) -> Result<Identity, KeyStoreError> {
        let identity = match self.0.identity.generate_identity(&mut OsRng) {
            Ok(identity) => identity,
            // A prior partial creation may have stored the identity but not the discovery key.
            Err(IdentityError::AlreadyExists) => match self.0.discovery.stored_status()? {
                DiscoveryKeyStatus::Present(_) => {
                    return Err(IdentityError::AlreadyExists.into());
                }
                DiscoveryKeyStatus::Malformed => {
                    return Err(DiscoveryKeyError::InvalidData(
                        "stored discovery key is malformed; reset before regenerating".into(),
                    )
                    .into());
                }
                DiscoveryKeyStatus::Absent => self.0.identity.load_identity()?,
            },
            Err(e) => return Err(e.into()),
        };
        self.0.discovery.rotate_now(&mut OsRng)?;
        Ok(identity)
    }

    /// Loads the stored [`Identity`].
    ///
    /// # Errors
    /// - [`KeyStoreError::Identity`] (`Corrupt`) if only one of the two identity keys is present.
    /// - [`KeyStoreError::Identity`] (`InvalidData`) if a stored key has the wrong byte length.
    /// - [`KeyStoreError::Identity`] (`LockPoisoned`) on storage lock poisoning.
    /// - [`KeyStoreError::Identity`] (`NotFound`) if no identity is stored.
    /// - [`KeyStoreError::Identity`] (`Storage`) on platform storage failure.
    pub fn load_identity(&self) -> Result<Identity, KeyStoreError> {
        Ok(self.0.identity.load_identity()?)
    }

    /// Exports the stored identity as a passphrase-encrypted backup blob.
    ///
    /// # Errors
    /// - [`KeyStoreError::Identity`] (`BackupFailed`) on RNG failure, Argon2id derivation error,
    ///   or authenticated encryption failure.
    /// - [`KeyStoreError::Identity`] (`Corrupt` | `InvalidData` | `NotFound`) when loading the
    ///   identity to export fails.
    /// - [`KeyStoreError::Identity`] (`LockPoisoned` | `Storage`) on storage failures.
    pub fn export_encrypted_backup(&self, passphrase: &str) -> Result<Vec<u8>, KeyStoreError> {
        Ok(self
            .0
            .identity
            .export_encrypted_backup(&mut OsRng, passphrase)?)
    }

    /// Returns the stored [`SignedPreKeyBundle`].
    ///
    /// The bundle is signed by the current discovery key, so verify it against the discovery key's
    /// verifying key (from [`Self::current_discovery_key_bundle`]), not the identity key.
    ///
    /// # Errors
    /// - [`KeyStoreError::SignedPreKey`] (`InvalidData`) if the stored blob is malformed.
    /// - [`KeyStoreError::SignedPreKey`] (`LockPoisoned` | `Storage`) on storage failures.
    /// - [`KeyStoreError::SignedPreKey`] (`NotFound`) if no signed pre-key is stored.
    pub fn current_signed_prekey_bundle(&self) -> Result<SignedPreKeyBundle, KeyStoreError> {
        Ok(self.0.signed_prekey.current_bundle()?)
    }

    /// Returns the current [`DiscoveryKeyBundle`], verified against the identity key.
    ///
    /// # Errors
    /// - [`KeyStoreError::Discovery`] (`Corrupt`) if the stored discovery key does not verify against
    ///   the identity key.
    /// - [`KeyStoreError::Discovery`] (`InvalidData`) if the stored discovery key is malformed.
    /// - [`KeyStoreError::Discovery`] (`Identity`) if loading the identity to verify against fails.
    /// - [`KeyStoreError::Discovery`] (`LockPoisoned` | `Storage`) on storage failures.
    /// - [`KeyStoreError::Discovery`] (`NotFound`) if no discovery key is stored.
    pub fn current_discovery_key_bundle(&self) -> Result<DiscoveryKeyBundle, KeyStoreError> {
        Ok(self.0.discovery.current_bundle()?)
    }

    /// Rotates the discovery key and its signed pre-key in one operation, returning both bundles.
    ///
    /// Advances the discovery-key epoch and generates a fresh signed pre-key signed by the new
    /// discovery key. The previous signed pre-key is cleared before the new discovery key is stored,
    /// so a partial failure leaves at most a missing signed pre-key, never one signed by a stale
    /// discovery key.
    ///
    /// # Errors
    /// - [`KeyStoreError::Discovery`] (`Clock`) if the system clock is before the Unix epoch.
    /// - [`KeyStoreError::Discovery`] (`EpochExhausted`) if the epoch counter cannot advance.
    /// - [`KeyStoreError::Discovery`] (`Identity`) if loading the identity fails.
    /// - [`KeyStoreError::Discovery`] (`InvalidData`) if the stored discovery key is malformed.
    /// - [`KeyStoreError::Discovery`] | [`KeyStoreError::SignedPreKey`] (`LockPoisoned` | `Storage`)
    ///   on storage failures.
    pub fn rotate_discovery_key_now(&self) -> Result<DiscoveryKeyRotationBundle, KeyStoreError> {
        self.0.signed_prekey.reset()?;
        let discovery_key = self.0.discovery.rotate_now(&mut OsRng)?;
        let signed_prekey = self.0.signed_prekey.rotate_now(&mut OsRng)?;
        Ok(DiscoveryKeyRotationBundle {
            discovery_key: discovery_key.bundle(),
            signed_prekey: signed_prekey.bundle(),
        })
    }

    /// Returns whether this keystore has identity data in storage.
    ///
    /// This is a presence check only. Use [`Self::load_identity`] to read and validate the stored
    /// identity.
    ///
    /// # Errors
    /// - [`KeyStoreError::Identity`] (`LockPoisoned`) on storage lock poisoning.
    /// - [`KeyStoreError::Identity`] (`Storage`) on platform storage failure.
    pub fn has_identity(&self) -> Result<bool, KeyStoreError> {
        Ok(self.0.identity.has_identity()?)
    }

    /// Rotates the stored signed pre-key when its bundle is stale or missing.
    ///
    /// Returns `Some(bundle)` when callers need to upload a new bundle, or `None` when no rotation
    /// was needed.
    ///
    /// # Errors
    /// - [`KeyStoreError::SignedPreKey`] (`Clock`) if the system clock is before the Unix epoch.
    /// - [`KeyStoreError::SignedPreKey`] (`Identity`) when loading the identity fails.
    /// - [`KeyStoreError::SignedPreKey`] (`InvalidData`) if the stored signed-pre-key blob is
    ///   malformed.
    /// - [`KeyStoreError::SignedPreKey`] (`LockPoisoned` | `Storage`) on storage failures.
    pub fn rotate_signed_prekey_if_stale(
        &self,
    ) -> Result<Option<SignedPreKeyBundle>, KeyStoreError> {
        Ok(self
            .0
            .signed_prekey
            .rotate_if_stale(&mut OsRng)?
            .map(|signed_prekey| signed_prekey.bundle()))
    }

    /// Forces an immediate signed-pre-key rotation and returns the new bundle.
    ///
    /// Use this for explicit key-reset operations that must publish a fresh signed pre-key even
    /// when the stored bundle is still fresh.
    ///
    /// # Errors
    /// - [`KeyStoreError::SignedPreKey`] (`Clock`) if the system clock is before the Unix epoch.
    /// - [`KeyStoreError::SignedPreKey`] (`Identity`) when loading the identity fails.
    /// - [`KeyStoreError::SignedPreKey`] (`LockPoisoned` | `Storage`) on storage failures.
    pub fn rotate_signed_prekey_now(&self) -> Result<SignedPreKeyBundle, KeyStoreError> {
        Ok(self.0.signed_prekey.rotate_now(&mut OsRng)?.bundle())
    }

    /// Restores an identity from an encrypted backup.
    ///
    /// Replaces any current identity, clears the previous signed pre-key and discovery key, and
    /// mints a fresh discovery key (epoch 0) under the restored identity. The discovery key is not
    /// part of the backup, so a restored device starts a new discovery epoch.
    ///
    /// Decryption and validation happen before storage mutation, so wrong passphrases, tampered
    /// blobs, and wrong-length blobs leave the current state unchanged.
    ///
    /// Storage failures after writes begin may leave identity keys from different identities, or an
    /// identity without a discovery key. That state is invalid until cleared by [`Self::reset`] or
    /// repaired by [`Self::rotate_discovery_key_now`].
    ///
    /// # Errors
    /// - [`KeyStoreError::Identity`] (`BackupFailed`) on Argon2id parameter or derivation failure.
    /// - [`KeyStoreError::Identity`] (`DecryptionFailed`) on wrong passphrase or tampered blob.
    /// - [`KeyStoreError::Identity`] (`InvalidData`) on wrong blob length.
    /// - [`KeyStoreError::Identity`] (`LockPoisoned` | `Storage`) on storage failure while
    ///   committing the new identity.
    /// - [`KeyStoreError::Discovery`] (`Clock` | `LockPoisoned` | `Storage`) on discovery-key reset
    ///   or generation failure.
    /// - [`KeyStoreError::SignedPreKey`] (`LockPoisoned` | `Storage`) on signed-pre-key delete
    ///   failure.
    pub fn import_encrypted_backup(
        &self,
        data: &[u8],
        passphrase: &str,
    ) -> Result<(), KeyStoreError> {
        let plaintext = self.0.identity.decrypt_backup(data, passphrase)?;
        self.0.signed_prekey.reset()?;
        self.0.discovery.reset()?;
        self.0.identity.store_decrypted_identity(&plaintext)?;
        self.0.discovery.rotate_now(&mut OsRng)?;
        Ok(())
    }

    /// Clears the stored signed pre-key, discovery key, and identity.
    ///
    /// Deletion runs dependents-first (signed pre-key, then discovery key, then identity), so a
    /// partial failure never leaves a key attached to material that is already gone.
    ///
    /// # Errors
    /// - [`KeyStoreError::Identity`] (`LockPoisoned` | `Storage`) on identity delete failure.
    /// - [`KeyStoreError::Discovery`] (`LockPoisoned` | `Storage`) on discovery-key delete failure.
    /// - [`KeyStoreError::SignedPreKey`] (`LockPoisoned` | `Storage`) on signed-pre-key delete
    ///   failure.
    pub fn reset(&self) -> Result<(), KeyStoreError> {
        self.0.signed_prekey.reset()?;
        self.0.discovery.reset()?;
        self.0.identity.reset()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{InMemorySecureStorage, StorageError};
    use aether_crypto::{verify_bundle, verify_discovery_key_bundle};
    use std::sync::atomic::{AtomicBool, Ordering};
    use zeroize::Zeroizing;

    // Storage keys are duplicated from the manager modules so tests can inspect and tamper.
    const DISCOVERY_KEY_STORAGE_KEY: &str = "discovery/current";
    const SIGNED_PREKEY_STORAGE_KEY: &str = "prekey/signed";

    fn store() -> KeyStore {
        KeyStore::new(Box::new(InMemorySecureStorage::new()))
    }

    // An in-memory store whose contents the test can inspect and mutate after handing a clone to a
    // `KeyStore`.
    #[derive(Clone)]
    struct SharedMemoryStorage(Arc<Mutex<InMemorySecureStorage>>);

    impl SharedMemoryStorage {
        fn new() -> Self {
            SharedMemoryStorage(Arc::new(Mutex::new(InMemorySecureStorage::new())))
        }

        fn load_blob(&self, key: &str) -> Vec<u8> {
            self.0.lock().unwrap().load(key).unwrap().unwrap().to_vec()
        }

        fn put(&self, key: &str, value: &[u8]) {
            self.0.lock().unwrap().store(key, value).unwrap();
        }

        fn remove(&self, key: &str) {
            self.0.lock().unwrap().delete(key).unwrap();
        }
    }

    impl SecureStorage for SharedMemoryStorage {
        fn store(&mut self, key: &str, value: &[u8]) -> Result<(), StorageError> {
            self.0.lock().unwrap().store(key, value)
        }
        fn load(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, StorageError> {
            self.0.lock().unwrap().load(key)
        }
        fn delete(&mut self, key: &str) -> Result<(), StorageError> {
            self.0.lock().unwrap().delete(key)
        }
    }

    // Returns a `KeyStore` and a shared handle to its backing storage for inspection and tampering.
    fn shared_store() -> (KeyStore, SharedMemoryStorage) {
        let storage = SharedMemoryStorage::new();
        (KeyStore::new(Box::new(storage.clone())), storage)
    }

    // An in-memory store that fails `store` for one key once armed, to exercise partial-failure paths.
    struct FailingStorage {
        inner: Arc<Mutex<InMemorySecureStorage>>,
        fail_key: String,
        armed: Arc<AtomicBool>,
    }

    impl SecureStorage for FailingStorage {
        fn store(&mut self, key: &str, value: &[u8]) -> Result<(), StorageError> {
            if self.armed.load(Ordering::SeqCst) && key == self.fail_key {
                return Err(StorageError::IO("injected store failure".into()));
            }
            self.inner.lock().unwrap().store(key, value)
        }
        fn load(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, StorageError> {
            self.inner.lock().unwrap().load(key)
        }
        fn delete(&mut self, key: &str) -> Result<(), StorageError> {
            self.inner.lock().unwrap().delete(key)
        }
    }

    #[test]
    fn key_store_clone_shares_storage() {
        let original_store = store();
        let cloned_store = original_store.clone();
        original_store.generate_identity().unwrap();
        assert!(cloned_store.load_identity().is_ok());
    }

    #[test]
    fn sub_manager_writes_do_not_collide() {
        let key_store = store();
        key_store.generate_identity().unwrap();
        key_store.rotate_signed_prekey_if_stale().unwrap();
        assert!(key_store.load_identity().is_ok());
        assert!(key_store.current_signed_prekey_bundle().is_ok());
    }

    #[test]
    fn import_with_wrong_passphrase_does_not_disturb_existing_state() {
        let destination_store = store();
        destination_store.generate_identity().unwrap();
        destination_store.rotate_signed_prekey_if_stale().unwrap();
        let original_identity = destination_store.load_identity().unwrap();
        let original_signed_prekey = destination_store
            .current_signed_prekey_bundle()
            .unwrap()
            .public_key;

        let source_store = store();
        source_store.generate_identity().unwrap();
        let backup = source_store.export_encrypted_backup("right").unwrap();
        assert!(
            destination_store
                .import_encrypted_backup(&backup, "wrong")
                .is_err()
        );

        let current_identity = destination_store.load_identity().unwrap();
        let current_signed_prekey = destination_store
            .current_signed_prekey_bundle()
            .unwrap()
            .public_key;
        assert_eq!(
            original_identity.public_key(),
            current_identity.public_key()
        );
        assert_eq!(
            original_signed_prekey.as_bytes(),
            current_signed_prekey.as_bytes()
        );
    }

    #[test]
    fn import_encrypted_backup_clears_stale_signed_prekey() {
        let destination_store = store();
        destination_store.generate_identity().unwrap();
        destination_store.rotate_signed_prekey_if_stale().unwrap();

        let source_store = store();
        source_store.generate_identity().unwrap();
        let backup = source_store.export_encrypted_backup("pass").unwrap();

        // Import clears the stale signed pre-key from the previous identity.
        destination_store
            .import_encrypted_backup(&backup, "pass")
            .unwrap();
        assert!(matches!(
            destination_store.current_signed_prekey_bundle(),
            Err(KeyStoreError::SignedPreKey(SignedPreKeyError::NotFound))
        ));

        let imported_identity = destination_store.load_identity().unwrap();
        let source_identity = source_store.load_identity().unwrap();
        assert_eq!(
            imported_identity.verifying_key().as_bytes(),
            source_identity.verifying_key().as_bytes()
        );
    }

    #[test]
    fn import_then_rotate_yields_signed_prekey_signed_by_imported_discovery_key() {
        let destination_store = store();
        destination_store.generate_identity().unwrap();
        destination_store.rotate_signed_prekey_if_stale().unwrap();

        let source_store = store();
        source_store.generate_identity().unwrap();
        let backup = source_store.export_encrypted_backup("pass").unwrap();
        destination_store
            .import_encrypted_backup(&backup, "pass")
            .unwrap();
        destination_store.rotate_signed_prekey_if_stale().unwrap();

        let rotated_bundle = destination_store.current_signed_prekey_bundle().unwrap();
        let imported_identity = destination_store.load_identity().unwrap();
        let discovery_bundle = destination_store.current_discovery_key_bundle().unwrap();
        // The fresh discovery key verifies under the imported identity, and the signed pre-key
        // verifies under that discovery key.
        assert!(
            verify_discovery_key_bundle(&discovery_bundle, imported_identity.verifying_key())
                .is_ok()
        );
        assert!(verify_bundle(&rotated_bundle, &discovery_bundle.verifying_key).is_ok());
    }

    #[test]
    fn reset_clears_identity_and_signed_prekey() {
        let key_store = store();
        key_store.generate_identity().unwrap();
        key_store.rotate_signed_prekey_if_stale().unwrap();
        key_store.reset().unwrap();
        assert!(matches!(
            key_store.load_identity(),
            Err(KeyStoreError::Identity(IdentityError::NotFound))
        ));
        assert!(matches!(
            key_store.current_signed_prekey_bundle(),
            Err(KeyStoreError::SignedPreKey(SignedPreKeyError::NotFound))
        ));
    }

    #[test]
    fn reset_returns_store_to_first_launch_state() {
        let key_store = store();
        key_store.generate_identity().unwrap();
        key_store.rotate_signed_prekey_if_stale().unwrap();
        key_store.reset().unwrap();
        key_store.generate_identity().unwrap();
        key_store.rotate_signed_prekey_if_stale().unwrap();
        assert!(key_store.current_signed_prekey_bundle().is_ok());
    }

    #[test]
    fn reset_on_empty_store_succeeds() {
        let key_store = store();
        key_store.reset().unwrap();
        key_store.reset().unwrap();
    }

    #[test]
    fn generate_identity_persists_discovery_key_at_epoch_zero() {
        let key_store = store();
        let identity = key_store.generate_identity().unwrap();
        let bundle = key_store.current_discovery_key_bundle().unwrap();
        assert_eq!(bundle.epoch, 0);
        assert!(verify_discovery_key_bundle(&bundle, identity.verifying_key()).is_ok());
    }

    #[test]
    fn generate_identity_twice_returns_already_exists() {
        let key_store = store();
        key_store.generate_identity().unwrap();
        assert!(matches!(
            key_store.generate_identity(),
            Err(KeyStoreError::Identity(IdentityError::AlreadyExists))
        ));
    }

    #[test]
    fn load_identity_succeeds_without_discovery_key() {
        let (key_store, storage) = shared_store();
        key_store.generate_identity().unwrap();
        // Drop the discovery key directly; the identity must still load (IK-only load).
        storage.remove(DISCOVERY_KEY_STORAGE_KEY);
        assert!(key_store.load_identity().is_ok());
        assert!(matches!(
            key_store.current_discovery_key_bundle(),
            Err(KeyStoreError::Discovery(DiscoveryKeyError::NotFound))
        ));
    }

    #[test]
    fn current_discovery_key_bundle_rejects_tampered_signature() {
        let (key_store, storage) = shared_store();
        key_store.generate_identity().unwrap();
        let mut blob = storage.load_blob(DISCOVERY_KEY_STORAGE_KEY);
        blob[69] ^= 0x01; // flip a byte in the identity-signature region
        storage.put(DISCOVERY_KEY_STORAGE_KEY, &blob);
        assert!(matches!(
            key_store.current_discovery_key_bundle(),
            Err(KeyStoreError::Discovery(DiscoveryKeyError::Corrupt))
        ));
    }

    #[test]
    fn generate_identity_completes_partial_discovery_key() {
        let (key_store, storage) = shared_store();
        key_store.generate_identity().unwrap();
        // Simulate a partial first launch: identity stored, discovery key never written.
        storage.remove(DISCOVERY_KEY_STORAGE_KEY);
        // A retry completes the discovery key rather than erroring with AlreadyExists.
        key_store.generate_identity().unwrap();
        assert!(key_store.current_discovery_key_bundle().is_ok());
    }

    #[test]
    fn generate_identity_rejects_malformed_discovery_key() {
        let (key_store, storage) = shared_store();
        key_store.generate_identity().unwrap();
        storage.put(DISCOVERY_KEY_STORAGE_KEY, &[0xAAu8; 50]);
        assert!(matches!(
            key_store.generate_identity(),
            Err(KeyStoreError::Discovery(DiscoveryKeyError::InvalidData(_)))
        ));
    }

    #[test]
    fn rotate_discovery_key_now_advances_epoch_and_refreshes_prekey() {
        let key_store = store();
        let identity = key_store.generate_identity().unwrap();
        let first_dk = key_store.current_discovery_key_bundle().unwrap();
        assert_eq!(first_dk.epoch, 0);

        let rotation = key_store.rotate_discovery_key_now().unwrap();
        assert_eq!(rotation.discovery_key.epoch, 1);
        assert_ne!(
            rotation.discovery_key.public_key.as_bytes(),
            first_dk.public_key.as_bytes()
        );
        // Identity keys stay stable across discovery-key rotation.
        assert_eq!(
            key_store
                .load_identity()
                .unwrap()
                .verifying_key()
                .as_bytes(),
            identity.verifying_key().as_bytes()
        );
        // The returned bundles verify as a chain: identity -> discovery key -> signed pre-key.
        assert!(
            verify_discovery_key_bundle(&rotation.discovery_key, identity.verifying_key()).is_ok()
        );
        assert!(
            verify_bundle(
                &rotation.signed_prekey,
                &rotation.discovery_key.verifying_key
            )
            .is_ok()
        );
    }

    #[test]
    fn repeated_rotations_match_persisted_state() {
        let key_store = store();
        key_store.generate_identity().unwrap();
        key_store.rotate_discovery_key_now().unwrap();
        let rotation = key_store.rotate_discovery_key_now().unwrap();
        assert_eq!(rotation.discovery_key.epoch, 2);

        let persisted_dk = key_store.current_discovery_key_bundle().unwrap();
        let persisted_spk = key_store.current_signed_prekey_bundle().unwrap();
        assert_eq!(
            persisted_dk.public_key.as_bytes(),
            rotation.discovery_key.public_key.as_bytes()
        );
        assert_eq!(persisted_dk.epoch, rotation.discovery_key.epoch);
        assert_eq!(
            persisted_spk.public_key.as_bytes(),
            rotation.signed_prekey.public_key.as_bytes()
        );
    }

    #[test]
    fn rotate_discovery_key_now_failure_leaves_no_mismatched_prekey() {
        let inner = Arc::new(Mutex::new(InMemorySecureStorage::new()));
        let armed = Arc::new(AtomicBool::new(false));
        let storage = FailingStorage {
            inner: Arc::clone(&inner),
            fail_key: SIGNED_PREKEY_STORAGE_KEY.to_string(),
            armed: Arc::clone(&armed),
        };
        let key_store = KeyStore::new(Box::new(storage));
        key_store.generate_identity().unwrap();
        assert!(key_store.rotate_signed_prekey_if_stale().unwrap().is_some());

        // Arm the failure: storing the new signed pre-key fails midway through rotation.
        armed.store(true, Ordering::SeqCst);
        assert!(key_store.rotate_discovery_key_now().is_err());
        armed.store(false, Ordering::SeqCst);

        // The discovery key advanced to epoch 1, and the stale epoch-0 pre-key was cleared rather
        // than left paired with the new discovery key: no mismatched pair is observable.
        assert_eq!(key_store.current_discovery_key_bundle().unwrap().epoch, 1);
        assert!(matches!(
            key_store.current_signed_prekey_bundle(),
            Err(KeyStoreError::SignedPreKey(SignedPreKeyError::NotFound))
        ));
    }

    #[test]
    fn reset_clears_discovery_key() {
        let key_store = store();
        key_store.generate_identity().unwrap();
        key_store.reset().unwrap();
        assert!(matches!(
            key_store.current_discovery_key_bundle(),
            Err(KeyStoreError::Discovery(DiscoveryKeyError::NotFound))
        ));
    }

    #[test]
    fn persistence_round_trip_restores_identity_and_discovery_key() {
        let storage = SharedMemoryStorage::new();
        let first = KeyStore::new(Box::new(storage.clone()));
        first.generate_identity().unwrap();
        first.rotate_discovery_key_now().unwrap();
        let dk = first.current_discovery_key_bundle().unwrap();
        let identity = first.load_identity().unwrap();
        drop(first);

        let second = KeyStore::new(Box::new(storage));
        let restored_identity = second.load_identity().unwrap();
        let restored_dk = second.current_discovery_key_bundle().unwrap();
        assert_eq!(
            restored_identity.verifying_key().as_bytes(),
            identity.verifying_key().as_bytes()
        );
        assert_eq!(restored_dk.public_key.as_bytes(), dk.public_key.as_bytes());
        assert_eq!(restored_dk.epoch, dk.epoch);
    }
}
