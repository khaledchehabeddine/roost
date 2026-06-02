use crate::clock::{Clock, SystemClock};
use crate::discovery_key::{DiscoveryKeyError, DiscoveryKeyManager, DiscoveryKeyStatus};
use crate::identity::{Identity, IdentityError, IdentityManager};
use crate::signed_prekey::{SignedPreKeyError, SignedPreKeyManager};
use crate::storage::SecureStorage;
use aether_crypto::{DiscoveryKeyBundle, SignedPreKeyBundle, verify_signed_prekey_bundle};
use rand::rngs::OsRng;
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

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

impl From<DiscoveryKeyError> for KeyStoreError {
    fn from(e: DiscoveryKeyError) -> Self {
        KeyStoreError::Discovery(e)
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

/// A key publication that verifies as identity -> discovery key -> signed pre-key.
///
/// Peers verify [`Self::discovery_key`] with the identity verifying key, then verify
/// [`Self::signed_prekey`] with the discovery key's verifying key.
#[derive(Clone, Debug)]
pub struct PublicationBundle {
    /// The discovery key for this publication.
    pub discovery_key: DiscoveryKeyBundle,
    /// The signed pre-key for this publication.
    pub signed_prekey: SignedPreKeyBundle,
}

struct KeyStoreInner {
    identity: Arc<IdentityManager>,
    discovery: Arc<DiscoveryKeyManager>,
    signed_prekey: Arc<SignedPreKeyManager>,
    // Coordinates operations that update more than one stored key.
    lifecycle: Mutex<()>,
}

/// Facade over identity, discovery-key, and signed-pre-key managers sharing one [`SecureStorage`].
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
            lifecycle: Mutex::new(()),
        }))
    }

    /// Generates a fresh [`Identity`] and discovery key, persisting both.
    ///
    /// If a previous call stored the identity but not the discovery key, this retries the
    /// discovery key creation. A malformed stored discovery key must be cleared with
    /// [`Self::reset`] first.
    ///
    /// # Errors
    /// - [`KeyStoreError::Identity`] (`AlreadyExists`) if a complete identity and discovery key
    ///   exist.
    /// - [`KeyStoreError::Discovery`] (`InvalidData`) if a stored discovery key is malformed.
    /// - [`KeyStoreError::Discovery`] (`Clock`) if the system clock is before the Unix epoch.
    /// - [`KeyStoreError::Discovery`] | [`KeyStoreError::Identity`] (`LockPoisoned` | `Storage`)
    ///   on storage failures.
    pub fn generate_identity(&self) -> Result<Identity, KeyStoreError> {
        let _lifecycle = self.lifecycle_guard();
        let identity = match self.0.identity.generate_identity(&mut OsRng) {
            Ok(identity) => identity,
            // A prior partial creation may have stored the identity but not the discovery key.
            Err(IdentityError::AlreadyExists) => match self.0.discovery.stored_status()? {
                DiscoveryKeyStatus::Absent => self.0.identity.load_identity()?,
                DiscoveryKeyStatus::Present { .. } => {
                    return Err(IdentityError::AlreadyExists.into());
                }
                DiscoveryKeyStatus::Malformed => {
                    return Err(DiscoveryKeyError::InvalidData(
                        "stored discovery key is malformed, must reset before regenerating".into(),
                    )
                    .into());
                }
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

    /// Returns the stored [`SignedPreKeyBundle`] without checking the full publication chain.
    ///
    /// Use [`Self::current_publication_bundle`] when publishing. It returns the matching discovery
    /// key and verifies the pair before returning it.
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
    /// - [`KeyStoreError::Discovery`] (`Corrupt`) if the stored discovery key does not verify
    ///   against the identity key.
    /// - [`KeyStoreError::Discovery`] (`Identity`) if loading the verifying identity fails.
    /// - [`KeyStoreError::Discovery`] (`InvalidData`) if the stored discovery key is malformed.
    /// - [`KeyStoreError::Discovery`] (`LockPoisoned` | `Storage`) on storage failures.
    /// - [`KeyStoreError::Discovery`] (`NotFound`) if no discovery key is stored.
    pub fn current_discovery_key_bundle(&self) -> Result<DiscoveryKeyBundle, KeyStoreError> {
        Ok(self.0.discovery.current_bundle()?)
    }

    /// Returns a publishable key pair.
    ///
    /// Refreshes a missing or stale signed pre-key, then returns a [`PublicationBundle`] whose
    /// keys verify together. Prefer this for identity publication over reading the two bundles
    /// separately.
    ///
    /// # Errors
    /// - [`KeyStoreError::Discovery`] (`Corrupt` | `InvalidData` | `NotFound`) if the discovery
    ///   key is unverifiable, malformed, or absent.
    /// - [`KeyStoreError::Discovery`] | [`KeyStoreError::SignedPreKey`]
    ///   (`LockPoisoned` | `Storage`) on storage failures.
    /// - [`KeyStoreError::SignedPreKey`] (`Clock`) if the system clock is before the Unix epoch.
    /// - [`KeyStoreError::SignedPreKey`] (`Corrupt`) if the stored signed pre-key does not verify
    ///   against the current discovery key.
    /// - [`KeyStoreError::SignedPreKey`] (`Discovery`) if signed-pre-key rotation cannot load or
    ///   verify the discovery key.
    /// - [`KeyStoreError::SignedPreKey`] (`InvalidData`) if the stored signed-pre-key blob is
    ///   malformed.
    pub fn current_publication_bundle(&self) -> Result<PublicationBundle, KeyStoreError> {
        let _lifecycle = self.lifecycle_guard();
        self.0.signed_prekey.rotate_if_stale(&mut OsRng)?;
        let discovery_key = self.0.discovery.current_bundle()?;
        let signed_prekey = self.0.signed_prekey.current_bundle()?;
        // Reject storage rollback/desync before publishing a mismatched pair.
        verify_signed_prekey_bundle(&signed_prekey, &discovery_key.verifying_key)
            .map_err(|_| SignedPreKeyError::Corrupt)?;
        Ok(PublicationBundle {
            discovery_key,
            signed_prekey,
        })
    }

    /// Rotates the discovery key and signed pre-key together.
    ///
    /// Advances the discovery-key epoch and returns a fresh [`PublicationBundle`]. If
    /// signed-pre-key storage fails after the discovery key rotates, the old signed pre-key has
    /// been cleared, so no stale signed pre-key remains publishable with the new discovery key.
    ///
    /// # Errors
    /// - [`KeyStoreError::Discovery`] (`Clock`) if the system clock is before the Unix epoch.
    /// - [`KeyStoreError::Discovery`] (`Identity`) if loading the identity fails.
    /// - [`KeyStoreError::Discovery`] (`InvalidData`) if the stored discovery key is malformed.
    /// - [`KeyStoreError::Discovery`] | [`KeyStoreError::SignedPreKey`]
    ///   (`LockPoisoned` | `Storage`) on storage failures.
    pub fn rotate_discovery_key_now(&self) -> Result<PublicationBundle, KeyStoreError> {
        let _lifecycle = self.lifecycle_guard();
        self.0.signed_prekey.reset()?;
        let discovery_key = self.0.discovery.rotate_now(&mut OsRng)?;
        let signed_prekey = self.0.signed_prekey.rotate_now(&mut OsRng)?;
        Ok(PublicationBundle {
            discovery_key: discovery_key.bundle(),
            signed_prekey: signed_prekey.bundle(),
        })
    }

    /// Rotates the stored signed pre-key when its bundle is stale or missing.
    ///
    /// Returns `Some(bundle)` when callers need to upload a new bundle, or `None` when no rotation
    /// was needed.
    ///
    /// # Errors
    /// - [`KeyStoreError::SignedPreKey`] (`Clock`) if the system clock is before the Unix epoch.
    /// - [`KeyStoreError::SignedPreKey`] (`Discovery`) when loading or verifying the discovery key
    ///   fails.
    /// - [`KeyStoreError::SignedPreKey`] (`InvalidData`) if the stored signed-pre-key blob is
    ///   malformed.
    /// - [`KeyStoreError::SignedPreKey`] (`LockPoisoned` | `Storage`) on storage failures.
    pub fn rotate_signed_prekey_if_stale(
        &self,
    ) -> Result<Option<SignedPreKeyBundle>, KeyStoreError> {
        let _lifecycle = self.lifecycle_guard();
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
    /// - [`KeyStoreError::SignedPreKey`] (`Discovery`) when loading or verifying the discovery key
    ///   fails.
    /// - [`KeyStoreError::SignedPreKey`] (`LockPoisoned` | `Storage`) on storage failures.
    pub fn rotate_signed_prekey_now(&self) -> Result<SignedPreKeyBundle, KeyStoreError> {
        let _lifecycle = self.lifecycle_guard();
        Ok(self.0.signed_prekey.rotate_now(&mut OsRng)?.bundle())
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

    /// Restores an identity from an encrypted backup.
    ///
    /// Validates the backup before changing storage. On success, the restored identity has a fresh
    /// discovery key and no signed pre-key. Callers can create one with
    /// [`Self::rotate_signed_prekey_if_stale`].
    ///
    /// # Errors
    /// - [`KeyStoreError::Discovery`] (`Clock` | `LockPoisoned` | `Storage`) on discovery-key
    ///   reset or generation failure.
    /// - [`KeyStoreError::Identity`] (`BackupFailed`) on Argon2id parameter or derivation failure.
    /// - [`KeyStoreError::Identity`] (`DecryptionFailed`) on wrong passphrase or tampered blob.
    /// - [`KeyStoreError::Identity`] (`InvalidData`) on wrong blob length.
    /// - [`KeyStoreError::Identity`] (`LockPoisoned` | `Storage`) on storage failure while
    ///   committing the new identity.
    /// - [`KeyStoreError::SignedPreKey`] (`LockPoisoned` | `Storage`) on signed-pre-key delete
    ///   failure.
    pub fn import_encrypted_backup(
        &self,
        data: &[u8],
        passphrase: &str,
    ) -> Result<(), KeyStoreError> {
        let _lifecycle = self.lifecycle_guard();
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
    /// - [`KeyStoreError::Discovery`] (`LockPoisoned` | `Storage`) on discovery-key delete
    ///   failure.
    /// - [`KeyStoreError::Identity`] (`LockPoisoned` | `Storage`) on identity delete failure.
    /// - [`KeyStoreError::SignedPreKey`] (`LockPoisoned` | `Storage`) on signed-pre-key delete
    ///   failure.
    pub fn reset(&self) -> Result<(), KeyStoreError> {
        let _lifecycle = self.lifecycle_guard();
        self.0.signed_prekey.reset()?;
        self.0.discovery.reset()?;
        self.0.identity.reset()?;
        Ok(())
    }

    // Keeps multikey updates from interleaving across cloned keystores. The per-storage mutex only
    // protects individual storage calls. This guard protects the keychain invariant.
    fn lifecycle_guard(&self) -> std::sync::MutexGuard<'_, ()> {
        self.0
            .lifecycle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::{InMemorySecureStorage, StorageError};
    use aether_crypto::verify_discovery_key_bundle;
    use std::sync::atomic::{AtomicBool, Ordering};
    use zeroize::Zeroizing;

    // Storage keys are duplicated from the manager modules so tests can inspect and tamper.
    const DISCOVERY_KEY: &str = "discovery/current";
    const SIGNED_PREKEY: &str = "prekey/signed";

    type SharedStorage = Arc<Mutex<Box<dyn SecureStorage>>>;

    fn store() -> KeyStore {
        KeyStore::new(Box::new(InMemorySecureStorage::new()))
    }

    fn store_with_storage() -> (KeyStore, SharedStorage) {
        let storage: SharedStorage = Arc::new(Mutex::new(Box::new(InMemorySecureStorage::new())));
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let identity = Arc::new(IdentityManager::new(Arc::clone(&storage)));
        let discovery = Arc::new(DiscoveryKeyManager::new(
            Arc::clone(&storage),
            Arc::clone(&identity),
            Arc::clone(&clock),
        ));
        let signed_prekey = Arc::new(SignedPreKeyManager::new(
            Arc::clone(&storage),
            Arc::clone(&discovery),
            clock,
        ));
        let key_store = KeyStore(Arc::new(KeyStoreInner {
            identity,
            discovery,
            signed_prekey,
            lifecycle: Mutex::new(()),
        }));
        (key_store, storage)
    }

    #[test]
    fn key_store_clone_shares_storage() {
        let original_store = store();
        let cloned_store = original_store.clone();
        original_store.generate_identity().unwrap();
        assert!(cloned_store.load_identity().is_ok());
    }

    #[test]
    fn generate_identity_persists_discovery_key_at_epoch_zero() {
        let key_store = store();
        key_store.generate_identity().unwrap();
        let bundle = key_store.current_discovery_key_bundle().unwrap();
        assert_eq!(bundle.epoch, 0);
    }

    #[test]
    fn generate_identity_completes_partial_discovery_key() {
        let (key_store, storage) = store_with_storage();
        key_store.generate_identity().unwrap();
        storage.lock().unwrap().delete(DISCOVERY_KEY).unwrap();
        key_store.generate_identity().unwrap();
        assert!(key_store.current_discovery_key_bundle().is_ok());
    }

    #[test]
    fn generate_identity_rejects_malformed_discovery_key() {
        let (key_store, storage) = store_with_storage();
        key_store.generate_identity().unwrap();
        storage
            .lock()
            .unwrap()
            .store(DISCOVERY_KEY, &[0xAAu8; 50])
            .unwrap();
        assert!(matches!(
            key_store.generate_identity(),
            Err(KeyStoreError::Discovery(DiscoveryKeyError::InvalidData(_)))
        ));
    }

    #[test]
    fn load_identity_succeeds_without_discovery_key() {
        let (key_store, storage) = store_with_storage();
        key_store.generate_identity().unwrap();
        storage.lock().unwrap().delete(DISCOVERY_KEY).unwrap();
        assert!(key_store.load_identity().is_ok());
    }

    #[test]
    fn current_publication_bundle_returns_verifiable_chain() {
        let key_store = store();
        let identity = key_store.generate_identity().unwrap();
        let publication = key_store.current_publication_bundle().unwrap();
        assert!(
            verify_discovery_key_bundle(&publication.discovery_key, identity.verifying_key())
                .is_ok()
        );
        assert!(
            verify_signed_prekey_bundle(
                &publication.signed_prekey,
                &publication.discovery_key.verifying_key
            )
            .is_ok()
        );
    }

    #[test]
    fn current_publication_bundle_rejects_prekey_signed_by_superseded_discovery_key() {
        let (key_store, storage) = store_with_storage();
        key_store.generate_identity().unwrap();
        key_store.current_publication_bundle().unwrap();
        let stale_prekey = storage
            .lock()
            .unwrap()
            .load(SIGNED_PREKEY)
            .unwrap()
            .unwrap()
            .to_vec();
        key_store.rotate_discovery_key_now().unwrap();
        storage
            .lock()
            .unwrap()
            .store(SIGNED_PREKEY, &stale_prekey)
            .unwrap();
        assert!(matches!(
            key_store.current_publication_bundle(),
            Err(KeyStoreError::SignedPreKey(SignedPreKeyError::Corrupt))
        ));
    }

    #[test]
    fn rotate_discovery_key_now_advances_epoch_and_refreshes_prekey() {
        let key_store = store();
        key_store.generate_identity().unwrap();
        let first_dk = key_store.current_discovery_key_bundle().unwrap();
        assert_eq!(first_dk.epoch, 0);

        let rotation = key_store.rotate_discovery_key_now().unwrap();
        assert_eq!(rotation.discovery_key.epoch, 1);
        assert_ne!(
            rotation.discovery_key.public_key.as_bytes(),
            first_dk.public_key.as_bytes()
        );
        assert!(
            verify_signed_prekey_bundle(
                &rotation.signed_prekey,
                &rotation.discovery_key.verifying_key
            )
            .is_ok()
        );
    }

    #[test]
    fn rotate_discovery_key_now_failure_leaves_no_mismatched_prekey() {
        struct FailingSignedPreKeyStorage {
            inner: InMemorySecureStorage,
            should_fail: Arc<AtomicBool>,
        }

        impl SecureStorage for FailingSignedPreKeyStorage {
            fn store(&mut self, key: &str, value: &[u8]) -> Result<(), StorageError> {
                if self.should_fail.load(Ordering::SeqCst) && key == SIGNED_PREKEY {
                    return Err(StorageError::IO("injected store failure".into()));
                }
                self.inner.store(key, value)
            }

            fn load(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, StorageError> {
                self.inner.load(key)
            }

            fn delete(&mut self, key: &str) -> Result<(), StorageError> {
                self.inner.delete(key)
            }
        }

        let should_fail = Arc::new(AtomicBool::new(false));
        let storage = FailingSignedPreKeyStorage {
            inner: InMemorySecureStorage::new(),
            should_fail: Arc::clone(&should_fail),
        };
        let key_store = KeyStore::new(Box::new(storage));
        key_store.generate_identity().unwrap();
        assert!(key_store.rotate_signed_prekey_if_stale().unwrap().is_some());

        should_fail.store(true, Ordering::SeqCst);
        assert!(key_store.rotate_discovery_key_now().is_err());
        should_fail.store(false, Ordering::SeqCst);

        assert_eq!(key_store.current_discovery_key_bundle().unwrap().epoch, 1);
        assert!(matches!(
            key_store.current_signed_prekey_bundle(),
            Err(KeyStoreError::SignedPreKey(SignedPreKeyError::NotFound))
        ));
    }

    #[test]
    fn concurrent_rotations_keep_discovery_key_and_signed_prekey_consistent() {
        let key_store = store();
        key_store.generate_identity().unwrap();
        key_store.rotate_signed_prekey_if_stale().unwrap();

        let rotate_discovery = key_store.clone();
        let rotate_prekey = key_store.clone();
        let discovery_thread = std::thread::spawn(move || {
            for _ in 0..8 {
                rotate_discovery.rotate_discovery_key_now().unwrap();
            }
        });
        let prekey_thread = std::thread::spawn(move || {
            for _ in 0..8 {
                rotate_prekey.rotate_signed_prekey_now().unwrap();
            }
        });
        discovery_thread.join().unwrap();
        prekey_thread.join().unwrap();

        let discovery = key_store.current_discovery_key_bundle().unwrap();
        let prekey = key_store.current_signed_prekey_bundle().unwrap();
        assert!(verify_signed_prekey_bundle(&prekey, &discovery.verifying_key).is_ok());
    }

    #[test]
    fn concurrent_publication_and_rotation_stays_consistent() {
        let key_store = store();
        key_store.generate_identity().unwrap();

        let publisher = key_store.clone();
        let rotator = key_store.clone();
        let rotate_thread = std::thread::spawn(move || {
            for _ in 0..8 {
                rotator.rotate_discovery_key_now().unwrap();
            }
        });
        for _ in 0..8 {
            let publication = publisher.current_publication_bundle().unwrap();
            assert!(
                verify_signed_prekey_bundle(
                    &publication.signed_prekey,
                    &publication.discovery_key.verifying_key
                )
                .is_ok()
            );
        }
        rotate_thread.join().unwrap();
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

        destination_store
            .import_encrypted_backup(&backup, "pass")
            .unwrap();
        assert!(matches!(
            destination_store.current_signed_prekey_bundle(),
            Err(KeyStoreError::SignedPreKey(SignedPreKeyError::NotFound))
        ));
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
        assert!(
            verify_discovery_key_bundle(&discovery_bundle, imported_identity.verifying_key())
                .is_ok()
        );
        assert!(
            verify_signed_prekey_bundle(&rotated_bundle, &discovery_bundle.verifying_key).is_ok()
        );
    }

    #[test]
    fn reset_clears_identity_discovery_key_and_signed_prekey() {
        let key_store = store();
        key_store.generate_identity().unwrap();
        key_store.rotate_signed_prekey_if_stale().unwrap();
        key_store.reset().unwrap();
        assert!(matches!(
            key_store.load_identity(),
            Err(KeyStoreError::Identity(IdentityError::NotFound))
        ));
        assert!(matches!(
            key_store.current_discovery_key_bundle(),
            Err(KeyStoreError::Discovery(DiscoveryKeyError::NotFound))
        ));
        assert!(matches!(
            key_store.current_signed_prekey_bundle(),
            Err(KeyStoreError::SignedPreKey(SignedPreKeyError::NotFound))
        ));
    }

    #[test]
    fn reset_on_empty_store_succeeds() {
        let key_store = store();
        key_store.reset().unwrap();
        key_store.reset().unwrap();
    }
}
