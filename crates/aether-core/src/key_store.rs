use crate::clock::{Clock, SystemClock};
use crate::discovery_key::{DiscoveryKeyError, DiscoveryKeyManager, DiscoveryKeyStatus};
use crate::identity::{Identity, IdentityError, IdentityManager};
use crate::one_time_prekey::{OneTimePreKeyError, OneTimePreKeyManager};
use crate::signed_prekey::{SignedPreKeyError, SignedPreKeyManager};
use crate::storage::SecureStorage;
use aether_crypto::{
    DiscoveryKeyBundle, OneTimePreKey, OneTimePreKeyBundle, PREKEY_BUNDLE_VERSION,
    SignedPreKeyBundle, verify_signed_prekey_bundle,
};
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
    /// A one-time-pre-key operation failed.
    OneTimePreKey(OneTimePreKeyError),
    /// A signed-pre-key operation failed.
    SignedPreKey(SignedPreKeyError),
}

impl fmt::Display for KeyStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyStoreError::Discovery(e) => write!(f, "discovery key: {e}"),
            KeyStoreError::Identity(e) => write!(f, "identity: {e}"),
            KeyStoreError::OneTimePreKey(e) => write!(f, "one-time pre-key: {e}"),
            KeyStoreError::SignedPreKey(e) => write!(f, "signed pre-key: {e}"),
        }
    }
}

impl Error for KeyStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            KeyStoreError::Discovery(e) => Some(e),
            KeyStoreError::Identity(e) => Some(e),
            KeyStoreError::OneTimePreKey(e) => Some(e),
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

impl From<OneTimePreKeyError> for KeyStoreError {
    fn from(e: OneTimePreKeyError) -> Self {
        KeyStoreError::OneTimePreKey(e)
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
    /// Version of the public pre-key bundle format.
    pub version: u8,
    /// The discovery key for this publication.
    pub discovery_key: DiscoveryKeyBundle,
    /// The signed pre-key for this publication.
    pub signed_prekey: SignedPreKeyBundle,
}

struct KeyStoreInner {
    identity: Arc<IdentityManager>,
    discovery: Arc<DiscoveryKeyManager>,
    one_time_prekey: Arc<OneTimePreKeyManager>,
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
        let one_time_prekey = Arc::new(OneTimePreKeyManager::new(
            Arc::clone(&storage),
            Arc::clone(&discovery),
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
            one_time_prekey,
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
    /// Returns a [`PublicationBundle`] whose caller-created keys verify together. Prefer this for
    /// identity publication over reading the two bundles separately. One-time pre-key bundles are
    /// managed by [`Self::generate_one_time_prekeys`] and [`Self::replenish_one_time_prekeys`].
    ///
    /// # Errors
    /// - [`KeyStoreError::Discovery`] (`Corrupt` | `InvalidData` | `NotFound`) if the discovery
    ///   key is unverifiable, malformed, or absent.
    /// - [`KeyStoreError::Discovery`] | [`KeyStoreError::SignedPreKey`]
    ///   (`LockPoisoned` | `Storage`) on storage failures.
    /// - [`KeyStoreError::SignedPreKey`] (`Clock`) if the system clock is before the Unix epoch.
    /// - [`KeyStoreError::SignedPreKey`] (`Corrupt`) if the stored signed pre-key does not verify
    ///   against the current discovery key.
    /// - [`KeyStoreError::SignedPreKey`] (`InvalidData`) if the stored signed-pre-key blob is
    ///   malformed.
    /// - [`KeyStoreError::SignedPreKey`] (`NotFound`) if no signed pre-key has been created.
    pub fn current_publication_bundle(&self) -> Result<PublicationBundle, KeyStoreError> {
        let _lifecycle = self.lifecycle_guard();
        let discovery_key = self.0.discovery.current_bundle()?;
        let signed_prekey = self.0.signed_prekey.current_bundle()?;
        // Reject storage rollback/desync before publishing a mismatched pair.
        verify_signed_prekey_bundle(&signed_prekey, &discovery_key.verifying_key)
            .map_err(|_| SignedPreKeyError::Corrupt)?;
        Ok(PublicationBundle {
            version: PREKEY_BUNDLE_VERSION,
            discovery_key,
            signed_prekey,
        })
    }

    /// Generates exactly `batch_size` one-time pre-keys for the current discovery-key epoch.
    ///
    /// The new secrets are persisted in the existing one-time-pre-key pool and no discovery-key
    /// rotation is required. The call fails if the requested batch would exceed the pool cap.
    ///
    /// # Errors
    /// - [`KeyStoreError::OneTimePreKey`] (`Clock`) if the system clock is before the Unix epoch.
    /// - [`KeyStoreError::OneTimePreKey`] (`Discovery`) if the discovery key is malformed,
    ///   unverifiable, or absent.
    /// - [`KeyStoreError::OneTimePreKey`] (`InvalidData`) if the stored one-time-pre-key pool is
    ///   malformed or the requested batch exceeds capacity.
    /// - [`KeyStoreError::OneTimePreKey`] (`LockPoisoned` | `Storage`) on storage failures.
    pub fn generate_one_time_prekeys(
        &self,
        batch_size: usize,
    ) -> Result<Vec<OneTimePreKeyBundle>, KeyStoreError> {
        let _lifecycle = self.lifecycle_guard();
        Ok(self
            .0
            .one_time_prekey
            .generate_batch(&mut OsRng, batch_size)?)
    }

    /// Replenishes the stored one-time pre-key pool.
    ///
    /// Returns the bundles created by this call. A missing or stale pool is rebuilt for the
    /// current discovery-key epoch; a current pool above the replenish threshold is left unchanged
    /// and returns an empty list.
    ///
    /// # Errors
    /// - [`KeyStoreError::OneTimePreKey`] (`Clock`) if the system clock is before the Unix epoch.
    /// - [`KeyStoreError::OneTimePreKey`] (`Discovery`) if the discovery key is malformed,
    ///   unverifiable, or absent.
    /// - [`KeyStoreError::OneTimePreKey`] (`InvalidData`) if the stored one-time-pre-key pool is
    ///   malformed.
    /// - [`KeyStoreError::OneTimePreKey`] (`LockPoisoned` | `Storage`) on storage failures.
    pub fn replenish_one_time_prekeys(&self) -> Result<Vec<OneTimePreKeyBundle>, KeyStoreError> {
        let _lifecycle = self.lifecycle_guard();
        Ok(self.0.one_time_prekey.replenish(&mut OsRng)?)
    }

    #[allow(dead_code)]
    pub(crate) fn consume_one_time_prekey(
        &self,
        epoch: u32,
        id: u64,
    ) -> Result<OneTimePreKey, KeyStoreError> {
        let _lifecycle = self.lifecycle_guard();
        Ok(self.0.one_time_prekey.consume_one_time_prekey(epoch, id)?)
    }

    /// Rotates the discovery key and signed pre-key together.
    ///
    /// Advances the discovery-key epoch, clears epoch-bound one-time pre-keys, and returns a fresh
    /// [`PublicationBundle`]. If signed-pre-key storage fails after the discovery key rotates, the
    /// old signed pre-key has been cleared, so no stale signed pre-key remains publishable with
    /// the new discovery key.
    ///
    /// # Errors
    /// - [`KeyStoreError::Discovery`] (`Clock`) if the system clock is before the Unix epoch.
    /// - [`KeyStoreError::Discovery`] (`Identity`) if loading the identity fails.
    /// - [`KeyStoreError::Discovery`] (`InvalidData`) if the stored discovery key is malformed.
    /// - [`KeyStoreError::Discovery`] | [`KeyStoreError::OneTimePreKey`] |
    ///   [`KeyStoreError::SignedPreKey`] (`LockPoisoned` | `Storage`) on storage failures.
    pub fn rotate_discovery_key_now(&self) -> Result<PublicationBundle, KeyStoreError> {
        let _lifecycle = self.lifecycle_guard();
        self.0.one_time_prekey.reset()?;
        self.0.signed_prekey.reset()?;
        let discovery_key = self.0.discovery.rotate_now(&mut OsRng)?;
        let signed_prekey = self.0.signed_prekey.rotate_now(&mut OsRng)?;
        Ok(PublicationBundle {
            version: PREKEY_BUNDLE_VERSION,
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
    /// discovery key and no one-time pre-keys or signed pre-key. Callers can create a signed
    /// pre-key with
    /// [`Self::rotate_signed_prekey_if_stale`].
    ///
    /// # Errors
    /// - [`KeyStoreError::Discovery`] (`Clock` | `LockPoisoned` | `Storage`) on discovery-key
    ///   reset or generation failure.
    /// - [`KeyStoreError::Identity`] (`LockPoisoned` | `Storage`) on identity delete failure while
    ///   clearing old identity material before commit.
    /// - [`KeyStoreError::Identity`] (`BackupFailed`) on Argon2id parameter or derivation failure.
    /// - [`KeyStoreError::Identity`] (`DecryptionFailed`) on wrong passphrase or tampered blob.
    /// - [`KeyStoreError::Identity`] (`InvalidData`) on wrong blob length.
    /// - [`KeyStoreError::Identity`] (`LockPoisoned` | `Storage`) on storage failure while
    ///   committing the new identity.
    /// - [`KeyStoreError::OneTimePreKey`] (`LockPoisoned` | `Storage`) on one-time-pre-key delete
    ///   failure.
    /// - [`KeyStoreError::SignedPreKey`] (`LockPoisoned` | `Storage`) on signed-pre-key delete
    ///   failure.
    pub fn import_encrypted_backup(
        &self,
        data: &[u8],
        passphrase: &str,
    ) -> Result<(), KeyStoreError> {
        let _lifecycle = self.lifecycle_guard();
        let plaintext = self.0.identity.decrypt_backup(data, passphrase)?;
        self.0.one_time_prekey.reset()?;
        self.0.signed_prekey.reset()?;
        self.0.discovery.reset()?;
        self.0.identity.reset()?;
        self.0.identity.store_decrypted_identity(&plaintext)?;
        self.0.discovery.rotate_now(&mut OsRng)?;
        Ok(())
    }

    /// Clears the stored one-time pre-keys, signed pre-key, discovery key, and identity.
    ///
    /// Deletion runs dependents-first (pre-keys, then discovery key, then identity), so a partial
    /// failure never leaves a key attached to material that is already gone.
    ///
    /// # Errors
    /// - [`KeyStoreError::Discovery`] (`LockPoisoned` | `Storage`) on discovery-key delete
    ///   failure.
    /// - [`KeyStoreError::Identity`] (`LockPoisoned` | `Storage`) on identity delete failure.
    /// - [`KeyStoreError::OneTimePreKey`] (`LockPoisoned` | `Storage`) on one-time-pre-key delete
    ///   failure.
    /// - [`KeyStoreError::SignedPreKey`] (`LockPoisoned` | `Storage`) on signed-pre-key delete
    ///   failure.
    pub fn reset(&self) -> Result<(), KeyStoreError> {
        let _lifecycle = self.lifecycle_guard();
        self.0.one_time_prekey.reset()?;
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
    use crate::one_time_prekey::{
        ONE_TIME_PREKEY_POOL_TARGET, ONE_TIME_PREKEY_REPLENISH_THRESHOLD,
    };
    use crate::storage::{InMemorySecureStorage, StorageError};
    use aether_crypto::verify_discovery_key_bundle;
    use std::collections::HashSet;
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use zeroize::Zeroizing;

    // Storage keys are duplicated from the manager modules so tests can inspect and tamper.
    const DISCOVERY_KEY: &str = "discovery/current";
    const IDENTITY_CURRENT_KEY: &str = "identity/current";
    const IDENTITY_ED25519_KEY: &str = "identity/ed25519";
    const IDENTITY_X25519_KEY: &str = "identity/x25519";
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
        let one_time_prekey = Arc::new(OneTimePreKeyManager::new(
            Arc::clone(&storage),
            Arc::clone(&discovery),
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
            one_time_prekey,
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
        assert!(matches!(
            key_store.current_publication_bundle(),
            Err(KeyStoreError::SignedPreKey(SignedPreKeyError::NotFound))
        ));
        key_store.rotate_signed_prekey_now().unwrap();
        let publication = key_store.current_publication_bundle().unwrap();
        assert_eq!(publication.version, aether_crypto::PREKEY_BUNDLE_VERSION);
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
    fn replenish_one_time_prekeys_creates_initial_pool() {
        let key_store = store();
        key_store.generate_identity().unwrap();
        let discovery = key_store.current_discovery_key_bundle().unwrap();
        let bundles = key_store.replenish_one_time_prekeys().unwrap();
        assert_eq!(bundles.len(), ONE_TIME_PREKEY_POOL_TARGET);
        assert!(bundles.iter().all(|bundle| bundle.epoch == discovery.epoch));
    }

    #[test]
    fn generate_one_time_prekeys_creates_exact_caller_size() {
        let key_store = store();
        key_store.generate_identity().unwrap();
        let discovery = key_store.current_discovery_key_bundle().unwrap();
        let first = key_store.generate_one_time_prekeys(3).unwrap();
        let second = key_store.generate_one_time_prekeys(2).unwrap();

        assert_eq!(first.len(), 3);
        assert_eq!(second.len(), 2);
        assert!(
            first
                .iter()
                .chain(&second)
                .all(|bundle| bundle.epoch == discovery.epoch)
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
    fn generate_one_time_prekeys_rejects_over_cap_batch() {
        let key_store = store();
        key_store.generate_identity().unwrap();
        key_store
            .generate_one_time_prekeys(ONE_TIME_PREKEY_POOL_TARGET)
            .unwrap();

        assert!(matches!(
            key_store.generate_one_time_prekeys(1),
            Err(KeyStoreError::OneTimePreKey(OneTimePreKeyError::InvalidData(reason)))
                if reason.contains("capacity")
        ));
    }

    #[test]
    fn generated_one_time_prekeys_persist_until_consumed() {
        let key_store = store();
        key_store.generate_identity().unwrap();
        let epoch = key_store.current_discovery_key_bundle().unwrap().epoch;
        let bundle = key_store.generate_one_time_prekeys(1).unwrap().remove(0);

        let prekey = key_store.consume_one_time_prekey(epoch, bundle.id).unwrap();
        assert_eq!(prekey.id(), bundle.id);
        assert!(matches!(
            key_store.consume_one_time_prekey(epoch, bundle.id),
            Err(KeyStoreError::OneTimePreKey(OneTimePreKeyError::NotFound))
        ));
    }

    #[test]
    fn consume_one_time_prekey_rejects_stale_epoch() {
        let key_store = store();
        key_store.generate_identity().unwrap();
        let epoch = key_store.current_discovery_key_bundle().unwrap().epoch;
        let bundle = key_store.generate_one_time_prekeys(1).unwrap().remove(0);

        assert!(matches!(
            key_store.consume_one_time_prekey(epoch + 1, bundle.id),
            Err(KeyStoreError::OneTimePreKey(OneTimePreKeyError::StaleEpoch))
        ));
    }

    #[test]
    fn replenish_one_time_prekeys_returns_empty_above_threshold() {
        let key_store = store();
        key_store.generate_identity().unwrap();
        key_store.replenish_one_time_prekeys().unwrap();
        let bundles = key_store.replenish_one_time_prekeys().unwrap();
        assert!(bundles.is_empty());
    }

    #[test]
    fn replenish_one_time_prekeys_tops_up_at_threshold() {
        let key_store = store();
        key_store.generate_identity().unwrap();
        let epoch = key_store.current_discovery_key_bundle().unwrap().epoch;
        let bundles = key_store.replenish_one_time_prekeys().unwrap();
        let keys_to_use = ONE_TIME_PREKEY_POOL_TARGET - ONE_TIME_PREKEY_REPLENISH_THRESHOLD;
        for bundle in bundles.iter().take(keys_to_use) {
            key_store.consume_one_time_prekey(epoch, bundle.id).unwrap();
        }
        let replenished = key_store.replenish_one_time_prekeys().unwrap();
        assert_eq!(replenished.len(), keys_to_use);
        assert_eq!(
            replenished.first().map(|bundle| bundle.id),
            Some(ONE_TIME_PREKEY_POOL_TARGET as u64)
        );
    }

    #[test]
    fn consume_one_time_prekey_consumes_secret_once() {
        let key_store = store();
        key_store.generate_identity().unwrap();
        let epoch = key_store.current_discovery_key_bundle().unwrap().epoch;
        let bundle = key_store.replenish_one_time_prekeys().unwrap().remove(0);
        let prekey = key_store.consume_one_time_prekey(epoch, bundle.id).unwrap();
        assert_eq!(prekey.id(), bundle.id);
        assert!(matches!(
            key_store.consume_one_time_prekey(epoch, bundle.id),
            Err(KeyStoreError::OneTimePreKey(OneTimePreKeyError::NotFound))
        ));
    }

    #[test]
    fn concurrent_consume_returns_one_time_prekey_once() {
        const THREADS: usize = 8;

        let key_store = store();
        key_store.generate_identity().unwrap();
        let epoch = key_store.current_discovery_key_bundle().unwrap().epoch;
        let bundle = key_store.replenish_one_time_prekeys().unwrap().remove(0);
        let barrier = Arc::new(Barrier::new(THREADS));
        let mut threads = Vec::new();
        for _ in 0..THREADS {
            let key_store = key_store.clone();
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                key_store
                    .consume_one_time_prekey(epoch, bundle.id)
                    .ok()
                    .map(|prekey| prekey.id())
            }));
        }
        let successes: Vec<u64> = threads
            .into_iter()
            .filter_map(|thread| thread.join().unwrap())
            .collect();
        assert_eq!(successes.len(), 1);
        assert_eq!(successes[0], bundle.id);
    }

    #[test]
    fn concurrent_replenish_does_not_return_duplicate_one_time_prekeys() {
        const THREADS: usize = 8;

        let key_store = store();
        key_store.generate_identity().unwrap();
        let barrier = Arc::new(Barrier::new(THREADS));
        let mut threads = Vec::new();
        for _ in 0..THREADS {
            let key_store = key_store.clone();
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                key_store.replenish_one_time_prekeys().unwrap()
            }));
        }
        let bundles: Vec<_> = threads
            .into_iter()
            .flat_map(|thread| thread.join().unwrap())
            .collect();
        let ids: HashSet<_> = bundles.iter().map(|bundle| bundle.id).collect();
        assert_eq!(
            (bundles.len(), ids.len()),
            (ONE_TIME_PREKEY_POOL_TARGET, ONE_TIME_PREKEY_POOL_TARGET)
        );
    }

    #[test]
    fn rotate_discovery_key_now_clears_one_time_prekey_pool() {
        let key_store = store();
        key_store.generate_identity().unwrap();
        key_store.replenish_one_time_prekeys().unwrap();
        let rotation = key_store.rotate_discovery_key_now().unwrap();
        let bundles = key_store.replenish_one_time_prekeys().unwrap();
        assert_eq!(bundles.len(), ONE_TIME_PREKEY_POOL_TARGET);
        assert!(
            bundles
                .iter()
                .all(|bundle| bundle.epoch == rotation.discovery_key.epoch)
        );
        assert_eq!(bundles.first().map(|bundle| bundle.id), Some(0));
    }

    #[test]
    fn import_encrypted_backup_clears_stale_one_time_prekey_pool() {
        let destination_store = store();
        destination_store.generate_identity().unwrap();
        destination_store.replenish_one_time_prekeys().unwrap();
        let source_store = store();
        source_store.generate_identity().unwrap();
        let backup = source_store.export_encrypted_backup("pass").unwrap();
        destination_store
            .import_encrypted_backup(&backup, "pass")
            .unwrap();
        assert!(matches!(
            destination_store
                .0
                .one_time_prekey
                .consume_one_time_prekey(0, 0),
            Err(OneTimePreKeyError::NotFound)
        ));
    }

    #[test]
    fn current_publication_bundle_rejects_prekey_signed_by_superseded_discovery_key() {
        let (key_store, storage) = store_with_storage();
        key_store.generate_identity().unwrap();
        key_store.rotate_signed_prekey_now().unwrap();
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
        assert_eq!(rotation.version, aether_crypto::PREKEY_BUNDLE_VERSION);
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
    fn rotate_discovery_key_now_clears_prior_epoch_signed_prekey_secret() {
        let key_store = store();
        key_store.generate_identity().unwrap();
        let first_epoch = key_store.current_discovery_key_bundle().unwrap().epoch;
        let first_prekey = key_store.rotate_signed_prekey_now().unwrap();

        key_store.rotate_discovery_key_now().unwrap();

        assert!(matches!(
            key_store
                .0
                .signed_prekey
                .prekey_for_public_key(first_epoch, first_prekey.public_key.as_bytes()),
            Err(SignedPreKeyError::NotFound)
        ));
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
        key_store.rotate_signed_prekey_now().unwrap();

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
    fn import_encrypted_backup_commits_identity_with_single_store() {
        struct CountingIdentityWriteStorage {
            inner: InMemorySecureStorage,
            fail_enabled: Arc<AtomicBool>,
            writes: Arc<AtomicUsize>,
        }

        impl SecureStorage for CountingIdentityWriteStorage {
            fn store(&mut self, key: &str, value: &[u8]) -> Result<(), StorageError> {
                if self.fail_enabled.load(Ordering::SeqCst)
                    && matches!(
                        key,
                        IDENTITY_CURRENT_KEY | IDENTITY_ED25519_KEY | IDENTITY_X25519_KEY
                    )
                {
                    let writes = self.writes.fetch_add(1, Ordering::SeqCst) + 1;
                    if writes == 2 {
                        return Err(StorageError::IO("injected identity store failure".into()));
                    }
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

        let fail_enabled = Arc::new(AtomicBool::new(false));
        let writes = Arc::new(AtomicUsize::new(0));
        let destination_store = KeyStore::new(Box::new(CountingIdentityWriteStorage {
            inner: InMemorySecureStorage::new(),
            fail_enabled: Arc::clone(&fail_enabled),
            writes: Arc::clone(&writes),
        }));
        destination_store.generate_identity().unwrap();

        let source_store = store();
        let source_identity = source_store.generate_identity().unwrap();
        let backup = source_store.export_encrypted_backup("pass").unwrap();

        fail_enabled.store(true, Ordering::SeqCst);
        destination_store
            .import_encrypted_backup(&backup, "pass")
            .unwrap();

        let imported_identity = destination_store.load_identity().unwrap();
        assert_eq!(writes.load(Ordering::SeqCst), 1);
        assert_eq!(source_identity.public_key(), imported_identity.public_key());
        assert_eq!(
            source_identity.verifying_key().as_bytes(),
            imported_identity.verifying_key().as_bytes()
        );
    }

    #[test]
    fn import_encrypted_backup_blob_store_failure_leaves_no_identity() {
        struct FailingBlobStorage {
            inner: InMemorySecureStorage,
            fail_blob_store: Arc<AtomicBool>,
        }

        impl SecureStorage for FailingBlobStorage {
            fn store(&mut self, key: &str, value: &[u8]) -> Result<(), StorageError> {
                if self.fail_blob_store.load(Ordering::SeqCst) && key == IDENTITY_CURRENT_KEY {
                    return Err(StorageError::IO("injected identity blob failure".into()));
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

        let fail_blob_store = Arc::new(AtomicBool::new(false));
        let destination_store = KeyStore::new(Box::new(FailingBlobStorage {
            inner: InMemorySecureStorage::new(),
            fail_blob_store: Arc::clone(&fail_blob_store),
        }));
        destination_store.generate_identity().unwrap();

        let source_store = store();
        source_store.generate_identity().unwrap();
        let backup = source_store.export_encrypted_backup("pass").unwrap();

        fail_blob_store.store(true, Ordering::SeqCst);
        assert!(
            destination_store
                .import_encrypted_backup(&backup, "pass")
                .is_err()
        );
        assert!(matches!(
            destination_store.load_identity(),
            Err(KeyStoreError::Identity(IdentityError::NotFound))
        ));
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
    fn reset_clears_identity_discovery_key_and_prekeys() {
        let key_store = store();
        key_store.generate_identity().unwrap();
        key_store.replenish_one_time_prekeys().unwrap();
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
            key_store.0.one_time_prekey.consume_one_time_prekey(0, 0),
            Err(OneTimePreKeyError::NotFound)
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
