use crate::clock::{Clock, SystemClock};
use crate::identity::{Identity, IdentityError, IdentityManager};
use crate::signed_prekey::{SignedPreKeyError, SignedPreKeyManager};
use crate::storage::SecureStorage;
use aether_crypto::SignedPreKeyBundle;
use rand::rngs::OsRng;
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex};

/// Errors returned by [`KeyStore`] operations.
#[derive(Debug)]
pub enum KeyStoreError {
    /// An identity-layer operation failed.
    Identity(IdentityError),
    /// A signed-pre-key operation failed.
    SignedPreKey(SignedPreKeyError),
}

impl fmt::Display for KeyStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyStoreError::Identity(e) => write!(f, "identity: {e}"),
            KeyStoreError::SignedPreKey(e) => write!(f, "signed pre-key: {e}"),
        }
    }
}

impl Error for KeyStoreError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
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

struct KeyStoreInner {
    identity: Arc<IdentityManager>,
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
        let signed_prekey = Arc::new(SignedPreKeyManager::new(
            storage,
            Arc::clone(&identity),
            clock,
        ));
        KeyStore(Arc::new(KeyStoreInner {
            identity,
            signed_prekey,
        }))
    }

    /// Generates a fresh [`Identity`] and persists it.
    ///
    /// # Errors
    /// - [`KeyStoreError::Identity`] (`AlreadyExists`) if an identity is already stored.
    /// - [`KeyStoreError::Identity`] (`LockPoisoned`) on storage lock poisoning.
    /// - [`KeyStoreError::Identity`] (`Storage`) on platform storage failure.
    pub fn generate_identity(&self) -> Result<Identity, KeyStoreError> {
        Ok(self.0.identity.generate_identity(&mut OsRng)?)
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
    /// # Errors
    /// - [`KeyStoreError::SignedPreKey`] (`InvalidData`) if the stored blob is malformed.
    /// - [`KeyStoreError::SignedPreKey`] (`LockPoisoned` | `Storage`) on storage failures.
    /// - [`KeyStoreError::SignedPreKey`] (`NotFound`) if no signed pre-key is stored.
    pub fn current_signed_prekey_bundle(&self) -> Result<SignedPreKeyBundle, KeyStoreError> {
        Ok(self.0.signed_prekey.current_bundle()?)
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
    /// Replaces any current identity and clears the signed pre-key from the previous identity.
    ///
    /// Decryption and validation happen before storage mutation, so wrong passphrases, tampered
    /// blobs, and wrong-length blobs leave the current state unchanged.
    ///
    /// Storage failures after writes begin may leave identity keys from different identities.
    /// That state is invalid until cleared.
    ///
    /// # Errors
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
        let plaintext = self.0.identity.decrypt_backup(data, passphrase)?;
        self.0.signed_prekey.reset()?;
        self.0.identity.store_decrypted_identity(&plaintext)?;
        Ok(())
    }

    /// Clears the stored signed pre-key and identity.
    ///
    /// The signed pre-key is deleted before identity keys, so a partial failure does not leave a
    /// signed pre-key attached to a missing identity.
    ///
    /// # Errors
    /// - [`KeyStoreError::Identity`] (`LockPoisoned` | `Storage`) on identity delete failure.
    /// - [`KeyStoreError::SignedPreKey`] (`LockPoisoned` | `Storage`) on signed-pre-key delete
    ///   failure.
    pub fn reset(&self) -> Result<(), KeyStoreError> {
        self.0.signed_prekey.reset()?;
        self.0.identity.reset()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::InMemorySecureStorage;
    use aether_crypto::verify_bundle;

    fn store() -> KeyStore {
        KeyStore::new(Box::new(InMemorySecureStorage::new()))
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
    fn import_then_rotate_yields_signed_prekey_signed_by_imported_identity() {
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
        assert!(verify_bundle(&rotated_bundle, imported_identity.verifying_key()).is_ok());
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
}
