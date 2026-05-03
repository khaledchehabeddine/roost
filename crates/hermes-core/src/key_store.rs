use crate::identity::{Identity, IdentityError, IdentityManager};
use crate::signed_prekey::{SignedPreKeyError, SignedPreKeyManager};
use crate::storage::SecureStorage;
use hermes_crypto::SignedPreKeyBundle;
use std::error::Error;
use std::fmt;
use std::sync::{Arc, Mutex};

/// Errors returned by [`KeyStore`] operations. Wraps the sub-manager error types so callers
/// handle a single error enum at the facade.
#[derive(Debug)]
pub enum KeyStoreError {
    /// Wraps an [`IdentityError`] from the underlying [`IdentityManager`].
    ///
    /// Recovery: see the wrapped [`IdentityError`] variant.
    Identity(IdentityError),
    /// Wraps a [`SignedPreKeyError`] from the underlying [`SignedPreKeyManager`]. Note that
    /// rotation errors that originate in the identity layer arrive nested here as
    /// `SignedPreKey(Identity(_))` — the manager wraps `IdentityError` before the facade does.
    ///
    /// Recovery: see the wrapped [`SignedPreKeyError`] variant.
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

/// Facade over [`IdentityManager`] and [`SignedPreKeyManager`], sharing a single
/// [`SecureStorage`]. Cheap to clone — internally an `Arc`.
#[derive(Clone)]
pub struct KeyStore(Arc<KeyStoreInner>);

impl KeyStore {
    /// Constructs a keystore that vends identity and signed-pre-key managers backed by the
    /// given `storage`. Cheap — no I/O, no key generation.
    pub fn new(storage: Box<dyn SecureStorage>) -> Self {
        let storage = Arc::new(Mutex::new(storage));
        let identity = Arc::new(IdentityManager::new(Arc::clone(&storage)));
        let signed_prekey = Arc::new(SignedPreKeyManager::new(storage, Arc::clone(&identity)));
        KeyStore(Arc::new(KeyStoreInner {
            identity,
            signed_prekey,
        }))
    }

    /// Generates a fresh identity (X25519 + Ed25519 key pairs) and persists it.
    ///
    /// # Errors
    /// - [`KeyStoreError::Identity`] (`AlreadyExists`) if an identity is already stored.
    /// - [`KeyStoreError::Identity`] (`Storage`) on platform storage failure.
    /// - [`KeyStoreError::Identity`] (`LockPoisoned`) on storage lock poisoning.
    pub fn generate_identity(&self) -> Result<Identity, KeyStoreError> {
        Ok(self.0.identity.generate_identity()?)
    }

    /// Loads the stored identity.
    ///
    /// # Errors
    /// - [`KeyStoreError::Identity`] (`NotFound`) if no identity is stored.
    /// - [`KeyStoreError::Identity`] (`Corrupt`) if only one of the two identity keys is present.
    /// - [`KeyStoreError::Identity`] (`InvalidData`) if a stored key has the wrong byte length.
    /// - [`KeyStoreError::Identity`] (`Storage`) on platform storage failure.
    /// - [`KeyStoreError::Identity`] (`LockPoisoned`) on storage lock poisoning.
    pub fn load_identity(&self) -> Result<Identity, KeyStoreError> {
        Ok(self.0.identity.load_identity()?)
    }

    /// Exports the stored identity as a passphrase-encrypted backup blob.
    ///
    /// # Errors
    /// - [`KeyStoreError::Identity`] (`NotFound` / `Corrupt` / `InvalidData`) when loading the
    ///   identity to export fails.
    /// - [`KeyStoreError::Identity`] (`BackupFailed`) on RNG failure, Argon2id derivation error,
    ///   or AEAD encryption failure.
    /// - [`KeyStoreError::Identity`] (`Storage` / `LockPoisoned`) on storage failures.
    pub fn export_encrypted_backup(&self, passphrase: &str) -> Result<Vec<u8>, KeyStoreError> {
        Ok(self.0.identity.export_encrypted_backup(passphrase)?)
    }

    /// Returns the currently-stored signed pre-key bundle.
    ///
    /// # Errors
    /// - [`KeyStoreError::SignedPreKey`] (`InvalidData`) if no signed pre-key is stored or the
    ///   stored blob is malformed.
    /// - [`KeyStoreError::SignedPreKey`] (`Storage` / `LockPoisoned`) on storage failures.
    pub fn current_signed_prekey_bundle(&self) -> Result<SignedPreKeyBundle, KeyStoreError> {
        Ok(self.0.signed_prekey.current_bundle()?)
    }

    /// Returns `true` if an X25519 identity key is present.
    ///
    /// Non-mutating storage probe; lets callers gate setup flows without exception-driven
    /// `load_identity` + `NotFound` catches. The Ed25519 component is not checked, so
    /// callers must still handle [`IdentityError::Corrupt`] from `load_identity` in case
    /// of partial-write damage.
    ///
    /// # Errors
    /// - [`KeyStoreError::Identity`] (`Storage`) on platform storage failure.
    /// - [`KeyStoreError::Identity`] (`LockPoisoned`) on storage lock poisoning.
    pub fn has_identity(&self) -> Result<bool, KeyStoreError> {
        Ok(self.0.identity.has_identity()?)
    }

    /// Call once at app launch. Returns the freshly-rotated bundle when rotation occurred,
    /// `None` when the stored signed pre-key is still fresh.
    ///
    /// `Some(bundle)` is the cheap signal to upload the new bundle to peers; `None` means there's
    /// nothing new to push.
    ///
    /// # Errors
    ///
    /// All errors arrive wrapped in [`KeyStoreError::SignedPreKey`]. The inner
    /// [`SignedPreKeyError`] cascade:
    ///
    /// - `Identity(NotFound)` if no identity is stored.
    /// - `Identity(Corrupt)` if only one of the two identity keys is present.
    /// - `Identity(InvalidData)` if a stored identity key has the wrong byte length.
    /// - `Identity(Storage)` / `Identity(LockPoisoned)` on storage failure while loading the
    ///   identity to sign the new signed pre-key.
    /// - `InvalidData` if the stored signed-pre-key blob has the wrong length or unsupported
    ///   version.
    /// - `Storage` / `LockPoisoned` on platform storage failure during signed-pre-key load or
    ///   store.
    /// - `Clock` if the system clock is before the Unix epoch.
    pub fn rotate_signed_prekey_if_stale(
        &self,
    ) -> Result<Option<SignedPreKeyBundle>, KeyStoreError> {
        Ok(self
            .0
            .signed_prekey
            .rotate_if_stale()?
            .map(|spk| spk.bundle()))
    }

    /// Forces an immediate signed-pre-key rotation regardless of staleness. Use for explicit
    /// user actions like "Reset Keys". Always returns the new bundle.
    ///
    /// # Errors
    ///
    /// All errors arrive wrapped in [`KeyStoreError::SignedPreKey`]. The inner
    /// [`SignedPreKeyError`] cascade:
    ///
    /// - `Identity(NotFound)` if no identity is stored.
    /// - `Identity(Corrupt)` if only one of the two identity keys is present.
    /// - `Identity(InvalidData)` if a stored identity key has the wrong byte length.
    /// - `Identity(Storage)` / `Identity(LockPoisoned)` on storage failure while loading the
    ///   identity.
    /// - `Storage` / `LockPoisoned` on platform storage failure during the signed-pre-key store.
    /// - `Clock` if the system clock is before the Unix epoch.
    pub fn rotate_signed_prekey_now(&self) -> Result<SignedPreKeyBundle, KeyStoreError> {
        Ok(self.0.signed_prekey.rotate_now()?.bundle())
    }

    /// Restores an identity from an encrypted backup, replacing any current identity and
    /// clearing the previously stored signed pre-key.
    ///
    /// Decrypt-then-commit: pre-mutation failures (`DecryptionFailed`, wrong-length
    /// `InvalidData`, Argon2 `BackupFailed`) leave any existing identity untouched. Failures
    /// after commit begins (`Storage`, `LockPoisoned`) may leave the keystore in a partial
    /// state — recover by calling [`Self::reset`] and retrying.
    ///
    /// Caveat when overwriting an existing identity: if the X25519 store succeeds and the
    /// Ed25519 store then fails, on-disk storage holds X25519 from the new identity and
    /// Ed25519 from the previous one. [`IdentityManager::load_identity`] cannot detect this
    /// chimera because the schema has no signed binding between the two halves. Treat any
    /// post-commit failure as a hard requirement to call [`Self::reset`] before reuse.
    ///
    /// # Errors
    /// - [`KeyStoreError::Identity`] (`DecryptionFailed`) on wrong passphrase or tampered blob.
    /// - [`KeyStoreError::Identity`] (`InvalidData`) on wrong blob length.
    /// - [`KeyStoreError::Identity`] (`BackupFailed`) on Argon2id parameter or derivation failure.
    /// - [`KeyStoreError::Identity`] (`Storage` / `LockPoisoned`) on storage failure while
    ///   committing the new identity.
    /// - [`KeyStoreError::SignedPreKey`] (`Storage` / `LockPoisoned`) on signed-pre-key delete
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

    /// Clears the stored signed pre-key and identity. Idempotent.
    ///
    /// Partial-failure safe: if the signed-pre-key delete succeeds but identity delete fails,
    /// retrying [`Self::reset`] completes the reset.
    ///
    /// # Errors
    /// - [`KeyStoreError::SignedPreKey`] (`Storage` / `LockPoisoned`) on signed-pre-key delete
    ///   failure.
    /// - [`KeyStoreError::Identity`] (`Storage` / `LockPoisoned`) on identity delete failure.
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
    use hermes_crypto::verify_bundle;

    fn store() -> KeyStore {
        KeyStore::new(Box::new(InMemorySecureStorage::new()))
    }

    #[test]
    fn key_store_clone_shares_storage() {
        let ks_a = store();
        let ks_b = ks_a.clone();
        ks_a.generate_identity().unwrap();
        assert!(ks_b.load_identity().is_ok());
    }

    #[test]
    fn sub_manager_writes_do_not_collide() {
        let ks = store();
        ks.generate_identity().unwrap();
        ks.rotate_signed_prekey_if_stale().unwrap();
        assert!(ks.load_identity().is_ok());
        assert!(ks.current_signed_prekey_bundle().is_ok());
    }

    #[test]
    fn import_encrypted_backup_clears_stale_spk() {
        let ks_b = store();
        ks_b.generate_identity().unwrap();
        ks_b.rotate_signed_prekey_if_stale().unwrap();

        let ks_a = store();
        ks_a.generate_identity().unwrap();
        let backup = ks_a.export_encrypted_backup("pass").unwrap();

        // Importing ks_a's backup into ks_b must clear ks_b's stale SPK (signed by old id)
        ks_b.import_encrypted_backup(&backup, "pass").unwrap();
        assert!(matches!(
            ks_b.current_signed_prekey_bundle(),
            Err(KeyStoreError::SignedPreKey(SignedPreKeyError::InvalidData(_)))
        ));

        let imported = ks_b.load_identity().unwrap();
        let original = ks_a.load_identity().unwrap();
        assert_eq!(
            imported.verifying_key().as_bytes(),
            original.verifying_key().as_bytes()
        );
    }

    #[test]
    fn import_then_rotate_yields_spk_signed_by_imported_identity() {
        let ks_a = store();
        ks_a.generate_identity().unwrap();
        ks_a.rotate_signed_prekey_if_stale().unwrap();

        let ks_b = store();
        ks_b.generate_identity().unwrap();
        let backup = ks_b.export_encrypted_backup("pass").unwrap();

        ks_a.import_encrypted_backup(&backup, "pass").unwrap();
        ks_a.rotate_signed_prekey_if_stale().unwrap();

        let new_bundle = ks_a.current_signed_prekey_bundle().unwrap();
        let imported = ks_a.load_identity().unwrap();
        assert!(verify_bundle(&new_bundle, imported.verifying_key()).is_ok());
    }

    #[test]
    fn import_with_wrong_passphrase_does_not_disturb_existing_state() {
        let ks_a = store();
        ks_a.generate_identity().unwrap();
        ks_a.rotate_signed_prekey_if_stale().unwrap();
        let original_id = ks_a.load_identity().unwrap();
        let original_spk = ks_a.current_signed_prekey_bundle().unwrap().public_key;

        let ks_b = store();
        ks_b.generate_identity().unwrap();
        let backup = ks_b.export_encrypted_backup("right").unwrap();

        assert!(ks_a.import_encrypted_backup(&backup, "wrong").is_err());

        let id = ks_a.load_identity().unwrap();
        let spk = ks_a.current_signed_prekey_bundle().unwrap().public_key;
        assert_eq!(original_id.public_key(), id.public_key());
        assert_eq!(original_spk.as_bytes(), spk.as_bytes());
    }

    #[test]
    fn reset_clears_identity_and_spk() {
        let ks = store();
        ks.generate_identity().unwrap();
        ks.rotate_signed_prekey_if_stale().unwrap();

        ks.reset().unwrap();

        assert!(matches!(
            ks.load_identity(),
            Err(KeyStoreError::Identity(IdentityError::NotFound))
        ));
        assert!(matches!(
            ks.current_signed_prekey_bundle(),
            Err(KeyStoreError::SignedPreKey(SignedPreKeyError::InvalidData(_)))
        ));
    }

    #[test]
    fn reset_returns_store_to_first_launch_state() {
        let ks = store();
        ks.generate_identity().unwrap();
        ks.rotate_signed_prekey_if_stale().unwrap();

        ks.reset().unwrap();

        ks.generate_identity().unwrap();
        ks.rotate_signed_prekey_if_stale().unwrap();
        assert!(ks.current_signed_prekey_bundle().is_ok());
    }

    #[test]
    fn reset_on_empty_store_succeeds() {
        let ks = store();
        ks.reset().unwrap();
        ks.reset().unwrap();
    }
}
