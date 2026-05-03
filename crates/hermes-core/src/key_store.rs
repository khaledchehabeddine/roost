use crate::identity::{IdentityError, IdentityManager};
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
    Identity(IdentityError),
    /// Wraps a [`SignedPreKeyError`] from the underlying [`SignedPreKeyManager`].
    SignedPreKey(SignedPreKeyError),
}

impl fmt::Display for KeyStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyStoreError::Identity(e) => write!(f, "identity: {e}"),
            KeyStoreError::SignedPreKey(e) => write!(f, "signed prekey: {e}"),
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
///
/// Most consumers should use the facade methods directly ([`Self::has_identity`],
/// [`Self::rotate_signed_prekey_if_stale`], [`Self::reset`], etc.). The
/// [`Self::identity`] and [`Self::signed_prekey`] accessors expose the sub-managers for
/// callers that need finer control.
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

    /// Returns the shared [`IdentityManager`] handle.
    pub fn identity(&self) -> Arc<IdentityManager> {
        Arc::clone(&self.0.identity)
    }

    /// Returns the shared [`SignedPreKeyManager`] handle.
    pub fn signed_prekey(&self) -> Arc<SignedPreKeyManager> {
        Arc::clone(&self.0.signed_prekey)
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
    /// `None` when the stored SPK is still fresh.
    ///
    /// `Some(bundle)` is the cheap signal to upload the new bundle to peers; `None` means there's
    /// nothing new to push.
    ///
    /// # Errors
    /// - [`KeyStoreError::Identity`] (`NotFound`) if no identity is stored.
    /// - [`KeyStoreError::Identity`] (`Corrupt`) if only one of the two identity keys is present.
    /// - [`KeyStoreError::Identity`] (`InvalidData`) if a stored identity key has the wrong byte length.
    /// - [`KeyStoreError::SignedPreKey`] (`InvalidData`) if the stored SPK has wrong length or version.
    /// - [`KeyStoreError::SignedPreKey`] (`Storage`) on platform storage failure.
    /// - [`KeyStoreError::SignedPreKey`] (`Clock` / `LockPoisoned`) on internal failures.
    pub fn rotate_signed_prekey_if_stale(
        &self,
    ) -> Result<Option<SignedPreKeyBundle>, KeyStoreError> {
        Ok(self
            .0
            .signed_prekey
            .rotate_if_stale()?
            .map(|spk| spk.bundle()))
    }

    /// Forces an immediate SPK rotation regardless of staleness. Use for explicit user actions
    /// like "Reset Keys". Always returns the new bundle.
    ///
    /// # Errors
    /// - [`KeyStoreError::Identity`] (`NotFound`) if no identity is stored.
    /// - [`KeyStoreError::Identity`] (`Corrupt`) if only one of the two identity keys is present.
    /// - [`KeyStoreError::Identity`] (`InvalidData`) if a stored identity key has the wrong byte length.
    /// - [`KeyStoreError::SignedPreKey`] (`Storage`) on platform storage failure.
    /// - [`KeyStoreError::SignedPreKey`] (`Clock` / `LockPoisoned`) on internal failures.
    pub fn rotate_signed_prekey_now(&self) -> Result<SignedPreKeyBundle, KeyStoreError> {
        Ok(self.0.signed_prekey.rotate_now()?.bundle())
    }

    /// Restores an identity from an encrypted backup, replacing any current identity and
    /// clearing the previously stored SPK.
    ///
    /// Decrypt-then-commit: a bad passphrase fails before any storage mutation. A partial
    /// failure during commit may leave the keystore in a `Corrupt` state (SPK cleared,
    /// identity partially written); recover by calling [`Self::reset`] and retrying.
    ///
    /// Caveat when overwriting an existing identity: if the X25519 store succeeds and the
    /// Ed25519 store then fails, on-disk storage holds X25519 from the new identity and
    /// Ed25519 from the previous one. [`IdentityManager::load_identity`] cannot detect this
    /// chimera because the schema has no signed binding between the two halves. Treat any
    /// failure of this method as a hard requirement to call [`Self::reset`] before reuse.
    ///
    /// # Errors
    /// - [`KeyStoreError::Identity`] (`DecryptionFailed`) on wrong passphrase or tampered blob
    /// - [`KeyStoreError::Identity`] (`InvalidData`) on wrong blob length
    /// - [`KeyStoreError::Identity`] (`Storage`) on platform storage failure
    /// - [`KeyStoreError::SignedPreKey`] (`Storage`) on SPK delete failure
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

    /// Clears the stored SPK and identity. Idempotent.
    ///
    /// Partial-failure safe: if SPK delete succeeds but identity delete fails, retrying
    /// [`Self::reset`] completes the reset.
    ///
    /// # Errors
    /// - [`KeyStoreError::SignedPreKey`] (`Storage`) on SPK delete failure.
    /// - [`KeyStoreError::Identity`] (`Storage`) on identity delete failure.
    /// - [`KeyStoreError::Identity`] (`LockPoisoned`) on storage lock poisoning.
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
        ks_a.identity().generate_identity().unwrap();
        assert!(ks_b.identity().load_identity().is_ok());
    }

    #[test]
    fn two_identity_handles_share_storage() {
        let ks = store();
        let id_a = ks.identity();
        let id_b = ks.identity();
        let generated = id_a.generate_identity().unwrap();
        let loaded = id_b.load_identity().unwrap();
        assert_eq!(generated.public_key(), loaded.public_key());
    }

    #[test]
    fn sub_manager_writes_do_not_collide() {
        let ks = store();
        ks.identity().generate_identity().unwrap();
        ks.rotate_signed_prekey_if_stale().unwrap();
        assert!(ks.identity().load_identity().is_ok());
        assert!(ks.signed_prekey().current_bundle().is_ok());
    }

    #[test]
    fn import_encrypted_backup_clears_stale_spk() {
        let ks_b = store();
        ks_b.identity().generate_identity().unwrap();
        ks_b.rotate_signed_prekey_if_stale().unwrap();

        let ks_a = store();
        ks_a.identity().generate_identity().unwrap();
        let backup = ks_a.identity().export_encrypted_backup("pass").unwrap();

        // Importing ks_a's backup into ks_b must clear ks_b's stale SPK (signed by old id)
        ks_b.import_encrypted_backup(&backup, "pass").unwrap();
        assert!(matches!(
            ks_b.signed_prekey().current_bundle(),
            Err(SignedPreKeyError::InvalidData(_))
        ));

        let imported = ks_b.identity().load_identity().unwrap();
        let original = ks_a.identity().load_identity().unwrap();
        assert_eq!(
            imported.verifying_key().as_bytes(),
            original.verifying_key().as_bytes()
        );
    }

    #[test]
    fn import_then_rotate_yields_spk_signed_by_imported_identity() {
        let ks_a = store();
        ks_a.identity().generate_identity().unwrap();
        ks_a.rotate_signed_prekey_if_stale().unwrap();

        let ks_b = store();
        ks_b.identity().generate_identity().unwrap();
        let backup = ks_b.identity().export_encrypted_backup("pass").unwrap();

        ks_a.import_encrypted_backup(&backup, "pass").unwrap();
        ks_a.rotate_signed_prekey_if_stale().unwrap();

        let new_bundle = ks_a.signed_prekey().current_bundle().unwrap();
        let imported = ks_a.identity().load_identity().unwrap();
        assert!(verify_bundle(&new_bundle, imported.verifying_key()).is_ok());
    }

    #[test]
    fn import_with_wrong_passphrase_does_not_disturb_existing_state() {
        let ks_a = store();
        ks_a.identity().generate_identity().unwrap();
        ks_a.rotate_signed_prekey_if_stale().unwrap();
        let original_id = ks_a.identity().load_identity().unwrap();
        let original_spk = ks_a.signed_prekey().current_bundle().unwrap().public_key;

        let ks_b = store();
        ks_b.identity().generate_identity().unwrap();
        let backup = ks_b.identity().export_encrypted_backup("right").unwrap();

        assert!(ks_a.import_encrypted_backup(&backup, "wrong").is_err());

        let id = ks_a.identity().load_identity().unwrap();
        let spk = ks_a.signed_prekey().current_bundle().unwrap().public_key;
        assert_eq!(original_id.public_key(), id.public_key());
        assert_eq!(original_spk.as_bytes(), spk.as_bytes());
    }

    #[test]
    fn reset_clears_identity_and_spk() {
        let ks = store();
        ks.identity().generate_identity().unwrap();
        ks.rotate_signed_prekey_if_stale().unwrap();

        ks.reset().unwrap();

        assert!(matches!(
            ks.identity().load_identity(),
            Err(IdentityError::NotFound)
        ));
        assert!(matches!(
            ks.signed_prekey().current_bundle(),
            Err(SignedPreKeyError::InvalidData(_))
        ));
    }

    #[test]
    fn reset_returns_store_to_first_launch_state() {
        let ks = store();
        ks.identity().generate_identity().unwrap();
        ks.rotate_signed_prekey_if_stale().unwrap();

        ks.reset().unwrap();

        ks.identity().generate_identity().unwrap();
        ks.rotate_signed_prekey_if_stale().unwrap();
        assert!(ks.signed_prekey().current_bundle().is_ok());
    }

    #[test]
    fn reset_on_empty_store_succeeds() {
        let ks = store();
        ks.reset().unwrap();
        ks.reset().unwrap();
    }
}
