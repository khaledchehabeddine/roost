//! UniFFI keystore object exposing identity and signed pre-key operations.

use crate::SecureStorage;
use crate::error::HermesError;
use crate::records::{Identity, SignedPreKeyBundle};
use crate::storage::SecureStorageAdapter;
use hermes_core::KeyStore as CoreKeyStore;
use std::sync::Arc;

/// Entry point for local identity and signed pre-key state.
///
/// Construct one keystore for the app and keep it for the process lifetime. Methods may be called
/// concurrently, but the keystore serializes access to the underlying [`SecureStorage`].
#[derive(uniffi::Object)]
pub struct KeyStore {
    inner: CoreKeyStore,
}

#[uniffi::export]
impl KeyStore {
    /// Constructs a keystore backed by the given platform [`SecureStorage`].
    ///
    /// No storage access or key generation occurs. Use [`Self::has_identity`] afterward to decide
    /// whether to generate or import an identity.
    ///
    /// # Examples
    /// ```
    /// use hermes::{InMemorySecureStorage, KeyStore, SecureStorage};
    /// use std::sync::Arc;
    ///
    /// let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// let store = KeyStore::new(storage);
    /// ```
    #[uniffi::constructor]
    pub fn new(storage: Arc<dyn SecureStorage>) -> Arc<Self> {
        Arc::new(KeyStore {
            inner: CoreKeyStore::new(Box::new(SecureStorageAdapter::new(storage))),
        })
    }

    /// Generates a fresh identity (X25519 + Ed25519 key pairs) and persists it via
    /// [`SecureStorage`].
    ///
    /// # Examples
    /// ```
    /// # use hermes::{HermesError, Identity, InMemorySecureStorage, KeyStore, SecureStorage};
    /// # use std::sync::Arc;
    /// # fn publish_identity(_identity: &Identity) -> Result<(), HermesError> { Ok(()) }
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let store = KeyStore::new(storage);
    /// let identity = store.generate_identity()?;
    /// publish_identity(&identity)?;
    /// # Ok::<(), HermesError>(())
    /// ```
    ///
    /// # Errors
    /// - [`HermesError::AlreadyExists`] if an identity is already stored.
    /// - [`HermesError::InternalError`] on storage lock poisoning.
    /// - [`HermesError::Storage`] if platform storage returns an error.
    pub fn generate_identity(&self) -> Result<Identity, HermesError> {
        Ok(self.inner.generate_identity()?.into())
    }

    /// Loads the stored identity's public material.
    ///
    /// # Examples
    /// ```
    /// # use hermes::{HermesError, InMemorySecureStorage, KeyStore, SecureStorage};
    /// # use std::sync::Arc;
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let store = KeyStore::new(storage);
    /// # store.generate_identity()?;
    /// let identity = store.load_identity()?;
    /// # Ok::<(), HermesError>(())
    /// ```
    ///
    /// # Errors
    /// - [`HermesError::Corrupt`] if only one of the two key parts is present.
    /// - [`HermesError::InternalError`] on storage lock poisoning.
    /// - [`HermesError::InvalidData`] if a stored key has the wrong byte length.
    /// - [`HermesError::NotFound`] if no identity is stored.
    /// - [`HermesError::Storage`] on platform storage failure.
    pub fn load_identity(&self) -> Result<Identity, HermesError> {
        Ok(self.inner.load_identity()?.into())
    }

    /// Exports the current identity as a passphrase-encrypted blob.
    ///
    /// The blob is portable across devices: pass it to another keystore's
    /// [`Self::import_encrypted_backup`] with the same `passphrase` to restore.
    ///
    /// # Examples
    /// ```
    /// # use hermes::{HermesError, InMemorySecureStorage, KeyStore, SecureStorage};
    /// # use std::sync::Arc;
    /// # fn persist_backup_blob(_blob: &[u8]) -> Result<(), HermesError> { Ok(()) }
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let store = KeyStore::new(storage);
    /// # store.generate_identity()?;
    /// let blob = store.export_encrypted_backup("strong passphrase".into())?;
    /// persist_backup_blob(&blob)?;
    /// # Ok::<(), HermesError>(())
    /// ```
    ///
    /// # Errors
    /// - [`HermesError::BackupFailed`] on randomness failure, Argon2id derivation error, or
    ///   authenticated encryption failure.
    /// - [`HermesError::Corrupt`] if only one of the two identity keys is present.
    /// - [`HermesError::InternalError`] on storage lock poisoning.
    /// - [`HermesError::InvalidData`] if a stored identity key has the wrong byte length.
    /// - [`HermesError::NotFound`] if no identity is stored.
    /// - [`HermesError::Storage`] on platform storage failure when loading an identity.
    ///
    /// # Performance
    /// The backup blob is 120 bytes. Each call runs one Argon2id password hashing step using
    /// 64 MiB memory and 3 iterations.
    pub fn export_encrypted_backup(&self, passphrase: String) -> Result<Vec<u8>, HermesError> {
        Ok(self.inner.export_encrypted_backup(&passphrase)?)
    }

    /// Restores an identity from an encrypted backup, replacing any current identity.
    ///
    /// The backup is decrypted before storage changes begin, so a wrong passphrase leaves the
    /// existing identity untouched. After a successful import, the stored signed pre-key is
    /// cleared because it was signed by the replaced identity.
    ///
    /// Errors from parsing, key derivation, or decryption happen before storage changes. Storage
    /// failures can occur after writing begins and may leave identity keys from different
    /// identities. That invalid state must be cleared before the keystore is used again.
    ///
    /// # Examples
    /// ```
    /// # use hermes::{HermesError, InMemorySecureStorage, KeyStore, SecureStorage};
    /// # use std::sync::Arc;
    /// // Source keystore: generate an identity and export an encrypted backup.
    /// let source: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// let source_store = KeyStore::new(source);
    /// source_store.generate_identity()?;
    /// let blob = source_store.export_encrypted_backup("strong passphrase".into())?;
    ///
    /// // Restored keystore: import the blob into a fresh store.
    /// let destination: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// let destination_store = KeyStore::new(destination);
    /// destination_store.import_encrypted_backup(blob, "strong passphrase".into())?;
    /// # Ok::<(), HermesError>(())
    /// ```
    ///
    /// # Errors
    /// - [`HermesError::BackupFailed`] on Argon2id parameter error.
    /// - [`HermesError::DecryptionFailed`] on wrong passphrase or tampered ciphertext.
    /// - [`HermesError::InternalError`] on storage lock poisoning.
    /// - [`HermesError::InvalidData`] if the blob length is wrong.
    /// - [`HermesError::Storage`] on platform storage failure during commit.
    ///
    /// # Performance
    /// The backup blob is 120 bytes. Each call runs one Argon2id password hashing step using
    /// 64 MiB memory and 3 iterations.
    pub fn import_encrypted_backup(
        &self,
        data: Vec<u8>,
        passphrase: String,
    ) -> Result<(), HermesError> {
        self.inner
            .import_encrypted_backup(&data, &passphrase)
            .map_err(Into::into)
    }

    /// Returns `true` when this keystore has identity data in storage.
    ///
    /// This is a presence check only. Use [`Self::load_identity`] to read and validate the public
    /// identity.
    ///
    /// # Examples
    /// ```
    /// # use hermes::{HermesError, InMemorySecureStorage, KeyStore, SecureStorage};
    /// # use std::sync::Arc;
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let store = KeyStore::new(storage);
    /// if !store.has_identity()? {
    ///     store.generate_identity()?;
    /// }
    /// # Ok::<(), HermesError>(())
    /// ```
    ///
    /// # Errors
    /// - [`HermesError::InternalError`] on storage lock poisoning.
    /// - [`HermesError::Storage`] on platform storage failure.
    pub fn has_identity(&self) -> Result<bool, HermesError> {
        Ok(self.inner.has_identity()?)
    }

    /// Rotates the signed pre-key if the stored one is missing or older than the rotation window.
    ///
    /// Returns the new bundle when rotation occurred, `None` when the stored signed pre-key is
    /// still fresh.
    ///
    /// Call once at app launch. Publish the returned bundle when this returns `Some`. `None` means
    /// the stored bundle is unchanged.
    ///
    /// # Examples
    /// ```
    /// # use hermes::{
    /// #     HermesError, InMemorySecureStorage, KeyStore, SecureStorage, SignedPreKeyBundle,
    /// # };
    /// # use std::sync::Arc;
    /// # fn publish_signed_prekey_bundle(_bundle: &SignedPreKeyBundle) -> Result<(), HermesError> {
    /// #     Ok(())
    /// # }
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let store = KeyStore::new(storage);
    /// # store.generate_identity()?;
    /// if let Some(new_bundle) = store.rotate_signed_prekey_if_stale()? {
    ///     publish_signed_prekey_bundle(&new_bundle)?;
    /// }
    /// # Ok::<(), HermesError>(())
    /// ```
    ///
    /// # Errors
    /// - [`HermesError::Corrupt`] if only one of the two identity keys is present.
    /// - [`HermesError::InternalError`] on storage lock poisoning or system clock anomaly.
    /// - [`HermesError::InvalidData`] if the stored signed pre-key has the wrong length or
    ///   version.
    /// - [`HermesError::NotFound`] if no identity is stored.
    /// - [`HermesError::Storage`] on platform storage failure.
    pub fn rotate_signed_prekey_if_stale(&self) -> Result<Option<SignedPreKeyBundle>, HermesError> {
        Ok(self.inner.rotate_signed_prekey_if_stale()?.map(Into::into))
    }

    /// Rotates the signed pre-key immediately, regardless of staleness, and returns the new
    /// bundle.
    ///
    /// Use when the caller needs a fresh bundle independent of the rotation window.
    ///
    /// # Examples
    /// ```
    /// # use hermes::{
    /// #     HermesError, InMemorySecureStorage, KeyStore, SecureStorage, SignedPreKeyBundle,
    /// # };
    /// # use std::sync::Arc;
    /// # fn publish_signed_prekey_bundle(_bundle: &SignedPreKeyBundle) -> Result<(), HermesError> {
    /// #     Ok(())
    /// # }
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let store = KeyStore::new(storage);
    /// # store.generate_identity()?;
    /// let new_bundle = store.rotate_signed_prekey_now()?;
    /// publish_signed_prekey_bundle(&new_bundle)?;
    /// # Ok::<(), HermesError>(())
    /// ```
    ///
    /// # Errors
    /// - [`HermesError::Corrupt`] if only one of the two identity keys is present.
    /// - [`HermesError::InternalError`] on storage lock poisoning or system clock anomaly.
    /// - [`HermesError::InvalidData`] if a stored identity key has the wrong byte length.
    /// - [`HermesError::NotFound`] if no identity is stored.
    /// - [`HermesError::Storage`] on platform storage failure.
    pub fn rotate_signed_prekey_now(&self) -> Result<SignedPreKeyBundle, HermesError> {
        Ok(self.inner.rotate_signed_prekey_now()?.into())
    }

    /// Returns the currently stored signed pre-key bundle.
    ///
    /// Hand this to peers asking for the bundle they need to start a session.
    ///
    /// # Examples
    /// ```
    /// # use hermes::{
    /// #     HermesError, InMemorySecureStorage, KeyStore, SecureStorage, SignedPreKeyBundle,
    /// # };
    /// # use std::sync::Arc;
    /// # fn send_bundle_to_peer(_bundle: &SignedPreKeyBundle) -> Result<(), HermesError> {
    /// #     Ok(())
    /// # }
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let store = KeyStore::new(storage);
    /// # store.generate_identity()?;
    /// # store.rotate_signed_prekey_if_stale()?;
    /// let bundle = store.current_signed_prekey_bundle()?;
    /// send_bundle_to_peer(&bundle)?;
    /// # Ok::<(), HermesError>(())
    /// ```
    ///
    /// # Errors
    /// - [`HermesError::InternalError`] on storage lock poisoning.
    /// - [`HermesError::InvalidData`] if the stored blob has the wrong length or unsupported
    ///   version.
    /// - [`HermesError::NotFound`] if no signed pre-key is stored.
    /// - [`HermesError::Storage`] on platform storage failure.
    pub fn current_signed_prekey_bundle(&self) -> Result<SignedPreKeyBundle, HermesError> {
        Ok(self.inner.current_signed_prekey_bundle()?.into())
    }

    /// Clears the stored identity and signed pre-key material.
    ///
    /// The signed pre-key is deleted before identity keys, so a partial failure does not leave a
    /// signed pre-key attached to a missing identity. Calling this on an empty store succeeds.
    /// Calling it again after a partial failure continues deleting any remaining keys.
    ///
    /// # Examples
    /// ```
    /// # use hermes::{HermesError, InMemorySecureStorage, KeyStore, SecureStorage};
    /// # use std::sync::Arc;
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let store = KeyStore::new(storage);
    /// store.reset()?;
    /// # Ok::<(), HermesError>(())
    /// ```
    ///
    /// # Errors
    /// - [`HermesError::InternalError`] on storage lock poisoning.
    /// - [`HermesError::Storage`] on platform storage failure.
    pub fn reset(&self) -> Result<(), HermesError> {
        self.inner.reset().map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::KeyStore;
    use crate::{InMemorySecureStorage, SecureStorage};
    use hermes_crypto::{PublicKey, Signature, SignedPreKeyBundle, VerifyingKey, verify_bundle};
    use std::sync::Arc;

    fn key_store() -> Arc<KeyStore> {
        let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
        KeyStore::new(storage)
    }

    #[test]
    fn generate_identity_returns_32_byte_keys() {
        let store = key_store();
        let identity = store.generate_identity().unwrap();
        assert_eq!(identity.public_key.len(), 32);
        assert_eq!(identity.verifying_key.len(), 32);
    }

    #[test]
    fn key_store_generates_and_verifies_signed_prekey_bundle() {
        let store = key_store();
        let identity = store.generate_identity().unwrap();
        let rotated_bundle = store.rotate_signed_prekey_if_stale().unwrap();
        assert!(
            rotated_bundle.is_some(),
            "first rotate must produce a bundle"
        );

        let bundle = store.current_signed_prekey_bundle().unwrap();
        assert_eq!(bundle.public_key.len(), 32);
        assert_eq!(bundle.signature.len(), 64);
        assert!(bundle.created_at > 0);

        let verifying_bytes: [u8; 32] = identity.verifying_key.as_slice().try_into().unwrap();
        let verifying_key = VerifyingKey::from_bytes(&verifying_bytes).unwrap();
        let public_key_bytes: [u8; 32] = bundle.public_key.as_slice().try_into().unwrap();
        let signature_bytes: [u8; 64] = bundle.signature.as_slice().try_into().unwrap();
        let crypto_bundle = SignedPreKeyBundle {
            public_key: PublicKey::from(public_key_bytes),
            signature: Signature::from_bytes(&signature_bytes),
            created_at: bundle.created_at,
        };
        assert!(verify_bundle(&crypto_bundle, &verifying_key).is_ok());
    }
}
