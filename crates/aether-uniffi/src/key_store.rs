//! UniFFI keystore object exposing identity and signed pre-key operations.

use crate::SecureStorage;
use crate::error::AetherError;
use crate::records::{DiscoveryKeyBundle, Identity, PublicationBundle, SignedPreKeyBundle};
use crate::storage::SecureStorageAdapter;
use aether_core::KeyStore as CoreKeyStore;
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
    /// use aether::{InMemorySecureStorage, KeyStore, SecureStorage};
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
    /// # use aether::{AetherError, Identity, InMemorySecureStorage, KeyStore, SecureStorage};
    /// # use std::sync::Arc;
    /// # fn publish_identity(_identity: &Identity) -> Result<(), AetherError> { Ok(()) }
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let store = KeyStore::new(storage);
    /// let identity = store.generate_identity()?;
    /// publish_identity(&identity)?;
    /// # Ok::<(), AetherError>(())
    /// ```
    ///
    /// # Errors
    /// - [`AetherError::AlreadyExists`] if an identity is already stored.
    /// - [`AetherError::InternalError`] on storage lock poisoning.
    /// - [`AetherError::Storage`] if platform storage returns an error.
    pub fn generate_identity(&self) -> Result<Identity, AetherError> {
        Ok(self.inner.generate_identity()?.into())
    }

    /// Loads the stored identity's public material.
    ///
    /// # Examples
    /// ```
    /// # use aether::{AetherError, InMemorySecureStorage, KeyStore, SecureStorage};
    /// # use std::sync::Arc;
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let store = KeyStore::new(storage);
    /// # store.generate_identity()?;
    /// let identity = store.load_identity()?;
    /// # Ok::<(), AetherError>(())
    /// ```
    ///
    /// # Errors
    /// - [`AetherError::Corrupt`] if only one of the two key parts is present.
    /// - [`AetherError::InternalError`] on storage lock poisoning.
    /// - [`AetherError::InvalidData`] if a stored key has the wrong byte length.
    /// - [`AetherError::NotFound`] if no identity is stored.
    /// - [`AetherError::Storage`] on platform storage failure.
    pub fn load_identity(&self) -> Result<Identity, AetherError> {
        Ok(self.inner.load_identity()?.into())
    }

    /// Exports the current identity as a passphrase-encrypted blob.
    ///
    /// The blob is portable across devices: pass it to another keystore's
    /// [`Self::import_encrypted_backup`] with the same `passphrase` to restore.
    ///
    /// # Examples
    /// ```
    /// # use aether::{AetherError, InMemorySecureStorage, KeyStore, SecureStorage};
    /// # use std::sync::Arc;
    /// # fn persist_backup_blob(_blob: &[u8]) -> Result<(), AetherError> { Ok(()) }
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let store = KeyStore::new(storage);
    /// # store.generate_identity()?;
    /// let blob = store.export_encrypted_backup("strong passphrase".into())?;
    /// persist_backup_blob(&blob)?;
    /// # Ok::<(), AetherError>(())
    /// ```
    ///
    /// # Errors
    /// - [`AetherError::BackupFailed`] on randomness failure, Argon2id derivation error, or
    ///   authenticated encryption failure.
    /// - [`AetherError::Corrupt`] if only one of the two identity keys is present.
    /// - [`AetherError::InternalError`] on storage lock poisoning.
    /// - [`AetherError::InvalidData`] if a stored identity key has the wrong byte length.
    /// - [`AetherError::NotFound`] if no identity is stored.
    /// - [`AetherError::Storage`] on platform storage failure when loading an identity.
    ///
    /// # Performance
    /// The backup blob is 120 bytes. Each call runs one Argon2id password hashing step using
    /// 64 MiB memory and 3 iterations.
    pub fn export_encrypted_backup(&self, passphrase: String) -> Result<Vec<u8>, AetherError> {
        Ok(self.inner.export_encrypted_backup(&passphrase)?)
    }

    /// Restores an identity from an encrypted backup, replacing any current identity.
    ///
    /// The backup is decrypted before storage changes begin, so a wrong passphrase leaves the
    /// existing identity untouched. After a successful import, the previous signed pre-key and
    /// discovery key are cleared and a fresh discovery key (epoch 0) is generated under the restored
    /// identity, since the discovery key is not part of the backup.
    ///
    /// Errors from parsing, key derivation, or decryption happen before storage changes. Storage
    /// failures can occur after writing begins and may leave identity keys from different
    /// identities. That invalid state must be cleared before the keystore is used again.
    ///
    /// # Examples
    /// ```
    /// # use aether::{AetherError, InMemorySecureStorage, KeyStore, SecureStorage};
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
    /// # Ok::<(), AetherError>(())
    /// ```
    ///
    /// # Errors
    /// - [`AetherError::BackupFailed`] on Argon2id parameter error.
    /// - [`AetherError::DecryptionFailed`] on wrong passphrase or tampered ciphertext.
    /// - [`AetherError::InternalError`] on storage lock poisoning or system clock anomaly.
    /// - [`AetherError::InvalidData`] if the blob length is wrong.
    /// - [`AetherError::Storage`] on platform storage failure during commit.
    ///
    /// # Performance
    /// The backup blob is 120 bytes. Each call runs one Argon2id password hashing step using
    /// 64 MiB memory and 3 iterations.
    pub fn import_encrypted_backup(
        &self,
        data: Vec<u8>,
        passphrase: String,
    ) -> Result<(), AetherError> {
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
    /// # use aether::{AetherError, InMemorySecureStorage, KeyStore, SecureStorage};
    /// # use std::sync::Arc;
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let store = KeyStore::new(storage);
    /// if !store.has_identity()? {
    ///     store.generate_identity()?;
    /// }
    /// # Ok::<(), AetherError>(())
    /// ```
    ///
    /// # Errors
    /// - [`AetherError::InternalError`] on storage lock poisoning.
    /// - [`AetherError::Storage`] on platform storage failure.
    pub fn has_identity(&self) -> Result<bool, AetherError> {
        Ok(self.inner.has_identity()?)
    }

    /// Rotates the signed pre-key if the stored one is missing or older than the rotation window.
    ///
    /// Returns the new bundle when rotation occurred, `None` when the stored signed pre-key is
    /// still fresh.
    ///
    /// Call once at app launch. The returned signed pre-key is signed by the current discovery key,
    /// so publish it together with that discovery-key bundle — prefer
    /// [`Self::current_publication_bundle`], which returns a consistent pair atomically. `None` means
    /// the stored signed pre-key is unchanged.
    ///
    /// # Examples
    /// ```
    /// # use aether::{
    /// #     AetherError, InMemorySecureStorage, KeyStore, SecureStorage, SignedPreKeyBundle,
    /// # };
    /// # use std::sync::Arc;
    /// # fn publish_signed_prekey_bundle(_bundle: &SignedPreKeyBundle) -> Result<(), AetherError> {
    /// #     Ok(())
    /// # }
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let store = KeyStore::new(storage);
    /// # store.generate_identity()?;
    /// if let Some(new_bundle) = store.rotate_signed_prekey_if_stale()? {
    ///     publish_signed_prekey_bundle(&new_bundle)?;
    /// }
    /// # Ok::<(), AetherError>(())
    /// ```
    ///
    /// # Errors
    /// - [`AetherError::Corrupt`] if the discovery key does not verify or identity keys are incomplete.
    /// - [`AetherError::InternalError`] on storage lock poisoning or system clock anomaly.
    /// - [`AetherError::InvalidData`] if the stored signed pre-key has the wrong length or
    ///   version.
    /// - [`AetherError::NotFound`] if no identity or discovery key is stored.
    /// - [`AetherError::Storage`] on platform storage failure.
    pub fn rotate_signed_prekey_if_stale(&self) -> Result<Option<SignedPreKeyBundle>, AetherError> {
        Ok(self.inner.rotate_signed_prekey_if_stale()?.map(Into::into))
    }

    /// Rotates the signed pre-key immediately, regardless of staleness, and returns the new
    /// bundle.
    ///
    /// Use when the caller needs a fresh bundle independent of the rotation window.
    ///
    /// # Examples
    /// ```
    /// # use aether::{
    /// #     AetherError, InMemorySecureStorage, KeyStore, SecureStorage, SignedPreKeyBundle,
    /// # };
    /// # use std::sync::Arc;
    /// # fn publish_signed_prekey_bundle(_bundle: &SignedPreKeyBundle) -> Result<(), AetherError> {
    /// #     Ok(())
    /// # }
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let store = KeyStore::new(storage);
    /// # store.generate_identity()?;
    /// let new_bundle = store.rotate_signed_prekey_now()?;
    /// publish_signed_prekey_bundle(&new_bundle)?;
    /// # Ok::<(), AetherError>(())
    /// ```
    ///
    /// # Errors
    /// - [`AetherError::Corrupt`] if the discovery key does not verify or identity keys are incomplete.
    /// - [`AetherError::InternalError`] on storage lock poisoning or system clock anomaly.
    /// - [`AetherError::InvalidData`] if a stored key has the wrong byte length.
    /// - [`AetherError::NotFound`] if no identity or discovery key is stored.
    /// - [`AetherError::Storage`] on platform storage failure.
    pub fn rotate_signed_prekey_now(&self) -> Result<SignedPreKeyBundle, AetherError> {
        Ok(self.inner.rotate_signed_prekey_now()?.into())
    }

    /// Returns the currently stored signed pre-key bundle.
    ///
    /// Hand this to peers asking for the bundle they need to start a session.
    ///
    /// # Examples
    /// ```
    /// # use aether::{
    /// #     AetherError, InMemorySecureStorage, KeyStore, SecureStorage, SignedPreKeyBundle,
    /// # };
    /// # use std::sync::Arc;
    /// # fn send_bundle_to_peer(_bundle: &SignedPreKeyBundle) -> Result<(), AetherError> {
    /// #     Ok(())
    /// # }
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let store = KeyStore::new(storage);
    /// # store.generate_identity()?;
    /// # store.rotate_signed_prekey_if_stale()?;
    /// let bundle = store.current_signed_prekey_bundle()?;
    /// send_bundle_to_peer(&bundle)?;
    /// # Ok::<(), AetherError>(())
    /// ```
    ///
    /// # Errors
    /// - [`AetherError::InternalError`] on storage lock poisoning.
    /// - [`AetherError::InvalidData`] if the stored blob has the wrong length or unsupported
    ///   version.
    /// - [`AetherError::NotFound`] if no signed pre-key is stored.
    /// - [`AetherError::Storage`] on platform storage failure.
    pub fn current_signed_prekey_bundle(&self) -> Result<SignedPreKeyBundle, AetherError> {
        Ok(self.inner.current_signed_prekey_bundle()?.into())
    }

    /// Rotates the discovery key and its signed pre-key in one operation, returning both bundles.
    ///
    /// Verify [`PublicationBundle::discovery_key`] against the identity verifying key, then
    /// verify [`PublicationBundle::signed_prekey`] against the discovery key's verifying
    /// key. Publish both.
    ///
    /// # Examples
    /// ```
    /// # use aether::{
    /// #     AetherError, PublicationBundle, InMemorySecureStorage, KeyStore, SecureStorage,
    /// # };
    /// # use std::sync::Arc;
    /// # fn publish_rotation(_bundle: &PublicationBundle) -> Result<(), AetherError> {
    /// #     Ok(())
    /// # }
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let store = KeyStore::new(storage);
    /// # store.generate_identity()?;
    /// let rotation = store.rotate_discovery_key_now()?;
    /// publish_rotation(&rotation)?;
    /// # Ok::<(), AetherError>(())
    /// ```
    ///
    /// # Errors
    /// - [`AetherError::Corrupt`] if the stored discovery key does not verify against the identity.
    /// - [`AetherError::InternalError`] on storage lock poisoning, system clock anomaly, or epoch
    ///   exhaustion.
    /// - [`AetherError::InvalidData`] if a stored discovery key is malformed.
    /// - [`AetherError::NotFound`] if no identity is stored.
    /// - [`AetherError::Storage`] on platform storage failure.
    pub fn rotate_discovery_key_now(&self) -> Result<PublicationBundle, AetherError> {
        Ok(self.inner.rotate_discovery_key_now()?.into())
    }

    /// Returns the current publishable pair (discovery-key bundle + signed pre-key), atomically.
    ///
    /// Rotates the signed pre-key if stale, then reads both bundles under the keystore's lifecycle
    /// lock, so the pair always verifies as a chain. Prefer this over reading the discovery-key and
    /// signed-pre-key bundles separately, which can race a concurrent rotation into a pair the peer
    /// rejects. Publish both bundles together.
    ///
    /// # Examples
    /// ```
    /// # use aether::{AetherError, InMemorySecureStorage, KeyStore, PublicationBundle, SecureStorage};
    /// # use std::sync::Arc;
    /// # fn publish(_bundle: &PublicationBundle) -> Result<(), AetherError> { Ok(()) }
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let store = KeyStore::new(storage);
    /// # store.generate_identity()?;
    /// let publication = store.current_publication_bundle()?;
    /// publish(&publication)?;
    /// # Ok::<(), AetherError>(())
    /// ```
    ///
    /// # Errors
    /// - [`AetherError::Corrupt`] if the stored discovery key does not verify against the identity.
    /// - [`AetherError::InternalError`] on storage lock poisoning or system clock anomaly.
    /// - [`AetherError::InvalidData`] if the stored discovery key or signed pre-key is malformed.
    /// - [`AetherError::NotFound`] if no identity or discovery key is stored.
    /// - [`AetherError::Storage`] on platform storage failure.
    pub fn current_publication_bundle(&self) -> Result<PublicationBundle, AetherError> {
        Ok(self.inner.current_publication_bundle()?.into())
    }

    /// Returns the current discovery-key bundle, verified against the identity key.
    ///
    /// Publish this alongside the signed pre-key bundle so peers can verify the trust chain.
    ///
    /// # Examples
    /// ```
    /// # use aether::{AetherError, DiscoveryKeyBundle, InMemorySecureStorage, KeyStore, SecureStorage};
    /// # use std::sync::Arc;
    /// # fn send_to_peer(_bundle: &DiscoveryKeyBundle) -> Result<(), AetherError> { Ok(()) }
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let store = KeyStore::new(storage);
    /// # store.generate_identity()?;
    /// let bundle = store.current_discovery_key_bundle()?;
    /// send_to_peer(&bundle)?;
    /// # Ok::<(), AetherError>(())
    /// ```
    ///
    /// # Errors
    /// - [`AetherError::Corrupt`] if the stored discovery key does not verify against the identity.
    /// - [`AetherError::InternalError`] on storage lock poisoning.
    /// - [`AetherError::InvalidData`] if the stored discovery key is malformed.
    /// - [`AetherError::NotFound`] if no discovery key is stored.
    /// - [`AetherError::Storage`] on platform storage failure.
    pub fn current_discovery_key_bundle(&self) -> Result<DiscoveryKeyBundle, AetherError> {
        Ok(self.inner.current_discovery_key_bundle()?.into())
    }

    /// Clears the stored identity and signed pre-key material.
    ///
    /// The signed pre-key is deleted before identity keys, so a partial failure does not leave a
    /// signed pre-key attached to a missing identity. Calling this on an empty store succeeds.
    /// Calling it again after a partial failure continues deleting any remaining keys.
    ///
    /// # Examples
    /// ```
    /// # use aether::{AetherError, InMemorySecureStorage, KeyStore, SecureStorage};
    /// # use std::sync::Arc;
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let store = KeyStore::new(storage);
    /// store.reset()?;
    /// # Ok::<(), AetherError>(())
    /// ```
    ///
    /// # Errors
    /// - [`AetherError::InternalError`] on storage lock poisoning.
    /// - [`AetherError::Storage`] on platform storage failure.
    pub fn reset(&self) -> Result<(), AetherError> {
        self.inner.reset().map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::KeyStore;
    use crate::{InMemorySecureStorage, SecureStorage};
    use aether_crypto::{
        DiscoveryKeyBundle, PublicKey, Signature, SignedPreKeyBundle, VerifyingKey, verify_bundle,
        verify_discovery_key_bundle,
    };
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
    fn key_store_signs_signed_prekey_with_discovery_key() {
        let store = key_store();
        let identity = store.generate_identity().unwrap();
        assert!(
            store.rotate_signed_prekey_if_stale().unwrap().is_some(),
            "first rotate must produce a bundle"
        );

        let discovery = store.current_discovery_key_bundle().unwrap();
        assert_eq!(discovery.public_key.len(), 32);
        assert_eq!(discovery.verifying_key.len(), 32);
        assert_eq!(discovery.signature.len(), 64);

        let prekey = store.current_signed_prekey_bundle().unwrap();
        assert_eq!(prekey.public_key.len(), 32);
        assert_eq!(prekey.signature.len(), 64);
        assert!(prekey.created_at > 0);

        // The discovery key verifies under the identity; the signed pre-key verifies under the
        // discovery key. The validating parser accepts the generated wire bytes.
        let identity_verifying = VerifyingKey::from_bytes(
            &<[u8; 32]>::try_from(identity.verifying_key.as_slice()).unwrap(),
        )
        .unwrap();
        let crypto_discovery = DiscoveryKeyBundle::from_bytes(
            &discovery.public_key,
            &discovery.verifying_key,
            &discovery.signature,
            discovery.epoch,
            discovery.created_at,
        )
        .unwrap();
        assert!(verify_discovery_key_bundle(&crypto_discovery, &identity_verifying).is_ok());

        let crypto_prekey = SignedPreKeyBundle {
            public_key: PublicKey::from(
                <[u8; 32]>::try_from(prekey.public_key.as_slice()).unwrap(),
            ),
            signature: Signature::from_bytes(
                &<[u8; 64]>::try_from(prekey.signature.as_slice()).unwrap(),
            ),
            created_at: prekey.created_at,
        };
        assert!(verify_bundle(&crypto_prekey, &crypto_discovery.verifying_key).is_ok());
    }

    #[test]
    fn rotate_discovery_key_now_returns_verifiable_bundles() {
        let store = key_store();
        let identity = store.generate_identity().unwrap();
        let rotation = store.rotate_discovery_key_now().unwrap();
        assert_eq!(rotation.discovery_key.public_key.len(), 32);
        assert_eq!(rotation.discovery_key.verifying_key.len(), 32);
        assert_eq!(rotation.discovery_key.signature.len(), 64);
        assert_eq!(rotation.signed_prekey.public_key.len(), 32);
        assert_eq!(rotation.signed_prekey.signature.len(), 64);

        let identity_verifying = VerifyingKey::from_bytes(
            &<[u8; 32]>::try_from(identity.verifying_key.as_slice()).unwrap(),
        )
        .unwrap();
        let crypto_discovery = DiscoveryKeyBundle::from_bytes(
            &rotation.discovery_key.public_key,
            &rotation.discovery_key.verifying_key,
            &rotation.discovery_key.signature,
            rotation.discovery_key.epoch,
            rotation.discovery_key.created_at,
        )
        .unwrap();
        assert!(verify_discovery_key_bundle(&crypto_discovery, &identity_verifying).is_ok());

        let crypto_prekey = SignedPreKeyBundle {
            public_key: PublicKey::from(
                <[u8; 32]>::try_from(rotation.signed_prekey.public_key.as_slice()).unwrap(),
            ),
            signature: Signature::from_bytes(
                &<[u8; 64]>::try_from(rotation.signed_prekey.signature.as_slice()).unwrap(),
            ),
            created_at: rotation.signed_prekey.created_at,
        };
        assert!(verify_bundle(&crypto_prekey, &crypto_discovery.verifying_key).is_ok());
    }

    #[test]
    fn current_publication_bundle_returns_verifiable_chain() {
        let store = key_store();
        let identity = store.generate_identity().unwrap();
        let publication = store.current_publication_bundle().unwrap();
        assert_eq!(publication.discovery_key.public_key.len(), 32);
        assert_eq!(publication.signed_prekey.public_key.len(), 32);

        let identity_verifying = VerifyingKey::from_bytes(
            &<[u8; 32]>::try_from(identity.verifying_key.as_slice()).unwrap(),
        )
        .unwrap();
        let crypto_discovery = DiscoveryKeyBundle::from_bytes(
            &publication.discovery_key.public_key,
            &publication.discovery_key.verifying_key,
            &publication.discovery_key.signature,
            publication.discovery_key.epoch,
            publication.discovery_key.created_at,
        )
        .unwrap();
        assert!(verify_discovery_key_bundle(&crypto_discovery, &identity_verifying).is_ok());

        let crypto_prekey = SignedPreKeyBundle {
            public_key: PublicKey::from(
                <[u8; 32]>::try_from(publication.signed_prekey.public_key.as_slice()).unwrap(),
            ),
            signature: Signature::from_bytes(
                &<[u8; 64]>::try_from(publication.signed_prekey.signature.as_slice()).unwrap(),
            ),
            created_at: publication.signed_prekey.created_at,
        };
        assert!(verify_bundle(&crypto_prekey, &crypto_discovery.verifying_key).is_ok());
    }
}
