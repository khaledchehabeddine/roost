//! UniFFI keystore object exposing identity, discovery-key, and signed-pre-key operations.

use crate::SecureStorage;
use crate::error::AetherError;
use crate::records::{
    DiscoveryKeyBundle, Identity, OneTimePreKeyBundle, PublicationBundle, SignedPreKeyBundle,
};
use crate::storage::SecureStorageAdapter;
use aether_core::KeyStore as CoreKeyStore;
use std::sync::Arc;

/// Entry point for local identity, discovery-key, and signed-pre-key state.
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
    /// - [`AetherError::AlreadyExists`] if complete identity and discovery-key material already
    ///   exist.
    /// - [`AetherError::Corrupt`] if stored identity key material is incomplete.
    /// - [`AetherError::InternalError`] on storage lock poisoning or system clock anomaly.
    /// - [`AetherError::InvalidData`] if stored discovery-key or identity bytes are malformed.
    /// - [`AetherError::Storage`] if platform storage returns an error.
    pub fn generate_identity(&self) -> Result<Identity, AetherError> {
        Ok(Identity::from_core(self.inner.generate_identity()?)?)
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
        Ok(Identity::from_core(self.inner.load_identity()?)?)
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

    /// Returns the current discovery-key bundle, verified against the identity key.
    ///
    /// Publish this alongside the signed pre-key bundle so peers can verify the trust chain.
    ///
    /// # Examples
    /// ```
    /// # use aether::{
    /// #     AetherError, DiscoveryKeyBundle, InMemorySecureStorage, KeyStore, SecureStorage
    /// # };
    /// # use std::sync::Arc;
    /// # fn send_to_peer(_bundle: &DiscoveryKeyBundle) -> Result<(), AetherError> {
    /// #     Ok(())
    /// # }
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let store = KeyStore::new(storage);
    /// # store.generate_identity()?;
    /// let bundle = store.current_discovery_key_bundle()?;
    /// send_to_peer(&bundle)?;
    /// # Ok::<(), AetherError>(())
    /// ```
    ///
    /// # Errors
    /// - [`AetherError::Corrupt`] if the stored discovery key does not verify or identity keys are
    ///   incomplete.
    /// - [`AetherError::InternalError`] on storage lock poisoning.
    /// - [`AetherError::InvalidData`] if stored discovery-key or identity bytes are malformed.
    /// - [`AetherError::NotFound`] if no identity or discovery key is stored.
    /// - [`AetherError::Storage`] on platform storage failure.
    pub fn current_discovery_key_bundle(&self) -> Result<DiscoveryKeyBundle, AetherError> {
        Ok(self.inner.current_discovery_key_bundle()?.into())
    }

    /// Returns the current publishable pair (discovery-key bundle + signed pre-key), atomically.
    ///
    /// Returns caller-created bundles that verify as a chain. Prefer this over reading the
    /// discovery-key and signed-pre-key bundles separately, which can race a concurrent rotation
    /// into a pair the peer rejects. Publish both bundles together.
    ///
    /// # Examples
    /// ```
    /// # use aether::{
    /// #     AetherError, InMemorySecureStorage, KeyStore, PublicationBundle, SecureStorage
    /// # };
    /// # use std::sync::Arc;
    /// # fn publish(_bundle: &PublicationBundle) -> Result<(), AetherError> {
    /// #     Ok(())
    /// # }
    /// # let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
    /// # let store = KeyStore::new(storage);
    /// # store.generate_identity()?;
    /// # store.rotate_signed_prekey_now()?;
    /// let publication = store.current_publication_bundle()?;
    /// publish(&publication)?;
    /// # Ok::<(), AetherError>(())
    /// ```
    ///
    /// # Errors
    /// - [`AetherError::Corrupt`] if stored key material does not verify as a chain.
    /// - [`AetherError::InternalError`] on storage lock poisoning or system clock anomaly.
    /// - [`AetherError::InvalidData`] if stored discovery-key, signed-pre-key, or identity bytes
    ///   are malformed.
    /// - [`AetherError::NotFound`] if no identity, discovery key, or signed pre-key is stored.
    /// - [`AetherError::Storage`] on platform storage failure.
    pub fn current_publication_bundle(&self) -> Result<PublicationBundle, AetherError> {
        Ok(self.inner.current_publication_bundle()?.into())
    }

    /// Generates exactly `batch_size` one-time pre-keys for the current discovery-key epoch.
    ///
    /// The returned records contain only public material. The secret halves remain in secure
    /// storage and are consumed by Rust when accepting a matching X3DH first message.
    ///
    /// # Errors
    /// - [`AetherError::InternalError`] on storage lock poisoning or system clock anomaly.
    /// - [`AetherError::InvalidData`] if stored one-time-pre-key data is malformed or the batch
    ///   exceeds capacity.
    /// - [`AetherError::NotFound`] if no identity or discovery key is stored.
    /// - [`AetherError::Storage`] on platform storage failure.
    pub fn generate_one_time_prekeys(
        &self,
        batch_size: u32,
    ) -> Result<Vec<OneTimePreKeyBundle>, AetherError> {
        Ok(self
            .inner
            .generate_one_time_prekeys(batch_size as usize)?
            .into_iter()
            .map(Into::into)
            .collect())
    }

    /// Rotates the discovery key and signed pre-key together, returning both bundles.
    ///
    /// The discovery-key and signed-pre-key rotations are one operation. Stored one-time pre-keys
    /// are cleared before the discovery-key epoch advances. Publish both returned bundles together
    /// so peers can verify the full trust chain.
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
    /// - [`AetherError::Corrupt`] if the discovery key cannot be verified while creating the
    ///   signed pre-key.
    /// - [`AetherError::InternalError`] on storage lock poisoning or system clock anomaly.
    /// - [`AetherError::InvalidData`] if stored discovery-key or identity bytes are malformed.
    /// - [`AetherError::NotFound`] if no identity is stored.
    /// - [`AetherError::Storage`] on platform storage failure.
    pub fn rotate_discovery_key_now(&self) -> Result<PublicationBundle, AetherError> {
        Ok(self.inner.rotate_discovery_key_now()?.into())
    }

    /// Rotates the signed pre-key if the stored one is missing or older than the rotation window.
    ///
    /// Returns the new bundle when rotation occurred, `None` when the stored signed pre-key is
    /// still fresh.
    ///
    /// Call once at app launch. The returned signed pre-key is signed by the current discovery
    /// key, so publish it together with that discovery-key bundle. Prefer
    /// [`Self::current_publication_bundle`] when publishing both keys. `None` means the stored
    /// signed pre-key is unchanged.
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
    /// - [`AetherError::Corrupt`] if the discovery key does not verify or identity keys are
    ///   incomplete.
    /// - [`AetherError::InternalError`] on storage lock poisoning or system clock anomaly.
    /// - [`AetherError::InvalidData`] if stored signed-pre-key, discovery-key, or identity bytes are
    ///   malformed.
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
    /// - [`AetherError::Corrupt`] if the discovery key does not verify or identity keys are
    ///   incomplete.
    /// - [`AetherError::InternalError`] on storage lock poisoning or system clock anomaly.
    /// - [`AetherError::InvalidData`] if stored discovery-key or identity bytes are malformed.
    /// - [`AetherError::NotFound`] if no identity or discovery key is stored.
    /// - [`AetherError::Storage`] on platform storage failure.
    pub fn rotate_signed_prekey_now(&self) -> Result<SignedPreKeyBundle, AetherError> {
        Ok(self.inner.rotate_signed_prekey_now()?.into())
    }

    /// Exports the current identity and discovery key as a passphrase-encrypted blob.
    ///
    /// The blob is portable across devices: pass it to another keystore's
    /// [`Self::import_encrypted_backup`] with the same `passphrase` to restore the same identity
    /// and discovery-epoch lineage.
    ///
    /// Requires a stored discovery key; if it is missing, regenerate the identity with
    /// [`Self::generate_identity`] (which repairs the discovery key) before exporting.
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
    /// - [`AetherError::NotFound`] if no identity or discovery key is stored.
    /// - [`AetherError::Storage`] on platform storage failure when loading an identity.
    ///
    /// # Performance
    /// The backup blob is about 274 bytes: a versioned header carrying the Argon2id parameters,
    /// followed by the encrypted identity and discovery keys. Each call runs one Argon2id password
    /// hashing step using 64 MiB memory and 3 iterations.
    pub fn export_encrypted_backup(&self, passphrase: String) -> Result<Vec<u8>, AetherError> {
        Ok(self.inner.export_encrypted_backup(&passphrase)?)
    }

    /// Restores an identity from an encrypted backup, replacing any current identity.
    ///
    /// The backup is decrypted and the restored discovery key validated before storage changes
    /// begin, so a wrong passphrase or malformed blob leaves the existing identity untouched. On
    /// success, the restored identity keeps the discovery key and epoch lineage carried by the
    /// backup and has no one-time pre-keys or signed pre-key. Call
    /// [`Self::rotate_signed_prekey_if_stale`] before publishing.
    ///
    /// Storage failures can happen after writes begin and may leave incomplete key material. Call
    /// [`Self::reset`] before using the keystore again after a failed import.
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
    /// - [`AetherError::InternalError`] on storage lock poisoning.
    /// - [`AetherError::InvalidData`] on a malformed header, unsupported version, below-floor
    ///   Argon2id parameters, or a malformed discovery-key blob.
    /// - [`AetherError::Storage`] on platform storage failure during commit.
    ///
    /// # Performance
    /// The backup blob is about 274 bytes: a versioned header carrying the Argon2id parameters,
    /// followed by the encrypted identity and discovery keys. Each call runs one Argon2id password
    /// hashing step using 64 MiB memory and 3 iterations.
    pub fn import_encrypted_backup(
        &self,
        data: Vec<u8>,
        passphrase: String,
    ) -> Result<(), AetherError> {
        self.inner
            .import_encrypted_backup(&data, &passphrase)
            .map_err(Into::into)
    }

    /// Clears the stored one-time pre-keys, signed pre-key, discovery-key, and identity material.
    ///
    /// Deletion runs dependents-first, so a partial failure does not leave newer key material
    /// attached to a missing identity. Calling this on an empty store succeeds. Calling it again
    /// after a partial failure continues deleting any remaining keys.
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
    use crate::{
        InMemorySecureStorage, SecureStorage,
        records::{
            DiscoveryKeyBundle as FfiDiscoveryKeyBundle, Identity as FfiIdentity,
            OneTimePreKeyBundle as FfiOneTimePreKeyBundle,
            PublicationBundle as FfiPublicationBundle, SignedPreKeyBundle as FfiSignedPreKeyBundle,
        },
    };
    use aether_crypto::{
        DiscoveryKeyBundle as CryptoDiscoveryKeyBundle,
        IdentityKeyBundle as CryptoIdentityKeyBundle, PublicKey, Signature,
        SignedPreKeyBundle as CryptoSignedPreKeyBundle, VerifyingKey, verify_discovery_key_bundle,
        verify_identity_key_bundle, verify_signed_prekey_bundle,
    };
    use std::sync::Arc;

    fn key_store() -> Arc<KeyStore> {
        let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
        KeyStore::new(storage)
    }

    fn verifying_key(identity: &FfiIdentity) -> VerifyingKey {
        VerifyingKey::from_bytes(
            &<[u8; 32]>::try_from(identity.ed25519_verifying_key.as_slice()).unwrap(),
        )
        .unwrap()
    }

    fn identity_bundle(identity: &FfiIdentity) -> CryptoIdentityKeyBundle {
        CryptoIdentityKeyBundle::from_bytes(
            &identity.x25519_public_key,
            &identity.ed25519_verifying_key,
            &identity.identity_binding_signature,
        )
        .unwrap()
    }

    fn discovery_bundle(bundle: &FfiDiscoveryKeyBundle) -> CryptoDiscoveryKeyBundle {
        CryptoDiscoveryKeyBundle::from_bytes(
            &bundle.public_key,
            &bundle.verifying_key,
            bundle.epoch,
            bundle.created_at,
            &bundle.signature,
        )
        .unwrap()
    }

    fn signed_prekey_bundle(bundle: &FfiSignedPreKeyBundle) -> CryptoSignedPreKeyBundle {
        CryptoSignedPreKeyBundle {
            public_key: PublicKey::from(
                <[u8; 32]>::try_from(bundle.public_key.as_slice()).unwrap(),
            ),
            signature: Signature::from_bytes(
                &<[u8; 64]>::try_from(bundle.signature.as_slice()).unwrap(),
            ),
            epoch: bundle.epoch,
            created_at: bundle.created_at,
        }
    }

    fn assert_discovery_key_verifies(
        identity: &FfiIdentity,
        discovery: &FfiDiscoveryKeyBundle,
    ) -> CryptoDiscoveryKeyBundle {
        let crypto_discovery = discovery_bundle(discovery);
        assert!(verify_discovery_key_bundle(&crypto_discovery, &verifying_key(identity)).is_ok());
        crypto_discovery
    }

    fn assert_signed_prekey_verifies(
        signed_prekey: &FfiSignedPreKeyBundle,
        discovery: &CryptoDiscoveryKeyBundle,
    ) {
        let crypto_prekey = signed_prekey_bundle(signed_prekey);
        assert!(verify_signed_prekey_bundle(&crypto_prekey, &discovery.verifying_key).is_ok());
    }

    fn assert_publication_verifies(identity: &FfiIdentity, publication: &FfiPublicationBundle) {
        assert_eq!(publication.version, aether_crypto::PREKEY_BUNDLE_VERSION);
        let discovery = assert_discovery_key_verifies(identity, &publication.discovery_key);
        assert_signed_prekey_verifies(&publication.signed_prekey, &discovery);
    }

    fn assert_one_time_prekey_record(bundle: &FfiOneTimePreKeyBundle, epoch: u32) {
        assert_eq!(bundle.public_key.len(), 32);
        assert_eq!(bundle.epoch, epoch);
    }

    #[test]
    fn generate_identity_returns_ffi_safe_public_keys() {
        let store = key_store();
        let identity = store.generate_identity().unwrap();
        assert_eq!(identity.x25519_public_key.len(), 32);
        assert_eq!(identity.ed25519_verifying_key.len(), 32);
        assert_eq!(identity.identity_binding_signature.len(), 64);
        verifying_key(&identity);
        assert!(verify_identity_key_bundle(&identity_bundle(&identity)).is_ok());
    }

    #[test]
    fn rotate_signed_prekey_if_stale_returns_verifiable_record() {
        let store = key_store();
        let identity = store.generate_identity().unwrap();
        let signed_prekey = store
            .rotate_signed_prekey_if_stale()
            .unwrap()
            .expect("first rotate must produce a bundle");
        let discovery = store.current_discovery_key_bundle().unwrap();
        let crypto_discovery = assert_discovery_key_verifies(&identity, &discovery);
        assert_signed_prekey_verifies(&signed_prekey, &crypto_discovery);
    }

    #[test]
    fn current_publication_bundle_returns_verifiable_records() {
        let store = key_store();
        let identity = store.generate_identity().unwrap();
        store.rotate_signed_prekey_now().unwrap();
        let publication = store.current_publication_bundle().unwrap();
        assert_publication_verifies(&identity, &publication);
    }

    #[test]
    fn generate_one_time_prekeys_returns_public_records() {
        let store = key_store();
        store.generate_identity().unwrap();
        let discovery = store.current_discovery_key_bundle().unwrap();
        let bundles = store.generate_one_time_prekeys(3).unwrap();

        assert_eq!(bundles.len(), 3);
        assert_eq!(
            bundles.iter().map(|bundle| bundle.id).collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        for bundle in &bundles {
            assert_one_time_prekey_record(bundle, discovery.epoch);
        }
    }

    #[test]
    fn rotate_discovery_key_now_advances_epoch_and_returns_verifiable_records() {
        let store = key_store();
        let identity = store.generate_identity().unwrap();
        let initial_discovery = store.current_discovery_key_bundle().unwrap();
        let rotation = store.rotate_discovery_key_now().unwrap();
        assert_eq!(rotation.discovery_key.epoch, initial_discovery.epoch + 1);
        assert_publication_verifies(&identity, &rotation);
    }
}
