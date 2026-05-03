//! UniFFI bindings for the cryptographic core.
//!
//! This crate exposes the storage-backed identity API that UniFFI projects into foreign-language
//! bindings. Consumers construct a single [`KeyStore`], provide a platform [`SecureStorage`]
//! implementation, and use the keystore to manage the local identity and signed pre-key.
//!
//! # Overview
//!
//! [`KeyStore`] is the entry point for identity and signed-pre-key operations. It delegates
//! persistence to [`SecureStorage`], which production apps must back with secure storage.
//!
//! # Examples
//!
//! ```
//! use hermes::{
//!     HermesError, InMemorySecureStorage, KeyStore, SecureStorage, SignedPreKeyBundle,
//! };
//! use std::sync::Arc;
//!
//! # fn publish_signed_prekey_bundle(_bundle: &SignedPreKeyBundle) -> Result<(), HermesError> {
//! #     Ok(())
//! # }
//! let storage: Arc<dyn SecureStorage> = Arc::new(InMemorySecureStorage::new());
//! let store = KeyStore::new(storage);
//!
//! if !store.has_identity()? {
//!     store.generate_identity()?;
//! }
//!
//! if let Some(new_bundle) = store.rotate_signed_prekey_if_stale()? {
//!     publish_signed_prekey_bundle(&new_bundle)?;
//! }
//! # Ok::<(), HermesError>(())
//! ```
//!
//! # Key Concepts
//!
//! - Construct one [`KeyStore`] per app and retain it for the application lifetime.
//! - [`SecureStorage`] is the platform hook. Production builds must back it with their own secure
//!   storage implementation. [`InMemorySecureStorage`] is only for tests and prototypes.
//! - All fallible methods return [`HermesError`].

uniffi::setup_scaffolding!("hermes");

use hermes_core::{
    Identity as CoreIdentity, IdentityError, KeyStore as CoreKeyStore, KeyStoreError,
    SecureStorage as CoreSecureStorage, SignedPreKeyError, StorageError,
};
use hermes_crypto::SignedPreKeyBundle as CoreSignedPreKeyBundle;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

/// Errors surfaced across the UniFFI boundary.
///
/// Variants group storage, identity, backup, and internal failures returned through generated
/// bindings. `reason` fields are diagnostic strings for logs and must not drive application
/// logic.
#[derive(Debug, uniffi::Error)]
pub enum HermesError {
    /// An identity already exists in storage.
    AlreadyExists,
    /// Encrypted backup creation failed during randomness, key derivation, or encryption.
    BackupFailed {
        /// Diagnostic failure context for logs only.
        reason: String,
    },
    /// Stored identity keys are incomplete.
    Corrupt,
    /// Backup decryption failed because the passphrase or backup bytes did not authenticate.
    DecryptionFailed,
    /// Internal failure that does not expose a more specific failure category.
    InternalError {
        /// Diagnostic context for logging only.
        reason: String,
    },
    /// Input bytes are malformed or the wrong length.
    InvalidData {
        /// Description of what was invalid for logging only.
        reason: String,
    },
    /// Requested identity or signed pre-key material is not stored.
    NotFound,
    /// Underlying [`SecureStorage`] returned a platform error.
    Storage {
        /// Platform-specific error message from the underlying [`SecureStorage`] implementation.
        reason: String,
    },
}

impl std::fmt::Display for HermesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HermesError::AlreadyExists => write!(f, "identity already exists"),
            HermesError::BackupFailed { reason } => write!(f, "backup failed: {reason}"),
            HermesError::Corrupt => write!(f, "identity data is corrupt"),
            HermesError::DecryptionFailed => write!(f, "decryption failed"),
            HermesError::InternalError { reason } => write!(f, "internal error: {reason}"),
            HermesError::InvalidData { reason } => write!(f, "invalid data: {reason}"),
            HermesError::NotFound => write!(f, "no identity found"),
            HermesError::Storage { reason } => write!(f, "storage error: {reason}"),
        }
    }
}

impl std::error::Error for HermesError {}

impl From<IdentityError> for HermesError {
    fn from(e: IdentityError) -> Self {
        match e {
            IdentityError::AlreadyExists => HermesError::AlreadyExists,
            IdentityError::BackupFailed(reason) => HermesError::BackupFailed { reason },
            IdentityError::Corrupt => HermesError::Corrupt,
            IdentityError::DecryptionFailed => HermesError::DecryptionFailed,
            IdentityError::InvalidData(reason) => HermesError::InvalidData { reason },
            IdentityError::LockPoisoned => HermesError::InternalError {
                reason: "internal lock poisoned".into(),
            },
            IdentityError::NotFound => HermesError::NotFound,
            IdentityError::Storage(e) => HermesError::Storage {
                reason: e.to_string(),
            },
        }
    }
}

impl From<SignedPreKeyError> for HermesError {
    fn from(e: SignedPreKeyError) -> Self {
        match e {
            SignedPreKeyError::Clock => HermesError::InternalError {
                reason: "system clock is before Unix epoch".into(),
            },
            SignedPreKeyError::Identity(e) => e.into(),
            SignedPreKeyError::InvalidData(reason) => HermesError::InvalidData { reason },
            SignedPreKeyError::LockPoisoned => HermesError::InternalError {
                reason: "internal lock poisoned".into(),
            },
            SignedPreKeyError::NotFound => HermesError::NotFound,
            SignedPreKeyError::Storage(e) => e.into(),
        }
    }
}

impl From<StorageError> for HermesError {
    fn from(e: StorageError) -> Self {
        HermesError::Storage {
            reason: e.to_string(),
        }
    }
}

impl From<KeyStoreError> for HermesError {
    fn from(e: KeyStoreError) -> Self {
        match e {
            KeyStoreError::Identity(e) => e.into(),
            KeyStoreError::SignedPreKey(e) => e.into(),
        }
    }
}

/// Identity material exposed through UniFFI.
///
/// Contains only public key material. It is safe to cache and send to peers.
#[derive(uniffi::Record)]
pub struct Identity {
    /// X25519 public key bytes. Always 32 bytes.
    pub public_key: Vec<u8>,
    /// Ed25519 verifying key bytes. Always 32 bytes.
    pub verifying_key: Vec<u8>,
}

impl From<CoreIdentity> for Identity {
    fn from(id: CoreIdentity) -> Self {
        Identity {
            public_key: id.public_key().as_bytes().to_vec(),
            verifying_key: id.verifying_key().as_bytes().to_vec(),
        }
    }
}

/// Public signed pre-key material a peer uses to start a session with this identity.
///
/// The owning identity signs [`SignedPreKeyBundle::public_key`] with its Ed25519 key. The identity
/// verifying key is not embedded. Verifiers retrieve it separately and pass it alongside this
/// bundle.
#[derive(uniffi::Record)]
pub struct SignedPreKeyBundle {
    /// X25519 public key bytes. Always 32 bytes.
    pub public_key: Vec<u8>,
    /// Ed25519 signature over `public_key`. Always 64 bytes.
    pub signature: Vec<u8>,
    /// Unix timestamp in seconds when this signed pre-key was generated.
    pub created_at: u64,
}

impl From<CoreSignedPreKeyBundle> for SignedPreKeyBundle {
    fn from(b: CoreSignedPreKeyBundle) -> Self {
        SignedPreKeyBundle {
            public_key: b.public_key.as_bytes().to_vec(),
            signature: b.signature.to_bytes().to_vec(),
            created_at: b.created_at,
        }
    }
}

/// Platform secure-storage boundary used by [`KeyStore`].
///
/// Implementations must persist bytes in platform secure storage, not plain files or temporary
/// process memory. Values returned from [`SecureStorage::load`] contain secret material and must
/// be treated as sensitive until overwritten or released.
///
/// `value` and `load` cross UniFFI as bare `Vec<u8>` because UniFFI does not support
/// [`Zeroizing`]. Rust wraps loaded values immediately after they cross this boundary.
///
/// # Implementation
///
/// Methods are called synchronously from Rust. Return [`HermesError::Storage`] for platform
/// failures instead of panicking.
///
/// See [`InMemorySecureStorage`] for a reference implementation suitable for tests.
#[uniffi::export(with_foreign)]
pub trait SecureStorage: Send + Sync {
    /// Stores `value` under `key`, overwriting any existing entry.
    ///
    /// # Errors
    /// - [`HermesError::Storage`] when platform storage returns an error.
    fn store(&self, key: String, value: Vec<u8>) -> Result<(), HermesError>;

    /// Returns the value stored under `key`, or `None` if not present.
    ///
    /// # Errors
    /// - [`HermesError::Storage`] when platform storage returns an error.
    fn load(&self, key: String) -> Result<Option<Vec<u8>>, HermesError>;

    /// Removes the value stored under `key`. Missing keys are treated as success.
    ///
    /// # Errors
    /// - [`HermesError::Storage`] when platform storage returns an error.
    fn delete(&self, key: String) -> Result<(), HermesError>;
}

/// In-memory secure storage for use in proofs-of-concept and tests.
///
/// Not suitable for production.
#[derive(uniffi::Object)]
pub struct InMemorySecureStorage {
    inner: Mutex<hermes_core::InMemorySecureStorage>,
}

impl Default for InMemorySecureStorage {
    fn default() -> Self {
        Self::new()
    }
}

#[uniffi::export]
impl InMemorySecureStorage {
    /// Creates an empty in-memory storage instance for use in tests and prototypes.
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(hermes_core::InMemorySecureStorage::new()),
        }
    }
}

impl InMemorySecureStorage {
    fn lock_inner(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, hermes_core::InMemorySecureStorage>, HermesError> {
        self.inner.lock().map_err(|_| HermesError::InternalError {
            reason: "storage lock poisoned".into(),
        })
    }
}

#[uniffi::export]
impl SecureStorage for InMemorySecureStorage {
    fn store(&self, key: String, value: Vec<u8>) -> Result<(), HermesError> {
        Ok(self.lock_inner()?.store(&key, &value)?)
    }

    fn load(&self, key: String) -> Result<Option<Vec<u8>>, HermesError> {
        Ok(self.lock_inner()?.load(&key)?.map(|z| z.to_vec()))
    }

    fn delete(&self, key: String) -> Result<(), HermesError> {
        Ok(self.lock_inner()?.delete(&key)?)
    }
}

// Bridges a client SecureStorage implementation into the core storage trait.
struct SecureStorageAdapter {
    storage: Arc<dyn SecureStorage>,
}

impl CoreSecureStorage for SecureStorageAdapter {
    fn store(&mut self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        self.storage
            .store(key.to_string(), value.to_vec())
            .map_err(|e| StorageError::IO(e.to_string()))
    }

    fn load(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, StorageError> {
        self.storage
            .load(key.to_string())
            .map(|opt| opt.map(Zeroizing::new))
            .map_err(|e| StorageError::IO(e.to_string()))
    }

    fn delete(&mut self, key: &str) -> Result<(), StorageError> {
        self.storage
            .delete(key.to_string())
            .map_err(|e| StorageError::IO(e.to_string()))
    }
}

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
            inner: CoreKeyStore::new(Box::new(SecureStorageAdapter { storage })),
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
    /// # let store = KeyStore::new(Arc::new(InMemorySecureStorage::new()) as Arc<dyn SecureStorage>);
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
    /// # let store = KeyStore::new(Arc::new(InMemorySecureStorage::new()) as Arc<dyn SecureStorage>);
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
    /// # let store = KeyStore::new(Arc::new(InMemorySecureStorage::new()) as Arc<dyn SecureStorage>);
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
    /// # let store = KeyStore::new(Arc::new(InMemorySecureStorage::new()) as Arc<dyn SecureStorage>);
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
    /// # let store = KeyStore::new(Arc::new(InMemorySecureStorage::new()) as Arc<dyn SecureStorage>);
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
    /// # let store = KeyStore::new(Arc::new(InMemorySecureStorage::new()) as Arc<dyn SecureStorage>);
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
    /// # let store = KeyStore::new(Arc::new(InMemorySecureStorage::new()) as Arc<dyn SecureStorage>);
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
    /// # let store = KeyStore::new(Arc::new(InMemorySecureStorage::new()) as Arc<dyn SecureStorage>);
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
    use super::*;
    use hermes_crypto::{PublicKey, Signature, SignedPreKeyBundle, VerifyingKey, verify_bundle};

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
