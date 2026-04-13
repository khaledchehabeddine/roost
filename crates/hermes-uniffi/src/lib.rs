uniffi::setup_scaffolding!("hermes");

use hermes_core::{IdentityError, SecureStorage as CoreSecureStorage, StorageError};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

/// FFI-visible identity snapshot returned by [`IdentityManager`].
#[derive(uniffi::Record)]
pub struct Identity {
    /// X25519 public key bytes (32 bytes).
    pub public_key: Vec<u8>,
    /// Ed25519 verifying key bytes (32 bytes).
    pub verifying_key: Vec<u8>,
}

/// Errors surfaced across the FFI boundary.
#[derive(Debug, uniffi::Error)]
pub enum HermesError {
    AlreadyExists,
    BackupFailed { reason: String },
    Corrupt,
    DecryptionFailed,
    InternalError { reason: String },
    InvalidData { reason: String },
    NotFound,
    Storage { reason: String },
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

impl From<StorageError> for HermesError {
    fn from(e: StorageError) -> Self {
        HermesError::Storage {
            reason: e.to_string(),
        }
    }
}

/// Platform storage abstraction exposed to Swift and Kotlin.
///
/// Implement this trait to provide [`IdentityManager`] with platform-specific secure storage
/// (e.g., iOS Keychain, Android Keystore).
///
/// # Secret material
///
/// `value` in `store` and the return of `load` carry secret key bytes as bare `Vec<u8>` because
/// UniFFI does not support `Zeroizing<Vec<u8>>`. On the Rust side, the `SecureStorageAdapter`
/// wraps loaded values in `Zeroizing` immediately. Platform implementations should treat these
/// bytes as sensitive and avoid unnecessary copies.
#[uniffi::export(with_foreign)]
pub trait SecureStorage: Send + Sync {
    fn store(&self, key: String, value: Vec<u8>) -> Result<(), HermesError>;
    fn load(&self, key: String) -> Result<Option<Vec<u8>>, HermesError>;
    fn delete(&self, key: String) -> Result<(), HermesError>;
}

/// Bridges an FFI [`SecureStorage`] into the core's [`SecureStorage`](CoreSecureStorage) trait.
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

/// In-memory secure storage for use in proofs-of-concept and tests.
///
/// Not suitable for production — data is not persisted and has no platform security guarantees.
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
    #[uniffi::constructor]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(hermes_core::InMemorySecureStorage::new()),
        }
    }
}

#[uniffi::export]
impl SecureStorage for InMemorySecureStorage {
    fn store(&self, key: String, value: Vec<u8>) -> Result<(), HermesError> {
        self.inner
            .lock()
            .map_err(|_| HermesError::InternalError {
                reason: "storage lock poisoned".into(),
            })?
            .store(&key, &value)?;
        Ok(())
    }

    fn load(&self, key: String) -> Result<Option<Vec<u8>>, HermesError> {
        let result = self
            .inner
            .lock()
            .map_err(|_| HermesError::InternalError {
                reason: "storage lock poisoned".into(),
            })?
            .load(&key)?;
        Ok(result.map(|z| z.to_vec()))
    }

    fn delete(&self, key: String) -> Result<(), HermesError> {
        self.inner
            .lock()
            .map_err(|_| HermesError::InternalError {
                reason: "storage lock poisoned".into(),
            })?
            .delete(&key)?;
        Ok(())
    }
}

/// Manages creation and retrieval of the local Hermes identity over the FFI boundary.
#[derive(uniffi::Object)]
pub struct IdentityManager {
    inner: hermes_core::IdentityManager,
}

#[uniffi::export]
impl IdentityManager {
    /// Constructs a new `IdentityManager` backed by the given storage.
    #[uniffi::constructor]
    pub fn new(storage: Arc<dyn SecureStorage>) -> Self {
        Self {
            inner: hermes_core::IdentityManager::new(Box::new(SecureStorageAdapter { storage })),
        }
    }

    /// Generates a new identity and persists it to storage.
    pub fn generate_identity(&self) -> Result<Identity, HermesError> {
        let id = self.inner.generate_identity()?;
        Ok(Identity {
            public_key: id.public_key().as_bytes().to_vec(),
            verifying_key: id.verifying_key().as_bytes().to_vec(),
        })
    }

    /// Loads the existing identity from storage.
    pub fn load_identity(&self) -> Result<Identity, HermesError> {
        let id = self.inner.load_identity()?;
        Ok(Identity {
            public_key: id.public_key().as_bytes().to_vec(),
            verifying_key: id.verifying_key().as_bytes().to_vec(),
        })
    }

    /// Exports the current identity as an encrypted backup blob.
    pub fn export_encrypted_backup(&self, passphrase: String) -> Result<Vec<u8>, HermesError> {
        Ok(self.inner.export_encrypted_backup(&passphrase)?)
    }

    /// Imports an identity from an encrypted backup blob.
    pub fn import_encrypted_backup(
        &self,
        data: Vec<u8>,
        passphrase: String,
    ) -> Result<(), HermesError> {
        Ok(self.inner.import_encrypted_backup(&data, &passphrase)?)
    }
}
