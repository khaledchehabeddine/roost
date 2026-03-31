uniffi::setup_scaffolding!("hermes");

use hermes_core::{IdentityError, SecureStorage, StorageError};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

/// FFI-visible identity snapshot returned by [`IdentityManager`].
#[derive(uniffi::Record)]
pub struct Identity {
    /// X25519 public key bytes (32 bytes).
    pub public_key: Vec<u8>,
}

/// Errors surfaced across the FFI boundary.
#[derive(Debug, uniffi::Error)]
pub enum HermesError {
    AlreadyExists,
    NotFound,
    Corrupt,
    DecryptionFailed,
    BackupFailed { reason: String },
    InvalidData { reason: String },
    Storage { reason: String },
}

impl std::fmt::Display for HermesError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HermesError::AlreadyExists => write!(f, "identity already exists"),
            HermesError::NotFound => write!(f, "no identity found"),
            HermesError::Corrupt => write!(f, "identity data is corrupt"),
            HermesError::DecryptionFailed => write!(f, "decryption failed"),
            HermesError::BackupFailed { reason } => write!(f, "backup failed: {reason}"),
            HermesError::InvalidData { reason } => write!(f, "invalid data: {reason}"),
            HermesError::Storage { reason } => write!(f, "storage error: {reason}"),
        }
    }
}

impl std::error::Error for HermesError {}

impl From<IdentityError> for HermesError {
    fn from(e: IdentityError) -> Self {
        match e {
            IdentityError::AlreadyExists => HermesError::AlreadyExists,
            IdentityError::NotFound => HermesError::NotFound,
            IdentityError::Corrupt => HermesError::Corrupt,
            IdentityError::DecryptionFailed => HermesError::DecryptionFailed,
            IdentityError::BackupFailed(reason) => HermesError::BackupFailed { reason },
            IdentityError::InvalidData(reason) => HermesError::InvalidData { reason },
            IdentityError::Storage(e) => HermesError::Storage { reason: e.to_string() },
            _ => HermesError::Storage { reason: "unknown error".into() },
        }
    }
}

/// In-memory secure storage for use in proofs-of-concept and tests.
///
/// Not suitable for production — data is not persisted and has no platform security guarantees.
#[derive(uniffi::Object)]
pub struct InMemorySecureStorage {
    inner: Mutex<hermes_core::InMemorySecureStorage>,
}

#[uniffi::export]
impl InMemorySecureStorage {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(hermes_core::InMemorySecureStorage::new()),
        })
    }
}

/// New type bridging `Arc<InMemorySecureStorage>` into the `SecureStorage` trait.
///
/// Required because Rust's orphan rule forbids implementing a foreign trait
/// (`SecureStorage`) directly on a foreign type (`Arc<T>`).
struct FfiStorage(Arc<InMemorySecureStorage>);

impl SecureStorage for FfiStorage {
    fn store(&mut self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        self.0.inner.lock().unwrap().store(key, value)
    }

    fn load(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, StorageError> {
        self.0.inner.lock().unwrap().load(key)
    }

    fn delete(&mut self, key: &str) -> Result<(), StorageError> {
        self.0.inner.lock().unwrap().delete(key)
    }
}

/// Manages creation and retrieval of the local Hermes identity over the FFI boundary.
///
/// Backed by [`InMemorySecureStorage`] for proof-of-concept use.
#[derive(uniffi::Object)]
pub struct IdentityManager {
    inner: Mutex<hermes_core::IdentityManager<FfiStorage>>,
}

#[uniffi::export]
impl IdentityManager {
    /// Constructs a new `IdentityManager` backed by the given storage.
    #[uniffi::constructor]
    pub fn new(storage: Arc<InMemorySecureStorage>) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(hermes_core::IdentityManager::new(FfiStorage(storage))),
        })
    }

    /// Generates a new identity and persists it to storage.
    pub fn generate_identity(&self) -> Result<Identity, HermesError> {
        let mut mgr = self.inner.lock().unwrap();
        let id = mgr.generate_identity()?;
        Ok(Identity {
            public_key: id.public_key().as_bytes().to_vec(),
        })
    }

    /// Loads the existing identity from storage.
    pub fn load_identity(&self) -> Result<Identity, HermesError> {
        let mgr = self.inner.lock().unwrap();
        let id = mgr.load_identity()?;
        Ok(Identity {
            public_key: id.public_key().as_bytes().to_vec(),
        })
    }
}
