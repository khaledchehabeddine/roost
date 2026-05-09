//! Platform secure-storage trait, in-memory reference implementation, and core storage adapter.

use crate::HermesError;
use hermes_core::{SecureStorage as CoreSecureStorage, StorageError};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

/// Platform secure-storage boundary used by [`KeyStore`](crate::KeyStore).
///
/// Implementations must persist bytes in platform secure storage, not plain files or temporary
/// process memory. Values returned from [`SecureStorage::load`] contain secret material and must
/// be treated as sensitive until overwritten or released.
///
/// `value` and `load` cross UniFFI as bare `Vec<u8>` because UniFFI does not support
/// [`Zeroizing`](zeroize::Zeroizing). Rust wraps loaded values immediately after they cross this
/// boundary.
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
pub(crate) struct SecureStorageAdapter {
    storage: Arc<dyn SecureStorage>,
}

impl SecureStorageAdapter {
    pub(crate) fn new(storage: Arc<dyn SecureStorage>) -> Self {
        Self { storage }
    }
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
