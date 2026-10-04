use crate::ClientError;
use roost_core::{SecureStorage as CoreSecureStorage, StorageError};
use std::sync::Arc;
#[cfg(test)]
use std::sync::Mutex;
use zeroize::Zeroizing;

/// Platform secure-storage boundary used by [`Client`](crate::Client).
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
/// Methods are called synchronously from Rust. Return [`ClientError::Storage`] for platform
/// failures instead of panicking. A successful mutation must be durable. An interrupted `store`
/// must leave either the complete previous value or the complete new value, never a torn value.
/// Core may retry `store` or `delete` after an ambiguous failure, so both operations must be safe
/// to repeat.
#[uniffi::export(with_foreign)]
pub trait SecureStorage: Send + Sync {
    /// Stores `value` under `key`, overwriting any existing entry.
    ///
    /// # Errors
    /// - [`ClientError::Storage`] when platform storage returns an error.
    fn store(&self, key: String, value: Vec<u8>) -> Result<(), ClientError>;

    /// Returns the value stored under `key`, or `None` if not present.
    ///
    /// # Errors
    /// - [`ClientError::Storage`] when platform storage returns an error.
    fn load(&self, key: String) -> Result<Option<Vec<u8>>, ClientError>;

    /// Removes the value stored under `key`. Missing keys are treated as success.
    ///
    /// # Errors
    /// - [`ClientError::Storage`] when platform storage returns an error.
    fn delete(&self, key: String) -> Result<(), ClientError>;
}

/// Secure storage held in memory, for this crate's unit tests.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct MemoryStorage {
    inner: Mutex<roost_core::InMemorySecureStorage>,
}

#[cfg(test)]
impl SecureStorage for MemoryStorage {
    fn store(&self, key: String, value: Vec<u8>) -> Result<(), ClientError> {
        let value = Zeroizing::new(value);
        Ok(self.inner.lock().unwrap().store(&key, &value)?)
    }

    fn load(&self, key: String) -> Result<Option<Vec<u8>>, ClientError> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .load(&key)?
            .map(|value| value.to_vec()))
    }

    fn delete(&self, key: String) -> Result<(), ClientError> {
        Ok(self.inner.lock().unwrap().delete(&key)?)
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
