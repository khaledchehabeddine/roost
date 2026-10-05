use crate::RoostError;
use roost_core::{SecureStorage as CoreSecureStorage, StorageError};
use std::sync::Arc;
#[cfg(test)]
use std::sync::Mutex;
use zeroize::Zeroizing;

/// Platform secure storage, such as Keychain or Keystore, that an [`IdentityContext`](crate::IdentityContext) keeps keys in.
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
/// Methods are called synchronously from Rust. Return [`RoostError::Storage`] for platform
/// failures instead of panicking. A successful mutation must be durable. An interrupted `save`
/// must leave either the complete previous value or the complete new value, never a torn value.
/// Roost may retry `save` or `remove` after an ambiguous failure, so both must be safe to repeat.
#[uniffi::export(with_foreign)]
pub trait SecureStorage: Send + Sync {
    /// Saves `value` under `key`, replacing any existing entry.
    ///
    /// # Errors
    /// - [`RoostError::Storage`] when platform storage returns an error.
    fn save(&self, key: String, value: Vec<u8>) -> Result<(), RoostError>;

    /// Returns the value saved under `key`, absent when there is none.
    ///
    /// # Errors
    /// - [`RoostError::Storage`] when platform storage returns an error.
    fn load(&self, key: String) -> Result<Option<Vec<u8>>, RoostError>;

    /// Removes the value stored under `key`. Missing keys are treated as success.
    ///
    /// # Errors
    /// - [`RoostError::Storage`] when platform storage returns an error.
    fn remove(&self, key: String) -> Result<(), RoostError>;
}

/// Secure storage held in memory, for this crate's unit tests.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct MemoryStorage {
    inner: Mutex<roost_core::InMemorySecureStorage>,
}

#[cfg(test)]
impl SecureStorage for MemoryStorage {
    fn save(&self, key: String, value: Vec<u8>) -> Result<(), RoostError> {
        let value = Zeroizing::new(value);
        Ok(self.inner.lock().unwrap().store(&key, &value)?)
    }

    fn load(&self, key: String) -> Result<Option<Vec<u8>>, RoostError> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .load(&key)?
            .map(|value| value.to_vec()))
    }

    fn remove(&self, key: String) -> Result<(), RoostError> {
        Ok(self.inner.lock().unwrap().delete(&key)?)
    }
}

// Bridges the host's SecureStorage into Core's storage trait.
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
            .save(key.to_string(), value.to_vec())
            .map_err(host_storage_error)
    }

    fn load(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, StorageError> {
        self.storage
            .load(key.to_string())
            .map(|opt| opt.map(Zeroizing::new))
            .map_err(host_storage_error)
    }

    fn delete(&mut self, key: &str) -> Result<(), StorageError> {
        self.storage
            .remove(key.to_string())
            .map_err(host_storage_error)
    }
}

// Keeps the host's own reason, so a storage failure that returns to the host isn't prefixed twice.
fn host_storage_error(error: RoostError) -> StorageError {
    if let RoostError::Storage { reason } = error {
        StorageError::IO(reason)
    } else {
        StorageError::IO(error.to_string())
    }
}
