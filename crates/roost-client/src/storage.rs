use crate::RoostError;
use roost_core::{SecureStorage as CoreSecureStorage, StorageError};
use std::sync::Arc;
use zeroize::Zeroizing;

/// Platform secure storage, such as Keychain or Keystore, that an
/// [`IdentityContext`](crate::IdentityContext) keeps keys in.
///
/// Implementations must persist bytes in platform secure storage, not plain files or temporary
/// process memory. The values Roost saves and loads are secret, so clear any copy the
/// implementation makes as soon as it's done with it.
///
/// # Implementation
///
/// Roost calls these methods synchronously, on the thread that called Roost. Throw
/// [`RoostError::Storage`] for platform failures. A successful mutation must be durable. An
/// interrupted `save` must leave either the complete previous value or the complete new value,
/// never a torn value. Roost may retry `save` or `remove` after an ambiguous failure, so both must
/// be safe to repeat.
#[uniffi::export(with_foreign)]
pub trait SecureStorage: Send + Sync {
    /// Saves `value` under `key`, replacing any existing entry.
    ///
    /// # Errors
    /// - [`RoostError::Storage`] if platform storage returns an error.
    fn save(&self, key: String, value: Vec<u8>) -> Result<(), RoostError>;

    /// Returns the value saved under `key`, absent when there is none.
    ///
    /// # Errors
    /// - [`RoostError::Storage`] if platform storage returns an error.
    fn load(&self, key: String) -> Result<Option<Vec<u8>>, RoostError>;

    /// Removes the value stored under `key`. Missing keys are treated as success.
    ///
    /// # Errors
    /// - [`RoostError::Storage`] if platform storage returns an error.
    fn remove(&self, key: String) -> Result<(), RoostError>;
}

// Bridges the app's SecureStorage to the key store's storage trait.
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
            .map_err(app_storage_error)
    }

    fn load(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, StorageError> {
        self.storage
            .load(key.to_string())
            .map(|value| value.map(Zeroizing::new))
            .map_err(app_storage_error)
    }

    fn delete(&mut self, key: &str) -> Result<(), StorageError> {
        self.storage
            .remove(key.to_string())
            .map_err(app_storage_error)
    }
}

// Keeps the app's own reason, so a storage failure that returns to the app isn't prefixed twice.
fn app_storage_error(error: RoostError) -> StorageError {
    if let RoostError::Storage { reason } = error {
        StorageError::IO(reason)
    } else {
        StorageError::IO(error.to_string())
    }
}
