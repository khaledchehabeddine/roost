#[cfg(test)]
use std::collections::HashMap;
use zeroize::Zeroizing;

/// A key-value storage abstraction for sensitive byte payloads.
///
/// Implementations usually wrap platform secure storage, and roost-client exports a version the
/// app implements in Swift or Kotlin. Each operation must be durable when it returns
/// success. An interrupted `store` must leave either the complete previous value or the complete
/// new value, never a torn value. `store` and `delete` may be retried after an ambiguous failure,
/// so repeating either operation must be safe.
pub trait SecureStorage: Send {
    /// Stores `value` under `key`, overwriting any existing entry.
    fn store(&mut self, key: &str, value: &[u8]) -> Result<(), StorageError>;

    /// Returns the value stored under `key`, or `None` if not present.
    fn load(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, StorageError>;

    /// Removes the value stored under `key`. Does nothing if the key is not present.
    fn delete(&mut self, key: &str) -> Result<(), StorageError>;
}

/// Errors returned by [`SecureStorage`] implementations.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// Platform storage returned an I/O or permission failure.
    #[error("{0}")]
    IO(String),
}

// A SecureStorage held in memory, for this crate's unit tests.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct InMemorySecureStorage {
    entries: HashMap<String, Zeroizing<Vec<u8>>>,
}

#[cfg(test)]
impl InMemorySecureStorage {
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
impl SecureStorage for InMemorySecureStorage {
    fn store(&mut self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        self.entries
            .insert(key.to_string(), Zeroizing::new(value.to_vec()));
        Ok(())
    }

    fn load(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, StorageError> {
        Ok(self.entries.get(key).cloned())
    }

    fn delete(&mut self, key: &str) -> Result<(), StorageError> {
        self.entries.remove(key);
        Ok(())
    }
}
