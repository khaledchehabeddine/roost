use std::collections::HashMap;
use zeroize::Zeroizing;

/// A key-value storage abstraction for sensitive byte payloads.
///
/// Implementations usually wrap platform secure storage. The UniFFI crate exposes a
/// foreign-implementable adapter for clients. Each operation must be durable when it returns
/// success. An interrupted `store` must leave either the complete previous value or the complete
/// new value, never a torn value. `store` and `delete` may be retried after an ambiguous failure,
/// so repeating either operation must be safe.
pub trait SecureStorage: Send {
    /// Stores `value` under `key`, overwriting any existing entry.
    fn store(&mut self, key: &str, value: &[u8]) -> Result<(), StorageError>;

    /// Returns the value stored under `key`, or `None` if not present.
    ///
    /// The returned bytes are wrapped in [`Zeroizing`].
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

/// An in-memory [`SecureStorage`] implementation for tests.
///
/// Not suitable for production as data is not persisted and has no platform security guarantees.
#[derive(Default)]
pub struct InMemorySecureStorage {
    entries: HashMap<String, Zeroizing<Vec<u8>>>,
}

impl InMemorySecureStorage {
    /// Creates an empty in-memory storage instance.
    pub fn new() -> Self {
        Self::default()
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    fn memory_storage() -> InMemorySecureStorage {
        InMemorySecureStorage::new()
    }

    fn loaded_bytes(storage: &InMemorySecureStorage, key: &str) -> Option<Vec<u8>> {
        storage.load(key).unwrap().map(|bytes| bytes.to_vec())
    }

    #[test]
    fn store_and_load_round_trip() {
        let mut storage = memory_storage();
        storage.store("key", b"value").unwrap();
        assert_eq!(
            loaded_bytes(&storage, "key").as_deref(),
            Some(b"value".as_ref())
        );
    }

    #[test]
    fn store_overwrites_existing_value() {
        let mut storage = memory_storage();
        storage.store("key", b"first").unwrap();
        storage.store("key", b"second").unwrap();
        assert_eq!(
            loaded_bytes(&storage, "key").as_deref(),
            Some(b"second".as_ref())
        );
    }

    #[test]
    fn independent_keys_do_not_interfere() {
        let mut storage = memory_storage();
        storage.store("a", b"value-a").unwrap();
        storage.store("b", b"value-b").unwrap();
        assert_eq!(
            loaded_bytes(&storage, "a").as_deref(),
            Some(b"value-a".as_ref())
        );
        assert_eq!(
            loaded_bytes(&storage, "b").as_deref(),
            Some(b"value-b".as_ref())
        );
    }

    #[test]
    fn load_missing_key_returns_none() {
        let storage = memory_storage();
        assert_eq!(storage.load("missing").unwrap(), None);
    }

    #[test]
    fn load_returns_independent_copy() {
        let mut storage = memory_storage();
        storage.store("key", b"original").unwrap();
        let mut loaded = storage.load("key").unwrap().unwrap();
        loaded[0] = b'X';
        assert_eq!(
            loaded_bytes(&storage, "key").as_deref(),
            Some(b"original".as_ref())
        );
    }

    #[test]
    fn delete_removes_entry() {
        let mut storage = memory_storage();
        storage.store("key", b"value").unwrap();
        storage.delete("key").unwrap();
        assert_eq!(storage.load("key").unwrap(), None);
    }

    #[test]
    fn delete_missing_key_is_noop() {
        let mut storage = memory_storage();
        assert!(storage.delete("missing").is_ok());
    }
}
