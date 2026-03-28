use std::collections::HashMap;
use std::fmt;
use zeroize::Zeroizing;

/// Errors returned by [`SecureStorage`] implementations.
///
/// `InMemorySecureStorage` is infallible, but real backends (iOS Keychain, Android Keystore) will
/// surface I/O and permission errors through this type.
#[non_exhaustive]
#[derive(Debug)]
pub enum StorageError {
    IO(String),
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StorageError::IO(msg) => write!(f, "storage I/O error: {msg}"),
        }
    }
}

impl std::error::Error for StorageError {}

/// A key-value storage abstraction for sensitive byte payloads.
///
/// Implementations are expected to back this with platform secure storage (iOS Keychain,
/// Android Keystore).
pub trait SecureStorage {
    /// Stores `value` under `key`, overwriting any existing entry.
    fn store(&mut self, key: &str, value: &[u8]) -> Result<(), StorageError>;

    /// Returns the value stored under `key`, or `None` if not present.
    ///
    /// The returned bytes are wrapped in [`Zeroizing`], so they are scrubbed from memory when the
    /// caller drops them.
    fn load(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, StorageError>;

    fn delete(&mut self, key: &str) -> Result<(), StorageError>;
}

/// An in-memory [`SecureStorage`] implementation for use in tests.
///
/// Not suitable for production — data is not persisted and has no platform security guarantees.
#[derive(Default)]
pub struct InMemorySecureStorage {
    entries: HashMap<String, Zeroizing<Vec<u8>>>,
}

impl InMemorySecureStorage {
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
        Ok(self.entries.get(key).map(|v| Zeroizing::new(v.to_vec())))
    }

    fn delete(&mut self, key: &str) -> Result<(), StorageError> {
        self.entries.remove(key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn storage() -> InMemorySecureStorage {
        InMemorySecureStorage::new()
    }

    #[test]
    fn secure_storage_is_object_safe() {
        fn _assert(_: &dyn SecureStorage) {}
    }

    #[test]
    fn store_and_load_round_trip() {
        let mut s = storage();
        s.store("key", b"value").unwrap();
        assert_eq!(
            s.load("key").unwrap().as_ref().map(|v| v.as_slice()),
            Some(b"value".as_ref())
        );
    }

    #[test]
    fn load_missing_key_returns_none() {
        let s = storage();
        assert_eq!(s.load("missing").unwrap(), None);
    }

    #[test]
    fn store_overwrites_existing_value() {
        let mut s = storage();
        s.store("key", b"first").unwrap();
        s.store("key", b"second").unwrap();
        assert_eq!(
            s.load("key").unwrap().as_ref().map(|v| v.as_slice()),
            Some(b"second".as_ref())
        );
    }

    #[test]
    fn delete_removes_entry() {
        let mut s = storage();
        s.store("key", b"value").unwrap();
        s.delete("key").unwrap();
        assert_eq!(s.load("key").unwrap(), None);
    }

    #[test]
    fn delete_missing_key_is_noop() {
        let mut s = storage();
        assert!(s.delete("missing").is_ok());
    }

    #[test]
    fn independent_keys_do_not_interfere() {
        let mut s = storage();
        s.store("a", b"value-a").unwrap();
        s.store("b", b"value-b").unwrap();
        assert_eq!(
            s.load("a").unwrap().as_ref().map(|v| v.as_slice()),
            Some(b"value-a".as_ref())
        );
        assert_eq!(
            s.load("b").unwrap().as_ref().map(|v| v.as_slice()),
            Some(b"value-b".as_ref())
        );
    }

    #[test]
    fn load_returns_independent_copy() {
        let mut s = storage();
        s.store("key", b"original").unwrap();
        let mut loaded = s.load("key").unwrap().unwrap();
        loaded[0] = b'X';
        assert_eq!(
            s.load("key").unwrap().as_ref().map(|v| v.as_slice()),
            Some(b"original".as_ref())
        );
    }
}
