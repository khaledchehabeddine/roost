use roost_client::{ClientError, SecureStorage};
use roost_core::SecureStorage as _;
use std::sync::Mutex;
use zeroize::Zeroizing;

/// Secure storage held in memory, standing in for a platform store.
#[derive(Default)]
pub(crate) struct MemoryStorage {
    inner: Mutex<roost_core::InMemorySecureStorage>,
}

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
