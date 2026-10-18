use roost_client::{RoostError, SecureStorage};
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::Zeroizing;

/// Secure storage held in memory, standing in for a platform store.
#[derive(Default)]
pub(crate) struct MemoryStorage {
    entries: Mutex<BTreeMap<String, Zeroizing<Vec<u8>>>>,
    fail_next_load: AtomicBool,
}

impl MemoryStorage {
    /// Makes the next `load` fail the way a platform store reports an error.
    pub(crate) fn fail_next_load(&self) {
        self.fail_next_load.store(true, Ordering::SeqCst);
    }
}

impl SecureStorage for MemoryStorage {
    fn save(&self, key: String, value: Vec<u8>) -> Result<(), RoostError> {
        self.entries
            .lock()
            .unwrap()
            .insert(key, Zeroizing::new(value));
        Ok(())
    }

    fn load(&self, key: String) -> Result<Option<Vec<u8>>, RoostError> {
        if self.fail_next_load.swap(false, Ordering::SeqCst) {
            return Err(RoostError::Storage {
                reason: "keychain unavailable".into(),
            });
        }
        Ok(self
            .entries
            .lock()
            .unwrap()
            .get(&key)
            .map(|value| value.to_vec()))
    }

    fn remove(&self, key: String) -> Result<(), RoostError> {
        self.entries.lock().unwrap().remove(&key);
        Ok(())
    }
}
