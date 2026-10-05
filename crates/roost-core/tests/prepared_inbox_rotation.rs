//! Prepared inbox rotation across the public KeyStore and SecureStorage seam.
//!
//! The scenario proves that a newly returned inbox generation remains provisional until the
//! prepared secure mutation is reserved and finalized, including restart recovery after a
//! failed finalization transition.

use roost_core::{
    InMemorySecureStorage, KeyStore, KeyStoreOperationStatus, SecureStorage, StorageError,
};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

#[derive(Clone)]
struct SharedSecureStorage {
    state: Arc<Mutex<StorageState>>,
}

struct StorageState {
    storage: InMemorySecureStorage,
    fail_next_store: bool,
}

impl SharedSecureStorage {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(StorageState {
                storage: InMemorySecureStorage::new(),
                fail_next_store: false,
            })),
        }
    }

    fn key_store(&self) -> KeyStore {
        KeyStore::new(Box::new(self.clone()))
    }

    fn fail_next_store(&self) {
        self.state.lock().unwrap().fail_next_store = true;
    }
}

impl SecureStorage for SharedSecureStorage {
    fn store(&mut self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        let mut state = self.state.lock().unwrap();
        if state.fail_next_store {
            state.fail_next_store = false;
            return Err(StorageError::IO("injected store failure".into()));
        }
        state.storage.store(key, value)
    }

    fn load(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, StorageError> {
        self.state.lock().unwrap().storage.load(key)
    }

    fn delete(&mut self, key: &str) -> Result<(), StorageError> {
        self.state.lock().unwrap().storage.delete(key)
    }
}

#[test]
fn prepared_inbox_rotation_does_not_advance_authoritative_generation_before_finalize() {
    let store = KeyStore::new(Box::new(InMemorySecureStorage::new()));
    let identity = store.prepare_identity_creation().unwrap();
    store.reserve_operation(identity.operation.id).unwrap();
    store.finalize_operation(identity.operation.id).unwrap();
    let before = store.current_public_discovery_key().unwrap();

    let prepared = store.prepare_inbox_rotation().unwrap();

    assert_eq!(
        store.current_public_discovery_key().unwrap().epoch,
        before.epoch
    );
    assert_eq!(
        prepared.output.publication.discovery_key.epoch,
        before.epoch + 1
    );

    store.reserve_operation(prepared.operation.id).unwrap();
    store.finalize_operation(prepared.operation.id).unwrap();
    assert_eq!(
        store.current_public_discovery_key().unwrap().epoch,
        before.epoch + 1
    );
}

#[test]
fn reserved_inbox_rotation_resumes_after_restart_and_failed_finalization() {
    let storage = SharedSecureStorage::new();
    let store = storage.key_store();
    let identity = store.prepare_identity_creation().unwrap();
    store.reserve_operation(identity.operation.id).unwrap();
    store.finalize_operation(identity.operation.id).unwrap();
    let before = store.current_public_discovery_key().unwrap().epoch;
    let prepared = store.prepare_inbox_rotation().unwrap();
    let host_operation_id = prepared.operation.id;
    store.reserve_operation(host_operation_id).unwrap();

    storage.fail_next_store();
    assert!(store.finalize_operation(host_operation_id).is_err());
    drop(store);

    let recovered = storage.key_store();
    let unfinished = recovered.unfinished_operations().unwrap();
    assert_eq!(unfinished.len(), 1);
    assert_eq!(unfinished[0].operation.id, host_operation_id);
    assert_eq!(unfinished[0].status, KeyStoreOperationStatus::Reserved);
    recovered.finalize_operation(host_operation_id).unwrap();
    assert_eq!(
        recovered.current_public_discovery_key().unwrap().epoch,
        before + 1
    );
}
