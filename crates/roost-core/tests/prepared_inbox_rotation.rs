//! Prepared inbox rotation across the public KeyStore and SecureStorage seam.
//!
//! The scenario proves that a newly returned inbox generation remains provisional until the
//! prepared secure mutation is committed and finalized, including restart recovery after a
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
    let identity = store.prepare_generate_identity().unwrap();
    store
        .commit_operation(identity.operation.identifier)
        .unwrap();
    store
        .finalize_operation(identity.operation.identifier)
        .unwrap();
    let before = store.current_discovery_key_bundle().unwrap();

    let prepared = store.prepare_rotate_inbox_now().unwrap();

    assert_eq!(
        store.current_discovery_key_bundle().unwrap().epoch,
        before.epoch
    );
    assert_eq!(
        prepared.output.publication.discovery_key.epoch,
        before.epoch + 1
    );

    store
        .commit_operation(prepared.operation.identifier)
        .unwrap();
    store
        .finalize_operation(prepared.operation.identifier)
        .unwrap();
    assert_eq!(
        store.current_discovery_key_bundle().unwrap().epoch,
        before.epoch + 1
    );
}

#[test]
fn committed_inbox_rotation_resumes_after_restart_and_failed_finalization() {
    let storage = SharedSecureStorage::new();
    let store = storage.key_store();
    let identity = store.prepare_generate_identity().unwrap();
    store
        .commit_operation(identity.operation.identifier)
        .unwrap();
    store
        .finalize_operation(identity.operation.identifier)
        .unwrap();
    let before = store.current_discovery_key_bundle().unwrap().epoch;
    let prepared = store.prepare_rotate_inbox_now().unwrap();
    let host_operation_identifier = prepared.operation.identifier;
    store.commit_operation(host_operation_identifier).unwrap();

    storage.fail_next_store();
    assert!(store.finalize_operation(host_operation_identifier).is_err());
    drop(store);

    let recovered = storage.key_store();
    let unfinished = recovered.unfinished_operations().unwrap();
    assert_eq!(unfinished.len(), 1);
    assert_eq!(
        unfinished[0].operation.identifier,
        host_operation_identifier
    );
    assert_eq!(unfinished[0].status, KeyStoreOperationStatus::Committed);
    recovered
        .finalize_operation(host_operation_identifier)
        .unwrap();
    assert_eq!(
        recovered.current_discovery_key_bundle().unwrap().epoch,
        before + 1
    );
}
