//! Prepared KeyStore operation recovery across process replacement and storage failure.
//!
//! The scenario crosses the public KeyStore and SecureStorage seams to model orphaned preparation,
//! a crash after commit, ambiguous mutation results, and a crash during finalization.

use aether_core::{
    InMemorySecureStorage, KeyStore, KeyStoreError, KeyStoreOperationError,
    KeyStoreOperationStatus, SecureStorage, StorageError,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

#[derive(Clone)]
struct SharedSecureStorage {
    state: Arc<Mutex<StorageState>>,
}

struct StorageState {
    storage: InMemorySecureStorage,
    fail_delete_after_apply: Option<String>,
    fail_store_after_apply: Option<String>,
    stores_before_failure: Option<usize>,
    successful_deletes: BTreeMap<String, usize>,
    successful_stores: BTreeMap<String, usize>,
}

impl SharedSecureStorage {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(StorageState {
                storage: InMemorySecureStorage::new(),
                fail_delete_after_apply: None,
                fail_store_after_apply: None,
                stores_before_failure: None,
                successful_deletes: BTreeMap::new(),
                successful_stores: BTreeMap::new(),
            })),
        }
    }

    fn key_store(&self) -> KeyStore {
        KeyStore::new(Box::new(self.clone()))
    }

    fn fail_after_stores(&self, successful_stores: usize) {
        self.state.lock().unwrap().stores_before_failure = Some(successful_stores);
    }

    fn fail_delete_after_apply(&self, key: &str) {
        self.state.lock().unwrap().fail_delete_after_apply = Some(key.to_owned());
    }

    fn fail_store_after_apply(&self, key: &str) {
        self.state.lock().unwrap().fail_store_after_apply = Some(key.to_owned());
    }

    fn successful_deletes(&self, key: &str) -> usize {
        self.state
            .lock()
            .unwrap()
            .successful_deletes
            .get(key)
            .copied()
            .unwrap_or_default()
    }

    fn successful_stores(&self, key: &str) -> usize {
        self.state
            .lock()
            .unwrap()
            .successful_stores
            .get(key)
            .copied()
            .unwrap_or_default()
    }
}

impl SecureStorage for SharedSecureStorage {
    fn store(&mut self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        let mut state = self.state.lock().unwrap();
        if let Some(remaining) = state.stores_before_failure.as_mut() {
            if *remaining == 0 {
                state.stores_before_failure = None;
                return Err(StorageError::IO("injected store failure".into()));
            }
            *remaining -= 1;
        }
        state.storage.store(key, value)?;
        *state.successful_stores.entry(key.to_owned()).or_default() += 1;
        if state.fail_store_after_apply.as_deref() == Some(key) {
            state.fail_store_after_apply = None;
            return Err(StorageError::IO("injected post-apply store failure".into()));
        }
        Ok(())
    }

    fn load(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, StorageError> {
        self.state.lock().unwrap().storage.load(key)
    }

    fn delete(&mut self, key: &str) -> Result<(), StorageError> {
        let mut state = self.state.lock().unwrap();
        state.storage.delete(key)?;
        *state.successful_deletes.entry(key.to_owned()).or_default() += 1;
        if state.fail_delete_after_apply.as_deref() == Some(key) {
            state.fail_delete_after_apply = None;
            return Err(StorageError::IO(
                "injected post-apply delete failure".into(),
            ));
        }
        Ok(())
    }
}

#[test]
fn host_serialization_spans_distinct_key_store_instances() {
    let storage = SharedSecureStorage::new();
    let coordinator = Mutex::new(());

    {
        let _identity_operation = coordinator.lock().unwrap();
        let store = storage.key_store();
        let prepared = store.prepare_generate_identity().unwrap();
        store
            .commit_operation(prepared.operation.identifier)
            .unwrap();
        store
            .finalize_operation(prepared.operation.identifier)
            .unwrap();
    }

    {
        let _signed_prekey_operation = coordinator.lock().unwrap();
        let store = storage.key_store();
        let prepared = store.prepare_rotate_signed_prekey_now().unwrap();
        store
            .commit_operation(prepared.operation.identifier)
            .unwrap();
        store
            .finalize_operation(prepared.operation.identifier)
            .unwrap();
    }

    assert!(storage.key_store().current_publication_bundle().is_ok());
}

#[test]
fn orphaned_preparation_is_discoverable_and_abortable_after_restart() {
    let storage = SharedSecureStorage::new();
    let store = storage.key_store();
    let prepared = store.prepare_generate_identity().unwrap();
    drop(store);

    let recovered = storage.key_store();
    let unfinished = recovered.unfinished_operations().unwrap();
    assert_eq!(unfinished.len(), 1);
    assert_eq!(
        unfinished[0].operation.identifier,
        prepared.operation.identifier
    );
    assert_eq!(unfinished[0].status, KeyStoreOperationStatus::Prepared);

    recovered
        .abort_operation(prepared.operation.identifier)
        .unwrap();
    assert!(!recovered.has_identity().unwrap());
    assert!(recovered.unfinished_operations().unwrap().is_empty());
}

#[test]
fn committed_preparation_can_finalize_after_restart() {
    let storage = SharedSecureStorage::new();
    let store = storage.key_store();
    let prepared = store.prepare_generate_identity().unwrap();
    store
        .commit_operation(prepared.operation.identifier)
        .unwrap();
    drop(store);

    let recovered = storage.key_store();
    assert_eq!(
        recovered.unfinished_operations().unwrap()[0].status,
        KeyStoreOperationStatus::Committed
    );
    recovered
        .finalize_operation(prepared.operation.identifier)
        .unwrap();
    assert!(recovered.has_identity().unwrap());
}

#[test]
fn committed_preparation_blocks_authoritative_reads_until_recovery() {
    let storage = SharedSecureStorage::new();
    let store = storage.key_store();
    let prepared = store.prepare_generate_identity().unwrap();
    store
        .commit_operation(prepared.operation.identifier)
        .unwrap();

    assert!(matches!(
        store.has_identity(),
        Err(KeyStoreError::Operation(
            KeyStoreOperationError::RecoveryRequired { identifier }
        )) if identifier == prepared.operation.identifier
    ));

    store
        .abort_operation(prepared.operation.identifier)
        .unwrap();
    assert!(!store.has_identity().unwrap());
}

#[test]
fn interrupted_finalization_resumes_from_durable_progress() {
    let storage = SharedSecureStorage::new();
    let store = storage.key_store();
    let prepared = store.prepare_generate_identity().unwrap();
    store
        .commit_operation(prepared.operation.identifier)
        .unwrap();

    // Persist Finalizing, apply the first mutation, persist its progress, then fail the second
    // mutation. Recovery must resume at the second mutation instead of replaying the first.
    storage.fail_after_stores(3);
    assert!(
        store
            .finalize_operation(prepared.operation.identifier)
            .is_err()
    );
    assert_eq!(storage.successful_stores("discovery/current"), 1);
    drop(store);

    let recovered = storage.key_store();
    assert_eq!(
        recovered.unfinished_operations().unwrap()[0].status,
        KeyStoreOperationStatus::Finalizing
    );
    recovered
        .finalize_operation(prepared.operation.identifier)
        .unwrap();
    assert_eq!(storage.successful_stores("discovery/current"), 1);
    assert!(recovered.has_identity().unwrap());
}

#[test]
fn applied_store_with_ambiguous_failure_is_safely_replayed() {
    let storage = SharedSecureStorage::new();
    let store = storage.key_store();
    let prepared = store.prepare_generate_identity().unwrap();
    store
        .commit_operation(prepared.operation.identifier)
        .unwrap();

    storage.fail_store_after_apply("discovery/current");
    assert!(
        store
            .finalize_operation(prepared.operation.identifier)
            .is_err()
    );
    assert_eq!(storage.successful_stores("discovery/current"), 1);
    drop(store);

    let recovered = storage.key_store();
    recovered
        .finalize_operation(prepared.operation.identifier)
        .unwrap();
    assert_eq!(storage.successful_stores("discovery/current"), 2);
    assert!(recovered.has_identity().unwrap());
}

#[test]
fn applied_delete_with_ambiguous_failure_is_safely_replayed() {
    let storage = SharedSecureStorage::new();
    let store = storage.key_store();
    let identity = store.prepare_generate_identity().unwrap();
    store
        .commit_operation(identity.operation.identifier)
        .unwrap();
    store
        .finalize_operation(identity.operation.identifier)
        .unwrap();
    let reset = store.prepare_reset().unwrap();
    store.commit_operation(reset.operation.identifier).unwrap();

    storage.fail_delete_after_apply("discovery/current");
    assert!(
        store
            .finalize_operation(reset.operation.identifier)
            .is_err()
    );
    assert_eq!(storage.successful_deletes("discovery/current"), 1);
    drop(store);

    let recovered = storage.key_store();
    recovered
        .finalize_operation(reset.operation.identifier)
        .unwrap();
    assert_eq!(storage.successful_deletes("discovery/current"), 2);
    assert!(!recovered.has_identity().unwrap());
}
