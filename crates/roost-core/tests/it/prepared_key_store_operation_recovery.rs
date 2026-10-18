//! Prepared KeyStore operation recovery across process replacement and storage failure.
//!
//! The scenario crosses the public KeyStore and SecureStorage seams to model orphaned preparation,
//! a crash after reservation, ambiguous mutation results, and a crash during finalization.

use crate::support::host_identity::DeviceStorage;
use roost_core::{
    KeyStore, KeyStoreError, KeyStoreOperationError, KeyStoreOperationStatus, SecureStorage,
    StorageError,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

const OPERATION_JOURNAL_KEY: &str = "operation/journal";

fn is_storage_failure<T>(result: Result<T, KeyStoreError>) -> bool {
    matches!(
        result,
        Err(KeyStoreError::Operation(KeyStoreOperationError::Storage(
            StorageError::IO(_)
        )))
    )
}

#[derive(Clone)]
struct SharedSecureStorage {
    state: Arc<Mutex<StorageState>>,
}

struct StorageState {
    storage: DeviceStorage,
    fail_delete_after_apply: Option<String>,
    fail_store_after_apply: Option<String>,
    store_failure: Option<StoreFailure>,
    successful_deletes: BTreeMap<String, usize>,
    successful_stores: BTreeMap<String, usize>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FailureTiming {
    BeforeApply,
    AfterApply,
}

struct StoreFailure {
    key: String,
    matching_stores_before_failure: usize,
    timing: FailureTiming,
}

impl SharedSecureStorage {
    fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(StorageState {
                storage: DeviceStorage::default(),
                fail_delete_after_apply: None,
                fail_store_after_apply: None,
                store_failure: None,
                successful_deletes: BTreeMap::new(),
                successful_stores: BTreeMap::new(),
            })),
        }
    }

    fn key_store(&self) -> KeyStore {
        KeyStore::new(Box::new(self.clone()))
    }

    fn fail_delete_after_apply(&self, key: &str) {
        self.state.lock().unwrap().fail_delete_after_apply = Some(key.to_owned());
    }

    fn fail_store_after_apply(&self, key: &str) {
        self.state.lock().unwrap().fail_store_after_apply = Some(key.to_owned());
    }

    fn fail_store(&self, key: &str, matching_stores_before_failure: usize, timing: FailureTiming) {
        self.state.lock().unwrap().store_failure = Some(StoreFailure {
            key: key.to_owned(),
            matching_stores_before_failure,
            timing,
        });
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
        let failure_timing = state.store_failure.as_mut().and_then(|failure| {
            if failure.key != key {
                return None;
            }
            if failure.matching_stores_before_failure > 0 {
                failure.matching_stores_before_failure -= 1;
                return None;
            }
            Some(failure.timing)
        });
        if failure_timing == Some(FailureTiming::BeforeApply) {
            state.store_failure = None;
            return Err(StorageError::IO("injected pre-apply store failure".into()));
        }
        state.storage.store(key, value)?;
        *state.successful_stores.entry(key.to_owned()).or_default() += 1;
        if failure_timing == Some(FailureTiming::AfterApply) {
            state.store_failure = None;
            return Err(StorageError::IO("injected post-apply store failure".into()));
        }
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
fn prepared_journal_transition_recovers_from_before_and_after_apply_failures() {
    for timing in [FailureTiming::BeforeApply, FailureTiming::AfterApply] {
        let storage = SharedSecureStorage::new();
        storage.fail_store(OPERATION_JOURNAL_KEY, 0, timing);

        assert!(is_storage_failure(
            storage.key_store().prepare_identity_creation()
        ));

        let recovered = storage.key_store();
        let unfinished = recovered.unfinished_operations().unwrap();
        match timing {
            FailureTiming::BeforeApply => assert!(unfinished.is_empty()),
            FailureTiming::AfterApply => {
                assert_eq!(unfinished.len(), 1);
                assert_eq!(unfinished[0].status, KeyStoreOperationStatus::Prepared);
                recovered
                    .abort_operation(unfinished[0].operation.id)
                    .unwrap();
            }
        }
        assert!(recovered.identity().unwrap().is_none());
    }
}

#[test]
fn reserved_journal_transition_recovers_from_before_and_after_apply_failures() {
    for timing in [FailureTiming::BeforeApply, FailureTiming::AfterApply] {
        let storage = SharedSecureStorage::new();
        let store = storage.key_store();
        let prepared = store.prepare_identity_creation().unwrap();
        storage.fail_store(OPERATION_JOURNAL_KEY, 0, timing);

        assert!(is_storage_failure(
            store.reserve_operation(prepared.operation.id)
        ));

        let recovered = storage.key_store();
        let expected = match timing {
            FailureTiming::BeforeApply => KeyStoreOperationStatus::Prepared,
            FailureTiming::AfterApply => KeyStoreOperationStatus::Reserved,
        };
        assert_eq!(
            recovered.operation_status(prepared.operation.id).unwrap(),
            expected
        );
        // The host transaction was deliberately not attempted, so abort is safe in either case.
        recovered.abort_operation(prepared.operation.id).unwrap();
        assert!(recovered.identity().unwrap().is_none());
    }
}

#[test]
fn finalizing_journal_transition_recovers_from_before_and_after_apply_failures() {
    for timing in [FailureTiming::BeforeApply, FailureTiming::AfterApply] {
        let storage = SharedSecureStorage::new();
        let store = storage.key_store();
        let prepared = store.prepare_identity_creation().unwrap();
        store.reserve_operation(prepared.operation.id).unwrap();
        storage.fail_store(OPERATION_JOURNAL_KEY, 0, timing);

        assert!(is_storage_failure(
            store.finalize_operation(prepared.operation.id)
        ));

        let recovered = storage.key_store();
        let expected = match timing {
            FailureTiming::BeforeApply => KeyStoreOperationStatus::Reserved,
            FailureTiming::AfterApply => KeyStoreOperationStatus::Finalizing,
        };
        assert_eq!(
            recovered.operation_status(prepared.operation.id).unwrap(),
            expected
        );
        recovered.finalize_operation(prepared.operation.id).unwrap();
        assert!(recovered.identity().unwrap().is_some());
    }
}

#[test]
fn progress_checkpoint_recovers_from_before_and_after_apply_failures() {
    for timing in [FailureTiming::BeforeApply, FailureTiming::AfterApply] {
        let storage = SharedSecureStorage::new();
        let store = storage.key_store();
        let prepared = store.prepare_identity_creation().unwrap();
        store.reserve_operation(prepared.operation.id).unwrap();
        // Skip the Finalizing write, then fail the first durable progress checkpoint.
        storage.fail_store(OPERATION_JOURNAL_KEY, 1, timing);

        assert!(is_storage_failure(
            store.finalize_operation(prepared.operation.id)
        ));
        assert_eq!(storage.successful_stores("discovery/current"), 1);
        drop(store);

        let recovered = storage.key_store();
        assert_eq!(
            recovered.operation_status(prepared.operation.id).unwrap(),
            KeyStoreOperationStatus::Finalizing
        );
        recovered.finalize_operation(prepared.operation.id).unwrap();
        let expected_stores = match timing {
            FailureTiming::BeforeApply => 2,
            FailureTiming::AfterApply => 1,
        };
        assert_eq!(
            storage.successful_stores("discovery/current"),
            expected_stores
        );
        assert!(recovered.identity().unwrap().is_some());
    }
}

#[test]
fn finalized_journal_transition_recovers_from_before_and_after_apply_failures() {
    for timing in [FailureTiming::BeforeApply, FailureTiming::AfterApply] {
        let storage = SharedSecureStorage::new();
        let store = storage.key_store();
        let identity = store.prepare_identity_creation().unwrap();
        store.reserve_operation(identity.operation.id).unwrap();
        store.finalize_operation(identity.operation.id).unwrap();
        let initial_signed_prekey = store.prepare_signed_prekey_rotation().unwrap();
        store
            .reserve_operation(initial_signed_prekey.operation.id)
            .unwrap();
        store
            .finalize_operation(initial_signed_prekey.operation.id)
            .unwrap();
        let prepared = store.prepare_signed_prekey_rotation_if_stale().unwrap();
        assert!(prepared.output.is_none());
        store.reserve_operation(prepared.operation.id).unwrap();
        // A no-op has only Finalizing and Finalized journal writes.
        storage.fail_store(OPERATION_JOURNAL_KEY, 1, timing);

        assert!(is_storage_failure(
            store.finalize_operation(prepared.operation.id)
        ));

        let recovered = storage.key_store();
        let expected = match timing {
            FailureTiming::BeforeApply => KeyStoreOperationStatus::Finalizing,
            FailureTiming::AfterApply => KeyStoreOperationStatus::Finalized,
        };
        assert_eq!(
            recovered.operation_status(prepared.operation.id).unwrap(),
            expected
        );
        recovered.finalize_operation(prepared.operation.id).unwrap();
        assert!(recovered.unfinished_operations().unwrap().is_empty());
    }
}

#[test]
fn aborted_journal_transition_recovers_from_before_and_after_apply_failures() {
    for timing in [FailureTiming::BeforeApply, FailureTiming::AfterApply] {
        let storage = SharedSecureStorage::new();
        let store = storage.key_store();
        let prepared = store.prepare_identity_creation().unwrap();
        storage.fail_store(OPERATION_JOURNAL_KEY, 0, timing);

        assert!(is_storage_failure(
            store.abort_operation(prepared.operation.id)
        ));

        let recovered = storage.key_store();
        let expected = match timing {
            FailureTiming::BeforeApply => KeyStoreOperationStatus::Prepared,
            FailureTiming::AfterApply => KeyStoreOperationStatus::Aborted,
        };
        assert_eq!(
            recovered.operation_status(prepared.operation.id).unwrap(),
            expected
        );
        recovered.abort_operation(prepared.operation.id).unwrap();
        assert!(recovered.unfinished_operations().unwrap().is_empty());
        assert!(recovered.identity().unwrap().is_none());
    }
}

#[test]
fn orphaned_preparation_is_discoverable_and_abortable_after_restart() {
    let storage = SharedSecureStorage::new();
    let store = storage.key_store();
    let prepared = store.prepare_identity_creation().unwrap();
    drop(store);

    let recovered = storage.key_store();
    let unfinished = recovered.unfinished_operations().unwrap();
    assert_eq!(unfinished.len(), 1);
    assert_eq!(unfinished[0].operation.id, prepared.operation.id);
    assert_eq!(unfinished[0].status, KeyStoreOperationStatus::Prepared);

    recovered.abort_operation(prepared.operation.id).unwrap();
    assert!(recovered.identity().unwrap().is_none());
    assert!(recovered.unfinished_operations().unwrap().is_empty());
}

#[test]
fn reserved_preparation_blocks_authoritative_reads_until_recovery() {
    let storage = SharedSecureStorage::new();
    let store = storage.key_store();
    let prepared = store.prepare_identity_creation().unwrap();
    store.reserve_operation(prepared.operation.id).unwrap();

    assert!(matches!(
        store.identity(),
        Err(KeyStoreError::Operation(
            KeyStoreOperationError::RecoveryRequired { id }
        )) if id == prepared.operation.id
    ));

    store.abort_operation(prepared.operation.id).unwrap();
    assert!(store.identity().unwrap().is_none());
}

#[test]
fn applied_store_with_ambiguous_failure_is_safely_replayed() {
    let storage = SharedSecureStorage::new();
    let store = storage.key_store();
    let prepared = store.prepare_identity_creation().unwrap();
    store.reserve_operation(prepared.operation.id).unwrap();

    storage.fail_store_after_apply("discovery/current");
    assert!(is_storage_failure(
        store.finalize_operation(prepared.operation.id)
    ));
    assert_eq!(storage.successful_stores("discovery/current"), 1);
    drop(store);

    let recovered = storage.key_store();
    recovered.finalize_operation(prepared.operation.id).unwrap();
    assert_eq!(storage.successful_stores("discovery/current"), 2);
    let identity = recovered.load_identity().unwrap();
    assert_eq!(
        identity.public_key().as_bytes(),
        prepared.output.public_key().as_bytes()
    );
    assert_eq!(
        identity.verifying_key().to_bytes(),
        prepared.output.verifying_key().to_bytes()
    );
}

#[test]
fn applied_delete_with_ambiguous_failure_is_safely_replayed() {
    let storage = SharedSecureStorage::new();
    let store = storage.key_store();
    let identity = store.prepare_identity_creation().unwrap();
    store.reserve_operation(identity.operation.id).unwrap();
    store.finalize_operation(identity.operation.id).unwrap();
    let reset = store.prepare_identity_deletion().unwrap();
    store.reserve_operation(reset.operation.id).unwrap();

    storage.fail_delete_after_apply("discovery/current");
    assert!(is_storage_failure(
        store.finalize_operation(reset.operation.id)
    ));
    assert_eq!(storage.successful_deletes("discovery/current"), 1);
    drop(store);

    let recovered = storage.key_store();
    recovered.finalize_operation(reset.operation.id).unwrap();
    assert_eq!(storage.successful_deletes("discovery/current"), 2);
    assert!(recovered.identity().unwrap().is_none());
}
