//! Prepared KeyStore operation recovery across process replacement and storage failure.
//!
//! The scenario crosses the public KeyStore and SecureStorage seams to model orphaned preparation,
//! a crash after commit, ambiguous mutation results, and a crash during finalization.

use roost_core::{
    InMemorySecureStorage, KeyStore, KeyStoreError, KeyStoreOperationError,
    KeyStoreOperationStatus, SecureStorage, StorageError,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

const OPERATION_JOURNAL_KEY: &str = "operation/journal";

#[derive(Clone)]
struct SharedSecureStorage {
    state: Arc<Mutex<StorageState>>,
}

struct StorageState {
    storage: InMemorySecureStorage,
    fail_delete_after_apply: Option<String>,
    fail_store_after_apply: Option<String>,
    store_failure: Option<StoreFailure>,
    stores_before_failure: Option<usize>,
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
                storage: InMemorySecureStorage::new(),
                fail_delete_after_apply: None,
                fail_store_after_apply: None,
                store_failure: None,
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
        if let Some(remaining) = state.stores_before_failure.as_mut() {
            if *remaining == 0 {
                state.stores_before_failure = None;
                return Err(StorageError::IO("injected store failure".into()));
            }
            *remaining -= 1;
        }

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

        assert!(storage.key_store().prepare_generate_identity().is_err());

        let recovered = storage.key_store();
        let unfinished = recovered.unfinished_operations().unwrap();
        match timing {
            FailureTiming::BeforeApply => assert!(unfinished.is_empty()),
            FailureTiming::AfterApply => {
                assert_eq!(unfinished.len(), 1);
                assert_eq!(unfinished[0].status, KeyStoreOperationStatus::Prepared);
                recovered
                    .abort_operation(unfinished[0].operation.identifier)
                    .unwrap();
            }
        }
        assert!(!recovered.has_identity().unwrap());
    }
}

#[test]
fn committed_journal_transition_recovers_from_before_and_after_apply_failures() {
    for timing in [FailureTiming::BeforeApply, FailureTiming::AfterApply] {
        let storage = SharedSecureStorage::new();
        let store = storage.key_store();
        let prepared = store.prepare_generate_identity().unwrap();
        storage.fail_store(OPERATION_JOURNAL_KEY, 0, timing);

        assert!(
            store
                .commit_operation(prepared.operation.identifier)
                .is_err()
        );

        let recovered = storage.key_store();
        let expected = match timing {
            FailureTiming::BeforeApply => KeyStoreOperationStatus::Prepared,
            FailureTiming::AfterApply => KeyStoreOperationStatus::Committed,
        };
        assert_eq!(
            recovered
                .operation_status(prepared.operation.identifier)
                .unwrap(),
            expected
        );
        // The host transaction was deliberately not attempted, so abort is safe in either case.
        recovered
            .abort_operation(prepared.operation.identifier)
            .unwrap();
        assert!(!recovered.has_identity().unwrap());
    }
}

#[test]
fn finalizing_journal_transition_recovers_from_before_and_after_apply_failures() {
    for timing in [FailureTiming::BeforeApply, FailureTiming::AfterApply] {
        let storage = SharedSecureStorage::new();
        let store = storage.key_store();
        let prepared = store.prepare_generate_identity().unwrap();
        store
            .commit_operation(prepared.operation.identifier)
            .unwrap();
        storage.fail_store(OPERATION_JOURNAL_KEY, 0, timing);

        assert!(
            store
                .finalize_operation(prepared.operation.identifier)
                .is_err()
        );

        let recovered = storage.key_store();
        let expected = match timing {
            FailureTiming::BeforeApply => KeyStoreOperationStatus::Committed,
            FailureTiming::AfterApply => KeyStoreOperationStatus::Finalizing,
        };
        assert_eq!(
            recovered
                .operation_status(prepared.operation.identifier)
                .unwrap(),
            expected
        );
        recovered
            .finalize_operation(prepared.operation.identifier)
            .unwrap();
        assert!(recovered.has_identity().unwrap());
    }
}

#[test]
fn progress_checkpoint_recovers_from_before_and_after_apply_failures() {
    for timing in [FailureTiming::BeforeApply, FailureTiming::AfterApply] {
        let storage = SharedSecureStorage::new();
        let store = storage.key_store();
        let prepared = store.prepare_generate_identity().unwrap();
        store
            .commit_operation(prepared.operation.identifier)
            .unwrap();
        // Skip the Finalizing write, then fail the first durable progress checkpoint.
        storage.fail_store(OPERATION_JOURNAL_KEY, 1, timing);

        assert!(
            store
                .finalize_operation(prepared.operation.identifier)
                .is_err()
        );
        assert_eq!(storage.successful_stores("discovery/current"), 1);
        drop(store);

        let recovered = storage.key_store();
        assert_eq!(
            recovered
                .operation_status(prepared.operation.identifier)
                .unwrap(),
            KeyStoreOperationStatus::Finalizing
        );
        recovered
            .finalize_operation(prepared.operation.identifier)
            .unwrap();
        let expected_stores = match timing {
            FailureTiming::BeforeApply => 2,
            FailureTiming::AfterApply => 1,
        };
        assert_eq!(
            storage.successful_stores("discovery/current"),
            expected_stores
        );
        assert!(recovered.has_identity().unwrap());
    }
}

#[test]
fn finalized_journal_transition_recovers_from_before_and_after_apply_failures() {
    for timing in [FailureTiming::BeforeApply, FailureTiming::AfterApply] {
        let storage = SharedSecureStorage::new();
        let store = storage.key_store();
        let identity = store.prepare_generate_identity().unwrap();
        store
            .commit_operation(identity.operation.identifier)
            .unwrap();
        store
            .finalize_operation(identity.operation.identifier)
            .unwrap();
        let initial_signed_prekey = store.prepare_rotate_signed_prekey_now().unwrap();
        store
            .commit_operation(initial_signed_prekey.operation.identifier)
            .unwrap();
        store
            .finalize_operation(initial_signed_prekey.operation.identifier)
            .unwrap();
        let prepared = store.prepare_rotate_signed_prekey_if_stale().unwrap();
        assert!(prepared.output.is_none());
        store
            .commit_operation(prepared.operation.identifier)
            .unwrap();
        // A no-op has only Finalizing and Finalized journal writes.
        storage.fail_store(OPERATION_JOURNAL_KEY, 1, timing);

        assert!(
            store
                .finalize_operation(prepared.operation.identifier)
                .is_err()
        );

        let recovered = storage.key_store();
        let expected = match timing {
            FailureTiming::BeforeApply => KeyStoreOperationStatus::Finalizing,
            FailureTiming::AfterApply => KeyStoreOperationStatus::Finalized,
        };
        assert_eq!(
            recovered
                .operation_status(prepared.operation.identifier)
                .unwrap(),
            expected
        );
        recovered
            .finalize_operation(prepared.operation.identifier)
            .unwrap();
        assert!(recovered.unfinished_operations().unwrap().is_empty());
    }
}

#[test]
fn aborted_journal_transition_recovers_from_before_and_after_apply_failures() {
    for timing in [FailureTiming::BeforeApply, FailureTiming::AfterApply] {
        let storage = SharedSecureStorage::new();
        let store = storage.key_store();
        let prepared = store.prepare_generate_identity().unwrap();
        storage.fail_store(OPERATION_JOURNAL_KEY, 0, timing);

        assert!(
            store
                .abort_operation(prepared.operation.identifier)
                .is_err()
        );

        let recovered = storage.key_store();
        let expected = match timing {
            FailureTiming::BeforeApply => KeyStoreOperationStatus::Prepared,
            FailureTiming::AfterApply => KeyStoreOperationStatus::Aborted,
        };
        assert_eq!(
            recovered
                .operation_status(prepared.operation.identifier)
                .unwrap(),
            expected
        );
        recovered
            .abort_operation(prepared.operation.identifier)
            .unwrap();
        assert!(recovered.unfinished_operations().unwrap().is_empty());
        assert!(!recovered.has_identity().unwrap());
    }
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
