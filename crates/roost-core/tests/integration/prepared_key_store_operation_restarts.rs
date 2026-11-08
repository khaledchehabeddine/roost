use crate::support::app_identity::DeviceStorage;
use rand::rngs::OsRng;
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
fn prepared_journal_transition_resumes_after_failures_before_and_after_apply() {
    for timing in [FailureTiming::BeforeApply, FailureTiming::AfterApply] {
        let storage = SharedSecureStorage::new();
        storage.fail_store(OPERATION_JOURNAL_KEY, 0, timing);

        assert!(is_storage_failure(
            storage.key_store().prepare_identity_creation(&mut OsRng)
        ));

        let restarted = storage.key_store();
        let unfinished = restarted.unfinished_operations().unwrap();
        match timing {
            FailureTiming::BeforeApply => assert!(unfinished.is_empty()),
            FailureTiming::AfterApply => {
                assert_eq!(unfinished.len(), 1);
                assert_eq!(unfinished[0].status, KeyStoreOperationStatus::Prepared);
                restarted.abort_operation(unfinished[0].id).unwrap();
            }
        }
        assert!(restarted.identity().unwrap().is_none());
    }
}

#[test]
fn reserved_journal_transition_resumes_after_failures_before_and_after_apply() {
    for timing in [FailureTiming::BeforeApply, FailureTiming::AfterApply] {
        let storage = SharedSecureStorage::new();
        let store = storage.key_store();
        let prepared = store.prepare_identity_creation(&mut OsRng).unwrap();
        storage.fail_store(OPERATION_JOURNAL_KEY, 0, timing);

        assert!(is_storage_failure(store.reserve_operation(prepared.id)));

        let restarted = storage.key_store();
        let expected = match timing {
            FailureTiming::BeforeApply => KeyStoreOperationStatus::Prepared,
            FailureTiming::AfterApply => KeyStoreOperationStatus::Reserved,
        };
        assert_eq!(restarted.operation_status(prepared.id).unwrap(), expected);
        // The app never ran its transaction, so aborting is safe either way.
        restarted.abort_operation(prepared.id).unwrap();
        assert!(restarted.identity().unwrap().is_none());
    }
}

#[test]
fn finalizing_journal_transition_resumes_after_failures_before_and_after_apply() {
    for timing in [FailureTiming::BeforeApply, FailureTiming::AfterApply] {
        let storage = SharedSecureStorage::new();
        let store = storage.key_store();
        let prepared = store.prepare_identity_creation(&mut OsRng).unwrap();
        store.reserve_operation(prepared.id).unwrap();
        storage.fail_store(OPERATION_JOURNAL_KEY, 0, timing);

        assert!(is_storage_failure(store.finalize_operation(prepared.id)));

        let restarted = storage.key_store();
        let expected = match timing {
            FailureTiming::BeforeApply => KeyStoreOperationStatus::Reserved,
            FailureTiming::AfterApply => KeyStoreOperationStatus::Finalizing,
        };
        assert_eq!(restarted.operation_status(prepared.id).unwrap(), expected);
        restarted.finalize_operation(prepared.id).unwrap();
        assert!(restarted.identity().unwrap().is_some());
    }
}

#[test]
fn progress_checkpoint_resumes_after_failures_before_and_after_apply() {
    for timing in [FailureTiming::BeforeApply, FailureTiming::AfterApply] {
        let storage = SharedSecureStorage::new();
        let store = storage.key_store();
        let prepared = store.prepare_identity_creation(&mut OsRng).unwrap();
        store.reserve_operation(prepared.id).unwrap();
        // Skip the Finalizing write, then fail the first durable progress checkpoint.
        storage.fail_store(OPERATION_JOURNAL_KEY, 1, timing);

        assert!(is_storage_failure(store.finalize_operation(prepared.id)));
        assert_eq!(storage.successful_stores("discovery/current"), 1);
        drop(store);

        let restarted = storage.key_store();
        assert_eq!(
            restarted.operation_status(prepared.id).unwrap(),
            KeyStoreOperationStatus::Finalizing
        );
        restarted.finalize_operation(prepared.id).unwrap();
        let expected_stores = match timing {
            FailureTiming::BeforeApply => 2,
            FailureTiming::AfterApply => 1,
        };
        assert_eq!(
            storage.successful_stores("discovery/current"),
            expected_stores
        );
        assert!(restarted.identity().unwrap().is_some());
    }
}

#[test]
fn finalized_journal_transition_resumes_after_failures_before_and_after_apply() {
    for timing in [FailureTiming::BeforeApply, FailureTiming::AfterApply] {
        let storage = SharedSecureStorage::new();
        let store = storage.key_store();
        let identity = store.prepare_identity_creation(&mut OsRng).unwrap();
        store.reserve_operation(identity.id).unwrap();
        store.finalize_operation(identity.id).unwrap();
        let initial_signed_prekey = store.prepare_signed_prekey_rotation(&mut OsRng).unwrap();
        store.reserve_operation(initial_signed_prekey.id).unwrap();
        store.finalize_operation(initial_signed_prekey.id).unwrap();
        let prepared = store
            .prepare_signed_prekey_rotation_and_discovery_key_cleanup(&mut OsRng)
            .unwrap();
        assert!(prepared.output.is_none());
        store.reserve_operation(prepared.id).unwrap();
        // A no-op has only Finalizing and Finalized journal writes.
        storage.fail_store(OPERATION_JOURNAL_KEY, 1, timing);

        assert!(is_storage_failure(store.finalize_operation(prepared.id)));

        let restarted = storage.key_store();
        let expected = match timing {
            FailureTiming::BeforeApply => KeyStoreOperationStatus::Finalizing,
            FailureTiming::AfterApply => KeyStoreOperationStatus::Finalized,
        };
        assert_eq!(restarted.operation_status(prepared.id).unwrap(), expected);
        restarted.finalize_operation(prepared.id).unwrap();
        assert!(restarted.unfinished_operations().unwrap().is_empty());
    }
}

#[test]
fn aborted_journal_transition_resumes_after_failures_before_and_after_apply() {
    for timing in [FailureTiming::BeforeApply, FailureTiming::AfterApply] {
        let storage = SharedSecureStorage::new();
        let store = storage.key_store();
        let prepared = store.prepare_identity_creation(&mut OsRng).unwrap();
        storage.fail_store(OPERATION_JOURNAL_KEY, 0, timing);

        assert!(is_storage_failure(store.abort_operation(prepared.id)));

        let restarted = storage.key_store();
        let expected = match timing {
            FailureTiming::BeforeApply => KeyStoreOperationStatus::Prepared,
            FailureTiming::AfterApply => KeyStoreOperationStatus::Aborted,
        };
        assert_eq!(restarted.operation_status(prepared.id).unwrap(), expected);
        restarted.abort_operation(prepared.id).unwrap();
        assert!(restarted.unfinished_operations().unwrap().is_empty());
        assert!(restarted.identity().unwrap().is_none());
    }
}

#[test]
fn orphaned_preparation_is_discoverable_and_abortable_after_restart() {
    let storage = SharedSecureStorage::new();
    let store = storage.key_store();
    let prepared = store.prepare_identity_creation(&mut OsRng).unwrap();
    drop(store);

    let restarted = storage.key_store();
    let unfinished = restarted.unfinished_operations().unwrap();
    assert_eq!(unfinished.len(), 1);
    assert_eq!(unfinished[0].id, prepared.id);
    assert_eq!(unfinished[0].status, KeyStoreOperationStatus::Prepared);

    restarted.abort_operation(prepared.id).unwrap();
    assert!(restarted.identity().unwrap().is_none());
    assert!(restarted.unfinished_operations().unwrap().is_empty());
}

#[test]
fn reserved_preparation_blocks_authoritative_reads_until_finished() {
    let storage = SharedSecureStorage::new();
    let store = storage.key_store();
    let prepared = store.prepare_identity_creation(&mut OsRng).unwrap();
    store.reserve_operation(prepared.id).unwrap();

    assert!(matches!(
        store.identity(),
        Err(KeyStoreError::Operation(
            KeyStoreOperationError::UnfinishedReservation { id }
        )) if id == prepared.id
    ));

    store.abort_operation(prepared.id).unwrap();
    assert!(store.identity().unwrap().is_none());
}

#[test]
fn applied_store_with_ambiguous_failure_is_safely_replayed() {
    let storage = SharedSecureStorage::new();
    let store = storage.key_store();
    let prepared = store.prepare_identity_creation(&mut OsRng).unwrap();
    store.reserve_operation(prepared.id).unwrap();

    storage.fail_store_after_apply("discovery/current");
    assert!(is_storage_failure(store.finalize_operation(prepared.id)));
    assert_eq!(storage.successful_stores("discovery/current"), 1);
    drop(store);

    let restarted = storage.key_store();
    restarted.finalize_operation(prepared.id).unwrap();
    assert_eq!(storage.successful_stores("discovery/current"), 2);
    let identity = restarted.load_identity().unwrap();
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
    let identity = store.prepare_identity_creation(&mut OsRng).unwrap();
    store.reserve_operation(identity.id).unwrap();
    store.finalize_operation(identity.id).unwrap();
    let reset = store.prepare_identity_deletion(&mut OsRng).unwrap();
    store.reserve_operation(reset.id).unwrap();

    storage.fail_delete_after_apply("discovery/current");
    assert!(is_storage_failure(store.finalize_operation(reset.id)));
    assert_eq!(storage.successful_deletes("discovery/current"), 1);
    drop(store);

    let restarted = storage.key_store();
    restarted.finalize_operation(reset.id).unwrap();
    assert_eq!(storage.successful_deletes("discovery/current"), 2);
    assert!(restarted.identity().unwrap().is_none());
}
