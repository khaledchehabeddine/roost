//! A device's SecureStorage and the app's identity records, both surviving a process restart.

use roost_core::{
    KeyStore, KeyStoreError, KeyStoreOperationId, KeyStoreOperationStatus, SecureStorage,
    StorageError,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

/// SecureStorage that outlives each KeyStore, as a device keychain outlives the app process.
#[derive(Clone, Default)]
pub(crate) struct DeviceStorage(Arc<Mutex<BTreeMap<String, Zeroizing<Vec<u8>>>>>);

impl DeviceStorage {
    /// Starts a KeyStore over this storage, as a new process would.
    pub(crate) fn open(&self) -> KeyStore {
        KeyStore::new(Box::new(self.clone()))
    }
}

impl SecureStorage for DeviceStorage {
    fn store(&mut self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        self.0
            .lock()
            .unwrap()
            .insert(key.to_string(), Zeroizing::new(value.to_vec()));
        Ok(())
    }

    fn load(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, StorageError> {
        Ok(self.0.lock().unwrap().get(key).cloned())
    }

    fn delete(&mut self, key: &str) -> Result<(), StorageError> {
        self.0.lock().unwrap().remove(key);
        Ok(())
    }
}

/// How one host transaction ends.
pub(crate) enum HostCommit {
    /// The transaction commits and the host sees that it did.
    Applies,
    /// The transaction commits, but a lost reply or a cancellation hides that it did.
    AppliesWithUnknownOutcome,
    /// Nothing commits, and the host can't tell whether it did.
    FailsWithUnknownOutcome,
}

/// What the host learns when a transaction ends.
#[derive(Debug, Eq, PartialEq)]
pub(crate) enum CommitResult {
    Committed,
    Unknown,
}

/// The app's durable identity records, standing in for its database.
#[derive(Clone, Default)]
pub(crate) struct IdentityDatabase(Arc<Mutex<IdentityRecords>>);

#[derive(Default)]
struct IdentityRecords {
    committed_operations: BTreeSet<[u8; 16]>,
    pending_finalizations: BTreeSet<[u8; 16]>,
}

impl IdentityDatabase {
    /// Saves the identity's operation ID in one transaction.
    pub(crate) fn commit_identity(
        &self,
        operation: KeyStoreOperationId,
        commit: HostCommit,
    ) -> CommitResult {
        let applies = matches!(
            commit,
            HostCommit::Applies | HostCommit::AppliesWithUnknownOutcome
        );
        if applies {
            let mut records = self.0.lock().unwrap();
            records.committed_operations.insert(*operation.as_bytes());
            records.pending_finalizations.insert(*operation.as_bytes());
        }
        match commit {
            HostCommit::Applies => CommitResult::Committed,
            HostCommit::AppliesWithUnknownOutcome | HostCommit::FailsWithUnknownOutcome => {
                CommitResult::Unknown
            }
        }
    }

    /// Records that SecureStorage finalized the operation.
    pub(crate) fn mark_finalized(&self, operation: KeyStoreOperationId) {
        self.0
            .lock()
            .unwrap()
            .pending_finalizations
            .remove(operation.as_bytes());
    }

    /// Returns committed operations not yet marked finalized.
    pub(crate) fn pending_finalizations(&self) -> Vec<KeyStoreOperationId> {
        self.0
            .lock()
            .unwrap()
            .pending_finalizations
            .iter()
            .map(|id| KeyStoreOperationId::from_bytes(*id))
            .collect()
    }

    fn has_committed(&self, operation: KeyStoreOperationId) -> bool {
        self.0
            .lock()
            .unwrap()
            .committed_operations
            .contains(operation.as_bytes())
    }
}

/// Resolves unfinished operations against the host's records, as a host does at startup.
///
/// Panics when SecureStorage and the host disagree, since a host must stop rather than guess.
pub(crate) fn recover(store: &KeyStore, database: &IdentityDatabase) -> Result<(), KeyStoreError> {
    for unfinished in store.unfinished_operations()? {
        let id = unfinished.id;
        match (unfinished.status, database.has_committed(id)) {
            (KeyStoreOperationStatus::Reserved | KeyStoreOperationStatus::Finalizing, true) => {
                store.finalize_operation(id)?;
                database.mark_finalized(id);
            }
            (KeyStoreOperationStatus::Prepared | KeyStoreOperationStatus::Reserved, false) => {
                store.abort_operation(id)?;
            }
            (status, committed) => {
                panic!("SecureStorage reports {status:?} but host commit is {committed}")
            }
        }
    }
    // Finalization that finished before the host recorded it no longer appears as unfinished.
    for id in database.pending_finalizations() {
        assert_eq!(
            store.operation_status(id)?,
            KeyStoreOperationStatus::Finalized
        );
        database.mark_finalized(id);
    }
    Ok(())
}
