//! Identity creation and recovery across the prepared-operation lifecycle and a host commit.
//!
//! Each scenario reserves a prepared identity, commits it in a host transaction with a chosen
//! outcome, then recovers the way a host does at startup. An unknown outcome covers both a lost
//! reply and a cancellation that hides whether the transaction committed.

use crate::support::host_identity::{
    CommitResult, DeviceStorage, HostCommit, IdentityDatabase, recover,
};

#[test]
fn unknown_outcome_that_committed_finalizes_after_restart() {
    let storage = DeviceStorage::default();
    let database = IdentityDatabase::default();
    let store = storage.open();
    let prepared = store.prepare_identity_creation().unwrap();
    store.reserve_operation(prepared.operation.id).unwrap();
    assert_eq!(
        database.commit_identity(prepared.operation.id, HostCommit::AppliesWithUnknownOutcome),
        CommitResult::Unknown
    );
    drop(store);

    let restarted = storage.open();
    recover(&restarted, &database).unwrap();

    let identity = restarted.identity().unwrap().unwrap();
    assert_eq!(identity.public_key(), prepared.output.public_key());
    assert!(restarted.unfinished_operations().unwrap().is_empty());
    assert!(database.pending_finalizations().is_empty());
}

#[test]
fn unknown_outcome_that_did_not_commit_aborts_after_restart() {
    let storage = DeviceStorage::default();
    let database = IdentityDatabase::default();
    let store = storage.open();
    let lost = store.prepare_identity_creation().unwrap();
    store.reserve_operation(lost.operation.id).unwrap();
    assert_eq!(
        database.commit_identity(lost.operation.id, HostCommit::FailsWithUnknownOutcome),
        CommitResult::Unknown
    );
    drop(store);

    let restarted = storage.open();
    recover(&restarted, &database).unwrap();
    assert!(restarted.identity().unwrap().is_none());
    assert!(restarted.unfinished_operations().unwrap().is_empty());

    let created = restarted.prepare_identity_creation().unwrap();
    restarted.reserve_operation(created.operation.id).unwrap();
    database.commit_identity(created.operation.id, HostCommit::Applies);
    restarted.finalize_operation(created.operation.id).unwrap();
    assert_eq!(
        restarted.identity().unwrap().unwrap().public_key(),
        created.output.public_key()
    );
}

#[test]
fn finalization_the_host_never_recorded_is_reconciled_after_restart() {
    let storage = DeviceStorage::default();
    let database = IdentityDatabase::default();
    let store = storage.open();
    let prepared = store.prepare_identity_creation().unwrap();
    store.reserve_operation(prepared.operation.id).unwrap();
    database.commit_identity(prepared.operation.id, HostCommit::Applies);
    store.finalize_operation(prepared.operation.id).unwrap();
    drop(store);
    assert_eq!(database.pending_finalizations(), [prepared.operation.id]);

    let restarted = storage.open();
    recover(&restarted, &database).unwrap();
    assert!(database.pending_finalizations().is_empty());
    assert_eq!(
        restarted.identity().unwrap().unwrap().public_key(),
        prepared.output.public_key()
    );
}
