use crate::support::app_identity::{
    AppCommit, CommitResult, DeviceStorage, IdentityDatabase, resolve_unfinished,
};
use rand::rngs::OsRng;

#[test]
fn unknown_outcome_that_committed_finalizes_after_restart() {
    let storage = DeviceStorage::default();
    let database = IdentityDatabase::default();
    let store = storage.open();
    let prepared = store.prepare_identity_creation(&mut OsRng).unwrap();
    store.reserve_operation(prepared.id).unwrap();
    assert_eq!(
        database.commit_identity(prepared.id, AppCommit::AppliesWithUnknownOutcome),
        CommitResult::Unknown
    );
    drop(store);

    let restarted = storage.open();
    resolve_unfinished(&restarted, &database).unwrap();

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
    let lost = store.prepare_identity_creation(&mut OsRng).unwrap();
    store.reserve_operation(lost.id).unwrap();
    assert_eq!(
        database.commit_identity(lost.id, AppCommit::FailsWithUnknownOutcome),
        CommitResult::Unknown
    );
    drop(store);

    let restarted = storage.open();
    resolve_unfinished(&restarted, &database).unwrap();
    assert!(restarted.identity().unwrap().is_none());
    assert!(restarted.unfinished_operations().unwrap().is_empty());

    let created = restarted.prepare_identity_creation(&mut OsRng).unwrap();
    restarted.reserve_operation(created.id).unwrap();
    database.commit_identity(created.id, AppCommit::Applies);
    restarted.finalize_operation(created.id).unwrap();
    assert_eq!(
        restarted.identity().unwrap().unwrap().public_key(),
        created.output.public_key()
    );
}
