//! Prepared identity creation across the public KeyStore and SecureStorage seam.
//!
//! The scenario proves that staged secret material is not authoritative until the app reserves
//! and finalizes the prepared operation, including idempotent lifecycle calls.

use crate::support::app_identity::DeviceStorage;
use rand::rngs::OsRng;
use roost_core::{KeyStoreError, KeyStoreOperationError, KeyStoreOperationStatus};

#[test]
fn prepared_identity_creation_becomes_visible_only_after_finalize() {
    let store = DeviceStorage::default().open();

    let prepared = store.prepare_identity_creation(&mut OsRng).unwrap();
    let id = prepared.id;

    assert!(store.identity().unwrap().is_none());
    assert_eq!(
        store.operation_status(id).unwrap(),
        KeyStoreOperationStatus::Prepared
    );

    assert_eq!(
        store.reserve_operation(id).unwrap(),
        KeyStoreOperationStatus::Reserved
    );
    assert_eq!(
        store.reserve_operation(id).unwrap(),
        KeyStoreOperationStatus::Reserved
    );

    assert_eq!(
        store.finalize_operation(id).unwrap(),
        KeyStoreOperationStatus::Finalized
    );
    assert_eq!(
        store.finalize_operation(id).unwrap(),
        KeyStoreOperationStatus::Finalized
    );
    assert!(store.identity().unwrap().is_some());
    assert_eq!(
        store.load_identity().unwrap().public_key(),
        prepared.output.public_key()
    );
}

#[test]
fn prepared_operation_rejects_secure_state_changed_after_preparation() {
    let store = DeviceStorage::default().open();
    let first = store.prepare_identity_creation(&mut OsRng).unwrap();
    let stale = store.prepare_identity_creation(&mut OsRng).unwrap();

    store.reserve_operation(first.id).unwrap();
    store.finalize_operation(first.id).unwrap();

    assert!(matches!(
        store.reserve_operation(stale.id),
        Err(KeyStoreError::Operation(
            KeyStoreOperationError::PreconditionChanged { key }
        )) if key == "discovery/current"
    ));
    assert_eq!(
        store.abort_operation(stale.id).unwrap(),
        KeyStoreOperationStatus::Aborted
    );
    assert_eq!(
        store.abort_operation(stale.id).unwrap(),
        KeyStoreOperationStatus::Aborted
    );
}
