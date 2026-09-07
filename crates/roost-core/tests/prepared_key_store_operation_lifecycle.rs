//! Prepared identity creation across the public KeyStore and SecureStorage seam.
//!
//! The scenario proves that staged secret material is not authoritative until the caller commits
//! and finalizes the prepared operation, including idempotent lifecycle calls.

use roost_core::{
    InMemorySecureStorage, KeyStore, KeyStoreError, KeyStoreOperationError,
    KeyStoreOperationStatus, SecureStorageExpectedValue,
};

#[test]
fn prepared_identity_creation_becomes_visible_only_after_finalize() {
    let store = KeyStore::new(Box::new(InMemorySecureStorage::new()));

    let prepared = store.prepare_generate_identity().unwrap();
    let identifier = prepared.operation.identifier;

    assert!(!store.has_identity().unwrap());
    assert_eq!(
        store.operation_status(identifier).unwrap(),
        KeyStoreOperationStatus::Prepared
    );
    assert!(
        prepared
            .operation
            .secure_storage_preconditions
            .iter()
            .all(|precondition| matches!(
                precondition.expected_value,
                SecureStorageExpectedValue::Absent
            ))
    );

    assert_eq!(
        store.commit_operation(identifier).unwrap(),
        KeyStoreOperationStatus::Committed
    );
    assert_eq!(
        store.commit_operation(identifier).unwrap(),
        KeyStoreOperationStatus::Committed
    );

    assert_eq!(
        store.finalize_operation(identifier).unwrap(),
        KeyStoreOperationStatus::Finalized
    );
    assert_eq!(
        store.finalize_operation(identifier).unwrap(),
        KeyStoreOperationStatus::Finalized
    );
    assert!(store.has_identity().unwrap());
    assert_eq!(
        store.load_identity().unwrap().public_key(),
        prepared.output.public_key()
    );
}

#[test]
fn prepared_operation_rejects_secure_state_changed_after_preparation() {
    let store = KeyStore::new(Box::new(InMemorySecureStorage::new()));
    let first = store.prepare_generate_identity().unwrap();
    let stale = store.prepare_generate_identity().unwrap();

    store.commit_operation(first.operation.identifier).unwrap();
    store
        .finalize_operation(first.operation.identifier)
        .unwrap();

    assert!(matches!(
        store.commit_operation(stale.operation.identifier),
        Err(KeyStoreError::Operation(
            KeyStoreOperationError::PreconditionChanged { .. }
        ))
    ));
    assert_eq!(
        store.abort_operation(stale.operation.identifier).unwrap(),
        KeyStoreOperationStatus::Aborted
    );
    assert_eq!(
        store.abort_operation(stale.operation.identifier).unwrap(),
        KeyStoreOperationStatus::Aborted
    );
}
