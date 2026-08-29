//! Prepared inbox rotation across the public KeyStore and SecureStorage seam.
//!
//! The scenario proves that a newly returned inbox generation remains provisional until the
//! prepared secure mutation is committed and finalized.

use aether_core::{InMemorySecureStorage, KeyStore};

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
