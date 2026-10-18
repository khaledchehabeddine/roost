//! Prepared inbox rotation across the public KeyStore and SecureStorage seam.
//!
//! The scenario proves that a newly returned inbox rotation remains provisional until the
//! prepared secure mutation is reserved and finalized.

use crate::support::host_identity::DeviceStorage;

#[test]
fn prepared_inbox_rotation_does_not_advance_authoritative_epoch_before_finalize() {
    let store = DeviceStorage::default().open();
    let identity = store.prepare_identity_creation().unwrap();
    store.reserve_operation(identity.operation.id).unwrap();
    store.finalize_operation(identity.operation.id).unwrap();
    let before = store.current_public_discovery_key().unwrap();

    let prepared = store.prepare_inbox_rotation().unwrap();

    assert_eq!(
        store.current_public_discovery_key().unwrap().epoch,
        before.epoch
    );
    assert_eq!(prepared.output.discovery_key.epoch, before.epoch + 1);

    store.reserve_operation(prepared.operation.id).unwrap();
    store.finalize_operation(prepared.operation.id).unwrap();
    assert_eq!(
        store.current_public_discovery_key().unwrap().epoch,
        before.epoch + 1
    );
}
