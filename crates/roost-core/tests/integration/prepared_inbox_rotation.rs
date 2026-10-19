//! Prepared inbox rotation across the public KeyStore and SecureStorage seam.
//!
//! The scenario proves that a newly returned inbox rotation remains provisional until the
//! prepared secure mutation is reserved and finalized.

use crate::support::host_identity::DeviceStorage;
use roost_core::KeyStore;

fn epoch(store: &KeyStore) -> u32 {
    store.current_publication().unwrap().discovery_key.epoch
}

#[test]
fn prepared_inbox_rotation_does_not_advance_authoritative_epoch_before_finalize() {
    let store = DeviceStorage::default().open();
    let identity = store.prepare_identity_creation().unwrap();
    store.reserve_operation(identity.id).unwrap();
    store.finalize_operation(identity.id).unwrap();
    let signed_prekey = store.prepare_signed_prekey_rotation().unwrap();
    store.reserve_operation(signed_prekey.id).unwrap();
    store.finalize_operation(signed_prekey.id).unwrap();
    let before = epoch(&store);

    let prepared = store.prepare_inbox_rotation().unwrap();

    assert_eq!(epoch(&store), before);
    assert_eq!(prepared.output.discovery_key.epoch, before + 1);

    store.reserve_operation(prepared.id).unwrap();
    store.finalize_operation(prepared.id).unwrap();
    assert_eq!(epoch(&store), before + 1);
}
