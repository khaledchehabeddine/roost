//! Stable prekey identifiers across rotation through the public KeyStore interface.

use crate::support::app_identity::DeviceStorage;
use rand::rngs::OsRng;
use roost_core::{KeyStore, PreparedKeyStoreOperation};

#[test]
fn prekey_ids_are_stable_and_restart_with_each_discovery_key_epoch() {
    let store = DeviceStorage::default().open();
    let identity = store.prepare_identity_creation(&mut OsRng).unwrap();
    finalize(&store, &identity);

    let first_signed = store.prepare_signed_prekey_rotation(&mut OsRng).unwrap();
    assert_eq!(first_signed.output.id, 0);
    finalize(&store, &first_signed);
    let second_signed = store.prepare_signed_prekey_rotation(&mut OsRng).unwrap();
    assert_eq!(second_signed.output.id, 1);
    finalize(&store, &second_signed);
    assert_eq!(store.current_publication().unwrap().signed_prekey.id, 1);

    let one_time = store.prepare_one_time_prekeys(&mut OsRng, 2).unwrap();
    assert_eq!(
        one_time
            .output
            .iter()
            .map(|prekey| prekey.id)
            .collect::<Vec<_>>(),
        vec![0, 1]
    );
    finalize(&store, &one_time);

    let rotated_inbox = store.prepare_inbox_rotation(&mut OsRng).unwrap();
    assert_eq!(rotated_inbox.output.signed_prekey.id, 0);
    finalize(&store, &rotated_inbox);
    let next_epoch_one_time = store.prepare_one_time_prekeys(&mut OsRng, 1).unwrap();
    assert_eq!(next_epoch_one_time.output[0].id, 0);
}

fn finalize<T>(store: &KeyStore, prepared: &PreparedKeyStoreOperation<T>) {
    store.reserve_operation(prepared.id).unwrap();
    store.finalize_operation(prepared.id).unwrap();
}
