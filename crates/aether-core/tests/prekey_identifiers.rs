//! Stable prekey identifiers across rotation through the public KeyStore interface.

use aether_core::{InMemorySecureStorage, KeyStore, PreparedKeyStoreOperation};

#[test]
fn prekey_identifiers_are_stable_and_restart_with_each_discovery_key_epoch() {
    let store = KeyStore::new(Box::new(InMemorySecureStorage::new()));
    let identity = store.prepare_generate_identity().unwrap();
    finalize(&store, &identity);

    let first_signed = store.prepare_rotate_signed_prekey_now().unwrap();
    assert_eq!(first_signed.output.id, 0);
    finalize(&store, &first_signed);
    let second_signed = store.prepare_rotate_signed_prekey_now().unwrap();
    assert_eq!(second_signed.output.id, 1);
    finalize(&store, &second_signed);
    assert_eq!(
        store.current_publication_bundle().unwrap().signed_prekey.id,
        1
    );

    let one_time = store.prepare_generate_one_time_prekeys(2).unwrap();
    assert_eq!(
        one_time
            .output
            .iter()
            .map(|prekey| prekey.id)
            .collect::<Vec<_>>(),
        vec![0, 1]
    );
    finalize(&store, &one_time);

    let rotated_inbox = store.prepare_rotate_inbox_now().unwrap();
    assert_eq!(rotated_inbox.output.publication.signed_prekey.id, 0);
    finalize(&store, &rotated_inbox);
    let next_epoch_one_time = store.prepare_generate_one_time_prekeys(1).unwrap();
    assert_eq!(next_epoch_one_time.output[0].id, 0);
}

fn finalize<T>(store: &KeyStore, prepared: &PreparedKeyStoreOperation<T>) {
    store
        .commit_operation(prepared.operation.identifier)
        .unwrap();
    store
        .finalize_operation(prepared.operation.identifier)
        .unwrap();
}
