//! Signed-prekey layouts older than the current one fail with a typed error and stay in storage.

mod support;

use roost_core::{KeyStore, KeyStoreError, SecureStorage, SignedPreKeyError};
use support::host_identity::DeviceStorage;

const SIGNED_PREKEY_KEY: &str = "prekey/signed";

// Each old layout's version byte and total length: v1 held one record, v2 added a retained-key
// flag and record, and v3 added the retained key's supersession time.
const OLD_SIGNED_PREKEY_LAYOUTS: [(u8, usize); 3] = [(1, 109), (2, 218), (3, 226)];

fn key_store_with_identity(storage: &DeviceStorage) -> KeyStore {
    let key_store = storage.open();
    let id = key_store.prepare_identity_creation().unwrap().operation.id;
    key_store.reserve_operation(id).unwrap();
    key_store.finalize_operation(id).unwrap();
    key_store
}

fn is_unsupported_version<T>(result: Result<T, KeyStoreError>, version: u8) -> bool {
    matches!(
        result,
        Err(KeyStoreError::SignedPreKey(SignedPreKeyError::UnsupportedVersion(stored)))
            if stored == version
    )
}

#[test]
fn old_signed_prekey_layouts_fail_without_changing_storage() {
    for (version, len) in OLD_SIGNED_PREKEY_LAYOUTS {
        let mut storage = DeviceStorage::default();
        let key_store = key_store_with_identity(&storage);
        let mut blob = vec![0; len];
        blob[0] = version;
        storage.store(SIGNED_PREKEY_KEY, &blob).unwrap();

        assert!(is_unsupported_version(
            key_store.current_publication(),
            version
        ));
        assert!(is_unsupported_version(
            key_store.prepare_signed_prekey_rotation_if_stale(),
            version
        ));
        assert_eq!(
            storage.load(SIGNED_PREKEY_KEY).unwrap().unwrap().as_slice(),
            blob
        );
    }
}
