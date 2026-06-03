#![no_main]

use aether_core::{InMemorySecureStorage, KeyStore, SecureStorage};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_LEN: usize = 128;

fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(MAX_INPUT_LEN)];
    let split = data.len() / 2;
    let mut storage = InMemorySecureStorage::new();
    let _ = storage.store("identity/x25519", &data[..split]);
    let _ = storage.store("identity/ed25519", &data[split..]);

    let store = KeyStore::new(Box::new(storage));
    let _ = store.load_identity();
});
