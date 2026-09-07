#![no_main]

use roost_core::fuzzing::{fuzz_deduplication_digest, fuzz_unpad_sealed_payload};
use libfuzzer_sys::fuzz_target;

mod support;

fuzz_target!(|data: &[u8]| {
    let bytes = support::bytes_from_seed(data);
    let _ = fuzz_unpad_sealed_payload(&bytes);
    let mut key = [0u8; 32];
    let len = data.len().min(key.len());
    key[..len].copy_from_slice(&data[..len]);
    let _ = fuzz_deduplication_digest(key, &bytes);
});
