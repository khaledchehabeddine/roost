#![no_main]

use libfuzzer_sys::fuzz_target;
use roost_core::fuzzing::fuzz_unpad_sealed_payload;

fuzz_target!(|data: &[u8]| {
    let _ = fuzz_unpad_sealed_payload(data);
});
