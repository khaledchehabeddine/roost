#![no_main]

use libfuzzer_sys::fuzz_target;
use roost_core::fuzzing::fuzz_decode_sealed_sender_envelope;

fuzz_target!(|data: &[u8]| {
    let _ = fuzz_decode_sealed_sender_envelope(data);
});
