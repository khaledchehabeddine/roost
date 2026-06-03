#![no_main]

use aether_crypto::HandshakeEnvelope;
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_LEN: usize = 4096;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT_LEN {
        return;
    }
    let _ = HandshakeEnvelope::from_bytes(data);
});
