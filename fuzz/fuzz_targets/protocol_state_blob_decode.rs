#![no_main]

use libfuzzer_sys::fuzz_target;
use roost_core::fuzzing::fuzz_decode_protocol_state_blob;
use roost_core::{ProtocolStateBlob, ProtocolStateKey, ProtocolStateKind};

fuzz_target!(|data: &[u8]| {
    let [kind, key_len, payload @ ..] = data else {
        return;
    };
    let (key, blob) = payload.split_at(usize::from(*key_len).min(payload.len()));
    if let Ok(key) = ProtocolStateKey::from_bytes(key.to_vec()) {
        let kinds = ProtocolStateKind::all();
        let _ = fuzz_decode_protocol_state_blob(
            kinds[usize::from(*kind) % kinds.len()],
            key,
            ProtocolStateBlob::from_bytes(blob.to_vec()),
        );
    }
});
