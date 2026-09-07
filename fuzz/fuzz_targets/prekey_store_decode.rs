#![no_main]

use roost_core::fuzzing::{
    fuzz_decode_discovery_key_blob, fuzz_decode_one_time_prekey_pool,
    fuzz_decode_signed_prekey_blob,
};
use libfuzzer_sys::fuzz_target;

mod support;

fuzz_target!(|data: &[u8]| {
    if let Some(text) = support::text(data)
        && let Some((kind, blob)) = text_case(text)
    {
        decode_kind(kind, &blob);
        return;
    }

    let Some((&kind, blob)) = data.split_first() else {
        return;
    };
    decode_kind(kind, blob);
});

fn text_case(text: &str) -> Option<(u8, Vec<u8>)> {
    let kind = match support::field(text, "kind")? {
        "discovery" => 0,
        "signed" => 1,
        "one_time" => 2,
        _ => return None,
    };
    Some((kind, support::hex_field(text, "blob")?))
}

fn decode_kind(kind: u8, blob: &[u8]) {
    match kind % 3 {
        0 => {
            let _ = fuzz_decode_discovery_key_blob(blob);
        }
        1 => {
            let _ = fuzz_decode_signed_prekey_blob(blob);
        }
        _ => {
            let _ = fuzz_decode_one_time_prekey_pool(blob);
        }
    }
}
