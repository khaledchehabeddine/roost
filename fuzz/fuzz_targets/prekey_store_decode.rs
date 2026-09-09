#![no_main]

use libfuzzer_sys::fuzz_target;
use roost_core::fuzzing::{
    fuzz_decode_discovery_key_blob, fuzz_decode_one_time_prekey_pool,
    fuzz_decode_signed_prekey_blob,
};

fuzz_target!(|data: &[u8]| {
    let Some((&kind, blob)) = data.split_first() else {
        return;
    };
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
});
