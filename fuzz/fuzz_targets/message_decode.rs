#![no_main]

use libfuzzer_sys::fuzz_target;

mod support;

fuzz_target!(|data: &[u8]| {
    let bytes = support::bytes_from_seed(data);
    if let Ok(message) = roost_core::Message::from_bytes(&bytes) {
        let _ = message.to_bytes();
    }
});
