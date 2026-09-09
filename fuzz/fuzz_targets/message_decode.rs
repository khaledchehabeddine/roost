#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(message) = roost_core::Message::from_bytes(data) {
        let _ = message.to_bytes();
    }
});
