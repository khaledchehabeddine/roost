#![no_main]

use aether_crypto::{
    DiscoveryKeyBundle, OneTimePreKeyBundle, PreKeyBundle, SignedPreKeyBundle,
    verify_discovery_key_bundle, verify_signed_prekey_bundle,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_LEN: usize = 256;

struct Cursor<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    fn bytes(&mut self, len: usize) -> &'a [u8] {
        let start = self.offset.min(self.data.len());
        let end = start.saturating_add(len).min(self.data.len());
        self.offset = end;
        &self.data[start..end]
    }

    fn array<const N: usize>(&mut self) -> [u8; N] {
        let slice = self.bytes(N);
        let mut bytes = [0u8; N];
        bytes[..slice.len()].copy_from_slice(slice);
        bytes
    }

    fn u32(&mut self) -> u32 {
        u32::from_be_bytes(self.array())
    }

    fn u64(&mut self) -> u64 {
        u64::from_be_bytes(self.array())
    }
}

fuzz_target!(|data: &[u8]| {
    let data = &data[..data.len().min(MAX_INPUT_LEN)];
    let mut cursor = Cursor::new(data);

    let Ok(discovery_key) = DiscoveryKeyBundle::from_bytes(
        cursor.bytes(32),
        cursor.bytes(32),
        cursor.u32(),
        cursor.u64(),
        cursor.bytes(64),
    ) else {
        return;
    };
    let _ = verify_discovery_key_bundle(&discovery_key, &discovery_key.verifying_key);

    let Ok(signed_prekey) = SignedPreKeyBundle::from_bytes(
        cursor.bytes(32),
        cursor.bytes(64),
        discovery_key.epoch,
        cursor.u64(),
    ) else {
        return;
    };
    let _ = verify_signed_prekey_bundle(&signed_prekey, &discovery_key.verifying_key);

    let one_time_prekey = OneTimePreKeyBundle::from_bytes(
        cursor.u64(),
        cursor.bytes(32),
        discovery_key.epoch,
        cursor.u64(),
    )
    .ok();
    let _ = PreKeyBundle {
        discovery_key,
        signed_prekey,
        one_time_prekey,
    };
});
