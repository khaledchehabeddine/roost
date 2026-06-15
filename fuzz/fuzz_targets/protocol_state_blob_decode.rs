#![no_main]

use aether_core::fuzzing::fuzz_decode_protocol_state_blob;
use aether_core::{ProtocolStateBlob, ProtocolStateKey, ProtocolStateKind};
use libfuzzer_sys::fuzz_target;

mod support;

fuzz_target!(|data: &[u8]| {
    if let Some(text) = support::text(data)
        && let Some((kind, key, blob)) = text_case(text)
    {
        let _ = fuzz_decode_protocol_state_blob(kind, key, ProtocolStateBlob::from_bytes(blob));
        return;
    }

    let Some((&kind_byte, rest)) = data.split_first() else {
        return;
    };
    let key_len = rest.first().map_or(1, |byte| usize::from(*byte % 32) + 1);
    let payload = rest.get(1..).unwrap_or_default();
    let split = key_len.min(payload.len());
    let (key_bytes, blob) = payload.split_at(split);
    if let Some(key) = protocol_state_key(key_bytes.to_vec()) {
        let _ = fuzz_decode_protocol_state_blob(
            kind_from_byte(kind_byte),
            key,
            ProtocolStateBlob::from_bytes(blob.to_vec()),
        );
    }
});

fn text_case(text: &str) -> Option<(ProtocolStateKind, ProtocolStateKey, Vec<u8>)> {
    let kind = kind_from_name(support::field(text, "kind")?)?;
    let key = protocol_state_key(support::hex_field(text, "key")?)?;
    let blob = support::hex_field(text, "blob")?;
    Some((kind, key, blob))
}

fn protocol_state_key(bytes: Vec<u8>) -> Option<ProtocolStateKey> {
    ProtocolStateKey::from_bytes(bytes)
        .or_else(|_| ProtocolStateKey::from_bytes(vec![1]))
        .ok()
}

fn kind_from_name(name: &str) -> Option<ProtocolStateKind> {
    match name {
        "ratchet_session" => Some(ProtocolStateKind::RatchetSession),
        "deduplication_set" => Some(ProtocolStateKind::DeduplicationSet),
        "pending_acknowledgments" => Some(ProtocolStateKind::PendingAcknowledgments),
        "contact_state" => Some(ProtocolStateKind::ContactState),
        _ => None,
    }
}

fn kind_from_byte(byte: u8) -> ProtocolStateKind {
    match byte % 4 {
        0 => ProtocolStateKind::RatchetSession,
        1 => ProtocolStateKind::DeduplicationSet,
        2 => ProtocolStateKind::PendingAcknowledgments,
        _ => ProtocolStateKind::ContactState,
    }
}
