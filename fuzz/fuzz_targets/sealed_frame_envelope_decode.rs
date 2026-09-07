#![no_main]

use roost_core::fuzzing::fuzz_decode_sealed_sender_envelope;
use roost_crypto::{
    HandshakeEnvelope, KeyPair, PublicKey, SealedFrame, SealedFramePreKeyReference, open_frame,
    seal_frame,
};
use libfuzzer_sys::fuzz_target;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

mod support;

fuzz_target!(|data: &[u8]| {
    let bytes = support::bytes_from_seed(data);
    if let Ok(frame) = SealedFrame::from_bytes(&bytes) {
        let _ = frame.to_bytes();
    }
    if let Ok(envelope) = HandshakeEnvelope::from_bytes(&bytes) {
        let _ = envelope.to_bytes();
    }
    let _ = fuzz_decode_sealed_sender_envelope(&bytes);
    aad_probe(data);
});

fn aad_probe(data: &[u8]) {
    let recipient = KeyPair::from_secret_bytes([0x42; 32]);
    let mut rng = ChaCha20Rng::from_seed([0x12; 32]);
    let Ok(mut frame) = seal_frame(&mut rng, &recipient.public, None, b"metadata-bound") else {
        return;
    };
    match aad_case(data) {
        0 => frame.version = frame.version.wrapping_add(1),
        1 => frame.recipient_public_key = *KeyPair::from_secret_bytes([0x43; 32]).public.as_bytes(),
        2 => frame.ephemeral_public_key = *KeyPair::from_secret_bytes([0x44; 32]).public.as_bytes(),
        3 => {
            frame.prekey_reference = Some(SealedFramePreKeyReference {
                discovery_epoch: u32::from(data.get(1).copied().unwrap_or_default()),
                signed_prekey_public_key: *KeyPair::from_secret_bytes([0x45; 32]).public.as_bytes(),
                one_time_prekey_id: None,
                one_time_prekey_public_key: None,
            });
        }
        _ => {
            if let Some(last) = frame.ciphertext.last_mut() {
                *last ^= data.get(1).copied().unwrap_or(1);
            }
        }
    }
    let _ = frame.to_bytes();
    let _ = open_frame(&recipient, &frame);
    let _ = open_frame(&KeyPair::from_secret_bytes([0x43; 32]), &frame);
    let _ = seal_frame(
        &mut rng,
        &PublicKey::from(frame.recipient_public_key),
        frame.prekey_reference,
        &frame.ciphertext,
    );
}

fn aad_case(data: &[u8]) -> u8 {
    if let Some(label) = data.strip_prefix(b"aad:") {
        return match label
            .split(|byte| *byte == b'\n')
            .next()
            .unwrap_or_default()
        {
            b"version" => 0,
            b"recipient" => 1,
            b"ephemeral" => 2,
            b"prekey" => 3,
            _ => 4,
        };
    }
    data.first().copied().unwrap_or_default() % 5
}
