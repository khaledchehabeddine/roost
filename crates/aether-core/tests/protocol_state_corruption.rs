//! Corrupt committed blob scenario for Protocol State Blobs.

mod support;

use aether_core::{ProtocolStateEngine, ProtocolStateError};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use support::{
    ProtocolFixture, deduplication_address, inbound_with_certificate_validation, ratchet_address,
};

#[test]
fn corrupt_committed_blobs_surface_faults_without_reinitialization() {
    let engine = ProtocolStateEngine::new();
    let fixture = ProtocolFixture::new([0x56; 32]);
    let message = {
        let mut sender = fixture;
        sender.encrypt_from_alice(&engine, 1, b"corruption probe")
    };
    let fixture = ProtocolFixture::new([0x56; 32]);
    let domain_keys = [fixture.alice_sender.domain_signing_key()];
    let revoked = [];

    let ratchet_address = ratchet_address(fixture.session_key.clone());
    let mut corrupt_ratchet = fixture.bob_store.clone();
    corrupt_ratchet.set_raw(ratchet_address.clone(), vec![1, 0, 0xaa]);
    assert!(matches!(
        engine.decrypt_message(
            &mut ChaCha20Rng::from_seed([0x57; 32]),
            &corrupt_ratchet.read().snapshot,
            inbound_with_certificate_validation(
                fixture.session_key.clone(),
                fixture.deduplication_key.clone(),
                &message.message,
                &fixture.bob_sender,
                &domain_keys,
                &revoked,
            ),
        ),
        Err(ProtocolStateError::BlobDecode { address, .. }) if address == ratchet_address
    ));
    assert_eq!(
        corrupt_ratchet.blob_bytes(&ratchet_address).unwrap(),
        vec![1, 0, 0xaa]
    );

    let deduplication_address = deduplication_address(fixture.deduplication_key.clone());
    let mut corrupt_deduplication = fixture.bob_store.clone();
    corrupt_deduplication.set_raw(deduplication_address.clone(), vec![1, 0, 0xaa]);
    assert!(matches!(
        engine.decrypt_message(
            &mut ChaCha20Rng::from_seed([0x58; 32]),
            &corrupt_deduplication.read().snapshot,
            inbound_with_certificate_validation(
                fixture.session_key.clone(),
                fixture.deduplication_key.clone(),
                &message.message,
                &fixture.bob_sender,
                &domain_keys,
                &revoked,
            ),
        ),
        Err(ProtocolStateError::BlobDecode { address, .. }) if address == deduplication_address
    ));
    assert_eq!(
        corrupt_deduplication
            .blob_bytes(&deduplication_address)
            .unwrap(),
        vec![1, 0, 0xaa]
    );
}
