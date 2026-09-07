//! Interrupted host commit rollback scenario for Protocol State Blobs.

mod support;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use roost_core::{InboundMessageOutcome, ProtocolStateEngine};
use support::{
    ProtocolFixture, accepted, deduplication_address, inbound_duplicate,
    inbound_with_certificate_validation, ratchet_address,
};

#[test]
fn interrupted_receive_commit_leaves_only_last_committed_state_visible() {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0x51; 32]);
    let first = fixture.encrypt_from_alice(&engine, 1, b"committed");
    fixture.decrypt_for_bob(&engine, &first, 0x52);
    let second = fixture.encrypt_from_alice(&engine, 2, b"interrupted");
    let ratchet_address = ratchet_address(fixture.session_key.clone());
    let deduplication_address = deduplication_address(fixture.deduplication_key.clone());
    let committed_ratchet = fixture.bob_store.blob_bytes(&ratchet_address).unwrap();
    let committed_deduplication = fixture
        .bob_store
        .blob_bytes(&deduplication_address)
        .unwrap();

    let domain_keys = [fixture.alice_sender.domain_signing_key()];
    let revoked = [];
    let interrupted_read = fixture.bob_store.read();
    let interrupted = engine
        .decrypt_message_with_transport_bindings(
            &mut ChaCha20Rng::from_seed([0x53; 32]),
            &interrupted_read.snapshot,
            inbound_with_certificate_validation(
                fixture.session_key.clone(),
                fixture.deduplication_key.clone(),
                &second.message,
                &fixture.bob_sender,
                &domain_keys,
                &revoked,
            ),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .map(accepted)
        .unwrap();
    assert_eq!(interrupted.plaintext.as_slice(), b"interrupted");

    assert_eq!(
        fixture.bob_store.blob_bytes(&ratchet_address).unwrap(),
        committed_ratchet
    );
    assert_eq!(
        fixture
            .bob_store
            .blob_bytes(&deduplication_address)
            .unwrap(),
        committed_deduplication
    );

    let duplicate_first = engine
        .decrypt_message_with_transport_bindings(
            &mut ChaCha20Rng::from_seed([0x54; 32]),
            &fixture.bob_store.read().snapshot,
            inbound_duplicate(
                fixture.session_key.clone(),
                fixture.deduplication_key.clone(),
                &first.message,
                &fixture.bob_sender,
            ),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap();
    assert!(matches!(duplicate_first, InboundMessageOutcome::Duplicate));

    let retried_second = engine
        .decrypt_message_with_transport_bindings(
            &mut ChaCha20Rng::from_seed([0x55; 32]),
            &fixture.bob_store.read().snapshot,
            inbound_with_certificate_validation(
                fixture.session_key.clone(),
                fixture.deduplication_key.clone(),
                &second.message,
                &fixture.bob_sender,
                &domain_keys,
                &revoked,
            ),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .map(accepted)
        .unwrap();
    assert_eq!(retried_second.plaintext.as_slice(), b"interrupted");
}
