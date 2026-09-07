//! Dead Session host-store recovery scenario for Protocol State Blobs.

mod support;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use roost_core::{ProtocolStateEngine, SessionEvent, SessionUnrecoverableReason};
use support::{
    ProtocolFixture, dead_session_blob, inbound_with_certificate_validation, ratchet_address,
    session_unrecoverable,
};

#[test]
fn dead_session_marker_is_durable_until_caller_replaces_session() {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0x59; 32]);
    let message = fixture.encrypt_from_alice(&engine, 1, b"dead session probe");
    let address = ratchet_address(fixture.session_key.clone());
    fixture.bob_store.set_raw(
        address.clone(),
        dead_session_blob(false, fixture.alice_sender.sender_identity.identity_key)
            .as_bytes()
            .to_vec(),
    );
    let domain_keys = [fixture.alice_sender.domain_signing_key()];
    let revoked = [];

    let first_read = fixture.bob_store.read();
    let first = engine
        .decrypt_message(
            &mut ChaCha20Rng::from_seed([0x5a; 32]),
            &first_read.snapshot,
            inbound_with_certificate_validation(
                fixture.session_key.clone(),
                fixture.deduplication_key.clone(),
                &message.message,
                &fixture.bob_sender,
                &domain_keys,
                &revoked,
            ),
        )
        .map(session_unrecoverable)
        .unwrap();
    assert_eq!(
        first.reason,
        SessionUnrecoverableReason::SkippedKeyLimitExceeded
    );
    assert!(matches!(
        first.event,
        Some(SessionEvent::Unrecoverable {
            reason: SessionUnrecoverableReason::SkippedKeyLimitExceeded,
            ..
        })
    ));
    fixture
        .bob_store
        .commit(first_read.token, first.state_updates)
        .unwrap();

    let repeated = engine
        .decrypt_message(
            &mut ChaCha20Rng::from_seed([0x5b; 32]),
            &fixture.bob_store.read().snapshot,
            inbound_with_certificate_validation(
                fixture.session_key.clone(),
                fixture.deduplication_key.clone(),
                &message.message,
                &fixture.bob_sender,
                &domain_keys,
                &revoked,
            ),
        )
        .map(session_unrecoverable)
        .unwrap();
    assert!(repeated.event.is_none());
    assert!(repeated.state_updates.is_empty());

    let replacement = ProtocolFixture::new([0x60; 32]);
    fixture.alice_store = replacement.alice_store;
    fixture.bob_store = replacement.bob_store;
    let recovered = fixture.encrypt_from_alice(&engine, 2, b"after replacement");
    let recovered = fixture.decrypt_for_bob(&engine, &recovered, 0x61);
    assert_eq!(recovered.plaintext.as_slice(), b"after replacement");
}
