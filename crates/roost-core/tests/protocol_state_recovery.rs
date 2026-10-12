//! Dead Session host-store recovery scenario for Protocol State Blobs.

mod support;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use roost_core::{ProtocolStateEngine, SessionEvent, SessionUnrecoverableReason};
use support::{ProtocolFixture, dead_session_blob, session_address, session_unrecoverable};

#[test]
fn dead_session_marker_is_durable_until_caller_replaces_session() {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0x59; 32]);
    let message = fixture.encrypt_from_alice(&engine, 1, b"dead session probe");
    let address = session_address(fixture.session_id);
    fixture.bob_store.set_raw(
        address.clone(),
        dead_session_blob(false, fixture.alice.identity_key())
            .as_bytes()
            .to_vec(),
    );
    let domain_keys = [fixture.alice_sender.domain_signing_key()];
    let revoked = [];

    let first_read = fixture.bob_store.snapshot();
    let first = engine
        .decrypt_message_with_transport_bindings(
            &mut ChaCha20Rng::from_seed([0x5a; 32]),
            &first_read,
            fixture.inbound(&message.message, &domain_keys, &revoked),
            &fixture.binding,
            &fixture.binding,
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
    fixture.bob_store.commit(first.state_updates).unwrap();

    let repeated = engine
        .decrypt_message_with_transport_bindings(
            &mut ChaCha20Rng::from_seed([0x5b; 32]),
            &fixture.bob_store.snapshot(),
            fixture.inbound(&message.message, &domain_keys, &revoked),
            &fixture.binding,
            &fixture.binding,
        )
        .map(session_unrecoverable)
        .unwrap();
    assert!(repeated.event.is_none());
    assert!(repeated.state_updates.is_empty());

    let dead_session = fixture.session_id;
    // Only a new handshake replaces a Dead Session, and it gets its own SessionID.
    fixture.start_session(&engine, &mut ChaCha20Rng::from_seed([0x60; 32]));
    assert_ne!(fixture.session_id, dead_session);
    assert!(fixture.bob_store.blob_bytes(&address).is_some());
    let recovered = fixture.encrypt_from_alice(&engine, 2, b"after replacement");
    let recovered = fixture.decrypt_for_bob(&engine, &recovered, 0x61);
    assert_eq!(recovered.plaintext.as_slice(), b"after replacement");
}
