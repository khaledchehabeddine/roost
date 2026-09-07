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
        .decrypt_message_with_transport_bindings(
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
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
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
        .decrypt_message_with_transport_bindings(
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
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .map(session_unrecoverable)
        .unwrap();
    assert!(repeated.event.is_none());
    assert!(repeated.state_updates.is_empty());

    let replacement = support::setup([0x60; 32]);
    for (host, state, peer) in [
        (
            &mut fixture.alice_store,
            &replacement.alice_state,
            &fixture.bob_sender,
        ),
        (
            &mut fixture.bob_store,
            &replacement.bob_state,
            &fixture.alice_sender.sender_identity,
        ),
    ] {
        let initialize = || {
            engine
                .set_session_state_with_peer_identity(fixture.session_key.clone(), state, peer)
                .unwrap()
        };
        let read = host.read();
        // A new handshake cannot silently overwrite an existing live or dead Session.
        assert_eq!(
            host.commit(read.token, vec![initialize()]),
            Err(support::HostCommitError::StaleCondition)
        );
        let read = host.read();
        host.commit(
            read.token,
            engine.wipe(&read.snapshot, fixture.session_key.clone()),
        )
        .unwrap();
        assert!(host.blob_bytes(&address).is_none());
        let read = host.read();
        host.commit(
            read.token,
            vec![
                initialize(),
                engine
                    .initialize_pending_acknowledgments(fixture.session_key.clone())
                    .unwrap(),
            ],
        )
        .unwrap();
    }
    let recovered = fixture.encrypt_from_alice(&engine, 2, b"after replacement");
    let recovered = fixture.decrypt_for_bob(&engine, &recovered, 0x61);
    assert_eq!(recovered.plaintext.as_slice(), b"after replacement");
}
