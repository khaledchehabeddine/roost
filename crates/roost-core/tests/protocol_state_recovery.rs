//! Dead Session host-store recovery scenario for Protocol State Blobs.

mod support;

use roost_core::{SessionEvent, SessionUnrecoverableReason};
use support::{ProtocolFixture, dead_session_blob, session_address, session_unrecoverable};

#[test]
fn dead_session_marker_is_durable_until_caller_replaces_session() {
    let mut fixture = ProtocolFixture::new();
    let message = fixture.encrypt_from_alice(1, b"dead session probe");
    let address = session_address(fixture.session_id);
    fixture.bob.host.set_raw(
        address.clone(),
        dead_session_blob(false, fixture.alice.identity_key())
            .as_bytes()
            .to_vec(),
    );
    let first = fixture
        .receive(&fixture.bob.host, &message.message, 0x5a)
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
    fixture.bob.host.commit_changes(first.changes).unwrap();

    let repeated = fixture
        .receive(&fixture.bob.host, &message.message, 0x5b)
        .map(session_unrecoverable)
        .unwrap();
    assert!(repeated.event.is_none());
    assert!(repeated.changes.updates().is_empty());

    let dead_session = fixture.session_id;
    // Only a new handshake replaces a Dead Session, and it gets its own SessionID.
    fixture.start_session();
    assert_ne!(fixture.session_id, dead_session);
    assert!(fixture.bob.host.blob_bytes(&address).is_some());
    let recovered = fixture.encrypt_from_alice(2, b"after replacement");
    let recovered = fixture.decrypt_for_bob(&recovered, 0x61);
    assert_eq!(recovered.plaintext.as_slice(), b"after replacement");
}
