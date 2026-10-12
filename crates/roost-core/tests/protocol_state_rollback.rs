//! An interrupted receive discards provisional output and retries from committed host blobs.

mod support;

use roost_core::{InboundMessageOutcome, ProtocolStateEngine};
use support::{ProtocolFixture, accepted, deduplication_address, session_address};

#[test]
fn interrupted_receive_commit_leaves_only_last_committed_state_visible() {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0x51; 32]);
    let first = fixture.encrypt_from_alice(&engine, 1, b"committed");
    fixture.decrypt_for_bob(&engine, &first, 0x52);
    let second = fixture.encrypt_from_alice(&engine, 2, b"interrupted");
    let addresses = [
        session_address(fixture.session_id),
        deduplication_address(fixture.deduplication_key.clone()),
    ];
    let before = addresses
        .each_ref()
        .map(|address| fixture.bob_store.blob_bytes(address));
    let interrupted = accepted(
        fixture
            .receive(
                &engine,
                &fixture.bob_store.snapshot(),
                &second.message,
                0x53,
            )
            .unwrap(),
    );
    assert_eq!(interrupted.plaintext.as_slice(), b"interrupted");
    drop(interrupted);
    assert_eq!(
        addresses
            .each_ref()
            .map(|address| fixture.bob_store.blob_bytes(address)),
        before
    );

    let restarted = ProtocolStateEngine::new();
    let snapshot = fixture.bob_store.snapshot();
    assert!(matches!(
        fixture
            .receive(&restarted, &snapshot, &first.message, 0x54)
            .unwrap(),
        InboundMessageOutcome::Duplicate
    ));
    let retried = accepted(
        fixture
            .receive(&restarted, &snapshot, &second.message, 0x55)
            .unwrap(),
    );
    assert_eq!(retried.plaintext.as_slice(), b"interrupted");
}
