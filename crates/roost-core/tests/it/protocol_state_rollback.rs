//! An interrupted receive discards provisional output and retries from committed host blobs.

use crate::support::{ProtocolFixture, accepted};
use roost_core::{InboundMessageOutcome, ProtocolStateKind};

#[test]
fn interrupted_receive_commit_leaves_only_last_committed_state_visible() {
    let mut fixture = ProtocolFixture::new();
    let first = fixture.encrypt_from_alice(1, b"committed");
    fixture.decrypt_for_bob(&first, 0x52);
    let second = fixture.encrypt_from_alice(2, b"interrupted");
    let addresses = [
        ProtocolStateKind::RatchetSession,
        ProtocolStateKind::DeduplicationSet,
    ]
    .map(|kind| fixture.bob.host.only(kind));
    let before = addresses
        .each_ref()
        .map(|address| fixture.bob.host.blob_bytes(address));
    let interrupted = accepted(
        fixture
            .receive(&fixture.bob.host, &second.message, 0x53)
            .unwrap()
            .outcome,
    );
    assert_eq!(interrupted.plaintext.as_slice(), b"interrupted");
    drop(interrupted);
    assert_eq!(
        addresses
            .each_ref()
            .map(|address| fixture.bob.host.blob_bytes(address)),
        before
    );

    fixture.bob.restart();
    let store = fixture.bob.host.clone();
    assert!(matches!(
        fixture
            .receive(&store, &first.message, 0x54)
            .unwrap()
            .outcome,
        InboundMessageOutcome::Duplicate
    ));
    let retried = accepted(
        fixture
            .receive(&store, &second.message, 0x55)
            .unwrap()
            .outcome,
    );
    assert_eq!(retried.plaintext.as_slice(), b"interrupted");
}
