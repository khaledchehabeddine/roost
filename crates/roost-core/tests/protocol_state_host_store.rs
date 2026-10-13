//! Core commit conditions protect shared host blobs and outbox effects across Library Instances.

mod support;

use roost_core::ProtocolStateCommitCondition;
use support::device::{Device, Relay, contact_address};
use support::{HostCommitError, ProtocolFixture};

#[test]
fn core_conditions_reject_stale_absence_and_digest_before_host_effects() {
    let relay = Relay::new();
    let mut bob = Device::new(&relay, 0xb0);
    let stranger = Device::new(&relay, 0xc0).identity_key();
    let first = bob.store.prepare_block_contact(stranger, None).unwrap();
    let stale = bob.store.prepare_block_contact(stranger, None).unwrap();
    assert!(matches!(
        stale.changes.conditions()[0].1,
        ProtocolStateCommitCondition::Absent
    ));
    let stale_operation = stale.changes.operation().unwrap();
    bob.commit_changes(first.changes).unwrap();
    let address = contact_address(stranger);
    let before = bob.host.blob_bytes(&address);
    assert_eq!(
        bob.host.commit_changes(stale.changes),
        Err(HostCommitError::StaleCondition)
    );
    assert_eq!(bob.host.blob_bytes(&address), before);
    bob.store.abort_operation(stale_operation).unwrap();

    let mut fixture = ProtocolFixture::new();
    let stale = fixture
        .encrypt(&fixture.alice.host, fixture.outgoing(2, b"stale"), 0x40)
        .unwrap();
    assert!(
        stale
            .changes
            .conditions()
            .iter()
            .all(|(_, condition)| matches!(condition, ProtocolStateCommitCondition::Digest(_)))
    );
    let queued = fixture.alice.host.outbox().len();
    let committed = fixture.encrypt_from_alice(1, b"committed");
    let before = fixture.alice.host.snapshot_bytes();
    assert_eq!(
        fixture.alice.host.commit_sent(stale),
        Err(HostCommitError::StaleCondition)
    );
    assert_eq!(fixture.alice.host.snapshot_bytes(), before);
    let outbox = fixture.alice.host.outbox();
    assert_eq!(outbox.len(), queued + 1);
    assert_eq!(outbox[queued].message_id, committed.message_id);
    assert_eq!(
        outbox[queued].message().to_bytes().unwrap(),
        committed.message.to_bytes().unwrap()
    );
    let received = fixture.decrypt_for_bob(&committed, 0x42);
    assert_eq!(received.plaintext.as_slice(), b"committed");
}

#[test]
fn multiple_instances_mutate_same_identity_through_serialized_commits() {
    let mut fixture = ProtocolFixture::new();
    let first = fixture.encrypt_from_alice(1, b"from first instance");
    fixture.alice.store = fixture.alice.second_instance();
    let second = fixture.encrypt_from_alice(2, b"from second instance");
    let second_decrypted = fixture.decrypt_for_bob(&second, 0x32);
    assert_eq!(
        second_decrypted.plaintext.as_slice(),
        b"from second instance"
    );
    fixture.bob.store = fixture.bob.second_instance();
    let first_decrypted = fixture.decrypt_for_bob(&first, 0x33);
    assert_eq!(first_decrypted.plaintext.as_slice(), b"from first instance");
}
