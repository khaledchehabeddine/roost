//! Core commit conditions protect shared host blobs and outbox effects across Library Instances.

mod support;

use roost_core::{ProtocolStateCommitCondition, ProtocolStateEngine};
use support::{HostCommitError, HostStore, ProtocolFixture, accepted_contact_identity};

#[test]
fn core_conditions_reject_stale_absence_and_digest_before_host_effects() {
    let engine = ProtocolStateEngine::new();
    let mut host = HostStore::default();
    let contact = accepted_contact_identity();
    let first = engine
        .record_contact(&host.snapshot(), contact)
        .unwrap()
        .state_updates;
    let stale = engine
        .record_contact(&host.snapshot(), contact)
        .unwrap()
        .state_updates;
    assert!(matches!(
        first[0].commit_condition(),
        ProtocolStateCommitCondition::Absent
    ));
    host.commit(first).unwrap();
    let address = stale[0].address().clone();
    let before = host.blob_bytes(&address);
    assert_eq!(host.commit(stale), Err(HostCommitError::StaleCondition));
    assert_eq!(host.blob_bytes(&address), before);

    let mut fixture = ProtocolFixture::new([0x41; 32]);
    let stale = fixture
        .encrypt(
            &engine,
            &fixture.alice_store,
            fixture.outgoing(2, b"stale"),
            0x40,
        )
        .unwrap();
    assert!(
        stale
            .changes
            .conditions()
            .iter()
            .all(|(_, condition)| matches!(condition, ProtocolStateCommitCondition::Digest(_)))
    );
    let committed = fixture.encrypt_from_alice(&engine, 1, b"committed");
    let before = fixture.alice_store.snapshot_bytes();
    assert_eq!(
        fixture.alice_store.commit_sent(stale),
        Err(HostCommitError::StaleCondition)
    );
    assert_eq!(fixture.alice_store.snapshot_bytes(), before);
    assert_eq!(fixture.alice_store.outbox().len(), 1);
    assert_eq!(
        fixture.alice_store.outbox()[0].message_id,
        committed.message_id
    );
    assert_eq!(
        fixture.alice_store.outbox()[0]
            .message()
            .to_bytes()
            .unwrap(),
        committed.message.to_bytes().unwrap()
    );
    let received = fixture.decrypt_for_bob(&engine, &committed, 0x42);
    assert_eq!(received.plaintext.as_slice(), b"committed");
}

#[test]
fn multiple_instances_mutate_same_identity_through_serialized_commits() {
    let first_instance = ProtocolStateEngine::new();
    let second_instance = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0x31; 32]);
    let first = fixture.encrypt_from_alice(&first_instance, 1, b"from first instance");
    let second = fixture.encrypt_from_alice(&second_instance, 2, b"from second instance");
    let second_decrypted = fixture.decrypt_for_bob(&second_instance, &second, 0x32);
    assert_eq!(
        second_decrypted.plaintext.as_slice(),
        b"from second instance"
    );
    let first_decrypted = fixture.decrypt_for_bob(&first_instance, &first, 0x33);
    assert_eq!(first_decrypted.plaintext.as_slice(), b"from first instance");
}
