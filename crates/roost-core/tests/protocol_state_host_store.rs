//! Core commit conditions protect shared host blobs and outbox effects across Library Instances.

mod support;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use roost_core::{ProtocolStateCommitCondition, ProtocolStateEngine, ProtocolStateKey};
use support::{HostCommitError, HostStore, ProtocolFixture};

#[test]
fn core_conditions_reject_stale_absence_and_digest_before_host_effects() {
    let engine = ProtocolStateEngine::new();
    let key = ProtocolStateKey::from_bytes(b"new-identity".to_vec()).unwrap();
    let mut rng = ChaCha20Rng::from_seed([0x40; 32]);
    let first = engine
        .initialize_deduplication_set(&mut rng, key.clone())
        .unwrap();
    let stale = engine.initialize_deduplication_set(&mut rng, key).unwrap();
    assert!(matches!(
        first.commit_condition(),
        ProtocolStateCommitCondition::Absent
    ));
    let mut host = HostStore::default();
    host.commit(vec![first]).unwrap();
    let address = stale.address().clone();
    let before = host.blob_bytes(&address);
    assert_eq!(
        host.commit(vec![stale]),
        Err(HostCommitError::StaleCondition)
    );
    assert_eq!(host.blob_bytes(&address), before);

    let mut fixture = ProtocolFixture::new([0x41; 32]);
    let mut stale = engine
        .encrypt_message_with_transport_binding(
            &mut rng,
            &fixture.alice_store.snapshot(),
            fixture.outbound(2, b"stale"),
            &fixture.binding,
        )
        .unwrap();
    assert!(stale.state_updates.iter().all(|update| matches!(
        update.commit_condition(),
        ProtocolStateCommitCondition::Digest(_)
    )));
    let committed = fixture.encrypt_from_alice(&engine, 1, b"committed");
    let before: Vec<_> = stale
        .state_updates
        .iter()
        .map(|update| {
            (
                update.address().clone(),
                fixture.alice_store.blob_bytes(update.address()),
            )
        })
        .collect();
    // A valid first update must not apply if a later condition fails.
    let fresh = engine
        .initialize_deduplication_set(
            &mut rng,
            ProtocolStateKey::from_bytes(b"fresh".to_vec()).unwrap(),
        )
        .unwrap();
    let fresh_address = fresh.address().clone();
    stale.state_updates.insert(0, fresh);
    assert_eq!(
        fixture
            .alice_store
            .commit_outbound(stale.state_updates, stale.message_id, &stale.message),
        Err(HostCommitError::StaleCondition)
    );
    assert!(fixture.alice_store.blob_bytes(&fresh_address).is_none());
    for (address, blob) in before {
        assert_eq!(fixture.alice_store.blob_bytes(&address), blob);
    }
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
