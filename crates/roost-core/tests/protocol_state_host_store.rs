//! Host-store transaction scenarios for multiple Library Instances sharing Protocol State Blobs.

mod support;

use rand::SeedableRng;
use roost_core::ProtocolStateEngine;
use support::{
    HostCommitError, ProtocolFixture, inbound_with_certificate_validation, sequenced_outbound,
};

#[test]
fn core_conditions_reject_stale_absence_and_digest_before_host_effects() {
    use roost_core::{ProtocolStateCommitCondition, ProtocolStateKey};
    let engine = ProtocolStateEngine::new();
    let key = ProtocolStateKey::from_bytes(b"new-session".to_vec()).unwrap();
    let first = engine
        .initialize_pending_acknowledgments(key.clone())
        .unwrap();
    let stale = engine.initialize_pending_acknowledgments(key).unwrap();
    assert!(matches!(
        first.commit_condition(),
        ProtocolStateCommitCondition::Absent
    ));
    let mut host = support::HostStore::default();
    host.commit(host.read().token, vec![first]).unwrap();
    let address = stale.address().clone();
    let before = host.blob_bytes(&address);
    assert_eq!(
        host.commit(host.read().token, vec![stale]),
        Err(HostCommitError::StaleCondition)
    );
    assert_eq!(host.blob_bytes(&address), before);
    assert!(host.outbox().is_empty());

    let mut fixture = ProtocolFixture::new([0x41; 32]);
    let read = fixture.alice_store.read();
    let stale = engine
        .encrypt_message_with_transport_binding(
            &read.snapshot,
            fixture.session_key.clone(),
            sequenced_outbound(2, b"stale", &fixture.alice_sender.sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap();
    assert!(stale.state_updates.iter().all(|update| matches!(
        update.commit_condition(),
        ProtocolStateCommitCondition::Digest(_)
    )));
    fixture.encrypt_from_alice(&engine, 1, b"committed");
    let latest = fixture.alice_store.read();
    assert!(stale.state_updates.iter().any(|update| {
        !update
            .commit_condition()
            .is_satisfied_by(latest.snapshot.get(update.address()))
    }));
    // Even a current host revision cannot bless updates computed from old blobs.
    assert!(
        fixture
            .alice_store
            .commit_outbound(
                latest.token,
                stale.state_updates,
                stale.message_id,
                &stale.message
            )
            .is_err()
    );
    assert_eq!(fixture.alice_store.outbox().len(), 1);
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

#[test]
fn stale_read_commit_is_rejected_before_forked_state_becomes_authoritative() {
    let first_instance = ProtocolStateEngine::new();
    let second_instance = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0x34; 32]);

    let first_read = fixture.alice_store.read();
    let stale_read = fixture.alice_store.read();
    let first = first_instance
        .encrypt_message_with_transport_binding(
            &first_read.snapshot,
            fixture.session_key.clone(),
            sequenced_outbound(1, b"committed first", &fixture.alice_sender.sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap();
    let first_id = first.message_id;
    fixture
        .alice_store
        .commit_outbound(
            first_read.token,
            first.state_updates,
            first_id,
            &first.message,
        )
        .unwrap();

    let stale = second_instance
        .encrypt_message_with_transport_binding(
            &stale_read.snapshot,
            fixture.session_key.clone(),
            sequenced_outbound(2, b"stale fork", &fixture.alice_sender.sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap();
    let stale_id = stale.message_id;
    let stale_commit = fixture.alice_store.commit_outbound(
        stale_read.token,
        stale.state_updates,
        stale_id,
        &stale.message,
    );
    assert!(matches!(
        stale_commit,
        Err(HostCommitError::StaleRead { .. })
    ));
    assert!(
        fixture
            .alice_store
            .outbox()
            .iter()
            .all(|record| record.message_id != stale_id)
    );

    let latest_read = fixture.alice_store.read();
    let latest = second_instance
        .encrypt_message_with_transport_binding(
            &latest_read.snapshot,
            fixture.session_key.clone(),
            sequenced_outbound(
                3,
                b"committed second",
                &fixture.alice_sender.sender_identity,
            ),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap();
    let latest_id = latest.message_id;
    fixture
        .alice_store
        .commit_outbound(
            latest_read.token,
            latest.state_updates,
            latest_id,
            &latest.message,
        )
        .unwrap();
    assert_eq!(fixture.alice_store.outbox().len(), 2);

    let first_message = fixture
        .alice_store
        .outbox()
        .iter()
        .find(|record| record.message_id == first_id)
        .unwrap()
        .message();
    let latest_message = fixture
        .alice_store
        .outbox()
        .iter()
        .find(|record| record.message_id == latest_id)
        .unwrap()
        .message();
    let domain_keys = [fixture.alice_sender.domain_signing_key()];
    let revoked = [];
    let first_read = fixture.bob_store.read();
    let first_decrypted = first_instance
        .decrypt_message_with_transport_bindings(
            &mut rand_chacha::ChaCha20Rng::from_seed([0x35; 32]),
            &first_read.snapshot,
            inbound_with_certificate_validation(
                fixture.session_key.clone(),
                fixture.deduplication_key.clone(),
                &first_message,
                &fixture.bob_sender,
                &domain_keys,
                &revoked,
            ),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .map(support::accepted)
        .unwrap();
    fixture
        .bob_store
        .commit(first_read.token, first_decrypted.state_updates)
        .unwrap();

    let latest_read = fixture.bob_store.read();
    let latest_decrypted = second_instance
        .decrypt_message_with_transport_bindings(
            &mut rand_chacha::ChaCha20Rng::from_seed([0x36; 32]),
            &latest_read.snapshot,
            inbound_with_certificate_validation(
                fixture.session_key.clone(),
                fixture.deduplication_key.clone(),
                &latest_message,
                &fixture.bob_sender,
                &domain_keys,
                &revoked,
            ),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .map(support::accepted)
        .unwrap();
    assert_eq!(latest_decrypted.plaintext.as_slice(), b"committed second");
}
