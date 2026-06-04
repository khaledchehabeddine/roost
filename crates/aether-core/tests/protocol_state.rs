//! Exercises the public protocol-state API over consumer-held opaque blobs.

use aether_core::{
    MessageId, OutboundPlaintext, PayloadKind, ProtocolStateAddress, ProtocolStateBlob,
    ProtocolStateEngine, ProtocolStateError, ProtocolStateKey, ProtocolStateKind,
    ProtocolStateSnapshot, SessionId,
};
use aether_crypto::{
    PreKeyBundle, RatchetState, accept, generate_discovery_key, generate_one_time_prekey,
    generate_signed_prekey_for_discovery_key, generate_signing_key_pair, initial_associated_data,
    initiate,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

const CREATED_AT: u64 = 1_700_000_000;

struct Setup {
    associated_data: Vec<u8>,
    alice_state: RatchetState,
    bob_state: RatchetState,
}

fn setup() -> Setup {
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let alice_identity = generate_signing_key_pair(&mut rng);
    let bob_identity = generate_signing_key_pair(&mut rng);
    let alice_discovery = generate_discovery_key(&mut rng, &alice_identity, 0, CREATED_AT);
    let bob_discovery = generate_discovery_key(&mut rng, &bob_identity, 0, CREATED_AT);
    let bob_signed_prekey =
        generate_signed_prekey_for_discovery_key(&mut rng, &bob_discovery, CREATED_AT);
    let bob_one_time_prekey =
        generate_one_time_prekey(&mut rng, 9, bob_discovery.epoch(), CREATED_AT);
    let prekey_bundle = PreKeyBundle {
        discovery_key: bob_discovery.bundle(),
        signed_prekey: bob_signed_prekey.bundle(),
        one_time_prekey: Some(bob_one_time_prekey.bundle()),
    };
    let associated_data = initial_associated_data(
        alice_discovery.public_key(),
        bob_discovery.public_key(),
        bob_discovery.epoch(),
    );
    let (alice_state, envelope) = initiate(
        &mut rng,
        &alice_discovery,
        &bob_identity.verifying,
        &prekey_bundle,
        b"initial",
    )
    .unwrap();
    let (bob_state, plaintext) = accept(
        &mut rng,
        &envelope,
        &alice_identity.verifying,
        &alice_discovery.bundle(),
        &bob_discovery,
        &bob_signed_prekey,
        Some(bob_one_time_prekey),
    )
    .unwrap();
    assert_eq!(plaintext.as_slice(), b"initial");
    Setup {
        associated_data: associated_data.to_vec(),
        alice_state,
        bob_state,
    }
}

fn key() -> ProtocolStateKey {
    ProtocolStateKey::session(SessionId::from_bytes([9u8; 16]))
}

fn ratchet_address(key: ProtocolStateKey) -> ProtocolStateAddress {
    ProtocolStateAddress::new(ProtocolStateKind::RatchetSession, key)
}

fn snapshot_with_state(
    engine: &ProtocolStateEngine,
    key: ProtocolStateKey,
    state: &RatchetState,
) -> ProtocolStateSnapshot {
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot.apply(engine.set_session_state(key, state).unwrap());
    snapshot
}

fn outbound<'a>(id: u8, plaintext: &'a [u8], associated_data: &'a [u8]) -> OutboundPlaintext<'a> {
    OutboundPlaintext {
        id: MessageId::from_bytes([id; 16]),
        sender_public_key: [1u8; 32],
        recipient_public_key: [2u8; 32],
        timestamp_millis: 1_700_000_000_123 + u64::from(id),
        plaintext,
        associated_data,
    }
}

#[test]
fn outbound_message_and_advanced_state_return_together() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let address = ratchet_address(key.clone());
    let prior_blob = snapshot.get(&address).unwrap().as_bytes().to_vec();

    let result = engine
        .encrypt_message(
            &snapshot,
            key.clone(),
            outbound(1, b"second", &setup.associated_data),
        )
        .unwrap();

    assert_eq!(result.message.payload_kind, PayloadKind::EncryptedText);
    assert_eq!(result.state_updates.len(), 1);
    assert_eq!(result.state_updates[0].address(), &address);
    let advanced_blob = result.state_updates[0].blob().unwrap().as_bytes();
    assert_ne!(advanced_blob, prior_blob.as_slice());
}

#[test]
fn oversized_outbound_message_does_not_return_advanced_state() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let address = ratchet_address(key.clone());
    let prior_blob = snapshot.get(&address).unwrap().as_bytes().to_vec();
    let oversized_plaintext = vec![0u8; 64 * 1024];

    let result = engine.encrypt_message(
        &snapshot,
        key,
        outbound(1, &oversized_plaintext, &setup.associated_data),
    );

    assert!(matches!(result, Err(ProtocolStateError::MessageEncode(_))));
    assert_eq!(snapshot.get(&address).unwrap().as_bytes(), prior_blob);
}

#[test]
fn two_instances_alternate_against_latest_consumer_blobs() {
    let setup = setup();
    let first_instance = ProtocolStateEngine::new();
    let second_instance = ProtocolStateEngine::new();
    let key = key();
    let mut alice_snapshot = snapshot_with_state(&first_instance, key.clone(), &setup.alice_state);
    let mut bob_snapshot = snapshot_with_state(&first_instance, key.clone(), &setup.bob_state);

    let first = first_instance
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            outbound(1, b"from first", &setup.associated_data),
        )
        .unwrap();
    let first_message = first.message;
    alice_snapshot.apply_all(first.state_updates);

    let second = second_instance
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            outbound(2, b"from second", &setup.associated_data),
        )
        .unwrap();
    let second_message = second.message;
    alice_snapshot.apply_all(second.state_updates);

    let first_decrypt = first_instance
        .decrypt_message(
            &mut ChaCha20Rng::from_seed([10u8; 32]),
            &bob_snapshot,
            key.clone(),
            &first_message,
            &setup.associated_data,
        )
        .unwrap();
    let first_plaintext = first_decrypt.plaintext.to_vec();
    bob_snapshot.apply_all(first_decrypt.state_updates);
    let second_decrypt = second_instance
        .decrypt_message(
            &mut ChaCha20Rng::from_seed([11u8; 32]),
            &bob_snapshot,
            key,
            &second_message,
            &setup.associated_data,
        )
        .unwrap();
    let second_plaintext = second_decrypt.plaintext.to_vec();
    bob_snapshot.apply_all(second_decrypt.state_updates);

    assert_eq!(first_plaintext, b"from first");
    assert_eq!(second_plaintext, b"from second");
}

#[test]
fn wipe_removes_all_v0_5_0_state_kinds_for_key() {
    let engine = ProtocolStateEngine::new();
    let key = key();
    let mut snapshot = ProtocolStateSnapshot::new();
    for kind in ProtocolStateKind::v0_5_0_kinds() {
        snapshot.set(
            ProtocolStateAddress::new(*kind, key.clone()),
            ProtocolStateBlob::from_bytes(vec![*kind as u8, 7]),
        );
    }

    snapshot.apply_all(engine.wipe(key.clone()));

    for kind in ProtocolStateKind::v0_5_0_kinds() {
        assert!(
            snapshot
                .get(&ProtocolStateAddress::new(*kind, key.clone()))
                .is_none()
        );
    }
}

#[test]
fn corrupt_ratchet_blob_is_a_decode_fault() {
    let engine = ProtocolStateEngine::new();
    let key = key();
    let address = ratchet_address(key.clone());
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot.set(
        address.clone(),
        ProtocolStateBlob::from_bytes(vec![1, 0xaa]),
    );

    assert!(matches!(
        engine.encrypt_message(&snapshot, key, outbound(1, b"lost", b"ad")),
        Err(ProtocolStateError::BlobDecode { address: actual, .. }) if actual == address
    ));
}

#[test]
fn oversized_ratchet_blob_is_a_decode_fault_before_restore() {
    let engine = ProtocolStateEngine::new();
    let key = key();
    let address = ratchet_address(key.clone());
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot.set(
        address.clone(),
        ProtocolStateBlob::from_bytes(vec![1; 128 * 1024]),
    );

    assert!(matches!(
        engine.encrypt_message(&snapshot, key, outbound(1, b"lost", b"ad")),
        Err(ProtocolStateError::BlobDecode { address: actual, .. }) if actual == address
    ));
}

#[test]
fn corrupt_ratchet_blob_does_not_silently_reinitialize_state() {
    let engine = ProtocolStateEngine::new();
    let key = key();
    let address = ratchet_address(key.clone());
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot.set(
        address.clone(),
        ProtocolStateBlob::from_bytes(vec![1, 0xaa]),
    );

    let result = engine.encrypt_message(&snapshot, key, outbound(1, b"lost", b"ad"));

    assert!(matches!(result, Err(ProtocolStateError::BlobDecode { .. })));
    assert_eq!(snapshot.get(&address).unwrap().as_bytes(), &[1, 0xaa]);
}

#[test]
fn missing_required_state_is_an_explicit_failure() {
    let engine = ProtocolStateEngine::new();
    let key = key();
    let address = ratchet_address(key.clone());
    let snapshot = ProtocolStateSnapshot::new();

    assert!(matches!(
        engine.encrypt_message(&snapshot, key, outbound(1, b"lost", b"ad")),
        Err(ProtocolStateError::MissingRequiredState { address: actual }) if actual == address
    ));
}

#[test]
fn after_wipe_session_operation_requires_explicit_restore() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let mut snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    snapshot.apply_all(engine.wipe(key.clone()));

    assert!(matches!(
        engine.encrypt_message(
            &snapshot,
            key.clone(),
            outbound(1, b"after wipe", &setup.associated_data),
        ),
        Err(ProtocolStateError::MissingRequiredState { .. })
    ));

    snapshot.apply(
        engine
            .set_session_state(key.clone(), &setup.alice_state)
            .unwrap(),
    );
    let result = engine
        .encrypt_message(
            &snapshot,
            key,
            outbound(2, b"restored", &setup.associated_data),
        )
        .unwrap();
    assert_eq!(result.message.payload_kind, PayloadKind::EncryptedText);
}
