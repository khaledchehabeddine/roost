//! Exercises the public protocol-state API over consumer-held opaque blobs.

use aether_core::{
    Message, MessageId, OutboundPlaintext, PayloadKind, ProtocolStateAddress, ProtocolStateBlob,
    ProtocolStateEngine, ProtocolStateError, ProtocolStateKey, ProtocolStateKind,
    ProtocolStateSnapshot, SenderIdentityMaterial, SessionId,
};
use aether_crypto::{
    Header, InitialPlaintext, PreKeyBundle, RatchetState, accept, generate_discovery_key,
    generate_one_time_prekey, generate_signed_prekey_for_discovery_key, generate_signing_key_pair,
    initiate,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

const CREATED_AT: u64 = 1_700_000_000;

struct Setup {
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
    let (alice_state, envelope) = initiate(
        &mut rng,
        &alice_discovery,
        &bob_identity.verifying,
        &prekey_bundle,
        initial_plaintext(b"initial"),
    )
    .unwrap();
    let (bob_state, plaintext) = accept(
        &mut rng,
        &envelope,
        &bob_discovery,
        &bob_signed_prekey,
        Some(bob_one_time_prekey),
    )
    .unwrap();
    assert_eq!(plaintext.plaintext.as_slice(), b"initial");
    Setup {
        alice_state,
        bob_state,
    }
}

fn initial_plaintext(plaintext: &[u8]) -> InitialPlaintext<'_> {
    InitialPlaintext {
        sender_certificate: b"sender certificate",
        sender_signature: b"sender signature",
        plaintext,
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

fn snapshot_with_state_and_peer_identity(
    engine: &ProtocolStateEngine,
    key: ProtocolStateKey,
    state: &RatchetState,
    peer_sender_identity: &SenderIdentityMaterial,
) -> ProtocolStateSnapshot {
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot.apply(
        engine
            .set_session_state_with_peer_identity(key, state, peer_sender_identity)
            .unwrap(),
    );
    snapshot
}

fn outbound<'a>(
    id: u8,
    plaintext: &'a [u8],
    sender_identity: &'a SenderIdentityMaterial,
) -> OutboundPlaintext<'a> {
    OutboundPlaintext {
        id: MessageId::from_bytes([id; 16]),
        sender_identity,
        recipient_public_key: [2u8; 32],
        timestamp_millis: 1_700_000_000_123 + u64::from(id),
        plaintext,
    }
}

fn sender_identity(tag: u8) -> SenderIdentityMaterial {
    SenderIdentityMaterial {
        identity_key: [tag; 32],
        certificate: vec![tag, tag.wrapping_add(1), tag.wrapping_add(2)],
        signature: vec![tag.wrapping_add(3); 64],
    }
}

fn message_associated_data(message: &Message) -> Vec<u8> {
    let mut associated_data = Vec::new();
    associated_data.extend_from_slice(b"AetherMessage-v1:");
    associated_data.extend_from_slice(message.id.as_bytes());
    associated_data.extend_from_slice(&message.recipient_public_key);
    associated_data.extend_from_slice(&message.timestamp_millis.to_be_bytes());
    associated_data.push(0);
    associated_data
}

fn ratcheted_payload(header: &Header, ciphertext: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(1);
    payload.extend_from_slice(header.public_key.as_bytes());
    payload.extend_from_slice(&header.previous_chain_length.to_be_bytes());
    payload.extend_from_slice(&header.message_number.to_be_bytes());
    payload.extend_from_slice(ciphertext);
    payload
}

fn copy_message(message: &Message) -> Message {
    Message {
        id: message.id,
        recipient_public_key: message.recipient_public_key,
        timestamp_millis: message.timestamp_millis,
        payload_kind: message.payload_kind,
        payload: message.payload.clone(),
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
    let sender_identity = sender_identity(1);

    let result = engine
        .encrypt_message(
            &snapshot,
            key.clone(),
            outbound(1, b"second", &sender_identity),
        )
        .unwrap();

    assert_eq!(result.message.payload_kind, PayloadKind::EncryptedText);
    assert_eq!(result.state_updates.len(), 1);
    assert_eq!(result.state_updates[0].address(), &address);
    let advanced_blob = result.state_updates[0].blob().unwrap().as_bytes();
    assert_ne!(advanced_blob, prior_blob.as_slice());
}

#[test]
fn sealed_sender_round_trip_exposes_sender_identity_after_decrypt() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let sender_identity = sender_identity(0xa1);
    let mut alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let mut bob_snapshot = snapshot_with_state_and_peer_identity(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender_identity,
    );

    let encrypted = engine
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            OutboundPlaintext {
                id: MessageId::from_bytes([8; 16]),
                sender_identity: &sender_identity,
                recipient_public_key: [2u8; 32],
                timestamp_millis: 1_700_000_000_888,
                plaintext: b"sealed sender",
            },
        )
        .unwrap();
    alice_snapshot.apply_all(encrypted.state_updates);

    let encoded = encrypted.message.to_bytes().unwrap();
    assert!(
        !encoded
            .windows(sender_identity.identity_key.len())
            .any(|window| window == sender_identity.identity_key)
    );

    let decrypted = engine
        .decrypt_message(
            &mut ChaCha20Rng::from_seed([12u8; 32]),
            &bob_snapshot,
            key,
            &encrypted.message,
        )
        .unwrap();
    bob_snapshot.apply_all(decrypted.state_updates);

    assert_eq!(decrypted.plaintext.as_slice(), b"sealed sender");
    assert_eq!(
        decrypted.sender_identity.identity_key,
        sender_identity.identity_key
    );
    assert_eq!(
        decrypted.sender_identity.certificate,
        sender_identity.certificate
    );
    assert_eq!(
        decrypted.sender_identity.signature,
        sender_identity.signature
    );
}

#[test]
fn set_session_state_with_peer_identity_key_allows_key_only_install() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let sender_identity = sender_identity(0xa1);
    let alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let mut bob_snapshot = ProtocolStateSnapshot::new();
    bob_snapshot.apply(
        engine
            .set_session_state_with_peer_identity_key(
                key.clone(),
                &setup.bob_state,
                sender_identity.identity_key,
            )
            .unwrap(),
    );

    let encrypted = engine
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            outbound(7, b"key-only install", &sender_identity),
        )
        .unwrap()
        .message;

    let decrypted = engine
        .decrypt_message(
            &mut ChaCha20Rng::from_seed([18u8; 32]),
            &bob_snapshot,
            key,
            &encrypted,
        )
        .unwrap();

    assert_eq!(decrypted.plaintext.as_slice(), b"key-only install");
    assert_eq!(
        decrypted.sender_identity.identity_key,
        sender_identity.identity_key
    );
}

#[test]
fn bind_session_state_peer_identity_key_allows_existing_blob_to_decrypt() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let sender_identity = sender_identity(0xa1);
    let alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let mut bob_snapshot = snapshot_with_state(&engine, key.clone(), &setup.bob_state);
    let address = ratchet_address(key.clone());
    let unbound_blob = bob_snapshot.get(&address).unwrap().as_bytes().to_vec();

    let bind_update = engine
        .bind_session_state_peer_identity_key(
            &bob_snapshot,
            key.clone(),
            sender_identity.identity_key,
        )
        .unwrap();
    assert_eq!(bind_update.address(), &address);
    assert_ne!(bind_update.blob().unwrap().as_bytes(), unbound_blob);
    bob_snapshot.apply(bind_update);

    let encrypted = engine
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            outbound(2, b"bound by key", &sender_identity),
        )
        .unwrap()
        .message;

    let decrypted = engine
        .decrypt_message(
            &mut ChaCha20Rng::from_seed([17u8; 32]),
            &bob_snapshot,
            key,
            &encrypted,
        )
        .unwrap();

    assert_eq!(decrypted.plaintext.as_slice(), b"bound by key");
    assert_eq!(
        decrypted.sender_identity.identity_key,
        sender_identity.identity_key
    );
    assert_eq!(
        decrypted.sender_identity.certificate,
        sender_identity.certificate
    );
    assert_eq!(
        decrypted.sender_identity.signature,
        sender_identity.signature
    );
}

#[test]
fn bind_session_state_peer_identity_key_rejects_mismatched_rebind() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let bound_sender_identity = sender_identity(0xa1);
    let other_sender_identity = sender_identity(0xb1);
    let snapshot = snapshot_with_state_and_peer_identity(
        &engine,
        key.clone(),
        &setup.bob_state,
        &bound_sender_identity,
    );
    let address = ratchet_address(key.clone());

    let result = engine.bind_session_state_peer_identity_key(
        &snapshot,
        key,
        other_sender_identity.identity_key,
    );

    assert!(matches!(
        result,
        Err(ProtocolStateError::InvalidStateBinding { address: actual, .. }) if actual == address
    ));
}

#[test]
fn decrypt_rejects_sender_identity_that_is_not_bound_to_session() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let expected_sender_identity = sender_identity(0xa1);
    let actual_sender_identity = sender_identity(0xb1);
    let alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let mut bob_snapshot = ProtocolStateSnapshot::new();
    bob_snapshot.apply(
        engine
            .set_session_state_with_peer_identity(
                key.clone(),
                &setup.bob_state,
                &expected_sender_identity,
            )
            .unwrap(),
    );

    let encrypted = engine
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            OutboundPlaintext {
                id: MessageId::from_bytes([9; 16]),
                sender_identity: &actual_sender_identity,
                recipient_public_key: [2u8; 32],
                timestamp_millis: 1_700_000_000_999,
                plaintext: b"wrong sender",
            },
        )
        .unwrap();

    let result = engine.decrypt_message(
        &mut ChaCha20Rng::from_seed([15u8; 32]),
        &bob_snapshot,
        key,
        &encrypted.message,
    );

    assert!(matches!(
        result,
        Err(ProtocolStateError::InvalidMessage { .. })
    ));
}

#[test]
fn tampered_ciphertext_exposes_no_sender_identity() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let sender_identity = sender_identity(1);
    let alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let bob_snapshot = snapshot_with_state_and_peer_identity(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender_identity,
    );
    let mut encrypted = engine
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            outbound(3, b"secret", &sender_identity),
        )
        .unwrap()
        .message;
    let last = encrypted.payload.last_mut().unwrap();
    *last ^= 0x01;

    let result = engine.decrypt_message(
        &mut ChaCha20Rng::from_seed([13u8; 32]),
        &bob_snapshot,
        key,
        &encrypted,
    );

    assert!(matches!(result, Err(ProtocolStateError::Crypto(_))));
}

#[test]
fn tampered_transport_metadata_exposes_no_sender_identity() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let sender_identity = sender_identity(1);
    let alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let bob_snapshot = snapshot_with_state_and_peer_identity(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender_identity,
    );
    let encrypted = engine
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            outbound(5, b"metadata-bound", &sender_identity),
        )
        .unwrap()
        .message;

    let mut wrong_id = copy_message(&encrypted);
    wrong_id.id = MessageId::from_bytes([6; 16]);
    let mut wrong_recipient = copy_message(&encrypted);
    wrong_recipient.recipient_public_key[0] ^= 0x01;
    let mut wrong_timestamp = copy_message(&encrypted);
    wrong_timestamp.timestamp_millis += 1;

    for message in [wrong_id, wrong_recipient, wrong_timestamp] {
        let result = engine.decrypt_message(
            &mut ChaCha20Rng::from_seed([16u8; 32]),
            &bob_snapshot,
            key.clone(),
            &message,
        );
        assert!(matches!(result, Err(ProtocolStateError::Crypto(_))));
    }
}

#[test]
fn malformed_sealed_sender_envelope_is_rejected() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let mut alice_state = setup.alice_state;
    let sender_identity = sender_identity(1);
    let bob_snapshot = snapshot_with_state_and_peer_identity(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender_identity,
    );
    let mut message = Message {
        id: MessageId::from_bytes([4; 16]),
        recipient_public_key: [2u8; 32],
        timestamp_millis: 1_700_000_000_444,
        payload_kind: PayloadKind::EncryptedText,
        payload: Vec::new(),
    };
    let associated_data = message_associated_data(&message);
    let (header, ciphertext) = alice_state
        .ratchet_encrypt(b"not a sealed-sender envelope", &associated_data)
        .unwrap();
    message.payload = ratcheted_payload(&header, &ciphertext);

    let result = engine.decrypt_message(
        &mut ChaCha20Rng::from_seed([14u8; 32]),
        &bob_snapshot,
        key,
        &message,
    );

    assert!(matches!(
        result,
        Err(ProtocolStateError::InvalidMessage { .. })
    ));
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
    let sender_identity = sender_identity(1);

    let result = engine.encrypt_message(
        &snapshot,
        key,
        outbound(1, &oversized_plaintext, &sender_identity),
    );

    assert!(matches!(
        result,
        Err(ProtocolStateError::InvalidMessage { .. })
    ));
    assert_eq!(snapshot.get(&address).unwrap().as_bytes(), prior_blob);
}

#[test]
fn two_instances_alternate_against_latest_consumer_blobs() {
    let setup = setup();
    let first_instance = ProtocolStateEngine::new();
    let second_instance = ProtocolStateEngine::new();
    let key = key();
    let sender_identity = sender_identity(1);
    let mut alice_snapshot = snapshot_with_state(&first_instance, key.clone(), &setup.alice_state);
    let mut bob_snapshot = snapshot_with_state_and_peer_identity(
        &first_instance,
        key.clone(),
        &setup.bob_state,
        &sender_identity,
    );

    let first = first_instance
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            outbound(1, b"from first", &sender_identity),
        )
        .unwrap();
    let first_message = first.message;
    alice_snapshot.apply_all(first.state_updates);

    let second = second_instance
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            outbound(2, b"from second", &sender_identity),
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
        )
        .unwrap();
    let second_plaintext = second_decrypt.plaintext.to_vec();
    bob_snapshot.apply_all(second_decrypt.state_updates);

    assert_eq!(first_plaintext, b"from first");
    assert_eq!(second_plaintext, b"from second");
}

#[test]
fn wipe_removes_all_state_kinds_for_key() {
    let engine = ProtocolStateEngine::new();
    let key = key();
    let mut snapshot = ProtocolStateSnapshot::new();
    for kind in ProtocolStateKind::all() {
        snapshot.set(
            ProtocolStateAddress::new(*kind, key.clone()),
            ProtocolStateBlob::from_bytes(vec![*kind as u8, 7]),
        );
    }

    snapshot.apply_all(engine.wipe(key.clone()));

    for kind in ProtocolStateKind::all() {
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
    let sender_identity = sender_identity(1);
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot.set(
        address.clone(),
        ProtocolStateBlob::from_bytes(vec![1, 0, 0xaa]),
    );

    assert!(matches!(
        engine.encrypt_message(&snapshot, key, outbound(1, b"lost", &sender_identity)),
        Err(ProtocolStateError::BlobDecode { address: actual, .. }) if actual == address
    ));
}

#[test]
fn oversized_ratchet_blob_is_a_decode_fault_before_restore() {
    let engine = ProtocolStateEngine::new();
    let key = key();
    let address = ratchet_address(key.clone());
    let sender_identity = sender_identity(1);
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot.set(
        address.clone(),
        ProtocolStateBlob::from_bytes(vec![1; 128 * 1024]),
    );

    assert!(matches!(
        engine.encrypt_message(&snapshot, key, outbound(1, b"lost", &sender_identity)),
        Err(ProtocolStateError::BlobDecode { address: actual, .. }) if actual == address
    ));
}

#[test]
fn corrupt_ratchet_blob_does_not_silently_reinitialize_state() {
    let engine = ProtocolStateEngine::new();
    let key = key();
    let address = ratchet_address(key.clone());
    let sender_identity = sender_identity(1);
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot.set(
        address.clone(),
        ProtocolStateBlob::from_bytes(vec![1, 0, 0xaa]),
    );

    let result = engine.encrypt_message(&snapshot, key, outbound(1, b"lost", &sender_identity));

    assert!(matches!(result, Err(ProtocolStateError::BlobDecode { .. })));
    assert_eq!(snapshot.get(&address).unwrap().as_bytes(), &[1, 0, 0xaa]);
}

#[test]
fn missing_required_state_is_an_explicit_failure() {
    let engine = ProtocolStateEngine::new();
    let key = key();
    let address = ratchet_address(key.clone());
    let sender_identity = sender_identity(1);
    let snapshot = ProtocolStateSnapshot::new();

    assert!(matches!(
        engine.encrypt_message(&snapshot, key, outbound(1, b"lost", &sender_identity)),
        Err(ProtocolStateError::MissingRequiredState { address: actual }) if actual == address
    ));
}

#[test]
fn after_wipe_session_operation_requires_explicit_restore() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let mut snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let sender_identity = sender_identity(1);
    snapshot.apply_all(engine.wipe(key.clone()));

    assert!(matches!(
        engine.encrypt_message(
            &snapshot,
            key.clone(),
            outbound(1, b"after wipe", &sender_identity),
        ),
        Err(ProtocolStateError::MissingRequiredState { .. })
    ));

    snapshot.apply(
        engine
            .set_session_state(key.clone(), &setup.alice_state)
            .unwrap(),
    );
    let result = engine
        .encrypt_message(&snapshot, key, outbound(2, b"restored", &sender_identity))
        .unwrap();
    assert_eq!(result.message.payload_kind, PayloadKind::EncryptedText);
}
