//! Exercises the public protocol-state API over consumer-held opaque blobs.

use aether_core::{
    AcknowledgmentOutcome, InboundAcknowledgmentMessage, InboundEncryptedMessage,
    InboundMessageOutcome, MAX_DEDUPLICATION_CAPACITY, MIN_DEDUPLICATION_CAPACITY, Message,
    MessageId, OutboundAcknowledgment, OutboundPlaintext, PayloadKind, ProtocolStateAddress,
    ProtocolStateBlob, ProtocolStateEngine, ProtocolStateError, ProtocolStateKey,
    ProtocolStateKind, ProtocolStateSnapshot, SenderIdentityMaterial, SessionId,
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

fn deduplication_key() -> ProtocolStateKey {
    ProtocolStateKey::from_bytes(vec![0xdd; 16]).unwrap()
}

fn ratchet_address(key: ProtocolStateKey) -> ProtocolStateAddress {
    ProtocolStateAddress::new(ProtocolStateKind::RatchetSession, key)
}

fn deduplication_address(key: ProtocolStateKey) -> ProtocolStateAddress {
    ProtocolStateAddress::new(ProtocolStateKind::DeduplicationSet, key)
}

fn pending_acknowledgment_address(key: ProtocolStateKey) -> ProtocolStateAddress {
    ProtocolStateAddress::new(ProtocolStateKind::PendingAcknowledgments, key)
}

fn snapshot_with_state(
    engine: &ProtocolStateEngine,
    key: ProtocolStateKey,
    state: &RatchetState,
) -> ProtocolStateSnapshot {
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot.apply(engine.set_session_state(key.clone(), state).unwrap());
    install_pending_acknowledgments(engine, &mut snapshot, key);
    snapshot
}

fn install_deduplication_set(
    engine: &ProtocolStateEngine,
    snapshot: &mut ProtocolStateSnapshot,
    key: ProtocolStateKey,
    seed: u8,
) {
    snapshot.apply(
        engine
            .initialize_deduplication_set(&mut ChaCha20Rng::from_seed([seed; 32]), key)
            .unwrap(),
    );
}

fn install_pending_acknowledgments(
    engine: &ProtocolStateEngine,
    snapshot: &mut ProtocolStateSnapshot,
    key: ProtocolStateKey,
) {
    snapshot.apply(engine.initialize_pending_acknowledgments(key).unwrap());
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
            .set_session_state_with_peer_identity(key.clone(), state, peer_sender_identity)
            .unwrap(),
    );
    install_pending_acknowledgments(engine, &mut snapshot, key);
    snapshot
}

fn snapshot_with_state_peer_identity_and_deduplication(
    engine: &ProtocolStateEngine,
    key: ProtocolStateKey,
    state: &RatchetState,
    peer_sender_identity: &SenderIdentityMaterial,
    deduplication_key: ProtocolStateKey,
) -> ProtocolStateSnapshot {
    let mut snapshot =
        snapshot_with_state_and_peer_identity(engine, key, state, peer_sender_identity);
    install_deduplication_set(engine, &mut snapshot, deduplication_key, 0x44);
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

fn acknowledgment_sender_identity() -> SenderIdentityMaterial {
    sender_identity(0xb1)
}

fn acknowledgment<'a>(
    id: u8,
    sender_identity: &'a SenderIdentityMaterial,
) -> OutboundAcknowledgment<'a> {
    OutboundAcknowledgment {
        id: MessageId::from_bytes([id; 16]),
        sender_identity,
        recipient_public_key: [3u8; 32],
        timestamp_millis: 1_700_000_100_000 + u64::from(id),
    }
}

fn inbound<'a>(
    session_key: ProtocolStateKey,
    deduplication_key: ProtocolStateKey,
    message: &'a Message,
    acknowledgment_sender_identity: &'a SenderIdentityMaterial,
) -> InboundEncryptedMessage<'a> {
    InboundEncryptedMessage {
        session_key,
        deduplication_key,
        message,
        acknowledgment: acknowledgment(0xee, acknowledgment_sender_identity),
    }
}

fn inbound_acknowledgment<'a>(
    session_key: ProtocolStateKey,
    message: &'a Message,
) -> InboundAcknowledgmentMessage<'a> {
    InboundAcknowledgmentMessage {
        session_key,
        message,
    }
}

fn accepted(outcome: InboundMessageOutcome) -> aether_core::InboundMessageResult {
    match outcome {
        InboundMessageOutcome::Accepted(result) => *result,
        InboundMessageOutcome::Duplicate => panic!("message was unexpectedly duplicate"),
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
    let pending_address = pending_acknowledgment_address(key.clone());
    let prior_blob = snapshot.get(&address).unwrap().as_bytes().to_vec();
    let prior_pending_blob = snapshot.get(&pending_address).unwrap().as_bytes().to_vec();
    let sender_identity = sender_identity(1);

    let result = engine
        .encrypt_message(
            &snapshot,
            key.clone(),
            outbound(1, b"second", &sender_identity),
        )
        .unwrap();

    assert_eq!(result.message.payload_kind, PayloadKind::EncryptedText);
    assert_eq!(result.state_updates.len(), 2);
    assert_eq!(result.state_updates[0].address(), &address);
    assert_eq!(result.state_updates[1].address(), &pending_address);
    let advanced_blob = result.state_updates[0].blob().unwrap().as_bytes();
    assert_ne!(advanced_blob, prior_blob.as_slice());
    let advanced_pending_blob = result.state_updates[1].blob().unwrap().as_bytes();
    assert_ne!(advanced_pending_blob, prior_pending_blob.as_slice());
}

#[test]
fn sealed_sender_round_trip_exposes_sender_identity_after_decrypt() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let sender_identity = sender_identity(0xa1);
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let mut alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let mut bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender_identity,
        deduplication_key.clone(),
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
            inbound(
                key,
                deduplication_key,
                &encrypted.message,
                &acknowledgment_sender_identity,
            ),
        )
        .map(accepted)
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
fn accepted_message_generates_encrypted_acknowledgment_that_clears_pending_state() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let alice_sender = sender_identity(0xa1);
    let bob_sender = sender_identity(0xb1);
    let mut alice_snapshot = snapshot_with_state_and_peer_identity(
        &engine,
        key.clone(),
        &setup.alice_state,
        &bob_sender,
    );
    install_pending_acknowledgments(&engine, &mut alice_snapshot, key.clone());
    let mut bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        key.clone(),
        &setup.bob_state,
        &alice_sender,
        deduplication_key.clone(),
    );

    let encrypted = engine
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            outbound(0x31, b"ack me", &alice_sender),
        )
        .unwrap();
    alice_snapshot.apply_all(encrypted.state_updates);
    let pending = engine
        .pending_acknowledgments(&alice_snapshot, key.clone())
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].message.id, encrypted.message.id);

    let decrypted = engine
        .decrypt_message(
            &mut ChaCha20Rng::from_seed([0x31; 32]),
            &bob_snapshot,
            InboundEncryptedMessage {
                session_key: key.clone(),
                deduplication_key: deduplication_key.clone(),
                message: &encrypted.message,
                acknowledgment: acknowledgment(0x41, &bob_sender),
            },
        )
        .map(accepted)
        .unwrap();
    bob_snapshot.apply_all(decrypted.state_updates);

    assert_eq!(decrypted.plaintext.as_slice(), b"ack me");
    assert_eq!(
        decrypted.acknowledgment.payload_kind,
        PayloadKind::Acknowledgment
    );
    let encoded_ack = decrypted.acknowledgment.to_bytes().unwrap();
    assert!(
        !encoded_ack
            .windows(encrypted.message.id.as_bytes().len())
            .any(|window| window == encrypted.message.id.as_bytes())
    );

    let cleared = engine
        .process_acknowledgment(
            &mut ChaCha20Rng::from_seed([0x41; 32]),
            &alice_snapshot,
            inbound_acknowledgment(key.clone(), &decrypted.acknowledgment),
        )
        .unwrap();
    let AcknowledgmentOutcome::Cleared(cleared) = cleared else {
        panic!("acknowledgment did not clear pending state");
    };
    assert_eq!(cleared.acknowledged_message_id, encrypted.message.id);
    assert_eq!(
        cleared.sender_identity.identity_key,
        bob_sender.identity_key
    );
    alice_snapshot.apply_all(cleared.state_updates);

    assert!(
        engine
            .pending_acknowledgments(&alice_snapshot, key.clone())
            .unwrap()
            .is_empty()
    );
    let duplicate = engine
        .process_acknowledgment(
            &mut ChaCha20Rng::from_seed([0x42; 32]),
            &alice_snapshot,
            inbound_acknowledgment(key, &decrypted.acknowledgment),
        )
        .unwrap();
    assert!(matches!(duplicate, AcknowledgmentOutcome::Duplicate));
}

#[test]
fn unknown_acknowledgment_is_non_fatal_miss() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let alice_sender = sender_identity(0xa1);
    let bob_sender = sender_identity(0xb1);
    let mut alice_snapshot = snapshot_with_state_and_peer_identity(
        &engine,
        key.clone(),
        &setup.alice_state,
        &bob_sender,
    );
    install_pending_acknowledgments(&engine, &mut alice_snapshot, key.clone());
    let bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        key.clone(),
        &setup.bob_state,
        &alice_sender,
        deduplication_key.clone(),
    );
    let encrypted = engine
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            outbound(0x32, b"ack missing pending", &alice_sender),
        )
        .unwrap();
    for update in encrypted.state_updates {
        if update.address().kind() == ProtocolStateKind::RatchetSession {
            alice_snapshot.apply(update);
        }
    }
    let decrypted = engine
        .decrypt_message(
            &mut ChaCha20Rng::from_seed([0x32; 32]),
            &bob_snapshot,
            InboundEncryptedMessage {
                session_key: key.clone(),
                deduplication_key,
                message: &encrypted.message,
                acknowledgment: acknowledgment(0x42, &bob_sender),
            },
        )
        .map(accepted)
        .unwrap();

    let miss = engine
        .process_acknowledgment(
            &mut ChaCha20Rng::from_seed([0x43; 32]),
            &alice_snapshot,
            inbound_acknowledgment(key, &decrypted.acknowledgment),
        )
        .unwrap();

    assert!(matches!(miss, AcknowledgmentOutcome::Missed { .. }));
}

#[test]
fn retry_instructions_are_windowed_and_persisted() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let sender_identity = sender_identity(0xa1);
    let sent_at = 1_700_000_000_200;
    let mut snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    install_pending_acknowledgments(&engine, &mut snapshot, key.clone());

    let encrypted = engine
        .encrypt_message(
            &snapshot,
            key.clone(),
            OutboundPlaintext {
                id: MessageId::from_bytes([0x33; 16]),
                sender_identity: &sender_identity,
                recipient_public_key: [2u8; 32],
                timestamp_millis: sent_at,
                plaintext: b"retry later",
            },
        )
        .unwrap();
    snapshot.apply_all(encrypted.state_updates);

    let early = engine
        .retry_instructions(&snapshot, key.clone(), sent_at + 999, 1_000)
        .unwrap();
    assert!(early.instructions.is_empty());
    assert!(early.state_updates.is_empty());

    let due = engine
        .retry_instructions(&snapshot, key.clone(), sent_at + 1_000, 1_000)
        .unwrap();
    assert_eq!(due.instructions.len(), 1);
    assert_eq!(due.instructions[0].message.id, encrypted.message.id);
    snapshot.apply_all(due.state_updates);

    let repeated = ProtocolStateEngine::new()
        .retry_instructions(&snapshot, key.clone(), sent_at + 1_000, 1_000)
        .unwrap();
    assert!(repeated.instructions.is_empty());
    assert_eq!(
        ProtocolStateEngine::new()
            .pending_acknowledgments(&snapshot, key)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn pending_acknowledgment_state_faults_on_bad_blobs() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let address = pending_acknowledgment_address(key.clone());
    let sender_identity = sender_identity(0xa1);
    let mut corrupt_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    corrupt_snapshot.set(
        address.clone(),
        ProtocolStateBlob::from_bytes(vec![1, 0, 0xaa]),
    );
    assert!(matches!(
        engine.encrypt_message(
            &corrupt_snapshot,
            key.clone(),
            outbound(0x34, b"corrupt pending", &sender_identity),
        ),
        Err(ProtocolStateError::BlobDecode { address: actual, .. }) if actual == address
    ));

    let mut unsupported_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    unsupported_snapshot.set(
        address.clone(),
        ProtocolStateBlob::from_bytes(vec![2, 0, 0xaa]),
    );
    assert!(matches!(
        engine.pending_acknowledgments(&unsupported_snapshot, key),
        Err(ProtocolStateError::UnsupportedBlobVersion {
            address: actual,
            major: 2,
            minor: 0
        }) if actual == address
    ));
}

#[test]
fn unique_received_message_is_accepted_recorded_and_emitted_once() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let sender_identity = sender_identity(0xa1);
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let mut bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender_identity,
        deduplication_key.clone(),
    );
    let ratchet_address = ratchet_address(key.clone());
    let deduplication_address = deduplication_address(deduplication_key.clone());
    let prior_ratchet = bob_snapshot
        .get(&ratchet_address)
        .unwrap()
        .as_bytes()
        .to_vec();
    let prior_deduplication = bob_snapshot
        .get(&deduplication_address)
        .unwrap()
        .as_bytes()
        .to_vec();
    let encrypted = engine
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            outbound(10, b"accept once", &sender_identity),
        )
        .unwrap()
        .message;

    let decrypted = engine
        .decrypt_message(
            &mut ChaCha20Rng::from_seed([19u8; 32]),
            &bob_snapshot,
            inbound(
                key.clone(),
                deduplication_key.clone(),
                &encrypted,
                &acknowledgment_sender_identity,
            ),
        )
        .map(accepted)
        .unwrap();

    assert_eq!(decrypted.plaintext.as_slice(), b"accept once");
    assert_eq!(decrypted.state_updates.len(), 2);
    assert_eq!(decrypted.state_updates[0].address(), &ratchet_address);
    assert_eq!(decrypted.state_updates[1].address(), &deduplication_address);
    assert_ne!(
        decrypted.state_updates[0].blob().unwrap().as_bytes(),
        prior_ratchet
    );
    assert_ne!(
        decrypted.state_updates[1].blob().unwrap().as_bytes(),
        prior_deduplication
    );
    bob_snapshot.apply_all(decrypted.state_updates);

    let duplicate = ProtocolStateEngine::new()
        .decrypt_message(
            &mut ChaCha20Rng::from_seed([20u8; 32]),
            &bob_snapshot,
            inbound(
                key,
                deduplication_key,
                &encrypted,
                &acknowledgment_sender_identity,
            ),
        )
        .unwrap();
    assert!(matches!(duplicate, InboundMessageOutcome::Duplicate));
}

#[test]
fn duplicate_received_message_does_not_load_or_advance_ratchet_state() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let sender_identity = sender_identity(0xa1);
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let mut bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender_identity,
        deduplication_key.clone(),
    );
    let encrypted = engine
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            outbound(11, b"no duplicate effect", &sender_identity),
        )
        .unwrap()
        .message;
    let decrypted = engine
        .decrypt_message(
            &mut ChaCha20Rng::from_seed([21u8; 32]),
            &bob_snapshot,
            inbound(
                key.clone(),
                deduplication_key.clone(),
                &encrypted,
                &acknowledgment_sender_identity,
            ),
        )
        .map(accepted)
        .unwrap();
    bob_snapshot.apply_all(decrypted.state_updates);
    let ratchet_address = ratchet_address(key.clone());
    bob_snapshot.set(
        ratchet_address,
        ProtocolStateBlob::from_bytes(vec![1, 0, 0xaa]),
    );

    let duplicate = engine
        .decrypt_message(
            &mut ChaCha20Rng::from_seed([22u8; 32]),
            &bob_snapshot,
            inbound(
                key,
                deduplication_key,
                &encrypted,
                &acknowledgment_sender_identity,
            ),
        )
        .unwrap();

    assert!(matches!(duplicate, InboundMessageOutcome::Duplicate));
}

#[test]
fn deduplication_receive_rejects_bad_state_and_capacity() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let deduplication_address = deduplication_address(deduplication_key.clone());
    let sender_identity = sender_identity(0xa1);
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let encrypted = engine
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            outbound(12, b"bad dedup state", &sender_identity),
        )
        .unwrap()
        .message;

    let missing_snapshot = snapshot_with_state_and_peer_identity(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender_identity,
    );
    assert!(matches!(
        engine.decrypt_message(
            &mut ChaCha20Rng::from_seed([23u8; 32]),
            &missing_snapshot,
            inbound(
                key.clone(),
                deduplication_key.clone(),
                &encrypted,
                &acknowledgment_sender_identity,
            ),
        ),
        Err(ProtocolStateError::MissingRequiredState { address }) if address == deduplication_address
    ));

    let mut corrupt_snapshot = snapshot_with_state_and_peer_identity(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender_identity,
    );
    corrupt_snapshot.set(
        deduplication_address.clone(),
        ProtocolStateBlob::from_bytes(vec![1, 0, 0xaa]),
    );
    assert!(matches!(
        engine.decrypt_message(
            &mut ChaCha20Rng::from_seed([24u8; 32]),
            &corrupt_snapshot,
            inbound(
                key.clone(),
                deduplication_key.clone(),
                &encrypted,
                &acknowledgment_sender_identity,
            ),
        ),
        Err(ProtocolStateError::BlobDecode { address, .. }) if address == deduplication_address
    ));

    let mut unsupported_snapshot = snapshot_with_state_and_peer_identity(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender_identity,
    );
    unsupported_snapshot.set(
        deduplication_address.clone(),
        ProtocolStateBlob::from_bytes(vec![2, 0, 0xaa]),
    );
    assert!(matches!(
        engine.decrypt_message(
            &mut ChaCha20Rng::from_seed([25u8; 32]),
            &unsupported_snapshot,
            inbound(key, deduplication_key, &encrypted, &acknowledgment_sender_identity),
        ),
        Err(ProtocolStateError::UnsupportedBlobVersion {
            address,
            major: 2,
            minor: 0
        }) if address == deduplication_address
    ));

    assert!(matches!(
        ProtocolStateEngine::with_deduplication_capacity(MIN_DEDUPLICATION_CAPACITY - 1),
        Err(ProtocolStateError::InvalidDeduplicationCapacity { capacity, .. })
            if capacity == MIN_DEDUPLICATION_CAPACITY - 1
    ));
    assert!(matches!(
        ProtocolStateEngine::with_deduplication_capacity(MAX_DEDUPLICATION_CAPACITY + 1),
        Err(ProtocolStateError::InvalidDeduplicationCapacity { capacity, .. })
            if capacity == MAX_DEDUPLICATION_CAPACITY + 1
    ));
}

#[test]
fn deduplication_capacity_evicts_oldest_digest_first() {
    let setup = setup();
    let engine =
        ProtocolStateEngine::with_deduplication_capacity(MIN_DEDUPLICATION_CAPACITY).unwrap();
    let key = key();
    let deduplication_key = deduplication_key();
    let sender_identity = sender_identity(0xa1);
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let mut alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let mut bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender_identity,
        deduplication_key.clone(),
    );
    let mut first_message = None;

    for index in 0..=MIN_DEDUPLICATION_CAPACITY {
        let encrypted = engine
            .encrypt_message(
                &alice_snapshot,
                key.clone(),
                outbound(index as u8, b"fills window", &sender_identity),
            )
            .unwrap();
        let message = encrypted.message;
        alice_snapshot.apply_all(encrypted.state_updates);
        if index == 0 {
            first_message = Some(copy_message(&message));
        }
        let decrypted = engine
            .decrypt_message(
                &mut ChaCha20Rng::from_seed([26u8; 32]),
                &bob_snapshot,
                inbound(
                    key.clone(),
                    deduplication_key.clone(),
                    &message,
                    &acknowledgment_sender_identity,
                ),
            )
            .map(accepted)
            .unwrap();
        bob_snapshot.apply_all(decrypted.state_updates);
    }

    let result = engine.decrypt_message(
        &mut ChaCha20Rng::from_seed([27u8; 32]),
        &bob_snapshot,
        inbound(
            key,
            deduplication_key,
            &first_message.unwrap(),
            &acknowledgment_sender_identity,
        ),
    );

    assert!(matches!(result, Err(ProtocolStateError::Crypto(_))));
}

#[test]
fn set_session_state_with_peer_identity_key_allows_key_only_install() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let sender_identity = sender_identity(0xa1);
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
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
    install_deduplication_set(&engine, &mut bob_snapshot, deduplication_key.clone(), 0x44);

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
            inbound(
                key,
                deduplication_key,
                &encrypted,
                &acknowledgment_sender_identity,
            ),
        )
        .map(accepted)
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
    let deduplication_key = deduplication_key();
    let sender_identity = sender_identity(0xa1);
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
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
    install_deduplication_set(&engine, &mut bob_snapshot, deduplication_key.clone(), 0x44);

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
            inbound(
                key,
                deduplication_key,
                &encrypted,
                &acknowledgment_sender_identity,
            ),
        )
        .map(accepted)
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
    let deduplication_key = deduplication_key();
    let expected_sender_identity = sender_identity(0xa1);
    let actual_sender_identity = sender_identity(0xb1);
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
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
    install_deduplication_set(&engine, &mut bob_snapshot, deduplication_key.clone(), 0x44);

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
        inbound(
            key,
            deduplication_key,
            &encrypted.message,
            &acknowledgment_sender_identity,
        ),
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
    let deduplication_key = deduplication_key();
    let sender_identity = sender_identity(1);
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender_identity,
        deduplication_key.clone(),
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
        inbound(
            key,
            deduplication_key,
            &encrypted,
            &acknowledgment_sender_identity,
        ),
    );

    assert!(matches!(result, Err(ProtocolStateError::Crypto(_))));
}

#[test]
fn tampered_transport_metadata_exposes_no_sender_identity() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let sender_identity = sender_identity(1);
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender_identity,
        deduplication_key.clone(),
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
            inbound(
                key.clone(),
                deduplication_key.clone(),
                &message,
                &acknowledgment_sender_identity,
            ),
        );
        assert!(matches!(result, Err(ProtocolStateError::Crypto(_))));
    }
}

#[test]
fn malformed_sealed_sender_envelope_is_rejected() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let mut alice_state = setup.alice_state;
    let sender_identity = sender_identity(1);
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender_identity,
        deduplication_key.clone(),
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
        inbound(
            key,
            deduplication_key,
            &message,
            &acknowledgment_sender_identity,
        ),
    );

    assert!(matches!(
        result,
        Err(ProtocolStateError::InvalidMessage { .. })
    ));
}

#[test]
fn large_valid_outbound_message_persists_pending_acknowledgment() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let mut snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let sender_identity = sender_identity(1);
    let large_plaintext = vec![0u8; 65_316];

    let result = engine
        .encrypt_message(
            &snapshot,
            key.clone(),
            outbound(1, &large_plaintext, &sender_identity),
        )
        .unwrap();
    assert!(result.message.to_bytes().unwrap().len() > 64 * 1024);
    let message_id = result.message.id;
    snapshot.apply_all(result.state_updates);

    let pending = engine.pending_acknowledgments(&snapshot, key).unwrap();

    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].message.id, message_id);
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
    let deduplication_key = deduplication_key();
    let sender_identity = sender_identity(1);
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let mut alice_snapshot = snapshot_with_state(&first_instance, key.clone(), &setup.alice_state);
    let mut bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &first_instance,
        key.clone(),
        &setup.bob_state,
        &sender_identity,
        deduplication_key.clone(),
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
            inbound(
                key.clone(),
                deduplication_key.clone(),
                &first_message,
                &acknowledgment_sender_identity,
            ),
        )
        .map(accepted)
        .unwrap();
    let first_plaintext = first_decrypt.plaintext.to_vec();
    bob_snapshot.apply_all(first_decrypt.state_updates);
    let second_decrypt = second_instance
        .decrypt_message(
            &mut ChaCha20Rng::from_seed([11u8; 32]),
            &bob_snapshot,
            inbound(
                key,
                deduplication_key,
                &second_message,
                &acknowledgment_sender_identity,
            ),
        )
        .map(accepted)
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
    install_pending_acknowledgments(&engine, &mut snapshot, key.clone());
    let result = engine
        .encrypt_message(&snapshot, key, outbound(2, b"restored", &sender_identity))
        .unwrap();
    assert_eq!(result.message.payload_kind, PayloadKind::EncryptedText);
}
