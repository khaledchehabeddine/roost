//! Exercises the public protocol-state API over consumer-held opaque blobs.

mod support;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use roost_core::{
    AcknowledgmentOutcome, BlockedContactAcknowledgmentPolicy, ContactDiscoveryKey,
    ContactIdentity, ContactTrustState, InboundMessageOutcome, InboundSenderCertificateValidation,
    LocalSender, MAX_DEDUPLICATION_CAPACITY, MIN_DEDUPLICATION_CAPACITY, Message, MessageError,
    OutboundMessageResult, ProtocolHardeningLimits, ProtocolStateAddress, ProtocolStateBlob,
    ProtocolStateEngine, ProtocolStateError, ProtocolStateKey, ProtocolStateKind,
    ProtocolStateSnapshot, SessionEvent, SessionId, SessionUnrecoverableReason,
    SessionUnrecoverableResult, TransportBinding,
};
use roost_crypto::{
    KeyPair, RatchetError, SealedFrameError, SigningKeyPair, generate_discovery_key,
};
use roost_protocol::{
    DomainSigningKey, DomainSigningKeyStatus, MAX_CERTIFICATE_GRACE_WINDOW, PayloadKind,
    RevocationState, SenderCertificateIdentityKey, SenderCertificateValidationError,
    from_unix_millis,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use support::{
    CREATED_AT_SECS, HostStore, ProtocolFixture, TestIdentity, accepted, dead_session_blob,
    deduplication_address, session_address, validated_sender, validation,
};

#[derive(Deserialize, Serialize)]
struct TestPendingAcknowledgmentsWire {
    pending: Vec<TestPendingAcknowledgmentWire>,
    acknowledgment_digests: Vec<[u8; 16]>,
}

#[derive(Deserialize, Serialize)]
struct TestPendingAcknowledgmentWire {
    message_id: [u8; 16],
    encoded_message: Vec<u8>,
    first_sent_at_millis: u64,
    last_retried_at_millis: Option<u64>,
}

fn binding() -> TransportBinding {
    TransportBinding::new(b"test-route".to_vec()).unwrap()
}

fn rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

fn pending_address(session_id: SessionId) -> ProtocolStateAddress {
    ProtocolStateAddress::new(
        ProtocolStateKind::PendingAcknowledgments,
        ProtocolStateKey::from_bytes(session_id.as_bytes().to_vec()).unwrap(),
    )
}

// Alice encrypts on the fixture's Session without committing.
fn alice_sends(
    engine: &ProtocolStateEngine,
    fixture: &ProtocolFixture,
    sequence: u16,
    plaintext: &[u8],
) -> OutboundMessageResult {
    alice_sends_from(
        engine,
        fixture,
        &fixture.alice_store,
        fixture.alice.local_sender(),
        sequence,
        plaintext,
    )
}

fn alice_sends_from(
    engine: &ProtocolStateEngine,
    fixture: &ProtocolFixture,
    store: &HostStore,
    sender: LocalSender<'_>,
    sequence: u16,
    plaintext: &[u8],
) -> OutboundMessageResult {
    let mut outbound = fixture.outbound(sequence, plaintext);
    outbound.sender = sender;
    engine
        .encrypt_message_with_transport_binding(
            &mut rng(sequence as u8),
            &store.snapshot(),
            outbound,
            &binding(),
        )
        .unwrap()
}

// Bob receives `message` against `snapshot` with the given certificate validation inputs.
fn bob_receives(
    engine: &ProtocolStateEngine,
    fixture: &ProtocolFixture,
    snapshot: &ProtocolStateSnapshot,
    message: &Message,
    sender_certificate_validation: Option<InboundSenderCertificateValidation<'_>>,
    seed: u8,
) -> Result<InboundMessageOutcome, ProtocolStateError> {
    engine.decrypt_message_with_transport_bindings(
        &mut rng(seed),
        snapshot,
        fixture.inbound_with_validation(message, sender_certificate_validation),
        &binding(),
        &binding(),
    )
}

// Bob receives `message` with the default trusted domain and no revocations.
fn bob_receives_validated(
    engine: &ProtocolStateEngine,
    fixture: &ProtocolFixture,
    snapshot: &ProtocolStateSnapshot,
    message: &Message,
    seed: u8,
) -> Result<InboundMessageOutcome, ProtocolStateError> {
    let domain = validated_sender();
    let domain_keys = [domain.domain_signing_key()];
    bob_receives(
        engine,
        fixture,
        snapshot,
        message,
        Some(validation(&domain_keys, &[])),
        seed,
    )
}

fn blocked(outcome: InboundMessageOutcome) -> roost_core::BlockedInboundMessageResult {
    let InboundMessageOutcome::Blocked(result) = outcome else {
        panic!("message was not blocked")
    };
    *result
}

fn session_unrecoverable(outcome: InboundMessageOutcome) -> SessionUnrecoverableResult {
    let InboundMessageOutcome::SessionUnrecoverable(result) = outcome else {
        panic!("session was not unrecoverable")
    };
    *result
}

fn block_alice(engine: &ProtocolStateEngine, fixture: &mut ProtocolFixture) {
    let blocked = engine
        .block_contact(&fixture.bob_store.snapshot(), fixture.alice.identity_key())
        .unwrap();
    fixture.bob_store.commit(blocked.state_updates).unwrap();
}

fn alice_revoked_identity_key(fixture: &ProtocolFixture) -> SenderCertificateIdentityKey {
    let identity_key = fixture.alice.identity_key();
    SenderCertificateIdentityKey {
        x25519_public_key: identity_key.x25519_public_key,
        ed25519_verifying_key: identity_key.ed25519_verifying_key,
    }
}

fn blob(store: &HostStore, address: &ProtocolStateAddress) -> Vec<u8> {
    store.blob_bytes(address).unwrap()
}

#[test]
fn outbound_message_and_advanced_state_return_together() {
    let engine = ProtocolStateEngine::new();
    let fixture = ProtocolFixture::new([0x01; 32]);
    let address = session_address(fixture.session_id);
    let pending_address = pending_address(fixture.session_id);
    let prior_blob = blob(&fixture.alice_store, &address);
    let prior_pending_blob = blob(&fixture.alice_store, &pending_address);

    let result = alice_sends(&engine, &fixture, 1, b"second");

    assert_eq!(result.session_id, fixture.session_id);
    assert_eq!(result.payload_kind, PayloadKind::EncryptedText);
    assert_eq!(result.state_updates.len(), 2);
    assert_eq!(result.state_updates[0].address(), &address);
    assert_eq!(result.state_updates[1].address(), &pending_address);
    assert_ne!(
        result.state_updates[0].blob().unwrap().as_bytes(),
        prior_blob.as_slice()
    );
    assert_ne!(
        result.state_updates[1].blob().unwrap().as_bytes(),
        prior_pending_blob.as_slice()
    );
}

#[test]
fn sealed_sender_round_trip_hides_sender_identity_until_decrypt() {
    let engine = ProtocolStateEngine::new();
    let fixture = ProtocolFixture::new([0x02; 32]);
    let encrypted = alice_sends(&engine, &fixture, 8, b"sealed sender");
    let sender = &fixture.alice.sender_identity;

    let encoded = encrypted.message.to_bytes().unwrap();
    for (name, material) in [
        ("identity key", sender.identity_key.as_slice()),
        (
            "identity verifying key",
            sender.identity_verifying_key.as_slice(),
        ),
        (
            "identity binding signature",
            sender.identity_binding_signature.as_slice(),
        ),
        ("certificate", sender.certificate.as_slice()),
        ("certificate signature", sender.signature.as_slice()),
        ("session id", fixture.session_id.as_bytes().as_slice()),
    ] {
        assert!(
            !encoded
                .windows(material.len())
                .any(|window| window == material),
            "wire message exposes {name}"
        );
    }

    let decrypted = accepted(
        bob_receives_validated(
            &engine,
            &fixture,
            &fixture.bob_store.snapshot(),
            &encrypted.message,
            12,
        )
        .unwrap(),
    );

    assert_eq!(decrypted.plaintext.as_slice(), b"sealed sender");
    assert_eq!(decrypted.session_id, fixture.session_id);
    assert_eq!(decrypted.sender_identity.identity_key, sender.identity_key);
    assert_eq!(
        decrypted.sender_identity.identity_verifying_key,
        sender.identity_verifying_key
    );
    assert_eq!(
        decrypted.sender_identity.identity_binding_signature,
        sender.identity_binding_signature
    );
    assert_eq!(decrypted.sender_identity.certificate, sender.certificate);
    assert_eq!(decrypted.sender_identity.signature, sender.signature);
}

#[test]
fn sealed_frame_hides_message_metadata_until_decrypt() {
    let engine = ProtocolStateEngine::new();
    let fixture = ProtocolFixture::new([0x03; 32]);
    let encrypted = alice_sends(&engine, &fixture, 0x42, b"hidden metadata");

    assert_eq!(
        encrypted.message.recipient_public_key,
        *fixture.bob.discovery_key.public_key().as_bytes(),
        "only recipient routing key remains visible"
    );
    assert!(encrypted.message.prekey_reference.is_none());
    assert_ne!(encrypted.message.ephemeral_public_key, [0u8; 32]);
    assert!(!encrypted.message.ciphertext.is_empty());

    let decrypted = accepted(
        bob_receives_validated(
            &engine,
            &fixture,
            &fixture.bob_store.snapshot(),
            &encrypted.message,
            0x42,
        )
        .unwrap(),
    );

    assert_eq!(decrypted.message_id, encrypted.message_id);
    assert_eq!(decrypted.sent_at_millis, 1_700_000_300_000 + 0x42);
    assert_eq!(decrypted.payload_kind, PayloadKind::EncryptedText);
    assert_eq!(decrypted.plaintext.as_slice(), b"hidden metadata");
}

#[test]
fn accepted_message_generates_encrypted_acknowledgment_that_clears_pending_state() {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0x04; 32]);
    let encrypted = alice_sends(&engine, &fixture, 0x31, b"ack me");
    fixture.alice_store.commit(encrypted.state_updates).unwrap();
    let pending = engine
        .pending_acknowledgments(&fixture.alice_store.snapshot(), fixture.session_id)
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].message_id, encrypted.message_id);

    let decrypted = accepted(
        bob_receives_validated(
            &engine,
            &fixture,
            &fixture.bob_store.snapshot(),
            &encrypted.message,
            0x31,
        )
        .unwrap(),
    );
    assert_eq!(decrypted.plaintext.as_slice(), b"ack me");
    assert!(decrypted.acknowledgment.prekey_reference.is_none());
    let encoded_ack = decrypted.acknowledgment.to_bytes().unwrap();
    assert!(
        !encoded_ack
            .windows(encrypted.message_id.as_bytes().len())
            .any(|window| window == encrypted.message_id.as_bytes())
    );

    let process = |snapshot: &ProtocolStateSnapshot, seed: u8| {
        engine
            .process_acknowledgment_with_transport_binding(
                &mut rng(seed),
                snapshot,
                fixture.alice_acknowledgment(&decrypted.acknowledgment),
                &binding(),
            )
            .unwrap()
    };
    let AcknowledgmentOutcome::Cleared(cleared) = process(&fixture.alice_store.snapshot(), 0x41)
    else {
        panic!("acknowledgment did not clear pending state");
    };
    assert_eq!(cleared.session_id, fixture.session_id);
    assert_eq!(cleared.acknowledged_message_id, encrypted.message_id);
    assert_eq!(
        cleared.sender_identity.identity_key,
        fixture.bob.sender_identity.identity_key
    );
    let mut alice_store = fixture.alice_store.clone();
    alice_store.commit(cleared.state_updates).unwrap();
    assert!(
        engine
            .pending_acknowledgments(&alice_store.snapshot(), fixture.session_id)
            .unwrap()
            .is_empty()
    );
    for seed in 0x42..0x47 {
        assert!(matches!(
            process(&alice_store.snapshot(), seed),
            AcknowledgmentOutcome::Duplicate
        ));
    }

    // Duplicate detection reads only the stored digests, never the stored Messages.
    let pending_address = pending_address(fixture.session_id);
    let pending_blob = blob(&alice_store, &pending_address);
    let (mut wire, trailing): (TestPendingAcknowledgmentsWire, &[u8]) =
        postcard::take_from_bytes(&pending_blob[1..]).unwrap();
    assert!(trailing.is_empty());
    assert_eq!(wire.pending.len(), 0);
    assert_eq!(wire.acknowledgment_digests.len(), 1);
    wire.pending.push(TestPendingAcknowledgmentWire {
        message_id: [0x44; 16],
        encoded_message: vec![0xaa],
        first_sent_at_millis: 1_700_000_100_123,
        last_retried_at_millis: None,
    });
    let mut malformed_pending_blob = pending_blob[..1].to_vec();
    malformed_pending_blob.extend(postcard::to_stdvec(&wire).unwrap());
    alice_store.set_raw(pending_address, malformed_pending_blob);

    assert!(matches!(
        process(&alice_store.snapshot(), 0x47),
        AcknowledgmentOutcome::Duplicate
    ));
}

#[test]
fn unknown_acknowledgment_is_non_fatal_miss() {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0x05; 32]);
    let encrypted = alice_sends(&engine, &fixture, 0x32, b"ack missing pending");
    let session_update = encrypted
        .state_updates
        .into_iter()
        .filter(|update| update.address().kind() == ProtocolStateKind::RatchetSession)
        .collect();
    fixture.alice_store.commit(session_update).unwrap();
    let decrypted = accepted(
        bob_receives_validated(
            &engine,
            &fixture,
            &fixture.bob_store.snapshot(),
            &encrypted.message,
            0x32,
        )
        .unwrap(),
    );

    let miss = engine
        .process_acknowledgment_with_transport_binding(
            &mut rng(0x43),
            &fixture.alice_store.snapshot(),
            fixture.alice_acknowledgment(&decrypted.acknowledgment),
            &binding(),
        )
        .unwrap();

    assert!(matches!(miss, AcknowledgmentOutcome::Missed { .. }));
}

#[test]
fn retry_instructions_are_windowed_and_persisted() {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0x06; 32]);
    let encrypted = alice_sends(&engine, &fixture, 0x33, b"retry later");
    let sent_at = encrypted.sent_at_millis;
    fixture.alice_store.commit(encrypted.state_updates).unwrap();
    let retry = |snapshot: &ProtocolStateSnapshot, now_millis: u64| {
        ProtocolStateEngine::new()
            .retry_instructions(
                snapshot,
                fixture.session_id,
                from_unix_millis(now_millis).unwrap(),
                Duration::from_millis(1_000),
            )
            .unwrap()
    };

    let early = retry(&fixture.alice_store.snapshot(), sent_at + 999);
    assert!(early.instructions.is_empty());
    assert!(early.state_updates.is_empty());

    let due = retry(&fixture.alice_store.snapshot(), sent_at + 1_000);
    assert_eq!(due.instructions.len(), 1);
    assert_eq!(due.instructions[0].message_id, encrypted.message_id);
    let mut alice_store = fixture.alice_store.clone();
    alice_store.commit(due.state_updates).unwrap();

    let repeated = retry(&alice_store.snapshot(), sent_at + 1_000);
    assert!(repeated.instructions.is_empty());
    assert!(repeated.state_updates.is_empty());
    assert_eq!(
        engine
            .pending_acknowledgments(&alice_store.snapshot(), fixture.session_id)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn pending_acknowledgment_state_faults_on_bad_blobs() {
    let engine = ProtocolStateEngine::new();
    let fixture = ProtocolFixture::new([0x07; 32]);
    let address = pending_address(fixture.session_id);
    let mut corrupt = fixture.alice_store.clone();
    corrupt.set_raw(address.clone(), vec![1, 0, 0xaa]);
    assert!(matches!(
        engine.encrypt_message_with_transport_binding(
            &mut rng(0x34),
            &corrupt.snapshot(),
            fixture.outbound(0x34, b"corrupt pending"),
            &binding(),
        ),
        Err(ProtocolStateError::BlobDecode { address: actual, .. }) if actual == address
    ));

    let mut unsupported = fixture.alice_store.clone();
    unsupported.set_raw(address.clone(), vec![2, 0, 0xaa]);
    assert!(matches!(
        engine.pending_acknowledgments(&unsupported.snapshot(), fixture.session_id),
        Err(ProtocolStateError::UnsupportedBlobVersion {
            address: actual,
            version: 2,
        }) if actual == address
    ));
}

#[test]
fn hardening_limits_round_trip_on_engine() {
    let limits = ProtocolHardeningLimits {
        deduplication_capacity: MIN_DEDUPLICATION_CAPACITY,
        ..ProtocolHardeningLimits::default()
    };

    let engine = ProtocolStateEngine::with_hardening_limits(limits).unwrap();

    assert_eq!(engine.hardening_limits(), limits);
}

#[test]
fn hardening_limits_reject_unsupported_ceilings() {
    let mut limits = ProtocolHardeningLimits::default();
    limits.max_message_payload_len += 1;

    let result = ProtocolStateEngine::with_hardening_limits(limits);

    assert!(matches!(
        result,
        Err(ProtocolStateError::InvalidHardeningLimit {
            name: "message payload",
            ..
        })
    ));
}

#[test]
fn oversized_inbound_message_rejects_before_state_load() {
    let default_engine = ProtocolStateEngine::new();
    let fixture = ProtocolFixture::new([0x08; 32]);
    let encrypted = alice_sends(&default_engine, &fixture, 0x36, b"oversized before state").message;
    let limits = ProtocolHardeningLimits {
        max_encoded_message_len: encrypted.to_bytes().unwrap().len() - 1,
        ..ProtocolHardeningLimits::default()
    };
    let rejecting_engine = ProtocolStateEngine::with_hardening_limits(limits).unwrap();
    let session_address = session_address(fixture.session_id);
    let deduplication_address = deduplication_address(fixture.deduplication_key.clone());
    let corrupt = vec![1, 0, 0xaa];
    let mut bob_store = fixture.bob_store.clone();
    bob_store.set_raw(session_address.clone(), corrupt.clone());
    bob_store.set_raw(deduplication_address.clone(), corrupt.clone());

    let result = bob_receives_validated(
        &rejecting_engine,
        &fixture,
        &bob_store.snapshot(),
        &encrypted,
        0x36,
    );

    assert!(matches!(
        result,
        Err(ProtocolStateError::MessageEncode(
            MessageError::EncodedTooLarge
        ))
    ));
    assert_eq!(blob(&bob_store, &session_address), corrupt);
    assert_eq!(blob(&bob_store, &deduplication_address), corrupt);
}

#[test]
fn configured_blob_limit_rejects_decode_before_restore() {
    let fixture = ProtocolFixture::new([0x09; 32]);
    let address = session_address(fixture.session_id);
    let limits = ProtocolHardeningLimits {
        max_protocol_state_blob_len: blob(&fixture.alice_store, &address).len() - 1,
        ..ProtocolHardeningLimits::default()
    };
    let engine = ProtocolStateEngine::with_hardening_limits(limits).unwrap();

    let result = engine.encrypt_message_with_transport_binding(
        &mut rng(0x37),
        &fixture.alice_store.snapshot(),
        fixture.outbound(0x37, b"blob limit"),
        &binding(),
    );

    assert!(matches!(
        result,
        Err(ProtocolStateError::BlobDecode { address: actual, .. }) if actual == address
    ));
}

#[test]
fn configured_blob_limit_accepts_exact_size() {
    let fixture = ProtocolFixture::new([0x0a; 32]);
    let address = pending_address(fixture.session_id);
    let limits = ProtocolHardeningLimits {
        max_protocol_state_blob_len: blob(&fixture.alice_store, &address).len(),
        ..ProtocolHardeningLimits::default()
    };
    let engine = ProtocolStateEngine::with_hardening_limits(limits).unwrap();

    let pending = engine
        .pending_acknowledgments(&fixture.alice_store.snapshot(), fixture.session_id)
        .unwrap();

    assert!(pending.is_empty());
}

#[test]
fn configured_payload_limit_rejects_before_state_load() {
    let default_engine = ProtocolStateEngine::new();
    let fixture = ProtocolFixture::new([0x0b; 32]);
    let encrypted = alice_sends(&default_engine, &fixture, 0x38, b"payload limit").message;
    let limits = ProtocolHardeningLimits {
        max_message_payload_len: encrypted.ciphertext.len() - 1,
        ..ProtocolHardeningLimits::default()
    };
    let engine = ProtocolStateEngine::with_hardening_limits(limits).unwrap();
    let deduplication_address = deduplication_address(fixture.deduplication_key.clone());
    let corrupt = vec![1, 0, 0xaa];
    let mut bob_store = fixture.bob_store.clone();
    bob_store.set_raw(deduplication_address.clone(), corrupt.clone());

    let result = bob_receives_validated(&engine, &fixture, &bob_store.snapshot(), &encrypted, 0x38);

    assert!(matches!(
        result,
        Err(ProtocolStateError::MessageEncode(
            MessageError::PayloadTooLarge
        ))
    ));
    assert_eq!(blob(&bob_store, &deduplication_address), corrupt);
}

#[test]
fn configured_sender_material_limits_reject_without_state_updates() {
    let default_engine = ProtocolStateEngine::new();
    let fixture = ProtocolFixture::new([0x0c; 32]);
    let encrypted = alice_sends(&default_engine, &fixture, 0x39, b"certificate limit").message;
    let sender = &fixture.alice.sender_identity;
    for limits in [
        ProtocolHardeningLimits {
            max_sender_certificate_len: sender.certificate.len() - 1,
            ..ProtocolHardeningLimits::default()
        },
        ProtocolHardeningLimits {
            max_sender_signature_len: sender.signature.len() - 1,
            ..ProtocolHardeningLimits::default()
        },
    ] {
        let engine = ProtocolStateEngine::with_hardening_limits(limits).unwrap();

        let result = bob_receives_validated(
            &engine,
            &fixture,
            &fixture.bob_store.snapshot(),
            &encrypted,
            0x39,
        );

        assert!(matches!(
            result,
            Err(ProtocolStateError::InvalidMessage { .. })
        ));
    }
}

#[test]
fn configured_boundary_limits_accept_exact_sizes() {
    let default_engine = ProtocolStateEngine::new();
    let fixture = ProtocolFixture::new([0x0d; 32]);
    let encrypted = alice_sends(&default_engine, &fixture, 0x3a, b"exact limits").message;
    let sender = &fixture.alice.sender_identity;
    let limits = ProtocolHardeningLimits {
        max_encoded_message_len: encrypted.to_bytes().unwrap().len(),
        max_message_payload_len: encrypted.ciphertext.len(),
        max_sender_certificate_len: sender.certificate.len(),
        max_sender_signature_len: sender.signature.len(),
        ..ProtocolHardeningLimits::default()
    };
    let engine = ProtocolStateEngine::with_hardening_limits(limits).unwrap();

    let result = accepted(
        bob_receives_validated(
            &engine,
            &fixture,
            &fixture.bob_store.snapshot(),
            &encrypted,
            0x3a,
        )
        .unwrap(),
    );

    assert_eq!(result.plaintext.as_slice(), b"exact limits");
}

#[test]
fn unique_received_message_is_accepted_recorded_and_emitted_once() {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0x0e; 32]);
    let session_address = session_address(fixture.session_id);
    let deduplication_address = deduplication_address(fixture.deduplication_key.clone());
    let prior_session = blob(&fixture.bob_store, &session_address);
    let prior_deduplication = blob(&fixture.bob_store, &deduplication_address);
    let encrypted = alice_sends(&engine, &fixture, 10, b"accept once").message;

    let decrypted = accepted(
        bob_receives_validated(
            &engine,
            &fixture,
            &fixture.bob_store.snapshot(),
            &encrypted,
            19,
        )
        .unwrap(),
    );

    assert_eq!(decrypted.plaintext.as_slice(), b"accept once");
    assert_eq!(decrypted.state_updates.len(), 2);
    assert_eq!(decrypted.state_updates[0].address(), &session_address);
    assert_eq!(decrypted.state_updates[1].address(), &deduplication_address);
    assert_ne!(
        decrypted.state_updates[0].blob().unwrap().as_bytes(),
        prior_session
    );
    assert_ne!(
        decrypted.state_updates[1].blob().unwrap().as_bytes(),
        prior_deduplication
    );
    fixture.bob_store.commit(decrypted.state_updates).unwrap();

    let duplicate = bob_receives(
        &ProtocolStateEngine::new(),
        &fixture,
        &fixture.bob_store.snapshot(),
        &encrypted,
        None,
        20,
    )
    .unwrap();
    assert!(matches!(duplicate, InboundMessageOutcome::Duplicate));
}

#[test]
fn replay_storm_returns_duplicate_without_state_churn() {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0x0f; 32]);
    let encrypted = alice_sends(&engine, &fixture, 0x3c, b"replay storm").message;
    let decrypted = accepted(
        bob_receives_validated(
            &engine,
            &fixture,
            &fixture.bob_store.snapshot(),
            &encrypted,
            0x3c,
        )
        .unwrap(),
    );
    fixture.bob_store.commit(decrypted.state_updates).unwrap();
    let after_accept = fixture.bob_store.snapshot_bytes();

    for seed in 0x3d..0x45 {
        let duplicate = bob_receives(
            &engine,
            &fixture,
            &fixture.bob_store.snapshot(),
            &encrypted,
            None,
            seed,
        )
        .unwrap();
        assert!(matches!(duplicate, InboundMessageOutcome::Duplicate));
        assert_eq!(fixture.bob_store.snapshot_bytes(), after_accept);
    }
}

#[test]
fn skipped_key_total_overflow_rejects_without_marking_session_unrecoverable() {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0x10; 32]);
    let mut sequence = 0u16;
    // Each round skips 100 of Alice's Messages, the most one header may skip, then has Bob reply
    // so Alice starts a new sending chain. The acknowledgment Alice returns for that reply takes
    // the chain's first key, so 100 more Messages skip 100 keys. Five rounds fill Bob's 500-key
    // cache.
    for round in 0..5u8 {
        let mut last = None;
        for _ in 0..100 {
            sequence += 1;
            let sent = alice_sends(&engine, &fixture, sequence, b"fill");
            let session_update = sent
                .state_updates
                .into_iter()
                .filter(|update| update.address().kind() == ProtocolStateKind::RatchetSession)
                .collect();
            fixture.alice_store.commit(session_update).unwrap();
            last = Some(sent.message);
        }
        let received = accepted(
            bob_receives_validated(
                &engine,
                &fixture,
                &fixture.bob_store.snapshot(),
                &last.unwrap(),
                round,
            )
            .unwrap(),
        );
        fixture.bob_store.commit(received.state_updates).unwrap();
        fixture.bob_replies(&engine, round);
    }
    sequence += 1;
    let undelivered = alice_sends(&engine, &fixture, sequence, b"undelivered");
    fixture
        .alice_store
        .commit(undelivered.state_updates)
        .unwrap();
    let terminal = alice_sends(&engine, &fixture, sequence + 1, b"overflow").message;

    for seed in [0xf0, 0xf1] {
        assert!(matches!(
            bob_receives_validated(
                &engine,
                &fixture,
                &fixture.bob_store.snapshot(),
                &terminal,
                seed
            ),
            Err(ProtocolStateError::Ratchet(
                RatchetError::MaxSkippedKeysExceeded
            ))
        ));
    }
}

#[test]
fn dead_session_marker_reports_once_without_reset() {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0x11; 32]);
    let address = session_address(fixture.session_id);
    let dead_message = alice_sends(&engine, &fixture, 0x80, b"dead marker probe").message;
    fixture.bob_store.set_raw(
        address.clone(),
        dead_session_blob(false, fixture.alice.identity_key())
            .as_bytes()
            .to_vec(),
    );

    let unrecoverable = session_unrecoverable(
        bob_receives_validated(
            &engine,
            &fixture,
            &fixture.bob_store.snapshot(),
            &dead_message,
            0xe0,
        )
        .unwrap(),
    );
    assert_eq!(unrecoverable.session_id, fixture.session_id);
    assert_eq!(
        unrecoverable.reason,
        SessionUnrecoverableReason::SkippedKeyLimitExceeded
    );
    assert_eq!(unrecoverable.state_updates.len(), 1);
    assert_eq!(unrecoverable.state_updates[0].address(), &address);
    assert_eq!(
        unrecoverable.event,
        Some(SessionEvent::Unrecoverable {
            session_id: fixture.session_id,
            reason: SessionUnrecoverableReason::SkippedKeyLimitExceeded,
        })
    );
    fixture
        .bob_store
        .commit(unrecoverable.state_updates)
        .unwrap();

    let repeated = session_unrecoverable(
        bob_receives_validated(
            &engine,
            &fixture,
            &fixture.bob_store.snapshot(),
            &dead_message,
            0xe1,
        )
        .unwrap(),
    );
    assert!(repeated.event.is_none());
    assert!(repeated.state_updates.is_empty());
}

#[test]
fn transient_aead_failure_does_not_mark_session_unrecoverable() {
    let engine = ProtocolStateEngine::new();
    let fixture = ProtocolFixture::new([0x12; 32]);
    let encrypted = alice_sends(&engine, &fixture, 0x70, b"valid after tamper").message;
    let mut tampered = Message::from_bytes(&encrypted.to_bytes().unwrap()).unwrap();
    *tampered.ciphertext.last_mut().unwrap() ^= 0x01;

    assert!(matches!(
        bob_receives_validated(
            &engine,
            &fixture,
            &fixture.bob_store.snapshot(),
            &tampered,
            0x70
        ),
        Err(ProtocolStateError::SealedFrame(SealedFrameError::Aead))
    ));
    let decrypted = accepted(
        bob_receives_validated(
            &engine,
            &fixture,
            &fixture.bob_store.snapshot(),
            &encrypted,
            0x71,
        )
        .unwrap(),
    );

    assert_eq!(decrypted.plaintext.as_slice(), b"valid after tamper");
}

#[test]
fn receive_without_certificate_validation_rejects_before_plaintext_is_surfaced() {
    let engine = ProtocolStateEngine::new();
    let fixture = ProtocolFixture::new([0x13; 32]);
    let encrypted = alice_sends(&engine, &fixture, 0x4f, b"must validate").message;

    let result = bob_receives(
        &engine,
        &fixture,
        &fixture.bob_store.snapshot(),
        &encrypted,
        None,
        0x4f,
    );

    assert!(matches!(
        result,
        Err(ProtocolStateError::MissingSenderCertificateValidation)
    ));
}

#[test]
fn duplicate_received_message_does_not_load_or_advance_ratchet_state() {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0x14; 32]);
    let encrypted = alice_sends(&engine, &fixture, 11, b"no duplicate effect").message;
    let decrypted = accepted(
        bob_receives_validated(
            &engine,
            &fixture,
            &fixture.bob_store.snapshot(),
            &encrypted,
            21,
        )
        .unwrap(),
    );
    fixture.bob_store.commit(decrypted.state_updates).unwrap();
    fixture
        .bob_store
        .set_raw(session_address(fixture.session_id), vec![1, 0, 0xaa]);

    let duplicate = bob_receives(
        &engine,
        &fixture,
        &fixture.bob_store.snapshot(),
        &encrypted,
        None,
        22,
    )
    .unwrap();

    assert!(matches!(duplicate, InboundMessageOutcome::Duplicate));
}

#[test]
fn blocked_inbound_message_under_unreachable_policy_suppresses_acknowledgment_without_plaintext() {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0x15; 32]);
    block_alice(&engine, &mut fixture);
    let session_address = session_address(fixture.session_id);
    let deduplication_address = deduplication_address(fixture.deduplication_key.clone());
    let prior_session = blob(&fixture.bob_store, &session_address);
    let prior_deduplication = blob(&fixture.bob_store, &deduplication_address);
    let encrypted = alice_sends(&engine, &fixture, 0x51, b"blocked text").message;

    let blocked = blocked(
        bob_receives_validated(
            &engine,
            &fixture,
            &fixture.bob_store.snapshot(),
            &encrypted,
            0x51,
        )
        .unwrap(),
    );

    assert!(blocked.acknowledgment.is_none());
    assert_eq!(blocked.state_updates.len(), 2);
    assert_eq!(blocked.state_updates[0].address(), &session_address);
    assert_eq!(blocked.state_updates[1].address(), &deduplication_address);
    assert_ne!(
        blocked.state_updates[0].blob().unwrap().as_bytes(),
        prior_session
    );
    assert_ne!(
        blocked.state_updates[1].blob().unwrap().as_bytes(),
        prior_deduplication
    );
}

#[test]
fn blocked_inbound_message_under_silent_receipt_policy_returns_acknowledgment_without_plaintext() {
    let engine = ProtocolStateEngine::new().with_blocked_contact_acknowledgment_policy(
        BlockedContactAcknowledgmentPolicy::SilentReceipt,
    );
    let mut fixture = ProtocolFixture::new([0x16; 32]);
    block_alice(&engine, &mut fixture);
    let encrypted = alice_sends(&engine, &fixture, 0x54, b"blocked but receipted").message;

    let blocked = blocked(
        bob_receives_validated(
            &engine,
            &fixture,
            &fixture.bob_store.snapshot(),
            &encrypted,
            0x54,
        )
        .unwrap(),
    );

    let acknowledgment = blocked
        .acknowledgment
        .expect("silent-receipt returns an acknowledgment");
    assert!(acknowledgment.prekey_reference.is_none());
    assert_eq!(blocked.state_updates.len(), 2);
    assert_eq!(
        blocked.state_updates[0].address(),
        &session_address(fixture.session_id)
    );
    assert_eq!(
        blocked.state_updates[1].address(),
        &deduplication_address(fixture.deduplication_key.clone())
    );
}

#[test]
fn blocked_acknowledgment_policy_controls_sending_chain_advance() {
    let unreachable = ProtocolStateEngine::new();
    let silent_receipt = ProtocolStateEngine::new().with_blocked_contact_acknowledgment_policy(
        BlockedContactAcknowledgmentPolicy::SilentReceipt,
    );
    let mut fixture = ProtocolFixture::new([0x17; 32]);
    block_alice(&unreachable, &mut fixture);
    let encrypted = alice_sends(&unreachable, &fixture, 0x55, b"chain advance").message;
    let snapshot = fixture.bob_store.snapshot();

    let suppressed = blocked(
        bob_receives_validated(&unreachable, &fixture, &snapshot, &encrypted, 0x55).unwrap(),
    );
    let receipted = blocked(
        bob_receives_validated(&silent_receipt, &fixture, &snapshot, &encrypted, 0x55).unwrap(),
    );

    assert!(suppressed.acknowledgment.is_none());
    assert!(receipted.acknowledgment.is_some());
    let session_address = session_address(fixture.session_id);
    assert_eq!(suppressed.state_updates[0].address(), &session_address);
    assert_eq!(receipted.state_updates[0].address(), &session_address);
    // The acknowledgment advances the sending chain, so only silent-receipt mutates it further.
    assert_ne!(
        suppressed.state_updates[0].blob().unwrap().as_bytes(),
        receipted.state_updates[0].blob().unwrap().as_bytes(),
    );
}

#[test]
fn duplicate_blocked_inbound_message_does_not_load_or_advance_ratchet_state() {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0x18; 32]);
    block_alice(&engine, &mut fixture);
    let encrypted = alice_sends(&engine, &fixture, 0x52, b"blocked once").message;
    let first = blocked(
        bob_receives_validated(
            &engine,
            &fixture,
            &fixture.bob_store.snapshot(),
            &encrypted,
            0x52,
        )
        .unwrap(),
    );
    fixture.bob_store.commit(first.state_updates).unwrap();
    fixture
        .bob_store
        .set_raw(session_address(fixture.session_id), vec![1, 0, 0xaa]);

    let duplicate = bob_receives_validated(
        &engine,
        &fixture,
        &fixture.bob_store.snapshot(),
        &encrypted,
        0x53,
    )
    .unwrap();

    assert!(matches!(duplicate, InboundMessageOutcome::Duplicate));
}

#[test]
fn discovery_key_rotation_does_not_bypass_blocked_inbound_message() {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0x19; 32]);
    block_alice(&engine, &mut fixture);
    let rotated_discovery_key = generate_discovery_key(
        &mut rng(0x73),
        &fixture.alice.signing_key,
        1,
        CREATED_AT_SECS + 60,
    )
    .unwrap();
    let rotated = engine
        .record_contact(
            &fixture.bob_store.snapshot(),
            ContactIdentity {
                identity_key: fixture.alice.identity_key(),
                discovery_key: ContactDiscoveryKey::from(&rotated_discovery_key.public()),
            },
        )
        .unwrap();
    assert!(!rotated.state_updates.is_empty());
    fixture.bob_store.commit(rotated.state_updates).unwrap();
    let encrypted = alice_sends(&engine, &fixture, 0x54, b"rotated blocked").message;

    let outcome = bob_receives_validated(
        &engine,
        &fixture,
        &fixture.bob_store.snapshot(),
        &encrypted,
        0x54,
    )
    .unwrap();

    assert!(matches!(outcome, InboundMessageOutcome::Blocked(_)));
}

#[test]
fn revoked_certificate_rejects_before_local_block_handling() {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0x1a; 32]);
    block_alice(&engine, &mut fixture);
    let encrypted = alice_sends(&engine, &fixture, 0x55, b"revoked blocked").message;
    let domain = validated_sender();
    let domain_keys = [domain.domain_signing_key()];
    let revoked = [alice_revoked_identity_key(&fixture)];

    let result = bob_receives(
        &engine,
        &fixture,
        &fixture.bob_store.snapshot(),
        &encrypted,
        Some(validation(&domain_keys, &revoked)),
        0x55,
    );

    assert!(matches!(
        result,
        Err(ProtocolStateError::SenderCertificateValidation(
            SenderCertificateValidationError::RevokedIdentityKey
        ))
    ));
}

#[test]
fn validated_once_then_missing_validation_rejects_for_blocked_sender() {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0x1b; 32]);
    let first = fixture.encrypt_from_alice(&engine, 0x5b, b"validated first");
    fixture.decrypt_for_bob(&engine, &first, 0x5b);
    block_alice(&engine, &mut fixture);
    let second = alice_sends(&engine, &fixture, 0x5c, b"missing validation").message;

    let result = bob_receives(
        &engine,
        &fixture,
        &fixture.bob_store.snapshot(),
        &second,
        None,
        0x5c,
    );

    assert!(matches!(
        result,
        Err(ProtocolStateError::MissingSenderCertificateValidation)
    ));
}

#[test]
fn unavailable_revocation_state_rejects_before_plaintext_is_surfaced() {
    let engine = ProtocolStateEngine::new();
    let fixture = ProtocolFixture::new([0x1c; 32]);
    let encrypted = alice_sends(&engine, &fixture, 0x56, b"revocation unavailable").message;
    let domain = validated_sender();
    let domain_keys = [domain.domain_signing_key()];

    let result = bob_receives(
        &engine,
        &fixture,
        &fixture.bob_store.snapshot(),
        &encrypted,
        Some(InboundSenderCertificateValidation {
            revocation_state: RevocationState::Unavailable,
            ..validation(&domain_keys, &[])
        }),
        0x56,
    );

    assert!(matches!(
        result,
        Err(ProtocolStateError::SenderCertificateValidation(
            SenderCertificateValidationError::RevocationStateUnavailable
        ))
    ));
}

#[test]
fn untrusted_signing_key_rejects_before_plaintext_is_surfaced() {
    let engine = ProtocolStateEngine::new();
    let fixture = ProtocolFixture::new([0x1d; 32]);
    let encrypted = alice_sends(&engine, &fixture, 0x59, b"untrusted domain").message;
    let domain = validated_sender();
    let domain_keys = [DomainSigningKey {
        status: DomainSigningKeyStatus::Untrusted,
        ..domain.domain_signing_key()
    }];

    let result = bob_receives(
        &engine,
        &fixture,
        &fixture.bob_store.snapshot(),
        &encrypted,
        Some(validation(&domain_keys, &[])),
        0x59,
    );

    assert!(matches!(
        result,
        Err(ProtocolStateError::SenderCertificateValidation(
            SenderCertificateValidationError::UntrustedSigningKeyId
        ))
    ));
}

#[test]
fn engine_rejects_certificate_grace_above_the_maximum() {
    let grace = MAX_CERTIFICATE_GRACE_WINDOW + Duration::from_millis(1);
    assert!(matches!(
        ProtocolStateEngine::new().with_certificate_grace(grace),
        Err(ProtocolStateError::SenderCertificateValidation(
            SenderCertificateValidationError::GraceWindowTooLarge { grace_window, max }
        )) if grace_window == grace && max == MAX_CERTIFICATE_GRACE_WINDOW
    ));
}

#[test]
fn expired_certificate_rejects_before_plaintext_is_surfaced() {
    let engine = ProtocolStateEngine::new();
    let fixture = ProtocolFixture::new([0x1e; 32]);
    let expired = fixture.alice.certified_until(CREATED_AT_SECS - 1);
    let encrypted = alice_sends_from(
        &engine,
        &fixture,
        &fixture.alice_store,
        fixture.alice.local_sender_with(&expired),
        0x5a,
        b"expired domain",
    )
    .message;

    let result = bob_receives_validated(
        &engine,
        &fixture,
        &fixture.bob_store.snapshot(),
        &encrypted,
        0x5a,
    );

    assert!(matches!(
        result,
        Err(ProtocolStateError::SenderCertificateValidation(
            SenderCertificateValidationError::ExpiredCertificate
        ))
    ));
}

#[test]
fn message_at_the_configured_grace_boundary_is_accepted() {
    let engine = ProtocolStateEngine::new()
        .with_certificate_grace(MAX_CERTIFICATE_GRACE_WINDOW)
        .unwrap();
    let fixture = ProtocolFixture::new([0x1f; 32]);
    let expiring = fixture
        .alice
        .certified_until(CREATED_AT_SECS - MAX_CERTIFICATE_GRACE_WINDOW.as_secs());
    let encrypted = alice_sends_from(
        &engine,
        &fixture,
        &fixture.alice_store,
        fixture.alice.local_sender_with(&expiring),
        0x5e,
        b"at the grace window boundary",
    )
    .message;

    let accepted = accepted(
        bob_receives_validated(
            &engine,
            &fixture,
            &fixture.bob_store.snapshot(),
            &encrypted,
            0x5e,
        )
        .unwrap(),
    );

    assert_eq!(
        accepted.plaintext.as_slice(),
        b"at the grace window boundary"
    );
}

#[test]
fn certificate_identity_key_must_match_sealed_sender() {
    let engine = ProtocolStateEngine::new();
    let fixture = ProtocolFixture::new([0x20; 32]);
    let carol = TestIdentity::new(0x77, 0x73);
    let mut mismatched = fixture.alice.sender_identity.clone();
    mismatched.certificate = carol.sender_identity.certificate.clone();
    mismatched.signature = carol.sender_identity.signature.clone();
    let encrypted = alice_sends_from(
        &engine,
        &fixture,
        &fixture.alice_store,
        fixture.alice.local_sender_with(&mismatched),
        0x58,
        b"mismatched certificate",
    )
    .message;

    assert!(matches!(
        bob_receives_validated(&engine, &fixture, &fixture.bob_store.snapshot(), &encrypted, 0x58),
        Err(ProtocolStateError::InvalidMessage { reason })
            if reason == "sender certificate identity key does not match sealed sender"
    ));
}

#[test]
fn decrypt_rejects_sender_identity_that_is_not_bound_to_session() {
    let engine = ProtocolStateEngine::new();
    let fixture = ProtocolFixture::new([0x21; 32]);
    let carol = TestIdentity::new(0x77, 0x73);
    // Alice's ratchet keys, but Carol's sealed identity and signature.
    let encrypted = alice_sends_from(
        &engine,
        &fixture,
        &fixture.alice_store,
        carol.local_sender(),
        9,
        b"wrong sender",
    )
    .message;

    assert!(matches!(
        bob_receives_validated(&engine, &fixture, &fixture.bob_store.snapshot(), &encrypted, 15),
        Err(ProtocolStateError::InvalidMessage { reason })
            if reason == "sealed sender identity key does not match session"
    ));
}

#[test]
fn unblocked_contact_resumes_existing_session_without_new_handshake() {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0x22; 32]);
    block_alice(&engine, &mut fixture);
    let first = fixture.encrypt_from_alice(&engine, 0x56, b"blocked before unblock");
    let blocked = blocked(
        bob_receives_validated(
            &engine,
            &fixture,
            &fixture.bob_store.snapshot(),
            &first.message,
            0x56,
        )
        .unwrap(),
    );
    fixture.bob_store.commit(blocked.state_updates).unwrap();
    let unblocked = engine
        .unblock_contact(&fixture.bob_store.snapshot(), fixture.alice.identity_key())
        .unwrap();
    fixture.bob_store.commit(unblocked.state_updates).unwrap();
    let second = fixture.encrypt_from_alice(&engine, 0x57, b"after unblock");

    let accepted = fixture.decrypt_for_bob(&engine, &second, 0x57);

    assert_eq!(accepted.session_id, fixture.session_id);
    assert_eq!(accepted.plaintext.as_slice(), b"after unblock");
}

#[test]
fn in_band_messages_and_acknowledgments_do_not_verify_contact() {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0x23; 32]);
    let trust = |store: &HostStore, identity: &TestIdentity| {
        engine
            .contact_state(&store.snapshot(), identity.identity_key())
            .unwrap()
            .unwrap()
            .trust_state
    };
    assert_eq!(
        trust(&fixture.alice_store, &fixture.bob),
        ContactTrustState::Unverified
    );

    let encrypted = fixture.encrypt_from_alice(&engine, 12, b"in band is not verification");
    let decrypted = fixture.decrypt_for_bob(&engine, &encrypted, 23);
    assert_eq!(
        trust(&fixture.bob_store, &fixture.alice),
        ContactTrustState::Unverified
    );

    let AcknowledgmentOutcome::Cleared(cleared) = engine
        .process_acknowledgment_with_transport_binding(
            &mut rng(24),
            &fixture.alice_store.snapshot(),
            fixture.alice_acknowledgment(&decrypted.acknowledgment),
            &binding(),
        )
        .unwrap()
    else {
        panic!("acknowledgment did not clear pending state");
    };
    fixture.alice_store.commit(cleared.state_updates).unwrap();

    assert_eq!(
        trust(&fixture.alice_store, &fixture.bob),
        ContactTrustState::Unverified
    );
}

#[test]
fn deduplication_receive_rejects_bad_state_and_capacity() {
    let engine = ProtocolStateEngine::new();
    let fixture = ProtocolFixture::new([0x24; 32]);
    let deduplication_address = deduplication_address(fixture.deduplication_key.clone());
    let encrypted = alice_sends(&engine, &fixture, 12, b"bad dedup state").message;
    let receive = |store: &HostStore, seed: u8| {
        bob_receives(&engine, &fixture, &store.snapshot(), &encrypted, None, seed)
    };

    let mut missing = HostStore::default();
    for (address, bytes) in fixture.bob_store.snapshot_bytes() {
        if address != deduplication_address {
            missing.set_raw(address, bytes);
        }
    }
    assert!(matches!(
        receive(&missing, 23),
        Err(ProtocolStateError::MissingRequiredState { address }) if address == deduplication_address
    ));

    let mut corrupt = fixture.bob_store.clone();
    corrupt.set_raw(deduplication_address.clone(), vec![1, 0, 0xaa]);
    assert!(matches!(
        receive(&corrupt, 24),
        Err(ProtocolStateError::BlobDecode { address, .. }) if address == deduplication_address
    ));

    let mut unsupported = fixture.bob_store.clone();
    unsupported.set_raw(deduplication_address.clone(), vec![2, 0, 0xaa]);
    assert!(matches!(
        receive(&unsupported, 25),
        Err(ProtocolStateError::UnsupportedBlobVersion { address, version: 2 })
            if address == deduplication_address
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
    let engine =
        ProtocolStateEngine::with_deduplication_capacity(MIN_DEDUPLICATION_CAPACITY).unwrap();
    let mut fixture = ProtocolFixture::new([0x25; 32]);
    let smallest = engine
        .initialize_deduplication_set(&mut rng(0x44), fixture.deduplication_key.clone())
        .unwrap();
    fixture.bob_store.set_raw(
        smallest.address().clone(),
        smallest.blob().unwrap().as_bytes().to_vec(),
    );
    let mut first_message = None;

    for index in 0..=MIN_DEDUPLICATION_CAPACITY {
        let encrypted = fixture.encrypt_from_alice(&engine, index as u16 + 1, b"fills window");
        fixture.decrypt_for_bob(&engine, &encrypted, 26);
        first_message.get_or_insert(encrypted.message);
    }

    let result = bob_receives(
        &engine,
        &fixture,
        &fixture.bob_store.snapshot(),
        &first_message.unwrap(),
        None,
        27,
    );

    assert!(matches!(result, Err(ProtocolStateError::Ratchet(_))));
}

#[test]
fn tampered_ciphertext_exposes_no_sender_identity() {
    let engine = ProtocolStateEngine::new();
    let fixture = ProtocolFixture::new([0x26; 32]);
    let mut encrypted = alice_sends(&engine, &fixture, 3, b"secret").message;
    *encrypted.ciphertext.last_mut().unwrap() ^= 0x01;

    let result = bob_receives(
        &engine,
        &fixture,
        &fixture.bob_store.snapshot(),
        &encrypted,
        None,
        13,
    );

    assert!(matches!(result, Err(ProtocolStateError::SealedFrame(_))));
}

#[test]
fn tampered_transport_metadata_exposes_no_sender_identity() {
    let engine = ProtocolStateEngine::new();
    let fixture = ProtocolFixture::new([0x27; 32]);
    let encrypted = alice_sends(&engine, &fixture, 5, b"metadata-bound").message;
    let copy = || Message::from_bytes(&encrypted.to_bytes().unwrap()).unwrap();
    let mut wrong_recipient = copy();
    wrong_recipient.recipient_public_key = *fixture.alice.discovery_key.public_key().as_bytes();
    let mut wrong_ephemeral = copy();
    wrong_ephemeral.ephemeral_public_key =
        *KeyPair::from_secret_bytes([0x55; 32]).public.as_bytes();

    for message in [wrong_recipient, wrong_ephemeral] {
        let result = bob_receives(
            &engine,
            &fixture,
            &fixture.bob_store.snapshot(),
            &message,
            None,
            16,
        );
        assert!(matches!(result, Err(ProtocolStateError::SealedFrame(_))));
    }
}

#[test]
fn decrypt_message_rejects_recipient_identity_discovery_mismatch() {
    let engine = ProtocolStateEngine::new();
    let fixture = ProtocolFixture::new([0x28; 32]);
    let encrypted = alice_sends(&engine, &fixture, 0x1a, b"wrong recipient identity").message;
    for (recipient_identity_verifying_key, expected) in [
        (
            SigningKeyPair::from_signing_bytes([0x44; 32])
                .verifying
                .to_bytes(),
            "recipient discovery key does not match recipient identity key",
        ),
        (
            [0xff; 32],
            "recipient identity verifying key is not canonical",
        ),
    ] {
        let mut inbound = fixture.inbound_with_validation(&encrypted, None);
        inbound.recipient_identity_verifying_key = recipient_identity_verifying_key;

        let result = engine.decrypt_message_with_transport_bindings(
            &mut rng(0x1a),
            &fixture.bob_store.snapshot(),
            inbound,
            &binding(),
            &binding(),
        );

        assert!(matches!(
            result,
            Err(ProtocolStateError::InvalidMessage { reason }) if reason == expected
        ));
    }
}

#[test]
fn process_acknowledgment_rejects_recipient_identity_discovery_mismatch() {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0x29; 32]);
    let encrypted = fixture.encrypt_from_alice(&engine, 0x1c, b"acknowledgment recipient");
    let decrypted = fixture.decrypt_for_bob(&engine, &encrypted, 0x1c);
    for (recipient_identity_verifying_key, expected) in [
        (
            SigningKeyPair::from_signing_bytes([0x44; 32])
                .verifying
                .to_bytes(),
            "recipient discovery key does not match recipient identity key",
        ),
        (
            [0xff; 32],
            "recipient identity verifying key is not canonical",
        ),
    ] {
        let mut inbound = fixture.alice_acknowledgment(&decrypted.acknowledgment);
        inbound.recipient_identity_verifying_key = recipient_identity_verifying_key;

        let result = engine.process_acknowledgment_with_transport_binding(
            &mut rng(0x1c),
            &fixture.alice_store.snapshot(),
            inbound,
            &binding(),
        );

        assert!(matches!(
            result,
            Err(ProtocolStateError::InvalidMessage { reason }) if reason == expected
        ));
    }
}

#[test]
fn large_valid_outbound_message_persists_pending_acknowledgment() {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0x2a; 32]);
    let large_plaintext = vec![0u8; 65_180];

    let result = alice_sends(&engine, &fixture, 1, &large_plaintext);
    assert!(result.message.to_bytes().unwrap().len() > 64 * 1024);
    let message_id = result.message_id;
    fixture.alice_store.commit(result.state_updates).unwrap();

    let pending = engine
        .pending_acknowledgments(&fixture.alice_store.snapshot(), fixture.session_id)
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].message_id, message_id);
}

#[test]
fn oversized_outbound_message_does_not_return_advanced_state() {
    let engine = ProtocolStateEngine::new();
    let fixture = ProtocolFixture::new([0x2b; 32]);
    let before = fixture.alice_store.snapshot_bytes();

    let result = engine.encrypt_message_with_transport_binding(
        &mut rng(1),
        &fixture.alice_store.snapshot(),
        fixture.outbound(1, &[0u8; 64 * 1024]),
        &binding(),
    );

    assert!(matches!(
        result,
        Err(ProtocolStateError::InvalidMessage { .. })
    ));
    assert_eq!(fixture.alice_store.snapshot_bytes(), before);
}

#[test]
fn wipe_removes_all_state_kinds_for_key() {
    let engine = ProtocolStateEngine::new();
    let key = ProtocolStateKey::from_bytes(vec![9u8; 16]).unwrap();
    let mut snapshot = ProtocolStateSnapshot::new();
    let active_kinds = [
        ProtocolStateKind::RatchetSession,
        ProtocolStateKind::DeduplicationSet,
        ProtocolStateKind::PendingAcknowledgments,
        ProtocolStateKind::ContactState,
        // Wiping must clear a peer's delivery capability too: leaving one behind after session
        // replacement would keep a stale bearer secret on disk with nothing left that uses it.
        ProtocolStateKind::PeerInboxAuthorization,
        ProtocolStateKind::LocalInboxAuthorization,
        ProtocolStateKind::PeerSessions,
    ];
    assert_eq!(ProtocolStateKind::all(), active_kinds.as_slice());

    for kind in active_kinds {
        snapshot
            .set(
                ProtocolStateAddress::new(kind, key.clone()),
                ProtocolStateBlob::from_bytes(vec![kind as u8, 7]),
            )
            .unwrap();
    }

    let updates = engine.wipe(&snapshot, key.clone());
    assert_eq!(
        updates
            .iter()
            .map(|update| update.address().kind())
            .collect::<Vec<_>>(),
        active_kinds
    );
    snapshot.apply_all(updates).unwrap();

    for kind in active_kinds {
        assert!(
            snapshot
                .get(&ProtocolStateAddress::new(kind, key.clone()))
                .is_none()
        );
    }
}

#[test]
fn oversized_or_corrupt_session_blob_is_a_decode_fault_without_reinitialization() {
    let engine = ProtocolStateEngine::new();
    let fixture = ProtocolFixture::new([0x2c; 32]);
    let address = session_address(fixture.session_id);
    for stored in [vec![1; 128 * 1024], vec![1, 0, 0xaa]] {
        let mut alice_store = fixture.alice_store.clone();
        alice_store.set_raw(address.clone(), stored.clone());

        let result = engine.encrypt_message_with_transport_binding(
            &mut rng(1),
            &alice_store.snapshot(),
            fixture.outbound(1, b"lost"),
            &binding(),
        );

        assert!(matches!(
            result,
            Err(ProtocolStateError::BlobDecode { address: actual, .. }) if actual == address
        ));
        assert_eq!(blob(&alice_store, &address), stored);
    }
}

#[test]
fn missing_required_state_is_an_explicit_failure() {
    let engine = ProtocolStateEngine::new();
    let fixture = ProtocolFixture::new([0x2d; 32]);
    let address = session_address(fixture.session_id);
    let mut alice_store = HostStore::default();
    for (stored_address, bytes) in fixture.alice_store.snapshot_bytes() {
        if stored_address != address {
            alice_store.set_raw(stored_address, bytes);
        }
    }

    assert!(matches!(
        engine.encrypt_message_with_transport_binding(
            &mut rng(1),
            &alice_store.snapshot(),
            fixture.outbound(1, b"lost"),
            &binding(),
        ),
        Err(ProtocolStateError::MissingRequiredState { address: actual }) if actual == address
    ));
}

#[test]
fn after_wipe_session_operation_requires_a_new_handshake() {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0x2e; 32]);
    let wiped_session = fixture.session_id;
    let key = ProtocolStateKey::from_bytes(wiped_session.as_bytes().to_vec()).unwrap();
    let wipe = engine.wipe(&fixture.alice_store.snapshot(), key);
    fixture.alice_store.commit(wipe).unwrap();

    assert!(matches!(
        engine.encrypt_message_with_transport_binding(
            &mut rng(1),
            &fixture.alice_store.snapshot(),
            fixture.outbound(1, b"after wipe"),
            &binding(),
        ),
        Err(ProtocolStateError::MissingRequiredState { .. })
    ));

    fixture.start_session(&engine, &mut rng(0x2f));
    assert_ne!(fixture.session_id, wiped_session);
    let restored = fixture.encrypt_from_alice(&engine, 2, b"restored");
    let received = fixture.decrypt_for_bob(&engine, &restored, 0x30);
    assert_eq!(received.plaintext.as_slice(), b"restored");
}
