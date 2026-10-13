//! Exercises the public protocol-state API over consumer-held opaque blobs.

mod support;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use roost_core::{
    BlockedContactAcknowledgmentPolicy, ContactDiscoveryKey, ContactIdentity, ContactTrustState,
    DEFAULT_DEDUPLICATION_CAPACITY, InboundMessageOutcome, InboundSenderCertificateValidation,
    MIN_DEDUPLICATION_CAPACITY, Message, MessageError, MessageOperationError,
    OutboundMessageResult, ProtocolHardeningLimits, ProtocolStateAddress, ProtocolStateBlob,
    ProtocolStateEngine, ProtocolStateError, ProtocolStateKey, ProtocolStateKind,
    ProtocolStateSnapshot, ReceiveSettings, SessionEvent, SessionId, SessionUnrecoverableReason,
    SessionUnrecoverableResult, SignedSenderCertificate,
};
use roost_crypto::{KeyPair, RatchetError, SealedFrameError, generate_discovery_key};
use roost_protocol::{
    DomainSigningKeyStatus, MAX_CERTIFICATE_GRACE_WINDOW, PayloadKind,
    SenderCertificateIdentityKey, SenderCertificateValidationError, from_unix_millis,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use support::{
    CREATED_AT_SECS, HostStore, ProtocolFixture, TestIdentity, accepted, dead_session_blob,
    deduplication_address, session_address, signed, trusted_validation, validated_sender,
    validation,
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
    fixture
        .encrypt(
            engine,
            &fixture.alice_store,
            fixture.outgoing(sequence, plaintext),
            sequence as u8,
        )
        .unwrap()
}

// Alice encrypts with `certificate` in place of her own, without committing.
fn alice_sends_certified(
    engine: &ProtocolStateEngine,
    fixture: &ProtocolFixture,
    certificate: SignedSenderCertificate,
    sequence: u16,
    plaintext: &[u8],
) -> OutboundMessageResult {
    let mut outgoing = fixture.outgoing(sequence, plaintext);
    outgoing.sender_certificate = certificate;
    fixture
        .encrypt(engine, &fixture.alice_store, outgoing, sequence as u8)
        .unwrap()
}

// Bob receives `message` over `store` with the given settings and certificate validation inputs.
fn bob_receives(
    engine: &ProtocolStateEngine,
    fixture: &ProtocolFixture,
    store: &HostStore,
    message: &Message,
    settings: ReceiveSettings,
    sender_certificate_validation: InboundSenderCertificateValidation,
    seed: u8,
) -> Result<InboundMessageOutcome, MessageOperationError> {
    fixture.decrypt(
        engine,
        store,
        fixture.incoming(message, settings, sender_certificate_validation),
        seed,
    )
}

// Bob receives `message` with default settings, the trusted domain, and no revocations.
fn bob_receives_validated(
    engine: &ProtocolStateEngine,
    fixture: &ProtocolFixture,
    store: &HostStore,
    message: &Message,
    seed: u8,
) -> Result<InboundMessageOutcome, MessageOperationError> {
    fixture.receive(engine, store, message, seed)
}

// Returns the protocol fault an operation failed with.
fn failure<T>(result: Result<T, MessageOperationError>) -> ProtocolStateError {
    match result {
        Err(MessageOperationError::ProtocolState(error)) => error,
        Err(error) => panic!("expected a protocol fault, got {error}"),
        Ok(_) => panic!("expected a protocol fault"),
    }
}

fn settings_with_policy(policy: BlockedContactAcknowledgmentPolicy) -> ReceiveSettings {
    ReceiveSettings::new(DEFAULT_DEDUPLICATION_CAPACITY, policy, Duration::ZERO).unwrap()
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
    assert_eq!(result.changes.updates().len(), 2);
    assert_eq!(result.changes.updates()[0].address(), &address);
    assert_eq!(result.changes.updates()[1].address(), &pending_address);
    assert_ne!(
        result.changes.updates()[0].blob().unwrap().as_bytes(),
        prior_blob.as_slice()
    );
    assert_ne!(
        result.changes.updates()[1].blob().unwrap().as_bytes(),
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
            &fixture.bob_store,
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
            &fixture.bob_store,
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
    let message_id = encrypted.message_id;
    let message = support::copy(&encrypted.message);
    fixture
        .alice_store
        .commit_changes(encrypted.changes)
        .unwrap();
    let pending = engine
        .pending_acknowledgments(&fixture.alice_store.snapshot(), fixture.session_id)
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].message_id, message_id);

    let decrypted = accepted(
        bob_receives_validated(&engine, &fixture, &fixture.bob_store, &message, 0x31).unwrap(),
    );
    assert_eq!(decrypted.plaintext.as_slice(), b"ack me");
    assert!(decrypted.acknowledgment.prekey_reference.is_none());
    let encoded_ack = decrypted.acknowledgment.to_bytes().unwrap();
    assert!(
        !encoded_ack
            .windows(message_id.as_bytes().len())
            .any(|window| window == message_id.as_bytes())
    );

    let process = |store: &HostStore, seed: u8| {
        fixture
            .alice_receives_over(&engine, store, &decrypted.acknowledgment, seed)
            .unwrap()
    };
    let InboundMessageOutcome::AcknowledgmentMatched(cleared) = process(&fixture.alice_store, 0x41)
    else {
        panic!("acknowledgment did not clear pending state");
    };
    assert_eq!(cleared.session_id, fixture.session_id);
    assert_eq!(cleared.acknowledged_message_id, message_id);
    assert_eq!(
        cleared.sender_identity.identity_key,
        fixture.bob.sender_identity.identity_key
    );
    let mut alice_store = fixture.alice_store.clone();
    alice_store.commit_changes(cleared.changes).unwrap();
    assert!(
        engine
            .pending_acknowledgments(&alice_store.snapshot(), fixture.session_id)
            .unwrap()
            .is_empty()
    );
    for seed in 0x42..0x47 {
        assert!(matches!(
            process(&alice_store, seed),
            InboundMessageOutcome::Duplicate
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
        process(&alice_store, 0x47),
        InboundMessageOutcome::Duplicate
    ));
}

#[test]
fn retry_instructions_are_windowed_and_persisted() {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0x06; 32]);
    let encrypted = alice_sends(&engine, &fixture, 0x33, b"retry later");
    let sent_at = encrypted.sent_at_millis;
    let message_id = encrypted.message_id;
    fixture
        .alice_store
        .commit_changes(encrypted.changes)
        .unwrap();
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
    assert_eq!(due.instructions[0].message_id, message_id);
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
        failure(fixture.encrypt(
            &engine,
            &corrupt,
            fixture.outgoing(0x34, b"corrupt pending"),
            0x34,
        )),
        ProtocolStateError::BlobDecode { address: actual, .. } if actual == address
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
fn oversized_inbound_message_rejects_before_any_read() {
    let engine = ProtocolStateEngine::new();
    let fixture = ProtocolFixture::new([0x08; 32]);
    let mut oversized = alice_sends(&engine, &fixture, 0x36, b"oversized").message;
    oversized.ciphertext = vec![0; ProtocolHardeningLimits::default().max_message_payload_len + 1];

    let result = engine.start_decryption(
        fixture.bob.local_keys(),
        fixture.incoming(&oversized, ReceiveSettings::default(), trusted_validation()),
    );

    assert!(matches!(
        result,
        Err(ProtocolStateError::MessageEncode(
            MessageError::PayloadTooLarge
        ))
    ));
}

#[test]
fn an_oversized_session_blob_faults_before_decoding() {
    let engine = ProtocolStateEngine::new();
    let fixture = ProtocolFixture::new([0x09; 32]);
    let address = session_address(fixture.session_id);
    let mut alice_store = fixture.alice_store.clone();
    alice_store.set_raw(
        address.clone(),
        vec![1; ProtocolHardeningLimits::default().max_protocol_state_blob_len + 1],
    );

    let result = fixture.encrypt(
        &engine,
        &alice_store,
        fixture.outgoing(0x37, b"blob limit"),
        0x37,
    );

    assert!(matches!(
        failure(result),
        ProtocolStateError::BlobDecode { address: actual, .. } if actual == address
    ));
}

#[test]
fn oversized_sender_material_is_refused_before_sealing() {
    let engine = ProtocolStateEngine::new();
    let fixture = ProtocolFixture::new([0x0c; 32]);
    let limits = ProtocolHardeningLimits::default();
    let certificate = fixture.alice.certificate();
    for oversized in [
        SignedSenderCertificate {
            certificate: vec![0; limits.max_sender_certificate_len + 1],
            signature: certificate.signature.clone(),
        },
        SignedSenderCertificate {
            certificate: certificate.certificate.clone(),
            signature: vec![0; limits.max_sender_signature_len + 1],
        },
    ] {
        let mut outgoing = fixture.outgoing(0x39, b"certificate limit");
        outgoing.sender_certificate = oversized;

        let result = engine.start_encryption(fixture.alice.local_keys(), outgoing);

        assert!(matches!(
            result,
            Err(ProtocolStateError::InvalidMessage { .. })
        ));
    }
}

#[test]
fn unique_received_message_is_accepted_recorded_and_emitted_once() {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0x0e; 32]);
    let session_address = session_address(fixture.session_id);
    let deduplication_address = deduplication_address();
    let prior_session = blob(&fixture.bob_store, &session_address);
    let prior_deduplication = blob(&fixture.bob_store, &deduplication_address);
    let encrypted = alice_sends(&engine, &fixture, 10, b"accept once").message;

    let decrypted = accepted(
        bob_receives_validated(&engine, &fixture, &fixture.bob_store, &encrypted, 19).unwrap(),
    );

    assert_eq!(decrypted.plaintext.as_slice(), b"accept once");
    assert_eq!(decrypted.changes.updates().len(), 2);
    assert_eq!(decrypted.changes.updates()[0].address(), &session_address);
    assert_eq!(
        decrypted.changes.updates()[1].address(),
        &deduplication_address
    );
    assert_ne!(
        decrypted.changes.updates()[0].blob().unwrap().as_bytes(),
        prior_session
    );
    assert_ne!(
        decrypted.changes.updates()[1].blob().unwrap().as_bytes(),
        prior_deduplication
    );
    fixture.bob_store.commit_changes(decrypted.changes).unwrap();

    let duplicate = bob_receives_validated(
        &ProtocolStateEngine::new(),
        &fixture,
        &fixture.bob_store,
        &encrypted,
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
        bob_receives_validated(&engine, &fixture, &fixture.bob_store, &encrypted, 0x3c).unwrap(),
    );
    fixture.bob_store.commit_changes(decrypted.changes).unwrap();
    let after_accept = fixture.bob_store.snapshot_bytes();

    for seed in 0x3d..0x45 {
        let duplicate =
            bob_receives_validated(&engine, &fixture, &fixture.bob_store, &encrypted, seed)
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
            last = Some(support::copy(&sent.message));
            let session_update = sent
                .changes
                .into_updates()
                .into_iter()
                .filter(|update| update.address().kind() == ProtocolStateKind::RatchetSession)
                .collect();
            fixture.alice_store.commit(session_update).unwrap();
        }
        let received = accepted(
            bob_receives_validated(&engine, &fixture, &fixture.bob_store, &last.unwrap(), round)
                .unwrap(),
        );
        fixture.bob_store.commit_changes(received.changes).unwrap();
        fixture.bob_replies(&engine, round);
    }
    sequence += 1;
    let undelivered = alice_sends(&engine, &fixture, sequence, b"undelivered");
    fixture
        .alice_store
        .commit_changes(undelivered.changes)
        .unwrap();
    let terminal = alice_sends(&engine, &fixture, sequence + 1, b"overflow").message;

    for seed in [0xf0, 0xf1] {
        assert!(matches!(
            failure(bob_receives_validated(
                &engine,
                &fixture,
                &fixture.bob_store,
                &terminal,
                seed
            )),
            ProtocolStateError::Ratchet(RatchetError::MaxSkippedKeysExceeded)
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
        bob_receives_validated(&engine, &fixture, &fixture.bob_store, &dead_message, 0xe0).unwrap(),
    );
    assert_eq!(unrecoverable.session_id, fixture.session_id);
    assert_eq!(
        unrecoverable.reason,
        SessionUnrecoverableReason::SkippedKeyLimitExceeded
    );
    assert_eq!(unrecoverable.changes.updates().len(), 1);
    assert_eq!(unrecoverable.changes.updates()[0].address(), &address);
    assert_eq!(
        unrecoverable.event,
        Some(SessionEvent::Unrecoverable {
            session_id: fixture.session_id,
            reason: SessionUnrecoverableReason::SkippedKeyLimitExceeded,
        })
    );
    fixture
        .bob_store
        .commit_changes(unrecoverable.changes)
        .unwrap();

    let repeated = session_unrecoverable(
        bob_receives_validated(&engine, &fixture, &fixture.bob_store, &dead_message, 0xe1).unwrap(),
    );
    assert!(repeated.event.is_none());
    assert!(repeated.changes.updates().is_empty());
}

#[test]
fn transient_aead_failure_does_not_mark_session_unrecoverable() {
    let engine = ProtocolStateEngine::new();
    let fixture = ProtocolFixture::new([0x12; 32]);
    let encrypted = alice_sends(&engine, &fixture, 0x70, b"valid after tamper").message;
    let mut tampered = support::copy(&encrypted);
    *tampered.ciphertext.last_mut().unwrap() ^= 0x01;

    assert!(matches!(
        failure(bob_receives_validated(
            &engine,
            &fixture,
            &fixture.bob_store,
            &tampered,
            0x70
        )),
        ProtocolStateError::SealedFrame(SealedFrameError::Aead)
    ));
    let decrypted = accepted(
        bob_receives_validated(&engine, &fixture, &fixture.bob_store, &encrypted, 0x71).unwrap(),
    );

    assert_eq!(decrypted.plaintext.as_slice(), b"valid after tamper");
}

#[test]
fn duplicate_received_message_does_not_load_or_advance_ratchet_state() {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0x14; 32]);
    let encrypted = alice_sends(&engine, &fixture, 11, b"no duplicate effect").message;
    let decrypted = accepted(
        bob_receives_validated(&engine, &fixture, &fixture.bob_store, &encrypted, 21).unwrap(),
    );
    fixture.bob_store.commit_changes(decrypted.changes).unwrap();
    fixture
        .bob_store
        .set_raw(session_address(fixture.session_id), vec![1, 0, 0xaa]);

    let duplicate =
        bob_receives_validated(&engine, &fixture, &fixture.bob_store, &encrypted, 22).unwrap();

    assert!(matches!(duplicate, InboundMessageOutcome::Duplicate));
}

#[test]
fn blocked_inbound_message_under_unreachable_policy_suppresses_acknowledgment_without_plaintext() {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0x15; 32]);
    block_alice(&engine, &mut fixture);
    let session_address = session_address(fixture.session_id);
    let deduplication_address = deduplication_address();
    let prior_session = blob(&fixture.bob_store, &session_address);
    let prior_deduplication = blob(&fixture.bob_store, &deduplication_address);
    let encrypted = alice_sends(&engine, &fixture, 0x51, b"blocked text").message;

    let blocked = blocked(
        bob_receives_validated(&engine, &fixture, &fixture.bob_store, &encrypted, 0x51).unwrap(),
    );

    assert!(blocked.acknowledgment.is_none());
    assert_eq!(blocked.changes.updates().len(), 2);
    assert_eq!(blocked.changes.updates()[0].address(), &session_address);
    assert_eq!(
        blocked.changes.updates()[1].address(),
        &deduplication_address
    );
    assert_ne!(
        blocked.changes.updates()[0].blob().unwrap().as_bytes(),
        prior_session
    );
    assert_ne!(
        blocked.changes.updates()[1].blob().unwrap().as_bytes(),
        prior_deduplication
    );
}

#[test]
fn blocked_inbound_message_under_silent_receipt_policy_returns_acknowledgment_without_plaintext() {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0x16; 32]);
    block_alice(&engine, &mut fixture);
    let encrypted = alice_sends(&engine, &fixture, 0x54, b"blocked but receipted").message;

    let blocked = blocked(
        bob_receives(
            &engine,
            &fixture,
            &fixture.bob_store,
            &encrypted,
            settings_with_policy(BlockedContactAcknowledgmentPolicy::SilentReceipt),
            trusted_validation(),
            0x54,
        )
        .unwrap(),
    );

    let acknowledgment = blocked
        .acknowledgment
        .expect("silent-receipt returns an acknowledgment");
    assert!(acknowledgment.prekey_reference.is_none());
    assert_eq!(blocked.changes.updates().len(), 2);
    assert_eq!(
        blocked.changes.updates()[0].address(),
        &session_address(fixture.session_id)
    );
    assert_eq!(
        blocked.changes.updates()[1].address(),
        &deduplication_address()
    );
}

#[test]
fn blocked_acknowledgment_policy_controls_sending_chain_advance() {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0x17; 32]);
    block_alice(&engine, &mut fixture);
    let encrypted = alice_sends(&engine, &fixture, 0x55, b"chain advance").message;
    let receive = |policy| {
        blocked(
            bob_receives(
                &engine,
                &fixture,
                &fixture.bob_store,
                &encrypted,
                settings_with_policy(policy),
                trusted_validation(),
                0x55,
            )
            .unwrap(),
        )
    };

    let suppressed = receive(BlockedContactAcknowledgmentPolicy::Unreachable);
    let receipted = receive(BlockedContactAcknowledgmentPolicy::SilentReceipt);

    assert!(suppressed.acknowledgment.is_none());
    assert!(receipted.acknowledgment.is_some());
    let session_address = session_address(fixture.session_id);
    assert_eq!(suppressed.changes.updates()[0].address(), &session_address);
    assert_eq!(receipted.changes.updates()[0].address(), &session_address);
    // The acknowledgment advances the sending chain, so only silent-receipt mutates it further.
    assert_ne!(
        suppressed.changes.updates()[0].blob().unwrap().as_bytes(),
        receipted.changes.updates()[0].blob().unwrap().as_bytes(),
    );
}

#[test]
fn duplicate_blocked_inbound_message_does_not_load_or_advance_ratchet_state() {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0x18; 32]);
    block_alice(&engine, &mut fixture);
    let encrypted = alice_sends(&engine, &fixture, 0x52, b"blocked once").message;
    let first = blocked(
        bob_receives_validated(&engine, &fixture, &fixture.bob_store, &encrypted, 0x52).unwrap(),
    );
    fixture.bob_store.commit_changes(first.changes).unwrap();
    fixture
        .bob_store
        .set_raw(session_address(fixture.session_id), vec![1, 0, 0xaa]);

    let duplicate =
        bob_receives_validated(&engine, &fixture, &fixture.bob_store, &encrypted, 0x53).unwrap();

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

    let outcome =
        bob_receives_validated(&engine, &fixture, &fixture.bob_store, &encrypted, 0x54).unwrap();

    assert!(matches!(outcome, InboundMessageOutcome::Blocked(_)));
}

#[test]
fn revoked_certificate_rejects_before_local_block_handling() {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0x1a; 32]);
    block_alice(&engine, &mut fixture);
    let encrypted = alice_sends(&engine, &fixture, 0x55, b"revoked blocked").message;
    let revoked = vec![alice_revoked_identity_key(&fixture)];

    let result = bob_receives(
        &engine,
        &fixture,
        &fixture.bob_store,
        &encrypted,
        ReceiveSettings::default(),
        validation(vec![validated_sender().domain_signing_key()], revoked),
        0x55,
    );

    assert!(matches!(
        failure(result),
        ProtocolStateError::SenderCertificateValidation(
            SenderCertificateValidationError::RevokedIdentityKey
        )
    ));
}

#[test]
fn unavailable_revocation_state_rejects_before_plaintext_is_surfaced() {
    let engine = ProtocolStateEngine::new();
    let fixture = ProtocolFixture::new([0x1c; 32]);
    let encrypted = alice_sends(&engine, &fixture, 0x56, b"revocation unavailable").message;

    let result = bob_receives(
        &engine,
        &fixture,
        &fixture.bob_store,
        &encrypted,
        ReceiveSettings::default(),
        InboundSenderCertificateValidation {
            revoked_identity_keys: None,
            ..trusted_validation()
        },
        0x56,
    );

    assert!(matches!(
        failure(result),
        ProtocolStateError::SenderCertificateValidation(
            SenderCertificateValidationError::RevocationStateUnavailable
        )
    ));
}

#[test]
fn untrusted_signing_key_rejects_before_plaintext_is_surfaced() {
    let engine = ProtocolStateEngine::new();
    let fixture = ProtocolFixture::new([0x1d; 32]);
    let encrypted = alice_sends(&engine, &fixture, 0x59, b"untrusted domain").message;
    let mut untrusted = validated_sender().domain_signing_key();
    untrusted.status = DomainSigningKeyStatus::Untrusted;

    let result = bob_receives(
        &engine,
        &fixture,
        &fixture.bob_store,
        &encrypted,
        ReceiveSettings::default(),
        validation(vec![untrusted], Vec::new()),
        0x59,
    );

    assert!(matches!(
        failure(result),
        ProtocolStateError::SenderCertificateValidation(
            SenderCertificateValidationError::UntrustedSigningKeyId
        )
    ));
}

#[test]
fn expired_certificate_rejects_before_plaintext_is_surfaced() {
    let engine = ProtocolStateEngine::new();
    let fixture = ProtocolFixture::new([0x1e; 32]);
    let expired = fixture.alice.certified_until(CREATED_AT_SECS - 1);
    let encrypted =
        alice_sends_certified(&engine, &fixture, signed(&expired), 0x5a, b"expired domain").message;

    let result = bob_receives_validated(&engine, &fixture, &fixture.bob_store, &encrypted, 0x5a);

    assert!(matches!(
        failure(result),
        ProtocolStateError::SenderCertificateValidation(
            SenderCertificateValidationError::ExpiredCertificate
        )
    ));
}

#[test]
fn message_at_the_passed_grace_boundary_is_accepted() {
    let engine = ProtocolStateEngine::new();
    let fixture = ProtocolFixture::new([0x1f; 32]);
    let expiring = fixture
        .alice
        .certified_until(CREATED_AT_SECS - MAX_CERTIFICATE_GRACE_WINDOW.as_secs());
    let encrypted = alice_sends_certified(
        &engine,
        &fixture,
        signed(&expiring),
        0x5e,
        b"at the grace window boundary",
    )
    .message;
    let settings = ReceiveSettings::new(
        DEFAULT_DEDUPLICATION_CAPACITY,
        BlockedContactAcknowledgmentPolicy::Unreachable,
        MAX_CERTIFICATE_GRACE_WINDOW,
    )
    .unwrap();

    let accepted = accepted(
        bob_receives(
            &engine,
            &fixture,
            &fixture.bob_store,
            &encrypted,
            settings,
            trusted_validation(),
            0x5e,
        )
        .unwrap(),
    );

    assert_eq!(
        accepted.plaintext.as_slice(),
        b"at the grace window boundary"
    );
    assert!(matches!(
        failure(bob_receives_validated(
            &engine,
            &fixture,
            &fixture.bob_store,
            &encrypted,
            0x5f
        )),
        ProtocolStateError::SenderCertificateValidation(
            SenderCertificateValidationError::ExpiredCertificate
        )
    ));
}

#[test]
fn certificate_identity_key_must_match_sealed_sender() {
    let engine = ProtocolStateEngine::new();
    let fixture = ProtocolFixture::new([0x20; 32]);
    let carol = TestIdentity::new(0x77, 0x73);
    let encrypted = alice_sends_certified(
        &engine,
        &fixture,
        carol.certificate(),
        0x58,
        b"mismatched certificate",
    )
    .message;

    assert!(matches!(
        failure(bob_receives_validated(&engine, &fixture, &fixture.bob_store, &encrypted, 0x58)),
        ProtocolStateError::InvalidMessage { reason }
            if reason == "sender certificate identity key does not match sealed sender"
    ));
}

#[test]
fn decrypt_rejects_sender_identity_that_is_not_bound_to_session() {
    let engine = ProtocolStateEngine::new();
    let fixture = ProtocolFixture::new([0x21; 32]);
    let carol = TestIdentity::new(0x77, 0x73);
    // Alice's Session state, but Carol's keys and sealed identity.
    let mut outgoing = fixture.outgoing(9, b"wrong sender");
    outgoing.sender_certificate = carol.certificate();
    let encrypted = support::run_encryption(
        engine
            .start_encryption(carol.local_keys(), outgoing)
            .unwrap(),
        &fixture.alice_store,
        &mut rng(9),
        &fixture.binding,
    )
    .unwrap()
    .message;

    assert!(matches!(
        failure(bob_receives_validated(&engine, &fixture, &fixture.bob_store, &encrypted, 15)),
        ProtocolStateError::InvalidMessage { reason }
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
        bob_receives_validated(&engine, &fixture, &fixture.bob_store, &first.message, 0x56)
            .unwrap(),
    );
    fixture.bob_store.commit_changes(blocked.changes).unwrap();
    let unblocked = engine
        .unblock_contact(&fixture.bob_store.snapshot(), fixture.alice.identity_key())
        .unwrap();
    fixture.bob_store.commit(unblocked.state_updates).unwrap();
    let second = fixture.encrypt_from_alice(&engine, 0x57, b"after unblock");

    let accepted = accepted(
        bob_receives_validated(&engine, &fixture, &fixture.bob_store, &second.message, 0x57)
            .unwrap(),
    );

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

    let InboundMessageOutcome::AcknowledgmentMatched(cleared) = fixture
        .alice_receives(&engine, &decrypted.acknowledgment, 24)
        .unwrap()
    else {
        panic!("acknowledgment did not clear pending state");
    };
    fixture.alice_store.commit_changes(cleared.changes).unwrap();

    assert_eq!(
        trust(&fixture.alice_store, &fixture.bob),
        ContactTrustState::Unverified
    );
}

#[test]
fn deduplication_receive_rejects_bad_state() {
    let engine = ProtocolStateEngine::new();
    let fixture = ProtocolFixture::new([0x24; 32]);
    let deduplication_address = deduplication_address();
    let encrypted = alice_sends(&engine, &fixture, 12, b"bad dedup state").message;
    let receive = |store: &HostStore, seed: u8| {
        bob_receives_validated(&engine, &fixture, store, &encrypted, seed)
    };

    let mut corrupt = fixture.bob_store.clone();
    corrupt.set_raw(deduplication_address.clone(), vec![1, 0, 0xaa]);
    assert!(matches!(
        failure(receive(&corrupt, 24)),
        ProtocolStateError::BlobDecode { address, .. } if address == deduplication_address
    ));

    let mut unsupported = fixture.bob_store.clone();
    unsupported.set_raw(deduplication_address.clone(), vec![2, 0, 0xaa]);
    assert!(matches!(
        failure(receive(&unsupported, 25)),
        ProtocolStateError::UnsupportedBlobVersion { address, version: 2 }
            if address == deduplication_address
    ));
}

#[test]
fn deduplication_capacity_evicts_oldest_digest_first() {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0x25; 32]);
    let smallest = ReceiveSettings::new(
        MIN_DEDUPLICATION_CAPACITY,
        BlockedContactAcknowledgmentPolicy::Unreachable,
        Duration::ZERO,
    )
    .unwrap();
    fixture.bob_store.remove(&deduplication_address());
    let mut first_message = None;

    for index in 0..=MIN_DEDUPLICATION_CAPACITY {
        let encrypted = fixture.encrypt_from_alice(&engine, index as u16 + 1, b"fills window");
        let received = accepted(
            bob_receives(
                &engine,
                &fixture,
                &fixture.bob_store,
                &encrypted.message,
                smallest,
                trusted_validation(),
                26,
            )
            .unwrap(),
        );
        fixture.bob_store.commit_changes(received.changes).unwrap();
        first_message.get_or_insert(encrypted.message);
    }

    let result = bob_receives(
        &engine,
        &fixture,
        &fixture.bob_store,
        &first_message.unwrap(),
        smallest,
        trusted_validation(),
        27,
    );

    assert!(matches!(failure(result), ProtocolStateError::Ratchet(_)));
}

#[test]
fn tampered_ciphertext_exposes_no_sender_identity() {
    let engine = ProtocolStateEngine::new();
    let fixture = ProtocolFixture::new([0x26; 32]);
    let mut encrypted = alice_sends(&engine, &fixture, 3, b"secret").message;
    *encrypted.ciphertext.last_mut().unwrap() ^= 0x01;

    let result = bob_receives_validated(&engine, &fixture, &fixture.bob_store, &encrypted, 13);

    assert!(matches!(
        failure(result),
        ProtocolStateError::SealedFrame(_)
    ));
}

#[test]
fn tampered_transport_metadata_exposes_no_sender_identity() {
    let engine = ProtocolStateEngine::new();
    let fixture = ProtocolFixture::new([0x27; 32]);
    let encrypted = alice_sends(&engine, &fixture, 5, b"metadata-bound").message;
    let mut wrong_recipient = support::copy(&encrypted);
    wrong_recipient.recipient_public_key = *fixture.alice.discovery_key.public_key().as_bytes();
    let mut wrong_ephemeral = support::copy(&encrypted);
    wrong_ephemeral.ephemeral_public_key =
        *KeyPair::from_secret_bytes([0x55; 32]).public.as_bytes();

    for message in [wrong_recipient, wrong_ephemeral] {
        let result = bob_receives_validated(&engine, &fixture, &fixture.bob_store, &message, 16);
        assert!(matches!(
            failure(result),
            ProtocolStateError::SealedFrame(_)
        ));
    }
}

#[test]
fn operations_refuse_a_discovery_key_the_identity_did_not_sign() {
    let engine = ProtocolStateEngine::new();
    let fixture = ProtocolFixture::new([0x28; 32]);
    let encrypted = alice_sends(&engine, &fixture, 0x1a, b"wrong recipient identity").message;
    let mismatched = || {
        let mut keys = fixture.bob.local_keys();
        keys.discovery_key = fixture.alice.local_keys().discovery_key;
        keys
    };
    let expected = "recipient discovery key does not match recipient identity key";

    let decryption = engine.start_decryption(
        mismatched(),
        fixture.incoming(&encrypted, ReceiveSettings::default(), trusted_validation()),
    );
    let encryption = engine.start_encryption(mismatched(), fixture.outgoing(1, b"unsent"));

    assert!(matches!(
        decryption,
        Err(ProtocolStateError::InvalidMessage { reason }) if reason == expected
    ));
    assert!(matches!(
        encryption,
        Err(ProtocolStateError::InvalidMessage { reason }) if reason == expected
    ));
}

#[test]
fn large_valid_outbound_message_persists_pending_acknowledgment() {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0x2a; 32]);
    let large_plaintext = vec![0u8; 65_180];

    let result = alice_sends(&engine, &fixture, 1, &large_plaintext);
    assert!(result.message.to_bytes().unwrap().len() > 64 * 1024);
    let message_id = result.message_id;
    fixture.alice_store.commit_changes(result.changes).unwrap();

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

    let result = fixture.encrypt(
        &engine,
        &fixture.alice_store,
        fixture.outgoing(1, &[0u8; 64 * 1024]),
        1,
    );

    assert!(matches!(
        failure(result),
        ProtocolStateError::InvalidMessage { .. }
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

        let result = fixture.encrypt(&engine, &alice_store, fixture.outgoing(1, b"lost"), 1);

        assert!(matches!(
            failure(result),
            ProtocolStateError::BlobDecode { address: actual, .. } if actual == address
        ));
        assert_eq!(blob(&alice_store, &address), stored);
    }
}

#[test]
fn missing_required_state_is_an_explicit_failure() {
    let engine = ProtocolStateEngine::new();
    let fixture = ProtocolFixture::new([0x2d; 32]);
    let address = session_address(fixture.session_id);
    let mut alice_store = fixture.alice_store.clone();
    alice_store.remove(&address);

    assert!(matches!(
        failure(fixture.encrypt(&engine, &alice_store, fixture.outgoing(1, b"lost"), 1)),
        ProtocolStateError::MissingRequiredState { address: actual } if actual == address
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
        failure(fixture.encrypt(
            &engine,
            &fixture.alice_store,
            fixture.outgoing(1, b"after wipe"),
            1,
        )),
        ProtocolStateError::MissingRequiredState { .. }
    ));

    fixture.start_session(&engine, &mut rng(0x2f));
    assert_ne!(fixture.session_id, wiped_session);
    let restored = fixture.encrypt_from_alice(&engine, 2, b"restored");
    let received = fixture.decrypt_for_bob(&engine, &restored, 0x30);
    assert_eq!(received.plaintext.as_slice(), b"restored");
}
