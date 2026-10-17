//! Exercises the public protocol-state API over consumer-held opaque blobs.

mod support;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use roost_core::{
    BlockedContactAcknowledgmentPolicy, ContactTrustState, DEFAULT_DEDUPLICATION_CAPACITY,
    InboundMessageOutcome, InboundSenderCertificateValidation, MIN_DEDUPLICATION_CAPACITY, Message,
    MessageError, MessageOperationError, MessageStartError, OutboundMessageResult,
    ProtocolHardeningLimits, ProtocolStateAddress, ProtocolStateBlob, ProtocolStateEngine,
    ProtocolStateError, ProtocolStateKey, ProtocolStateKind, ReceiveSettings, SessionId,
    SignedSenderCertificate,
};
use roost_crypto::{KeyPair, RatchetError, SealedFrameError};
use roost_protocol::{
    DomainSigningKeyStatus, MAX_CERTIFICATE_GRACE_WINDOW, PayloadKind,
    SenderCertificateIdentityKey, SenderCertificateValidationError,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use support::device::{Device, Relay};
use support::{
    CREATED_AT_SECS, HostStore, ProtocolFixture, accepted, deduplication_address, session_address,
    trusted_domain_signing_key, trusted_validation, validation,
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
    payload_kind: u8,
    grant: Option<(u64, u32)>,
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
    fixture: &ProtocolFixture,
    sequence: u16,
    plaintext: &[u8],
) -> OutboundMessageResult {
    fixture
        .encrypt(
            &fixture.alice.host,
            fixture.outgoing(sequence, plaintext),
            sequence as u8,
        )
        .unwrap()
}

// Alice encrypts with `certificate` in place of her own, without committing.
fn alice_sends_certified(
    fixture: &ProtocolFixture,
    certificate: SignedSenderCertificate,
    sequence: u16,
    plaintext: &[u8],
) -> OutboundMessageResult {
    let mut outgoing = fixture.outgoing(sequence, plaintext);
    outgoing.sender_certificate = certificate;
    fixture
        .encrypt(&fixture.alice.host, outgoing, sequence as u8)
        .unwrap()
}

// Bob receives `message` over `store` with the given settings and certificate validation inputs.
fn bob_receives(
    fixture: &ProtocolFixture,
    store: &HostStore,
    message: &Message,
    settings: ReceiveSettings,
    sender_certificate_validation: InboundSenderCertificateValidation,
    seed: u8,
) -> Result<InboundMessageOutcome, MessageOperationError> {
    fixture.decrypt(
        store,
        fixture.incoming(message, settings, sender_certificate_validation),
        seed,
    )
}

// Bob receives `message` with default settings, the trusted domain, and no revocations.
fn bob_receives_validated(
    fixture: &ProtocolFixture,
    store: &HostStore,
    message: &Message,
    seed: u8,
) -> Result<InboundMessageOutcome, MessageOperationError> {
    fixture.receive(store, message, seed)
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

// Has Bob block Alice. The block rotates Bob's inbox, so Alice reaches him again only by requesting
// on his new prekeys, which starts the fixture's new Session.
fn block_alice(fixture: &mut ProtocolFixture) {
    fixture.bob.block(fixture.alice.identity_key());
    fixture.alice.forget_sessions_with(&fixture.bob);
    let request = fixture.alice.request(&fixture.bob, b"after the block");
    blocked(fixture.bob.receive(&request.message));
    fixture.session_id = request.session_id;
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
    let fixture = ProtocolFixture::new();
    let address = session_address(fixture.session_id);
    let pending_address = pending_address(fixture.session_id);
    let prior_blob = blob(&fixture.alice.host, &address);
    let prior_pending_blob = blob(&fixture.alice.host, &pending_address);

    let result = alice_sends(&fixture, 1, b"second");

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
    let fixture = ProtocolFixture::new();
    let encrypted = alice_sends(&fixture, 8, b"sealed sender");
    let identity = &fixture.alice.identity;
    let certificate = fixture.alice.certificate();

    let encoded = encrypted.message.to_bytes().unwrap();
    for (name, material) in [
        ("identity key", identity.public_key.as_bytes().as_slice()),
        (
            "identity verifying key",
            identity.verifying_key.as_bytes().as_slice(),
        ),
        (
            "identity binding signature",
            &identity.binding_signature.to_bytes()[..],
        ),
        ("certificate", certificate.certificate.as_slice()),
        ("certificate signature", certificate.signature.as_slice()),
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
        bob_receives_validated(&fixture, &fixture.bob.host, &encrypted.message, 12).unwrap(),
    );

    assert_eq!(decrypted.plaintext.as_slice(), b"sealed sender");
    assert_eq!(decrypted.session_id, fixture.session_id);
    assert_eq!(
        decrypted.sender_identity.identity_key,
        *identity.public_key.as_bytes()
    );
    assert_eq!(
        decrypted.sender_identity.identity_verifying_key,
        identity.verifying_key.to_bytes()
    );
    assert_eq!(
        decrypted.sender_identity.identity_binding_signature,
        identity.binding_signature.to_bytes()
    );
    assert_eq!(
        decrypted.sender_identity.certificate,
        certificate.certificate
    );
    assert_eq!(decrypted.sender_identity.signature, certificate.signature);
}

#[test]
fn sealed_frame_hides_message_metadata_until_decrypt() {
    let fixture = ProtocolFixture::new();
    let encrypted = alice_sends(&fixture, 0x42, b"hidden metadata");

    assert_eq!(
        encrypted.message.recipient_public_key,
        *fixture.bob.discovery_key().public_key().as_bytes(),
        "only recipient routing key remains visible"
    );
    assert!(encrypted.message.prekey_reference.is_none());
    assert_ne!(encrypted.message.ephemeral_public_key, [0u8; 32]);
    assert!(!encrypted.message.ciphertext.is_empty());

    let decrypted = accepted(
        bob_receives_validated(&fixture, &fixture.bob.host, &encrypted.message, 0x42).unwrap(),
    );

    assert_eq!(decrypted.message_id, encrypted.message_id);
    assert_eq!(decrypted.sent_at_millis, 1_700_000_300_000 + 0x42);
    assert_eq!(decrypted.payload_kind, PayloadKind::EncryptedText);
    assert_eq!(decrypted.plaintext.as_slice(), b"hidden metadata");
}

#[test]
fn accepted_message_generates_encrypted_acknowledgment_that_clears_pending_state() {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new();
    let digests_before = postcard::take_from_bytes::<TestPendingAcknowledgmentsWire>(
        &blob(&fixture.alice.host, &pending_address(fixture.session_id))[1..],
    )
    .unwrap()
    .0
    .acknowledgment_digests
    .len();
    let encrypted = alice_sends(&fixture, 0x31, b"ack me");
    let message_id = encrypted.message_id;
    let message = support::copy(&encrypted.message);
    fixture
        .alice
        .host
        .commit_changes(encrypted.changes)
        .unwrap();
    let pending = engine
        .pending_acknowledgments(&fixture.alice.host.snapshot(), fixture.session_id)
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].message_id, message_id);

    let decrypted =
        accepted(bob_receives_validated(&fixture, &fixture.bob.host, &message, 0x31).unwrap());
    assert_eq!(decrypted.plaintext.as_slice(), b"ack me");
    let acknowledgment = decrypted.acknowledgment.unwrap();
    assert!(acknowledgment.prekey_reference.is_none());
    let encoded_ack = acknowledgment.to_bytes().unwrap();
    assert!(
        !encoded_ack
            .windows(message_id.as_bytes().len())
            .any(|window| window == message_id.as_bytes())
    );

    let process = |store: &HostStore, seed: u8| {
        fixture
            .alice_receives_over(store, &acknowledgment, seed)
            .unwrap()
    };
    let InboundMessageOutcome::AcknowledgmentMatched(cleared) = process(&fixture.alice.host, 0x41)
    else {
        panic!("acknowledgment did not clear pending state");
    };
    assert_eq!(cleared.session_id, fixture.session_id);
    assert_eq!(cleared.acknowledged_message_id, message_id);
    assert_eq!(
        cleared.sender_identity.identity_key,
        *fixture.bob.identity.public_key.as_bytes()
    );
    let mut alice_store = fixture.alice.host.clone();
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
    assert_eq!(wire.acknowledgment_digests.len(), digests_before + 1);
    wire.pending.push(TestPendingAcknowledgmentWire {
        message_id: [0x44; 16],
        encoded_message: vec![0xaa],
        first_sent_at_millis: 1_700_000_100_123,
        payload_kind: 0,
        grant: None,
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
fn pending_acknowledgment_state_faults_on_bad_blobs() {
    let engine = ProtocolStateEngine::new();
    let fixture = ProtocolFixture::new();
    let address = pending_address(fixture.session_id);
    let mut corrupt = fixture.alice.host.clone();
    corrupt.set_raw(address.clone(), vec![2, 0, 0xaa]);
    assert!(matches!(
        failure(fixture.encrypt(
            &corrupt,
            fixture.outgoing(0x34, b"corrupt pending"),
            0x34,
        )),
        ProtocolStateError::BlobDecode { address: actual, .. } if actual == address
    ));

    let mut unsupported = fixture.alice.host.clone();
    unsupported.set_raw(address.clone(), vec![3, 0, 0xaa]);
    assert!(matches!(
        engine.pending_acknowledgments(&unsupported.snapshot(), fixture.session_id),
        Err(ProtocolStateError::UnsupportedBlobVersion {
            address: actual,
            version: 3,
        }) if actual == address
    ));
}

#[test]
fn oversized_inbound_message_rejects_before_any_read() {
    let fixture = ProtocolFixture::new();
    let mut oversized = alice_sends(&fixture, 0x36, b"oversized").message;
    oversized.ciphertext = vec![0; ProtocolHardeningLimits::default().max_message_payload_len + 1];

    let result = fixture.bob.store.start_decryption(fixture.incoming(
        &oversized,
        ReceiveSettings::default(),
        trusted_validation(),
    ));

    assert!(matches!(
        result,
        Err(MessageStartError::ProtocolState(
            ProtocolStateError::MessageEncode(MessageError::PayloadTooLarge)
        ))
    ));
}

#[test]
fn an_oversized_session_blob_faults_before_decoding() {
    let fixture = ProtocolFixture::new();
    let address = session_address(fixture.session_id);
    let mut alice_store = fixture.alice.host.clone();
    alice_store.set_raw(
        address.clone(),
        vec![1; ProtocolHardeningLimits::default().max_protocol_state_blob_len + 1],
    );

    let result = fixture.encrypt(&alice_store, fixture.outgoing(0x37, b"blob limit"), 0x37);

    assert!(matches!(
        failure(result),
        ProtocolStateError::BlobDecode { address: actual, .. } if actual == address
    ));
}

#[test]
fn oversized_sender_material_is_refused_before_sealing() {
    let fixture = ProtocolFixture::new();
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

        let result = fixture.alice.store.start_encryption(outgoing);

        assert!(matches!(
            result,
            Err(MessageStartError::ProtocolState(
                ProtocolStateError::InvalidMessage { .. }
            ))
        ));
    }
}

#[test]
fn unique_received_message_is_accepted_recorded_and_emitted_once() {
    let mut fixture = ProtocolFixture::new();
    let session_address = session_address(fixture.session_id);
    let deduplication_address = deduplication_address();
    let prior_session = blob(&fixture.bob.host, &session_address);
    let prior_deduplication = blob(&fixture.bob.host, &deduplication_address);
    let encrypted = alice_sends(&fixture, 10, b"accept once").message;

    let decrypted =
        accepted(bob_receives_validated(&fixture, &fixture.bob.host, &encrypted, 19).unwrap());

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
    fixture.bob.host.commit_changes(decrypted.changes).unwrap();

    let duplicate = bob_receives_validated(&fixture, &fixture.bob.host, &encrypted, 20).unwrap();
    assert!(matches!(duplicate, InboundMessageOutcome::Duplicate));
}

#[test]
fn replay_storm_returns_duplicate_without_state_churn() {
    let mut fixture = ProtocolFixture::new();
    let encrypted = alice_sends(&fixture, 0x3c, b"replay storm").message;
    let decrypted =
        accepted(bob_receives_validated(&fixture, &fixture.bob.host, &encrypted, 0x3c).unwrap());
    fixture.bob.host.commit_changes(decrypted.changes).unwrap();
    let after_accept = fixture.bob.host.snapshot_bytes();

    for seed in 0x3d..0x45 {
        let duplicate =
            bob_receives_validated(&fixture, &fixture.bob.host, &encrypted, seed).unwrap();
        assert!(matches!(duplicate, InboundMessageOutcome::Duplicate));
        assert_eq!(fixture.bob.host.snapshot_bytes(), after_accept);
    }
}

#[test]
fn skipped_key_total_overflow_rejects_the_message_on_every_attempt() {
    let mut fixture = ProtocolFixture::new();
    let mut sequence = 0u16;
    // Each round skips 100 of Alice's Messages, the most one header may skip, then has Bob reply
    // so Alice starts a new sending chain. The acknowledgment Alice returns for that reply takes
    // the chain's first key, so 100 more Messages skip 100 keys. Five rounds fill Bob's 500-key
    // cache.
    for round in 0..5u8 {
        let mut last = None;
        for _ in 0..100 {
            sequence += 1;
            let sent = alice_sends(&fixture, sequence, b"fill");
            last = Some(support::copy(&sent.message));
            let session_update = sent
                .changes
                .into_updates()
                .into_iter()
                .filter(|update| update.address().kind() == ProtocolStateKind::RatchetSession)
                .collect();
            fixture.alice.host.commit(session_update).unwrap();
        }
        let received = accepted(
            bob_receives_validated(&fixture, &fixture.bob.host, &last.unwrap(), round).unwrap(),
        );
        fixture.bob.host.commit_changes(received.changes).unwrap();
        fixture.bob_replies(round);
    }
    sequence += 1;
    let undelivered = alice_sends(&fixture, sequence, b"undelivered");
    fixture
        .alice
        .host
        .commit_changes(undelivered.changes)
        .unwrap();
    let terminal = alice_sends(&fixture, sequence + 1, b"overflow").message;

    for seed in [0xf0, 0xf1] {
        assert!(matches!(
            failure(bob_receives_validated(
                &fixture,
                &fixture.bob.host,
                &terminal,
                seed
            )),
            ProtocolStateError::Ratchet(RatchetError::MaxSkippedKeysExceeded { .. })
        ));
    }
}

#[test]
fn a_tampered_message_fails_and_the_original_still_decrypts() {
    let fixture = ProtocolFixture::new();
    let encrypted = alice_sends(&fixture, 0x70, b"valid after tamper").message;
    let mut tampered = support::copy(&encrypted);
    *tampered.ciphertext.last_mut().unwrap() ^= 0x01;

    assert!(matches!(
        failure(bob_receives_validated(
            &fixture,
            &fixture.bob.host,
            &tampered,
            0x70
        )),
        ProtocolStateError::SealedFrame(SealedFrameError::Aead)
    ));
    let decrypted =
        accepted(bob_receives_validated(&fixture, &fixture.bob.host, &encrypted, 0x71).unwrap());

    assert_eq!(decrypted.plaintext.as_slice(), b"valid after tamper");
}

#[test]
fn duplicate_received_message_does_not_load_or_advance_ratchet_state() {
    let mut fixture = ProtocolFixture::new();
    let encrypted = alice_sends(&fixture, 11, b"no duplicate effect").message;
    let decrypted =
        accepted(bob_receives_validated(&fixture, &fixture.bob.host, &encrypted, 21).unwrap());
    fixture.bob.host.commit_changes(decrypted.changes).unwrap();
    fixture
        .bob
        .host
        .set_raw(session_address(fixture.session_id), vec![2, 0, 0xaa]);

    let duplicate = bob_receives_validated(&fixture, &fixture.bob.host, &encrypted, 22).unwrap();

    assert!(matches!(duplicate, InboundMessageOutcome::Duplicate));
}

#[test]
fn blocked_inbound_message_under_unreachable_policy_suppresses_acknowledgment_without_plaintext() {
    let mut fixture = ProtocolFixture::new();
    block_alice(&mut fixture);
    let session_address = session_address(fixture.session_id);
    let deduplication_address = deduplication_address();
    let prior_session = blob(&fixture.bob.host, &session_address);
    let prior_deduplication = blob(&fixture.bob.host, &deduplication_address);
    let encrypted = alice_sends(&fixture, 0x51, b"blocked text").message;

    let blocked =
        blocked(bob_receives_validated(&fixture, &fixture.bob.host, &encrypted, 0x51).unwrap());

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
    let mut fixture = ProtocolFixture::new();
    block_alice(&mut fixture);
    let encrypted = alice_sends(&fixture, 0x54, b"blocked but receipted").message;

    let blocked = blocked(
        bob_receives(
            &fixture,
            &fixture.bob.host,
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
    let mut fixture = ProtocolFixture::new();
    block_alice(&mut fixture);
    let encrypted = alice_sends(&fixture, 0x55, b"chain advance").message;
    let receive = |policy| {
        blocked(
            bob_receives(
                &fixture,
                &fixture.bob.host,
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
    let mut fixture = ProtocolFixture::new();
    block_alice(&mut fixture);
    let encrypted = alice_sends(&fixture, 0x52, b"blocked once").message;
    let first =
        blocked(bob_receives_validated(&fixture, &fixture.bob.host, &encrypted, 0x52).unwrap());
    fixture.bob.host.commit_changes(first.changes).unwrap();
    fixture
        .bob
        .host
        .set_raw(session_address(fixture.session_id), vec![2, 0, 0xaa]);

    let duplicate = bob_receives_validated(&fixture, &fixture.bob.host, &encrypted, 0x53).unwrap();

    assert!(matches!(duplicate, InboundMessageOutcome::Duplicate));
}

#[test]
fn discovery_key_rotation_does_not_bypass_blocked_inbound_message() {
    let mut fixture = ProtocolFixture::new();
    block_alice(&mut fixture);
    let rotation = fixture.alice.store.prepare_inbox_rotation().unwrap();
    fixture
        .alice
        .store
        .reserve_operation(rotation.operation.id)
        .unwrap();
    fixture
        .alice
        .store
        .finalize_operation(rotation.operation.id)
        .unwrap();
    let encrypted = alice_sends(&fixture, 0x54, b"rotated blocked");
    assert_eq!(encrypted.payload_kind, PayloadKind::EncryptedTextWithGrant);

    let outcome =
        bob_receives_validated(&fixture, &fixture.bob.host, &encrypted.message, 0x54).unwrap();

    let InboundMessageOutcome::Blocked(blocked) = outcome else {
        panic!("expected the rotated contact's Message to stay blocked");
    };
    fixture.bob.host.commit_changes(blocked.changes).unwrap();
    let contact = fixture.bob.contact(&fixture.alice).unwrap();
    assert!(contact.blocked);
    assert_eq!(
        contact.discovery_key.unwrap().x25519_public_key,
        *rotation.output.discovery_key.public_key.as_bytes()
    );
}

#[test]
fn revoked_certificate_rejects_before_local_block_handling() {
    let mut fixture = ProtocolFixture::new();
    block_alice(&mut fixture);
    let encrypted = alice_sends(&fixture, 0x55, b"revoked blocked").message;
    let revoked = vec![alice_revoked_identity_key(&fixture)];

    let result = bob_receives(
        &fixture,
        &fixture.bob.host,
        &encrypted,
        ReceiveSettings::default(),
        validation(vec![trusted_domain_signing_key()], revoked),
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
    let fixture = ProtocolFixture::new();
    let encrypted = alice_sends(&fixture, 0x56, b"revocation unavailable").message;

    let result = bob_receives(
        &fixture,
        &fixture.bob.host,
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
    let fixture = ProtocolFixture::new();
    let encrypted = alice_sends(&fixture, 0x59, b"untrusted domain").message;
    let mut untrusted = trusted_domain_signing_key();
    untrusted.status = DomainSigningKeyStatus::Untrusted;

    let result = bob_receives(
        &fixture,
        &fixture.bob.host,
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
    let fixture = ProtocolFixture::new();
    let expired = fixture.alice.certified_until(CREATED_AT_SECS - 1);
    let encrypted = alice_sends_certified(&fixture, expired, 0x5a, b"expired domain").message;

    let result = bob_receives_validated(&fixture, &fixture.bob.host, &encrypted, 0x5a);

    assert!(matches!(
        failure(result),
        ProtocolStateError::SenderCertificateValidation(
            SenderCertificateValidationError::ExpiredCertificate
        )
    ));
}

#[test]
fn message_at_the_passed_grace_boundary_is_accepted() {
    let fixture = ProtocolFixture::new();
    let expiring = fixture
        .alice
        .certified_until(CREATED_AT_SECS - MAX_CERTIFICATE_GRACE_WINDOW.as_secs());
    let encrypted =
        alice_sends_certified(&fixture, expiring, 0x5e, b"at the grace window boundary").message;
    let settings = ReceiveSettings::new(
        DEFAULT_DEDUPLICATION_CAPACITY,
        BlockedContactAcknowledgmentPolicy::Unreachable,
        MAX_CERTIFICATE_GRACE_WINDOW,
    )
    .unwrap();

    let accepted = accepted(
        bob_receives(
            &fixture,
            &fixture.bob.host,
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
            &fixture,
            &fixture.bob.host,
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
    let fixture = ProtocolFixture::new();
    let carol = Device::new(&Relay::new(), 0x77);
    let encrypted = alice_sends_certified(
        &fixture,
        carol.certificate(),
        0x58,
        b"mismatched certificate",
    )
    .message;

    assert!(matches!(
        failure(bob_receives_validated(&fixture, &fixture.bob.host, &encrypted, 0x58)),
        ProtocolStateError::InvalidMessage { reason }
            if reason == "sender certificate identity key does not match sealed sender"
    ));
}

#[test]
fn decrypt_rejects_sender_identity_that_is_not_bound_to_session() {
    let fixture = ProtocolFixture::new();
    let carol = Device::new(&Relay::new(), 0x77);
    // Alice's Session state, but Carol's keys and sealed identity.
    let mut outgoing = fixture.outgoing(9, b"wrong sender");
    outgoing.sender_certificate = carol.certificate();
    let encrypted = support::run_encryption(
        carol.store.start_encryption(outgoing).unwrap(),
        &fixture.alice.host,
        &mut rng(9),
        &fixture.binding,
    )
    .unwrap()
    .message;

    assert!(matches!(
        failure(bob_receives_validated(&fixture, &fixture.bob.host, &encrypted, 15)),
        ProtocolStateError::InvalidMessage { reason }
            if reason == "sealed sender identity key does not match session"
    ));
}

#[test]
fn unblocked_contact_resumes_existing_session_without_new_handshake() {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new();
    block_alice(&mut fixture);
    let first = fixture.encrypt_from_alice(0x56, b"blocked before unblock");
    let blocked =
        blocked(bob_receives_validated(&fixture, &fixture.bob.host, &first.message, 0x56).unwrap());
    fixture.bob.host.commit_changes(blocked.changes).unwrap();
    let record = fixture
        .bob
        .host
        .blob_bytes(&support::device::contact_address(
            fixture.alice.identity_key(),
        ))
        .map(ProtocolStateBlob::from_bytes);
    let unblocked = engine
        .unblock_contact(fixture.alice.identity_key(), record.as_ref())
        .unwrap();
    fixture.bob.host.commit_changes(unblocked).unwrap();
    let second = fixture.encrypt_from_alice(0x57, b"after unblock");

    let accepted = accepted(
        bob_receives_validated(&fixture, &fixture.bob.host, &second.message, 0x57).unwrap(),
    );

    assert_eq!(accepted.session_id, fixture.session_id);
    assert_eq!(accepted.plaintext.as_slice(), b"after unblock");
}

#[test]
fn in_band_messages_and_acknowledgments_do_not_verify_contact() {
    let mut fixture = ProtocolFixture::new();
    let trust = |device: &Device, peer: &Device| device.contact(peer).unwrap().trust_state;
    assert_eq!(
        trust(&fixture.alice, &fixture.bob),
        ContactTrustState::Unverified
    );

    let encrypted = fixture.encrypt_from_alice(12, b"in band is not verification");
    let decrypted = fixture.decrypt_for_bob(&encrypted, 23);
    assert_eq!(
        trust(&fixture.bob, &fixture.alice),
        ContactTrustState::Unverified
    );

    let InboundMessageOutcome::AcknowledgmentMatched(cleared) = fixture
        .alice_receives(&decrypted.acknowledgment, 24)
        .unwrap()
    else {
        panic!("acknowledgment did not clear pending state");
    };
    fixture.alice.host.commit_changes(cleared.changes).unwrap();

    assert_eq!(
        trust(&fixture.alice, &fixture.bob),
        ContactTrustState::Unverified
    );
}

#[test]
fn deduplication_receive_rejects_bad_state() {
    let fixture = ProtocolFixture::new();
    let deduplication_address = deduplication_address();
    let encrypted = alice_sends(&fixture, 12, b"bad dedup state").message;
    let receive =
        |store: &HostStore, seed: u8| bob_receives_validated(&fixture, store, &encrypted, seed);

    let mut corrupt = fixture.bob.host.clone();
    corrupt.set_raw(deduplication_address.clone(), vec![2, 0, 0xaa]);
    assert!(matches!(
        failure(receive(&corrupt, 24)),
        ProtocolStateError::BlobDecode { address, .. } if address == deduplication_address
    ));

    let mut unsupported = fixture.bob.host.clone();
    unsupported.set_raw(deduplication_address.clone(), vec![3, 0, 0xaa]);
    assert!(matches!(
        failure(receive(&unsupported, 25)),
        ProtocolStateError::UnsupportedBlobVersion { address, version: 3 }
            if address == deduplication_address
    ));
}

#[test]
fn deduplication_capacity_evicts_oldest_digest_first() {
    let mut fixture = ProtocolFixture::new();
    let smallest = ReceiveSettings::new(
        MIN_DEDUPLICATION_CAPACITY,
        BlockedContactAcknowledgmentPolicy::Unreachable,
        Duration::ZERO,
    )
    .unwrap();
    fixture.bob.host.remove(&deduplication_address());
    let mut first_message = None;

    for index in 0..=MIN_DEDUPLICATION_CAPACITY {
        let encrypted = fixture.encrypt_from_alice(index as u16 + 1, b"fills window");
        let received = accepted(
            bob_receives(
                &fixture,
                &fixture.bob.host,
                &encrypted.message,
                smallest,
                trusted_validation(),
                26,
            )
            .unwrap(),
        );
        fixture.bob.host.commit_changes(received.changes).unwrap();
        first_message.get_or_insert(encrypted.message);
    }

    let result = bob_receives(
        &fixture,
        &fixture.bob.host,
        &first_message.unwrap(),
        smallest,
        trusted_validation(),
        27,
    );

    assert!(matches!(failure(result), ProtocolStateError::Ratchet(_)));
}

#[test]
fn tampered_ciphertext_exposes_no_sender_identity() {
    let fixture = ProtocolFixture::new();
    let mut encrypted = alice_sends(&fixture, 3, b"secret").message;
    *encrypted.ciphertext.last_mut().unwrap() ^= 0x01;

    let result = bob_receives_validated(&fixture, &fixture.bob.host, &encrypted, 13);

    assert!(matches!(
        failure(result),
        ProtocolStateError::SealedFrame(_)
    ));
}

#[test]
fn tampered_transport_metadata_exposes_no_sender_identity() {
    let fixture = ProtocolFixture::new();
    let encrypted = alice_sends(&fixture, 5, b"metadata-bound").message;
    let mut wrong_recipient = support::copy(&encrypted);
    wrong_recipient.recipient_public_key = *fixture.alice.discovery_key().public_key().as_bytes();
    let mut wrong_ephemeral = support::copy(&encrypted);
    wrong_ephemeral.ephemeral_public_key =
        *KeyPair::from_secret_bytes([0x55; 32]).public.as_bytes();

    for message in [wrong_recipient, wrong_ephemeral] {
        let result = bob_receives_validated(&fixture, &fixture.bob.host, &message, 16);
        assert!(matches!(
            failure(result),
            ProtocolStateError::SealedFrame(_)
        ));
    }
}

#[test]
fn large_valid_outbound_message_persists_pending_acknowledgment() {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new();
    let large_plaintext = vec![0u8; 65_180];

    let result = alice_sends(&fixture, 1, &large_plaintext);
    assert!(result.message.to_bytes().unwrap().len() > 64 * 1024);
    let message_id = result.message_id;
    fixture.alice.host.commit_changes(result.changes).unwrap();

    let pending = engine
        .pending_acknowledgments(&fixture.alice.host.snapshot(), fixture.session_id)
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].message_id, message_id);
}

#[test]
fn oversized_outbound_message_does_not_return_advanced_state() {
    let fixture = ProtocolFixture::new();
    let before = fixture.alice.host.snapshot_bytes();

    let result = fixture.encrypt(
        &fixture.alice.host,
        fixture.outgoing(1, &[0u8; 64 * 1024]),
        1,
    );

    assert!(matches!(
        failure(result),
        ProtocolStateError::InvalidMessage { .. }
    ));
    assert_eq!(fixture.alice.host.snapshot_bytes(), before);
}

#[test]
fn oversized_or_corrupt_session_blob_is_a_decode_fault_without_reinitialization() {
    let fixture = ProtocolFixture::new();
    let address = session_address(fixture.session_id);
    for stored in [vec![1; 128 * 1024], vec![2, 0, 0xaa]] {
        let mut alice_store = fixture.alice.host.clone();
        alice_store.set_raw(address.clone(), stored.clone());

        let result = fixture.encrypt(&alice_store, fixture.outgoing(1, b"lost"), 1);

        assert!(matches!(
            failure(result),
            ProtocolStateError::BlobDecode { address: actual, .. } if actual == address
        ));
        assert_eq!(blob(&alice_store, &address), stored);
    }
}

#[test]
fn missing_required_state_is_an_explicit_failure() {
    let fixture = ProtocolFixture::new();
    let address = pending_address(fixture.session_id);
    let mut alice_store = fixture.alice.host.clone();
    alice_store.remove(&address);

    assert!(matches!(
        failure(fixture.encrypt(&alice_store, fixture.outgoing(1, b"lost"), 1)),
        ProtocolStateError::MissingRequiredState { address: actual } if actual == address
    ));
}
