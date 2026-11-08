//! Exercises the public protocol-state API over opaque blobs the app holds.

use crate::support::device::{Decrypted, Device, Relay, Sealed, run_encryption};
use crate::support::{
    AppDatabase, CREATED_AT_SECS, ProtocolFixture, TEST_RELAY_DOMAIN, accepted,
    trusted_domain_signing_key, trusted_validation, validation,
};
use rand::SeedableRng;
use rand::rngs::OsRng;
use rand_chacha::ChaCha20Rng;
use roost_core::{
    BlockedContactAcknowledgmentPolicy, ContactTrustState, InboundMessageOutcome,
    MessageOperationError, MessageStartError, ProtocolHardeningLimits, ProtocolStateAddress,
    ProtocolStateError, ProtocolStateKind, ReceiveSettings, RevocationState, SealedFrame,
    SenderCertificateValidation, SignedSenderCertificate,
};
use roost_crypto::{KeyPair, RatchetError, SealedFrameError};
use roost_protocol::{
    MAX_CERTIFICATE_GRACE_WINDOW, PayloadKind, SenderCertificateValidationError, from_unix_secs,
};
use std::time::Duration;

fn rng(seed: u8) -> ChaCha20Rng {
    ChaCha20Rng::from_seed([seed; 32])
}

// Alice encrypts on the fixture's session without committing.
fn alice_sends(fixture: &ProtocolFixture, sequence: u16, plaintext: &[u8]) -> Sealed {
    fixture
        .encrypt(
            &fixture.alice.database,
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
) -> Sealed {
    let mut outgoing = fixture.outgoing(sequence, plaintext);
    outgoing.sender_certificate = certificate;
    fixture
        .encrypt(&fixture.alice.database, outgoing, sequence as u8)
        .unwrap()
}

// Bob receives `message` over `store` with the given settings and certificate validation inputs.
fn bob_receives(
    fixture: &ProtocolFixture,
    store: &AppDatabase,
    message: &SealedFrame,
    settings: ReceiveSettings,
    sender_certificate_validation: SenderCertificateValidation,
    seed: u8,
) -> Result<Decrypted, MessageOperationError> {
    fixture.decrypt(
        store,
        fixture.incoming(message, settings, sender_certificate_validation),
        seed,
    )
}

// Bob receives `message` with default settings, the trusted domain, and no revocations.
fn bob_receives_validated(
    fixture: &ProtocolFixture,
    store: &AppDatabase,
    message: &SealedFrame,
    seed: u8,
) -> Result<Decrypted, MessageOperationError> {
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
    ReceiveSettings::new(
        ProtocolHardeningLimits::default().default_deduplication_capacity,
        policy,
        Duration::ZERO,
    )
    .unwrap()
}

fn blocked(outcome: InboundMessageOutcome) -> roost_core::BlockedInboundMessageResult {
    let InboundMessageOutcome::Blocked(result) = outcome else {
        panic!("message was not blocked")
    };
    *result
}

// Has Bob block Alice. The block rotates Bob's inbox, so Alice reaches him again only by requesting
// on his new prekeys, which starts the fixture's new session. Returns the address of the record Bob
// keeps for that session.
fn block_alice(fixture: &mut ProtocolFixture) -> ProtocolStateAddress {
    fixture.bob.block(fixture.alice.identity_key());
    fixture.alice.forget_sessions_with(&fixture.bob);
    let request = fixture.alice.request(&fixture.bob, b"after the block");
    let older = fixture
        .bob
        .database
        .addresses(ProtocolStateKind::RatchetSession);
    blocked(fixture.bob.receive(&request.message));
    fixture.session_id = request.session_id;
    fixture
        .bob
        .database
        .addresses(ProtocolStateKind::RatchetSession)
        .into_iter()
        .find(|address| !older.contains(address))
        .expect("the request starts a session")
}

fn blob(store: &AppDatabase, address: &ProtocolStateAddress) -> Vec<u8> {
    store.blob_bytes(address).unwrap()
}

#[test]
fn sealed_sender_round_trip_hides_sender_identity_until_decrypt() {
    let fixture = ProtocolFixture::new();
    let encrypted = alice_sends(&fixture, 8, b"sealed sender").result;
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
        bob_receives_validated(&fixture, &fixture.bob.database, &encrypted.message, 12)
            .unwrap()
            .outcome,
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
    let encrypted = alice_sends(&fixture, 0x42, b"hidden metadata").result;

    assert_eq!(
        encrypted.message.recipient_public_key,
        *fixture
            .bob
            .publication()
            .discovery_key
            .public_key
            .as_bytes(),
        "only recipient routing key remains visible"
    );
    assert!(encrypted.message.prekey_reference.is_none());
    assert_ne!(encrypted.message.ephemeral_public_key, [0u8; 32]);
    assert!(!encrypted.message.ciphertext.is_empty());

    let decrypted = accepted(
        bob_receives_validated(&fixture, &fixture.bob.database, &encrypted.message, 0x42)
            .unwrap()
            .outcome,
    );

    assert_eq!(decrypted.message_id, encrypted.message_id);
    assert_eq!(decrypted.sent_at_millis, 1_700_000_300_000 + 0x42);
    assert_eq!(decrypted.payload_kind, PayloadKind::Content);
    assert_eq!(decrypted.plaintext.as_slice(), b"hidden metadata");
}

#[test]
fn accepted_message_generates_encrypted_acknowledgment_that_clears_pending_state() {
    let mut fixture = ProtocolFixture::new();
    let engine = *fixture.alice.store.protocol_engine();
    let encrypted = alice_sends(&fixture, 0x31, b"ack me");
    let message_id = encrypted.result.message_id;
    let message = encrypted.result.message;
    fixture.alice.database.commit(encrypted.changes).unwrap();
    let pending = engine
        .pending_acknowledgments(
            fixture.session_id,
            fixture
                .alice
                .database
                .pending_acknowledgments_record(fixture.session_id)
                .as_ref(),
        )
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].message_id, message_id);

    let decrypted = accepted(
        bob_receives_validated(&fixture, &fixture.bob.database, &message, 0x31)
            .unwrap()
            .outcome,
    );
    assert_eq!(decrypted.plaintext.as_slice(), b"ack me");
    let acknowledgment = decrypted.acknowledgment.unwrap();
    assert!(acknowledgment.prekey_reference.is_none());
    let encoded_ack = acknowledgment.to_bytes().unwrap();
    assert!(
        !encoded_ack
            .windows(message_id.as_bytes().len())
            .any(|window| window == message_id.as_bytes())
    );

    let process = |store: &AppDatabase, seed: u8| {
        fixture
            .alice_receives_over(store, &acknowledgment, seed)
            .unwrap()
    };
    let processed = process(&fixture.alice.database, 0x41);
    let InboundMessageOutcome::AcknowledgmentMatched(cleared) = processed.outcome else {
        panic!("acknowledgment did not clear pending state");
    };
    assert_eq!(cleared.session_id, fixture.session_id);
    assert_eq!(cleared.acknowledged_message_id, message_id);
    assert_eq!(
        cleared.sender_identity.identity_key,
        *fixture.bob.identity.public_key.as_bytes()
    );
    let mut alice_store = fixture.alice.database.clone();
    alice_store.commit(processed.changes).unwrap();
    assert!(
        engine
            .pending_acknowledgments(
                fixture.session_id,
                alice_store
                    .pending_acknowledgments_record(fixture.session_id)
                    .as_ref()
            )
            .unwrap()
            .is_empty()
    );
    for seed in 0x42..0x47 {
        assert!(matches!(
            process(&alice_store, seed).outcome,
            InboundMessageOutcome::Duplicate
        ));
    }
}

#[test]
fn pending_acknowledgment_state_faults_on_bad_blobs() {
    let fixture = ProtocolFixture::new();
    let address = fixture
        .alice
        .database
        .only(ProtocolStateKind::PendingAcknowledgments);
    let mut corrupt = fixture.alice.database.clone();
    corrupt.corrupt(&address);

    assert!(matches!(
        failure(fixture.encrypt(
            &corrupt,
            fixture.outgoing(0x34, b"corrupt pending"),
            0x34,
        )),
        ProtocolStateError::BlobDecode { address: actual, .. } if actual == address
    ));
}

#[test]
fn oversized_inbound_message_rejects_before_any_read() {
    let fixture = ProtocolFixture::new();
    let mut oversized = alice_sends(&fixture, 0x36, b"oversized").result.message;
    oversized.ciphertext = vec![0; SealedFrame::MAX_CIPHERTEXT_LEN + 1];

    let result = fixture.bob.store.start_decryption(fixture.incoming(
        &oversized,
        ReceiveSettings::default(),
        trusted_validation(),
    ));

    assert!(matches!(
        result,
        Err(MessageStartError::ProtocolState(ProtocolStateError::SealedFrame(
            SealedFrameError::CiphertextTooLong { len, max }
        ))) if len == max + 1
    ));
}

#[test]
fn oversized_sender_certificate_is_refused_before_sealing() {
    let fixture = ProtocolFixture::new();
    let limits = ProtocolHardeningLimits::default();
    let mut outgoing = fixture.outgoing(0x39, b"certificate limit");
    outgoing.sender_certificate = SignedSenderCertificate {
        certificate: vec![0; limits.max_sender_certificate_len + 1],
        signature: fixture.alice.certificate().signature,
    };

    let result = fixture.alice.store.start_encryption(outgoing);

    assert!(matches!(
        result,
        Err(MessageStartError::ProtocolState(
            ProtocolStateError::InvalidMessage { reason }
        )) if reason == format!(
            "sender certificate length exceeds limit: {}",
            limits.max_sender_certificate_len + 1
        )
    ));
}

#[test]
fn unique_received_message_is_accepted_recorded_and_emitted_once() {
    let mut fixture = ProtocolFixture::new();
    let session_address = fixture.bob.database.only(ProtocolStateKind::RatchetSession);
    let deduplication_address = fixture
        .bob
        .database
        .only(ProtocolStateKind::DeduplicationSet);
    let prior_session = blob(&fixture.bob.database, &session_address);
    let prior_deduplication = blob(&fixture.bob.database, &deduplication_address);
    let encrypted = alice_sends(&fixture, 10, b"accept once").result.message;

    let received = bob_receives_validated(&fixture, &fixture.bob.database, &encrypted, 19).unwrap();

    assert_eq!(
        accepted(received.outcome).plaintext.as_slice(),
        b"accept once"
    );
    let updates = fixture.bob.database.commit(received.changes).unwrap();
    assert_eq!(updates.len(), 2);
    assert_eq!(updates[0].address(), &session_address);
    assert_eq!(updates[1].address(), &deduplication_address);
    assert_ne!(updates[0].blob().unwrap().as_bytes(), prior_session);
    assert_ne!(updates[1].blob().unwrap().as_bytes(), prior_deduplication);

    let duplicate =
        bob_receives_validated(&fixture, &fixture.bob.database, &encrypted, 20).unwrap();
    assert!(matches!(
        duplicate.outcome,
        InboundMessageOutcome::Duplicate
    ));
}

#[test]
fn skipped_key_total_overflow_rejects_the_message_on_every_attempt() {
    let mut fixture = ProtocolFixture::new();
    let mut sequence = 0u16;
    // Each round skips 100 of Alice's messages, the most one header may skip, then has Bob reply
    // so Alice starts a new sending chain. The acknowledgment Alice returns for that reply takes
    // the chain's first key, so 100 more messages skip 100 keys. Five rounds fill Bob's 500-key
    // cache.
    for round in 0..5u8 {
        let mut last = None;
        for _ in 0..100 {
            sequence += 1;
            let sent = alice_sends(&fixture, sequence, b"fill");
            last = Some(sent.result.message);
            let session_update: Vec<_> = sent
                .changes
                .into_updates()
                .into_iter()
                .filter(|update| update.address().kind() == ProtocolStateKind::RatchetSession)
                .collect();
            fixture.alice.database.apply_all(&session_update);
        }
        let received =
            bob_receives_validated(&fixture, &fixture.bob.database, &last.unwrap(), round).unwrap();
        accepted(received.outcome);
        fixture.bob.database.commit(received.changes).unwrap();
        fixture.bob_replies(round);
    }
    sequence += 1;
    let undelivered = alice_sends(&fixture, sequence, b"undelivered");
    fixture.alice.database.commit(undelivered.changes).unwrap();
    let terminal = alice_sends(&fixture, sequence + 1, b"overflow")
        .result
        .message;

    for seed in [0xf0, 0xf1] {
        assert!(matches!(
            failure(bob_receives_validated(
                &fixture,
                &fixture.bob.database,
                &terminal,
                seed
            )),
            ProtocolStateError::Ratchet(RatchetError::MaxSkippedKeysExceeded { max: 500 })
        ));
    }
}

#[test]
fn a_tampered_message_fails_and_the_original_still_decrypts() {
    let fixture = ProtocolFixture::new();
    let encrypted = alice_sends(&fixture, 0x70, b"valid after tamper")
        .result
        .message;
    let mut tampered = encrypted.clone();
    *tampered.ciphertext.last_mut().unwrap() ^= 0x01;

    assert!(matches!(
        failure(bob_receives_validated(
            &fixture,
            &fixture.bob.database,
            &tampered,
            0x70
        )),
        ProtocolStateError::SealedFrame(SealedFrameError::Aead)
    ));
    let decrypted = accepted(
        bob_receives_validated(&fixture, &fixture.bob.database, &encrypted, 0x71)
            .unwrap()
            .outcome,
    );

    assert_eq!(decrypted.plaintext.as_slice(), b"valid after tamper");
}

#[test]
fn a_blocked_message_hides_its_plaintext_and_is_acknowledged_only_under_the_acknowledge_policy() {
    let mut fixture = ProtocolFixture::new();
    let session_address = block_alice(&mut fixture);
    let deduplication_address = fixture
        .bob
        .database
        .only(ProtocolStateKind::DeduplicationSet);
    let prior_session = blob(&fixture.bob.database, &session_address);
    let prior_deduplication = blob(&fixture.bob.database, &deduplication_address);
    let encrypted = alice_sends(&fixture, 0x55, b"blocked text").result.message;
    let receive = |policy| {
        let received = bob_receives(
            &fixture,
            &fixture.bob.database,
            &encrypted,
            settings_with_policy(policy),
            trusted_validation(),
            0x55,
        )
        .unwrap();
        let updates = fixture
            .bob
            .database
            .clone()
            .commit(received.changes)
            .unwrap();
        (blocked(received.outcome).acknowledgment, updates)
    };

    let (suppressed, suppressed_updates) = receive(BlockedContactAcknowledgmentPolicy::Unreachable);
    let (acknowledged, acknowledged_updates) =
        receive(BlockedContactAcknowledgmentPolicy::Acknowledge);

    assert!(suppressed.is_none());
    assert!(acknowledged.unwrap().prekey_reference.is_none());
    for updates in [&suppressed_updates, &acknowledged_updates] {
        assert_eq!(updates.len(), 2);
        assert_eq!(updates[0].address(), &session_address);
        assert_eq!(updates[1].address(), &deduplication_address);
        assert_ne!(updates[0].blob().unwrap().as_bytes(), prior_session);
        assert_ne!(updates[1].blob().unwrap().as_bytes(), prior_deduplication);
    }
    // The acknowledgment advances the sending chain, so only the acknowledge policy changes it
    // further.
    assert_ne!(
        suppressed_updates[0].blob().unwrap().as_bytes(),
        acknowledged_updates[0].blob().unwrap().as_bytes(),
    );
}

#[test]
fn discovery_key_rotation_does_not_bypass_blocked_inbound_message() {
    let mut fixture = ProtocolFixture::new();
    block_alice(&mut fixture);
    let rotation = fixture
        .alice
        .store
        .prepare_inbox_rotation(&mut OsRng)
        .unwrap();
    fixture.alice.store.reserve_operation(rotation.id).unwrap();
    fixture.alice.store.finalize_operation(rotation.id).unwrap();
    let encrypted = alice_sends(&fixture, 0x54, b"rotated blocked").result;
    assert_eq!(encrypted.payload_kind, PayloadKind::ContentWithGrant);

    let received =
        bob_receives_validated(&fixture, &fixture.bob.database, &encrypted.message, 0x54).unwrap();

    let InboundMessageOutcome::Blocked(_) = received.outcome else {
        panic!("expected the rotated contact's message to stay blocked");
    };
    fixture.bob.database.commit(received.changes).unwrap();
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
    let encrypted = alice_sends(&fixture, 0x55, b"revoked blocked")
        .result
        .message;
    let revoked = vec![fixture.alice.identity_key()];

    let result = bob_receives(
        &fixture,
        &fixture.bob.database,
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
fn a_certificate_that_fails_validation_rejects_before_plaintext_is_surfaced() {
    let fixture = ProtocolFixture::new();
    let unavailable_revocations = SenderCertificateValidation::new(
        vec![trusted_domain_signing_key()],
        TEST_RELAY_DOMAIN.to_vec(),
        RevocationState::Unavailable,
        from_unix_secs(CREATED_AT_SECS).unwrap(),
    )
    .unwrap();
    let cases = [
        (
            fixture.alice.certificate(),
            unavailable_revocations,
            SenderCertificateValidationError::RevocationStateUnavailable,
        ),
        (
            fixture.alice.certificate(),
            validation(Vec::new(), Vec::new()),
            SenderCertificateValidationError::UnknownSigningKeyId,
        ),
        (
            fixture.alice.certified_until(CREATED_AT_SECS - 1),
            trusted_validation(),
            SenderCertificateValidationError::ExpiredCertificate,
        ),
    ];

    for (sequence, (certificate, validation, expected)) in (0x56..).zip(cases) {
        let encrypted = alice_sends_certified(&fixture, certificate, sequence, b"never shown")
            .result
            .message;

        let result = bob_receives(
            &fixture,
            &fixture.bob.database,
            &encrypted,
            ReceiveSettings::default(),
            validation,
            sequence as u8,
        );

        assert!(matches!(
            failure(result),
            ProtocolStateError::SenderCertificateValidation(error) if error == expected
        ));
    }
}

#[test]
fn message_at_the_passed_grace_boundary_is_accepted() {
    let fixture = ProtocolFixture::new();
    let expiring = fixture
        .alice
        .certified_until(CREATED_AT_SECS - MAX_CERTIFICATE_GRACE_WINDOW.as_secs());
    let encrypted =
        alice_sends_certified(&fixture, expiring, 0x5e, b"at the grace window boundary")
            .result
            .message;
    let settings = ReceiveSettings::new(
        ProtocolHardeningLimits::default().default_deduplication_capacity,
        BlockedContactAcknowledgmentPolicy::Unreachable,
        MAX_CERTIFICATE_GRACE_WINDOW,
    )
    .unwrap();

    let accepted = accepted(
        bob_receives(
            &fixture,
            &fixture.bob.database,
            &encrypted,
            settings,
            trusted_validation(),
            0x5e,
        )
        .unwrap()
        .outcome,
    );

    assert_eq!(
        accepted.plaintext.as_slice(),
        b"at the grace window boundary"
    );
    assert!(matches!(
        failure(bob_receives_validated(
            &fixture,
            &fixture.bob.database,
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
    .result
    .message;

    assert!(matches!(
        failure(bob_receives_validated(&fixture, &fixture.bob.database, &encrypted, 0x58)),
        ProtocolStateError::InvalidMessage { reason }
            if reason == "sender certificate identity key does not match sealed sender"
    ));
}

#[test]
fn decrypt_rejects_sender_identity_that_is_not_bound_to_session() {
    let fixture = ProtocolFixture::new();
    let carol = Device::new(&Relay::new(), 0x77);
    // Alice's session state, but Carol's keys and sealed identity.
    let mut outgoing = fixture.outgoing(9, b"wrong sender");
    outgoing.sender_certificate = carol.certificate();
    let encrypted = run_encryption(
        carol.store.start_encryption(outgoing).unwrap(),
        &fixture.alice.database,
        &mut rng(9),
        &fixture.binding,
    )
    .unwrap()
    .ready()
    .result
    .message;

    assert!(matches!(
        failure(bob_receives_validated(&fixture, &fixture.bob.database, &encrypted, 15)),
        ProtocolStateError::InvalidMessage { reason }
            if reason == "sealed sender identity key does not match session"
    ));
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

    let processed = fixture
        .alice_receives(&decrypted.acknowledgment, 24)
        .unwrap();
    assert!(
        matches!(
            processed.outcome,
            InboundMessageOutcome::AcknowledgmentMatched(_)
        ),
        "acknowledgment did not clear pending state"
    );
    fixture.alice.database.commit(processed.changes).unwrap();

    assert_eq!(
        trust(&fixture.alice, &fixture.bob),
        ContactTrustState::Unverified
    );
}

#[test]
fn deduplication_capacity_evicts_oldest_digest_first() {
    let mut fixture = ProtocolFixture::new();
    let smallest = ReceiveSettings::new(
        ProtocolHardeningLimits::default().min_deduplication_capacity,
        BlockedContactAcknowledgmentPolicy::Unreachable,
        Duration::ZERO,
    )
    .unwrap();
    fixture.bob.forget_received_digests();
    let mut first_message = None;

    for index in 0..=ProtocolHardeningLimits::default().min_deduplication_capacity {
        let encrypted = fixture.encrypt_from_alice(index as u16 + 1, b"fills window");
        let received = bob_receives(
            &fixture,
            &fixture.bob.database,
            &encrypted.message,
            smallest,
            trusted_validation(),
            26,
        )
        .unwrap();
        accepted(received.outcome);
        fixture.bob.database.commit(received.changes).unwrap();
        first_message.get_or_insert(encrypted.message);
    }

    let result = bob_receives(
        &fixture,
        &fixture.bob.database,
        &first_message.unwrap(),
        smallest,
        trusted_validation(),
        27,
    );

    assert!(matches!(
        failure(result),
        ProtocolStateError::Ratchet(RatchetError::Aead)
    ));
}

#[test]
fn tampered_transport_metadata_exposes_no_sender_identity() {
    let fixture = ProtocolFixture::new();
    let encrypted = alice_sends(&fixture, 5, b"metadata-bound").result.message;
    let mut wrong_recipient = encrypted.clone();
    wrong_recipient.recipient_public_key = *fixture
        .alice
        .publication()
        .discovery_key
        .public_key
        .as_bytes();
    let mut wrong_ephemeral = encrypted.clone();
    wrong_ephemeral.ephemeral_public_key =
        *KeyPair::from_secret_bytes(&[0x55; 32]).public.as_bytes();

    for message in [wrong_recipient, wrong_ephemeral] {
        let result = bob_receives_validated(&fixture, &fixture.bob.database, &message, 16);
        assert!(matches!(
            failure(result),
            ProtocolStateError::SealedFrame(_)
        ));
    }
}

#[test]
fn oversized_outbound_message_does_not_return_advanced_state() {
    let fixture = ProtocolFixture::new();
    let before = fixture.alice.database.snapshot_bytes();

    let result = fixture.encrypt(
        &fixture.alice.database,
        fixture.outgoing(1, &[0u8; 64 * 1024]),
        1,
    );

    assert!(matches!(
        failure(result),
        ProtocolStateError::ContentTooLong { len, max } if len > max
    ));
    assert_eq!(fixture.alice.database.snapshot_bytes(), before);
}

#[test]
fn oversized_or_corrupt_session_blob_is_a_decode_fault_without_reinitialization() {
    let fixture = ProtocolFixture::new();
    let address = fixture
        .alice
        .database
        .only(ProtocolStateKind::RatchetSession);
    let mut torn = blob(&fixture.alice.database, &address);
    torn.pop();
    let oversized = vec![1; ProtocolHardeningLimits::default().max_protocol_state_blob_len + 1];
    for stored in [oversized, torn] {
        let mut alice_store = fixture.alice.database.clone();
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
    let address = fixture.alice.database.only(ProtocolStateKind::ContactState);
    let mut alice_store = fixture.alice.database.clone();
    alice_store.remove(&address);
    assert!(matches!(
        failure(fixture.encrypt(&alice_store, fixture.outgoing(1, b"lost"), 1)),
        ProtocolStateError::MissingRequiredState { address: actual } if actual == address
    ));
}
