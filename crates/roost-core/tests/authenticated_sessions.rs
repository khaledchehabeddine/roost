//! Sessions that two Devices establish through real X3DH and find again by SessionID.

mod support;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use roost_core::{
    AcknowledgmentOutcome, HandshakeError, InboundMessageOutcome, InboundSessionStart, LocalSender,
    Message, MessageOperationError, OutboundSessionStart, PreKeyBundle, ProtocolStateEngine,
    ProtocolStateError, ProtocolStateKey, PublicKeyError, SessionAcceptanceOutcome,
    SessionEstablishmentError, SessionId,
};
use roost_crypto::{
    RatchetError, SealedFrameError, open_frame_for_discovery_key_with_associated_data,
    seal_frame_with_associated_data,
};
use roost_protocol::{MessageId, SenderCertificateValidationError, SignatureError};
use support::device::{Device, Relay};
use support::{
    CREATED_AT_SECS, ProtocolFixture, TestIdentity, dead_session_blob, session_address,
    validated_sender, validation,
};

fn accepted_session(outcome: SessionAcceptanceOutcome) -> roost_core::SessionAcceptanceResult {
    let SessionAcceptanceOutcome::Accepted(result) = outcome else {
        panic!("expected an accepted Session")
    };
    *result
}

fn accepted_message(outcome: InboundMessageOutcome) -> roost_core::InboundMessageResult {
    let InboundMessageOutcome::Accepted(result) = outcome else {
        panic!("expected an accepted Message")
    };
    *result
}

fn befriend(first: &mut Device<'_>, second: &mut Device<'_>) {
    first.accept_contact(second);
    second.accept_contact(first);
}

// Starts a Session from `initiator`, has `responder` accept it and reply, and returns its ID.
fn establish(initiator: &mut Device<'_>, responder: &mut Device<'_>) -> SessionId {
    let bundle = responder.bundle();
    let initiation = initiator.initiate(&bundle, b"hello");
    accepted_session(responder.accept(&initiation.message, bundle.selection));
    let reply = responder.send(initiator, b"reply");
    accepted_message(initiator.receive(&reply.message));
    initiation.session_id
}

#[test]
fn peers_derive_one_session_id_and_exchange_messages_both_ways() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    let bob_bundle = bob.bundle();

    let initiation = alice.initiate(&bob_bundle, b"hello bob");
    assert!(matches!(
        bob.receive(&initiation.message),
        InboundMessageOutcome::UnknownSession
    ));
    let accepted = accepted_session(bob.accept(&initiation.message, bob_bundle.selection));

    assert_eq!(accepted.session_id, initiation.session_id);
    assert_eq!(&*accepted.plaintext, b"hello bob");
    assert_eq!(accepted.contact, alice.contact_identity());

    bob.accept_contact(&alice);
    let reply = bob.send(&alice, b"hello alice");
    assert_eq!(reply.session_id, initiation.session_id);
    let received = accepted_message(alice.receive(&reply.message));
    assert_eq!(received.session_id, initiation.session_id);
    assert_eq!(&*received.plaintext, b"hello alice");

    alice.accept_contact(&bob);
    let follow_up = alice.send(&bob, b"how are you");
    assert_eq!(follow_up.session_id, initiation.session_id);
    let received = accepted_message(bob.receive(&follow_up.message));
    assert_eq!(&*received.plaintext, b"how are you");
}

#[test]
fn any_message_before_the_first_reply_can_start_the_session() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    befriend(&mut alice, &mut bob);
    let bundle = bob.bundle();
    let first = alice.initiate(&bundle, b"first");
    let second = alice.send(&bob, b"second");
    assert_eq!(second.session_id, first.session_id);
    assert_eq!(
        second.message.prekey_reference,
        first.message.prekey_reference
    );

    // The first Message is late, so the second one starts the Session.
    assert!(matches!(
        bob.receive(&second.message),
        InboundMessageOutcome::UnknownSession
    ));
    let accepted = accepted_session(bob.accept(&second.message, bundle.selection));
    assert_eq!(accepted.session_id, first.session_id);
    assert_eq!(&*accepted.plaintext, b"second");
    let late = accepted_message(bob.receive(&first.message));
    assert_eq!(late.session_id, first.session_id);
    assert_eq!(&*late.plaintext, b"first");

    let reply = bob.send(&alice, b"reply");
    accepted_message(alice.receive(&reply.message));
    let after_reply = alice.send(&bob, b"after reply");
    assert!(after_reply.message.prekey_reference.is_none());
    let received = accepted_message(bob.receive(&after_reply.message));
    assert_eq!(&*received.plaintext, b"after reply");
}

#[test]
fn a_message_naming_an_unknown_session_changes_nothing() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    befriend(&mut alice, &mut bob);
    let session_id = establish(&mut alice, &mut bob);
    let ordinary = alice.send(&bob, b"to a session bob lost");
    let reply = bob.send(&alice, b"needs an acknowledgment");
    let acknowledgment = accepted_message(alice.receive(&reply.message)).acknowledgment;
    for device in [&mut alice, &mut bob] {
        let key = ProtocolStateKey::from_bytes(session_id.as_bytes().to_vec()).unwrap();
        let wipe = device
            .store
            .protocol_engine()
            .wipe(&device.host.snapshot(), key);
        device.host.commit(wipe).unwrap();
    }
    let before = bob.host.snapshot_bytes();

    assert!(matches!(
        bob.receive(&ordinary.message),
        InboundMessageOutcome::UnknownSession
    ));
    assert!(matches!(
        bob.process_acknowledgment(&acknowledgment),
        AcknowledgmentOutcome::UnknownSession
    ));
    assert_eq!(bob.host.snapshot_bytes(), before);
}

#[test]
fn a_first_message_delivered_twice_is_a_duplicate() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    let bundle = bob.bundle_without_one_time_prekey();
    let initiation = alice.initiate(&bundle, b"once");
    accepted_session(bob.accept(&initiation.message, bundle.selection));
    let before = bob.host.snapshot_bytes();

    assert!(matches!(
        bob.receive(&initiation.message),
        InboundMessageOutcome::Duplicate
    ));
    assert!(matches!(
        bob.accept(&initiation.message, bundle.selection),
        SessionAcceptanceOutcome::Duplicate
    ));
    assert_eq!(bob.host.snapshot_bytes(), before);
}

#[test]
fn a_handshake_never_replaces_a_session_it_names() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    befriend(&mut alice, &mut bob);
    let bundle = bob.bundle_without_one_time_prekey();
    let first = alice.initiate(&bundle, b"first");
    let second = alice.send(&bob, b"second");
    accepted_session(bob.accept(&first.message, bundle.selection));
    let before = bob.host.snapshot_bytes();

    assert!(matches!(
        bob.prepare_accept(&second.message, bundle.selection),
        Err(SessionEstablishmentError::ProtocolState(
            ProtocolStateError::InvalidMessage { reason }
        )) if reason == "message names a session this identity already has"
    ));
    assert_eq!(bob.host.snapshot_bytes(), before);
    let received = accepted_message(bob.receive(&second.message));
    assert_eq!(received.session_id, first.session_id);
}

#[test]
fn simultaneous_starts_converge_on_the_lower_session_id() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    befriend(&mut alice, &mut bob);
    let alice_bundle = alice.bundle();
    let bob_bundle = bob.bundle();
    let from_alice = alice.initiate(&bob_bundle, b"from alice");
    let from_bob = bob.initiate(&alice_bundle, b"from bob");

    accepted_session(bob.accept(&from_alice.message, bob_bundle.selection));
    accepted_session(alice.accept(&from_bob.message, alice_bundle.selection));

    let lower = from_alice.session_id.min(from_bob.session_id);
    let alice_next = alice.send(&bob, b"alice next");
    let bob_next = bob.send(&alice, b"bob next");
    assert_eq!(alice_next.session_id, lower);
    assert_eq!(bob_next.session_id, lower);
    assert_eq!(
        &*accepted_message(bob.receive(&alice_next.message)).plaintext,
        b"alice next"
    );
    assert_eq!(
        &*accepted_message(alice.receive(&bob_next.message)).plaintext,
        b"bob next"
    );
}

#[test]
fn each_peer_sends_on_the_session_that_last_delivered() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    befriend(&mut alice, &mut bob);
    let older = establish(&mut alice, &mut bob);
    let in_flight = bob.send(&alice, b"sent on the older session");
    let newer = alice.initiate(&bob.bundle(), b"newer session");
    assert_eq!(alice.send(&bob, b"on newer").session_id, newer.session_id);

    let received = accepted_message(alice.receive(&in_flight.message));

    assert_eq!(received.session_id, older);
    assert_eq!(alice.send(&bob, b"back on older").session_id, older);
}

#[test]
fn sessions_beyond_five_older_ones_are_deleted_and_stop_receiving() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    befriend(&mut alice, &mut bob);
    let oldest = establish(&mut alice, &mut bob);
    let late = alice.send(&bob, b"sent before eviction");
    for _ in 0..5 {
        establish(&mut alice, &mut bob);
    }
    assert!(alice.host.blob_bytes(&session_address(oldest)).is_some());

    establish(&mut alice, &mut bob);

    for device in [&alice, &bob] {
        assert!(device.host.blob_bytes(&session_address(oldest)).is_none());
    }
    assert!(matches!(
        bob.receive(&late.message),
        InboundMessageOutcome::UnknownSession
    ));
}

#[test]
fn a_replayed_first_message_cannot_revive_a_deleted_session() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    befriend(&mut alice, &mut bob);
    let bundle = bob.bundle_without_one_time_prekey();
    let first = alice.initiate(&bundle, b"replay me");
    accepted_session(bob.accept(&first.message, bundle.selection));
    let reply = bob.send(&alice, b"reply");
    accepted_message(alice.receive(&reply.message));
    for _ in 0..6 {
        establish(&mut alice, &mut bob);
    }
    assert!(
        bob.host
            .blob_bytes(&session_address(first.session_id))
            .is_none()
    );
    bob.forget_received_digests();
    let current = bob.send(&alice, b"current").session_id;
    let before = bob.host.snapshot_bytes();

    assert!(matches!(
        bob.receive(&first.message),
        InboundMessageOutcome::UnknownSession
    ));
    assert!(matches!(
        bob.accept(&first.message, bundle.selection),
        SessionAcceptanceOutcome::DeletedSession
    ));

    assert_eq!(bob.host.snapshot_bytes(), before);
    assert_eq!(bob.send(&alice, b"still current").session_id, current);
}

#[test]
fn a_peer_can_start_a_new_session_after_the_host_wipes_the_current_one() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    befriend(&mut alice, &mut bob);
    let wiped = establish(&mut alice, &mut bob);
    let key = ProtocolStateKey::from_bytes(wiped.as_bytes().to_vec()).unwrap();
    let wipe = bob.store.protocol_engine().wipe(&bob.host.snapshot(), key);
    bob.host.commit(wipe).unwrap();
    let bundle = bob.bundle();

    let replacement = alice.initiate(&bundle, b"after the wipe");
    let accepted = accepted_session(bob.accept(&replacement.message, bundle.selection));

    assert_eq!(accepted.session_id, replacement.session_id);
    assert_eq!(
        bob.send(&alice, b"on the replacement").session_id,
        replacement.session_id
    );
}

#[test]
fn a_handshake_cannot_bring_back_a_session_the_host_wiped() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    befriend(&mut alice, &mut bob);
    let bundle = bob.bundle_without_one_time_prekey();
    let first = alice.initiate(&bundle, b"first");
    let second = alice.send(&bob, b"second");
    accepted_session(bob.accept(&first.message, bundle.selection));
    let key = ProtocolStateKey::from_bytes(first.session_id.as_bytes().to_vec()).unwrap();
    let wipe = bob.store.protocol_engine().wipe(&bob.host.snapshot(), key);
    bob.host.commit(wipe).unwrap();
    let before = bob.host.snapshot_bytes();

    assert!(matches!(
        bob.receive(&second.message),
        InboundMessageOutcome::UnknownSession
    ));
    assert!(matches!(
        bob.accept(&second.message, bundle.selection),
        SessionAcceptanceOutcome::DeletedSession
    ));

    assert_eq!(bob.host.snapshot_bytes(), before);
    let replacement = establish(&mut alice, &mut bob);
    assert_eq!(bob.send(&alice, b"recovered").session_id, replacement);
}

#[test]
fn a_dead_session_is_never_sent_on_until_a_new_handshake() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    befriend(&mut alice, &mut bob);
    let dead = establish(&mut alice, &mut bob);
    alice.host.set_raw(
        session_address(dead),
        dead_session_blob(true, bob.identity_key())
            .as_bytes()
            .to_vec(),
    );

    assert!(matches!(
        alice.encrypt(&bob, b"on a dead session"),
        Err(MessageOperationError::ProtocolState(
            ProtocolStateError::SessionUnrecoverable
        ))
    ));

    let replacement = establish(&mut alice, &mut bob);
    let sent = alice.send(&bob, b"on the replacement");
    assert_eq!(sent.session_id, replacement);
    accepted_message(bob.receive(&sent.message));
}

#[test]
fn sessions_continue_across_restarts() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    befriend(&mut alice, &mut bob);
    let bundle = bob.bundle();
    let initiation = alice.initiate(&bundle, b"before restart");
    alice.restart();
    bob.restart();

    accepted_session(bob.accept(&initiation.message, bundle.selection));
    bob.restart();
    let reply = bob.send(&alice, b"after restart");
    alice.restart();
    let received = accepted_message(alice.receive(&reply.message));

    assert_eq!(received.session_id, initiation.session_id);
    assert_eq!(&*received.plaintext, b"after restart");
}

#[test]
fn a_tampered_or_misdelivered_first_message_changes_nothing() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    let carol = Device::new(&relay, 0xc0);
    let bundle = bob.bundle();
    let initiation = alice.initiate(&bundle, b"for bob");
    let mut tampered = Message::from_bytes(&initiation.message.to_bytes().unwrap()).unwrap();
    *tampered.ciphertext.last_mut().unwrap() ^= 0x01;
    let bob_before = bob.host.snapshot_bytes();
    let carol_before = carol.host.snapshot_bytes();

    assert!(matches!(
        bob.prepare_accept(&tampered, bundle.selection),
        Err(SessionEstablishmentError::ProtocolState(
            ProtocolStateError::SealedFrame(SealedFrameError::Aead)
        ))
    ));
    assert!(matches!(
        carol.decrypt(&initiation.message),
        Err(MessageOperationError::ProtocolState(
            ProtocolStateError::SealedFrame(SealedFrameError::Decode)
        ))
    ));
    assert_eq!(bob.host.snapshot_bytes(), bob_before);
    assert_eq!(carol.host.snapshot_bytes(), carol_before);

    // Nothing was consumed, so the genuine Message still starts the Session.
    let accepted = accepted_session(bob.accept(&initiation.message, bundle.selection));
    assert_eq!(accepted.session_id, initiation.session_id);
}

#[test]
fn initiation_refuses_a_discovery_key_that_does_not_vouch_for_the_identity() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let bob = Device::new(&relay, 0xb0);
    let mallory = Device::new(&relay, 0xd0);
    let mut bundle = bob.bundle();
    // Mallory's Discovery Key signature, valid bytes over the wrong identity.
    bundle.discovery_to_identity = mallory.bundle().discovery_to_identity;
    let before = alice.host.snapshot_bytes();

    assert!(matches!(
        alice.initiate_session(&bundle, b"hello bob"),
        Err(SessionEstablishmentError::ProtocolState(
            ProtocolStateError::Handshake(HandshakeError::PublicKey(PublicKeyError::Signature(
                SignatureError::SignatureInvalid
            )))
        ))
    ));
    assert_eq!(alice.host.snapshot_bytes(), before);
}

// Re-seals a Message's layer sealed to `recipient` after `edit` changes its plaintext.
fn reseal(
    message: &Message,
    recipient: &roost_crypto::DiscoveryKey,
    binding: &roost_core::TransportBinding,
    edit: impl FnOnce(&mut Vec<u8>),
) -> Message {
    let mut plaintext = open_frame_for_discovery_key_with_associated_data(
        recipient,
        &roost_crypto::SealedFrame::from_bytes(&message.to_bytes().unwrap()).unwrap(),
        binding.as_bytes(),
    )
    .unwrap()
    .to_vec();
    edit(&mut plaintext);
    let frame = seal_frame_with_associated_data(
        &mut ChaCha20Rng::from_seed([0x5e; 32]),
        recipient.public_key(),
        message.prekey_reference,
        &plaintext,
        binding.as_bytes(),
    )
    .unwrap();
    Message::from_bytes(&frame.to_bytes().unwrap()).unwrap()
}

#[test]
fn a_session_id_substituted_under_the_discovery_key_is_rejected() {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0x61; 32]);
    let older = fixture.session_id;
    fixture.start_session(&engine, &mut ChaCha20Rng::from_seed([0x62; 32]));
    let message = fixture.encrypt_from_alice(&engine, 1, b"for the newer session");
    let substituted = reseal(
        &message.message,
        &fixture.bob.discovery_key,
        &fixture.binding,
        |plaintext| plaintext[..16].copy_from_slice(older.as_bytes()),
    );
    let before = fixture.bob_store.snapshot_bytes();

    assert!(matches!(
        fixture.receive(&engine, &fixture.bob_store.snapshot(), &substituted, 0x63),
        Err(ProtocolStateError::Ratchet(RatchetError::Aead))
    ));
    assert_eq!(fixture.bob_store.snapshot_bytes(), before);
    let received = fixture.decrypt_for_bob(&engine, &message, 0x64);
    assert_eq!(received.plaintext.as_slice(), b"for the newer session");
}

// Starts a Session from Alice to Bob in `fixture`, with Alice's credentials replaced by `sender`.
fn first_message_from(
    engine: &ProtocolStateEngine,
    fixture: &ProtocolFixture,
    sender: LocalSender<'_>,
) -> Message {
    engine
        .initiate_session(
            &mut ChaCha20Rng::from_seed([0x71; 32]),
            &fixture.alice_store.snapshot(),
            OutboundSessionStart {
                responder_identity_key: &fixture.bob.public_identity_key(),
                responder_discovery_to_identity: fixture.bob.discovery_to_identity(),
                responder_prekey_bundle: &PreKeyBundle {
                    version: roost_crypto::PREKEY_BUNDLE_VERSION,
                    discovery_key: fixture.bob.discovery_key.public(),
                    signed_prekey: fixture.bob_signed_prekey.public(),
                    one_time_prekey: None,
                },
                sender,
                id: MessageId::from_bytes([0x72; 16]),
                sent_at_millis: CREATED_AT_SECS * 1000,
                plaintext: b"first",
            },
            &fixture.binding,
        )
        .unwrap()
        .message
}

fn bob_accepts(
    engine: &ProtocolStateEngine,
    fixture: &ProtocolFixture,
    message: &Message,
) -> Result<SessionAcceptanceOutcome, ProtocolStateError> {
    let domain = validated_sender();
    let domain_keys = [domain.domain_signing_key()];
    engine.accept_session(
        &mut ChaCha20Rng::from_seed([0x73; 32]),
        &fixture.bob_store.snapshot(),
        InboundSessionStart {
            deduplication_key: fixture.deduplication_key.clone(),
            message,
            recipient_discovery_key: &fixture.bob.discovery_key,
            signed_prekey: &fixture.bob_signed_prekey,
            one_time_prekey: None,
            held_signed_prekeys: &[fixture.bob_signed_prekey.public()],
            sender_certificate_validation: validation(&domain_keys, &[]),
        },
        &fixture.binding,
    )
}

#[test]
fn a_first_message_whose_session_id_does_not_match_its_handshake_is_rejected() {
    let engine = ProtocolStateEngine::new();
    let fixture = ProtocolFixture::new([0x74; 32]);
    let message = first_message_from(&engine, &fixture, fixture.alice.local_sender());
    let substituted = reseal(
        &message,
        &fixture.bob.discovery_key,
        &fixture.binding,
        |plaintext| {
            plaintext[..16].copy_from_slice(&[0x75; 16]);
        },
    );

    assert!(matches!(
        bob_accepts(&engine, &fixture, &substituted),
        Err(ProtocolStateError::InvalidMessage { reason })
            if reason == "session id does not match its handshake"
    ));
    assert!(matches!(
        bob_accepts(&engine, &fixture, &message),
        Ok(SessionAcceptanceOutcome::Accepted(_))
    ));
}

#[test]
fn a_first_message_cannot_claim_an_identity_without_its_key() {
    let engine = ProtocolStateEngine::new();
    let fixture = ProtocolFixture::new([0x76; 32]);
    let mallory = TestIdentity::new(0x77, 0x78);
    // Alice's certified identity and Discovery Key, which are public, but Mallory's secret keys.
    let with_copied_identity = first_message_from(
        &engine,
        &fixture,
        LocalSender {
            signing_key: &mallory.signing_key,
            agreement_key: &mallory.agreement_key,
            ..fixture.alice.local_sender()
        },
    );
    // Alice's certified identity with Mallory's own Discovery Key.
    let with_own_discovery_key = first_message_from(
        &engine,
        &fixture,
        LocalSender {
            identity: &fixture.alice.sender_identity,
            ..mallory.local_sender()
        },
    );

    assert!(matches!(
        bob_accepts(&engine, &fixture, &with_copied_identity),
        Err(ProtocolStateError::Handshake(
            HandshakeError::SenderProofInvalid
        ))
    ));
    assert!(matches!(
        bob_accepts(&engine, &fixture, &with_own_discovery_key),
        Err(ProtocolStateError::InvalidMessage { reason })
            if reason == "sender discovery key is not signed by its identity key"
    ));
}

#[test]
fn a_first_message_needs_a_valid_certificate() {
    let engine = ProtocolStateEngine::new();
    let fixture = ProtocolFixture::new([0x79; 32]);
    let expired = fixture.alice.certified_until(CREATED_AT_SECS - 1);
    let message = first_message_from(&engine, &fixture, fixture.alice.local_sender_with(&expired));

    assert!(matches!(
        bob_accepts(&engine, &fixture, &message),
        Err(ProtocolStateError::SenderCertificateValidation(
            SenderCertificateValidationError::ExpiredCertificate
        ))
    ));
}

#[test]
fn a_first_message_keeps_the_padding_and_size_limits() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    let bundle = bob.bundle();
    let largest = vec![0x2a; 65_532];

    assert!(matches!(
        alice.initiate_session(&bundle, &[0; 65_533]),
        Err(SessionEstablishmentError::ProtocolState(
            ProtocolStateError::InvalidMessage { reason }
        )) if reason == "sealed payload length exceeds limit: 65533"
    ));
    let initiation = alice.initiate(&bundle, &largest);
    assert!(initiation.message.to_bytes().unwrap().len() > 64 * 1024);
    let accepted = accepted_session(bob.accept(&initiation.message, bundle.selection));
    assert_eq!(*accepted.plaintext, largest);
}
