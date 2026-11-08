//! Sessions that two devices establish through real X3DH and find again by session ID.

use crate::support::CREATED_AT_SECS;
use crate::support::device::{Device, DeviceError, Intent, Relay, SentMessage};
use roost_core::{
    HandshakeError, InboundMessageOutcome, MessageOperationError, ProtocolStateError,
    ProtocolStateKind, PublicKeyError, SessionId,
};
use roost_crypto::SealedFrameError;
use roost_protocol::{SenderCertificateValidationError, SignatureError};

fn accepted_message(outcome: InboundMessageOutcome) -> roost_core::InboundMessageResult {
    let (InboundMessageOutcome::Accepted(result) | InboundMessageOutcome::ContactRequest(result)) =
        outcome
    else {
        panic!("expected a delivered message")
    };
    *result
}

fn protocol_fault(result: Result<InboundMessageOutcome, DeviceError>) -> ProtocolStateError {
    match result {
        Err(DeviceError::Operation(MessageOperationError::ProtocolState(error))) => error,
        Err(error) => panic!("expected a protocol fault, got {error:?}"),
        Ok(_) => panic!("expected a protocol fault"),
    }
}

// Has `initiator` ask `responder` with `bundle`, without delivering anything.
fn request_with(
    initiator: &mut Device,
    responder: &Device,
    bundle: roost_core::PeerPreKeyBundle,
    plaintext: &[u8],
) -> SentMessage {
    let mut outgoing = initiator.outgoing(responder, plaintext);
    outgoing.prekey_bundle = Some(bundle);
    initiator.send_with(outgoing, Intent::Request)
}

fn establish(initiator: &mut Device, responder: &mut Device) -> SessionId {
    let request = initiator.request(responder, b"hello");
    accepted_message(responder.receive(&request.message));
    let acceptance = responder.accept_request(initiator, b"reply");
    accepted_message(initiator.receive(&acceptance.message));
    request.session_id
}

// Starts another session from `initiator` to an accepted `responder`, as an app that lost its
// session list does by requesting again, and has `responder` reply on it.
fn reestablish(initiator: &mut Device, responder: &mut Device) -> SessionId {
    initiator.forget_sessions_with(responder);
    let request = initiator.request(responder, b"hello again");
    accepted_message(responder.receive(&request.message));
    let reply = responder.send(initiator, b"reply");
    accepted_message(initiator.receive(&reply.message));
    request.session_id
}

#[test]
fn peers_derive_one_session_id_and_exchange_messages_both_ways() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);

    let request = alice.request(&bob, b"hello bob");
    let InboundMessageOutcome::ContactRequest(received) = bob.receive(&request.message) else {
        panic!("expected a contact request");
    };
    assert_eq!(received.session_id, request.session_id);
    assert_eq!(&*received.plaintext, b"hello bob");

    let acceptance = bob.accept_request(&alice, b"hello alice");
    assert_eq!(acceptance.session_id, request.session_id);
    let received = accepted_message(alice.receive(&acceptance.message));
    assert_eq!(received.session_id, request.session_id);
    assert_eq!(&*received.plaintext, b"hello alice");

    let follow_up = alice.send(&bob, b"how are you");
    assert_eq!(follow_up.session_id, request.session_id);
    let received = accepted_message(bob.receive(&follow_up.message));
    assert_eq!(&*received.plaintext, b"how are you");
}

#[test]
fn any_message_before_acceptance_can_start_the_session() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    let first = alice.request(&bob, b"first");
    let second = alice.send(&bob, b"second");
    assert_eq!(second.session_id, first.session_id);
    assert_eq!(
        second.message.prekey_reference,
        first.message.prekey_reference
    );

    // The first message is late, so the second one starts the session.
    let InboundMessageOutcome::ContactRequest(started) = bob.receive(&second.message) else {
        panic!("expected a contact request");
    };
    assert_eq!(started.session_id, first.session_id);
    assert_eq!(&*started.plaintext, b"second");
    let late = accepted_message(bob.receive(&first.message));
    assert_eq!(late.session_id, first.session_id);
    assert_eq!(&*late.plaintext, b"first");

    let acceptance = bob.accept_request(&alice, b"welcome");
    accepted_message(alice.receive(&acceptance.message));
    let after_acceptance = alice.send(&bob, b"after acceptance");
    assert!(after_acceptance.message.prekey_reference.is_none());
    let received = accepted_message(bob.receive(&after_acceptance.message));
    assert_eq!(&*received.plaintext, b"after acceptance");
}

#[test]
fn a_message_naming_an_unknown_session_changes_nothing() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    establish(&mut alice, &mut bob);
    let ordinary = alice.send(&bob, b"to a session bob lost");
    let reply = bob.send(&alice, b"needs an acknowledgment");
    let acknowledgment = accepted_message(alice.receive(&reply.message))
        .acknowledgment
        .unwrap();
    for device in [&mut alice, &mut bob] {
        device.database.forget_session();
    }
    let before = bob.database.snapshot_bytes();

    assert!(matches!(
        bob.receive(&ordinary.message),
        InboundMessageOutcome::UnknownSession
    ));
    assert!(matches!(
        bob.receive(&acknowledgment),
        InboundMessageOutcome::UnknownSession
    ));
    assert_eq!(bob.database.snapshot_bytes(), before);
}

#[test]
fn a_first_message_delivered_twice_is_a_duplicate() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    let request = request_with(
        &mut alice,
        &bob,
        bob.bundle_without_one_time_prekey(),
        b"once",
    );
    bob.receive(&request.message);
    let before = bob.database.snapshot_bytes();

    assert!(matches!(
        bob.receive(&request.message),
        InboundMessageOutcome::Duplicate
    ));
    assert_eq!(bob.database.snapshot_bytes(), before);
}

#[test]
fn crossing_requests_converge_on_the_lower_session_id() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    let from_alice = alice.request(&bob, b"from alice");
    let from_bob = bob.request(&alice, b"from bob");

    accepted_message(bob.receive(&from_alice.message));
    accepted_message(alice.receive(&from_bob.message));

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
    let from_alice = alice.request(&bob, b"from alice");
    let from_bob = bob.request(&alice, b"from bob");
    let lower = from_alice.session_id.min(from_bob.session_id);
    let higher = from_alice.session_id.max(from_bob.session_id);
    // Whoever started the higher session sends on it again before the requests cross.
    let alice_started_higher = from_alice.session_id == higher;
    let in_flight = if alice_started_higher {
        alice.send(&bob, b"on the higher session")
    } else {
        bob.send(&alice, b"on the higher session")
    };
    accepted_message(alice.receive(&from_bob.message));
    accepted_message(bob.receive(&from_alice.message));
    let (receiver, sender) = if alice_started_higher {
        (&mut bob, &alice)
    } else {
        (&mut alice, &bob)
    };
    assert_eq!(receiver.send(sender, b"on lower").session_id, lower);

    let received = accepted_message(receiver.receive(&in_flight.message));

    assert_eq!(received.session_id, higher);
    assert_eq!(receiver.send(sender, b"back on higher").session_id, higher);
}

#[test]
fn sessions_beyond_five_older_ones_are_deleted_and_stop_receiving() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    establish(&mut alice, &mut bob);
    let oldest = bob.database.only(ProtocolStateKind::RatchetSession);
    let late = alice.send(&bob, b"sent before eviction");
    for _ in 0..5 {
        reestablish(&mut alice, &mut bob);
    }
    assert!(bob.database.blob_bytes(&oldest).is_some());

    reestablish(&mut alice, &mut bob);

    assert!(bob.database.blob_bytes(&oldest).is_none());
    assert!(matches!(
        bob.receive(&late.message),
        InboundMessageOutcome::UnknownSession
    ));
}

// Returns the message IDs `device` still waits to have acknowledged on `session_id`.
fn waiting_on(device: &Device, session_id: SessionId) -> Vec<roost_protocol::MessageId> {
    device
        .store
        .protocol_engine()
        .pending_acknowledgments(
            session_id,
            device
                .database
                .pending_acknowledgments_record(session_id)
                .as_ref(),
        )
        .unwrap()
        .into_iter()
        .map(|pending| pending.message_id)
        .collect()
}

#[test]
fn a_session_the_peer_evicts_lists_its_unacknowledged_messages_as_undelivered() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    let oldest = establish(&mut alice, &mut bob);
    let oldest_record = bob.database.only(ProtocolStateKind::RatchetSession);
    let stranded = bob.send(&alice, b"never acknowledged");
    for _ in 0..5 {
        reestablish(&mut alice, &mut bob);
    }
    let waiting = waiting_on(&bob, oldest);
    assert!(waiting.contains(&stranded.message_id));
    alice.forget_sessions_with(&bob);
    let request = alice.request(&bob, b"hello again");

    accepted_message(bob.receive(&request.message));

    assert_eq!(bob.database.undelivered(), waiting);
    assert!(bob.database.blob_bytes(&oldest_record).is_none());
}

#[test]
fn a_session_a_send_evicts_lists_its_unacknowledged_messages_as_undelivered() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    let oldest = establish(&mut alice, &mut bob);
    let oldest_record = alice.database.only(ProtocolStateKind::RatchetSession);
    let stranded = alice.send(&bob, b"never acknowledged");
    // Each rotation makes Alice's next send start a session from Bob's newer bundle.
    for _ in 0..5 {
        bob.rotate_inbox();
        let mut outgoing = alice.outgoing(&bob, b"to the newer inbox");
        outgoing.prekey_bundle = Some(bob.bundle());
        alice.send_with(outgoing, Intent::Message);
    }
    assert_eq!(waiting_on(&alice, oldest), [stranded.message_id]);
    bob.rotate_inbox();
    let mut outgoing = alice.outgoing(&bob, b"evicts the oldest");
    outgoing.prekey_bundle = Some(bob.bundle());

    let sealed = alice.encrypt(outgoing, Intent::Message).unwrap().ready();

    assert_eq!(sealed.changes.undelivered(), [stranded.message_id]);
    alice
        .database
        .commit_sent(&sealed.result, sealed.changes)
        .unwrap();
    assert!(alice.database.blob_bytes(&oldest_record).is_none());
}

#[test]
fn a_replayed_first_message_cannot_revive_a_deleted_session() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    let first = request_with(
        &mut alice,
        &bob,
        bob.bundle_without_one_time_prekey(),
        b"replay me",
    );
    bob.receive(&first.message);
    let first_record = bob.database.only(ProtocolStateKind::RatchetSession);
    let acceptance = bob.accept_request(&alice, b"welcome");
    accepted_message(alice.receive(&acceptance.message));
    for _ in 0..6 {
        reestablish(&mut alice, &mut bob);
    }
    assert!(bob.database.blob_bytes(&first_record).is_none());
    // Starting the next session keeps the deleted session's ID, since Bob still holds its signed
    // prekey.
    reestablish(&mut alice, &mut bob);
    bob.forget_received_digests();
    let current = bob.send(&alice, b"current").session_id;
    let before = bob.database.snapshot_bytes();

    assert!(matches!(
        bob.receive(&first.message),
        InboundMessageOutcome::DeletedSession
    ));

    assert_eq!(bob.database.snapshot_bytes(), before);
    assert_eq!(bob.send(&alice, b"still current").session_id, current);
}

#[test]
fn a_peer_can_start_a_new_session_after_the_app_wipes_the_current_one() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    establish(&mut alice, &mut bob);
    bob.database.forget_session();

    alice.forget_sessions_with(&bob);
    let replacement = alice.request(&bob, b"after the wipe");
    let received = accepted_message(bob.receive(&replacement.message));

    assert_eq!(received.session_id, replacement.session_id);
    assert_eq!(
        bob.send(&alice, b"on the replacement").session_id,
        replacement.session_id
    );
}

#[test]
fn a_handshake_cannot_bring_back_a_session_the_app_wiped() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    let first = request_with(
        &mut alice,
        &bob,
        bob.bundle_without_one_time_prekey(),
        b"first",
    );
    let second = alice.send(&bob, b"second");
    bob.receive(&first.message);
    bob.database.forget_session();
    let before = bob.database.snapshot_bytes();

    assert!(matches!(
        bob.receive(&second.message),
        InboundMessageOutcome::DeletedSession
    ));

    assert_eq!(bob.database.snapshot_bytes(), before);
}

#[test]
fn sessions_continue_across_restarts() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    let request = alice.request(&bob, b"before restart");
    alice.restart();
    bob.restart();

    bob.receive(&request.message);
    bob.restart();
    let acceptance = bob.accept_request(&alice, b"after restart");
    alice.restart();
    let received = accepted_message(alice.receive(&acceptance.message));

    assert_eq!(received.session_id, request.session_id);
    assert_eq!(&*received.plaintext, b"after restart");
}

#[test]
fn a_tampered_or_misdelivered_first_message_changes_nothing() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    let carol = Device::new(&relay, 0xc0);
    let request = alice.request(&bob, b"for bob");
    let mut tampered = request.message.clone();
    *tampered.ciphertext.last_mut().unwrap() ^= 0x01;
    let bob_before = bob.database.snapshot_bytes();
    let carol_before = carol.database.snapshot_bytes();

    assert!(matches!(
        protocol_fault(bob.decrypt(&tampered)),
        ProtocolStateError::SealedFrame(SealedFrameError::Aead)
    ));
    assert!(matches!(
        protocol_fault(carol.decrypt(&request.message)),
        ProtocolStateError::SealedFrame(SealedFrameError::RecipientMismatch)
    ));
    assert_eq!(bob.database.snapshot_bytes(), bob_before);
    assert_eq!(carol.database.snapshot_bytes(), carol_before);

    // Nothing was consumed, so the genuine message still starts the session.
    let received = accepted_message(bob.receive(&request.message));
    assert_eq!(received.session_id, request.session_id);
}

#[test]
fn a_request_refuses_a_discovery_key_that_does_not_vouch_for_the_identity() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let bob = Device::new(&relay, 0xb0);
    let mallory = Device::new(&relay, 0xd0);
    let mut bundle = bob.bundle();
    // Mallory's discovery key signature, valid bytes over the wrong identity.
    bundle.discovery_to_identity = mallory.bundle().discovery_to_identity;
    let before = alice.database.snapshot_bytes();
    let mut outgoing = alice.outgoing(&bob, b"hello bob");
    outgoing.prekey_bundle = Some(bundle);

    assert!(matches!(
        alice.encrypt(outgoing, Intent::Request),
        Err(DeviceError::Operation(
            MessageOperationError::ProtocolState(ProtocolStateError::Handshake(
                HandshakeError::PublicKey(PublicKeyError::Signature(
                    SignatureError::SignatureInvalid
                ))
            ))
        ))
    ));
    assert_eq!(alice.database.snapshot_bytes(), before);
}

#[test]
fn a_first_message_needs_a_valid_certificate() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let bob = Device::new(&relay, 0xb0);
    let mut outgoing = alice.outgoing(&bob, b"first");
    outgoing.sender_certificate = alice.certified_until(CREATED_AT_SECS - 1);
    outgoing.prekey_bundle = Some(bob.bundle());
    let request = alice.send_with(outgoing, Intent::Request);

    assert!(matches!(
        protocol_fault(bob.decrypt(&request.message)),
        ProtocolStateError::SenderCertificateValidation(
            SenderCertificateValidationError::ExpiredCertificate
        )
    ));
}

#[test]
fn a_first_message_keeps_the_padding_and_size_limits() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    let mut too_large = alice.outgoing(&bob, &[0; 65_294]);
    too_large.prekey_bundle = Some(bob.bundle());
    assert!(matches!(
        alice.encrypt(too_large, Intent::Request),
        Err(DeviceError::Operation(
            MessageOperationError::ProtocolState(ProtocolStateError::ContentTooLong {
                len: 65_294,
                max: 65_293,
            })
        ))
    ));

    // The request's inbox grant shares the largest padding bucket with the longest content.
    let largest = vec![0x2a; 65_293];
    let request = alice.request(&bob, &largest);
    assert!(request.message.to_bytes().unwrap().len() > 64 * 1024);
    let received = accepted_message(bob.receive(&request.message));
    assert_eq!(*received.plaintext, largest);
}
