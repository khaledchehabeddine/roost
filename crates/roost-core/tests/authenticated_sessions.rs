//! Sessions that two Devices establish through real X3DH and find again by SessionID.

mod support;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use roost_core::{
    HandshakeError, InboundMessageOutcome, Message, MessageOperationError, ProtocolStateError,
    PublicKeyError, SessionId,
};
use roost_crypto::{
    RatchetError, SealedFrameError, open_frame_for_discovery_key_with_associated_data,
    seal_frame_with_associated_data,
};
use roost_protocol::{SenderCertificateValidationError, SignatureError};
use support::device::{Device, DeviceError, Intent, Relay, SentMessage};
use support::{CREATED_AT_SECS, ProtocolFixture, session_address};

fn accepted_message(outcome: InboundMessageOutcome) -> roost_core::InboundMessageResult {
    let (InboundMessageOutcome::Accepted(result) | InboundMessageOutcome::ContactRequest(result)) =
        outcome
    else {
        panic!("expected a delivered Message")
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

// Has `initiator` ask `responder`, `responder` accept, and `initiator` receive the acceptance.
fn establish(initiator: &mut Device, responder: &mut Device) -> SessionId {
    let request = initiator.request(responder, b"hello");
    accepted_message(responder.receive(&request.message));
    let acceptance = responder.accept_request(initiator, b"reply");
    accepted_message(initiator.receive(&acceptance.message));
    request.session_id
}

// Starts another Session from `initiator` to an accepted `responder`, as a host that lost its
// Session list does by requesting again, and has `responder` reply on it.
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

    // The first Message is late, so the second one starts the Session.
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
    let session_id = establish(&mut alice, &mut bob);
    let ordinary = alice.send(&bob, b"to a session bob lost");
    let reply = bob.send(&alice, b"needs an acknowledgment");
    let acknowledgment = accepted_message(alice.receive(&reply.message))
        .acknowledgment
        .unwrap();
    for device in [&mut alice, &mut bob] {
        device.host.forget_session(session_id);
    }
    let before = bob.host.snapshot_bytes();

    assert!(matches!(
        bob.receive(&ordinary.message),
        InboundMessageOutcome::UnknownSession
    ));
    assert!(matches!(
        bob.receive(&acknowledgment),
        InboundMessageOutcome::UnknownSession
    ));
    assert_eq!(bob.host.snapshot_bytes(), before);
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
    let before = bob.host.snapshot_bytes();

    assert!(matches!(
        bob.receive(&request.message),
        InboundMessageOutcome::Duplicate
    ));
    assert_eq!(bob.host.snapshot_bytes(), before);
}

#[test]
fn a_handshake_never_replaces_a_session_it_names() {
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

    // The second Message carries the same handshake, but its Session exists, so it decrypts on it.
    let received = accepted_message(bob.receive(&second.message));
    assert_eq!(received.session_id, first.session_id);
    assert_eq!(&*received.plaintext, b"second");
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
    // Whoever started the higher Session sends on it again before the requests cross.
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
    let oldest = establish(&mut alice, &mut bob);
    let late = alice.send(&bob, b"sent before eviction");
    for _ in 0..5 {
        reestablish(&mut alice, &mut bob);
    }
    assert!(bob.host.blob_bytes(&session_address(oldest)).is_some());

    reestablish(&mut alice, &mut bob);

    assert!(bob.host.blob_bytes(&session_address(oldest)).is_none());
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
    let first = request_with(
        &mut alice,
        &bob,
        bob.bundle_without_one_time_prekey(),
        b"replay me",
    );
    bob.receive(&first.message);
    let acceptance = bob.accept_request(&alice, b"welcome");
    accepted_message(alice.receive(&acceptance.message));
    for _ in 0..6 {
        reestablish(&mut alice, &mut bob);
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
        InboundMessageOutcome::DeletedSession
    ));

    assert_eq!(bob.host.snapshot_bytes(), before);
    assert_eq!(bob.send(&alice, b"still current").session_id, current);
}

#[test]
fn a_peer_can_start_a_new_session_after_the_host_wipes_the_current_one() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    let wiped = establish(&mut alice, &mut bob);
    bob.host.forget_session(wiped);

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
fn a_handshake_cannot_bring_back_a_session_the_host_wiped() {
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
    bob.host.forget_session(first.session_id);
    let before = bob.host.snapshot_bytes();

    assert!(matches!(
        bob.receive(&second.message),
        InboundMessageOutcome::DeletedSession
    ));

    assert_eq!(bob.host.snapshot_bytes(), before);
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
    let mut tampered = Message::from_bytes(&request.message.to_bytes().unwrap()).unwrap();
    *tampered.ciphertext.last_mut().unwrap() ^= 0x01;
    let bob_before = bob.host.snapshot_bytes();
    let carol_before = carol.host.snapshot_bytes();

    assert!(matches!(
        protocol_fault(bob.decrypt(&tampered)),
        ProtocolStateError::SealedFrame(SealedFrameError::Aead)
    ));
    assert!(matches!(
        protocol_fault(carol.decrypt(&request.message)),
        ProtocolStateError::SealedFrame(SealedFrameError::Decode)
    ));
    assert_eq!(bob.host.snapshot_bytes(), bob_before);
    assert_eq!(carol.host.snapshot_bytes(), carol_before);

    // Nothing was consumed, so the genuine Message still starts the Session.
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
    // Mallory's Discovery Key signature, valid bytes over the wrong identity.
    bundle.discovery_to_identity = mallory.bundle().discovery_to_identity;
    let before = alice.host.snapshot_bytes();
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
    let mut fixture = ProtocolFixture::new();
    let older = fixture.session_id;
    fixture.start_session();
    let message = fixture.encrypt_from_alice(1, b"for the newer session");
    let substituted = reseal(
        &message.message,
        &fixture.bob.discovery_key(),
        &fixture.binding,
        |plaintext| plaintext[..16].copy_from_slice(older.as_bytes()),
    );
    let before = fixture.bob.host.snapshot_bytes();

    assert!(matches!(
        fixture.receive(&fixture.bob.host, &substituted, 0x63),
        Err(MessageOperationError::ProtocolState(
            ProtocolStateError::Ratchet(RatchetError::Aead)
        ))
    ));
    assert_eq!(fixture.bob.host.snapshot_bytes(), before);
    let received = fixture.decrypt_for_bob(&message, 0x64);
    assert_eq!(received.plaintext.as_slice(), b"for the newer session");
}

#[test]
fn a_first_message_whose_session_id_does_not_match_its_handshake_is_rejected() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let bob = Device::new(&relay, 0xb0);
    let request = request_with(
        &mut alice,
        &bob,
        bob.bundle_without_one_time_prekey(),
        b"first",
    );
    let substituted = reseal(
        &request.message,
        &bob.discovery_key(),
        &support::device::binding(),
        |plaintext| plaintext[..16].copy_from_slice(&[0x75; 16]),
    );

    assert!(matches!(
        protocol_fault(bob.decrypt(&substituted)),
        ProtocolStateError::InvalidMessage { reason }
            if reason == "session id does not match its handshake"
    ));
    assert!(bob.decrypt(&request.message).is_ok());
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
    // The request's Inbox Grant shares the largest padding bucket with the plaintext.
    let mut too_large = alice.outgoing(&bob, &[0; 65_533]);
    too_large.prekey_bundle = Some(bob.bundle());
    let Err(DeviceError::Operation(MessageOperationError::ProtocolState(
        ProtocolStateError::InvalidMessage { reason },
    ))) = alice.encrypt(too_large, Intent::Request)
    else {
        panic!("expected the oversized request to be refused");
    };
    assert!(reason.starts_with("sealed payload length exceeds limit"));

    let largest = vec![0x2a; 65_200];
    let request = alice.request(&bob, &largest);
    assert!(request.message.to_bytes().unwrap().len() > 64 * 1024);
    let received = accepted_message(bob.receive(&request.message));
    assert_eq!(*received.plaintext, largest);
}
