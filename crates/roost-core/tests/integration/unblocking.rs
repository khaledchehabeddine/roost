//! Unblocking keeps a contact's sessions, and the first send after it checks whether the contact
//! rotated its inbox during the block.

use crate::support::accepted;
use crate::support::device::{
    Device, DeviceError, Encrypted, Intent, Relay, Route, befriended, established_verifier,
    requested,
};
use roost_core::{
    ContactTrustState, InboundMessageOutcome, MessageOperationError, ProtocolStateError,
};
use roost_crypto::SealedFrameError;
use roost_protocol::PayloadKind;

fn blocked_then_unblocked(relay: &Relay) -> (Device, Device) {
    let (mut alice, bob) = befriended(relay);
    alice.block(bob.identity_key());
    alice.unblock(bob.identity_key());
    (alice, bob)
}

#[test]
fn the_first_send_after_an_unblock_asks_for_the_contacts_bundle() {
    let relay = Relay::new();
    let (mut alice, bob) = blocked_then_unblocked(&relay);
    let outgoing = alice.outgoing(&bob, b"hello again");
    let before = alice.database.snapshot_bytes();

    let Encrypted::NeedsPreKeyBundle(identity_key) =
        alice.encrypt(outgoing, Intent::Message).unwrap()
    else {
        panic!("expected a request for Bob's bundle");
    };

    assert_eq!(identity_key, bob.identity_key());
    assert_eq!(alice.database.snapshot_bytes(), before);
}

#[test]
fn an_unchanged_discovery_key_keeps_the_session_and_carries_the_new_grant() {
    let relay = Relay::new();
    let (mut alice, mut bob) = befriended(&relay);
    let kept = alice.send(&bob, b"before the block").session_id;
    alice.block(bob.identity_key());
    alice.unblock(bob.identity_key());
    let mut outgoing = alice.outgoing(&bob, b"hello again");
    outgoing.prekey_bundle = Some(bob.bundle());

    let sent = alice.send_with(outgoing, Intent::Message);

    assert_eq!(sent.session_id, kept);
    assert_eq!(sent.payload_kind, PayloadKind::ContentWithGrant);
    assert_eq!(Route::of(&sent.destination), bob.established_route());
    bob.receive(&sent.message);
    assert_eq!(
        established_verifier(&bob.send(&alice, b"welcome back").destination).as_bytes(),
        alice.publication().recipient_delivery_verifier.as_bytes()
    );
    // Only the first send after the unblock asks for a bundle.
    alice.send(&bob, b"no bundle needed");
}

#[test]
fn a_contact_that_rotated_during_the_block_gets_a_new_session() {
    let relay = Relay::new();
    let (mut alice, mut bob) = befriended(&relay);
    let kept = alice.send(&bob, b"before the block").session_id;
    alice.block(bob.identity_key());
    let rotation = bob.rotate_inbox();
    alice.unblock(bob.identity_key());
    let mut outgoing = alice.outgoing(&bob, b"hello again");
    outgoing.prekey_bundle = Some(bob.bundle());

    let sent = alice.send_with(outgoing, Intent::Message);

    assert_ne!(sent.session_id, kept);
    assert!(matches!(
        Route::of(&sent.destination),
        Route::FirstMessage { discovery_key, .. }
            if discovery_key == *rotation.discovery_key.public_key.as_bytes()
    ));
    let acknowledgment = accepted(bob.receive(&sent.message)).acknowledgment.unwrap();
    assert!(matches!(
        alice.receive(&acknowledgment),
        InboundMessageOutcome::AcknowledgmentMatched(_)
    ));
    assert_eq!(
        established_verifier(&alice.send(&bob, b"after the handshake").destination).as_bytes(),
        rotation.recipient_delivery_verifier.as_bytes()
    );
    let contact = alice.contact(&bob).unwrap();
    assert_eq!(contact.trust_state, ContactTrustState::Unverified);
    assert!(!contact.blocked);
}

// Alice asks Bob, Bob blocks her before answering, Alice rotates her inbox, and Bob unblocks her.
fn requester_rotated_during_the_block(relay: &Relay) -> (Device, Device) {
    let (alice, mut bob) = requested(relay);
    bob.block(alice.identity_key());
    alice.rotate_inbox();
    bob.unblock(alice.identity_key());
    (alice, bob)
}

#[test]
fn accepting_a_requester_that_rotated_during_the_block_sends_a_crossing_request() {
    let relay = Relay::new();
    let (mut alice, mut bob) = requester_rotated_during_the_block(&relay);
    let mut outgoing = bob.outgoing(&alice, b"sorry, welcome");
    outgoing.prekey_bundle = Some(alice.bundle());

    let sent = bob.send_with(outgoing, Intent::Acceptance);

    assert_eq!(sent.payload_kind, PayloadKind::ContentWithGrant);
    assert!(matches!(
        Route::of(&sent.destination),
        Route::FirstMessage { .. }
    ));
    assert_eq!(
        bob.contact(&alice).unwrap().trust_state,
        ContactTrustState::Unverified
    );
    let acknowledgment = accepted(alice.receive(&sent.message))
        .acknowledgment
        .unwrap();
    assert_eq!(
        alice.contact(&bob).unwrap().trust_state,
        ContactTrustState::Unverified
    );
    assert!(matches!(
        bob.receive(&acknowledgment),
        InboundMessageOutcome::AcknowledgmentMatched(_)
    ));
    let reply = alice.send(&bob, b"thanks");
    assert_eq!(reply.session_id, sent.session_id);
    assert_eq!(
        accepted(bob.receive(&reply.message)).plaintext.as_slice(),
        b"thanks"
    );
}

#[test]
fn a_message_to_a_requester_that_rotated_during_the_block_accepts_it() {
    let relay = Relay::new();
    let (mut alice, mut bob) = requester_rotated_during_the_block(&relay);
    let mut outgoing = bob.outgoing(&alice, b"still there?");
    outgoing.prekey_bundle = Some(alice.bundle());

    let sent = bob.send_with(outgoing, Intent::Message);

    assert_eq!(sent.payload_kind, PayloadKind::ContentWithGrant);
    assert_eq!(
        bob.contact(&alice).unwrap().trust_state,
        ContactTrustState::Unverified
    );
    assert!(
        accepted(alice.receive(&sent.message))
            .acknowledgment
            .is_some()
    );
}

#[test]
fn a_requester_reaches_this_side_after_an_unblock_only_from_the_new_bundle() {
    let relay = Relay::new();
    let (mut alice, mut bob) = requested(&relay);
    bob.block(alice.identity_key());
    bob.unblock(alice.identity_key());

    // The block rotated Bob's inbox, so Alice's first session names prekeys Bob deleted.
    let stale = alice.send(&bob, b"still there?");
    assert!(matches!(
        bob.decrypt(&stale.message),
        Err(DeviceError::Operation(
            MessageOperationError::ProtocolState(ProtocolStateError::SealedFrame(
                SealedFrameError::RecipientMismatch
            ))
        ))
    ));

    let mut outgoing = alice.outgoing(&bob, b"asking again");
    outgoing.prekey_bundle = Some(bob.bundle());
    let sent = alice.send_with(outgoing, Intent::Message);

    assert_ne!(sent.session_id, stale.session_id);
    assert_eq!(
        accepted(bob.receive(&sent.message)).plaintext.as_slice(),
        b"asking again"
    );
    assert_eq!(
        bob.contact(&alice).unwrap().trust_state,
        ContactTrustState::Pending
    );
}
