//! Unblocking keeps a contact's Sessions, and the first send after it checks whether the contact
//! rotated its inbox during the block.

mod support;

use roost_core::{ContactTrustState, InboundMessageOutcome};
use roost_protocol::PayloadKind;
use support::accepted;
use support::device::{Device, Encrypted, Intent, Relay, Route, befriended, established_verifier};

// Alice blocks Bob and later unblocks him.
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
    let before = alice.host.snapshot_bytes();

    let Encrypted::NeedsPreKeyBundle(identity_key) =
        alice.encrypt(outgoing, Intent::Message).unwrap()
    else {
        panic!("expected a request for Bob's bundle");
    };

    assert_eq!(identity_key, bob.identity_key());
    assert_eq!(alice.host.snapshot_bytes(), before);
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
    assert_eq!(sent.payload_kind, PayloadKind::EncryptedTextWithGrant);
    assert_eq!(Route::of(&sent.destination), bob.established_route());
    bob.receive(&sent.message);
    assert_eq!(
        established_verifier(&bob.send(&alice, b"welcome back").destination),
        alice.publication().recipient_delivery_verifier
    );
    // The check happens once.
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
        established_verifier(&alice.send(&bob, b"after the handshake").destination),
        rotation.recipient_delivery_verifier
    );
    let contact = alice.contact(&bob).unwrap();
    assert_eq!(contact.trust_state, ContactTrustState::Unverified);
    assert!(!contact.blocked);
}
