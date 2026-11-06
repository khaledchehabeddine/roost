//! Grant updates carry an identity's current inbox grant to the contacts the app picks, and Roost
//! decides who may hold it.

use crate::support::device::{
    Device, DeviceError, Encrypted, Intent, Relay, befriended, established_verifier, requested,
};
use roost_core::{
    GrantUpdateResult, InboundMessageOutcome, MessageOperationError, ProtocolStateError,
};
use roost_protocol::PayloadKind;

fn encrypt_grant_update(sender: &mut Device, recipient: &Device) -> Result<Encrypted, DeviceError> {
    let outgoing = sender.outgoing(recipient, b"");
    sender.encrypt(outgoing, Intent::GrantUpdate)
}

fn refused(result: Result<Encrypted, DeviceError>) -> ProtocolStateError {
    match result {
        Err(DeviceError::Operation(MessageOperationError::ProtocolState(error))) => error,
        Err(error) => panic!("expected a protocol refusal, got {error:?}"),
        Ok(_) => panic!("expected a protocol refusal"),
    }
}

fn grant_update(outcome: InboundMessageOutcome) -> GrantUpdateResult {
    let InboundMessageOutcome::GrantUpdate(result) = outcome else {
        panic!("expected a Grant Update");
    };
    *result
}

#[test]
fn a_grant_update_after_a_rotation_reaches_the_contact_and_is_acknowledged() {
    let relay = Relay::new();
    let (mut alice, mut bob) = befriended(&relay);
    let rotation = bob.rotate_inbox();

    let update = bob.send_grant_update(&alice);

    assert_eq!(update.payload_kind, PayloadKind::GrantUpdate);
    let received = grant_update(alice.receive(&update.message));
    assert!(matches!(
        bob.receive(&received.acknowledgment.unwrap()),
        InboundMessageOutcome::AcknowledgmentMatched(_)
    ));
    assert_eq!(
        established_verifier(&alice.send(&bob, b"got it").destination),
        rotation.recipient_delivery_verifier
    );
}

#[test]
fn a_grant_update_to_a_contact_that_acknowledged_the_current_grant_has_nothing_to_send() {
    let relay = Relay::new();
    let (mut alice, mut bob) = befriended(&relay);
    bob.rotate_inbox();
    let update = bob.send_grant_update(&alice);
    let acknowledgment = grant_update(alice.receive(&update.message))
        .acknowledgment
        .unwrap();
    bob.receive(&acknowledgment);
    let before = bob.host.snapshot_bytes();

    let again = encrypt_grant_update(&mut bob, &alice).unwrap();

    assert!(matches!(again, Encrypted::NothingToSend));
    assert_eq!(bob.host.snapshot_bytes(), before);
}

#[test]
fn a_grant_update_to_a_blocked_contact_is_refused() {
    let relay = Relay::new();
    let (alice, mut bob) = befriended(&relay);
    bob.block(alice.identity_key());
    let before = bob.host.snapshot_bytes();

    assert!(matches!(
        refused(encrypt_grant_update(&mut bob, &alice)),
        ProtocolStateError::BlockedContact
    ));
    assert_eq!(bob.host.snapshot_bytes(), before);
}

#[test]
fn a_grant_update_to_a_requester_this_side_has_not_accepted_is_refused() {
    let relay = Relay::new();
    let (alice, mut bob) = requested(&relay);
    bob.rotate_inbox();
    let before = bob.host.snapshot_bytes();

    assert!(matches!(
        refused(encrypt_grant_update(&mut bob, &alice)),
        ProtocolStateError::ContactNotAccepted
    ));
    assert_eq!(bob.host.snapshot_bytes(), before);
}

#[test]
fn a_requester_sends_grant_updates_outside_the_limit_so_the_acceptance_reaches_its_new_inbox() {
    let relay = Relay::new();
    let (mut alice, mut bob) = requested(&relay);
    for plaintext in [b"second", b"third!"] {
        bob.receive(&alice.send(&bob, plaintext).message);
    }
    let rotation = alice.rotate_inbox();

    let update = alice.send_grant_update(&bob);

    // The requester's messages carry the handshake until the asked side accepts.
    assert!(matches!(
        update.destination,
        roost_core::MessageDestination::FirstMessage { .. }
    ));
    assert!(
        grant_update(bob.receive(&update.message))
            .acknowledgment
            .is_none()
    );
    let acceptance = bob.accept_request(&alice, b"welcome");
    assert_eq!(
        established_verifier(&acceptance.destination),
        rotation.recipient_delivery_verifier
    );
}

#[test]
fn a_requesters_grant_update_the_asked_side_acknowledged_stops_the_grant() {
    let relay = Relay::new();
    let (mut alice, mut bob) = requested(&relay);
    // Bob replies, so he acknowledges what Alice sends before he accepts.
    alice.receive(&bob.send(&alice, b"who is this?").message);
    alice.rotate_inbox();
    let update = alice.send_grant_update(&bob);
    let acknowledgment = grant_update(bob.receive(&update.message))
        .acknowledgment
        .unwrap();
    alice.receive(&acknowledgment);
    let before = alice.host.snapshot_bytes();

    let again = encrypt_grant_update(&mut alice, &bob).unwrap();

    assert!(matches!(again, Encrypted::NothingToSend));
    assert_eq!(alice.host.snapshot_bytes(), before);
    assert_eq!(
        alice.send(&bob, b"after the update").payload_kind,
        PayloadKind::Content
    );
}

#[test]
fn a_grant_update_cannot_start_a_contact() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    let request = alice.request(&bob, b"hi bob");
    alice.rotate_inbox();
    // The grant update carries the request's handshake and reaches Bob before the request.
    let update = alice.send_grant_update(&bob);

    assert!(matches!(
        bob.observe(&update.message),
        Err(DeviceError::Operation(MessageOperationError::ProtocolState(
            ProtocolStateError::InvalidMessage { reason }
        ))) if reason == "a grant update cannot start a contact"
    ));
    assert!(matches!(
        bob.receive(&request.message),
        InboundMessageOutcome::ContactRequest(_)
    ));
}
