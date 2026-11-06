//! Contacts keep reaching an inbox, and blocked contacts stay out, as inboxes rotate.

use crate::support::accepted;
use crate::support::device::{Device, DeviceError, Relay, befriended, established_verifier};
use roost_core::{
    BlockedContactAcknowledgmentPolicy, InboundMessageOutcome, MessageOperationError,
    ProtocolHardeningLimits, ProtocolStateError, ReceiveSettings,
};
use std::time::Duration;

fn silent_receipt() -> ReceiveSettings {
    ReceiveSettings::new(
        ProtocolHardeningLimits::default().default_deduplication_capacity,
        BlockedContactAcknowledgmentPolicy::SilentReceipt,
        Duration::ZERO,
    )
    .unwrap()
}

fn blocked(outcome: InboundMessageOutcome) -> roost_core::BlockedInboundMessageResult {
    let InboundMessageOutcome::Blocked(result) = outcome else {
        panic!("expected a blocked Message");
    };
    *result
}

// Alice starts a new session from Bob's current bundle, as she must once his inbox rotated.
fn restart_session(alice: &mut Device, bob: &Device) -> crate::support::device::SentMessage {
    alice.forget_sessions_with(bob);
    alice.request(bob, b"new session")
}

#[test]
fn an_acknowledgment_carries_the_grant_to_a_contact_on_a_newer_discovery_key() {
    let relay = Relay::new();
    let (mut alice, mut bob) = befriended(&relay);
    // Bob rotates without writing to Alice, so only his bundle names the new discovery key.
    let rotation = bob.rotate_inbox();
    let request = restart_session(&mut alice, &bob);
    let acknowledgment = accepted(bob.receive(&request.message))
        .acknowledgment
        .unwrap();

    alice.receive(&acknowledgment);

    assert_eq!(
        established_verifier(&alice.send(&bob, b"after the handshake").destination),
        rotation.recipient_delivery_verifier
    );
}

#[test]
fn a_silent_receipt_to_a_blocked_contact_carries_no_grant() {
    let relay = Relay::new();
    let (mut alice, mut bob) = befriended(&relay);
    bob.settings = silent_receipt();
    bob.block(alice.identity_key());
    let request = restart_session(&mut alice, &bob);
    let acknowledgment = blocked(bob.receive(&request.message))
        .acknowledgment
        .unwrap();

    alice.receive(&acknowledgment);

    // Alice holds no delivery capability for Bob's rotated inbox, so she can't reach it.
    assert!(matches!(
        alice.encrypt_to(&bob, b"after the block"),
        Err(DeviceError::Operation(
            MessageOperationError::ProtocolState(ProtocolStateError::NoDeliveryCapability)
        ))
    ));
}

#[test]
fn a_message_sealed_before_a_rotation_still_opens_after_it() {
    let relay = Relay::new();
    let (mut alice, mut bob) = befriended(&relay);
    let queued = alice.send(&bob, b"queued at the relay");
    bob.rotate_inbox();

    let received = accepted(bob.receive(&queued.message));

    assert_eq!(received.plaintext.as_slice(), b"queued at the relay");
}

#[test]
fn a_blocked_contacts_message_queued_before_the_block_stays_hidden() {
    let relay = Relay::new();
    let (mut alice, mut bob) = befriended(&relay);
    let queued = alice.send(&bob, b"queued at the relay");
    bob.block(alice.identity_key());

    assert!(
        blocked(bob.receive(&queued.message))
            .acknowledgment
            .is_none()
    );
}
