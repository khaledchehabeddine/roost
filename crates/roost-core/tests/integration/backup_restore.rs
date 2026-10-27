//! Restoring a backup brings back every contact, and each contact can send and receive again right
//! away on new Sessions. The exception is an Asked Side that hasn't accepted yet. This side drops
//! its acceptance on the old Session and can only send it a new Contact Request. Both sides end up
//! accepted whether the Asked Side accepts before or after that request.

use crate::support::device::{
    DeviceError, Intent, Recovered, Relay, Route, befriended, redraft, requested,
};
use crate::support::{CREATED_AT_SECS, accepted};
use roost_core::{
    ContactTrustState, InboundMessageOutcome, MessageOperationError, ProtocolStateError,
};
use roost_protocol::PayloadKind;

const HOUR_MILLIS: u64 = 60 * 60 * 1000;

#[test]
fn a_restored_side_talks_both_ways_and_gets_messages_sent_after_the_backup_once() {
    let relay = Relay::new();
    let (mut alice, mut bob) = befriended(&relay);
    let backup = bob.back_up();
    let first = alice.send(&bob, b"sent after the backup");
    let second = alice.send(&bob, b"also sent after it");
    // Bob's phone breaks before either arrives, and he restores the backup on a new one.
    bob.restore(&backup);
    let update = bob.send_fetching_a_bundle(&alice, b"", Intent::GrantUpdate);
    assert!(matches!(
        alice.receive(&update.message),
        InboundMessageOutcome::GrantUpdate(_)
    ));
    // The Relay still delivers the first copies, which name the Session Bob no longer has.
    for original in [&first, &second] {
        assert!(matches!(
            bob.receive(&original.message),
            InboundMessageOutcome::UnknownSession
        ));
    }

    assert!(
        alice
            .check_deliveries(&bob, CREATED_AT_SECS * 1000 + HOUR_MILLIS)
            .starts_recovery
    );
    let resent = [
        alice.recover(&bob, None).committed(),
        alice.recover(&bob, None).committed(),
    ];
    assert!(matches!(alice.recover(&bob, None), Recovered::Finished));

    for (copy, original, plaintext) in [
        (&resent[0], &first, &b"sent after the backup"[..]),
        (&resent[1], &second, &b"also sent after it"[..]),
    ] {
        assert_eq!(copy.session_id, update.session_id);
        let received = accepted(bob.receive(&copy.message));
        assert_eq!(received.message_id, original.message_id);
        assert_eq!(received.plaintext.as_slice(), plaintext);
        assert!(matches!(
            alice.receive(&received.acknowledgment.unwrap()),
            InboundMessageOutcome::AcknowledgmentMatched(_)
        ));
    }
    let reply = bob.send(&alice, b"back again");
    assert_eq!(
        accepted(alice.receive(&reply.message)).plaintext.as_slice(),
        b"back again"
    );
    let answer = alice.send(&bob, b"welcome back");
    assert_eq!(answer.session_id, update.session_id);
    assert_eq!(
        accepted(bob.receive(&answer.message)).plaintext.as_slice(),
        b"welcome back"
    );
}

#[test]
fn accepting_a_request_open_in_the_backup_accepts_both_sides() {
    let relay = Relay::new();
    let (mut alice, mut bob) = requested(&relay);
    let backup = bob.back_up();
    bob.restore(&backup);

    let acceptance = bob.send_fetching_a_bundle(&alice, b"welcome", Intent::Acceptance);

    assert!(matches!(
        Route::of(&acceptance.destination),
        Route::FirstMessage { .. }
    ));
    assert_eq!(
        bob.contact(&alice).unwrap().trust_state,
        ContactTrustState::Unverified
    );
    let received = accepted(alice.receive(&acceptance.message));
    assert_eq!(received.plaintext.as_slice(), b"welcome");
    assert_eq!(
        alice.contact(&bob).unwrap().trust_state,
        ContactTrustState::Unverified
    );
    assert!(matches!(
        bob.receive(&received.acknowledgment.unwrap()),
        InboundMessageOutcome::AcknowledgmentMatched(_)
    ));
    let reply = alice.send(&bob, b"thanks");
    assert_eq!(reply.session_id, acceptance.session_id);
    assert_eq!(
        accepted(bob.receive(&reply.message)).plaintext.as_slice(),
        b"thanks"
    );
}

#[test]
fn a_restored_requester_cant_accept_a_contact_that_never_wrote() {
    let relay = Relay::new();
    let (mut alice, bob) = requested(&relay);
    let backup = alice.back_up();
    alice.restore(&backup);
    let mut outgoing = alice.outgoing(&bob, b"accepting my own request");
    outgoing.prekey_bundle = Some(bob.bundle());
    let before = alice.host.snapshot_bytes();

    assert!(matches!(
        alice.encrypt(redraft(&outgoing), Intent::Acceptance),
        Err(DeviceError::Operation(
            MessageOperationError::ProtocolState(ProtocolStateError::NoContactRequest)
        ))
    ));
    assert!(matches!(
        alice.encrypt(outgoing, Intent::Acceptance),
        Err(DeviceError::Operation(
            MessageOperationError::ProtocolState(ProtocolStateError::NoContactRequest)
        ))
    ));
    assert_eq!(alice.host.snapshot_bytes(), before);
}

#[test]
fn a_restored_requester_cant_send_a_grant_update_or_message_before_acceptance() {
    let relay = Relay::new();
    let (mut alice, bob) = requested(&relay);
    let backup = alice.back_up();
    alice.restore(&backup);
    let outgoing = alice.outgoing(&bob, b"still there?");
    let before = alice.host.snapshot_bytes();

    for intent in [Intent::GrantUpdate, Intent::Message] {
        let mut fetched = redraft(&outgoing);
        fetched.prekey_bundle = Some(bob.bundle());
        for draft in [redraft(&outgoing), fetched] {
            assert!(matches!(
                alice.encrypt(draft, intent),
                Err(DeviceError::Operation(
                    MessageOperationError::ProtocolState(ProtocolStateError::ContactNotAccepted)
                ))
            ));
        }
    }
    assert_eq!(alice.host.snapshot_bytes(), before);
}

#[test]
fn a_restored_requester_that_asks_again_is_accepted_on_the_new_session() {
    let relay = Relay::new();
    let (mut alice, mut bob) = requested(&relay);
    let backup = alice.back_up();
    alice.restore(&backup);

    let request = alice.send_fetching_a_bundle(&bob, b"asking again", Intent::Request);

    assert!(matches!(
        Route::of(&request.destination),
        Route::FirstMessage { .. }
    ));
    assert_eq!(
        accepted(bob.receive(&request.message)).plaintext.as_slice(),
        b"asking again"
    );
    let acceptance = bob.accept_request(&alice, b"welcome");
    assert_eq!(acceptance.session_id, request.session_id);
    assert_eq!(acceptance.payload_kind, PayloadKind::ContactAcceptance);
    let received = accepted(alice.receive(&acceptance.message));
    assert_eq!(received.plaintext.as_slice(), b"welcome");
    for (device, peer) in [(&alice, &bob), (&bob, &alice)] {
        assert_eq!(
            device.contact(peer).unwrap().trust_state,
            ContactTrustState::Unverified
        );
    }
    assert!(matches!(
        bob.receive(&received.acknowledgment.unwrap()),
        InboundMessageOutcome::AcknowledgmentMatched(_)
    ));
    let reply = alice.send(&bob, b"thanks");
    assert_eq!(reply.session_id, request.session_id);
    assert_eq!(
        accepted(bob.receive(&reply.message)).plaintext.as_slice(),
        b"thanks"
    );
}

#[test]
fn asking_again_accepts_a_restored_requester_whose_acceptance_was_lost() {
    let relay = Relay::new();
    let (mut alice, mut bob) = requested(&relay);
    let backup = alice.back_up();
    let acceptance = bob.accept_request(&alice, b"welcome");
    let acknowledgment = accepted(alice.receive(&acceptance.message))
        .acknowledgment
        .unwrap();
    assert!(matches!(
        bob.receive(&acknowledgment),
        InboundMessageOutcome::AcknowledgmentMatched(_)
    ));
    // The backup is from before the acceptance, so Bob has nothing left to resend.
    alice.restore(&backup);

    let request = alice.send_fetching_a_bundle(&bob, b"asking again", Intent::Request);
    let received = accepted(bob.receive(&request.message));
    alice.receive(&received.acknowledgment.unwrap());

    for (device, peer) in [(&alice, &bob), (&bob, &alice)] {
        assert_eq!(
            device.contact(peer).unwrap().trust_state,
            ContactTrustState::Unverified
        );
    }
    let reply = bob.send(&alice, b"glad you're back");
    assert_eq!(reply.session_id, request.session_id);
    assert_eq!(
        accepted(alice.receive(&reply.message)).plaintext.as_slice(),
        b"glad you're back"
    );
    let answer = alice.send(&bob, b"me too");
    assert_eq!(
        accepted(bob.receive(&answer.message)).plaintext.as_slice(),
        b"me too"
    );
}
