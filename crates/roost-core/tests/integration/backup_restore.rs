//! Restoring a backup brings back every contact, and each contact can send and receive again right
//! away on new sessions. The exception is a contact the restored side asked that hasn't accepted.
//! The restored side loses any acceptance sent on the old session and can only send that contact a
//! new contact request. Both sides end up accepted whether the contact accepts before or after it.

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
    // The relay still delivers the first copies, which name the session Bob no longer has.
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
fn a_restored_side_talks_both_ways_with_a_contact_that_rotated_after_the_backup() {
    let relay = Relay::new();
    let (mut alice, mut bob) = befriended(&relay);
    let backup = bob.back_up();
    alice.rotate_inbox();
    let update = alice.send_grant_update(&bob);
    let InboundMessageOutcome::GrantUpdate(received) = bob.receive(&update.message) else {
        panic!("expected a grant update");
    };
    // Bob's old phone acknowledges Alice's new grant before it breaks.
    alice.receive(&received.acknowledgment.unwrap());
    // Bob's restored record holds Alice's old discovery key, and her bundle shows the new one.
    bob.restore(&backup);

    let reconnect = bob.send_fetching_a_bundle(&alice, b"", Intent::GrantUpdate);
    let InboundMessageOutcome::GrantUpdate(received) = alice.receive(&reconnect.message) else {
        panic!("expected a grant update");
    };
    bob.receive(&received.acknowledgment.unwrap());

    let from_alice = alice.send(&bob, b"found you");
    assert_eq!(from_alice.session_id, reconnect.session_id);
    let received = accepted(bob.receive(&from_alice.message));
    assert_eq!(received.plaintext.as_slice(), b"found you");
    assert!(matches!(
        alice.receive(&received.acknowledgment.unwrap()),
        InboundMessageOutcome::AcknowledgmentMatched(_)
    ));
    let from_bob = bob.send(&alice, b"found you too");
    assert_eq!(from_bob.session_id, reconnect.session_id);
    assert_eq!(
        accepted(alice.receive(&from_bob.message))
            .plaintext
            .as_slice(),
        b"found you too"
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
    let before = alice.database.snapshot_bytes();

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
    assert_eq!(alice.database.snapshot_bytes(), before);
}

#[test]
fn a_restored_requester_cant_send_a_grant_update_or_message_before_acceptance() {
    let relay = Relay::new();
    let (mut alice, bob) = requested(&relay);
    let backup = alice.back_up();
    alice.restore(&backup);
    let outgoing = alice.outgoing(&bob, b"still there?");
    let before = alice.database.snapshot_bytes();

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
    assert_eq!(alice.database.snapshot_bytes(), before);
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
    // Alice acknowledged the acceptance, so Bob has nothing to resend, but her backup predates it.
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

#[test]
fn a_restored_requester_that_used_up_the_limit_asks_again_within_the_asked_sides_limit() {
    let relay = Relay::new();
    let (mut alice, mut bob) = requested(&relay);
    for follow_up in [b"hello?".as_slice(), b"still there?"] {
        let sent = alice.send(&bob, follow_up);
        accepted(bob.receive(&sent.message));
    }
    let backup = alice.back_up();
    alice.restore(&backup);

    let request = alice.send_fetching_a_bundle(&bob, b"asking again", Intent::Request);

    // Bob already received all the messages Alice may send him before he accepts.
    let InboundMessageOutcome::Withheld(withheld) = bob.receive(&request.message) else {
        panic!("expected the new request withheld");
    };
    assert_eq!(withheld.message_id, request.message_id);
    let acceptance = bob.accept_request(&alice, b"welcome");
    assert_eq!(acceptance.session_id, request.session_id);
    accepted(alice.receive(&acceptance.message));
    for (device, peer) in [(&alice, &bob), (&bob, &alice)] {
        assert_eq!(
            device.contact(peer).unwrap().trust_state,
            ContactTrustState::Unverified
        );
    }
}

#[test]
fn a_restored_requester_asking_a_contact_that_rotated_since_the_backup_counts_from_zero() {
    let relay = Relay::new();
    let (mut alice, mut bob) = requested(&relay);
    for follow_up in [b"hello?".as_slice(), b"still there?"] {
        let sent = alice.send(&bob, follow_up);
        accepted(bob.receive(&sent.message));
    }
    // The backup counts all the messages Alice may send before acceptance.
    let backup = alice.back_up();
    alice.restore(&backup);
    let rotation = bob.rotate_inbox();

    let request = alice.send_fetching_a_bundle(&bob, b"asking again", Intent::Request);

    assert!(matches!(
        Route::of(&request.destination),
        Route::FirstMessage { discovery_key, .. }
            if discovery_key == *rotation.discovery_key.public_key.as_bytes()
    ));
}
