use crate::support::device::{
    Device, DeviceError, Encrypted, Intent, Relay, Route, befriended, redraft, requested,
};
use crate::support::{AppCommitError, accepted};
use roost_core::{
    InboundMessageOutcome, MessageOperationError, ProtocolStateError, ProtocolStateKind,
};

// Sends `plaintext` to `recipient`, asserting that the first attempt asks for `recipient`'s bundle.
fn send_fetching_a_bundle(
    sender: &mut Device,
    recipient: &Device,
    plaintext: &[u8],
) -> crate::support::device::SentMessage {
    let mut outgoing = sender.outgoing(recipient, plaintext);
    let Encrypted::NeedsPreKeyBundle(identity_key) =
        sender.encrypt(redraft(&outgoing), Intent::Message).unwrap()
    else {
        panic!("expected a request for the contact's bundle");
    };
    assert_eq!(identity_key, recipient.identity_key());
    outgoing.prekey_bundle = Some(recipient.bundle());
    sender.send_with(outgoing, Intent::Message)
}

#[test]
fn a_send_to_an_accepted_contact_without_its_session_list_starts_a_new_session() {
    let relay = Relay::new();
    let (mut alice, mut bob) = befriended(&relay);
    let lost = alice.send(&bob, b"before the loss").session_id;
    alice.forget_sessions_with(&bob);

    let sent = send_fetching_a_bundle(&mut alice, &bob, b"after the loss");

    assert_ne!(sent.session_id, lost);
    assert!(matches!(
        Route::of(&sent.destination),
        Route::FirstMessage { .. }
    ));
    assert!(matches!(
        bob.receive(&sent.message),
        InboundMessageOutcome::Accepted(_)
    ));
}

#[test]
fn a_send_to_an_accepted_contact_without_its_current_session_starts_a_new_session() {
    let relay = Relay::new();
    let (mut alice, mut bob) = befriended(&relay);
    let lost = alice.send(&bob, b"before the loss").session_id;
    alice.database.forget_session();

    let sent = send_fetching_a_bundle(&mut alice, &bob, b"after the loss");

    assert_ne!(sent.session_id, lost);
    assert!(matches!(
        bob.receive(&sent.message),
        InboundMessageOutcome::Accepted(_)
    ));
    assert_eq!(
        alice.send(&bob, b"on the new one").session_id,
        sent.session_id
    );
}

#[test]
fn a_session_that_lost_its_pending_acknowledgments_keeps_sending_and_tracks_new_messages() {
    let relay = Relay::new();
    let (mut alice, mut bob) = befriended(&relay);
    let kept = alice.send(&bob, b"before the loss");
    let address = alice
        .database
        .only(ProtocolStateKind::PendingAcknowledgments);
    alice.database.remove(&address);

    let sent = alice.send(&bob, b"after the loss");

    assert_eq!(sent.session_id, kept.session_id);
    let waiting = alice
        .store
        .protocol_engine()
        .pending_acknowledgments(
            sent.session_id,
            alice
                .database
                .pending_acknowledgments_record(sent.session_id)
                .as_ref(),
        )
        .unwrap();
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0].message_id, sent.message_id);
    accepted(bob.receive(&kept.message));
    assert_eq!(
        accepted(bob.receive(&sent.message)).plaintext.as_slice(),
        b"after the loss"
    );
}

#[test]
fn an_acknowledgment_on_a_session_that_lost_its_pending_acknowledgments_is_unmatched_once() {
    let relay = Relay::new();
    let (mut alice, mut bob) = befriended(&relay);
    let sent = alice.send(&bob, b"before the loss");
    let acknowledgment = accepted(bob.receive(&sent.message)).acknowledgment.unwrap();
    let address = alice
        .database
        .only(ProtocolStateKind::PendingAcknowledgments);
    alice.database.remove(&address);

    let outcome = alice.receive(&acknowledgment);

    assert!(matches!(
        outcome,
        InboundMessageOutcome::AcknowledgmentUnmatched(_)
    ));
    alice.forget_received_digests();
    assert!(matches!(
        alice.receive(&acknowledgment),
        InboundMessageOutcome::Duplicate
    ));
}

#[test]
fn a_new_session_for_missing_records_fails_to_commit_when_they_exist_after_all() {
    let relay = Relay::new();
    let (mut alice, bob) = befriended(&relay);
    let complete = alice.database.clone();
    alice.forget_sessions_with(&bob);
    let mut outgoing = alice.outgoing(&bob, b"after the loss");
    outgoing.prekey_bundle = Some(bob.bundle());

    let sealed = alice.encrypt(outgoing, Intent::Message).unwrap().ready();

    alice.database = complete;
    assert_eq!(
        alice
            .database
            .commit_sent(&sealed.result, sealed.changes)
            .err(),
        Some(AppCommitError::StaleCondition)
    );
}

#[test]
fn a_message_to_a_requester_whose_sessions_are_missing_is_refused() {
    let relay = Relay::new();
    let (alice, mut bob) = requested(&relay);
    bob.forget_sessions_with(&alice);
    let mut outgoing = bob.outgoing(&alice, b"who is this?");
    outgoing.prekey_bundle = Some(alice.bundle());

    assert!(matches!(
        bob.encrypt(outgoing, Intent::Message),
        Err(DeviceError::Operation(
            MessageOperationError::ProtocolState(ProtocolStateError::ContactNotAccepted)
        ))
    ));
}

#[test]
fn a_late_message_on_a_session_the_lost_list_no_longer_keeps_names_an_unknown_session() {
    let relay = Relay::new();
    let (mut alice, mut bob) = befriended(&relay);
    let on_its_way = bob.send(&alice, b"sent before alice's new session");
    // The app keeps the session's own record but loses the list that keeps it.
    alice.forget_sessions_with(&bob);
    send_fetching_a_bundle(&mut alice, &bob, b"after the loss");
    let before = alice.database.snapshot_bytes();

    assert!(matches!(
        alice.receive(&on_its_way.message),
        InboundMessageOutcome::UnknownSession
    ));
    assert_eq!(alice.database.snapshot_bytes(), before);
}
