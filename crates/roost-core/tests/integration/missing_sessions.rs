//! A send to a contact whose session records the host lost starts a new session from a fetched
//! bundle, and refuses to when the contact isn't accepted. A session that lost only its pending
//! acknowledgments keeps working. A message on a session the records no longer keep names an
//! unknown session.

use crate::support::device::{
    Device, DeviceError, Encrypted, Intent, Relay, Route, befriended, redraft, requested,
};
use crate::support::{HostCommitError, accepted};
use roost_core::{
    InboundMessageOutcome, MessageOperationError, ProtocolStateError, ProtocolStateKind,
};

// Sends `plaintext` from `sender` to `recipient`, fetching `recipient`'s bundle when asked, as the
// app restarts an attempt that ends with `NeedsPreKeyBundle`.
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
    alice.host.forget_session();

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
    let address = alice.host.only(ProtocolStateKind::PendingAcknowledgments);
    alice.host.remove(&address);

    let sent = alice.send(&bob, b"after the loss");

    assert_eq!(sent.session_id, kept.session_id);
    let waiting = alice
        .store
        .protocol_engine()
        .pending_acknowledgments(&alice.host.snapshot(), sent.session_id)
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
    let address = alice.host.only(ProtocolStateKind::PendingAcknowledgments);
    alice.host.remove(&address);

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
    let complete = alice.host.clone();
    alice.forget_sessions_with(&bob);
    let mut outgoing = alice.outgoing(&bob, b"after the loss");
    outgoing.prekey_bundle = Some(bob.bundle());

    let sealed = alice.encrypt(outgoing, Intent::Message).unwrap().ready();

    alice.host = complete;
    assert_eq!(
        alice.host.commit_sent(&sealed.result, sealed.changes).err(),
        Some(HostCommitError::StaleCondition)
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
    // The host keeps the session's own record but loses the list that keeps it.
    alice.forget_sessions_with(&bob);
    send_fetching_a_bundle(&mut alice, &bob, b"after the loss");
    let before = alice.host.snapshot_bytes();

    assert!(matches!(
        alice.receive(&on_its_way.message),
        InboundMessageOutcome::UnknownSession
    ));
    assert_eq!(alice.host.snapshot_bytes(), before);
}
