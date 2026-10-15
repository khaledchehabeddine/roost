//! A send to a contact whose Session records the host lost starts a new Session from a fetched
//! bundle, and refuses to when the contact isn't accepted.

mod support;

use roost_core::{InboundMessageOutcome, MessageOperationError, ProtocolStateError};
use support::HostCommitError;
use support::device::{
    Device, DeviceError, Encrypted, Intent, Relay, Route, befriended, redraft, requested,
};

// Sends `plaintext` from `sender` to `recipient`, fetching `recipient`'s bundle when asked, as the
// app restarts an attempt that ends with `NeedsPreKeyBundle`.
fn send_fetching_a_bundle(
    sender: &mut Device,
    recipient: &Device,
    plaintext: &[u8],
) -> support::device::SentMessage {
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
    alice.host.forget_session(lost);

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
fn a_new_session_for_missing_records_fails_to_commit_when_they_exist_after_all() {
    let relay = Relay::new();
    let (mut alice, bob) = befriended(&relay);
    let complete = alice.host.clone();
    alice.forget_sessions_with(&bob);
    let mut outgoing = alice.outgoing(&bob, b"after the loss");
    outgoing.prekey_bundle = Some(bob.bundle());

    let (result, _) = alice.encrypt(outgoing, Intent::Message).unwrap().ready();

    alice.host = complete;
    assert_eq!(
        alice.host.commit_sent(result),
        Err(HostCommitError::StaleCondition)
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
