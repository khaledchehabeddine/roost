//! The sender finds Messages its contact hasn't acknowledged, resends them once to a newer inbox,
//! and recovers them on a newer Session, and the contact shows each one once.

mod support;

use roost_core::InboundMessageOutcome;
use roost_protocol::PayloadKind;
use support::HostCommitError;
use support::device::{
    Device, Encrypted, Intent, Recovered, Relay, Route, SentMessage, befriended, redraft,
};
use support::{CREATED_AT_SECS, accepted};

const HOUR_MILLIS: u64 = 60 * 60 * 1000;
const DAY_MILLIS: u64 = 24 * HOUR_MILLIS;

// Every test Message is sent within a second of this time.
fn sent_at_millis() -> u64 {
    CREATED_AT_SECS * 1000
}

#[test]
fn a_message_unacknowledged_for_less_than_a_day_signals_nothing() {
    let relay = Relay::new();
    let (mut alice, bob) = befriended(&relay);
    alice.send(&bob, b"are you there?");

    let checked = alice.check_deliveries(&bob, sent_at_millis() + DAY_MILLIS - HOUR_MILLIS);

    assert!(!checked.starts_recovery);
    assert!(checked.retries.is_empty());
    assert!(checked.changes.undelivered().is_empty());
}

#[test]
fn a_day_without_an_acknowledgment_signals_one_recovery() {
    let relay = Relay::new();
    let (mut alice, bob) = befriended(&relay);
    alice.send(&bob, b"are you there?");

    let first = alice.check_deliveries(&bob, sent_at_millis() + DAY_MILLIS + HOUR_MILLIS);
    let next_check = alice.check_deliveries(&bob, sent_at_millis() + 2 * DAY_MILLIS);
    alice.restart();
    let after_a_restart = alice.check_deliveries(&bob, sent_at_millis() + 3 * DAY_MILLIS);

    assert!(first.starts_recovery);
    assert!(!next_check.starts_recovery);
    assert!(!after_a_restart.starts_recovery);
}

#[test]
fn an_acknowledged_message_signals_nothing() {
    let relay = Relay::new();
    let (mut alice, mut bob) = befriended(&relay);
    let sent = alice.send(&bob, b"are you there?");
    let acknowledgment = accepted(bob.receive(&sent.message)).acknowledgment.unwrap();
    alice.receive(&acknowledgment);

    let checked = alice.check_deliveries(&bob, sent_at_millis() + 2 * DAY_MILLIS);

    assert!(!checked.starts_recovery);
}

#[test]
fn an_unacknowledged_recovery_is_signaled_again_after_seven_days() {
    let relay = Relay::new();
    let (mut alice, bob) = befriended(&relay);
    alice.send(&bob, b"are you there?");
    assert!(
        alice
            .check_deliveries(&bob, sent_at_millis() + 2 * DAY_MILLIS)
            .starts_recovery
    );

    let before_the_recheck =
        alice.check_deliveries(&bob, sent_at_millis() + 9 * DAY_MILLIS - HOUR_MILLIS);
    let at_the_recheck = alice.check_deliveries(&bob, sent_at_millis() + 9 * DAY_MILLIS);

    assert!(!before_the_recheck.starts_recovery);
    assert!(at_the_recheck.starts_recovery);
}

#[test]
fn messages_unacknowledged_for_thirty_days_show_as_not_delivered_once() {
    let relay = Relay::new();
    let (mut alice, bob) = befriended(&relay);
    let first = alice.send(&bob, b"first");
    let second = alice.send(&bob, b"second");

    let checked = alice.check_deliveries(&bob, sent_at_millis() + 30 * DAY_MILLIS + HOUR_MILLIS);
    let again = alice.check_deliveries(&bob, sent_at_millis() + 31 * DAY_MILLIS);

    assert_eq!(
        checked.changes.undelivered(),
        [first.message_id, second.message_id]
    );
    assert!(!checked.starts_recovery);
    assert!(again.changes.undelivered().is_empty());
    assert!(
        alice
            .store
            .protocol_engine()
            .pending_acknowledgments(&alice.host.snapshot(), first.session_id)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn a_newer_grant_resends_each_unacknowledged_message_once_to_the_new_inbox() {
    let relay = Relay::new();
    let (mut alice, mut bob) = befriended(&relay);
    let waiting = alice.send(&bob, b"sent to the old inbox");
    let rotation = bob.rotate_inbox();
    let update = bob.send_grant_update(&alice);
    alice.receive(&update.message);

    let checked = alice.check_deliveries(&bob, sent_at_millis() + HOUR_MILLIS);
    let again = alice.check_deliveries(&bob, sent_at_millis() + 2 * HOUR_MILLIS);

    let [retry] = &checked.retries[..] else {
        panic!("expected one retry");
    };
    assert_eq!(retry.message_id, waiting.message_id);
    assert_eq!(
        retry.message.to_bytes().unwrap(),
        waiting.message.to_bytes().unwrap()
    );
    assert_eq!(Route::of(&retry.destination), bob.established_route());
    assert_eq!(
        support::device::established_verifier(&retry.destination),
        rotation.recipient_delivery_verifier
    );
    assert!(again.retries.is_empty());
    assert_eq!(
        accepted(bob.receive(&retry.message)).plaintext.as_slice(),
        b"sent to the old inbox"
    );
}

#[test]
fn a_resend_to_a_newer_inbox_restarts_the_wait_before_a_recovery() {
    let relay = Relay::new();
    let (mut alice, mut bob) = befriended(&relay);
    alice.send(&bob, b"sent to the old inbox");
    bob.rotate_inbox();
    let update = bob.send_grant_update(&alice);
    assert!(matches!(
        alice.receive(&update.message),
        InboundMessageOutcome::GrantUpdate(_)
    ));

    let retried = alice.check_deliveries(&bob, sent_at_millis() + 2 * DAY_MILLIS);
    let a_day_later = alice.check_deliveries(&bob, sent_at_millis() + 3 * DAY_MILLIS);

    assert_eq!(retried.retries.len(), 1);
    assert!(!retried.starts_recovery);
    assert!(a_day_later.starts_recovery);
}

// Sends `plaintext` from `sender` to `recipient`, fetching `recipient`'s bundle when asked.
fn send_fetching_a_bundle(
    sender: &mut Device,
    recipient: &Device,
    plaintext: &[u8],
) -> SentMessage {
    let mut outgoing = sender.outgoing(recipient, plaintext);
    if let Encrypted::NeedsPreKeyBundle(_) =
        sender.encrypt(redraft(&outgoing), Intent::Message).unwrap()
    {
        outgoing.prekey_bundle = Some(recipient.bundle());
    }
    sender.send_with(outgoing, Intent::Message)
}

// Returns the MessageIDs `device` still waits to have acknowledged on `session_id`.
fn waiting_on(
    device: &Device,
    session_id: roost_core::SessionId,
) -> Vec<roost_protocol::MessageId> {
    device
        .store
        .protocol_engine()
        .pending_acknowledgments(&device.host.snapshot(), session_id)
        .map(|pending| pending.into_iter().map(|entry| entry.message_id).collect())
        .unwrap_or_default()
}

#[test]
fn a_contact_that_starts_a_new_session_gets_each_unacknowledged_message_again_on_it() {
    let relay = Relay::new();
    let (mut alice, mut bob) = befriended(&relay);
    let first = alice.send(&bob, b"first");
    let second = alice.send(&bob, b"second");
    // Bob loses his Session with Alice before either arrives, and writes on a new one.
    bob.host.forget_session(first.session_id);
    bob.forget_sessions_with(&alice);
    let restart = send_fetching_a_bundle(&mut bob, &alice, b"I lost our chat");
    alice.receive(&restart.message);

    let checked = alice.check_deliveries(&bob, sent_at_millis() + HOUR_MILLIS);
    let resent_first = alice.recover(&bob, None).committed();
    let resent_second = alice.recover(&bob, None).committed();

    assert!(checked.starts_recovery);
    assert!(matches!(alice.recover(&bob, None), Recovered::Finished));
    for (resent, original) in [(&resent_first, &first), (&resent_second, &second)] {
        assert_eq!(resent.session_id, restart.session_id);
        assert_eq!(resent.message_id, original.message_id);
        assert_eq!(Route::of(&resent.destination), bob.established_route());
        // Bob may have lost Alice's grant with the Session.
        assert_eq!(resent.payload_kind, PayloadKind::EncryptedTextWithGrant);
    }
    assert!(waiting_on(&alice, first.session_id).is_empty());
    assert_eq!(
        waiting_on(&alice, restart.session_id),
        [first.message_id, second.message_id]
    );
    assert!(matches!(
        bob.receive(&first.message),
        InboundMessageOutcome::UnknownSession
    ));
    let received = accepted(bob.receive(&resent_first.message));
    assert_eq!(received.message_id, first.message_id);
    assert_eq!(
        received.sent_at_millis,
        sent_at_millis() + u64::from(first.message_id.as_bytes()[1])
    );
    assert_eq!(received.plaintext.as_slice(), b"first");
    assert_eq!(
        accepted(bob.receive(&resent_second.message))
            .plaintext
            .as_slice(),
        b"second"
    );
}

#[test]
fn a_silent_contact_gets_one_probe_on_a_new_session_and_the_rest_once_it_acknowledges() {
    let relay = Relay::new();
    let (mut alice, mut bob) = befriended(&relay);
    let first = alice.send(&bob, b"first");
    let second = alice.send(&bob, b"second");
    // Bob loses the Session but keeps Alice as a contact, so he can't tell she wrote.
    bob.host.forget_session(first.session_id);
    assert!(
        alice
            .check_deliveries(&bob, sent_at_millis() + 2 * DAY_MILLIS)
            .starts_recovery
    );

    assert!(matches!(
        alice.recover(&bob, None),
        Recovered::NeedsPreKeyBundle
    ));
    let probe = alice.recover(&bob, Some(bob.bundle())).committed();
    assert!(matches!(
        alice.recover(&bob, None),
        Recovered::AwaitingProbe(id) if id == first.message_id
    ));

    assert_eq!(probe.message_id, first.message_id);
    assert_ne!(probe.session_id, first.session_id);
    assert!(matches!(
        Route::of(&probe.destination),
        Route::FirstMessage { .. }
    ));
    assert_eq!(waiting_on(&alice, first.session_id), [second.message_id]);
    let received = accepted(bob.receive(&probe.message));
    assert_eq!(received.plaintext.as_slice(), b"first");
    assert!(
        !alice
            .check_deliveries(&bob, sent_at_millis() + 2 * DAY_MILLIS)
            .starts_recovery
    );
    assert!(matches!(
        alice.receive(&received.acknowledgment.unwrap()),
        InboundMessageOutcome::AcknowledgmentMatched(_)
    ));
    // The acknowledgment signals the rest, even when the app ended the job at the probe.
    assert!(
        alice
            .check_deliveries(&bob, sent_at_millis() + 2 * DAY_MILLIS)
            .starts_recovery
    );
    let rest = alice.recover(&bob, None).committed();
    assert_eq!(rest.message_id, second.message_id);
    assert_eq!(rest.session_id, probe.session_id);
    assert_eq!(Route::of(&rest.destination), bob.established_route());
    assert!(matches!(alice.recover(&bob, None), Recovered::Finished));
    assert_eq!(
        accepted(bob.receive(&rest.message)).plaintext.as_slice(),
        b"second"
    );
}

// Alice sends Bob a Message he never acknowledges, and a day later starts a recovery.
fn unanswered(relay: &Relay) -> (Device, Device, SentMessage) {
    let (mut alice, bob) = befriended(relay);
    let sent = alice.send(&bob, b"are you there?");
    assert!(
        alice
            .check_deliveries(&bob, sent_at_millis() + 2 * DAY_MILLIS)
            .starts_recovery
    );
    (alice, bob, sent)
}

#[test]
fn an_unacknowledged_probe_is_sent_again_on_another_session_after_the_recheck() {
    let relay = Relay::new();
    let (mut alice, bob, sent) = unanswered(&relay);
    let probe = alice.recover(&bob, Some(bob.bundle())).committed();
    assert!(
        !alice
            .check_deliveries(&bob, sent_at_millis() + 8 * DAY_MILLIS)
            .starts_recovery
    );

    assert!(
        alice
            .check_deliveries(&bob, sent_at_millis() + 9 * DAY_MILLIS)
            .starts_recovery
    );
    let again = alice.recover(&bob, Some(bob.bundle())).committed();

    assert_eq!(again.message_id, sent.message_id);
    assert_ne!(again.session_id, probe.session_id);
    assert!(waiting_on(&alice, probe.session_id).is_empty());
    assert_eq!(waiting_on(&alice, again.session_id), [sent.message_id]);
}

#[test]
fn a_probe_that_evicts_its_own_session_isnt_listed_as_undelivered() {
    let relay = Relay::new();
    let (mut alice, bob) = befriended(&relay);
    let sent = alice.send(&bob, b"are you there?");
    // Each rotation makes Alice's next send start a Session, until hers with the Message is the
    // oldest one kept.
    for _ in 0..5 {
        bob.rotate_inbox();
        let mut outgoing = alice.outgoing(&bob, b"to the newer inbox");
        outgoing.prekey_bundle = Some(bob.bundle());
        alice.send_with(outgoing, Intent::Message);
    }
    assert!(
        alice
            .check_deliveries(&bob, sent_at_millis() + 2 * DAY_MILLIS)
            .starts_recovery
    );

    let Recovered::Resent(resent) = alice.observe_recovery(&bob, Some(bob.bundle())).unwrap()
    else {
        panic!("expected the probe");
    };
    let (probe, _) = *resent;

    assert_eq!(probe.message_id, sent.message_id);
    assert!(probe.changes.undelivered().is_empty());
    let probe_session = probe.session_id;
    alice.host.commit_sent(probe).unwrap();
    assert!(
        alice
            .host
            .blob_bytes(&support::session_address(sent.session_id))
            .is_none()
    );
    assert_eq!(waiting_on(&alice, probe_session), [sent.message_id]);
}

#[test]
fn a_newer_session_from_the_contact_during_the_fetch_wins_over_the_bundle() {
    let relay = Relay::new();
    let (mut alice, mut bob, sent) = unanswered(&relay);
    assert!(matches!(
        alice.recover(&bob, None),
        Recovered::NeedsPreKeyBundle
    ));
    let bundle = bob.bundle();
    // While Alice fetches, Bob, who lost the Session, writes on a new one.
    bob.host.forget_session(sent.session_id);
    bob.forget_sessions_with(&alice);
    let restart = send_fetching_a_bundle(&mut bob, &alice, b"I lost our chat");
    alice.receive(&restart.message);

    let resent = alice.recover(&bob, Some(bundle)).committed();

    assert_eq!(resent.session_id, restart.session_id);
    assert_eq!(Route::of(&resent.destination), bob.established_route());
    assert!(matches!(alice.recover(&bob, None), Recovered::Finished));
}

#[test]
fn of_two_processes_recovering_at_once_only_the_first_commits() {
    let relay = Relay::new();
    let (mut alice, bob, sent) = unanswered(&relay);
    let mut extension = alice.second_instance_device();

    let Recovered::Resent(first) = alice.observe_recovery(&bob, Some(bob.bundle())).unwrap() else {
        panic!("expected a resend");
    };
    let Recovered::Resent(second) = extension
        .observe_recovery(&bob, Some(bob.bundle()))
        .unwrap()
    else {
        panic!("expected a resend");
    };
    alice.host.commit_sent(first.0).unwrap();

    assert_eq!(
        alice.host.commit_sent(second.0),
        Err(HostCommitError::StaleCondition)
    );
    extension.host = alice.host.clone();
    assert!(matches!(
        extension.recover(&bob, None),
        Recovered::AwaitingProbe(id) if id == sent.message_id
    ));
}

#[test]
fn a_recovery_whose_message_is_acknowledged_meanwhile_fails_to_commit_and_finishes() {
    let relay = Relay::new();
    let (mut alice, mut bob, sent) = unanswered(&relay);
    let Recovered::Resent(stale) = alice.observe_recovery(&bob, Some(bob.bundle())).unwrap() else {
        panic!("expected a resend");
    };
    // Bob was only offline, and his acknowledgment arrives first.
    let acknowledgment = accepted(bob.receive(&sent.message)).acknowledgment.unwrap();
    alice.receive(&acknowledgment);

    assert_eq!(
        alice.host.commit_sent(stale.0),
        Err(HostCommitError::StaleCondition)
    );
    assert!(matches!(
        alice.recover(&bob, Some(bob.bundle())),
        Recovered::Finished
    ));
    assert!(
        !alice
            .check_deliveries(&bob, sent_at_millis() + 3 * DAY_MILLIS)
            .starts_recovery
    );
}

#[test]
fn an_unneeded_recovery_reaches_the_contact_twice_under_one_message_id() {
    let relay = Relay::new();
    let (mut alice, mut bob, sent) = unanswered(&relay);
    let probe = alice.recover(&bob, Some(bob.bundle())).committed();

    // Bob was only offline, so both copies arrive and both decrypt.
    let original = accepted(bob.receive(&sent.message));
    let copy = accepted(bob.receive(&probe.message));

    assert_eq!(original.message_id, sent.message_id);
    assert_eq!(copy.message_id, sent.message_id);
    assert_eq!(original.plaintext, copy.plaintext);
    assert!(matches!(
        alice.receive(&original.acknowledgment.unwrap()),
        InboundMessageOutcome::AcknowledgmentUnmatched(_)
    ));
    assert!(matches!(
        alice.receive(&copy.acknowledgment.unwrap()),
        InboundMessageOutcome::AcknowledgmentMatched(_)
    ));
    assert!(matches!(alice.recover(&bob, None), Recovered::Finished));
}

#[test]
fn a_recovery_nobody_signaled_resends_nothing() {
    let relay = Relay::new();
    let (mut alice, bob) = befriended(&relay);
    alice.send(&bob, b"are you there?");
    let before = alice.host.snapshot_bytes();

    assert!(matches!(
        alice.recover(&bob, Some(bob.bundle())),
        Recovered::Finished
    ));
    assert_eq!(alice.host.snapshot_bytes(), before);
}

#[test]
fn after_the_relay_refuses_the_fetch_only_the_contacts_new_session_signals_again() {
    let relay = Relay::new();
    let (mut alice, mut bob, sent) = unanswered(&relay);
    // The Relay doesn't know Bob's old Discovery Key, so Alice's app ends the recovery job.
    assert!(matches!(
        alice.recover(&bob, None),
        Recovered::NeedsPreKeyBundle
    ));
    assert!(
        !alice
            .check_deliveries(&bob, sent_at_millis() + 4 * DAY_MILLIS)
            .starts_recovery
    );
    bob.host.forget_session(sent.session_id);
    bob.forget_sessions_with(&alice);
    bob.rotate_inbox();
    let restart = send_fetching_a_bundle(&mut bob, &alice, b"new inbox, new chat");
    alice.receive(&restart.message);

    assert!(
        alice
            .check_deliveries(&bob, sent_at_millis() + 4 * DAY_MILLIS)
            .starts_recovery
    );
    let resent = alice.recover(&bob, None).committed();
    assert_eq!(resent.session_id, restart.session_id);
    assert_eq!(
        accepted(bob.receive(&resent.message)).message_id,
        sent.message_id
    );
}

#[test]
fn a_probe_lost_to_the_contacts_rotation_is_recovered_once_its_newer_grant_arrives() {
    let relay = Relay::new();
    let (mut alice, mut bob, sent) = unanswered(&relay);
    let probe = alice.recover(&bob, Some(bob.bundle())).committed();
    // Bob rotates before the probe arrives, which deletes the prekeys it used, and then gives
    // Alice his new grant on the Session he still has.
    let rotation = bob.rotate_inbox();
    let update = bob.send_grant_update(&alice);
    alice.receive(&update.message);

    let checked = alice.check_deliveries(&bob, sent_at_millis() + 3 * DAY_MILLIS);
    let resent = alice.recover(&bob, None).committed();

    assert!(checked.retries.is_empty());
    assert!(checked.starts_recovery);
    assert_eq!(resent.message_id, probe.message_id);
    assert_eq!(resent.session_id, sent.session_id);
    assert_eq!(
        support::device::established_verifier(&resent.destination),
        rotation.recipient_delivery_verifier
    );
    assert_eq!(
        accepted(bob.receive(&resent.message)).message_id,
        sent.message_id
    );
}

#[test]
fn messages_to_a_blocked_contact_still_show_as_not_delivered_but_are_never_recovered() {
    let relay = Relay::new();
    let (mut alice, bob) = befriended(&relay);
    let sent = alice.send(&bob, b"before the block");
    alice.block(bob.identity_key());

    let after_a_day = alice.check_deliveries(&bob, sent_at_millis() + 2 * DAY_MILLIS);
    let after_thirty_days = alice.check_deliveries(&bob, sent_at_millis() + 31 * DAY_MILLIS);

    assert!(!after_a_day.starts_recovery);
    assert_eq!(after_thirty_days.changes.undelivered(), [sent.message_id]);
}

#[test]
fn a_recovery_runs_again_after_a_lost_commit_and_moves_on_after_one_that_landed() {
    let relay = Relay::new();
    let (mut alice, bob, sent) = unanswered(&relay);
    // The app dies before committing the first resend.
    let Recovered::Resent(_) = alice.observe_recovery(&bob, Some(bob.bundle())).unwrap() else {
        panic!("expected a resend");
    };

    let committed = alice.recover(&bob, Some(bob.bundle())).committed();
    // The app can't tell whether that commit landed, so it runs the recovery again.
    let again = alice.recover(&bob, Some(bob.bundle()));

    assert_eq!(committed.message_id, sent.message_id);
    assert!(matches!(again, Recovered::AwaitingProbe(id) if id == sent.message_id));
    assert!(waiting_on(&alice, sent.session_id).is_empty());
    assert_eq!(waiting_on(&alice, committed.session_id), [sent.message_id]);
}
