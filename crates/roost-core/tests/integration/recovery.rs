//! The sender finds Messages its contact hasn't acknowledged and recovers them on a newer Session,
//! and the contact shows each one once.

use crate::support::HostCommitError;
use crate::support::device::{
    Device, DeviceError, Intent, Recovered, Relay, Route, SentMessage, befriended,
};
use crate::support::{CREATED_AT_SECS, accepted};
use roost_core::{
    InboundMessageOutcome, MessageOperationError, ProtocolStateError, ProtocolStateKind,
};
use roost_protocol::PayloadKind;

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
    assert!(alice.host.undelivered().is_empty());
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
    alice.check_deliveries(&bob, sent_at_millis() + 31 * DAY_MILLIS);

    // The second check marks nothing again.
    assert_eq!(
        alice.host.undelivered(),
        [first.message_id, second.message_id]
    );
    assert!(!checked.starts_recovery);
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
fn a_newer_grant_recovers_each_unacknowledged_message_on_a_new_session_to_the_new_inbox() {
    let relay = Relay::new();
    let (mut alice, mut bob) = befriended(&relay);
    let waiting = alice.send(&bob, b"sent to the old inbox");
    let rotation = bob.rotate_inbox();
    let update = bob.send_grant_update(&alice);
    alice.receive(&update.message);

    let checked = alice.check_deliveries(&bob, sent_at_millis() + HOUR_MILLIS);
    assert!(checked.starts_recovery);
    let again = alice.check_deliveries(&bob, sent_at_millis() + 2 * HOUR_MILLIS);
    let probe = alice.recover(&bob, Some(bob.bundle())).committed();

    assert!(!again.starts_recovery);
    assert_eq!(probe.message_id, waiting.message_id);
    assert_ne!(probe.session_id, waiting.session_id);
    assert!(matches!(
        Route::of(&probe.destination),
        Route::FirstMessage { discovery_key, .. }
            if discovery_key == *rotation.discovery_key.public_key.as_bytes()
    ));
    assert_eq!(
        accepted(bob.receive(&probe.message)).plaintext.as_slice(),
        b"sent to the old inbox"
    );
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
    bob.host.forget_session();
    bob.forget_sessions_with(&alice);
    let restart = bob.send_fetching_a_bundle(&alice, b"I lost our chat", Intent::Message);
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
    bob.host.forget_session();
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

#[test]
fn a_recovery_resends_the_longest_message_and_every_message_after_it() {
    let relay = Relay::new();
    let (mut alice, mut bob) = befriended(&relay);
    // Bob acknowledges a Message carrying Alice's grant, so her next Messages leave it off.
    let ready = alice.send(&bob, b"ready");
    alice.receive(
        &accepted(bob.receive(&ready.message))
            .acknowledgment
            .unwrap(),
    );
    let Err(DeviceError::Operation(MessageOperationError::ProtocolState(
        ProtocolStateError::ContentTooLong { max, .. },
    ))) = alice.encrypt_to(&bob, &[0; 64 * 1024])
    else {
        panic!("expected 64 KiB of content to be refused");
    };
    let longest = alice.send(&bob, &vec![0x2a; max]);
    let after = alice.send(&bob, b"sent after it");
    assert!(
        alice
            .check_deliveries(&bob, sent_at_millis() + 2 * DAY_MILLIS)
            .starts_recovery
    );

    let probe = alice.recover(&bob, Some(bob.bundle())).committed();
    let received = accepted(bob.receive(&probe.message));
    alice.receive(&received.acknowledgment.unwrap());
    assert!(
        alice
            .check_deliveries(&bob, sent_at_millis() + 2 * DAY_MILLIS)
            .starts_recovery
    );
    let rest = alice.recover(&bob, None).committed();

    assert_eq!(longest.payload_kind, PayloadKind::EncryptedText);
    assert_eq!(probe.payload_kind, PayloadKind::EncryptedTextWithGrant);
    assert_eq!(probe.message_id, longest.message_id);
    assert_eq!(received.plaintext.len(), max);
    assert_eq!(rest.message_id, after.message_id);
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
    let sent_record = alice.host.only(ProtocolStateKind::RatchetSession);
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

    let Recovered::Resent(probe) = alice.observe_recovery(&bob, Some(bob.bundle())).unwrap() else {
        panic!("expected the probe");
    };

    assert_eq!(probe.result.message_id, sent.message_id);
    assert!(probe.changes.undelivered().is_empty());
    alice
        .host
        .commit_sent(&probe.result, probe.changes)
        .unwrap();
    assert!(alice.host.blob_bytes(&sent_record).is_none());
    assert_eq!(
        waiting_on(&alice, probe.result.session_id),
        [sent.message_id]
    );
}

#[test]
fn a_newer_session_from_the_contact_during_the_fetch_wins_over_the_bundle() {
    let relay = Relay::new();
    let (mut alice, mut bob, _) = unanswered(&relay);
    assert!(matches!(
        alice.recover(&bob, None),
        Recovered::NeedsPreKeyBundle
    ));
    let bundle = bob.bundle();
    // While Alice fetches, Bob, who lost the Session, writes on a new one.
    bob.host.forget_session();
    bob.forget_sessions_with(&alice);
    let restart = bob.send_fetching_a_bundle(&alice, b"I lost our chat", Intent::Message);
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
    alice
        .host
        .commit_sent(&first.result, first.changes)
        .unwrap();

    assert_eq!(
        alice.host.commit_sent(&second.result, second.changes).err(),
        Some(HostCommitError::StaleCondition)
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
        alice.host.commit_sent(&stale.result, stale.changes).err(),
        Some(HostCommitError::StaleCondition)
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
    bob.host.forget_session();
    bob.forget_sessions_with(&alice);
    bob.rotate_inbox();
    let restart = bob.send_fetching_a_bundle(&alice, b"new inbox, new chat", Intent::Message);
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
fn a_probe_lost_to_a_rotation_goes_out_again_on_a_new_session_once_the_newer_grant_arrives() {
    let relay = Relay::new();
    let (mut alice, mut bob, sent) = unanswered(&relay);
    let probe = alice.recover(&bob, Some(bob.bundle())).committed();
    // Bob rotates before the probe arrives, which deletes the prekeys it used, and then gives
    // Alice his new grant on the older Session he still has.
    let rotation = bob.rotate_inbox();
    let update = bob.send_grant_update(&alice);
    alice.receive(&update.message);

    let checked = alice.check_deliveries(&bob, sent_at_millis() + 3 * DAY_MILLIS);
    assert!(checked.starts_recovery);
    let resent = alice.recover(&bob, Some(bob.bundle())).committed();

    assert_eq!(resent.message_id, probe.message_id);
    assert_ne!(resent.session_id, sent.session_id);
    assert_ne!(resent.session_id, probe.session_id);
    assert!(matches!(
        Route::of(&resent.destination),
        Route::FirstMessage { discovery_key, .. }
            if discovery_key == *rotation.discovery_key.public_key.as_bytes()
    ));
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
    alice.check_deliveries(&bob, sent_at_millis() + 31 * DAY_MILLIS);

    assert!(!after_a_day.starts_recovery);
    assert_eq!(alice.host.undelivered(), [sent.message_id]);
}
