//! Two identities that have never met request, accept, and message each other through Message
//! Operations, committing every result through the host.

use std::time::Duration;

use crate::support::accepted;
use crate::support::device::{
    Device, Encrypted, Intent, Relay, befriended, established_verifier, requested,
};
use roost_core::{
    BlockedContactAcknowledgmentPolicy, ContactTrustState, InboundMessageOutcome,
    MessageDestination, ProtocolHardeningLimits, ProtocolStateKind, ReceiveSettings,
};
use roost_protocol::PayloadKind;

fn first_message_route(destination: &MessageDestination) -> (u64, Option<u64>) {
    match destination {
        MessageDestination::FirstMessage {
            signed_prekey_id,
            one_time_prekey_id,
            ..
        } => (*signed_prekey_id, *one_time_prekey_id),
        MessageDestination::Established { .. } => panic!("expected a first Message"),
    }
}

#[test]
fn a_request_without_a_bundle_asks_for_one_and_records_nothing() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let bob = Device::new(&relay, 0xb0);
    let before = alice.host.snapshot_bytes();

    let outgoing = alice.outgoing(&bob, b"hi bob");
    let Encrypted::NeedsPreKeyBundle(identity_key) =
        alice.encrypt(outgoing, Intent::Request).unwrap()
    else {
        panic!("expected a request for Bob's bundle");
    };

    assert_eq!(identity_key, bob.identity_key());
    assert_eq!(alice.host.snapshot_bytes(), before);
}

#[test]
fn a_request_routes_to_the_bundles_prekeys_and_records_a_pending_contact() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let bob = Device::new(&relay, 0xb0);
    let bundle = bob.bundle();
    let expected_route = (
        bundle.bundle.signed_prekey.id,
        bundle
            .bundle
            .one_time_prekey
            .as_ref()
            .map(|prekey| prekey.id),
    );
    let mut outgoing = alice.outgoing(&bob, b"hi bob");
    outgoing.prekey_bundle = Some(bundle);

    let request = alice.send_with(outgoing, Intent::Request);

    assert_eq!(first_message_route(&request.destination), expected_route);
    assert_eq!(request.payload_kind, PayloadKind::EncryptedTextWithGrant);
    let contact = alice.contact(&bob).unwrap();
    assert_eq!(contact.trust_state, ContactTrustState::Pending);
    assert_eq!(
        contact.discovery_key.unwrap().x25519_public_key,
        *bob.publication().discovery_key.public_key.as_bytes()
    );
}

#[test]
fn the_asked_side_gets_a_contact_request_and_acknowledges_nothing() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    let request = alice.request(&bob, b"hi bob");

    let received = bob.observe(&request.message).unwrap();

    assert!(received.acknowledgment_destination.is_none());
    let InboundMessageOutcome::ContactRequest(result) = received.outcome else {
        panic!("expected a contact request");
    };
    assert_eq!(result.plaintext.as_slice(), b"hi bob");
    assert!(result.acknowledgment.is_none());
    bob.commit_changes(received.changes).unwrap();
    let contact = bob.contact(&alice).unwrap();
    assert_eq!(contact.trust_state, ContactTrustState::Pending);
    assert!(!contact.blocked);
}

#[test]
fn a_reply_before_acceptance_reaches_the_requester_with_its_capability_and_no_grant() {
    let relay = Relay::new();
    let (mut alice, mut bob) = requested(&relay);

    let reply = bob.send(&alice, b"who is this?");

    assert_eq!(
        established_verifier(&reply.destination),
        alice.publication().recipient_delivery_verifier
    );
    assert_eq!(reply.payload_kind, PayloadKind::EncryptedText);
    let received = accepted(alice.receive(&reply.message));
    assert_eq!(received.plaintext.as_slice(), b"who is this?");
    assert!(received.acknowledgment.is_none());
    assert_eq!(
        alice.contact(&bob).unwrap().trust_state,
        ContactTrustState::Pending
    );
}

#[test]
fn the_requester_keeps_sending_first_messages_until_acceptance() {
    let relay = Relay::new();
    let (mut alice, mut bob) = requested(&relay);
    let reply = bob.send(&alice, b"who is this?");
    alice.receive(&reply.message);

    let follow_up = alice.send(&bob, b"it's alice");

    first_message_route(&follow_up.destination);
    assert_eq!(follow_up.payload_kind, PayloadKind::EncryptedTextWithGrant);
}

#[test]
fn the_asked_side_acknowledges_only_after_its_first_reply() {
    let relay = Relay::new();
    let (mut alice, mut bob) = requested(&relay);
    let second = alice.send(&bob, b"second");
    assert!(
        accepted(bob.receive(&second.message))
            .acknowledgment
            .is_none()
    );

    bob.send(&alice, b"who is this?");
    let third = alice.send(&bob, b"third");
    let received = bob.observe(&third.message).unwrap();

    assert_eq!(
        established_verifier(&received.acknowledgment_destination.unwrap()),
        alice.publication().recipient_delivery_verifier
    );
    assert!(accepted(received.outcome).acknowledgment.is_some());
}

#[test]
fn an_acceptance_shares_the_asked_sides_grant_and_accepts_both_sides() {
    let relay = Relay::new();
    let (mut alice, mut bob) = requested(&relay);

    let acceptance = bob.accept_request(&alice, b"welcome");

    assert_eq!(acceptance.payload_kind, PayloadKind::ContactAcceptance);
    assert_eq!(
        bob.contact(&alice).unwrap().trust_state,
        ContactTrustState::Unverified
    );
    let observed = alice.observe(&acceptance.message).unwrap();
    assert_eq!(
        established_verifier(&observed.acknowledgment_destination.unwrap()),
        bob.publication().recipient_delivery_verifier
    );
    let received = accepted(observed.outcome);
    assert_eq!(received.plaintext.as_slice(), b"welcome");
    alice.commit_changes(observed.changes).unwrap();
    assert_eq!(
        alice.contact(&bob).unwrap().trust_state,
        ContactTrustState::Unverified
    );
    let message = alice.send(&bob, b"hello again");
    assert_eq!(
        established_verifier(&message.destination),
        bob.publication().recipient_delivery_verifier
    );
}

#[test]
fn the_requester_cannot_accept_its_own_request() {
    let relay = Relay::new();
    let (mut alice, bob) = requested(&relay);
    let outgoing = alice.outgoing(&bob, b"accepting myself");

    assert!(matches!(
        alice.encrypt(outgoing, Intent::Acceptance),
        Err(crate::support::device::DeviceError::Operation(
            roost_core::MessageOperationError::ProtocolState(
                roost_core::ProtocolStateError::NoContactRequest
            )
        ))
    ));
}

fn refused(
    result: Result<Encrypted, crate::support::device::DeviceError>,
) -> roost_core::ProtocolStateError {
    match result {
        Err(crate::support::device::DeviceError::Operation(
            roost_core::MessageOperationError::ProtocolState(error),
        )) => error,
        Err(error) => panic!("expected a protocol refusal, got {error:?}"),
        Ok(_) => panic!("expected a protocol refusal"),
    }
}

#[test]
fn each_side_sends_at_most_three_distinct_messages_before_acceptance() {
    let relay = Relay::new();
    let (mut alice, bob) = requested(&relay);
    alice.send(&bob, b"second");
    let third = alice.outgoing(&bob, b"third");
    let resent_third = crate::support::device::redraft(&third);
    alice.send_with(third, Intent::Message);

    let fourth = alice.outgoing(&bob, b"fourth");
    assert!(matches!(
        refused(alice.encrypt(fourth, Intent::Message)),
        roost_core::ProtocolStateError::PendingLimitReached { limit: 3 }
    ));
    assert!(alice.encrypt(resent_third, Intent::Message).is_ok());
}

#[test]
fn the_receiver_withholds_plaintext_past_the_limit() {
    let relay = Relay::new();
    let (mut alice, mut bob) = requested(&relay);
    let second = alice.send(&bob, b"second");
    let contact_address = alice.contact_address(bob.identity_key());
    let count_before_third = alice.host.blob_bytes(&contact_address).unwrap();
    let third = alice.send(&bob, b"third");
    // A sender that forgets its count, as a modified client would, sends a fourth distinct Message.
    alice.host.set_raw(contact_address, count_before_third);
    let fourth = alice.send(&bob, b"fourth");
    for message in [&second, &third] {
        accepted(bob.receive(&message.message));
    }

    let InboundMessageOutcome::Withheld(withheld) = bob.receive(&fourth.message) else {
        panic!("expected the fourth Message withheld");
    };

    assert_eq!(withheld.message_id, fourth.message_id);
}

#[test]
fn requests_that_cross_accept_both_sides() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    let from_alice = alice.request(&bob, b"hi bob");
    let from_bob = bob.request(&alice, b"hi alice");

    let alice_received = accepted(alice.receive(&from_bob.message));
    let bob_received = accepted(bob.receive(&from_alice.message));

    assert!(alice_received.acknowledgment.is_some());
    assert!(bob_received.acknowledgment.is_some());
    for (device, peer) in [(&alice, &bob), (&bob, &alice)] {
        assert_eq!(
            device.contact(peer).unwrap().trust_state,
            ContactTrustState::Unverified
        );
    }
}

#[test]
fn a_request_restarted_after_the_peer_asked_becomes_an_acceptance() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    let draft = bob.outgoing(&alice, b"hi alice");
    let Encrypted::NeedsPreKeyBundle(_) = bob
        .encrypt(crate::support::device::redraft(&draft), Intent::Request)
        .unwrap()
    else {
        panic!("expected a request for Alice's bundle");
    };
    let request = alice.request(&bob, b"hi bob");
    bob.receive(&request.message);

    let mut restarted = draft;
    restarted.prekey_bundle = Some(alice.bundle());
    let sent = bob.send_with(restarted, Intent::Request);

    assert_eq!(sent.payload_kind, PayloadKind::ContactAcceptance);
    assert_eq!(sent.session_id, request.session_id);
    accepted(alice.receive(&sent.message));
    assert_eq!(
        alice.contact(&bob).unwrap().trust_state,
        ContactTrustState::Unverified
    );
}

#[test]
fn a_request_restarted_after_the_peer_accepted_becomes_an_ordinary_message() {
    let relay = Relay::new();
    let (mut alice, mut bob) = requested(&relay);
    let acceptance = bob.accept_request(&alice, b"welcome");
    alice.receive(&acceptance.message);

    let mut restarted = alice.outgoing(&bob, b"thanks");
    restarted.prekey_bundle = Some(bob.bundle());
    let sent = alice.send_with(restarted, Intent::Request);

    assert_eq!(sent.session_id, acceptance.session_id);
    assert_eq!(
        established_verifier(&sent.destination),
        bob.publication().recipient_delivery_verifier
    );
}

#[test]
fn a_bundle_older_than_the_contacts_discovery_key_asks_again() {
    let relay = Relay::new();
    let (mut alice, mut bob) = requested(&relay);
    let stale = bob.bundle_without_one_time_prekey();
    let rotation = bob.store.prepare_inbox_rotation().unwrap();
    bob.store.reserve_operation(rotation.id).unwrap();
    bob.store.finalize_operation(rotation.id).unwrap();
    let acceptance = bob.accept_request(&alice, b"welcome");
    alice.receive(&acceptance.message);
    // Alice's host lost her Sessions with Bob but kept his record, which the grant updated.
    alice.forget_sessions_with(&bob);

    let mut outgoing = alice.outgoing(&bob, b"hello again");
    outgoing.prekey_bundle = Some(stale);
    assert!(matches!(
        alice
            .encrypt(crate::support::device::redraft(&outgoing), Intent::Request)
            .unwrap(),
        Encrypted::NeedsPreKeyBundle(_)
    ));
    outgoing.prekey_bundle = Some(bob.bundle());
    let sent = alice.send_with(outgoing, Intent::Request);

    accepted(bob.receive(&sent.message));
}

fn rotate_signed_prekey(device: &Device) {
    let rotation = device.store.prepare_signed_prekey_rotation().unwrap();
    device.store.reserve_operation(rotation.id).unwrap();
    device.store.finalize_operation(rotation.id).unwrap();
}

#[test]
fn a_first_message_on_the_current_signed_prekey_needs_no_admission() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let bob = Device::new(&relay, 0xb0);
    let request = alice.request(&bob, b"hi bob");

    assert!(bob.observe(&request.message).unwrap().admission.is_none());
}

#[test]
fn a_first_message_on_a_kept_signed_prekey_needs_proven_admission() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    let bundle = bob.bundle_without_one_time_prekey();
    let kept_signed_prekey_id = bundle.bundle.signed_prekey.id;
    rotate_signed_prekey(&bob);
    let mut outgoing = alice.outgoing(&bob, b"hi bob");
    outgoing.prekey_bundle = Some(bundle);
    let request = alice.send_with(outgoing, Intent::Request);
    let before = bob.host.snapshot_bytes();

    bob.admits = false;
    let Err(crate::support::device::DeviceError::NotAdmitted(admission)) =
        bob.observe(&request.message)
    else {
        panic!("expected Roost to ask for admission");
    };
    assert_eq!(admission.signed_prekey_id, kept_signed_prekey_id);
    assert_eq!(bob.host.snapshot_bytes(), before);

    bob.admits = true;
    assert!(matches!(
        bob.receive(&request.message),
        InboundMessageOutcome::ContactRequest(_)
    ));
}

#[test]
fn a_first_message_on_a_one_time_prekey_commits_its_use_with_the_session() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    let request = alice.request(&bob, b"hi bob");
    let (_, one_time_prekey_id) = first_message_route(&request.destination);
    assert!(one_time_prekey_id.is_some());

    let observed = bob.observe(&request.message).unwrap();
    assert!(matches!(
        observed.outcome,
        InboundMessageOutcome::ContactRequest(_)
    ));
    let operation = observed.changes.operation().unwrap();
    assert!(
        bob.store
            .unfinished_operations()
            .unwrap()
            .iter()
            .any(|unfinished| unfinished.id == operation)
    );
    bob.commit_changes(observed.changes).unwrap();

    assert_eq!(
        bob.store.operation_status(operation).unwrap(),
        roost_core::KeyStoreOperationStatus::Finalized
    );
}

#[test]
fn a_first_message_without_a_one_time_prekey_carries_no_operation() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let bob = Device::new(&relay, 0xb0);
    let mut outgoing = alice.outgoing(&bob, b"hi bob");
    outgoing.prekey_bundle = Some(bob.bundle_without_one_time_prekey());
    let request = alice.send_with(outgoing, Intent::Request);
    assert_eq!(first_message_route(&request.destination).1, None);

    let observed = bob.observe(&request.message).unwrap();

    assert!(matches!(
        observed.outcome,
        InboundMessageOutcome::ContactRequest(_)
    ));
    assert!(observed.changes.operation().is_none());
}

#[test]
fn a_replayed_first_message_is_a_duplicate_and_another_on_its_one_time_prekey_fails() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    let bundle = bob.bundle();
    let before_request = alice.host.clone();
    let mut first = alice.outgoing(&bob, b"hi bob");
    first.prekey_bundle = Some(clone_bundle(&bundle));
    let request = alice.send_with(first, Intent::Request);
    bob.receive(&request.message);

    assert!(matches!(
        bob.observe(&request.message).unwrap().outcome,
        InboundMessageOutcome::Duplicate
    ));
    // A host that lost Alice's commit starts another Session on the same bundle.
    alice.host = before_request;
    let mut second = alice.outgoing(&bob, b"hi again");
    second.prekey_bundle = Some(bundle);
    let second = alice.send_with(second, Intent::Request);
    assert!(matches!(
        bob.observe(&second.message),
        Err(crate::support::device::DeviceError::Operation(
            roost_core::MessageOperationError::KeyStore(roost_core::KeyStoreError::OneTimePreKey(
                roost_core::OneTimePreKeyError::Used { .. }
            ))
        ))
    ));
}

fn clone_bundle(bundle: &roost_core::PeerPreKeyBundle) -> roost_core::PeerPreKeyBundle {
    roost_core::PeerPreKeyBundle {
        identity_key: bundle.identity_key.clone(),
        discovery_to_identity: bundle.discovery_to_identity,
        bundle: bundle.bundle.clone(),
    }
}

#[test]
fn a_conflicting_commit_aborts_and_a_rerun_uses_the_one_time_prekey_once() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    let request = alice.request(&bob, b"hi bob");
    let stale = bob.observe(&request.message).unwrap();
    assert!(matches!(
        stale.outcome,
        InboundMessageOutcome::ContactRequest(_)
    ));
    let stale_operation = stale.changes.operation().unwrap();
    // Another receive commits first and changes the Deduplication Set this one read.
    let mut other = Device::new(&relay, 0xc0);
    let other_request = other.request(&bob, b"hi from carol");
    bob.receive(&other_request.message);

    assert_eq!(
        bob.commit_changes(stale.changes).err(),
        Some(crate::support::HostCommitError::StaleCondition)
    );
    assert_eq!(
        bob.store.operation_status(stale_operation).unwrap(),
        roost_core::KeyStoreOperationStatus::Aborted
    );
    assert!(matches!(
        bob.receive(&request.message),
        InboundMessageOutcome::ContactRequest(_)
    ));
}

#[test]
fn an_unknown_commit_outcome_is_reconciled_at_startup_without_losing_the_one_time_prekey() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    let request = alice.request(&bob, b"hi bob");
    let observed = bob.observe(&request.message).unwrap();
    assert!(matches!(
        observed.outcome,
        InboundMessageOutcome::ContactRequest(_)
    ));
    let operation = observed.changes.operation().unwrap();
    bob.store.reserve_operation(operation).unwrap();
    // The transaction commits, but a lost reply hides that it did, and the app restarts.
    bob.host.commit(observed.changes).unwrap();
    bob.restart();

    let unfinished = bob.store.unfinished_operations().unwrap();
    assert_eq!(unfinished.len(), 1);
    assert_eq!(unfinished[0].id, operation);
    bob.store.finalize_operation(operation).unwrap();
    assert!(matches!(
        bob.observe(&request.message).unwrap().outcome,
        InboundMessageOutcome::Duplicate
    ));
}

#[test]
fn a_grant_rides_on_messages_until_the_contact_acknowledges_one() {
    let relay = Relay::new();
    let (mut alice, mut bob) = befriended(&relay);

    let first = alice.send(&bob, b"first");
    assert_eq!(first.payload_kind, PayloadKind::EncryptedTextWithGrant);
    let unacknowledged = alice.send(&bob, b"second");
    assert_eq!(
        unacknowledged.payload_kind,
        PayloadKind::EncryptedTextWithGrant
    );
    let acknowledgment = accepted(bob.receive(&first.message))
        .acknowledgment
        .unwrap();
    alice.receive(&acknowledgment);

    assert_eq!(
        alice.send(&bob, b"third").payload_kind,
        PayloadKind::EncryptedText
    );
}

#[test]
fn after_an_inbox_rotation_contacts_get_the_new_grant() {
    let relay = Relay::new();
    let (mut alice, mut bob) = befriended(&relay);
    let rotation = bob.store.prepare_inbox_rotation().unwrap();
    bob.store.reserve_operation(rotation.id).unwrap();
    bob.store.finalize_operation(rotation.id).unwrap();

    let message = bob.send(&alice, b"new inbox");
    assert_eq!(message.payload_kind, PayloadKind::EncryptedTextWithGrant);
    alice.receive(&message.message);

    assert_eq!(
        established_verifier(&alice.send(&bob, b"got it").destination),
        rotation.output.recipient_delivery_verifier
    );
}

#[test]
fn a_grant_for_an_older_discovery_key_changes_nothing() {
    let relay = Relay::new();
    let (mut alice, mut bob) = befriended(&relay);
    let delayed = bob.send(&alice, b"sent before the rotation");
    let rotation = bob.store.prepare_inbox_rotation().unwrap();
    bob.store.reserve_operation(rotation.id).unwrap();
    bob.store.finalize_operation(rotation.id).unwrap();
    let current = bob.send(&alice, b"sent after the rotation");
    alice.receive(&current.message);

    alice.receive(&delayed.message);

    assert_eq!(
        established_verifier(&alice.send(&bob, b"which inbox?").destination),
        rotation.output.recipient_delivery_verifier
    );
}

#[test]
fn the_requesters_grant_stops_once_the_asked_side_acknowledges_a_message_carrying_it() {
    let relay = Relay::new();
    let (mut alice, mut bob) = requested(&relay);
    let reply = bob.send(&alice, b"who is this?");
    alice.receive(&reply.message);
    let second = alice.send(&bob, b"it's alice");
    assert_eq!(second.payload_kind, PayloadKind::EncryptedTextWithGrant);
    let acknowledgment = accepted(bob.receive(&second.message))
        .acknowledgment
        .unwrap();

    alice.receive(&acknowledgment);

    assert_eq!(
        alice.send(&bob, b"third").payload_kind,
        PayloadKind::EncryptedText
    );
}

#[test]
fn messages_before_acceptance_leave_nothing_waiting_for_an_acknowledgment() {
    let relay = Relay::new();
    let (mut alice, bob) = requested(&relay);
    let message = alice.send(&bob, b"second");

    assert!(
        bob.store
            .protocol_engine()
            .pending_acknowledgments(&alice.host.snapshot(), message.session_id)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn blocking_a_stranger_rotates_the_inbox_and_hides_their_request() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    let bundle = bob.bundle();
    let before = bob.publication();

    let publication = bob.block(alice.identity_key()).unwrap();

    assert_ne!(
        publication.discovery_key.public_key.as_bytes(),
        before.discovery_key.public_key.as_bytes()
    );
    let contact = bob.contact(&alice).unwrap();
    assert!(contact.blocked);
    assert!(contact.discovery_key.is_none());
    // Bob's old bundle no longer reaches his inbox, and a fresh one reaches a blocked record.
    let before_stale = alice.host.clone();
    let mut stale = alice.outgoing(&bob, b"hi bob");
    stale.prekey_bundle = Some(bundle);
    let stale = alice.send_with(stale, Intent::Request);
    assert!(matches!(
        bob.observe(&stale.message),
        Err(crate::support::device::DeviceError::Operation(
            roost_core::MessageOperationError::ProtocolState(
                roost_core::ProtocolStateError::SealedFrame(
                    roost_crypto::SealedFrameError::RecipientMismatch
                )
            )
        ))
    ));
    alice.host = before_stale;
    let request = alice.request(&bob, b"hi again");
    assert!(matches!(
        bob.receive(&request.message),
        InboundMessageOutcome::Blocked(_)
    ));
    assert!(bob.block(alice.identity_key()).is_none());
}

#[test]
fn a_blocked_stranger_learns_nothing_even_under_silent_receipt() {
    let relay = Relay::new();
    let (mut alice, mut bob) = requested(&relay);
    bob.settings = ReceiveSettings::new(
        ProtocolHardeningLimits::default().default_deduplication_capacity,
        BlockedContactAcknowledgmentPolicy::SilentReceipt,
        Duration::ZERO,
    )
    .unwrap();
    bob.block(alice.identity_key());
    // Blocking rotated Bob's inbox, so Alice reaches him on his new prekeys.
    alice.forget_sessions_with(&bob);
    let request = alice.request(&bob, b"hello?");

    let InboundMessageOutcome::Blocked(blocked) = bob.receive(&request.message) else {
        panic!("expected a blocked Message");
    };
    assert!(blocked.acknowledgment.is_none());
}

#[test]
fn a_blocked_contacts_new_session_is_authenticated_and_kept_with_its_plaintext_withheld() {
    for policy in [
        BlockedContactAcknowledgmentPolicy::Unreachable,
        BlockedContactAcknowledgmentPolicy::SilentReceipt,
    ] {
        let relay = Relay::new();
        let (mut alice, mut bob) = befriended(&relay);
        bob.settings = ReceiveSettings::new(
            ProtocolHardeningLimits::default().default_deduplication_capacity,
            policy,
            Duration::ZERO,
        )
        .unwrap();
        bob.block(alice.identity_key());
        // Blocking rotated Bob's inbox, so Alice reaches him only with a new Session.
        alice.forget_sessions_with(&bob);
        let request = alice.request(&bob, b"hidden");

        let InboundMessageOutcome::Blocked(hidden) = bob.receive(&request.message) else {
            panic!("expected a blocked Message");
        };

        assert_eq!(
            hidden.acknowledgment.is_some(),
            policy == BlockedContactAcknowledgmentPolicy::SilentReceipt
        );
        bob.unblock(alice.identity_key());
        let shown = accepted(bob.receive(&alice.send(&bob, b"shown").message));
        assert_eq!(shown.session_id, request.session_id);
        assert_eq!(shown.plaintext.as_slice(), b"shown");
    }
}

// Alice's modified client stores `list` as her record of the Sessions kept with `peer`. A list
// `peer` wrote for her says she started their Session, so to Alice it says `peer` did.
fn claim_the_peer_started_the_session(alice: &mut Device, peer: &Device, list: Vec<u8>) {
    let address = alice.sessions_address(peer.identity_key());
    alice.host.set_raw(address, list);
}

fn unsolicited(
    result: Result<crate::support::device::Decrypted, crate::support::device::DeviceError>,
) -> bool {
    matches!(
        result,
        Err(crate::support::device::DeviceError::Operation(
            roost_core::MessageOperationError::ProtocolState(
                roost_core::ProtocolStateError::UnsolicitedAcceptance
            )
        ))
    )
}

#[test]
fn an_acceptance_on_a_session_the_sender_started_is_refused() {
    let relay = Relay::new();
    let (mut alice, bob) = requested(&relay);
    let list = bob
        .host
        .blob_bytes(&bob.sessions_address(alice.identity_key()))
        .unwrap();
    claim_the_peer_started_the_session(&mut alice, &bob, list);
    let acceptance = alice.accept_request(&bob, b"accepting myself");

    assert!(unsolicited(bob.observe(&acceptance.message)));
    assert_eq!(
        bob.contact(&alice).unwrap().trust_state,
        ContactTrustState::Pending
    );
}

#[test]
fn an_acceptance_that_starts_a_session_is_refused() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let bob = Device::new(&relay, 0xb0);
    let mut request = alice.outgoing(&bob, b"hi bob");
    request.prekey_bundle = Some(bob.bundle_without_one_time_prekey());
    let request = alice.send_with(request, Intent::Request);
    // Bob never commits the request, so only a copy of his store holds the list it writes.
    let received = bob.observe(&request.message).unwrap();
    let written = bob.host.clone().commit(received.changes).unwrap();
    let list = written
        .iter()
        .find(|update| update.address().kind() == ProtocolStateKind::PeerSessions)
        .and_then(|update| update.blob())
        .unwrap()
        .as_bytes()
        .to_vec();
    claim_the_peer_started_the_session(&mut alice, &bob, list);
    let acceptance = alice.accept_request(&bob, b"accepting myself");

    assert!(unsolicited(bob.observe(&acceptance.message)));
    assert!(bob.contact(&alice).is_none());
}

#[test]
fn a_cancelled_receive_leaves_the_one_time_prekey_for_a_rerun_after_startup_recovery() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    let request = alice.request(&bob, b"hi bob");
    let cancelled = bob.observe(&request.message).unwrap();
    assert!(matches!(
        cancelled.outcome,
        InboundMessageOutcome::ContactRequest(_)
    ));
    let operation = cancelled.changes.operation().unwrap();
    // The app is killed before it reserves the operation or commits anything.
    drop(cancelled);
    bob.restart();

    let unfinished = bob.store.unfinished_operations().unwrap();
    assert_eq!(unfinished.len(), 1);
    assert_eq!(
        unfinished[0].status,
        roost_core::KeyStoreOperationStatus::Prepared
    );
    bob.store.abort_operation(operation).unwrap();

    assert!(matches!(
        bob.receive(&request.message),
        InboundMessageOutcome::ContactRequest(_)
    ));
}

#[test]
fn a_request_without_a_grant_from_an_identity_with_no_record_is_refused() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    let request = alice.request(&bob, b"hi bob");
    bob.receive(&request.message);
    let acceptance = bob.accept_request(&alice, b"welcome");
    let acknowledgment = accepted(alice.receive(&acceptance.message))
        .acknowledgment
        .unwrap();
    bob.receive(&acknowledgment);
    let message = alice.send(&bob, b"carries the grant");
    let acknowledgment = accepted(bob.receive(&message.message))
        .acknowledgment
        .unwrap();
    alice.receive(&acknowledgment);
    // Bob's host deletes everything about Alice, while Alice still counts Bob as accepted.
    for address in [
        bob.contact_address(alice.identity_key()),
        bob.sessions_address(alice.identity_key()),
    ] {
        bob.host.remove(&address);
    }
    alice.forget_sessions_with(&bob);
    let ungranted = alice.request(&bob, b"no grant this time");
    assert_eq!(ungranted.payload_kind, PayloadKind::EncryptedText);

    assert!(matches!(
        bob.observe(&ungranted.message),
        Err(crate::support::device::DeviceError::Operation(
            roost_core::MessageOperationError::ProtocolState(
                roost_core::ProtocolStateError::InvalidMessage { reason }
            )
        )) if reason == "contact request carries no inbox grant"
    ));
    assert!(bob.contact(&alice).is_none());
}
