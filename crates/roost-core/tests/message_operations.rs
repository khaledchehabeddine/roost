//! Message Operations that ask a host for exact records and return results it commits atomically.

mod support;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use roost_core::{
    BlockedContactAcknowledgmentPolicy, InboundMessageOutcome, MessageDecryption,
    MessageDecryptionStep, MessageEncryption, MessageEncryptionStep, MessageOperationError,
    OutboundMessageResult, OutgoingMessage, ProtocolHardeningLimits, ProtocolStateAddress,
    ProtocolStateBlob, ProtocolStateCommitCondition, ProtocolStateError, ProtocolStateKey,
    ProtocolStateKind, ReceiveSettings, SignedSenderCertificate, StateEntryError,
    commit_conditions_match,
};
use roost_protocol::{MAX_CERTIFICATE_GRACE_WINDOW, SenderCertificateValidationError};
use std::time::Duration;
use support::device::{Device, Relay, Route, binding};

// Has `initiator` ask `responder`, `responder` accept, and `initiator` receive the acceptance.
fn establish(initiator: &mut Device, responder: &mut Device) -> roost_core::SessionId {
    let request = initiator.request(responder, b"hello");
    responder.receive(&request.message);
    let acceptance = responder.accept_request(initiator, b"reply");
    initiator.receive(&acceptance.message);
    request.session_id
}

fn address(kind: ProtocolStateKind, key: &[u8]) -> ProtocolStateAddress {
    ProtocolStateAddress::new(kind, ProtocolStateKey::from_bytes(key.to_vec()).unwrap())
}

fn rng() -> ChaCha20Rng {
    ChaCha20Rng::from_seed([0x5e; 32])
}

#[test]
fn encryption_reads_the_contact_then_its_session_then_asks_for_a_transport() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    let session_id = establish(&mut alice, &mut bob);
    let bob_key = bob.identity_key().canonical_encoding();
    let outgoing = alice.outgoing(&bob, b"hello again");
    let mut encryption = alice.store.start_encryption(outgoing).unwrap();

    let MessageEncryptionStep::NeedsState(contact_reads) = encryption.step(&mut rng()).unwrap()
    else {
        panic!("expected a read of the contact's records")
    };
    assert_eq!(
        contact_reads,
        [
            address(ProtocolStateKind::ContactState, &bob_key),
            address(ProtocolStateKind::PeerSessions, &bob_key),
        ]
    );
    encryption
        .supply_state(alice.host.read(&contact_reads))
        .unwrap();
    let MessageEncryptionStep::NeedsState(session_reads) = encryption.step(&mut rng()).unwrap()
    else {
        panic!("expected a read of the Session's records")
    };
    assert_eq!(
        session_reads,
        [
            address(ProtocolStateKind::RatchetSession, session_id.as_bytes()),
            address(
                ProtocolStateKind::PendingAcknowledgments,
                session_id.as_bytes()
            ),
        ]
    );
    encryption
        .supply_state(alice.host.read(&session_reads))
        .unwrap();
    let MessageEncryptionStep::NeedsTransport(destination) = encryption.step(&mut rng()).unwrap()
    else {
        panic!("expected a transport request")
    };
    assert_eq!(Route::of(&destination), bob.established_route());
    encryption.supply_transport_binding(binding()).unwrap();
    let MessageEncryptionStep::Ready(sent) = encryption.step(&mut rng()).unwrap() else {
        panic!("expected the sealed Message")
    };
    assert_eq!(sent.session_id, session_id);
    let message = sent.message.clone();
    alice.host.commit_changes(&sent.changes).unwrap();

    let InboundMessageOutcome::Accepted(received) = bob.receive(&message) else {
        panic!("expected Bob to accept the Message")
    };
    assert_eq!(&*received.plaintext, b"hello again");
}

#[test]
fn decryption_checks_duplicates_first_and_asks_where_to_acknowledge_only_after_authenticating() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    let session_id = establish(&mut alice, &mut bob);
    let sent = alice.send(&bob, b"ping");
    let alice_key = alice.identity_key().canonical_encoding();
    let mut decryption = bob
        .store
        .start_decryption(bob.incoming(&sent.message))
        .unwrap();

    let MessageDecryptionStep::NeedsState(deduplication_read) =
        decryption.step(&mut rng()).unwrap()
    else {
        panic!("expected a read of the Deduplication Set")
    };
    assert_eq!(
        deduplication_read,
        [address(ProtocolStateKind::DeduplicationSet, &[0])]
    );
    decryption
        .supply_state(bob.host.read(&deduplication_read))
        .unwrap();
    let MessageDecryptionStep::NeedsState(session_read) = decryption.step(&mut rng()).unwrap()
    else {
        panic!("expected a read of the named Session")
    };
    assert_eq!(
        session_read,
        [address(
            ProtocolStateKind::RatchetSession,
            session_id.as_bytes()
        )]
    );
    decryption
        .supply_state(bob.host.read(&session_read))
        .unwrap();
    let MessageDecryptionStep::NeedsState(peer_reads) = decryption.step(&mut rng()).unwrap() else {
        panic!("expected a read of the peer's records")
    };
    assert_eq!(
        peer_reads,
        [
            address(ProtocolStateKind::ContactState, &alice_key),
            address(ProtocolStateKind::PeerSessions, &alice_key),
        ]
    );
    decryption.supply_state(bob.host.read(&peer_reads)).unwrap();
    let MessageDecryptionStep::NeedsAcknowledgmentTransport(destination) =
        decryption.step(&mut rng()).unwrap()
    else {
        panic!("expected a transport request for the acknowledgment")
    };
    assert_eq!(Route::of(&destination), alice.established_route());
    decryption
        .supply_acknowledgment_transport_binding(binding())
        .unwrap();
    let MessageDecryptionStep::Ready(outcome) = decryption.step(&mut rng()).unwrap() else {
        panic!("expected the received Message")
    };
    let InboundMessageOutcome::Accepted(received) = *outcome else {
        panic!("expected an accepted Message")
    };
    assert_eq!(&*received.plaintext, b"ping");
}

#[test]
fn a_tampered_message_fails_before_roost_asks_where_to_acknowledge() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    establish(&mut alice, &mut bob);
    let mut tampered = alice.send(&bob, b"ping").message;
    let last = tampered.ciphertext.len() - 1;
    tampered.ciphertext[last] ^= 1;
    let mut decryption = bob.store.start_decryption(bob.incoming(&tampered)).unwrap();

    let failure = loop {
        match decryption.step(&mut rng()) {
            Ok(MessageDecryptionStep::NeedsState(addresses)) => {
                decryption.supply_state(bob.host.read(&addresses)).unwrap();
            }
            Ok(
                MessageDecryptionStep::NeedsAcknowledgmentTransport(_)
                | MessageDecryptionStep::NeedsAdmission(_),
            ) => panic!("a tampered Message must not reach the acknowledgment"),
            Ok(MessageDecryptionStep::Ready(_)) => panic!("a tampered Message must not decrypt"),
            Err(error) => break error,
        }
    };

    assert!(matches!(
        failure,
        MessageOperationError::ProtocolState(ProtocolStateError::SealedFrame(_))
    ));
    assert!(matches!(
        decryption.step(&mut rng()),
        Err(MessageOperationError::Finished)
    ));
}

// Runs `encryption` to its result, asking each step twice when `ask_twice` is set.
fn seal(
    mut encryption: MessageEncryption,
    host: &support::HostStore,
    ask_twice: bool,
) -> OutboundMessageResult {
    let mut rng = rng();
    loop {
        let step = encryption.step(&mut rng).unwrap();
        if ask_twice && !matches!(step, MessageEncryptionStep::Ready(_)) {
            let again = encryption.step(&mut rng).unwrap();
            match (&step, &again) {
                (
                    MessageEncryptionStep::NeedsState(first),
                    MessageEncryptionStep::NeedsState(second),
                ) => {
                    assert_eq!(first, second);
                }
                (
                    MessageEncryptionStep::NeedsTransport(first),
                    MessageEncryptionStep::NeedsTransport(second),
                ) => assert_eq!(Route::of(first), Route::of(second)),
                _ => panic!("asking again changed the request"),
            }
        }
        match step {
            MessageEncryptionStep::NeedsState(addresses) => {
                encryption.supply_state(host.read(&addresses)).unwrap();
            }
            MessageEncryptionStep::NeedsTransport(_) => {
                encryption.supply_transport_binding(binding()).unwrap();
            }
            MessageEncryptionStep::NeedsPreKeyBundle(_) | MessageEncryptionStep::NothingToSend => {
                panic!("expected an existing Session")
            }
            MessageEncryptionStep::Ready(sent) => return *sent,
        }
    }
}

#[test]
fn asking_a_waiting_operation_again_returns_the_same_request_without_repeating_work() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    establish(&mut alice, &mut bob);
    let outgoing = alice.outgoing(&bob, b"once");
    let replay = redraft(&outgoing);

    let asked_once = seal(
        alice.store.start_encryption(outgoing).unwrap(),
        &alice.host,
        false,
    );
    let asked_twice = seal(
        alice.store.start_encryption(replay).unwrap(),
        &alice.host,
        true,
    );

    // Sealing draws randomness, so a repeated seal would change the bytes the same seed produces.
    assert_eq!(
        asked_twice.message.to_bytes().unwrap(),
        asked_once.message.to_bytes().unwrap()
    );
}

// What a host might hand back wrongly for a pending read.
#[derive(Clone, Copy, Debug)]
enum BadEntries {
    MissingOne,
    RepeatedOne,
    Unrequested,
}

#[test]
fn entries_that_do_not_match_the_pending_read_end_the_operation() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    establish(&mut alice, &mut bob);

    for bad in [
        BadEntries::MissingOne,
        BadEntries::RepeatedOne,
        BadEntries::Unrequested,
    ] {
        let outgoing = alice.outgoing(&bob, b"never sent");
        let mut encryption = alice.store.start_encryption(outgoing).unwrap();
        let MessageEncryptionStep::NeedsState(addresses) = encryption.step(&mut rng()).unwrap()
        else {
            panic!("expected a read")
        };
        let mut entries = alice.host.read(&addresses);
        entries.reverse();
        match bad {
            BadEntries::MissingOne => {
                entries.pop();
            }
            BadEntries::RepeatedOne => {
                let repeated = entries[0].0.clone();
                entries.push((repeated, None));
            }
            BadEntries::Unrequested => {
                entries[0].0 = address(ProtocolStateKind::ContactState, &[0x77; 64]);
            }
        }

        let supplied = encryption.supply_state(entries);

        let Err(MessageOperationError::ProtocolState(ProtocolStateError::StateEntry(error))) =
            supplied
        else {
            panic!("expected a mismatch for {bad:?}")
        };
        assert!(
            matches!(
                (bad, error),
                (BadEntries::MissingOne, StateEntryError::Missing { .. })
                    | (BadEntries::RepeatedOne, StateEntryError::Repeated { .. })
                    | (BadEntries::Unrequested, StateEntryError::Unexpected { .. })
            ),
            "wrong mismatch for {bad:?}"
        );
        assert!(matches!(
            encryption.step(&mut rng()),
            Err(MessageOperationError::Finished)
        ));
    }
}

#[test]
fn entries_in_any_order_satisfy_the_pending_read() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    establish(&mut alice, &mut bob);
    let outgoing = alice.outgoing(&bob, b"reordered");
    let mut encryption = alice.store.start_encryption(outgoing).unwrap();
    let MessageEncryptionStep::NeedsState(addresses) = encryption.step(&mut rng()).unwrap() else {
        panic!("expected a read")
    };
    let mut entries = alice.host.read(&addresses);
    entries.reverse();

    encryption.supply_state(entries).unwrap();

    assert!(matches!(
        encryption.step(&mut rng()),
        Ok(MessageEncryptionStep::NeedsState(_))
    ));
}

#[test]
fn a_supply_call_out_of_turn_ends_the_operation() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    establish(&mut alice, &mut bob);

    let outgoing = alice.outgoing(&bob, b"early");
    let mut early_binding = alice.store.start_encryption(outgoing).unwrap();
    assert!(matches!(
        early_binding.supply_transport_binding(binding()),
        Err(MessageOperationError::NotAwaitingTransportBinding)
    ));
    assert!(matches!(
        early_binding.step(&mut rng()),
        Err(MessageOperationError::Finished)
    ));

    let outgoing = alice.outgoing(&bob, b"early");
    let mut early_state = alice.store.start_encryption(outgoing).unwrap();
    assert!(matches!(
        early_state.supply_state(Vec::new()),
        Err(MessageOperationError::NotAwaitingState)
    ));
    assert!(matches!(
        early_state.step(&mut rng()),
        Err(MessageOperationError::Finished)
    ));
}

#[test]
fn an_operation_refuses_every_call_after_returning_its_result() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    establish(&mut alice, &mut bob);
    let outgoing = alice.outgoing(&bob, b"done");
    let mut encryption = alice.store.start_encryption(outgoing).unwrap();
    loop {
        match encryption.step(&mut rng()).unwrap() {
            MessageEncryptionStep::NeedsState(addresses) => {
                encryption
                    .supply_state(alice.host.read(&addresses))
                    .unwrap();
            }
            MessageEncryptionStep::NeedsTransport(_) => {
                encryption.supply_transport_binding(binding()).unwrap();
            }
            MessageEncryptionStep::NeedsPreKeyBundle(_) | MessageEncryptionStep::NothingToSend => {
                panic!("expected an existing Session")
            }
            MessageEncryptionStep::Ready(_) => break,
        }
    }

    assert!(matches!(
        encryption.step(&mut rng()),
        Err(MessageOperationError::Finished)
    ));
    assert!(matches!(
        encryption.supply_state(Vec::new()),
        Err(MessageOperationError::Finished)
    ));
    assert!(matches!(
        encryption.supply_transport_binding(binding()),
        Err(MessageOperationError::Finished)
    ));
}

#[test]
fn a_send_cannot_commit_after_another_operation_blocks_its_contact() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    establish(&mut alice, &mut bob);
    let sent = alice.encrypt_to(&bob, b"before the block").unwrap();
    let contact = address(
        ProtocolStateKind::ContactState,
        &bob.identity_key().canonical_encoding(),
    );
    // The send reads the contact but never writes it.
    assert!(
        sent.changes
            .updates()
            .iter()
            .all(|update| update.address() != &contact)
    );

    alice.block(bob.identity_key());
    let before = alice.host.snapshot_bytes();
    let queued = alice.host.outbox().len();

    assert_eq!(
        alice.host.commit_sent(sent),
        Err(support::HostCommitError::StaleCondition)
    );
    assert_eq!(alice.host.snapshot_bytes(), before);
    assert_eq!(alice.host.outbox().len(), queued);
}

#[test]
fn matching_checks_each_condition_and_rejects_malformed_records() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    establish(&mut alice, &mut bob);
    let sent = alice.encrypt_to(&bob, b"conditional").unwrap();
    let addresses: Vec<_> = sent
        .changes
        .conditions()
        .iter()
        .map(|(address, _)| address.clone())
        .collect();
    let current = alice.host.read(&addresses);
    assert!(commit_conditions_match(sent.changes.conditions(), &current).unwrap());

    let mut changed = alice.host.read(&addresses);
    changed[0].1 = Some(ProtocolStateBlob::from_bytes(vec![1, 2, 3]));
    assert!(!commit_conditions_match(sent.changes.conditions(), &changed).unwrap());
    let mut removed = alice.host.read(&addresses);
    removed[0].1 = None;
    assert!(!commit_conditions_match(sent.changes.conditions(), &removed).unwrap());

    let mut missing = alice.host.read(&addresses);
    missing.pop();
    assert!(matches!(
        commit_conditions_match(sent.changes.conditions(), &missing),
        Err(StateEntryError::Missing { .. })
    ));
    let mut repeated = alice.host.read(&addresses);
    repeated.push(alice.host.read(&addresses[..1]).remove(0));
    assert!(matches!(
        commit_conditions_match(sent.changes.conditions(), &repeated),
        Err(StateEntryError::Repeated { .. })
    ));
    let mut extra = alice.host.read(&addresses);
    extra.push((address(ProtocolStateKind::ContactState, &[0x77; 64]), None));
    assert!(matches!(
        commit_conditions_match(sent.changes.conditions(), &extra),
        Err(StateEntryError::Unexpected { .. })
    ));
}

#[test]
fn the_first_receive_creates_the_deduplication_set_and_a_redelivery_stops_before_decrypting() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    establish(&mut alice, &mut bob);
    bob.forget_received_digests();
    let deduplication_set = address(ProtocolStateKind::DeduplicationSet, &[0]);
    let sent = alice.send(&bob, b"once");

    assert!(matches!(
        bob.receive(&sent.message),
        InboundMessageOutcome::Accepted(_)
    ));
    assert!(bob.host.blob_bytes(&deduplication_set).is_some());

    let mut redelivery = bob
        .store
        .start_decryption(bob.incoming(&sent.message))
        .unwrap();
    let MessageDecryptionStep::NeedsState(reads) = redelivery.step(&mut rng()).unwrap() else {
        panic!("expected a read of the Deduplication Set")
    };
    assert_eq!(reads, [deduplication_set]);
    redelivery.supply_state(bob.host.read(&reads)).unwrap();
    assert!(matches!(
        redelivery.step(&mut rng()),
        Ok(MessageDecryptionStep::Ready(outcome)) if matches!(*outcome, InboundMessageOutcome::Duplicate)
    ));
}

#[test]
fn shrinking_the_deduplication_set_evicts_its_oldest_digests() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    establish(&mut alice, &mut bob);
    let settings = |capacity| {
        ReceiveSettings::new(
            capacity,
            BlockedContactAcknowledgmentPolicy::Unreachable,
            Duration::ZERO,
        )
        .unwrap()
    };
    bob.settings = settings(2 * ProtocolHardeningLimits::default().min_deduplication_capacity);
    let oldest = alice.send(&bob, b"oldest");
    bob.receive(&oldest.message);
    for _ in 0..ProtocolHardeningLimits::default().min_deduplication_capacity {
        let newer = alice.send(&bob, b"newer");
        bob.receive(&newer.message);
    }
    assert!(matches!(
        bob.decrypt(&oldest.message).unwrap(),
        InboundMessageOutcome::Duplicate
    ));

    bob.settings = settings(ProtocolHardeningLimits::default().min_deduplication_capacity);
    let latest = alice.send(&bob, b"latest");
    assert!(matches!(
        bob.receive(&latest.message),
        InboundMessageOutcome::Accepted(_)
    ));

    // The smaller set evicted the oldest digest, so the ratchet's replay check catches it instead.
    assert!(matches!(
        bob.decrypt(&oldest.message),
        Err(support::device::DeviceError::Operation(
            MessageOperationError::ProtocolState(ProtocolStateError::Ratchet(_))
        ))
    ));
}

#[test]
fn receive_settings_refuse_values_outside_roosts_limits() {
    let policy = BlockedContactAcknowledgmentPolicy::Unreachable;
    for capacity in [
        ProtocolHardeningLimits::default().min_deduplication_capacity - 1,
        ProtocolHardeningLimits::default().max_deduplication_capacity + 1,
    ] {
        assert!(matches!(
            ReceiveSettings::new(capacity, policy, Duration::ZERO),
            Err(ProtocolStateError::InvalidDeduplicationCapacity { capacity: rejected, .. })
                if rejected == capacity
        ));
    }
    assert!(matches!(
        ReceiveSettings::new(
            ProtocolHardeningLimits::default().default_deduplication_capacity,
            policy,
            MAX_CERTIFICATE_GRACE_WINDOW + Duration::from_millis(1)
        ),
        Err(ProtocolStateError::SenderCertificateValidation(
            SenderCertificateValidationError::GraceWindowTooLarge { .. }
        ))
    ));
    assert!(
        ReceiveSettings::new(
            ProtocolHardeningLimits::default().max_deduplication_capacity,
            policy,
            MAX_CERTIFICATE_GRACE_WINDOW
        )
        .is_ok()
    );
}

// Runs `decryption` to its result and returns it with every request it made.
fn decrypt_recording(
    mut decryption: MessageDecryption,
    host: &support::HostStore,
) -> (Vec<String>, InboundMessageOutcome) {
    let mut requests = Vec::new();
    loop {
        match decryption.step(&mut rng()).unwrap() {
            MessageDecryptionStep::NeedsState(addresses) => {
                requests.push(format!("{} records", addresses.len()));
                decryption.supply_state(host.read(&addresses)).unwrap();
            }
            MessageDecryptionStep::NeedsAdmission(_) => {
                requests.push("admission".into());
                decryption.confirm_admission().unwrap();
            }
            MessageDecryptionStep::NeedsAcknowledgmentTransport(_) => {
                requests.push("acknowledgment transport".into());
                decryption
                    .supply_acknowledgment_transport_binding(binding())
                    .unwrap();
            }
            MessageDecryptionStep::Ready(outcome) => return (requests, *outcome),
        }
    }
}

#[test]
fn an_acknowledgment_decrypts_like_any_message_and_never_asks_for_a_reply_transport() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    let session_id = establish(&mut alice, &mut bob);
    let sent = alice.send(&bob, b"please acknowledge");
    let InboundMessageOutcome::Accepted(received) = bob.receive(&sent.message) else {
        panic!("expected Bob to accept the Message")
    };
    let engine = *alice.store.protocol_engine();
    let pending = engine
        .pending_acknowledgments(&alice.host.snapshot(), session_id)
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].message_id, sent.message_id);

    let decryption = alice
        .store
        .start_decryption(alice.incoming(received.acknowledgment.as_ref().unwrap()))
        .unwrap();
    let (requests, outcome) = decrypt_recording(decryption, &alice.host);

    assert_eq!(requests, ["1 records", "2 records", "2 records"]);
    let InboundMessageOutcome::AcknowledgmentMatched(matched) = outcome else {
        panic!("expected a matched acknowledgment")
    };
    assert_eq!(matched.acknowledged_message_id, sent.message_id);
    alice.host.commit_changes(&matched.changes).unwrap();
    assert!(
        engine
            .pending_acknowledgments(&alice.host.snapshot(), session_id)
            .unwrap()
            .is_empty()
    );
    assert!(matches!(
        alice
            .decrypt(received.acknowledgment.as_ref().unwrap())
            .unwrap(),
        InboundMessageOutcome::Duplicate
    ));
}

#[test]
fn an_unmatched_acknowledgment_still_commits_its_advanced_state() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    establish(&mut alice, &mut bob);
    let sent = alice.encrypt_to(&bob, b"forgotten").unwrap();
    let message = sent.message.clone();
    // The host keeps the ratchet's advance but loses the Pending Acknowledgment.
    let session_only: Vec<_> = sent
        .changes
        .into_updates()
        .into_iter()
        .filter(|update| update.address().kind() == ProtocolStateKind::RatchetSession)
        .collect();
    alice.host.apply_all(&session_only);
    let InboundMessageOutcome::Accepted(received) = bob.receive(&message) else {
        panic!("expected Bob to accept the Message")
    };

    let InboundMessageOutcome::AcknowledgmentUnmatched(unmatched) =
        alice.receive(received.acknowledgment.as_ref().unwrap())
    else {
        panic!("expected an unmatched acknowledgment")
    };

    assert_eq!(unmatched.acknowledged_message_id, sent.message_id);
    assert!(matches!(
        alice
            .decrypt(received.acknowledgment.as_ref().unwrap())
            .unwrap(),
        InboundMessageOutcome::Duplicate
    ));
}

#[test]
fn an_acknowledgment_needs_a_valid_sender_certificate() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    establish(&mut alice, &mut bob);
    let sent = alice.send(&bob, b"acknowledge me");
    let InboundMessageOutcome::Accepted(received) = bob.receive(&sent.message) else {
        panic!("expected Bob to accept the Message")
    };
    let mut incoming = alice.incoming(received.acknowledgment.as_ref().unwrap());
    // Bob's certificate expired long before this reference time.
    incoming.sender_certificate_validation.reference_time += Duration::from_secs(1_000_000);
    let before = alice.host.snapshot_bytes();

    let failure = support::run_decryption(
        alice.store.start_decryption(incoming).unwrap(),
        &alice.host,
        &mut rng(),
        &binding(),
    );

    assert!(matches!(
        failure,
        Err(MessageOperationError::ProtocolState(
            ProtocolStateError::SenderCertificateValidation(
                SenderCertificateValidationError::ExpiredCertificate
            )
        ))
    ));
    assert_eq!(alice.host.snapshot_bytes(), before);
}

#[test]
fn a_blocked_sender_gets_an_acknowledgment_only_under_the_silent_receipt_choice() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    establish(&mut alice, &mut bob);
    bob.block(alice.identity_key());
    // The block rotated Bob's inbox, so only a request on his new prekeys still reaches him.
    alice
        .host
        .remove(&support::device::peer_sessions_address(bob.identity_key()));
    let sent = alice.request(&bob, b"from a blocked contact");

    let unreachable = bob
        .store
        .start_decryption(bob.incoming(&sent.message))
        .unwrap();
    let (requests, outcome) = decrypt_recording(unreachable, &bob.host);
    assert_eq!(requests, ["1 records", "1 records", "2 records"]);
    let InboundMessageOutcome::Blocked(hidden) = outcome else {
        panic!("expected a blocked Message")
    };
    assert!(hidden.acknowledgment.is_none());

    bob.settings = ReceiveSettings::new(
        ProtocolHardeningLimits::default().default_deduplication_capacity,
        BlockedContactAcknowledgmentPolicy::SilentReceipt,
        Duration::ZERO,
    )
    .unwrap();
    let silent_receipt = bob
        .store
        .start_decryption(bob.incoming(&sent.message))
        .unwrap();
    let (requests, outcome) = decrypt_recording(silent_receipt, &bob.host);
    assert_eq!(
        requests,
        [
            "1 records",
            "1 records",
            "2 records",
            "acknowledgment transport"
        ]
    );
    let InboundMessageOutcome::Blocked(receipted) = outcome else {
        panic!("expected a blocked Message")
    };
    let acknowledgment = receipted.acknowledgment.unwrap();
    assert!(matches!(
        alice.receive(&acknowledgment),
        InboundMessageOutcome::AcknowledgmentMatched(_)
    ));
}

// Copies a draft so a retry sends it under the same MessageID.
fn redraft(draft: &OutgoingMessage) -> OutgoingMessage {
    OutgoingMessage {
        recipient: draft.recipient,
        message_id: draft.message_id,
        sent_at_millis: draft.sent_at_millis,
        sender_certificate: SignedSenderCertificate {
            certificate: draft.sender_certificate.certificate.clone(),
            signature: draft.sender_certificate.signature.clone(),
        },
        plaintext: draft.plaintext.clone(),
        prekey_bundle: None,
    }
}

#[test]
fn a_second_instance_that_loses_the_commit_retries_from_fresh_reads() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    establish(&mut alice, &mut bob);
    let extension = alice.second_instance();
    let app_draft = alice.outgoing(&bob, b"from the app");
    let extension_draft = alice.outgoing(&bob, b"from the extension");

    let from_app = seal(
        alice.store.start_encryption(app_draft).unwrap(),
        &alice.host,
        false,
    );
    let stale = seal(
        extension
            .start_encryption(redraft(&extension_draft))
            .unwrap(),
        &alice.host,
        false,
    );
    let app_message = from_app.message.clone();
    alice.host.commit_sent(from_app).unwrap();
    assert_eq!(
        alice.host.commit_sent(stale),
        Err(support::HostCommitError::StaleCondition)
    );
    let retried = seal(
        extension.start_encryption(extension_draft).unwrap(),
        &alice.host,
        false,
    );
    let extension_message = retried.message.clone();
    alice.host.commit_sent(retried).unwrap();

    for (message, plaintext) in [
        (app_message, &b"from the app"[..]),
        (extension_message, &b"from the extension"[..]),
    ] {
        let InboundMessageOutcome::Accepted(received) = bob.receive(&message) else {
            panic!("expected Bob to accept the Message")
        };
        assert_eq!(&*received.plaintext, plaintext);
    }
}

#[test]
fn dropping_an_unfinished_operation_changes_nothing_and_a_restart_sends_the_draft() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    establish(&mut alice, &mut bob);
    let draft = alice.outgoing(&bob, b"survives a crash");
    let before = alice.host.snapshot_bytes();
    let mut interrupted = alice.store.start_encryption(redraft(&draft)).unwrap();
    loop {
        match interrupted.step(&mut rng()).unwrap() {
            MessageEncryptionStep::NeedsState(addresses) => {
                interrupted
                    .supply_state(alice.host.read(&addresses))
                    .unwrap();
            }
            MessageEncryptionStep::NeedsTransport(_) => break,
            MessageEncryptionStep::NeedsPreKeyBundle(_)
            | MessageEncryptionStep::NothingToSend
            | MessageEncryptionStep::Ready(_) => {
                panic!("expected the crash before sealing")
            }
        }
    }
    drop(interrupted);
    assert_eq!(alice.host.snapshot_bytes(), before);

    alice.restart();
    let sent = seal(
        alice.store.start_encryption(draft).unwrap(),
        &alice.host,
        false,
    );
    let message_id = sent.message_id;
    let message = sent.message.clone();
    alice.host.commit_sent(sent).unwrap();

    let InboundMessageOutcome::Accepted(received) = bob.receive(&message) else {
        panic!("expected Bob to accept the Message")
    };
    assert_eq!(received.message_id, message_id);
    assert_eq!(&*received.plaintext, b"survives a crash");
}

#[test]
fn a_receive_that_found_no_deduplication_set_cannot_commit_after_another_creates_one() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    establish(&mut alice, &mut bob);
    bob.forget_received_digests();
    let first = alice.send(&bob, b"first");
    let second = alice.send(&bob, b"second");
    let InboundMessageOutcome::Accepted(first) = bob.decrypt(&first.message).unwrap() else {
        panic!("expected Bob to accept the first Message")
    };
    let InboundMessageOutcome::Accepted(second) = bob.decrypt(&second.message).unwrap() else {
        panic!("expected Bob to accept the second Message")
    };
    let deduplication_set = address(ProtocolStateKind::DeduplicationSet, &[0]);
    assert!(
        second
            .changes
            .conditions()
            .iter()
            .any(|(address, condition)| {
                address == &deduplication_set
                    && matches!(condition, ProtocolStateCommitCondition::Absent)
            })
    );

    bob.host.commit_changes(&first.changes).unwrap();
    let before = bob.host.snapshot_bytes();

    assert_eq!(
        bob.host.commit_changes(&second.changes),
        Err(support::HostCommitError::StaleCondition)
    );
    assert_eq!(bob.host.snapshot_bytes(), before);
}

// Runs `decryption` to its result, asking each step twice when `ask_twice` is set.
fn open_and_acknowledge(
    mut decryption: MessageDecryption,
    host: &support::HostStore,
    ask_twice: bool,
) -> InboundMessageOutcome {
    let mut rng = rng();
    loop {
        let step = decryption.step(&mut rng).unwrap();
        if ask_twice && !matches!(step, MessageDecryptionStep::Ready(_)) {
            let again = decryption.step(&mut rng).unwrap();
            match (&step, &again) {
                (
                    MessageDecryptionStep::NeedsState(first),
                    MessageDecryptionStep::NeedsState(second),
                ) => {
                    assert_eq!(first, second);
                }
                (
                    MessageDecryptionStep::NeedsAcknowledgmentTransport(first),
                    MessageDecryptionStep::NeedsAcknowledgmentTransport(second),
                ) => assert_eq!(Route::of(first), Route::of(second)),
                _ => panic!("asking again changed the request"),
            }
        }
        match step {
            MessageDecryptionStep::NeedsState(addresses) => {
                decryption.supply_state(host.read(&addresses)).unwrap();
            }
            MessageDecryptionStep::NeedsAdmission(_) => decryption.confirm_admission().unwrap(),
            MessageDecryptionStep::NeedsAcknowledgmentTransport(_) => {
                decryption
                    .supply_acknowledgment_transport_binding(binding())
                    .unwrap();
            }
            MessageDecryptionStep::Ready(outcome) => return *outcome,
        }
    }
}

#[test]
fn asking_a_waiting_decryption_again_repeats_no_work() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    establish(&mut alice, &mut bob);
    let sent = alice.send(&bob, b"once");

    let outcomes = [false, true].map(|ask_twice| {
        let decryption = bob
            .store
            .start_decryption(bob.incoming(&sent.message))
            .unwrap();
        let InboundMessageOutcome::Accepted(received) =
            open_and_acknowledge(decryption, &bob.host, ask_twice)
        else {
            panic!("expected Bob to accept the Message")
        };
        received.acknowledgment.unwrap().to_bytes().unwrap()
    });

    // Opening and sealing draw randomness, so repeated work would change the acknowledgment.
    assert_eq!(outcomes[0], outcomes[1]);
}
