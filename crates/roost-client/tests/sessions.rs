//! Two hosts become contacts and exchange Messages through the exported Message Operations.

mod support;

use roost_client::{
    BlockedContactAcknowledgmentPolicy, ContactSafetyNumberConfirmation, ContactTrustState,
    DeliveryCheckResult, DeliveryCheckStep, DomainSigningKey, DomainSigningKeyStatus,
    IdentityContext, IdentityKey, InboundMessageOutcome, IncomingMessage, Message,
    MessageDecryptionStep, MessageDestination, MessageEncryption, MessageEncryptionStep, MessageId,
    MessageRecoveryStep, OperationId, OutboundMessageResult, OutgoingGrantUpdate, OutgoingMessage,
    OutgoingRecovery, PayloadKind, PreKeyBundle, ProtocolStateKind, ReceiveSettings,
    RevocationState, RoostError, SenderCertificateValidation, SessionId, SignedSenderCertificate,
    StateChanges, StateEntry, StateKey, TransportBinding, derive_safety_number,
};
use roost_crypto::{RecipientDeliveryCapability, SigningKeyPair};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use support::MemoryStorage;

const CERTIFICATE_DOMAIN_TAG: &[u8] = b"RoostSenderCertificate-v2:";
const CERTIFICATE_VERSION: u8 = 2;
const DOMAIN_SIGNING_KEY_ID: &[u8] = b"relay-signing-key";
const RELAY_DOMAIN: &[u8] = b"relay.example";
const NOW_MILLIS: u64 = 1_700_000_000_000;

fn domain_signing_key() -> SigningKeyPair {
    SigningKeyPair::from_signing_bytes([0x41; 32])
}

fn binding() -> TransportBinding {
    TransportBinding {
        bytes: b"route".to_vec(),
    }
}

fn settings() -> ReceiveSettings {
    ReceiveSettings {
        deduplication_capacity: 1024,
        blocked_contact_acknowledgment_policy: BlockedContactAcknowledgmentPolicy::Unreachable,
        certificate_grace_millis: 0,
    }
}

fn validation() -> SenderCertificateValidation {
    SenderCertificateValidation {
        domain_signing_keys: vec![DomainSigningKey {
            id: DOMAIN_SIGNING_KEY_ID.to_vec(),
            verifying_key: domain_signing_key().verifying.to_bytes().to_vec(),
            status: DomainSigningKeyStatus::Trusted,
        }],
        expected_relay_domain: RELAY_DOMAIN.to_vec(),
        revocation_state: RevocationState {
            available: true,
            revoked_identity_keys: Vec::new(),
        },
        reference_time_millis: NOW_MILLIS,
    }
}

/// A sealed Message, the destination Roost named for it, and the changes to commit with it.
struct Sealed {
    result: OutboundMessageResult,
    destination: MessageDestination,
}

/// One app's IdentityContext, its host store, and the certificate its relay issued.
struct Host {
    context: Arc<IdentityContext>,
    records: HashMap<StateKey, Vec<u8>>,
    certificate: Vec<u8>,
    certificate_signature: Vec<u8>,
}

impl Host {
    fn new() -> Self {
        let context = IdentityContext::new(Arc::new(MemoryStorage::default()));
        let identity = context.prepare_identity_creation().unwrap();
        complete(&context, identity.operation_id);
        let signed_prekey = context.prepare_signed_prekey_rotation().unwrap();
        complete(&context, signed_prekey.operation_id);
        // Encoded as a relay's domain authority does before signing.
        let certificate = [
            CERTIFICATE_DOMAIN_TAG,
            &[CERTIFICATE_VERSION],
            &[u8::try_from(DOMAIN_SIGNING_KEY_ID.len()).unwrap()],
            DOMAIN_SIGNING_KEY_ID,
            &[u8::try_from(RELAY_DOMAIN.len()).unwrap()],
            RELAY_DOMAIN,
            &identity.identity.key.agreement_key,
            &identity.identity.key.signing_key,
            &(NOW_MILLIS / 1_000 + 3_600).to_be_bytes(),
        ]
        .concat();
        Self {
            certificate_signature: domain_signing_key().sign(&certificate).to_bytes().to_vec(),
            certificate,
            records: HashMap::new(),
            context,
        }
    }

    fn identity_key(&self) -> IdentityKey {
        self.context.identity().unwrap().unwrap().key
    }

    fn signed_certificate(&self) -> SignedSenderCertificate {
        SignedSenderCertificate {
            certificate: self.certificate.clone(),
            signature: self.certificate_signature.clone(),
        }
    }

    // Publishes a bundle with a fresh one-time prekey, as the relay would serve it.
    fn bundle(&self) -> PreKeyBundle {
        let one_time_prekeys = self.context.prepare_one_time_prekeys(1).unwrap();
        complete(&self.context, one_time_prekeys.operation_id);
        PreKeyBundle {
            identity: self.context.identity().unwrap().unwrap(),
            publication: self.context.current_publication().unwrap(),
            one_time_prekey: Some(one_time_prekeys.one_time_prekeys[0].clone()),
        }
    }

    fn snapshot(&self) -> Vec<StateEntry> {
        self.records
            .iter()
            .map(|(key, blob)| StateEntry {
                key: key.clone(),
                blob: Some(blob.clone()),
            })
            .collect()
    }

    fn read(&self, keys: &[StateKey]) -> Vec<StateEntry> {
        keys.iter()
            .map(|key| StateEntry {
                key: key.clone(),
                blob: self.records.get(key).cloned(),
            })
            .collect()
    }

    // Returns the record the host holds for `peer`'s contact, by decoding each contact record.
    fn contact_record(&self, peer: &Host) -> Option<Vec<u8>> {
        let contacts = self.context.contacts();
        self.records
            .iter()
            .filter(|(key, _)| matches!(key.kind, ProtocolStateKind::ContactState))
            .find(|(key, blob)| {
                contacts
                    .contact_state(StateEntry {
                        key: (*key).clone(),
                        blob: Some((*blob).clone()),
                    })
                    .unwrap()
                    .is_some_and(|contact| contact.identity_key == peer.identity_key())
            })
            .map(|(_, blob)| blob.clone())
    }

    // Writes `changes` only when every condition holds, as one host transaction does, around the
    // operation the changes carry.
    fn commit(&mut self, changes: StateChanges) -> bool {
        if let Some(operation) = &changes.operation_id {
            self.context.reserve_operation(operation.clone()).unwrap();
        }
        let keys: Vec<_> = changes
            .conditions
            .iter()
            .map(|condition| condition.key.clone())
            .collect();
        if !changes.matches(self.read(&keys)).unwrap() {
            if let Some(operation) = changes.operation_id {
                self.context.abort_operation(operation).unwrap();
            }
            return false;
        }
        for update in changes.updates {
            match update.blob {
                Some(blob) => self.records.insert(update.key, blob),
                None => self.records.remove(&update.key),
            };
        }
        if let Some(operation) = changes.operation_id {
            self.context.finalize_operation(operation).unwrap();
        }
        true
    }

    fn outgoing(&self, recipient: &Host, plaintext: &[u8]) -> OutgoingMessage {
        OutgoingMessage {
            recipient: recipient.identity_key(),
            message_id: self.context.messaging().create_message().unwrap(),
            sent_at_millis: NOW_MILLIS,
            sender_certificate: self.signed_certificate(),
            plaintext: plaintext.to_vec(),
            prekey_bundle: None,
        }
    }

    fn grant_update(&self, recipient: &Host) -> OutgoingGrantUpdate {
        OutgoingGrantUpdate {
            recipient: recipient.identity_key(),
            message_id: self.context.messaging().create_message().unwrap(),
            sent_at_millis: NOW_MILLIS,
            sender_certificate: self.signed_certificate(),
            prekey_bundle: None,
        }
    }

    // Runs `encryption`, and returns the contact whose bundle it needs when it asks for one.
    fn seal(&self, encryption: Arc<MessageEncryption>) -> Result<Sealed, IdentityKey> {
        let mut destination = None;
        loop {
            match encryption.step().unwrap() {
                MessageEncryptionStep::NeedsState { keys } => {
                    encryption.supply_state(self.read(&keys)).unwrap();
                }
                MessageEncryptionStep::NeedsTransport { destination: asked } => {
                    destination = Some(asked);
                    encryption.supply_transport_binding(binding()).unwrap();
                }
                MessageEncryptionStep::NeedsPreKeyBundle { identity_key } => {
                    return Err(identity_key);
                }
                MessageEncryptionStep::NothingToSend => panic!("expected a Message to seal"),
                MessageEncryptionStep::Ready { result } => {
                    return Ok(Sealed {
                        result,
                        destination: destination.unwrap(),
                    });
                }
            }
        }
    }

    fn encrypt(&self, outgoing: OutgoingMessage) -> Result<OutboundMessageResult, RoostError> {
        let encryption = self.context.messaging().start_encryption(outgoing)?;
        Ok(self.seal(encryption).unwrap().result)
    }

    fn send(&mut self, recipient: &Host, plaintext: &[u8]) -> (SessionId, MessageId, Message) {
        let sent = self.encrypt(self.outgoing(recipient, plaintext)).unwrap();
        assert!(self.commit(sent.changes));
        (sent.session_id, sent.message_id, sent.message)
    }

    // Asks `recipient` to become a contact, fetching their bundle when Roost asks for it.
    fn request(&mut self, recipient: &Host, plaintext: &[u8]) -> Sealed {
        let contacts = self.context.contacts();
        let mut draft = self.outgoing(recipient, plaintext);
        let first = self.seal(contacts.request_contact(redraft(&draft)).unwrap());
        assert_eq!(first.err(), Some(recipient.identity_key()));
        draft.prekey_bundle = Some(recipient.bundle());
        let mut sealed = self.seal(contacts.request_contact(draft).unwrap()).unwrap();
        assert!(self.commit(take_changes(&mut sealed.result)));
        sealed
    }

    fn accept(&mut self, requester: &Host, plaintext: &[u8]) -> Sealed {
        let encryption = self
            .context
            .contacts()
            .accept_contact(self.outgoing(requester, plaintext))
            .unwrap();
        let mut sealed = self.seal(encryption).unwrap();
        assert!(self.commit(take_changes(&mut sealed.result)));
        sealed
    }

    fn decrypt(&self, message: Message) -> Result<InboundMessageOutcome, RoostError> {
        let decryption = self.context.messaging().start_decryption(IncomingMessage {
            message,
            transport_binding: binding(),
            settings: settings(),
            sender_certificate_validation: validation(),
            acknowledgment_sent_at_millis: NOW_MILLIS,
            acknowledgment_sender_certificate: self.signed_certificate(),
        })?;
        loop {
            match decryption.step()? {
                MessageDecryptionStep::NeedsState { keys } => {
                    decryption.supply_state(self.read(&keys))?;
                }
                MessageDecryptionStep::NeedsAdmission { .. } => decryption.confirm_admission()?,
                MessageDecryptionStep::NeedsAcknowledgmentTransport { .. } => {
                    decryption.supply_acknowledgment_transport_binding(binding())?;
                }
                MessageDecryptionStep::Ready { outcome } => return Ok(outcome),
            }
        }
    }
}

impl Host {
    // Checks the delivery of what this host sent `peer`, and commits the result.
    fn check_deliveries(&mut self, peer: &Host, now_millis: u64) -> DeliveryCheckResult {
        let check = self
            .context
            .messaging()
            .start_delivery_check(peer.identity_key(), now_millis)
            .unwrap();
        loop {
            match check.step().unwrap() {
                DeliveryCheckStep::NeedsState { keys } => {
                    check.supply_state(self.read(&keys)).unwrap();
                }
                DeliveryCheckStep::Ready { mut result } => {
                    let changes = std::mem::replace(
                        &mut result.changes,
                        StateChanges {
                            conditions: Vec::new(),
                            updates: Vec::new(),
                            operation_id: None,
                            undelivered: Vec::new(),
                        },
                    );
                    assert!(self.commit(changes));
                    return result;
                }
            }
        }
    }

    // Runs one recovery of what this host sent `peer`, supplying `content` for the Message it
    // names, and returns how it ended with the destination it named.
    fn recover(
        &self,
        peer: &Host,
        prekey_bundle: Option<PreKeyBundle>,
        content: &[u8],
    ) -> (MessageRecoveryStep, Option<MessageDestination>) {
        let recovery = self
            .context
            .messaging()
            .start_recovery(OutgoingRecovery {
                recipient: peer.identity_key(),
                sender_certificate: self.signed_certificate(),
                prekey_bundle,
            })
            .unwrap();
        let mut destination = None;
        loop {
            match recovery.step().unwrap() {
                MessageRecoveryStep::NeedsState { keys } => {
                    recovery.supply_state(self.read(&keys)).unwrap();
                }
                MessageRecoveryStep::NeedsContent { .. } => {
                    recovery.supply_content(content.to_vec()).unwrap();
                }
                MessageRecoveryStep::NeedsTransport { destination: asked } => {
                    destination = Some(asked);
                    recovery.supply_transport_binding(binding()).unwrap();
                }
                ended @ (MessageRecoveryStep::NeedsPreKeyBundle { .. }
                | MessageRecoveryStep::AwaitingProbe { .. }
                | MessageRecoveryStep::Finished
                | MessageRecoveryStep::Ready { .. }) => return (ended, destination),
            }
        }
    }
}

// Copies a draft, as an app restarts it under the same MessageID.
fn redraft(draft: &OutgoingMessage) -> OutgoingMessage {
    OutgoingMessage {
        recipient: draft.recipient.clone(),
        message_id: draft.message_id.clone(),
        sent_at_millis: draft.sent_at_millis,
        sender_certificate: SignedSenderCertificate {
            certificate: draft.sender_certificate.certificate.clone(),
            signature: draft.sender_certificate.signature.clone(),
        },
        plaintext: draft.plaintext.clone(),
        prekey_bundle: draft.prekey_bundle.clone(),
    }
}

// Takes the changes a sealed Message commits with, leaving none behind.
fn take_changes(result: &mut OutboundMessageResult) -> StateChanges {
    std::mem::replace(
        &mut result.changes,
        StateChanges {
            conditions: Vec::new(),
            updates: Vec::new(),
            operation_id: None,
            undelivered: Vec::new(),
        },
    )
}

fn complete(context: &IdentityContext, id: OperationId) {
    context.reserve_operation(id.clone()).unwrap();
    context.finalize_operation(id).unwrap();
}

fn received(outcome: InboundMessageOutcome) -> roost_client::InboundMessageResult {
    let (InboundMessageOutcome::Accepted { result }
    | InboundMessageOutcome::ContactRequest { result }) = outcome
    else {
        panic!("expected a delivered Message")
    };
    result
}

fn verifier(destination: &MessageDestination) -> Vec<u8> {
    let MessageDestination::Established {
        delivery_capability,
        ..
    } = destination
    else {
        panic!("expected an established Message");
    };
    RecipientDeliveryCapability::from_bytes(delivery_capability.as_slice().try_into().unwrap())
        .verifier()
        .as_bytes()
        .to_vec()
}

// Alice asks Bob, Bob accepts, and Alice receives the acceptance. Returns the SessionID as each
// host saw it.
fn establish(alice: &mut Host, bob: &mut Host) -> (SessionId, SessionId) {
    let request = alice.request(bob, b"hello bob");
    let InboundMessageOutcome::ContactRequest { result } =
        bob.decrypt(request.result.message.clone()).unwrap()
    else {
        panic!("expected a contact request");
    };
    assert_eq!(result.plaintext, b"hello bob");
    assert!(bob.commit(result.changes));
    let acceptance = bob.accept(alice, b"hello alice");
    let accepted = received(alice.decrypt(acceptance.result.message).unwrap());
    assert!(alice.commit(accepted.changes));
    (request.result.session_id, result.session_id)
}

#[test]
fn a_request_routes_to_the_bundle_and_commits_its_one_time_prekey_with_the_contact() {
    let mut alice = Host::new();
    let mut bob = Host::new();

    let request = alice.request(&bob, b"hello bob");

    let MessageDestination::FirstMessage {
        identity_key,
        signed_prekey_id,
        one_time_prekey_id,
        ..
    } = &request.destination
    else {
        panic!("expected a first Message");
    };
    assert_eq!(*identity_key, bob.identity_key());
    let publication = bob.context.current_publication().unwrap();
    assert_eq!(*signed_prekey_id, publication.signed_prekey.id);
    assert!(one_time_prekey_id.is_some());
    let InboundMessageOutcome::ContactRequest { result } =
        bob.decrypt(request.result.message).unwrap()
    else {
        panic!("expected a contact request");
    };
    assert!(result.acknowledgment.is_none());
    assert!(result.changes.operation_id.is_some());
    assert!(bob.commit(result.changes));
    let contact = bob
        .context
        .contacts()
        .contact_states(
            bob.snapshot()
                .into_iter()
                .filter(|entry| matches!(entry.key.kind, ProtocolStateKind::ContactState))
                .collect(),
        )
        .unwrap()
        .remove(0);
    assert_eq!(contact.identity_key, alice.identity_key());
    assert!(matches!(contact.trust_state, ContactTrustState::Pending));
}

#[test]
fn an_acceptance_opens_established_routes_to_both_inboxes() {
    let mut alice = Host::new();
    let mut bob = Host::new();
    let request = alice.request(&bob, b"hello bob");
    assert!(bob.commit(received(bob.decrypt(request.result.message).unwrap()).changes));

    let acceptance = bob.accept(&alice, b"welcome");

    assert_eq!(
        verifier(&acceptance.destination),
        alice
            .context
            .current_publication()
            .unwrap()
            .recipient_delivery_verifier
    );
    assert!(alice.commit(received(alice.decrypt(acceptance.result.message).unwrap()).changes));
    let message = alice.encrypt(alice.outgoing(&bob, b"thanks")).unwrap();
    assert!(message.message.prekey_reference.is_none());
    let sealed = alice
        .seal(
            alice
                .context
                .messaging()
                .start_encryption(alice.outgoing(&bob, b"again"))
                .unwrap(),
        )
        .unwrap();
    assert_eq!(
        verifier(&sealed.destination),
        bob.context
            .current_publication()
            .unwrap()
            .recipient_delivery_verifier
    );
}

#[test]
fn a_reply_and_its_acknowledgment_round_trip_on_one_canonical_session_id() {
    let mut alice = Host::new();
    let mut bob = Host::new();

    let (alice_view, bob_view) = establish(&mut alice, &mut bob);

    assert_eq!(alice_view, bob_view);
    assert_eq!(
        HashSet::from([alice_view.clone(), bob_view.clone()]).len(),
        1
    );
    assert_eq!(alice_view.value.len(), 32);
    assert!(
        alice_view
            .value
            .bytes()
            .all(|digit| matches!(digit, b'0'..=b'9' | b'a'..=b'f'))
    );
    let (session_id, message_id, reply) = bob.send(&alice, b"hello again");
    assert_eq!(session_id, bob_view);
    let result = received(alice.decrypt(reply).unwrap());
    assert_eq!(result.session_id, alice_view);
    assert_eq!(result.message_id, message_id);
    assert_eq!(result.plaintext, b"hello again");
    assert!(alice.commit(result.changes));

    let Ok(InboundMessageOutcome::AcknowledgmentMatched { result: matched }) =
        bob.decrypt(result.acknowledgment.unwrap())
    else {
        panic!("expected the reply's acknowledgment");
    };
    assert_eq!(matched.acknowledged_message_id, message_id);
    assert!(bob.commit(matched.changes));
    assert!(
        bob.context
            .messaging()
            .pending_acknowledgments(bob.snapshot(), bob_view)
            .unwrap()
            .iter()
            .all(|pending| pending.message_id != message_id)
    );
}

#[test]
fn safety_number_confirmation_uses_the_contexts_local_identity() {
    let mut alice = Host::new();
    let mut bob = Host::new();
    let charlie = Host::new();
    establish(&mut alice, &mut bob);
    let contacts = alice.context.contacts();
    let foreign = derive_safety_number(charlie.identity_key(), bob.identity_key()).unwrap();

    let rejected = contacts
        .confirm_contact_safety_number(
            bob.identity_key(),
            alice.contact_record(&bob),
            foreign.grouped_decimal,
        )
        .unwrap();
    assert!(matches!(
        rejected,
        ContactSafetyNumberConfirmation::Mismatched
    ));
    let correct = derive_safety_number(alice.identity_key(), bob.identity_key()).unwrap();
    let ContactSafetyNumberConfirmation::Matched { changes } = contacts
        .confirm_contact_safety_number(
            bob.identity_key(),
            alice.contact_record(&bob),
            correct.grouped_decimal,
        )
        .unwrap()
    else {
        panic!("expected the Safety Number to match");
    };
    assert!(alice.commit(changes));

    let record = alice.contact_record(&bob);
    let contact = alice
        .context
        .contacts()
        .contact_state(StateEntry {
            key: alice
                .records
                .iter()
                .find(|(_, blob)| Some(*blob) == record.as_ref())
                .unwrap()
                .0
                .clone(),
            blob: record,
        })
        .unwrap()
        .unwrap();
    assert!(matches!(contact.trust_state, ContactTrustState::Verified));
}

#[test]
fn blocking_rotates_the_inbox_through_the_operation_its_changes_carry() {
    let mut alice = Host::new();
    let mut bob = Host::new();
    establish(&mut alice, &mut bob);
    let before = alice.context.current_publication().unwrap();

    let block = alice
        .context
        .contacts()
        .prepare_block_contact(bob.identity_key(), alice.contact_record(&bob))
        .unwrap();

    assert!(block.changes.operation_id.is_some());
    let publication = block.publication.unwrap();
    assert!(alice.commit(block.changes));
    assert_eq!(
        alice.context.current_publication().unwrap().discovery_key,
        publication.discovery_key
    );
    assert_ne!(publication.discovery_key, before.discovery_key);
    let unblock = alice
        .context
        .contacts()
        .unblock_contact(bob.identity_key(), alice.contact_record(&bob))
        .unwrap();
    assert!(unblock.operation_id.is_none());
    assert!(alice.commit(unblock));
}

#[test]
fn a_grant_update_after_a_rotation_is_acknowledged_and_then_has_nothing_to_send() {
    let mut alice = Host::new();
    let mut bob = Host::new();
    establish(&mut alice, &mut bob);
    let rotation = bob.context.prepare_inbox_rotation().unwrap();
    complete(&bob.context, rotation.operation_id);
    let contacts = bob.context.contacts();

    let mut update = bob
        .seal(
            contacts
                .start_grant_update(bob.grant_update(&alice))
                .unwrap(),
        )
        .unwrap();

    assert!(matches!(
        update.result.payload_kind,
        PayloadKind::GrantUpdate
    ));
    assert!(bob.commit(take_changes(&mut update.result)));
    let InboundMessageOutcome::GrantUpdate { result } =
        alice.decrypt(update.result.message).unwrap()
    else {
        panic!("expected a Grant Update");
    };
    let acknowledgment = result.acknowledgment.unwrap();
    assert!(alice.commit(result.changes));
    let InboundMessageOutcome::AcknowledgmentMatched { result } =
        bob.decrypt(acknowledgment).unwrap()
    else {
        panic!("expected the Grant Update's acknowledgment");
    };
    assert!(bob.commit(result.changes));
    let again = contacts
        .start_grant_update(bob.grant_update(&alice))
        .unwrap();
    let mut step = again.step().unwrap();
    while let MessageEncryptionStep::NeedsState { keys } = step {
        again.supply_state(bob.read(&keys)).unwrap();
        step = again.step().unwrap();
    }
    assert!(matches!(step, MessageEncryptionStep::NothingToSend));
}

#[test]
fn session_ids_must_be_canonical() {
    let mut alice = Host::new();
    let mut bob = Host::new();
    let (session_id, _) = establish(&mut alice, &mut bob);

    for value in [
        session_id.value.to_uppercase(),
        session_id.value[..30].to_string(),
        format!("{}0", session_id.value),
    ] {
        assert!(matches!(
            alice
                .context
                .messaging()
                .pending_acknowledgments(alice.snapshot(), SessionId { value }),
            Err(RoostError::InvalidData { .. })
        ));
    }
}

#[test]
fn each_draft_gets_its_own_canonical_message_id() {
    let alice = Host::new();
    let bob = Host::new();
    let messaging = alice.context.messaging();
    let ids: HashSet<_> = (0..16)
        .map(|_| messaging.create_message().unwrap())
        .collect();

    assert_eq!(ids.len(), 16);
    for id in &ids {
        assert_eq!(id.value.len(), 32);
        assert!(
            id.value
                .bytes()
                .all(|digit| matches!(digit, b'0'..=b'9' | b'a'..=b'f'))
        );
    }
    let mut uppercase = alice.outgoing(&bob, b"never sent");
    uppercase.message_id.value = uppercase.message_id.value.to_uppercase();
    assert!(matches!(
        messaging.start_encryption(uppercase),
        Err(RoostError::InvalidData { .. })
    ));
}

#[test]
fn a_malformed_entry_ends_the_operation() {
    let mut alice = Host::new();
    let mut bob = Host::new();
    establish(&mut alice, &mut bob);
    let encryption = alice
        .context
        .messaging()
        .start_encryption(alice.outgoing(&bob, b"never sent"))
        .unwrap();
    let MessageEncryptionStep::NeedsState { keys } = encryption.step().unwrap() else {
        panic!("expected a read");
    };
    let mut entries = alice.read(&keys);
    entries[0].key.id = entries[0].key.id.to_uppercase();

    assert!(matches!(
        encryption.supply_state(entries),
        Err(RoostError::InvalidData { .. })
    ));
    assert!(matches!(
        encryption.step(),
        Err(RoostError::OperationFinished)
    ));
    assert!(matches!(
        encryption.supply_transport_binding(binding()),
        Err(RoostError::OperationFinished)
    ));
}

#[test]
fn calls_from_two_threads_take_turns() {
    let mut alice = Host::new();
    let mut bob = Host::new();
    establish(&mut alice, &mut bob);
    let encryption: Arc<MessageEncryption> = alice
        .context
        .messaging()
        .start_encryption(alice.outgoing(&bob, b"shared"))
        .unwrap();

    let requests: Vec<_> = (0..2)
        .map(|_| {
            let encryption = Arc::clone(&encryption);
            std::thread::spawn(move || match encryption.step().unwrap() {
                MessageEncryptionStep::NeedsState { keys } => keys,
                MessageEncryptionStep::NeedsTransport { .. }
                | MessageEncryptionStep::NeedsPreKeyBundle { .. }
                | MessageEncryptionStep::NothingToSend
                | MessageEncryptionStep::Ready { .. } => panic!("expected a read"),
            })
        })
        .collect::<Vec<_>>()
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();

    assert_eq!(requests[0], requests[1]);
}

#[test]
fn matches_refuses_stale_and_malformed_records() {
    let mut alice = Host::new();
    let mut bob = Host::new();
    establish(&mut alice, &mut bob);
    let sent = alice.encrypt(alice.outgoing(&bob, b"conditional")).unwrap();
    let keys: Vec<_> = sent
        .changes
        .conditions
        .iter()
        .map(|condition| condition.key.clone())
        .collect();
    assert!(sent.changes.matches(alice.read(&keys)).unwrap());

    let mut changed = alice.read(&keys);
    changed[0].blob = Some(vec![1, 2, 3]);
    assert!(!sent.changes.matches(changed).unwrap());
    let mut missing = alice.read(&keys);
    missing.pop();
    assert!(matches!(
        sent.changes.matches(missing),
        Err(RoostError::InvalidData { .. })
    ));
}

#[test]
fn a_silent_contact_gets_its_unacknowledged_message_again_through_a_probe() {
    const DAY_MILLIS: u64 = 24 * 60 * 60 * 1000;
    let mut alice = Host::new();
    let mut bob = Host::new();
    establish(&mut alice, &mut bob);
    let (_, message_id, _) = alice.send(&bob, b"are you there?");

    assert!(
        alice
            .check_deliveries(&bob, NOW_MILLIS + 2 * DAY_MILLIS)
            .starts_recovery
    );
    let (needs_bundle, _) = alice.recover(&bob, None, b"are you there?");
    assert!(matches!(
        needs_bundle,
        MessageRecoveryStep::NeedsPreKeyBundle { identity_key } if identity_key == bob.identity_key()
    ));
    let (MessageRecoveryStep::Ready { mut result }, Some(destination)) =
        alice.recover(&bob, Some(bob.bundle()), b"are you there?")
    else {
        panic!("expected a resent Message");
    };
    assert!(matches!(
        destination,
        MessageDestination::FirstMessage { .. }
    ));
    assert_eq!(result.message_id, message_id);
    assert_eq!(result.sent_at_millis, NOW_MILLIS);
    assert!(alice.commit(take_changes(&mut result)));

    assert!(matches!(
        alice.recover(&bob, None, b"").0,
        MessageRecoveryStep::AwaitingProbe { message_id: probe } if probe == message_id
    ));
    let delivered = received(bob.decrypt(result.message).unwrap());
    assert_eq!(delivered.message_id, message_id);
    assert_eq!(delivered.plaintext, b"are you there?");
}
