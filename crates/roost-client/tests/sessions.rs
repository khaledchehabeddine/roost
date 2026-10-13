//! Two hosts establish a Session and exchange Messages through the exported Message Operations.

mod support;

use roost_client::{
    BlockedContactAcknowledgmentPolicy, ContactIdentity, DomainSigningKey, DomainSigningKeyStatus,
    IdentityContext, IdentityKey, InboundMessageOutcome, IncomingMessage, Message,
    MessageDecryptionStep, MessageEncryption, MessageEncryptionStep, MessageId, OperationId,
    OutboundMessageResult, OutgoingMessage, PreKeySelection, ReceiveSettings, RevocationState,
    RoostError, SenderCertificateValidation, SessionAcceptanceOutcome, SessionId,
    SignedSenderCertificate, StateChanges, StateEntry, StateKey, TransportBinding,
};
use roost_crypto::SigningKeyPair;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use support::MemoryStorage;

const CERTIFICATE_DOMAIN_TAG: &[u8] = b"AetherSenderCertificate-v2:";
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

    fn contact(&self) -> ContactIdentity {
        let publication = self.context.current_publication().unwrap();
        ContactIdentity {
            identity_key: self.identity_key(),
            discovery_key: roost_client::ContactDiscoveryKey {
                x25519_public_key: publication.discovery_key.public_key,
                ed25519_verifying_key: publication.discovery_key.verifying_key,
                epoch: publication.discovery_key.epoch,
                created_at_millis: publication.discovery_key.created_at_millis,
                identity_signature: publication.discovery_key.signature,
            },
        }
    }

    fn accept_contact(&mut self, peer: &Host) {
        let contacts = self.context.contacts();
        let recorded = contacts
            .record_contact(self.snapshot(), peer.contact())
            .unwrap();
        assert!(self.commit(recorded.changes));
        let accepted = contacts
            .accept_contact(self.snapshot(), peer.identity_key())
            .unwrap();
        assert!(self.commit(accepted.changes));
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

    // Writes `changes` only when every condition holds, as one host transaction does.
    fn commit(&mut self, changes: StateChanges) -> bool {
        let keys: Vec<_> = changes
            .conditions
            .iter()
            .map(|condition| condition.key.clone())
            .collect();
        if !changes.matches(self.read(&keys)).unwrap() {
            return false;
        }
        for update in changes.updates {
            match update.blob {
                Some(blob) => self.records.insert(update.key, blob),
                None => self.records.remove(&update.key),
            };
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
        }
    }

    fn encrypt(&self, outgoing: OutgoingMessage) -> Result<OutboundMessageResult, RoostError> {
        let encryption = self.context.messaging().start_encryption(outgoing)?;
        loop {
            match encryption.step()? {
                MessageEncryptionStep::NeedsState { keys } => {
                    encryption.supply_state(self.read(&keys))?;
                }
                MessageEncryptionStep::NeedsTransport { .. } => {
                    encryption.supply_transport_binding(binding())?;
                }
                MessageEncryptionStep::Ready { result } => return Ok(result),
            }
        }
    }

    fn send(&mut self, recipient: &Host, plaintext: &[u8]) -> (SessionId, MessageId, Message) {
        let sent = self.encrypt(self.outgoing(recipient, plaintext)).unwrap();
        assert!(self.commit(sent.changes));
        (sent.session_id, sent.message_id, sent.message)
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
                MessageDecryptionStep::NeedsAcknowledgmentTransport { .. } => {
                    decryption.supply_acknowledgment_transport_binding(binding())?;
                }
                MessageDecryptionStep::Ready { outcome } => return Ok(outcome),
            }
        }
    }
}

fn complete(context: &IdentityContext, id: OperationId) {
    context.reserve_operation(id.clone()).unwrap();
    context.finalize_operation(id).unwrap();
}

// Starts a Session from `alice` to `bob`, has Bob accept it, and returns its SessionIDs as each
// host saw them.
fn establish(alice: &mut Host, bob: &mut Host) -> (SessionId, SessionId) {
    let one_time_prekeys = bob.context.prepare_one_time_prekeys(1).unwrap();
    complete(&bob.context, one_time_prekeys.operation_id);
    let one_time_prekey = one_time_prekeys.one_time_prekeys[0].clone();
    let publication = bob.context.current_publication().unwrap();
    let selection = PreKeySelection {
        signed_prekey_id: publication.signed_prekey.id,
        one_time_prekey_id: Some(one_time_prekey.id),
    };
    let initiation = alice
        .context
        .messaging()
        .initiate_session(
            alice.snapshot(),
            bob.context.identity().unwrap().unwrap(),
            publication,
            Some(one_time_prekey),
            alice.context.messaging().create_message().unwrap(),
            NOW_MILLIS,
            alice.signed_certificate(),
            b"hello bob".to_vec(),
            binding(),
        )
        .unwrap();
    assert!(alice.commit(initiation.changes));
    assert!(matches!(
        bob.decrypt(initiation.message.clone()),
        Ok(InboundMessageOutcome::UnknownSession)
    ));
    let prepared = bob
        .context
        .messaging()
        .prepare_accept_session(
            bob.snapshot(),
            initiation.message,
            settings(),
            validation(),
            binding(),
            selection,
        )
        .unwrap();
    bob.context
        .reserve_operation(prepared.operation_id.clone())
        .unwrap();
    let SessionAcceptanceOutcome::Accepted { result } = prepared.acceptance else {
        panic!("expected an accepted Session");
    };
    assert_eq!(result.plaintext, b"hello bob");
    assert!(bob.commit(result.changes));
    bob.context
        .finalize_operation(prepared.operation_id)
        .unwrap();
    (initiation.session_id, result.session_id)
}

fn befriended() -> (Host, Host) {
    let mut alice = Host::new();
    let mut bob = Host::new();
    alice.accept_contact(&bob);
    bob.accept_contact(&alice);
    (alice, bob)
}

#[test]
fn a_reply_and_its_acknowledgment_round_trip_on_one_canonical_session_id() {
    let (mut alice, mut bob) = befriended();

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
    let (session_id, message_id, reply) = bob.send(&alice, b"hello alice");
    assert_eq!(session_id, bob_view);
    let Ok(InboundMessageOutcome::Accepted { result }) = alice.decrypt(reply) else {
        panic!("expected an accepted reply");
    };
    assert_eq!(result.session_id, alice_view);
    assert_eq!(result.message_id, message_id);
    assert_eq!(result.plaintext, b"hello alice");
    assert!(alice.commit(result.changes));

    let Ok(InboundMessageOutcome::AcknowledgmentMatched { result: matched }) =
        bob.decrypt(result.acknowledgment)
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
            .is_empty()
    );
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
    let (alice, bob) = befriended();
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
    let (mut alice, mut bob) = befriended();
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
    let (mut alice, mut bob) = befriended();
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
    let (mut alice, mut bob) = befriended();
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
