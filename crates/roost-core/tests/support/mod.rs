#![allow(dead_code, unreachable_pub)]

pub mod device;
pub mod host_identity;

use device::{Device, Relay, binding};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use roost_core::{
    ContactIdentityKey, InboundMessageOutcome, InboundSenderCertificateValidation, IncomingMessage,
    KnownDomainSigningKey, Message, MessageDecryptionStep, MessageEncryptionStep,
    MessageOperationError, MessageStartError, OutboundMessageResult, OutgoingMessage,
    ProtocolStateAddress, ProtocolStateBlob, ProtocolStateKey, ProtocolStateKind,
    ProtocolStateSnapshot, ProtocolStateUpdate, ReceiveSettings, SessionId,
    SignedSenderCertificate, StateChanges, TransportBinding,
};
use roost_crypto::{SigningKeyPair, generate_signing_key_pair};
use roost_protocol::{
    DomainSigningKeyStatus, MessageId, SenderCertificateIdentityKey, from_unix_secs,
};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

pub const CREATED_AT_SECS: u64 = 1_700_000_000;
pub const TEST_RELAY_DOMAIN: &[u8] = b"relay.test";
const CERTIFICATE_DOMAIN_TAG: &[u8] = b"RoostSenderCertificate-v2:";
const CERTIFICATE_VERSION: u8 = 2;
const TEST_DOMAIN_ID: &[u8] = b"test-domain";

/// Alice and Bob, each a Device, who accepted each other: Alice asked on the fixture's Session and
/// Bob's Contact Acceptance replied on it, so Alice's Messages no longer carry the handshake, and
/// each acknowledged the other's Inbox Grant, so neither sends one again.
pub struct ProtocolFixture {
    pub session_id: SessionId,
    pub alice: Device,
    pub bob: Device,
    pub binding: TransportBinding,
}

#[derive(Clone, Default)]
pub struct HostStore {
    blobs: BTreeMap<ProtocolStateAddress, Zeroizing<Vec<u8>>>,
    outbox: Vec<OutboxRecord>,
}

impl HostStore {
    pub fn snapshot(&self) -> ProtocolStateSnapshot {
        let mut snapshot = ProtocolStateSnapshot::new();
        for (address, blob) in &self.blobs {
            snapshot
                .set(
                    address.clone(),
                    ProtocolStateBlob::from_bytes(blob.to_vec()),
                )
                .unwrap();
        }
        snapshot
    }

    pub fn commit(&mut self, updates: Vec<ProtocolStateUpdate>) -> Result<(), HostCommitError> {
        self.commit_with(updates, None)
    }

    pub fn commit_outbound(
        &mut self,
        updates: Vec<ProtocolStateUpdate>,
        message_id: MessageId,
        message: &Message,
    ) -> Result<(), HostCommitError> {
        self.commit_with(
            updates,
            Some(OutboxRecord {
                message_id,
                message: message.to_bytes().unwrap(),
            }),
        )
    }

    /// Commits `changes` in one transaction when every Commit Condition still holds.
    pub fn commit_changes(&mut self, changes: StateChanges) -> Result<(), HostCommitError> {
        self.commit_changes_with(changes, None)
    }

    /// Commits a sent Message's changes and queues the Message in the same transaction.
    pub fn commit_sent(&mut self, sent: OutboundMessageResult) -> Result<(), HostCommitError> {
        let outbox = OutboxRecord {
            message_id: sent.message_id,
            message: sent.message.to_bytes().unwrap(),
        };
        self.commit_changes_with(sent.changes, Some(outbox))
    }

    /// Returns the host's entry for each requested record, with `None` where it holds none.
    pub fn read(
        &self,
        addresses: &[ProtocolStateAddress],
    ) -> Vec<(ProtocolStateAddress, Option<ProtocolStateBlob>)> {
        addresses
            .iter()
            .map(|address| {
                (
                    address.clone(),
                    self.blobs
                        .get(address)
                        .map(|blob| ProtocolStateBlob::from_bytes(blob.to_vec())),
                )
            })
            .collect()
    }

    fn commit_changes_with(
        &mut self,
        changes: StateChanges,
        outbox: Option<OutboxRecord>,
    ) -> Result<(), HostCommitError> {
        let addresses: Vec<_> = changes
            .conditions()
            .iter()
            .map(|(address, _)| address.clone())
            .collect();
        if !changes.matches(&self.read(&addresses)).unwrap() {
            return Err(HostCommitError::StaleCondition);
        }
        self.apply_all(changes.into_updates());
        self.outbox.extend(outbox);
        Ok(())
    }

    pub fn outbox(&self) -> &[OutboxRecord] {
        &self.outbox
    }

    pub fn remove(&mut self, address: &ProtocolStateAddress) {
        self.blobs.remove(address);
    }

    /// Deletes every record stored under `session_id`, as a host that lost them does.
    pub fn forget_session(&mut self, session_id: SessionId) {
        let key = ProtocolStateKey::from_bytes(session_id.as_bytes().to_vec()).unwrap();
        self.blobs.retain(|address, _| *address.key() != key);
    }

    pub fn set_raw(&mut self, address: ProtocolStateAddress, blob: Vec<u8>) {
        self.blobs.insert(address, Zeroizing::new(blob));
    }

    /// Returns every stored blob, to compare whole stores before and after an operation.
    pub fn snapshot_bytes(&self) -> BTreeMap<ProtocolStateAddress, Vec<u8>> {
        self.blobs
            .iter()
            .map(|(address, blob)| (address.clone(), blob.to_vec()))
            .collect()
    }

    pub fn blob_bytes(&self, address: &ProtocolStateAddress) -> Option<Vec<u8>> {
        self.blobs.get(address).map(|blob| blob.to_vec())
    }

    fn commit_with(
        &mut self,
        updates: Vec<ProtocolStateUpdate>,
        outbox: Option<OutboxRecord>,
    ) -> Result<(), HostCommitError> {
        let snapshot = self.snapshot();
        if updates.iter().any(|update| {
            !update
                .commit_condition()
                .is_satisfied_by(snapshot.get(update.address()))
        }) {
            return Err(HostCommitError::StaleCondition);
        }
        // Validate the entire write set before changing either blobs or outbox effects.
        self.apply_all(updates);
        self.outbox.extend(outbox);
        Ok(())
    }

    pub fn apply_all(&mut self, updates: impl IntoIterator<Item = ProtocolStateUpdate>) {
        for update in updates {
            match update.blob() {
                Some(blob) => {
                    self.set_raw(update.address().clone(), blob.as_bytes().to_vec());
                }
                None => {
                    self.blobs.remove(update.address());
                }
            }
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum HostCommitError {
    StaleCondition,
}

#[derive(Clone)]
pub struct OutboxRecord {
    pub message_id: MessageId,
    message: Vec<u8>,
}

impl OutboxRecord {
    pub fn message(&self) -> Message {
        Message::from_bytes(&self.message).unwrap()
    }
}

pub struct StoredMessage {
    pub message_id: MessageId,
    pub plaintext: Vec<u8>,
    pub message: Message,
}

/// The test domain's signing key, which every Device's Relay certificate names.
pub fn trusted_domain_signing_key() -> KnownDomainSigningKey {
    KnownDomainSigningKey {
        id: TEST_DOMAIN_ID.to_vec(),
        verifying_key: test_domain_key().verifying.to_bytes(),
        status: DomainSigningKeyStatus::Trusted,
    }
}

/// Every identity's certificate validation inputs at the fixed test time.
pub fn validation(
    domain_signing_keys: Vec<KnownDomainSigningKey>,
    revoked_identity_keys: Vec<SenderCertificateIdentityKey>,
) -> InboundSenderCertificateValidation {
    InboundSenderCertificateValidation {
        domain_signing_keys,
        expected_relay_domain: TEST_RELAY_DOMAIN.to_vec(),
        revoked_identity_keys: Some(revoked_identity_keys),
        reference_time: from_unix_secs(CREATED_AT_SECS).unwrap(),
    }
}

/// The test domain's validation inputs with nothing revoked.
pub fn trusted_validation() -> InboundSenderCertificateValidation {
    validation(vec![trusted_domain_signing_key()], Vec::new())
}

/// Returns `identity_key`'s certificate from the test domain, expiring at `expires_at_secs`.
pub fn certificate_until(
    identity_key: ContactIdentityKey,
    expires_at_secs: u64,
) -> SignedSenderCertificate {
    let certificate = sender_certificate_bytes(TEST_DOMAIN_ID, identity_key, expires_at_secs);
    SignedSenderCertificate {
        signature: test_domain_key().sign(&certificate).to_bytes().to_vec(),
        certificate,
    }
}

fn test_domain_key() -> SigningKeyPair {
    generate_signing_key_pair(&mut ChaCha20Rng::from_seed([0x90; 32]))
}

/// Takes the changes an outcome asks the host to commit, if any, leaving empty changes behind.
pub fn split_changes(
    mut outcome: InboundMessageOutcome,
) -> (InboundMessageOutcome, Option<StateChanges>) {
    let changes = match &mut outcome {
        InboundMessageOutcome::Accepted(result) | InboundMessageOutcome::ContactRequest(result) => {
            Some(&mut result.changes)
        }
        InboundMessageOutcome::Blocked(result) => Some(&mut result.changes),
        InboundMessageOutcome::Withheld(result) => Some(&mut result.changes),
        InboundMessageOutcome::GrantUpdate(result) => Some(&mut result.changes),
        InboundMessageOutcome::AcknowledgmentMatched(result)
        | InboundMessageOutcome::AcknowledgmentUnmatched(result) => Some(&mut result.changes),
        InboundMessageOutcome::Duplicate
        | InboundMessageOutcome::UnknownSession
        | InboundMessageOutcome::DeletedSession => None,
    }
    .map(|changes| std::mem::replace(changes, StateChanges::from(Vec::new())));
    (outcome, changes)
}

/// Runs `encryption` over `host`'s records, supplying `binding` when it asks for a transport.
pub fn run_encryption(
    mut encryption: roost_core::MessageEncryption,
    host: &HostStore,
    rng: &mut ChaCha20Rng,
    binding: &TransportBinding,
) -> Result<OutboundMessageResult, MessageOperationError> {
    loop {
        match encryption.step(rng)? {
            MessageEncryptionStep::NeedsState(addresses) => {
                encryption.supply_state(host.read(&addresses))?;
            }
            MessageEncryptionStep::NeedsTransport(_) => {
                encryption.supply_transport_binding(binding.clone())?;
            }
            MessageEncryptionStep::NeedsPreKeyBundle(_) | MessageEncryptionStep::NothingToSend => {
                panic!("expected an existing Session")
            }
            MessageEncryptionStep::Ready(result) => return Ok(*result),
        }
    }
}

/// Runs `decryption` over `host`'s records, confirming admission and supplying `binding` when its
/// acknowledgment asks for a transport.
pub fn run_decryption(
    mut decryption: roost_core::MessageDecryption,
    host: &HostStore,
    rng: &mut ChaCha20Rng,
    binding: &TransportBinding,
) -> Result<InboundMessageOutcome, MessageOperationError> {
    loop {
        match decryption.step(rng)? {
            MessageDecryptionStep::NeedsState(addresses) => {
                decryption.supply_state(host.read(&addresses))?;
            }
            MessageDecryptionStep::NeedsAdmission(_) => decryption.confirm_admission()?,
            MessageDecryptionStep::NeedsAcknowledgmentTransport(_) => {
                decryption.supply_acknowledgment_transport_binding(binding.clone())?;
            }
            MessageDecryptionStep::Ready(outcome) => return Ok(*outcome),
        }
    }
}

// Starting an operation fails only on its inputs, which these tests report as protocol faults.
fn started<T>(started: Result<T, MessageStartError>) -> Result<T, MessageOperationError> {
    started.map_err(|error| match error {
        MessageStartError::ProtocolState(error) => MessageOperationError::ProtocolState(error),
        error @ (MessageStartError::Discovery(_)
        | MessageStartError::Identity(_)
        | MessageStartError::Operation(_)) => panic!("operation failed to start: {error}"),
    })
}

impl ProtocolFixture {
    pub fn new() -> Self {
        let relay = Relay::new();
        let mut alice = Device::new(&relay, 0xa2);
        let mut bob = Device::new(&relay, 0xa1);
        let request = alice.request(&bob, b"initial");
        assert!(matches!(
            bob.receive(&request.message),
            InboundMessageOutcome::ContactRequest(_)
        ));
        let acceptance = bob.accept_request(&alice, b"reply");
        let acknowledgment = accepted(alice.receive(&acceptance.message)).acknowledgment;
        bob.receive(&acknowledgment.unwrap());
        // Bob acknowledges a Message carrying Alice's grant, so neither side sends a grant again.
        let ready = alice.send(&bob, b"ready");
        let acknowledgment = accepted(bob.receive(&ready.message)).acknowledgment;
        alice.receive(&acknowledgment.unwrap());
        Self {
            session_id: request.session_id,
            alice,
            bob,
            binding: binding(),
        }
    }

    /// Starts a new Session from Alice to Bob, as a host that lost Alice's Session list does by
    /// requesting Bob again, and has Bob reply so neither side's Messages carry the handshake.
    pub fn start_session(&mut self) {
        self.alice
            .host
            .remove(&device::peer_sessions_address(self.bob.identity_key()));
        let request = self.alice.request(&self.bob, b"initial");
        accepted(self.bob.receive(&request.message));
        self.bob_replies(0x45);
        self.session_id = request.session_id;
    }

    /// Has Bob send to Alice on the Session Roost selects, and Alice receive it.
    pub fn bob_replies(&mut self, seed: u8) {
        let reply = self.bob.send(&self.alice, &[seed]);
        accepted(self.alice.receive(&reply.message));
    }

    /// Returns Alice's input for sending `plaintext` to Bob as Message number `sequence`.
    pub fn outgoing(&self, sequence: u16, plaintext: &[u8]) -> OutgoingMessage {
        let mut id = [0; 16];
        id[..2].copy_from_slice(&sequence.to_be_bytes());
        id[6] = 0x40;
        id[8] = 0x80;
        OutgoingMessage {
            recipient: self.bob.identity_key(),
            message_id: MessageId::from_bytes(id),
            sent_at_millis: 1_700_000_300_000 + u64::from(sequence),
            sender_certificate: self.alice.certificate(),
            plaintext: Zeroizing::new(plaintext.to_vec()),
            prekey_bundle: None,
        }
    }

    /// Returns Bob's input for receiving `message` with `settings` and certificate `validation`.
    pub fn incoming(
        &self,
        message: &Message,
        settings: ReceiveSettings,
        validation: InboundSenderCertificateValidation,
    ) -> IncomingMessage {
        IncomingMessage {
            message: copy(message),
            transport_binding: self.binding.clone(),
            settings,
            sender_certificate_validation: validation,
            acknowledgment_sent_at_millis: 1_700_000_100_000 + 0xee,
            acknowledgment_sender_certificate: self.bob.certificate(),
        }
    }

    /// Has Alice encrypt `outgoing` over `store` without committing.
    pub fn encrypt(
        &self,
        store: &HostStore,
        outgoing: OutgoingMessage,
        rng_seed: u8,
    ) -> Result<OutboundMessageResult, MessageOperationError> {
        run_encryption(
            started(self.alice.store.start_encryption(outgoing))?,
            store,
            &mut ChaCha20Rng::from_seed([rng_seed; 32]),
            &self.binding,
        )
    }

    /// Has Bob decrypt `incoming` over `store` without committing.
    pub fn decrypt(
        &self,
        store: &HostStore,
        incoming: IncomingMessage,
        rng_seed: u8,
    ) -> Result<InboundMessageOutcome, MessageOperationError> {
        run_decryption(
            started(self.bob.store.start_decryption(incoming))?,
            store,
            &mut ChaCha20Rng::from_seed([rng_seed; 32]),
            &self.binding,
        )
    }

    /// Has Bob receive `message` over `store` with default settings and the trusted domain.
    pub fn receive(
        &self,
        store: &HostStore,
        message: &Message,
        rng_seed: u8,
    ) -> Result<InboundMessageOutcome, MessageOperationError> {
        self.decrypt(
            store,
            self.incoming(message, ReceiveSettings::default(), trusted_validation()),
            rng_seed,
        )
    }

    /// Has Alice receive `message` over her store, such as Bob's reply, without committing.
    pub fn alice_receives(
        &self,
        message: &Message,
        rng_seed: u8,
    ) -> Result<InboundMessageOutcome, MessageOperationError> {
        self.alice_receives_over(&self.alice.host, message, rng_seed)
    }

    /// Has Alice receive `message` over `store` without committing.
    pub fn alice_receives_over(
        &self,
        store: &HostStore,
        message: &Message,
        rng_seed: u8,
    ) -> Result<InboundMessageOutcome, MessageOperationError> {
        run_decryption(
            started(self.alice.store.start_decryption(IncomingMessage {
                message: copy(message),
                transport_binding: self.binding.clone(),
                settings: ReceiveSettings::default(),
                sender_certificate_validation: trusted_validation(),
                acknowledgment_sent_at_millis: 1_700_000_100_000 + 0xef,
                acknowledgment_sender_certificate: self.alice.certificate(),
            }))?,
            store,
            &mut ChaCha20Rng::from_seed([rng_seed; 32]),
            &self.binding,
        )
    }

    /// Has Alice encrypt to Bob and commits the Message with its changes.
    pub fn encrypt_from_alice(&mut self, sequence: u16, plaintext: &[u8]) -> StoredMessage {
        let encrypted = self
            .encrypt(
                &self.alice.host,
                self.outgoing(sequence, plaintext),
                sequence as u8,
            )
            .unwrap();
        let message_id = encrypted.message_id;
        let message = copy(&encrypted.message);
        self.alice.host.commit_sent(encrypted).unwrap();
        StoredMessage {
            message_id,
            plaintext: plaintext.to_vec(),
            message,
        }
    }

    /// Has Bob receive `message` and commits what it changed.
    pub fn decrypt_for_bob(&mut self, message: &StoredMessage, rng_seed: u8) -> ReceivedMessage {
        let decrypted = accepted(
            self.receive(&self.bob.host, &message.message, rng_seed)
                .unwrap(),
        );
        self.bob.host.commit_changes(decrypted.changes).unwrap();
        ReceivedMessage {
            message_id: decrypted.message_id,
            plaintext: decrypted.plaintext,
            acknowledgment: decrypted
                .acknowledgment
                .expect("an accepted contact acknowledges"),
        }
    }
}

/// A received Message after the host committed it.
pub struct ReceivedMessage {
    pub message_id: MessageId,
    pub plaintext: Zeroizing<Vec<u8>>,
    pub acknowledgment: Message,
}

/// Returns a copy of `message`, even one too large to encode.
pub fn copy(message: &Message) -> Message {
    Message {
        version: message.version,
        recipient_public_key: message.recipient_public_key,
        prekey_reference: message.prekey_reference,
        ephemeral_public_key: message.ephemeral_public_key,
        ciphertext: message.ciphertext.clone(),
    }
}

pub fn session_address(session_id: SessionId) -> ProtocolStateAddress {
    ProtocolStateAddress::new(
        ProtocolStateKind::RatchetSession,
        ProtocolStateKey::from_bytes(session_id.as_bytes().to_vec()).unwrap(),
    )
}

/// The Deduplication Set's address, which Roost fixes.
pub fn deduplication_address() -> ProtocolStateAddress {
    ProtocolStateAddress::new(
        ProtocolStateKind::DeduplicationSet,
        ProtocolStateKey::from_bytes(vec![0]).unwrap(),
    )
}

pub fn accepted(outcome: InboundMessageOutcome) -> roost_core::InboundMessageResult {
    let InboundMessageOutcome::Accepted(result) = outcome else {
        panic!("expected an accepted message")
    };
    *result
}

pub fn sender_certificate_bytes(
    signing_key_id: &[u8],
    identity_key: ContactIdentityKey,
    expires_at_secs: u64,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(CERTIFICATE_DOMAIN_TAG);
    bytes.push(CERTIFICATE_VERSION);
    bytes.push(signing_key_id.len() as u8);
    bytes.extend_from_slice(signing_key_id);
    bytes.push(TEST_RELAY_DOMAIN.len() as u8);
    bytes.extend_from_slice(TEST_RELAY_DOMAIN);
    bytes.extend_from_slice(&identity_key.x25519_public_key);
    bytes.extend_from_slice(&identity_key.ed25519_verifying_key);
    bytes.extend_from_slice(&expires_at_secs.to_be_bytes());
    bytes
}
