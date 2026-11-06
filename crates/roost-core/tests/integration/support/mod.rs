pub(crate) mod device;
pub(crate) mod host_identity;

use device::{Decrypted, Device, Relay, Sealed, binding, run_encryption};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use roost_core::{
    ContactIdentityKey, DomainSigningKey, InboundMessageOutcome, IncomingMessage,
    MessageDecryptionStep, MessageOperationError, MessageStartError, OutboundMessageResult,
    OutgoingMessage, ProtocolStateAddress, ProtocolStateBlob, ProtocolStateKind,
    ProtocolStateSnapshot, ProtocolStateUpdate, ReceiveSettings, RevocationState, SealedFrame,
    SenderCertificateValidation, SessionId, SignedSenderCertificate, StateChanges,
    TransportBinding, commit_conditions_match,
};
use roost_crypto::{SigningKeyPair, generate_signing_key_pair};
use roost_protocol::{MessageId, from_unix_secs};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

pub(crate) const CREATED_AT_SECS: u64 = 1_700_000_000;
pub(crate) const TEST_RELAY_DOMAIN: &[u8] = b"relay.test";
const CERTIFICATE_LABEL: &[u8] = b"RoostSenderCertificate-v1:";
const CERTIFICATE_VERSION: u8 = 1;
const TEST_DOMAIN_ID: &[u8] = b"test-domain";

/// Alice and Bob, each a device, who accepted each other: Alice asked on the fixture's session and
/// Bob's contact acceptance replied on it, so Alice's messages no longer carry the handshake, and
/// each acknowledged the other's inbox grant, so neither sends one again.
pub(crate) struct ProtocolFixture {
    pub(crate) session_id: SessionId,
    pub(crate) alice: Device,
    pub(crate) bob: Device,
    pub(crate) binding: TransportBinding,
}

/// The app's database: the records Roost asked it to keep, the messages it queued, and the sent
/// messages it shows as not delivered.
#[derive(Clone, Default)]
pub(crate) struct HostStore {
    blobs: BTreeMap<ProtocolStateAddress, Zeroizing<Vec<u8>>>,
    outbox: Vec<SealedFrame>,
    undelivered: Vec<MessageId>,
}

impl HostStore {
    pub(crate) fn snapshot(&self) -> ProtocolStateSnapshot {
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

    /// Commits `changes` in one transaction when every commit condition still holds, and returns
    /// the updates it wrote.
    pub(crate) fn commit(
        &mut self,
        changes: StateChanges,
    ) -> Result<Vec<ProtocolStateUpdate>, HostCommitError> {
        self.commit_with(changes, None)
    }

    /// Commits a sent message's changes and queues the message in the same transaction.
    pub(crate) fn commit_sent(
        &mut self,
        sent: &OutboundMessageResult,
        changes: StateChanges,
    ) -> Result<Vec<ProtocolStateUpdate>, HostCommitError> {
        self.commit_with(changes, Some(sent.message.clone()))
    }

    /// Returns the host's entry for each requested record, with `None` where it holds none.
    pub(crate) fn read(
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

    // Checks every condition, then writes the updates, queues `outbox`, and marks the undelivered
    // messages, as one transaction.
    fn commit_with(
        &mut self,
        changes: StateChanges,
        outbox: Option<SealedFrame>,
    ) -> Result<Vec<ProtocolStateUpdate>, HostCommitError> {
        let addresses: Vec<_> = changes
            .conditions()
            .iter()
            .map(|(address, _)| address.clone())
            .collect();
        if !commit_conditions_match(changes.conditions(), &self.read(&addresses)).unwrap() {
            return Err(HostCommitError::StaleCondition);
        }
        self.undelivered.extend_from_slice(changes.undelivered());
        let updates = changes.into_updates();
        self.apply_all(&updates);
        self.outbox.extend(outbox);
        Ok(updates)
    }

    pub(crate) fn outbox(&self) -> &[SealedFrame] {
        &self.outbox
    }

    /// Returns every sent message the host shows as not delivered, in the order commits marked
    /// them.
    pub(crate) fn undelivered(&self) -> &[MessageId] {
        &self.undelivered
    }

    pub(crate) fn remove(&mut self, address: &ProtocolStateAddress) {
        self.blobs.remove(address);
    }

    /// Returns this database as restoring it from a backup leaves it: the contact records kept,
    /// and every other record and queued message gone.
    pub(crate) fn restored(&self) -> Self {
        Self {
            blobs: self
                .blobs
                .iter()
                .filter(|(address, _)| address.kind() == ProtocolStateKind::ContactState)
                .map(|(address, blob)| (address.clone(), blob.clone()))
                .collect(),
            outbox: Vec::new(),
            undelivered: self.undelivered.clone(),
        }
    }

    /// Returns the address of every record of `kind` the host holds.
    pub(crate) fn addresses(&self, kind: ProtocolStateKind) -> Vec<ProtocolStateAddress> {
        self.blobs
            .keys()
            .filter(|address| address.kind() == kind)
            .cloned()
            .collect()
    }

    /// Returns the address of the one record of `kind` the host holds.
    pub(crate) fn only(&self, kind: ProtocolStateKind) -> ProtocolStateAddress {
        let [address] = &self.addresses(kind)[..] else {
            panic!("expected one {kind} record");
        };
        address.clone()
    }

    /// Deletes the records of the one session the host holds, as a host that lost them does.
    pub(crate) fn forget_session(&mut self) {
        for kind in [
            ProtocolStateKind::RatchetSession,
            ProtocolStateKind::PendingAcknowledgments,
        ] {
            let address = self.only(kind);
            self.remove(&address);
        }
    }

    pub(crate) fn set_raw(&mut self, address: ProtocolStateAddress, blob: Vec<u8>) {
        self.blobs.insert(address, Zeroizing::new(blob));
    }

    /// Returns every stored blob, to compare whole stores before and after an operation.
    pub(crate) fn snapshot_bytes(&self) -> BTreeMap<ProtocolStateAddress, Vec<u8>> {
        self.blobs
            .iter()
            .map(|(address, blob)| (address.clone(), blob.to_vec()))
            .collect()
    }

    /// Cuts the last byte off the record at `address`, as a torn write does, and returns what's
    /// left.
    pub(crate) fn corrupt(&mut self, address: &ProtocolStateAddress) -> Vec<u8> {
        let mut blob = self.blob_bytes(address).unwrap();
        blob.pop();
        self.set_raw(address.clone(), blob.clone());
        blob
    }

    pub(crate) fn blob_bytes(&self, address: &ProtocolStateAddress) -> Option<Vec<u8>> {
        self.blobs.get(address).map(|blob| blob.to_vec())
    }

    /// Writes `updates` without checking any condition, as a host that commits only part of a
    /// result does.
    pub(crate) fn apply_all(&mut self, updates: &[ProtocolStateUpdate]) {
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
pub(crate) enum HostCommitError {
    StaleCondition,
}

pub(crate) struct StoredMessage {
    pub(crate) message_id: MessageId,
    pub(crate) plaintext: Vec<u8>,
    pub(crate) message: SealedFrame,
}

/// The test domain's signing key, which every device's relay certificate names.
pub(crate) fn trusted_domain_signing_key() -> DomainSigningKey {
    DomainSigningKey {
        id: TEST_DOMAIN_ID.to_vec(),
        verifying_key: test_domain_key().verifying.to_bytes(),
    }
}

/// Every identity's certificate validation inputs at the fixed test time.
pub(crate) fn validation(
    domain_signing_keys: Vec<DomainSigningKey>,
    revoked_identity_keys: Vec<ContactIdentityKey>,
) -> SenderCertificateValidation {
    SenderCertificateValidation {
        domain_signing_keys,
        expected_relay_domain: TEST_RELAY_DOMAIN.to_vec(),
        revocation_state: RevocationState::Available(revoked_identity_keys),
        reference_time: from_unix_secs(CREATED_AT_SECS).unwrap(),
    }
}

/// The test domain's validation inputs with nothing revoked.
pub(crate) fn trusted_validation() -> SenderCertificateValidation {
    validation(vec![trusted_domain_signing_key()], Vec::new())
}

/// Returns `identity_key`'s certificate from the test domain, expiring at `expires_at_secs`.
pub(crate) fn certificate_until(
    identity_key: ContactIdentityKey,
    expires_at_secs: u64,
) -> SignedSenderCertificate {
    let certificate = sender_certificate_bytes(TEST_DOMAIN_ID, identity_key, expires_at_secs);
    SignedSenderCertificate {
        signature: test_domain_key().sign(&certificate).to_bytes(),
        certificate,
    }
}

fn test_domain_key() -> SigningKeyPair {
    generate_signing_key_pair(&mut ChaCha20Rng::from_seed([0x90; 32]))
}

/// Runs `decryption` over `host`'s records, confirming admission and supplying `binding` when its
/// acknowledgment asks for a transport.
pub(crate) fn run_decryption(
    mut decryption: roost_core::MessageDecryption,
    host: &HostStore,
    rng: &mut ChaCha20Rng,
    binding: &TransportBinding,
) -> Result<Decrypted, MessageOperationError> {
    let mut admission = None;
    let mut acknowledgment_destination = None;
    loop {
        match decryption.step(rng)? {
            MessageDecryptionStep::NeedsState(addresses) => {
                decryption.supply_state(host.read(&addresses))?;
            }
            MessageDecryptionStep::NeedsAdmission(request) => {
                admission = Some(request);
                decryption.confirm_admission()?;
            }
            MessageDecryptionStep::NeedsAcknowledgmentTransport(destination) => {
                acknowledgment_destination = Some(destination);
                decryption.supply_acknowledgment_transport_binding(binding.clone())?;
            }
            MessageDecryptionStep::Ready { outcome, changes } => {
                return Ok(Decrypted {
                    outcome,
                    changes,
                    admission,
                    acknowledgment_destination,
                });
            }
        }
    }
}

// Starting an operation fails only on its inputs, which these tests report as protocol faults.
fn started<T>(started: Result<T, MessageStartError>) -> Result<T, MessageOperationError> {
    started.map_err(start_failure)
}

pub(crate) fn start_failure(error: MessageStartError) -> MessageOperationError {
    match error {
        MessageStartError::ProtocolState(error) => MessageOperationError::ProtocolState(error),
        error @ (MessageStartError::Discovery(_)
        | MessageStartError::Identity(_)
        | MessageStartError::Operation(_)) => panic!("operation failed to start: {error}"),
    }
}

impl ProtocolFixture {
    pub(crate) fn new() -> Self {
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
        // Bob acknowledges a message carrying Alice's grant, so neither side sends a grant again.
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

    /// Has Bob send to Alice on the session Roost selects, and Alice receive it.
    pub(crate) fn bob_replies(&mut self, seed: u8) {
        let reply = self.bob.send(&self.alice, &[seed]);
        accepted(self.alice.receive(&reply.message));
    }

    /// Returns Alice's input for sending `plaintext` to Bob as message number `sequence`.
    pub(crate) fn outgoing(&self, sequence: u16, plaintext: &[u8]) -> OutgoingMessage {
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
    pub(crate) fn incoming(
        &self,
        message: &SealedFrame,
        settings: ReceiveSettings,
        validation: SenderCertificateValidation,
    ) -> IncomingMessage {
        IncomingMessage {
            message: message.clone(),
            transport_binding: self.binding.clone(),
            settings,
            sender_certificate_validation: validation,
            acknowledgment_sent_at_millis: 1_700_000_100_000 + 0xee,
            acknowledgment_sender_certificate: self.bob.certificate(),
        }
    }

    /// Has Alice encrypt `outgoing` over `store` without committing.
    pub(crate) fn encrypt(
        &self,
        store: &HostStore,
        outgoing: OutgoingMessage,
        rng_seed: u8,
    ) -> Result<Sealed, MessageOperationError> {
        Ok(run_encryption(
            started(self.alice.store.start_encryption(outgoing))?,
            store,
            &mut ChaCha20Rng::from_seed([rng_seed; 32]),
            &self.binding,
        )?
        .ready())
    }

    /// Has Bob decrypt `incoming` over `store` without committing.
    pub(crate) fn decrypt(
        &self,
        store: &HostStore,
        incoming: IncomingMessage,
        rng_seed: u8,
    ) -> Result<Decrypted, MessageOperationError> {
        run_decryption(
            started(self.bob.store.start_decryption(incoming))?,
            store,
            &mut ChaCha20Rng::from_seed([rng_seed; 32]),
            &self.binding,
        )
    }

    /// Has Bob receive `message` over `store` with default settings and the trusted domain.
    pub(crate) fn receive(
        &self,
        store: &HostStore,
        message: &SealedFrame,
        rng_seed: u8,
    ) -> Result<Decrypted, MessageOperationError> {
        self.decrypt(
            store,
            self.incoming(message, ReceiveSettings::default(), trusted_validation()),
            rng_seed,
        )
    }

    /// Has Alice receive `message` over her store, such as Bob's reply, without committing.
    pub(crate) fn alice_receives(
        &self,
        message: &SealedFrame,
        rng_seed: u8,
    ) -> Result<Decrypted, MessageOperationError> {
        self.alice_receives_over(&self.alice.host, message, rng_seed)
    }

    /// Has Alice receive `message` over `store` without committing.
    pub(crate) fn alice_receives_over(
        &self,
        store: &HostStore,
        message: &SealedFrame,
        rng_seed: u8,
    ) -> Result<Decrypted, MessageOperationError> {
        run_decryption(
            started(self.alice.store.start_decryption(IncomingMessage {
                message: message.clone(),
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

    /// Has Alice encrypt to Bob and commits the message with its changes.
    pub(crate) fn encrypt_from_alice(&mut self, sequence: u16, plaintext: &[u8]) -> StoredMessage {
        let Sealed {
            result, changes, ..
        } = self
            .encrypt(
                &self.alice.host,
                self.outgoing(sequence, plaintext),
                sequence as u8,
            )
            .unwrap();
        self.alice.host.commit_sent(&result, changes).unwrap();
        StoredMessage {
            message_id: result.message_id,
            plaintext: plaintext.to_vec(),
            message: result.message,
        }
    }

    /// Has Bob receive `message` and commits what it changed.
    pub(crate) fn decrypt_for_bob(
        &mut self,
        message: &StoredMessage,
        rng_seed: u8,
    ) -> ReceivedMessage {
        let decrypted = self
            .receive(&self.bob.host, &message.message, rng_seed)
            .unwrap();
        self.bob.host.commit(decrypted.changes).unwrap();
        let received = accepted(decrypted.outcome);
        ReceivedMessage {
            message_id: received.message_id,
            plaintext: received.plaintext,
            acknowledgment: received
                .acknowledgment
                .expect("an accepted contact acknowledges"),
        }
    }
}

/// A received message after the host committed it.
pub(crate) struct ReceivedMessage {
    pub(crate) message_id: MessageId,
    pub(crate) plaintext: Zeroizing<Vec<u8>>,
    pub(crate) acknowledgment: SealedFrame,
}

pub(crate) fn accepted(outcome: InboundMessageOutcome) -> roost_core::InboundMessageResult {
    let InboundMessageOutcome::Accepted(result) = outcome else {
        panic!("expected an accepted message")
    };
    *result
}

/// Returns the bytes the test domain signs for `identity_key`, as a relay issues a sender
/// certificate.
pub(crate) fn sender_certificate_bytes(
    signing_key_id: &[u8],
    identity_key: ContactIdentityKey,
    expires_at_secs: u64,
) -> Vec<u8> {
    let mut bytes = CERTIFICATE_LABEL.to_vec();
    bytes.push(CERTIFICATE_VERSION);
    for field in [signing_key_id, TEST_RELAY_DOMAIN] {
        bytes.extend_from_slice(&u32::try_from(field.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(field);
    }
    bytes.extend_from_slice(&identity_key.x25519_public_key);
    bytes.extend_from_slice(&identity_key.ed25519_verifying_key);
    bytes.extend_from_slice(&expires_at_secs.to_be_bytes());
    bytes
}
