#![allow(dead_code, unreachable_pub)]

pub mod device;
pub mod host_identity;

use roost_protocol::from_unix_secs;
use std::collections::BTreeMap;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use roost_core::{
    ContactDiscoveryKey, ContactIdentity, ContactIdentityKey, InboundMessageOutcome,
    InboundSenderCertificateValidation, InboundSessionStart, IncomingMessage,
    KnownDomainSigningKey, LocalIdentityKeys, LocalSender, Message, MessageDecryption,
    MessageDecryptionStep, MessageEncryption, MessageEncryptionStep, MessageOperationError,
    OutboundMessageResult, OutboundSessionStart, OutgoingMessage, ProtocolStateAddress,
    ProtocolStateBlob, ProtocolStateEngine, ProtocolStateKey, ProtocolStateKind,
    ProtocolStateSnapshot, ProtocolStateUpdate, PublicDiscoveryKey, ReceiveSettings,
    SenderIdentityMaterial, SessionAcceptanceOutcome, SessionId, SessionUnrecoverableResult,
    Signature, SignedSenderCertificate, StateChanges, TransportBinding,
};
use roost_crypto::{
    DiscoveryKey, KeyPair, PreKeyBundle, PublicIdentityKey, SignedPreKey, SigningKeyPair,
    generate_discovery_key, generate_signed_prekey_for_discovery_key, generate_signing_key_pair,
    sign_identity_key_binding,
};
use roost_protocol::{DomainSigningKeyStatus, MessageId, SenderCertificateIdentityKey};
use zeroize::Zeroizing;

pub const CREATED_AT_SECS: u64 = 1_700_000_000;
pub const TEST_RELAY_DOMAIN: &[u8] = b"relay.test";
const CERTIFICATE_DOMAIN_TAG: &[u8] = b"AetherSenderCertificate-v2:";
const CERTIFICATE_VERSION: u8 = 2;

pub struct ProtocolFixture {
    pub session_id: SessionId,
    pub alice_store: HostStore,
    pub bob_store: HostStore,
    pub alice_sender: ValidatedSender,
    pub bob_sender: SenderIdentityMaterial,
    pub binding: TransportBinding,
    pub alice: TestIdentity,
    pub bob: TestIdentity,
    pub bob_signed_prekey: SignedPreKey,
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

pub struct ValidatedSender {
    pub sender_identity: SenderIdentityMaterial,
    domain_id: Vec<u8>,
    domain_verifying_key: [u8; 32],
}

impl ValidatedSender {
    pub fn domain_signing_key(&self) -> KnownDomainSigningKey {
        KnownDomainSigningKey {
            id: self.domain_id.clone(),
            verifying_key: self.domain_verifying_key,
            status: DomainSigningKeyStatus::Trusted,
        }
    }
}

/// Runs `encryption` over `host`'s records, supplying `binding` when it asks for a transport.
pub fn run_encryption(
    mut encryption: MessageEncryption,
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
            MessageEncryptionStep::Ready(result) => return Ok(*result),
        }
    }
}

/// Runs `decryption` over `host`'s records, supplying `binding` when its acknowledgment asks for
/// a transport.
pub fn run_decryption(
    mut decryption: MessageDecryption,
    host: &HostStore,
    rng: &mut ChaCha20Rng,
    binding: &TransportBinding,
) -> Result<InboundMessageOutcome, MessageOperationError> {
    loop {
        match decryption.step(rng)? {
            MessageDecryptionStep::NeedsState(addresses) => {
                decryption.supply_state(host.read(&addresses))?;
            }
            MessageDecryptionStep::NeedsAcknowledgmentTransport(_) => {
                decryption.supply_acknowledgment_transport_binding(binding.clone())?;
            }
            MessageDecryptionStep::Ready(outcome) => return Ok(*outcome),
        }
    }
}

/// Takes the changes an outcome asks the host to commit, if any, leaving empty changes behind.
pub fn split_changes(
    mut outcome: InboundMessageOutcome,
) -> (InboundMessageOutcome, Option<StateChanges>) {
    let changes = match &mut outcome {
        InboundMessageOutcome::Accepted(result) => Some(&mut result.changes),
        InboundMessageOutcome::Blocked(result) => Some(&mut result.changes),
        InboundMessageOutcome::SessionUnrecoverable(result) => Some(&mut result.changes),
        InboundMessageOutcome::AcknowledgmentMatched(result)
        | InboundMessageOutcome::AcknowledgmentUnmatched(result) => Some(&mut result.changes),
        InboundMessageOutcome::Duplicate | InboundMessageOutcome::UnknownSession => None,
    }
    .map(|changes| std::mem::replace(changes, StateChanges::from(Vec::new())));
    (outcome, changes)
}

/// One identity's secrets and certified public material, held in memory for engine-level tests.
pub struct TestIdentity {
    tag: u8,
    discovery_seed: u8,
    pub sender_identity: SenderIdentityMaterial,
    pub signing_key: SigningKeyPair,
    pub agreement_key: KeyPair,
    pub discovery_key: DiscoveryKey,
    discovery_public: PublicDiscoveryKey,
    discovery_to_identity: Signature,
}

impl TestIdentity {
    /// Creates an identity whose certificate the test domain signed.
    pub fn new(tag: u8, discovery_seed: u8) -> Self {
        let signing_key = SigningKeyPair::from_signing_bytes([tag; 32]);
        let agreement_key = KeyPair::from_secret_bytes([tag.wrapping_add(0x33); 32]);
        let discovery_key = discovery_key(&signing_key, discovery_seed);
        let public_identity_key = PublicIdentityKey {
            public_key: agreement_key.public,
            verifying_key: signing_key.verifying,
            binding_signature: sign_identity_key_binding(&signing_key, &agreement_key.public)
                .unwrap(),
        };
        let identity_key = ContactIdentityKey {
            x25519_public_key: *agreement_key.public.as_bytes(),
            ed25519_verifying_key: signing_key.verifying.to_bytes(),
        };
        let certificate =
            sender_certificate_bytes(TEST_DOMAIN_ID, identity_key, CREATED_AT_SECS + 100_000);
        let certificate_signature = test_domain_key().sign(&certificate).to_bytes().to_vec();
        Self {
            tag,
            discovery_seed,
            sender_identity: SenderIdentityMaterial {
                identity_key: identity_key.x25519_public_key,
                identity_verifying_key: identity_key.ed25519_verifying_key,
                identity_binding_signature: public_identity_key
                    .binding_signature
                    .to_bytes()
                    .to_vec(),
                certificate,
                signature: certificate_signature,
            },
            discovery_public: discovery_key.public(),
            discovery_to_identity: discovery_key
                .sign_identity_binding(&public_identity_key)
                .unwrap(),
            signing_key,
            agreement_key,
            discovery_key,
        }
    }

    pub fn identity_key(&self) -> ContactIdentityKey {
        ContactIdentityKey {
            x25519_public_key: self.sender_identity.identity_key,
            ed25519_verifying_key: self.sender_identity.identity_verifying_key,
        }
    }

    /// Returns a copy of this identity's secret keys for one Message Operation.
    pub fn local_keys(&self) -> LocalIdentityKeys {
        LocalIdentityKeys {
            agreement_key: KeyPair::from_secret_bytes([self.tag.wrapping_add(0x33); 32]),
            signing_key: SigningKeyPair::from_signing_bytes([self.tag; 32]),
            discovery_key: discovery_key(&self.signing_key, self.discovery_seed),
        }
    }

    /// Returns this identity's sender certificate and the domain's signature.
    pub fn certificate(&self) -> SignedSenderCertificate {
        signed(&self.sender_identity)
    }

    pub fn public_identity_key(&self) -> PublicIdentityKey {
        PublicIdentityKey::from_bytes(
            &self.sender_identity.identity_key,
            &self.sender_identity.identity_verifying_key,
            &self.sender_identity.identity_binding_signature,
        )
        .unwrap()
    }

    pub fn contact_identity(&self) -> ContactIdentity {
        ContactIdentity {
            identity_key: self.identity_key(),
            discovery_key: ContactDiscoveryKey::from(&self.discovery_public),
        }
    }

    pub fn local_sender(&self) -> LocalSender<'_> {
        LocalSender {
            identity: &self.sender_identity,
            signing_key: &self.signing_key,
            agreement_key: &self.agreement_key,
            discovery_key: &self.discovery_public,
            discovery_to_identity: &self.discovery_to_identity,
        }
    }

    pub fn discovery_to_identity(&self) -> &Signature {
        &self.discovery_to_identity
    }

    /// Returns this identity's keys sealing `identity` in place of its own certified material.
    pub fn local_sender_with<'a>(
        &'a self,
        identity: &'a SenderIdentityMaterial,
    ) -> LocalSender<'a> {
        LocalSender {
            identity,
            ..self.local_sender()
        }
    }

    /// Returns this identity's material with a certificate that expires at `expires_at_secs`.
    pub fn certified_until(&self, expires_at_secs: u64) -> SenderIdentityMaterial {
        let certificate =
            sender_certificate_bytes(TEST_DOMAIN_ID, self.identity_key(), expires_at_secs);
        let mut identity = self.sender_identity.clone();
        identity.signature = test_domain_key().sign(&certificate).to_bytes().to_vec();
        identity.certificate = certificate;
        identity
    }
}

const TEST_DOMAIN_ID: &[u8] = b"test-domain";

fn test_domain_key() -> SigningKeyPair {
    generate_signing_key_pair(&mut ChaCha20Rng::from_seed([0x90; 32]))
}

pub fn validated_sender() -> ValidatedSender {
    ValidatedSender {
        sender_identity: TestIdentity::new(0xa2, 0xc2).sender_identity,
        domain_id: TEST_DOMAIN_ID.to_vec(),
        domain_verifying_key: test_domain_key().verifying.to_bytes(),
    }
}

/// Returns `identity`'s certificate and signature as a sender passes them.
pub fn signed(identity: &SenderIdentityMaterial) -> SignedSenderCertificate {
    SignedSenderCertificate {
        certificate: identity.certificate.clone(),
        signature: identity.signature.clone(),
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
    validation(vec![validated_sender().domain_signing_key()], Vec::new())
}

impl ProtocolFixture {
    /// Starts a Session from Alice to Bob through the engine's handshake, then has Bob reply once
    /// so Alice's Messages no longer carry the handshake.
    pub fn new(seed: [u8; 32]) -> Self {
        let engine = ProtocolStateEngine::new();
        let mut rng = ChaCha20Rng::from_seed(seed);
        let alice = TestIdentity::new(0xa2, 0xc2);
        let bob = TestIdentity::new(0xa1, 0x71);
        let bob_signed_prekey = generate_signed_prekey_for_discovery_key(
            &mut rng,
            &bob.discovery_key,
            0,
            CREATED_AT_SECS,
        )
        .unwrap();
        let binding = TransportBinding::new(b"test-route".to_vec()).unwrap();
        let mut alice_store = HostStore::default();
        let mut bob_store = HostStore::default();
        for (store, peer) in [(&mut alice_store, &bob), (&mut bob_store, &alice)] {
            let recorded = engine
                .record_contact(&store.snapshot(), peer.contact_identity())
                .unwrap();
            store.apply_all(recorded.state_updates);
            let accepted = engine
                .accept_contact(&store.snapshot(), peer.identity_key())
                .unwrap();
            store.apply_all(accepted.state_updates);
        }
        let mut fixture = Self {
            session_id: SessionId::from_bytes([0; 16]),
            alice_store,
            bob_store,
            alice_sender: validated_sender(),
            bob_sender: bob.sender_identity.clone(),
            binding,
            alice,
            bob,
            bob_signed_prekey,
        };
        fixture.start_session(&engine, &mut rng);
        fixture
    }

    /// Runs a fresh handshake from Alice to Bob and has Bob reply once, so the new Session is the
    /// one both send on and Alice's Messages no longer carry the handshake.
    pub fn start_session(&mut self, engine: &ProtocolStateEngine, rng: &mut ChaCha20Rng) {
        let initiation = engine
            .initiate_session(
                rng,
                &self.alice_store.snapshot(),
                OutboundSessionStart {
                    responder_identity_key: &self.bob.public_identity_key(),
                    responder_discovery_to_identity: self.bob.discovery_to_identity(),
                    responder_prekey_bundle: &PreKeyBundle {
                        version: roost_crypto::PREKEY_BUNDLE_VERSION,
                        discovery_key: self.bob.discovery_key.public(),
                        signed_prekey: self.bob_signed_prekey.public(),
                        one_time_prekey: None,
                    },
                    sender: self.alice.local_sender(),
                    id: MessageId::from_bytes([0x01; 16]),
                    sent_at_millis: CREATED_AT_SECS * 1000,
                    plaintext: b"initial",
                },
                &self.binding,
            )
            .unwrap();
        self.alice_store.commit(initiation.state_updates).unwrap();
        let SessionAcceptanceOutcome::Accepted(accepted) = engine
            .accept_session(
                rng,
                &self.bob_store.snapshot(),
                InboundSessionStart {
                    message: &initiation.message,
                    recipient_discovery_key: &self.bob.discovery_key,
                    signed_prekey: &self.bob_signed_prekey,
                    one_time_prekey: None,
                    held_signed_prekeys: &[self.bob_signed_prekey.public()],
                    settings: ReceiveSettings::default(),
                    sender_certificate_validation: &trusted_validation(),
                },
                &self.binding,
            )
            .unwrap()
        else {
            panic!("fixture handshake was not accepted")
        };
        self.bob_store.commit(accepted.state_updates).unwrap();
        self.bob_replies(engine, 0x45);
        self.session_id = initiation.session_id;
    }

    /// Has Bob send to Alice on the Session Roost selects, and Alice receive it.
    pub fn bob_replies(&mut self, engine: &ProtocolStateEngine, seed: u8) {
        let mut id = [0xb0; 16];
        id[1] = seed;
        let reply = run_encryption(
            engine
                .start_encryption(
                    self.bob.local_keys(),
                    OutgoingMessage {
                        recipient: self.alice.identity_key(),
                        message_id: MessageId::from_bytes(id),
                        sent_at_millis: CREATED_AT_SECS * 1000,
                        sender_certificate: self.bob.certificate(),
                        plaintext: Zeroizing::new(b"reply".to_vec()),
                    },
                )
                .unwrap(),
            &self.bob_store,
            &mut ChaCha20Rng::from_seed([seed; 32]),
            &self.binding,
        )
        .unwrap();
        let message = Message::from_bytes(&reply.message.to_bytes().unwrap()).unwrap();
        self.bob_store.commit_changes(reply.changes).unwrap();
        let received = accepted(self.alice_receives(engine, &message, seed).unwrap());
        self.alice_store.commit_changes(received.changes).unwrap();
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
            acknowledgment_sender_certificate: signed(&self.bob_sender),
        }
    }

    /// Has Alice encrypt `outgoing` over `store` without committing.
    pub fn encrypt(
        &self,
        engine: &ProtocolStateEngine,
        store: &HostStore,
        outgoing: OutgoingMessage,
        rng_seed: u8,
    ) -> Result<OutboundMessageResult, MessageOperationError> {
        run_encryption(
            engine.start_encryption(self.alice.local_keys(), outgoing)?,
            store,
            &mut ChaCha20Rng::from_seed([rng_seed; 32]),
            &self.binding,
        )
    }

    /// Has Bob decrypt `incoming` over `store` without committing.
    pub fn decrypt(
        &self,
        engine: &ProtocolStateEngine,
        store: &HostStore,
        incoming: IncomingMessage,
        rng_seed: u8,
    ) -> Result<InboundMessageOutcome, MessageOperationError> {
        run_decryption(
            engine.start_decryption(self.bob.local_keys(), incoming)?,
            store,
            &mut ChaCha20Rng::from_seed([rng_seed; 32]),
            &self.binding,
        )
    }

    /// Has Bob receive `message` over `store` with default settings and the trusted domain.
    pub fn receive(
        &self,
        engine: &ProtocolStateEngine,
        store: &HostStore,
        message: &Message,
        rng_seed: u8,
    ) -> Result<InboundMessageOutcome, MessageOperationError> {
        self.decrypt(
            engine,
            store,
            self.incoming(message, ReceiveSettings::default(), trusted_validation()),
            rng_seed,
        )
    }

    /// Has Alice receive `message` over her store, such as Bob's reply, without committing.
    pub fn alice_receives(
        &self,
        engine: &ProtocolStateEngine,
        message: &Message,
        rng_seed: u8,
    ) -> Result<InboundMessageOutcome, MessageOperationError> {
        self.alice_receives_over(engine, &self.alice_store, message, rng_seed)
    }

    /// Has Alice receive `message` over `store` without committing.
    pub fn alice_receives_over(
        &self,
        engine: &ProtocolStateEngine,
        store: &HostStore,
        message: &Message,
        rng_seed: u8,
    ) -> Result<InboundMessageOutcome, MessageOperationError> {
        run_decryption(
            engine.start_decryption(
                self.alice.local_keys(),
                IncomingMessage {
                    message: copy(message),
                    transport_binding: self.binding.clone(),
                    settings: ReceiveSettings::default(),
                    sender_certificate_validation: trusted_validation(),
                    acknowledgment_sent_at_millis: 1_700_000_100_000 + 0xef,
                    acknowledgment_sender_certificate: self.alice.certificate(),
                },
            )?,
            store,
            &mut ChaCha20Rng::from_seed([rng_seed; 32]),
            &self.binding,
        )
    }

    /// Has Alice encrypt to Bob and commits the Message with its changes.
    pub fn encrypt_from_alice(
        &mut self,
        engine: &ProtocolStateEngine,
        sequence: u16,
        plaintext: &[u8],
    ) -> StoredMessage {
        let encrypted = self
            .encrypt(
                engine,
                &self.alice_store,
                self.outgoing(sequence, plaintext),
                sequence as u8,
            )
            .unwrap();
        let message_id = encrypted.message_id;
        let message = copy(&encrypted.message);
        self.alice_store.commit_sent(encrypted).unwrap();
        StoredMessage {
            message_id,
            plaintext: plaintext.to_vec(),
            message,
        }
    }

    /// Has Bob receive `message` and commits what it changed.
    pub fn decrypt_for_bob(
        &mut self,
        engine: &ProtocolStateEngine,
        message: &StoredMessage,
        rng_seed: u8,
    ) -> ReceivedMessage {
        let decrypted = accepted(
            self.receive(engine, &self.bob_store, &message.message, rng_seed)
                .unwrap(),
        );
        self.bob_store.commit_changes(decrypted.changes).unwrap();
        ReceivedMessage {
            message_id: decrypted.message_id,
            plaintext: decrypted.plaintext,
            acknowledgment: decrypted.acknowledgment,
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

pub fn session_unrecoverable(outcome: InboundMessageOutcome) -> SessionUnrecoverableResult {
    let InboundMessageOutcome::SessionUnrecoverable(result) = outcome else {
        panic!("expected an unrecoverable session")
    };
    *result
}

pub fn dead_session_blob(
    event_emitted: bool,
    peer_identity_key: ContactIdentityKey,
) -> ProtocolStateBlob {
    // Blob version 1, the peer's two key halves, Unrecoverable variant 1, reason 0, event flag.
    let mut bytes = vec![1];
    bytes.extend_from_slice(&peer_identity_key.x25519_public_key);
    bytes.extend_from_slice(&peer_identity_key.ed25519_verifying_key);
    bytes.extend_from_slice(&[1, 0, u8::from(event_emitted)]);
    ProtocolStateBlob::from_bytes(bytes)
}

pub fn accepted_contact_identity() -> ContactIdentity {
    TestIdentity::new(0xa1, 0x71).contact_identity()
}

pub fn acknowledgment_recipient_discovery_key() -> DiscoveryKey {
    TestIdentity::new(0xa2, 0xc2).discovery_key
}

fn discovery_key(signing_key: &SigningKeyPair, seed: u8) -> DiscoveryKey {
    generate_discovery_key(
        &mut ChaCha20Rng::from_seed([seed; 32]),
        signing_key,
        0,
        CREATED_AT_SECS,
    )
    .unwrap()
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
