#![allow(dead_code)]

use std::collections::BTreeMap;

use aether_core::{
    ContactDiscoveryKey, ContactIdentity, ContactIdentityKey, DomainSigningKey,
    DomainSigningKeyStatus, InboundEncryptedMessage, InboundMessageOutcome,
    InboundSenderCertificateValidation, Message, MessageId, OutboundAcknowledgment,
    OutboundPlaintext, ProtocolStateAddress, ProtocolStateBlob, ProtocolStateEngine,
    ProtocolStateKey, ProtocolStateKind, ProtocolStateSnapshot, ProtocolStateUpdate,
    RevocationState, SenderCertificateIdentityKey, SenderIdentityMaterial, SessionId,
    SessionUnrecoverableReason, SessionUnrecoverableResult,
};
use aether_crypto::{
    DiscoveryKey, IdentityKeyBundle, InitialPlaintext, KeyPair, PreKeyBundle, PublicKey,
    RatchetState, SigningKeyPair, accept, generate_discovery_key, generate_key_pair,
    generate_one_time_prekey, generate_signed_prekey_for_discovery_key, generate_signing_key_pair,
    initiate, sign_identity_key_binding,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::Serialize;
use zeroize::Zeroizing;

pub const CREATED_AT: u64 = 1_700_000_000;
const CERTIFICATE_DOMAIN_TAG: &[u8] = b"AetherSenderCertificate-v2:";
const CERTIFICATE_VERSION: u8 = 2;
const CERTIFICATE_EXPIRES_AT: u64 = 1_700_100_000;
const CERTIFICATE_REFERENCE_TIME: u64 = 1_700_000_000;

pub struct ProtocolFixture {
    pub session_key: ProtocolStateKey,
    pub deduplication_key: ProtocolStateKey,
    pub alice_store: HostStore,
    pub bob_store: HostStore,
    pub alice_sender: ValidatedSender,
    pub bob_sender: SenderIdentityMaterial,
}

#[derive(Clone, Default)]
pub struct HostStore {
    blobs: BTreeMap<ProtocolStateAddress, Zeroizing<Vec<u8>>>,
    outbox: Vec<OutboxRecord>,
    revision: u64,
}

pub struct HostRead {
    pub token: u64,
    pub snapshot: ProtocolStateSnapshot,
}

#[derive(Debug, Eq, PartialEq)]
pub enum HostCommitError {
    StaleRead { expected: u64, actual: u64 },
}

#[derive(Clone)]
pub struct OutboxRecord {
    pub message_id: MessageId,
    message: Vec<u8>,
}

pub struct StoredMessage {
    pub message_id: MessageId,
    pub plaintext: Vec<u8>,
    pub message: Message,
}

pub struct ValidatedSender {
    pub sender_identity: SenderIdentityMaterial,
    domain_identifier: Vec<u8>,
    domain_verifying_key: Vec<u8>,
}

struct Setup {
    alice_state: RatchetState,
    bob_state: RatchetState,
}

#[derive(Serialize)]
struct DeadSessionWire {
    version: u8,
    reason: SessionUnrecoverableReason,
    event_emitted: bool,
    peer_sender_identity_key: Option<[u8; 32]>,
    contact_identity_key: Option<()>,
}

impl HostStore {
    pub fn read(&self) -> HostRead {
        HostRead {
            token: self.revision,
            snapshot: self.snapshot(),
        }
    }

    pub fn snapshot(&self) -> ProtocolStateSnapshot {
        let mut snapshot = ProtocolStateSnapshot::new();
        for (address, blob) in &self.blobs {
            snapshot.set(
                address.clone(),
                ProtocolStateBlob::from_bytes(blob.as_slice().to_vec()),
            );
        }
        snapshot
    }

    pub fn commit(
        &mut self,
        token: u64,
        updates: Vec<ProtocolStateUpdate>,
    ) -> Result<(), HostCommitError> {
        self.commit_with(token, updates, None)
    }

    pub fn commit_outbound(
        &mut self,
        token: u64,
        updates: Vec<ProtocolStateUpdate>,
        message_id: MessageId,
        message: &Message,
    ) -> Result<(), HostCommitError> {
        let record = OutboxRecord {
            message_id,
            message: message.to_bytes().unwrap(),
        };
        self.commit_with(token, updates, Some(record))
    }

    pub fn outbox(&self) -> &[OutboxRecord] {
        &self.outbox
    }

    pub fn set_raw(&mut self, address: ProtocolStateAddress, blob: Vec<u8>) {
        self.blobs.insert(address, Zeroizing::new(blob));
        self.revision += 1;
    }

    pub fn blob_bytes(&self, address: &ProtocolStateAddress) -> Option<Vec<u8>> {
        self.blobs.get(address).map(|blob| blob.as_slice().to_vec())
    }

    fn commit_with(
        &mut self,
        token: u64,
        updates: Vec<ProtocolStateUpdate>,
        outbox: Option<OutboxRecord>,
    ) -> Result<(), HostCommitError> {
        if token != self.revision {
            return Err(HostCommitError::StaleRead {
                expected: self.revision,
                actual: token,
            });
        }
        self.apply_all(updates);
        if let Some(record) = outbox {
            self.outbox.push(record);
        }
        self.revision += 1;
        Ok(())
    }

    fn apply(&mut self, update: ProtocolStateUpdate) {
        let address = update.address().clone();
        match update.blob() {
            Some(blob) => {
                self.blobs
                    .insert(address, Zeroizing::new(blob.as_bytes().to_vec()));
            }
            None => {
                self.blobs.remove(&address);
            }
        }
    }

    fn apply_all<I>(&mut self, updates: I)
    where
        I: IntoIterator<Item = ProtocolStateUpdate>,
    {
        for update in updates {
            self.apply(update);
        }
    }
}

impl OutboxRecord {
    pub fn message(&self) -> Message {
        Message::from_bytes(&self.message).unwrap()
    }
}

impl ProtocolFixture {
    pub fn new(seed: [u8; 32]) -> Self {
        let engine = ProtocolStateEngine::new();
        let setup = setup(seed);
        let session_key = session_key();
        let deduplication_key = deduplication_key();
        let alice_sender = validated_sender();
        let bob_sender = sender_identity_for_contact(
            accepted_contact_identity(),
            vec![0xb2, 0xb3, 0xb4],
            vec![0xb5; 64],
        );
        let mut alice_store = HostStore::default();
        let mut bob_store = HostStore::default();

        install_session(
            &engine,
            &mut alice_store,
            session_key.clone(),
            &setup.alice_state,
            &bob_sender,
        );
        install_session(
            &engine,
            &mut bob_store,
            session_key.clone(),
            &setup.bob_state,
            &alice_sender.sender_identity,
        );
        install_deduplication_set(&engine, &mut bob_store, deduplication_key.clone(), 0x44);

        Self {
            session_key,
            deduplication_key,
            alice_store,
            bob_store,
            alice_sender,
            bob_sender,
        }
    }

    pub fn encrypt_from_alice(
        &mut self,
        engine: &ProtocolStateEngine,
        sequence: u16,
        plaintext: &[u8],
    ) -> StoredMessage {
        let read = self.alice_store.read();
        let encrypted = engine
            .encrypt_message(
                &read.snapshot,
                self.session_key.clone(),
                sequenced_outbound(sequence, plaintext, &self.alice_sender.sender_identity),
            )
            .unwrap();
        self.alice_store
            .commit_outbound(
                read.token,
                encrypted.state_updates,
                encrypted.message_id,
                &encrypted.message,
            )
            .unwrap();
        StoredMessage {
            message_id: encrypted.message_id,
            plaintext: plaintext.to_vec(),
            message: encrypted.message,
        }
    }

    pub fn decrypt_for_bob(
        &mut self,
        engine: &ProtocolStateEngine,
        message: &StoredMessage,
        rng_seed: u8,
    ) -> aether_core::InboundMessageResult {
        let read = self.bob_store.read();
        let domain_keys = [self.alice_sender.domain_signing_key()];
        let revoked = [];
        let mut decrypted = engine
            .decrypt_message(
                &mut ChaCha20Rng::from_seed([rng_seed; 32]),
                &read.snapshot,
                inbound_with_certificate_validation(
                    self.session_key.clone(),
                    self.deduplication_key.clone(),
                    &message.message,
                    &self.bob_sender,
                    &domain_keys,
                    &revoked,
                ),
            )
            .map(accepted)
            .unwrap();
        let updates = std::mem::take(&mut decrypted.state_updates);
        self.bob_store.commit(read.token, updates).unwrap();
        decrypted
    }
}

impl ValidatedSender {
    pub fn domain_signing_key(&self) -> DomainSigningKey<'_> {
        DomainSigningKey {
            identifier: &self.domain_identifier,
            verifying_key: &self.domain_verifying_key,
            status: DomainSigningKeyStatus::Trusted,
        }
    }
}

pub fn session_key() -> ProtocolStateKey {
    ProtocolStateKey::session(SessionId::from_bytes([9u8; 16]))
}

pub fn deduplication_key() -> ProtocolStateKey {
    ProtocolStateKey::from_bytes(vec![0xdd; 16]).unwrap()
}

pub fn ratchet_address(key: ProtocolStateKey) -> ProtocolStateAddress {
    ProtocolStateAddress::new(ProtocolStateKind::RatchetSession, key)
}

pub fn deduplication_address(key: ProtocolStateKey) -> ProtocolStateAddress {
    ProtocolStateAddress::new(ProtocolStateKind::DeduplicationSet, key)
}

pub fn inbound_duplicate<'a>(
    session_key: ProtocolStateKey,
    deduplication_key: ProtocolStateKey,
    message: &'a Message,
    acknowledgment_sender_identity: &'a SenderIdentityMaterial,
) -> InboundEncryptedMessage<'a> {
    InboundEncryptedMessage {
        session_key,
        deduplication_key,
        message,
        recipient_discovery_key: accepted_contact_discovery_key_ref(),
        acknowledgment: acknowledgment(0xee, acknowledgment_sender_identity),
        sender_certificate_validation: None,
    }
}

pub fn inbound_with_certificate_validation<'a>(
    session_key: ProtocolStateKey,
    deduplication_key: ProtocolStateKey,
    message: &'a Message,
    acknowledgment_sender_identity: &'a SenderIdentityMaterial,
    domain_signing_keys: &'a [DomainSigningKey<'a>],
    revoked_identity_keys: &'a [SenderCertificateIdentityKey],
) -> InboundEncryptedMessage<'a> {
    InboundEncryptedMessage {
        session_key,
        deduplication_key,
        message,
        recipient_discovery_key: accepted_contact_discovery_key_ref(),
        acknowledgment: acknowledgment(0xee, acknowledgment_sender_identity),
        sender_certificate_validation: Some(sender_certificate_validation(
            domain_signing_keys,
            RevocationState::Available(revoked_identity_keys),
        )),
    }
}

pub fn sequenced_outbound<'a>(
    sequence: u16,
    plaintext: &'a [u8],
    sender_identity: &'a SenderIdentityMaterial,
) -> OutboundPlaintext<'a> {
    let contact = accepted_contact_identity();
    let mut id = [0u8; 16];
    id[..2].copy_from_slice(&sequence.to_be_bytes());
    OutboundPlaintext {
        id: MessageId::from_bytes(id),
        sender_identity,
        sender_identity_signing_key: sender_identity_signing_key(sender_identity),
        contact_identity_key: contact.identity_key,
        recipient_public_key: contact.discovery_key.prekey_bundle_lookup_key(),
        timestamp_millis: 1_700_000_300_000 + u64::from(sequence),
        plaintext,
    }
}

pub fn accepted(outcome: InboundMessageOutcome) -> aether_core::InboundMessageResult {
    match outcome {
        InboundMessageOutcome::Accepted(result) => *result,
        InboundMessageOutcome::Blocked(_) => panic!("message was unexpectedly blocked"),
        InboundMessageOutcome::Duplicate => panic!("message was unexpectedly duplicate"),
        InboundMessageOutcome::SessionUnrecoverable(_) => {
            panic!("message was unexpectedly unrecoverable")
        }
    }
}

pub fn session_unrecoverable(outcome: InboundMessageOutcome) -> SessionUnrecoverableResult {
    match outcome {
        InboundMessageOutcome::SessionUnrecoverable(result) => *result,
        InboundMessageOutcome::Accepted(_) => panic!("message was unexpectedly accepted"),
        InboundMessageOutcome::Blocked(_) => panic!("message was unexpectedly blocked"),
        InboundMessageOutcome::Duplicate => panic!("message was unexpectedly duplicate"),
    }
}

pub fn dead_session_blob(
    event_emitted: bool,
    peer_sender_identity_key: [u8; 32],
) -> ProtocolStateBlob {
    let wire = DeadSessionWire {
        version: 3,
        reason: SessionUnrecoverableReason::SkippedKeyLimitExceeded,
        event_emitted,
        peer_sender_identity_key: Some(peer_sender_identity_key),
        contact_identity_key: None,
    };
    let mut bytes = vec![1, 0];
    bytes.extend_from_slice(&postcard::to_stdvec(&wire).unwrap());
    ProtocolStateBlob::from_bytes(bytes)
}

fn setup(seed: [u8; 32]) -> Setup {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let alice_identity = generate_signing_key_pair(&mut rng);
    let bob_identity = generate_signing_key_pair(&mut rng);
    let alice_identity_key = identity_key_bundle(&mut rng, &alice_identity);
    let bob_identity_key = identity_key_bundle(&mut rng, &bob_identity);
    let alice_discovery = generate_discovery_key(&mut rng, &alice_identity, 0, CREATED_AT);
    let bob_discovery = generate_discovery_key(&mut rng, &bob_identity, 0, CREATED_AT);
    let bob_signed_prekey =
        generate_signed_prekey_for_discovery_key(&mut rng, &bob_discovery, CREATED_AT);
    let bob_one_time_prekey =
        generate_one_time_prekey(&mut rng, 9, bob_discovery.epoch(), CREATED_AT);
    let prekey_bundle = PreKeyBundle {
        version: aether_crypto::PREKEY_BUNDLE_VERSION,
        discovery_key: bob_discovery.bundle(),
        signed_prekey: bob_signed_prekey.bundle(),
        one_time_prekey: Some(bob_one_time_prekey.bundle()),
    };
    let (alice_state, envelope) = initiate(
        &mut rng,
        &alice_discovery,
        &alice_identity_key,
        &bob_identity_key,
        &prekey_bundle,
        initial_plaintext(b"initial"),
    )
    .unwrap();
    let (bob_state, plaintext) = accept(
        &mut rng,
        &envelope,
        Some(&alice_identity_key),
        &bob_identity_key,
        &bob_discovery,
        &bob_signed_prekey,
        Some(bob_one_time_prekey),
    )
    .unwrap();
    assert_eq!(plaintext.plaintext.as_slice(), b"initial");
    Setup {
        alice_state,
        bob_state,
    }
}

fn install_session(
    engine: &ProtocolStateEngine,
    store: &mut HostStore,
    key: ProtocolStateKey,
    state: &RatchetState,
    peer_sender_identity: &SenderIdentityMaterial,
) {
    store.apply(
        engine
            .set_session_state_with_peer_identity(key.clone(), state, peer_sender_identity)
            .unwrap(),
    );
    store.apply(engine.initialize_pending_acknowledgments(key).unwrap());
    install_accepted_contact(engine, store);
}

fn install_deduplication_set(
    engine: &ProtocolStateEngine,
    store: &mut HostStore,
    key: ProtocolStateKey,
    seed: u8,
) {
    store.apply(
        engine
            .initialize_deduplication_set(&mut ChaCha20Rng::from_seed([seed; 32]), key)
            .unwrap(),
    );
}

fn install_accepted_contact(engine: &ProtocolStateEngine, store: &mut HostStore) {
    let contact = accepted_contact_identity();
    let snapshot = store.snapshot();
    let created = engine.record_contact(&snapshot, contact).unwrap();
    store.apply_all(created.state_updates);
    let snapshot = store.snapshot();
    let accepted = engine
        .accept_contact(&snapshot, contact.identity_key)
        .unwrap();
    store.apply_all(accepted.state_updates);
}

fn initial_plaintext(plaintext: &[u8]) -> InitialPlaintext<'_> {
    InitialPlaintext {
        sender_certificate: b"sender certificate",
        sender_signature: b"sender signature",
        plaintext,
    }
}

fn identity_key_bundle(rng: &mut ChaCha20Rng, signing_key: &SigningKeyPair) -> IdentityKeyBundle {
    let agreement_key = generate_key_pair(rng);
    let binding_signature = sign_identity_key_binding(signing_key, &agreement_key.public).unwrap();
    IdentityKeyBundle {
        public_key: agreement_key.public,
        verifying_key: signing_key.verifying,
        binding_signature,
    }
}

fn test_identity_key_pair(tag: u8) -> KeyPair {
    KeyPair::from_secret_bytes([tag.wrapping_add(0x33); 32])
}

fn test_sender_identity_signing_key(tag: u8) -> &'static SigningKeyPair {
    Box::leak(Box::new(SigningKeyPair::from_signing_bytes([tag; 32])))
}

fn sender_identity_signing_key(
    sender_identity: &SenderIdentityMaterial,
) -> &'static SigningKeyPair {
    for tag in 0..=u8::MAX {
        let signing_key = SigningKeyPair::from_signing_bytes([tag; 32]);
        if signing_key.verifying.to_bytes() == sender_identity.identity_verifying_key {
            return Box::leak(Box::new(signing_key));
        }
    }
    panic!("test sender identity uses an unknown signing key")
}

fn sender_identity_signing_key_for_contact(
    identity_key: ContactIdentityKey,
) -> &'static SigningKeyPair {
    for tag in 0..=u8::MAX {
        let signing_key = SigningKeyPair::from_signing_bytes([tag; 32]);
        if signing_key.verifying.to_bytes() == identity_key.ed25519_verifying_key {
            return Box::leak(Box::new(signing_key));
        }
    }
    panic!("test contact identity uses an unknown signing key")
}

fn sender_identity_for_contact(
    contact: ContactIdentity,
    certificate: Vec<u8>,
    signature: Vec<u8>,
) -> SenderIdentityMaterial {
    let signing_key = sender_identity_signing_key_for_contact(contact.identity_key);
    let public_key = PublicKey::from(contact.identity_key.x25519_public_key);
    let binding_signature = sign_identity_key_binding(signing_key, &public_key).unwrap();
    SenderIdentityMaterial {
        identity_key: contact.identity_key.x25519_public_key,
        identity_verifying_key: contact.identity_key.ed25519_verifying_key,
        identity_binding_signature: binding_signature.to_bytes().to_vec(),
        certificate,
        signature,
    }
}

fn sender_identity(tag: u8) -> SenderIdentityMaterial {
    let signing_key = test_sender_identity_signing_key(tag);
    let identity_key_pair = test_identity_key_pair(tag);
    let binding_signature =
        sign_identity_key_binding(signing_key, &identity_key_pair.public).unwrap();
    SenderIdentityMaterial {
        identity_key: *identity_key_pair.public.as_bytes(),
        identity_verifying_key: signing_key.verifying.to_bytes(),
        identity_binding_signature: binding_signature.to_bytes().to_vec(),
        certificate: vec![tag, tag.wrapping_add(1), tag.wrapping_add(2)],
        signature: vec![tag.wrapping_add(3); 64],
    }
}

fn validated_sender() -> ValidatedSender {
    let mut rng = ChaCha20Rng::from_seed([0x90; 32]);
    let domain_signing_key = generate_signing_key_pair(&mut rng);
    let contact = accepted_contact_identity();
    let domain_identifier = b"test-domain".to_vec();
    let certificate = sender_certificate_bytes(&domain_identifier, contact, CERTIFICATE_EXPIRES_AT);
    let signature = domain_signing_key.sign(&certificate).to_bytes().to_vec();
    ValidatedSender {
        sender_identity: sender_identity_for_contact(contact, certificate, signature),
        domain_identifier,
        domain_verifying_key: domain_signing_key.verifying.to_bytes().to_vec(),
    }
}

pub fn accepted_contact_identity() -> ContactIdentity {
    let identity = test_sender_identity_signing_key(0xa1);
    let identity_key_pair = test_identity_key_pair(0xa1);
    let mut rng = ChaCha20Rng::from_seed([0x71; 32]);
    let discovery_key = generate_discovery_key(&mut rng, identity, 0, CREATED_AT);
    ContactIdentity {
        identity_key: ContactIdentityKey {
            x25519_public_key: *identity_key_pair.public.as_bytes(),
            ed25519_verifying_key: identity.verifying.to_bytes(),
        },
        discovery_key: ContactDiscoveryKey::from(&discovery_key.bundle()),
    }
}

fn accepted_contact_discovery_key() -> DiscoveryKey {
    let identity = test_sender_identity_signing_key(0xa1);
    let mut rng = ChaCha20Rng::from_seed([0x71; 32]);
    generate_discovery_key(&mut rng, identity, 0, CREATED_AT)
}

fn accepted_contact_discovery_key_ref() -> &'static DiscoveryKey {
    Box::leak(Box::new(accepted_contact_discovery_key()))
}

fn acknowledgment_recipient_discovery_key() -> DiscoveryKey {
    DiscoveryKey::from_secret_bytes([0xc2; 32], [0xc3; 32], 0, CREATED_AT, [0u8; 64])
}

fn acknowledgment<'a>(
    id: u8,
    sender_identity: &'a SenderIdentityMaterial,
) -> OutboundAcknowledgment<'a> {
    let recipient = acknowledgment_recipient_discovery_key();
    OutboundAcknowledgment {
        id: MessageId::from_bytes([id; 16]),
        sender_identity,
        sender_identity_signing_key: sender_identity_signing_key(sender_identity),
        recipient_public_key: *recipient.public_key().as_bytes(),
        timestamp_millis: 1_700_000_100_000 + u64::from(id),
    }
}

pub const TEST_RELAY_DOMAIN: &[u8] = b"relay.test";

fn sender_certificate_bytes(
    signing_key_identifier: &[u8],
    contact: ContactIdentity,
    expires_at_secs: u64,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(CERTIFICATE_DOMAIN_TAG);
    bytes.push(CERTIFICATE_VERSION);
    bytes.push(signing_key_identifier.len() as u8);
    bytes.extend_from_slice(signing_key_identifier);
    bytes.push(TEST_RELAY_DOMAIN.len() as u8);
    bytes.extend_from_slice(TEST_RELAY_DOMAIN);
    bytes.extend_from_slice(&contact.identity_key.x25519_public_key);
    bytes.extend_from_slice(&contact.identity_key.ed25519_verifying_key);
    bytes.extend_from_slice(&expires_at_secs.to_be_bytes());
    bytes
}

fn sender_certificate_validation<'a>(
    domain_signing_keys: &'a [DomainSigningKey<'a>],
    revocation_state: RevocationState<'a>,
) -> InboundSenderCertificateValidation<'a> {
    InboundSenderCertificateValidation {
        domain_signing_keys,
        expected_relay_domain: TEST_RELAY_DOMAIN,
        revocation_state,
        reference_timestamp_secs: CERTIFICATE_REFERENCE_TIME,
        grace_window_secs: 0,
    }
}
