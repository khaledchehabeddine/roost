#![allow(dead_code, unreachable_pub)]

use roost_protocol::from_unix_secs;
use std::collections::BTreeMap;
use std::time::Duration;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use roost_core::{
    ContactDiscoveryKey, ContactIdentity, ContactIdentityKey, InboundEncryptedMessage,
    InboundMessageOutcome, InboundSenderCertificateValidation, Message, OutboundAcknowledgment,
    OutboundPlaintext, ProtocolStateAddress, ProtocolStateBlob, ProtocolStateEngine,
    ProtocolStateError, ProtocolStateKey, ProtocolStateKind, ProtocolStateSnapshot,
    ProtocolStateUpdate, SenderIdentityMaterial, SessionId, SessionUnrecoverableResult,
    TransportBinding,
};
use roost_crypto::{
    DiscoveryKey, InitialPlaintext, KeyPair, PreKeyBundle, PublicIdentityKey, RatchetState,
    SigningKeyPair, accept, generate_discovery_key, generate_key_pair, generate_one_time_prekey,
    generate_signed_prekey_for_discovery_key, generate_signing_key_pair, initiate,
    sign_identity_key_binding,
};
use roost_protocol::{
    DomainSigningKey, DomainSigningKeyStatus, MessageId, RevocationState,
    SenderCertificateIdentityKey,
};
use zeroize::Zeroizing;

pub const CREATED_AT_SECS: u64 = 1_700_000_000;
pub const TEST_RELAY_DOMAIN: &[u8] = b"relay.test";
const CERTIFICATE_DOMAIN_TAG: &[u8] = b"AetherSenderCertificate-v2:";
const CERTIFICATE_VERSION: u8 = 2;

pub struct ProtocolFixture {
    pub session_key: ProtocolStateKey,
    pub deduplication_key: ProtocolStateKey,
    pub alice_store: HostStore,
    pub bob_store: HostStore,
    pub alice_sender: ValidatedSender,
    pub bob_sender: SenderIdentityMaterial,
    pub binding: TransportBinding,
    bob_signing_key: SigningKeyPair,
    bob_discovery_key: DiscoveryKey,
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

    pub fn outbox(&self) -> &[OutboxRecord] {
        &self.outbox
    }

    pub fn set_raw(&mut self, address: ProtocolStateAddress, blob: Vec<u8>) {
        self.blobs.insert(address, Zeroizing::new(blob));
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

    fn apply_all(&mut self, updates: impl IntoIterator<Item = ProtocolStateUpdate>) {
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
    signing_key: SigningKeyPair,
    domain_id: Vec<u8>,
    domain_verifying_key: Vec<u8>,
}

impl ValidatedSender {
    pub fn domain_signing_key(&self) -> DomainSigningKey<'_> {
        DomainSigningKey {
            id: &self.domain_id,
            verifying_key: &self.domain_verifying_key,
            status: DomainSigningKeyStatus::Trusted,
        }
    }
}

pub struct Setup {
    pub alice_state: RatchetState,
    pub bob_state: RatchetState,
}

impl ProtocolFixture {
    pub fn new(seed: [u8; 32]) -> Self {
        let engine = ProtocolStateEngine::new();
        let states = setup(seed);
        let alice_sender = validated_sender();
        let bob_signing_key = SigningKeyPair::from_signing_bytes([0xa1; 32]);
        let bob_discovery_key = discovery_key(&bob_signing_key, 0x71);
        let bob_sender = sender_identity(
            0xa1,
            &bob_signing_key,
            vec![0xb2, 0xb3, 0xb4],
            vec![0xb5; 64],
        );
        let mut fixture = Self {
            session_key: ProtocolStateKey::session(SessionId::from_bytes([9; 16])),
            deduplication_key: ProtocolStateKey::from_bytes(vec![0xdd; 16]).unwrap(),
            alice_store: HostStore::default(),
            bob_store: HostStore::default(),
            alice_sender,
            bob_sender,
            binding: TransportBinding::new(b"test-route".to_vec()).unwrap(),
            bob_signing_key,
            bob_discovery_key,
        };
        for (store, state, peer) in [
            (
                &mut fixture.alice_store,
                &states.alice_state,
                &fixture.bob_sender,
            ),
            (
                &mut fixture.bob_store,
                &states.bob_state,
                &fixture.alice_sender.sender_identity,
            ),
        ] {
            store.apply_all([
                engine
                    .set_session_state_with_peer_identity(fixture.session_key.clone(), state, peer)
                    .unwrap(),
                engine
                    .initialize_pending_acknowledgments(fixture.session_key.clone())
                    .unwrap(),
            ]);
            let contact = accepted_contact_identity();
            let recorded = engine.record_contact(&store.snapshot(), contact).unwrap();
            store.apply_all(recorded.state_updates);
            let accepted = engine
                .accept_contact(&store.snapshot(), contact.identity_key)
                .unwrap();
            store.apply_all(accepted.state_updates);
        }
        fixture.bob_store.apply_all([engine
            .initialize_deduplication_set(
                &mut ChaCha20Rng::from_seed([0x44; 32]),
                fixture.deduplication_key.clone(),
            )
            .unwrap()]);
        fixture
    }

    pub fn outbound<'a>(&'a self, sequence: u16, plaintext: &'a [u8]) -> OutboundPlaintext<'a> {
        let contact = accepted_contact_identity();
        let mut id = [0; 16];
        id[..2].copy_from_slice(&sequence.to_be_bytes());
        id[6] = 0x40;
        id[8] = 0x80;
        OutboundPlaintext {
            id: MessageId::from_bytes(id),
            sender_identity: &self.alice_sender.sender_identity,
            sender_identity_signing_key: &self.alice_sender.signing_key,
            contact_identity_key: contact.identity_key,
            recipient_public_key: contact.discovery_key.prekey_bundle_lookup_key(),
            sent_at_millis: 1_700_000_300_000 + u64::from(sequence),
            plaintext,
        }
    }

    pub fn inbound<'a>(
        &'a self,
        message: &'a Message,
        domain_signing_keys: &'a [DomainSigningKey<'a>],
        revoked_identity_keys: &'a [SenderCertificateIdentityKey],
    ) -> InboundEncryptedMessage<'a> {
        InboundEncryptedMessage {
            session_key: self.session_key.clone(),
            deduplication_key: self.deduplication_key.clone(),
            message,
            recipient_discovery_key: &self.bob_discovery_key,
            recipient_identity_verifying_key: self.bob_sender.identity_verifying_key,
            acknowledgment: OutboundAcknowledgment {
                id: MessageId::from_bytes([0xee; 16]),
                sender_identity: &self.bob_sender,
                sender_identity_signing_key: &self.bob_signing_key,
                recipient_public_key: *acknowledgment_recipient_discovery_key()
                    .public_key()
                    .as_bytes(),
                sent_at_millis: 1_700_000_100_000 + 0xee,
            },
            sender_certificate_validation: Some(InboundSenderCertificateValidation {
                domain_signing_keys,
                expected_relay_domain: TEST_RELAY_DOMAIN,
                revocation_state: RevocationState::Available(revoked_identity_keys),
                reference_time: from_unix_secs(CREATED_AT_SECS).unwrap(),
                grace_window: Duration::ZERO,
            }),
        }
    }

    pub fn receive(
        &self,
        engine: &ProtocolStateEngine,
        snapshot: &ProtocolStateSnapshot,
        message: &Message,
        rng_seed: u8,
    ) -> Result<InboundMessageOutcome, ProtocolStateError> {
        let domain_keys = [self.alice_sender.domain_signing_key()];
        engine.decrypt_message_with_transport_bindings(
            &mut ChaCha20Rng::from_seed([rng_seed; 32]),
            snapshot,
            self.inbound(message, &domain_keys, &[]),
            &self.binding,
            &self.binding,
        )
    }

    pub fn encrypt_from_alice(
        &mut self,
        engine: &ProtocolStateEngine,
        sequence: u16,
        plaintext: &[u8],
    ) -> StoredMessage {
        let encrypted = engine
            .encrypt_message_with_transport_binding(
                &self.alice_store.snapshot(),
                self.session_key.clone(),
                self.outbound(sequence, plaintext),
                &self.binding,
            )
            .unwrap();
        self.alice_store
            .commit_outbound(
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
    ) -> roost_core::InboundMessageResult {
        let mut decrypted = accepted(
            self.receive(
                engine,
                &self.bob_store.snapshot(),
                &message.message,
                rng_seed,
            )
            .unwrap(),
        );
        self.bob_store
            .commit(std::mem::take(&mut decrypted.state_updates))
            .unwrap();
        decrypted
    }
}

pub fn ratchet_address(key: ProtocolStateKey) -> ProtocolStateAddress {
    ProtocolStateAddress::new(ProtocolStateKind::RatchetSession, key)
}

pub fn deduplication_address(key: ProtocolStateKey) -> ProtocolStateAddress {
    ProtocolStateAddress::new(ProtocolStateKind::DeduplicationSet, key)
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
    peer_sender_identity_key: [u8; 32],
) -> ProtocolStateBlob {
    // Envelope 1.0, session body 4, Unrecoverable variant 2, reason 0,
    // recovery flag, absent contact binding, present peer identity.
    let mut bytes = vec![1, 0, 4, 2, 0, u8::from(event_emitted), 0, 1];
    bytes.extend_from_slice(&peer_sender_identity_key);
    ProtocolStateBlob::from_bytes(bytes)
}

pub fn setup(seed: [u8; 32]) -> Setup {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let alice_identity = generate_signing_key_pair(&mut rng);
    let bob_identity = generate_signing_key_pair(&mut rng);
    let alice_identity_key = public_identity_key(&mut rng, &alice_identity);
    let bob_identity_key = public_identity_key(&mut rng, &bob_identity);
    let alice_discovery = generate_discovery_key(&mut rng, &alice_identity, 0, CREATED_AT_SECS);
    let bob_discovery = generate_discovery_key(&mut rng, &bob_identity, 0, CREATED_AT_SECS);
    let bob_signed_prekey =
        generate_signed_prekey_for_discovery_key(&mut rng, &bob_discovery, 0, CREATED_AT_SECS);
    let bob_one_time_prekey =
        generate_one_time_prekey(&mut rng, 9, bob_discovery.epoch(), CREATED_AT_SECS);
    let prekey_bundle = PreKeyBundle {
        version: roost_crypto::PREKEY_BUNDLE_VERSION,
        discovery_key: bob_discovery.public(),
        signed_prekey: bob_signed_prekey.public(),
        one_time_prekey: Some(bob_one_time_prekey.public()),
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

fn initial_plaintext(plaintext: &[u8]) -> InitialPlaintext<'_> {
    InitialPlaintext {
        sender_certificate: b"sender certificate",
        sender_signature: b"sender signature",
        plaintext,
    }
}

fn public_identity_key(rng: &mut ChaCha20Rng, signing_key: &SigningKeyPair) -> PublicIdentityKey {
    let agreement_key = generate_key_pair(rng);
    let binding_signature = sign_identity_key_binding(signing_key, &agreement_key.public).unwrap();
    PublicIdentityKey {
        public_key: agreement_key.public,
        verifying_key: signing_key.verifying,
        binding_signature,
    }
}

fn discovery_key(signing_key: &SigningKeyPair, seed: u8) -> DiscoveryKey {
    generate_discovery_key(
        &mut ChaCha20Rng::from_seed([seed; 32]),
        signing_key,
        0,
        CREATED_AT_SECS,
    )
}

fn contact_identity(tag: u8, signing_key: &SigningKeyPair, discovery_seed: u8) -> ContactIdentity {
    ContactIdentity {
        identity_key: ContactIdentityKey {
            x25519_public_key: *KeyPair::from_secret_bytes([tag.wrapping_add(0x33); 32])
                .public
                .as_bytes(),
            ed25519_verifying_key: signing_key.verifying.to_bytes(),
        },
        discovery_key: ContactDiscoveryKey::from(
            &discovery_key(signing_key, discovery_seed).public(),
        ),
    }
}

pub fn accepted_contact_identity() -> ContactIdentity {
    contact_identity(0xa1, &SigningKeyPair::from_signing_bytes([0xa1; 32]), 0x71)
}

pub fn acknowledgment_recipient_discovery_key() -> DiscoveryKey {
    discovery_key(&SigningKeyPair::from_signing_bytes([0xa2; 32]), 0xc2)
}

fn sender_identity(
    tag: u8,
    signing_key: &SigningKeyPair,
    certificate: Vec<u8>,
    signature: Vec<u8>,
) -> SenderIdentityMaterial {
    let pair = KeyPair::from_secret_bytes([tag.wrapping_add(0x33); 32]);
    SenderIdentityMaterial {
        identity_key: *pair.public.as_bytes(),
        identity_verifying_key: signing_key.verifying.to_bytes(),
        identity_binding_signature: sign_identity_key_binding(signing_key, &pair.public)
            .unwrap()
            .to_bytes()
            .to_vec(),
        certificate,
        signature,
    }
}

fn validated_sender() -> ValidatedSender {
    let signing_key = SigningKeyPair::from_signing_bytes([0xa2; 32]);
    let domain_signing_key = generate_signing_key_pair(&mut ChaCha20Rng::from_seed([0x90; 32]));
    let domain_id = b"test-domain".to_vec();
    let certificate = sender_certificate_bytes(
        &domain_id,
        contact_identity(0xa2, &signing_key, 0x72),
        1_700_100_000,
    );
    let signature = domain_signing_key.sign(&certificate).to_bytes().to_vec();
    ValidatedSender {
        sender_identity: sender_identity(0xa2, &signing_key, certificate, signature),
        signing_key,
        domain_id,
        domain_verifying_key: domain_signing_key.verifying.to_bytes().to_vec(),
    }
}

fn sender_certificate_bytes(
    signing_key_id: &[u8],
    contact: ContactIdentity,
    expires_at_secs: u64,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(CERTIFICATE_DOMAIN_TAG);
    bytes.push(CERTIFICATE_VERSION);
    bytes.push(signing_key_id.len() as u8);
    bytes.extend_from_slice(signing_key_id);
    bytes.push(TEST_RELAY_DOMAIN.len() as u8);
    bytes.extend_from_slice(TEST_RELAY_DOMAIN);
    bytes.extend_from_slice(&contact.identity_key.x25519_public_key);
    bytes.extend_from_slice(&contact.identity_key.ed25519_verifying_key);
    bytes.extend_from_slice(&expires_at_secs.to_be_bytes());
    bytes
}
