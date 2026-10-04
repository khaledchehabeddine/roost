//! Exercises the public protocol-state API over consumer-held opaque blobs.

mod support;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use roost_core::{
    AcknowledgmentOutcome, BlockedContactAcknowledgmentPolicy, ContactDiscoveryKey,
    ContactIdentity, ContactIdentityKey, ContactTrustState, InboundAcknowledgmentMessage,
    InboundEncryptedMessage, InboundMessageOutcome, InboundSenderCertificateValidation,
    MAX_DEDUPLICATION_CAPACITY, MIN_DEDUPLICATION_CAPACITY, Message, MessageError,
    OutboundAcknowledgment, OutboundPlaintext, ProtocolHardeningLimits, ProtocolStateAddress,
    ProtocolStateBlob, ProtocolStateEngine, ProtocolStateError, ProtocolStateKey,
    ProtocolStateKind, ProtocolStateSnapshot, SenderIdentityMaterial, SessionEvent, SessionId,
    SessionUnrecoverableReason, SessionUnrecoverableResult,
};
use roost_crypto::{
    DiscoveryKey, Header, KeyPair, PublicKey, RatchetError, RatchetState, SealedFrameError,
    SealedFramePreKeyReference, SigningKeyPair, generate_discovery_key, generate_signing_key_pair,
    seal_frame_with_associated_data, sign_identity_key_binding,
};
use roost_protocol::{
    DomainSigningKey, DomainSigningKeyStatus, MAX_CERTIFICATE_GRACE_WINDOW, MessageId, PayloadKind,
    RevocationState, SenderCertificateIdentityKey, SenderCertificateValidationError,
    from_unix_millis, from_unix_secs,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use support::dead_session_blob;

const CREATED_AT_SECS: u64 = 1_700_000_000;
const CERTIFICATE_DOMAIN_TAG: &[u8] = b"AetherSenderCertificate-v2:";
const TEST_RELAY_DOMAIN: &[u8] = b"relay.test";
const CERTIFICATE_VERSION: u8 = 2;
const CERTIFICATE_EXPIRES_AT: u64 = 1_700_100_000;
const CERTIFICATE_REFERENCE_TIME_SECS: u64 = 1_700_000_000;

#[derive(Deserialize, Serialize)]
struct TestPendingAcknowledgmentsWire {
    version: u8,
    pending: Vec<TestPendingAcknowledgmentWire>,
    acknowledgment_digests: Vec<[u8; 16]>,
}

#[derive(Deserialize, Serialize)]
struct TestPendingAcknowledgmentWire {
    message_id: [u8; 16],
    encoded_message: Vec<u8>,
    first_sent_at_millis: u64,
    last_retried_at_millis: Option<u64>,
}

fn setup() -> support::Setup {
    support::setup([7; 32])
}

fn test_identity_key_pair(tag: u8) -> KeyPair {
    KeyPair::from_secret_bytes([tag.wrapping_add(0x33); 32])
}

fn test_sender_identity_signing_key(tag: u8) -> SigningKeyPair {
    SigningKeyPair::from_signing_bytes([tag; 32])
}

struct Sender {
    material: SenderIdentityMaterial,
    signing_key: SigningKeyPair,
}

impl std::ops::Deref for Sender {
    type Target = SenderIdentityMaterial;

    fn deref(&self) -> &Self::Target {
        &self.material
    }
}

fn sender_identity_signing_key(sender: &Sender) -> &SigningKeyPair {
    &sender.signing_key
}

fn sender_identity_for_contact(
    contact: ContactIdentity,
    certificate: Vec<u8>,
    signature: Vec<u8>,
) -> Sender {
    let signing_key = sender_identity_signing_key_for_contact(contact.identity_key);
    let public_key = PublicKey::from(contact.identity_key.x25519_public_key);
    let binding_signature = sign_identity_key_binding(&signing_key, &public_key).unwrap();
    Sender {
        material: SenderIdentityMaterial {
            identity_key: contact.identity_key.x25519_public_key,
            identity_verifying_key: contact.identity_key.ed25519_verifying_key,
            identity_binding_signature: binding_signature.to_bytes().to_vec(),
            certificate,
            signature,
        },
        signing_key,
    }
}

fn sender_identity_signing_key_for_contact(identity: ContactIdentityKey) -> SigningKeyPair {
    [0xa1, 0x77, 0xc1]
        .into_iter()
        .map(test_sender_identity_signing_key)
        .find(|key| key.verifying.to_bytes() == identity.ed25519_verifying_key)
        .expect("known test contact")
}

fn key() -> ProtocolStateKey {
    ProtocolStateKey::session(SessionId::from_bytes([9u8; 16]))
}

fn deduplication_key() -> ProtocolStateKey {
    ProtocolStateKey::from_bytes(vec![0xdd; 16]).unwrap()
}

fn ratchet_address(key: ProtocolStateKey) -> ProtocolStateAddress {
    ProtocolStateAddress::new(ProtocolStateKind::RatchetSession, key)
}

fn deduplication_address(key: ProtocolStateKey) -> ProtocolStateAddress {
    ProtocolStateAddress::new(ProtocolStateKind::DeduplicationSet, key)
}

fn pending_acknowledgment_address(key: ProtocolStateKey) -> ProtocolStateAddress {
    ProtocolStateAddress::new(ProtocolStateKind::PendingAcknowledgments, key)
}

fn contact_identities() -> (ContactIdentity, ContactIdentity) {
    let identity = test_sender_identity_signing_key(0xa1);
    let identity_key_pair = test_identity_key_pair(0xa1);
    let mut rng = ChaCha20Rng::from_seed([0x71; 32]);
    let discovery_key = generate_discovery_key(&mut rng, &identity, 0, CREATED_AT_SECS);
    let rotated_discovery_key =
        generate_discovery_key(&mut rng, &identity, 1, CREATED_AT_SECS + 60);
    let identity_key = ContactIdentityKey {
        x25519_public_key: *identity_key_pair.public.as_bytes(),
        ed25519_verifying_key: identity.verifying.to_bytes(),
    };
    (
        ContactIdentity {
            identity_key,
            discovery_key: ContactDiscoveryKey::from(&discovery_key.public()),
        },
        ContactIdentity {
            identity_key,
            discovery_key: ContactDiscoveryKey::from(&rotated_discovery_key.public()),
        },
    )
}

fn accepted_contact_identity() -> ContactIdentity {
    contact_identities().0
}

fn accepted_contact_discovery_key() -> DiscoveryKey {
    let identity = test_sender_identity_signing_key(0xa1);
    let mut rng = ChaCha20Rng::from_seed([0x71; 32]);
    generate_discovery_key(&mut rng, &identity, 0, CREATED_AT_SECS)
}

fn accepted_contact_discovery_key_ref() -> &'static DiscoveryKey {
    Box::leak(Box::new(accepted_contact_discovery_key()))
}

fn rotated_contact_identity() -> ContactIdentity {
    contact_identities().1
}

fn acknowledgment_recipient_discovery_key() -> DiscoveryKey {
    let mut rng = ChaCha20Rng::from_seed([0xc2; 32]);
    generate_discovery_key(
        &mut rng,
        &test_sender_identity_signing_key(0xa1),
        0,
        CREATED_AT_SECS,
    )
}

fn acknowledgment_recipient_discovery_key_ref() -> &'static DiscoveryKey {
    Box::leak(Box::new(acknowledgment_recipient_discovery_key()))
}

struct ValidatedSender {
    contact: ContactIdentity,
    sender_identity: Sender,
    domain_id: Vec<u8>,
    domain_verifying_key: Vec<u8>,
}

impl ValidatedSender {
    fn domain_signing_key(&self) -> DomainSigningKey<'_> {
        self.domain_signing_key_with_status(DomainSigningKeyStatus::Trusted)
    }

    fn domain_signing_key_with_status(
        &self,
        status: DomainSigningKeyStatus,
    ) -> DomainSigningKey<'_> {
        DomainSigningKey {
            id: &self.domain_id,
            verifying_key: &self.domain_verifying_key,
            status,
        }
    }

    fn revoked_identity_key(&self) -> SenderCertificateIdentityKey {
        SenderCertificateIdentityKey {
            x25519_public_key: self.contact.identity_key.x25519_public_key,
            ed25519_verifying_key: self.contact.identity_key.ed25519_verifying_key,
        }
    }
}

fn validated_sender() -> ValidatedSender {
    validated_sender_for_contact(accepted_contact_identity())
}

fn validated_sender_for_contact(contact: ContactIdentity) -> ValidatedSender {
    validated_sender_for_contact_expires_at(contact, CERTIFICATE_EXPIRES_AT)
}

fn validated_sender_for_contact_expires_at(
    contact: ContactIdentity,
    expires_at_secs: u64,
) -> ValidatedSender {
    let mut rng = ChaCha20Rng::from_seed([0x90; 32]);
    let domain_signing_key = generate_signing_key_pair(&mut rng);
    let domain_id = b"test-domain".to_vec();
    let certificate = sender_certificate_bytes(&domain_id, contact, expires_at_secs);
    let signature = domain_signing_key.sign(&certificate).to_bytes().to_vec();
    ValidatedSender {
        contact,
        sender_identity: sender_identity_for_contact(
            contact,
            certificate.clone(),
            signature.clone(),
        ),
        domain_id,
        domain_verifying_key: domain_signing_key.verifying.to_bytes().to_vec(),
    }
}

fn alternate_contact_identity() -> ContactIdentity {
    let identity = test_sender_identity_signing_key(0x77);
    let identity_key_pair = test_identity_key_pair(0x77);
    let mut rng = ChaCha20Rng::from_seed([0x73; 32]);
    let discovery_key = generate_discovery_key(&mut rng, &identity, 0, CREATED_AT_SECS);
    ContactIdentity {
        identity_key: ContactIdentityKey {
            x25519_public_key: *identity_key_pair.public.as_bytes(),
            ed25519_verifying_key: identity.verifying.to_bytes(),
        },
        discovery_key: ContactDiscoveryKey::from(&discovery_key.public()),
    }
}

fn contact_with_unrelated_identity_key_and_sender_discovery() -> ContactIdentity {
    let identity = test_sender_identity_signing_key(0xc1);
    let identity_key_pair = test_identity_key_pair(0xc1);
    let contact = accepted_contact_identity();
    ContactIdentity {
        identity_key: ContactIdentityKey {
            x25519_public_key: *identity_key_pair.public.as_bytes(),
            ed25519_verifying_key: identity.verifying.to_bytes(),
        },
        discovery_key: contact.discovery_key,
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

fn sender_certificate_validation<'a>(
    domain_signing_keys: &'a [DomainSigningKey<'a>],
    revocation_state: RevocationState<'a>,
) -> InboundSenderCertificateValidation<'a> {
    InboundSenderCertificateValidation {
        expected_relay_domain: TEST_RELAY_DOMAIN,
        domain_signing_keys,
        revocation_state,
        reference_time: from_unix_secs(CERTIFICATE_REFERENCE_TIME_SECS).unwrap(),
    }
}

fn inbound_with_certificate_validation<'a>(
    session_key: ProtocolStateKey,
    deduplication_key: ProtocolStateKey,
    message: &'a Message,
    acknowledgment_sender_identity: &'a Sender,
    domain_signing_keys: &'a [DomainSigningKey<'a>],
    revoked_identity_keys: &'a [SenderCertificateIdentityKey],
) -> InboundEncryptedMessage<'a> {
    InboundEncryptedMessage {
        session_key,
        deduplication_key,
        message,
        recipient_discovery_key: accepted_contact_discovery_key_ref(),
        recipient_identity_verifying_key: accepted_contact_identity()
            .identity_key
            .ed25519_verifying_key,
        acknowledgment: acknowledgment(0xee, acknowledgment_sender_identity),
        sender_certificate_validation: Some(sender_certificate_validation(
            domain_signing_keys,
            RevocationState::Available(revoked_identity_keys),
        )),
    }
}

fn block_contact(engine: &ProtocolStateEngine, snapshot: &mut ProtocolStateSnapshot) {
    let contact = accepted_contact_identity();
    let blocked = engine
        .block_contact(snapshot, contact.identity_key)
        .unwrap();
    snapshot.apply_all(blocked.state_updates).unwrap();
}

fn rotate_blocked_contact(engine: &ProtocolStateEngine, snapshot: &mut ProtocolStateSnapshot) {
    let rotated = engine
        .record_contact(snapshot, rotated_contact_identity())
        .unwrap();
    snapshot.apply_all(rotated.state_updates).unwrap();
}

fn install_accepted_contact(engine: &ProtocolStateEngine, snapshot: &mut ProtocolStateSnapshot) {
    let contact = accepted_contact_identity();
    install_accepted_contact_identity(engine, snapshot, contact);
}

fn install_accepted_contact_identity(
    engine: &ProtocolStateEngine,
    snapshot: &mut ProtocolStateSnapshot,
    contact: ContactIdentity,
) {
    let created = engine.record_contact(snapshot, contact).unwrap();
    snapshot.apply_all(created.state_updates).unwrap();
    let accepted = engine
        .accept_contact(snapshot, contact.identity_key)
        .unwrap();
    snapshot.apply_all(accepted.state_updates).unwrap();
}

fn snapshot_with_state(
    engine: &ProtocolStateEngine,
    key: ProtocolStateKey,
    state: &RatchetState,
) -> ProtocolStateSnapshot {
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot
        .apply(engine.set_session_state(key.clone(), state).unwrap())
        .unwrap();
    install_pending_acknowledgments(engine, &mut snapshot, key);
    install_accepted_contact(engine, &mut snapshot);
    snapshot
}

fn install_deduplication_set(
    engine: &ProtocolStateEngine,
    snapshot: &mut ProtocolStateSnapshot,
    key: ProtocolStateKey,
    seed: u8,
) {
    snapshot
        .apply(
            engine
                .initialize_deduplication_set(&mut ChaCha20Rng::from_seed([seed; 32]), key)
                .unwrap(),
        )
        .unwrap();
}

fn install_pending_acknowledgments(
    engine: &ProtocolStateEngine,
    snapshot: &mut ProtocolStateSnapshot,
    key: ProtocolStateKey,
) {
    snapshot
        .apply(engine.initialize_pending_acknowledgments(key).unwrap())
        .unwrap();
}

fn snapshot_with_state_and_peer_identity(
    engine: &ProtocolStateEngine,
    key: ProtocolStateKey,
    state: &RatchetState,
    peer_sender_identity: &SenderIdentityMaterial,
) -> ProtocolStateSnapshot {
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot
        .apply(
            engine
                .set_session_state_with_peer_identity(key.clone(), state, peer_sender_identity)
                .unwrap(),
        )
        .unwrap();
    install_pending_acknowledgments(engine, &mut snapshot, key);
    install_accepted_contact(engine, &mut snapshot);
    snapshot
}

fn snapshot_with_state_peer_identity_and_deduplication(
    engine: &ProtocolStateEngine,
    key: ProtocolStateKey,
    state: &RatchetState,
    peer_sender_identity: &SenderIdentityMaterial,
    deduplication_key: ProtocolStateKey,
) -> ProtocolStateSnapshot {
    let mut snapshot =
        snapshot_with_state_and_peer_identity(engine, key, state, peer_sender_identity);
    install_deduplication_set(engine, &mut snapshot, deduplication_key, 0x44);
    snapshot
}

fn outbound<'a>(id: u8, plaintext: &'a [u8], sender_identity: &'a Sender) -> OutboundPlaintext<'a> {
    let contact = accepted_contact_identity();
    OutboundPlaintext {
        id: MessageId::from_bytes([id; 16]),
        sender_identity,
        sender_identity_signing_key: sender_identity_signing_key(sender_identity),
        contact_identity_key: contact.identity_key,
        recipient_public_key: contact.discovery_key.prekey_bundle_lookup_key(),
        sent_at_millis: 1_700_000_000_123 + u64::from(id),
        plaintext,
    }
}

fn sequenced_outbound<'a>(
    sequence: u16,
    plaintext: &'a [u8],
    sender_identity: &'a Sender,
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
        sent_at_millis: 1_700_000_300_000 + u64::from(sequence),
        plaintext,
    }
}

fn sender_identity(tag: u8) -> Sender {
    let signing_key = test_sender_identity_signing_key(tag);
    let identity_key_pair = test_identity_key_pair(tag);
    let binding_signature =
        sign_identity_key_binding(&signing_key, &identity_key_pair.public).unwrap();
    Sender {
        material: SenderIdentityMaterial {
            identity_key: *identity_key_pair.public.as_bytes(),
            identity_verifying_key: signing_key.verifying.to_bytes(),
            identity_binding_signature: binding_signature.to_bytes().to_vec(),
            certificate: vec![tag, tag.wrapping_add(1), tag.wrapping_add(2)],
            signature: vec![tag.wrapping_add(3); 64],
        },
        signing_key,
    }
}

fn acknowledgment_sender_identity() -> Sender {
    sender_identity_for_contact(
        accepted_contact_identity(),
        vec![0xb2, 0xb3, 0xb4],
        vec![0xb5; 64],
    )
}

fn acknowledgment<'a>(id: u8, sender_identity: &'a Sender) -> OutboundAcknowledgment<'a> {
    let recipient = acknowledgment_recipient_discovery_key();
    OutboundAcknowledgment {
        id: MessageId::from_bytes([id; 16]),
        sender_identity,
        sender_identity_signing_key: sender_identity_signing_key(sender_identity),
        recipient_public_key: *recipient.public_key().as_bytes(),
        sent_at_millis: 1_700_000_100_000 + u64::from(id),
    }
}

fn inbound<'a>(
    session_key: ProtocolStateKey,
    deduplication_key: ProtocolStateKey,
    message: &'a Message,
    acknowledgment_sender_identity: &'a Sender,
) -> InboundEncryptedMessage<'a> {
    InboundEncryptedMessage {
        session_key,
        deduplication_key,
        message,
        recipient_discovery_key: accepted_contact_discovery_key_ref(),
        recipient_identity_verifying_key: accepted_contact_identity()
            .identity_key
            .ed25519_verifying_key,
        acknowledgment: acknowledgment(0xee, acknowledgment_sender_identity),
        sender_certificate_validation: None,
    }
}

fn inbound_acknowledgment<'a>(
    session_key: ProtocolStateKey,
    message: &'a Message,
) -> InboundAcknowledgmentMessage<'a> {
    InboundAcknowledgmentMessage {
        session_key,
        message,
        recipient_discovery_key: acknowledgment_recipient_discovery_key_ref(),
        recipient_identity_verifying_key: accepted_contact_identity()
            .identity_key
            .ed25519_verifying_key,
    }
}

fn acknowledgment_processing_setup(
    id: u8,
) -> (
    ProtocolStateEngine,
    ProtocolStateKey,
    ProtocolStateSnapshot,
    Message,
) {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let sender = validated_sender_for_contact(accepted_contact_identity());
    let domain_keys = [sender.domain_signing_key()];
    let revoked = [];
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let mut alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender.sender_identity,
        deduplication_key.clone(),
    );
    let encrypted = engine
        .encrypt_message_with_transport_binding(
            &alice_snapshot,
            key.clone(),
            outbound(
                id,
                b"acknowledgment recipient validation",
                &sender.sender_identity,
            ),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap();
    alice_snapshot.apply_all(encrypted.state_updates).unwrap();
    let decrypted = engine
        .decrypt_message_with_transport_bindings(
            &mut ChaCha20Rng::from_seed([id; 32]),
            &bob_snapshot,
            inbound_with_certificate_validation(
                key.clone(),
                deduplication_key,
                &encrypted.message,
                &acknowledgment_sender_identity,
                &domain_keys,
                &revoked,
            ),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .map(accepted)
        .unwrap();
    let bound = engine
        .bind_session_state_peer_identity_key(
            &alice_snapshot,
            key.clone(),
            acknowledgment_sender_identity.identity_key,
        )
        .unwrap();
    alice_snapshot.apply(bound).unwrap();
    (engine, key, alice_snapshot, decrypted.acknowledgment)
}

fn accepted(outcome: InboundMessageOutcome) -> roost_core::InboundMessageResult {
    match outcome {
        InboundMessageOutcome::Accepted(result) => *result,
        InboundMessageOutcome::Blocked(_) => panic!("message was unexpectedly blocked"),
        InboundMessageOutcome::Duplicate => panic!("message was unexpectedly duplicate"),
        InboundMessageOutcome::SessionUnrecoverable(_) => {
            panic!("message was unexpectedly unrecoverable")
        }
    }
}

fn blocked(outcome: InboundMessageOutcome) -> roost_core::BlockedInboundMessageResult {
    match outcome {
        InboundMessageOutcome::Blocked(result) => *result,
        InboundMessageOutcome::Accepted(_) => panic!("message was unexpectedly accepted"),
        InboundMessageOutcome::Duplicate => panic!("message was unexpectedly duplicate"),
        InboundMessageOutcome::SessionUnrecoverable(_) => {
            panic!("message was unexpectedly unrecoverable")
        }
    }
}

fn session_unrecoverable(outcome: InboundMessageOutcome) -> SessionUnrecoverableResult {
    match outcome {
        InboundMessageOutcome::SessionUnrecoverable(result) => *result,
        InboundMessageOutcome::Accepted(_) => panic!("message was unexpectedly accepted"),
        InboundMessageOutcome::Blocked(_) => panic!("message was unexpectedly blocked"),
        InboundMessageOutcome::Duplicate => panic!("message was unexpectedly duplicate"),
    }
}

fn ratcheted_payload(header: &Header, ciphertext: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.push(1);
    payload.extend_from_slice(header.public_key.as_bytes());
    payload.extend_from_slice(&header.previous_chain_length.to_be_bytes());
    payload.extend_from_slice(&header.message_number.to_be_bytes());
    payload.extend_from_slice(ciphertext);
    payload
}

fn ratchet_associated_data(
    session_key: &ProtocolStateKey,
    recipient_public_key: &[u8; 32],
) -> Vec<u8> {
    let mut associated_data = Vec::new();
    associated_data.extend_from_slice(b"AetherRatchetedPayload-v1:");
    associated_data.extend_from_slice(&(session_key.as_bytes().len() as u32).to_be_bytes());
    associated_data.extend_from_slice(session_key.as_bytes());
    associated_data.extend_from_slice(recipient_public_key);
    associated_data
}

fn message_frame_plaintext(
    id: MessageId,
    sent_at_millis: u64,
    payload_kind: PayloadKind,
    ratcheted_payload: &[u8],
) -> Vec<u8> {
    use serde::Serialize;

    #[derive(Serialize)]
    struct Wire<'a> {
        version: u8,
        id: [u8; 16],
        sent_at_millis: u64,
        payload_kind: u8,
        ratcheted_payload: &'a [u8],
    }

    let payload_kind = match payload_kind {
        PayloadKind::EncryptedText => 0,
        PayloadKind::Acknowledgment => 1,
        PayloadKind::KeyExchange => 2,
        PayloadKind::RatchetHeader => 3,
    };
    postcard::to_stdvec(&Wire {
        version: 1,
        id: *id.as_bytes(),
        sent_at_millis,
        payload_kind,
        ratcheted_payload,
    })
    .unwrap()
}

fn copy_message(message: &Message) -> Message {
    Message {
        version: message.version,
        recipient_public_key: message.recipient_public_key,
        prekey_reference: message.prekey_reference,
        ephemeral_public_key: message.ephemeral_public_key,
        ciphertext: message.ciphertext.clone(),
    }
}

#[test]
fn outbound_message_and_advanced_state_return_together() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let address = ratchet_address(key.clone());
    let pending_address = pending_acknowledgment_address(key.clone());
    let prior_blob = snapshot.get(&address).unwrap().as_bytes().to_vec();
    let prior_pending_blob = snapshot.get(&pending_address).unwrap().as_bytes().to_vec();
    let sender_identity = sender_identity(1);

    let result = engine
        .encrypt_message_with_transport_binding(
            &snapshot,
            key.clone(),
            outbound(1, b"second", &sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap();

    assert_eq!(result.payload_kind, PayloadKind::EncryptedText);
    assert_eq!(result.state_updates.len(), 2);
    assert_eq!(result.state_updates[0].address(), &address);
    assert_eq!(result.state_updates[1].address(), &pending_address);
    let advanced_blob = result.state_updates[0].blob().unwrap().as_bytes();
    assert_ne!(advanced_blob, prior_blob.as_slice());
    let advanced_pending_blob = result.state_updates[1].blob().unwrap().as_bytes();
    assert_ne!(advanced_pending_blob, prior_pending_blob.as_slice());
}

#[test]
fn sealed_sender_round_trip_hides_sender_identity_until_decrypt() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let sender = validated_sender_for_contact(alternate_contact_identity());
    let domain_keys = [sender.domain_signing_key()];
    let revoked = [];
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let mut alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let mut bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender.sender_identity,
        deduplication_key.clone(),
    );

    let encrypted = engine
        .encrypt_message_with_transport_binding(
            &alice_snapshot,
            key.clone(),
            {
                let contact = accepted_contact_identity();
                OutboundPlaintext {
                    id: MessageId::from_bytes([8; 16]),
                    sender_identity: &sender.sender_identity,
                    sender_identity_signing_key: sender_identity_signing_key(
                        &sender.sender_identity,
                    ),
                    contact_identity_key: contact.identity_key,
                    recipient_public_key: contact.discovery_key.prekey_bundle_lookup_key(),
                    sent_at_millis: 1_700_000_000_888,
                    plaintext: b"sealed sender",
                }
            },
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap();
    alice_snapshot.apply_all(encrypted.state_updates).unwrap();

    let encoded = encrypted.message.to_bytes().unwrap();
    for (name, material) in [
        (
            "identity key",
            sender.sender_identity.identity_key.as_slice(),
        ),
        (
            "identity verifying key",
            sender.sender_identity.identity_verifying_key.as_slice(),
        ),
        (
            "identity binding signature",
            sender.sender_identity.identity_binding_signature.as_slice(),
        ),
        ("certificate", sender.sender_identity.certificate.as_slice()),
        (
            "certificate signature",
            sender.sender_identity.signature.as_slice(),
        ),
    ] {
        assert!(
            !encoded
                .windows(material.len())
                .any(|window| window == material),
            "wire message exposes {name}"
        );
    }

    let decrypted = engine
        .decrypt_message_with_transport_bindings(
            &mut ChaCha20Rng::from_seed([12u8; 32]),
            &bob_snapshot,
            inbound_with_certificate_validation(
                key,
                deduplication_key,
                &encrypted.message,
                &acknowledgment_sender_identity,
                &domain_keys,
                &revoked,
            ),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .map(accepted)
        .unwrap();
    bob_snapshot.apply_all(decrypted.state_updates).unwrap();

    assert_eq!(decrypted.plaintext.as_slice(), b"sealed sender");
    assert_eq!(
        decrypted.sender_identity.identity_key,
        sender.sender_identity.identity_key
    );
    assert_eq!(
        decrypted.sender_identity.identity_verifying_key,
        sender.sender_identity.identity_verifying_key
    );
    assert_eq!(
        decrypted.sender_identity.identity_binding_signature,
        sender.sender_identity.identity_binding_signature
    );
    assert_eq!(
        decrypted.sender_identity.certificate,
        sender.sender_identity.certificate
    );
    assert_eq!(
        decrypted.sender_identity.signature,
        sender.sender_identity.signature
    );
}

#[test]
fn sealed_frame_hides_message_metadata_until_decrypt() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let sender = validated_sender();
    let domain_keys = [sender.domain_signing_key()];
    let revoked = [];
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender.sender_identity,
        deduplication_key.clone(),
    );
    let encrypted = engine
        .encrypt_message_with_transport_binding(
            &alice_snapshot,
            key.clone(),
            outbound(0x42, b"hidden metadata", &sender.sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap();

    assert_eq!(
        encrypted.message.recipient_public_key,
        accepted_contact_identity()
            .discovery_key
            .prekey_bundle_lookup_key(),
        "only recipient routing key remains visible"
    );
    assert!(encrypted.message.prekey_reference.is_none());
    assert_ne!(encrypted.message.ephemeral_public_key, [0u8; 32]);
    assert!(!encrypted.message.ciphertext.is_empty());

    let decrypted = engine
        .decrypt_message_with_transport_bindings(
            &mut ChaCha20Rng::from_seed([0x42; 32]),
            &bob_snapshot,
            inbound_with_certificate_validation(
                key,
                deduplication_key,
                &encrypted.message,
                &acknowledgment_sender_identity,
                &domain_keys,
                &revoked,
            ),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .map(accepted)
        .unwrap();

    assert_eq!(decrypted.message_id, MessageId::from_bytes([0x42; 16]));
    assert_eq!(decrypted.sent_at_millis, 1_700_000_000_123 + 0x42);
    assert_eq!(decrypted.payload_kind, PayloadKind::EncryptedText);
    assert_eq!(decrypted.plaintext.as_slice(), b"hidden metadata");
}

#[test]
fn accepted_message_generates_encrypted_acknowledgment_that_clears_pending_state() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let alice = validated_sender();
    let alice_domain_keys = [alice.domain_signing_key()];
    let revoked = [];
    let bob_sender = acknowledgment_sender_identity();
    let mut alice_snapshot = snapshot_with_state_and_peer_identity(
        &engine,
        key.clone(),
        &setup.alice_state,
        &bob_sender,
    );
    install_pending_acknowledgments(&engine, &mut alice_snapshot, key.clone());
    let mut bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        key.clone(),
        &setup.bob_state,
        &alice.sender_identity,
        deduplication_key.clone(),
    );

    let encrypted = engine
        .encrypt_message_with_transport_binding(
            &alice_snapshot,
            key.clone(),
            outbound(0x31, b"ack me", &alice.sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap();
    alice_snapshot.apply_all(encrypted.state_updates).unwrap();
    let pending = engine
        .pending_acknowledgments(&alice_snapshot, key.clone())
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].message_id, encrypted.message_id);

    let decrypted = engine
        .decrypt_message_with_transport_bindings(
            &mut ChaCha20Rng::from_seed([0x31; 32]),
            &bob_snapshot,
            inbound_with_certificate_validation(
                key.clone(),
                deduplication_key.clone(),
                &encrypted.message,
                &bob_sender,
                &alice_domain_keys,
                &revoked,
            ),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .map(accepted)
        .unwrap();
    bob_snapshot.apply_all(decrypted.state_updates).unwrap();

    assert_eq!(decrypted.plaintext.as_slice(), b"ack me");
    assert!(decrypted.acknowledgment.prekey_reference.is_none());
    let encoded_ack = decrypted.acknowledgment.to_bytes().unwrap();
    assert!(
        !encoded_ack
            .windows(encrypted.message_id.as_bytes().len())
            .any(|window| window == encrypted.message_id.as_bytes())
    );

    let cleared = engine
        .process_acknowledgment_with_transport_binding(
            &mut ChaCha20Rng::from_seed([0x41; 32]),
            &alice_snapshot,
            inbound_acknowledgment(key.clone(), &decrypted.acknowledgment),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap();
    let AcknowledgmentOutcome::Cleared(cleared) = cleared else {
        panic!("acknowledgment did not clear pending state");
    };
    assert_eq!(cleared.acknowledged_message_id, encrypted.message_id);
    assert_eq!(
        cleared.sender_identity.identity_key,
        bob_sender.identity_key
    );
    alice_snapshot.apply_all(cleared.state_updates).unwrap();

    assert!(
        engine
            .pending_acknowledgments(&alice_snapshot, key.clone())
            .unwrap()
            .is_empty()
    );
    let duplicate = engine
        .process_acknowledgment_with_transport_binding(
            &mut ChaCha20Rng::from_seed([0x42; 32]),
            &alice_snapshot,
            inbound_acknowledgment(key.clone(), &decrypted.acknowledgment),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap();
    assert!(matches!(duplicate, AcknowledgmentOutcome::Duplicate));
    for seed in 0x43..0x47 {
        let repeated = engine
            .process_acknowledgment_with_transport_binding(
                &mut ChaCha20Rng::from_seed([seed; 32]),
                &alice_snapshot,
                inbound_acknowledgment(key.clone(), &decrypted.acknowledgment),
                &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            )
            .unwrap();
        assert!(matches!(repeated, AcknowledgmentOutcome::Duplicate));
    }

    let pending_address = pending_acknowledgment_address(key.clone());
    let pending_blob = alice_snapshot.get(&pending_address).unwrap().as_bytes();
    let (mut wire, trailing): (TestPendingAcknowledgmentsWire, &[u8]) =
        postcard::take_from_bytes(&pending_blob[2..]).unwrap();
    assert!(trailing.is_empty());
    assert_eq!(wire.pending.len(), 0);
    assert_eq!(wire.acknowledgment_digests.len(), 1);
    wire.pending.push(TestPendingAcknowledgmentWire {
        message_id: [0x44; 16],
        encoded_message: vec![0xaa],
        first_sent_at_millis: 1_700_000_100_123,
        last_retried_at_millis: None,
    });
    let mut malformed_pending_blob = pending_blob[..2].to_vec();
    malformed_pending_blob.extend(postcard::to_stdvec(&wire).unwrap());
    let mut duplicate_snapshot = ProtocolStateSnapshot::new();
    duplicate_snapshot
        .set(
            pending_address,
            ProtocolStateBlob::from_bytes(malformed_pending_blob),
        )
        .unwrap();

    let duplicate = engine
        .process_acknowledgment_with_transport_binding(
            &mut ChaCha20Rng::from_seed([0x47; 32]),
            &duplicate_snapshot,
            inbound_acknowledgment(key, &decrypted.acknowledgment),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap();
    assert!(matches!(duplicate, AcknowledgmentOutcome::Duplicate));
}

#[test]
fn unknown_acknowledgment_is_non_fatal_miss() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let alice = validated_sender();
    let alice_domain_keys = [alice.domain_signing_key()];
    let revoked = [];
    let bob_sender = acknowledgment_sender_identity();
    let mut alice_snapshot = snapshot_with_state_and_peer_identity(
        &engine,
        key.clone(),
        &setup.alice_state,
        &bob_sender,
    );
    install_pending_acknowledgments(&engine, &mut alice_snapshot, key.clone());
    let bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        key.clone(),
        &setup.bob_state,
        &alice.sender_identity,
        deduplication_key.clone(),
    );
    let encrypted = engine
        .encrypt_message_with_transport_binding(
            &alice_snapshot,
            key.clone(),
            outbound(0x32, b"ack missing pending", &alice.sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap();
    for update in encrypted.state_updates {
        if update.address().kind() == ProtocolStateKind::RatchetSession {
            alice_snapshot.apply(update).unwrap();
        }
    }
    let decrypted = engine
        .decrypt_message_with_transport_bindings(
            &mut ChaCha20Rng::from_seed([0x32; 32]),
            &bob_snapshot,
            inbound_with_certificate_validation(
                key.clone(),
                deduplication_key,
                &encrypted.message,
                &bob_sender,
                &alice_domain_keys,
                &revoked,
            ),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .map(accepted)
        .unwrap();

    let miss = engine
        .process_acknowledgment_with_transport_binding(
            &mut ChaCha20Rng::from_seed([0x43; 32]),
            &alice_snapshot,
            inbound_acknowledgment(key, &decrypted.acknowledgment),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap();

    assert!(matches!(miss, AcknowledgmentOutcome::Missed { .. }));
}

#[test]
fn retry_instructions_are_windowed_and_persisted() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let sender_identity = sender_identity(0xa1);
    let sent_at = 1_700_000_000_200;
    let mut snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    install_pending_acknowledgments(&engine, &mut snapshot, key.clone());

    let encrypted = engine
        .encrypt_message_with_transport_binding(
            &snapshot,
            key.clone(),
            {
                let contact = accepted_contact_identity();
                OutboundPlaintext {
                    id: MessageId::from_bytes([0x33; 16]),
                    sender_identity: &sender_identity,
                    sender_identity_signing_key: sender_identity_signing_key(&sender_identity),
                    contact_identity_key: contact.identity_key,
                    recipient_public_key: contact.discovery_key.prekey_bundle_lookup_key(),
                    sent_at_millis: sent_at,
                    plaintext: b"retry later",
                }
            },
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap();
    snapshot.apply_all(encrypted.state_updates).unwrap();

    let early = engine
        .retry_instructions(
            &snapshot,
            key.clone(),
            from_unix_millis(sent_at + 999).unwrap(),
            Duration::from_millis(1_000),
        )
        .unwrap();
    assert!(early.instructions.is_empty());
    assert!(early.state_updates.is_empty());

    let due = engine
        .retry_instructions(
            &snapshot,
            key.clone(),
            from_unix_millis(sent_at + 1_000).unwrap(),
            Duration::from_millis(1_000),
        )
        .unwrap();
    assert_eq!(due.instructions.len(), 1);
    assert_eq!(due.instructions[0].message_id, encrypted.message_id);
    snapshot.apply_all(due.state_updates).unwrap();

    let repeated = ProtocolStateEngine::new()
        .retry_instructions(
            &snapshot,
            key.clone(),
            from_unix_millis(sent_at + 1_000).unwrap(),
            Duration::from_millis(1_000),
        )
        .unwrap();
    assert!(repeated.instructions.is_empty());
    assert!(repeated.state_updates.is_empty());
    assert_eq!(
        ProtocolStateEngine::new()
            .pending_acknowledgments(&snapshot, key)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn pending_acknowledgment_state_faults_on_bad_blobs() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let address = pending_acknowledgment_address(key.clone());
    let sender_identity = sender_identity(0xa1);
    let mut corrupt_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    corrupt_snapshot
        .set(
            address.clone(),
            ProtocolStateBlob::from_bytes(vec![1, 0, 0xaa]),
        )
        .unwrap();
    assert!(matches!(
            engine.encrypt_message_with_transport_binding(
                &corrupt_snapshot,
                key.clone(),
                outbound(0x34, b"corrupt pending", &sender_identity), &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
    ),
            Err(ProtocolStateError::BlobDecode { address: actual, .. }) if actual == address
        ));

    let mut unsupported_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    unsupported_snapshot
        .set(
            address.clone(),
            ProtocolStateBlob::from_bytes(vec![2, 0, 0xaa]),
        )
        .unwrap();
    assert!(matches!(
        engine.pending_acknowledgments(&unsupported_snapshot, key),
        Err(ProtocolStateError::UnsupportedBlobVersion {
            address: actual,
            major: 2,
            minor: 0
        }) if actual == address
    ));
}

#[test]
fn pending_acknowledgment_state_rejects_x3dh_frame_retries() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let address = pending_acknowledgment_address(key.clone());
    let sender_identity = sender_identity(0xa1);
    let snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let encrypted = engine
        .encrypt_message_with_transport_binding(
            &snapshot,
            key.clone(),
            outbound(0x35, b"retry wrong frame", &sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap();
    let pending_update = encrypted
        .state_updates
        .iter()
        .find(|update| update.address().kind() == ProtocolStateKind::PendingAcknowledgments)
        .unwrap();
    let pending_blob = pending_update.blob().unwrap().as_bytes();
    let (mut wire, trailing): (TestPendingAcknowledgmentsWire, &[u8]) =
        postcard::take_from_bytes(&pending_blob[2..]).unwrap();
    assert!(trailing.is_empty());
    assert_eq!(wire.pending.len(), 1);

    let signed_prekey = KeyPair::from_secret_bytes([0x61; 32]);
    let mut message = Message::from_bytes(&wire.pending[0].encoded_message).unwrap();
    message.prekey_reference = Some(SealedFramePreKeyReference {
        discovery_epoch: 7,
        signed_prekey_public_key: *signed_prekey.public.as_bytes(),
        one_time_prekey_id: None,
        one_time_prekey_public_key: None,
    });
    wire.pending[0].encoded_message = message.to_bytes().unwrap();

    let mut corrupt_blob = pending_blob[..2].to_vec();
    corrupt_blob.extend(postcard::to_stdvec(&wire).unwrap());
    let mut corrupt_snapshot = ProtocolStateSnapshot::new();
    corrupt_snapshot
        .set(address.clone(), ProtocolStateBlob::from_bytes(corrupt_blob))
        .unwrap();

    assert!(matches!(
        engine.pending_acknowledgments(&corrupt_snapshot, key),
        Err(ProtocolStateError::BlobDecode { address: actual, .. }) if actual == address
    ));
}

#[test]
fn hardening_limits_round_trip_on_engine() {
    let limits = ProtocolHardeningLimits {
        deduplication_capacity: MIN_DEDUPLICATION_CAPACITY,
        ..ProtocolHardeningLimits::default()
    };

    let engine = ProtocolStateEngine::with_hardening_limits(limits).unwrap();

    assert_eq!(engine.hardening_limits(), limits);
}

#[test]
fn hardening_limits_reject_unsupported_ceilings() {
    let mut limits = ProtocolHardeningLimits::default();
    limits.max_message_payload_len += 1;

    let result = ProtocolStateEngine::with_hardening_limits(limits);

    assert!(matches!(
        result,
        Err(ProtocolStateError::InvalidHardeningLimit {
            name: "message payload",
            ..
        })
    ));
}

#[test]
fn oversized_inbound_message_rejects_before_state_load() {
    let setup = setup();
    let default_engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let sender = validated_sender();
    let domain_keys = [sender.domain_signing_key()];
    let revoked = [];
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let alice_snapshot = snapshot_with_state(&default_engine, key.clone(), &setup.alice_state);
    let mut bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &default_engine,
        key.clone(),
        &setup.bob_state,
        &sender.sender_identity,
        deduplication_key.clone(),
    );
    let encrypted = default_engine
        .encrypt_message_with_transport_binding(
            &alice_snapshot,
            key.clone(),
            outbound(0x36, b"oversized before state", &sender.sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap()
        .message;
    let encoded_len = encrypted.to_bytes().unwrap().len();
    let limits = ProtocolHardeningLimits {
        max_encoded_message_len: encoded_len - 1,
        ..ProtocolHardeningLimits::default()
    };
    let rejecting_engine = ProtocolStateEngine::with_hardening_limits(limits).unwrap();
    let ratchet_address = ratchet_address(key.clone());
    let deduplication_address = deduplication_address(deduplication_key.clone());
    let corrupt = vec![1, 0, 0xaa];
    bob_snapshot
        .set(
            ratchet_address.clone(),
            ProtocolStateBlob::from_bytes(corrupt.clone()),
        )
        .unwrap();
    bob_snapshot
        .set(
            deduplication_address.clone(),
            ProtocolStateBlob::from_bytes(corrupt.clone()),
        )
        .unwrap();

    let result = rejecting_engine.decrypt_message_with_transport_bindings(
        &mut ChaCha20Rng::from_seed([0x36; 32]),
        &bob_snapshot,
        inbound_with_certificate_validation(
            key.clone(),
            deduplication_key.clone(),
            &encrypted,
            &acknowledgment_sender_identity,
            &domain_keys,
            &revoked,
        ),
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
    );

    assert!(matches!(
        result,
        Err(ProtocolStateError::MessageEncode(
            MessageError::EncodedTooLarge
        ))
    ));
    assert_eq!(
        bob_snapshot.get(&ratchet_address).unwrap().as_bytes(),
        corrupt
    );
    assert_eq!(
        bob_snapshot.get(&deduplication_address).unwrap().as_bytes(),
        corrupt
    );
}

#[test]
fn configured_blob_limit_rejects_decode_before_restore() {
    let setup = setup();
    let default_engine = ProtocolStateEngine::new();
    let key = key();
    let sender_identity = sender_identity(0xa1);
    let snapshot = snapshot_with_state(&default_engine, key.clone(), &setup.alice_state);
    let address = ratchet_address(key.clone());
    let blob_len = snapshot.get(&address).unwrap().as_bytes().len();
    let limits = ProtocolHardeningLimits {
        max_protocol_state_blob_len: blob_len - 1,
        ..ProtocolHardeningLimits::default()
    };
    let engine = ProtocolStateEngine::with_hardening_limits(limits).unwrap();

    let result = engine.encrypt_message_with_transport_binding(
        &snapshot,
        key,
        outbound(0x37, b"blob limit", &sender_identity),
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
    );

    assert!(matches!(
        result,
        Err(ProtocolStateError::BlobDecode { address: actual, .. }) if actual == address
    ));
}

#[test]
fn configured_blob_limit_accepts_exact_size() {
    let setup = setup();
    let default_engine = ProtocolStateEngine::new();
    let key = key();
    let snapshot = snapshot_with_state(&default_engine, key.clone(), &setup.alice_state);
    let address = pending_acknowledgment_address(key.clone());
    let blob_len = snapshot.get(&address).unwrap().as_bytes().len();
    let limits = ProtocolHardeningLimits {
        max_protocol_state_blob_len: blob_len,
        ..ProtocolHardeningLimits::default()
    };
    let engine = ProtocolStateEngine::with_hardening_limits(limits).unwrap();

    let pending = engine.pending_acknowledgments(&snapshot, key).unwrap();

    assert!(pending.is_empty());
}

#[test]
fn configured_payload_limit_rejects_before_state_load() {
    let setup = setup();
    let default_engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let sender = validated_sender();
    let domain_keys = [sender.domain_signing_key()];
    let revoked = [];
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let alice_snapshot = snapshot_with_state(&default_engine, key.clone(), &setup.alice_state);
    let mut bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &default_engine,
        key.clone(),
        &setup.bob_state,
        &sender.sender_identity,
        deduplication_key.clone(),
    );
    let encrypted = default_engine
        .encrypt_message_with_transport_binding(
            &alice_snapshot,
            key.clone(),
            outbound(0x38, b"payload limit", &sender.sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap()
        .message;
    let limits = ProtocolHardeningLimits {
        max_message_payload_len: encrypted.ciphertext.len() - 1,
        ..ProtocolHardeningLimits::default()
    };
    let engine = ProtocolStateEngine::with_hardening_limits(limits).unwrap();
    let deduplication_address = deduplication_address(deduplication_key.clone());
    let corrupt = vec![1, 0, 0xaa];
    bob_snapshot
        .set(
            deduplication_address.clone(),
            ProtocolStateBlob::from_bytes(corrupt.clone()),
        )
        .unwrap();

    let result = engine.decrypt_message_with_transport_bindings(
        &mut ChaCha20Rng::from_seed([0x38; 32]),
        &bob_snapshot,
        inbound_with_certificate_validation(
            key.clone(),
            deduplication_key.clone(),
            &encrypted,
            &acknowledgment_sender_identity,
            &domain_keys,
            &revoked,
        ),
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
    );

    assert!(matches!(
        result,
        Err(ProtocolStateError::MessageEncode(
            MessageError::PayloadTooLarge
        ))
    ));
    assert_eq!(
        bob_snapshot.get(&deduplication_address).unwrap().as_bytes(),
        corrupt
    );
}

#[test]
fn configured_sender_material_limits_reject_without_state_updates() {
    let setup = setup();
    let default_engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let sender = validated_sender();
    let domain_keys = [sender.domain_signing_key()];
    let revoked = [];
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let alice_snapshot = snapshot_with_state(&default_engine, key.clone(), &setup.alice_state);
    let bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &default_engine,
        key.clone(),
        &setup.bob_state,
        &sender.sender_identity,
        deduplication_key.clone(),
    );
    let encrypted = default_engine
        .encrypt_message_with_transport_binding(
            &alice_snapshot,
            key.clone(),
            outbound(0x39, b"certificate limit", &sender.sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap()
        .message;
    let ratchet_address = ratchet_address(key.clone());
    let deduplication_address = deduplication_address(deduplication_key.clone());
    let ratchet_before = bob_snapshot
        .get(&ratchet_address)
        .unwrap()
        .as_bytes()
        .to_vec();
    let dedup_before = bob_snapshot
        .get(&deduplication_address)
        .unwrap()
        .as_bytes()
        .to_vec();
    let limits = ProtocolHardeningLimits {
        max_sender_certificate_len: sender.sender_identity.certificate.len() - 1,
        ..ProtocolHardeningLimits::default()
    };
    let engine = ProtocolStateEngine::with_hardening_limits(limits).unwrap();

    let result = engine.decrypt_message_with_transport_bindings(
        &mut ChaCha20Rng::from_seed([0x39; 32]),
        &bob_snapshot,
        inbound_with_certificate_validation(
            key.clone(),
            deduplication_key.clone(),
            &encrypted,
            &acknowledgment_sender_identity,
            &domain_keys,
            &revoked,
        ),
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
    );

    assert!(matches!(
        result,
        Err(ProtocolStateError::InvalidMessage { .. })
    ));
    assert_eq!(
        bob_snapshot.get(&ratchet_address).unwrap().as_bytes(),
        ratchet_before
    );
    assert_eq!(
        bob_snapshot.get(&deduplication_address).unwrap().as_bytes(),
        dedup_before
    );

    let limits = ProtocolHardeningLimits {
        max_sender_signature_len: sender.sender_identity.signature.len() - 1,
        ..ProtocolHardeningLimits::default()
    };
    let engine = ProtocolStateEngine::with_hardening_limits(limits).unwrap();
    let result = engine.decrypt_message_with_transport_bindings(
        &mut ChaCha20Rng::from_seed([0x3b; 32]),
        &bob_snapshot,
        inbound_with_certificate_validation(
            key,
            deduplication_key,
            &encrypted,
            &acknowledgment_sender_identity,
            &domain_keys,
            &revoked,
        ),
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
    );

    assert!(matches!(
        result,
        Err(ProtocolStateError::InvalidMessage { .. })
    ));
}

#[test]
fn configured_boundary_limits_accept_exact_sizes() {
    let setup = setup();
    let default_engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let sender = validated_sender();
    let domain_keys = [sender.domain_signing_key()];
    let revoked = [];
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let alice_snapshot = snapshot_with_state(&default_engine, key.clone(), &setup.alice_state);
    let bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &default_engine,
        key.clone(),
        &setup.bob_state,
        &sender.sender_identity,
        deduplication_key.clone(),
    );
    let encrypted = default_engine
        .encrypt_message_with_transport_binding(
            &alice_snapshot,
            key.clone(),
            outbound(0x3a, b"exact limits", &sender.sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap()
        .message;
    let limits = ProtocolHardeningLimits {
        max_encoded_message_len: encrypted.to_bytes().unwrap().len(),
        max_message_payload_len: encrypted.ciphertext.len(),
        max_sender_certificate_len: sender.sender_identity.certificate.len(),
        max_sender_signature_len: sender.sender_identity.signature.len(),
        ..ProtocolHardeningLimits::default()
    };
    let engine = ProtocolStateEngine::with_hardening_limits(limits).unwrap();

    let result = engine
        .decrypt_message_with_transport_bindings(
            &mut ChaCha20Rng::from_seed([0x3a; 32]),
            &bob_snapshot,
            inbound_with_certificate_validation(
                key,
                deduplication_key,
                &encrypted,
                &acknowledgment_sender_identity,
                &domain_keys,
                &revoked,
            ),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .map(accepted)
        .unwrap();

    assert_eq!(result.plaintext.as_slice(), b"exact limits");
}

#[test]
fn unique_received_message_is_accepted_recorded_and_emitted_once() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let sender = validated_sender();
    let domain_keys = [sender.domain_signing_key()];
    let revoked = [];
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let mut bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender.sender_identity,
        deduplication_key.clone(),
    );
    let ratchet_address = ratchet_address(key.clone());
    let deduplication_address = deduplication_address(deduplication_key.clone());
    let prior_ratchet = bob_snapshot
        .get(&ratchet_address)
        .unwrap()
        .as_bytes()
        .to_vec();
    let prior_deduplication = bob_snapshot
        .get(&deduplication_address)
        .unwrap()
        .as_bytes()
        .to_vec();
    let encrypted = engine
        .encrypt_message_with_transport_binding(
            &alice_snapshot,
            key.clone(),
            outbound(10, b"accept once", &sender.sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap()
        .message;

    let decrypted = engine
        .decrypt_message_with_transport_bindings(
            &mut ChaCha20Rng::from_seed([19u8; 32]),
            &bob_snapshot,
            inbound_with_certificate_validation(
                key.clone(),
                deduplication_key.clone(),
                &encrypted,
                &acknowledgment_sender_identity,
                &domain_keys,
                &revoked,
            ),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .map(accepted)
        .unwrap();

    assert_eq!(decrypted.plaintext.as_slice(), b"accept once");
    assert_eq!(decrypted.state_updates.len(), 2);
    assert_eq!(decrypted.state_updates[0].address(), &ratchet_address);
    assert_eq!(decrypted.state_updates[1].address(), &deduplication_address);
    assert_ne!(
        decrypted.state_updates[0].blob().unwrap().as_bytes(),
        prior_ratchet
    );
    assert_ne!(
        decrypted.state_updates[1].blob().unwrap().as_bytes(),
        prior_deduplication
    );
    bob_snapshot.apply_all(decrypted.state_updates).unwrap();

    let duplicate = ProtocolStateEngine::new()
        .decrypt_message_with_transport_bindings(
            &mut ChaCha20Rng::from_seed([20u8; 32]),
            &bob_snapshot,
            inbound(
                key,
                deduplication_key,
                &encrypted,
                &acknowledgment_sender_identity,
            ),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap();
    assert!(matches!(duplicate, InboundMessageOutcome::Duplicate));
}

#[test]
fn replay_storm_returns_duplicate_without_state_churn() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let sender = validated_sender();
    let domain_keys = [sender.domain_signing_key()];
    let revoked = [];
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let mut bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender.sender_identity,
        deduplication_key.clone(),
    );
    let encrypted = engine
        .encrypt_message_with_transport_binding(
            &alice_snapshot,
            key.clone(),
            outbound(0x3c, b"replay storm", &sender.sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap()
        .message;
    let decrypted = engine
        .decrypt_message_with_transport_bindings(
            &mut ChaCha20Rng::from_seed([0x3c; 32]),
            &bob_snapshot,
            inbound_with_certificate_validation(
                key.clone(),
                deduplication_key.clone(),
                &encrypted,
                &acknowledgment_sender_identity,
                &domain_keys,
                &revoked,
            ),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .map(accepted)
        .unwrap();
    bob_snapshot.apply_all(decrypted.state_updates).unwrap();
    let ratchet_address = ratchet_address(key.clone());
    let deduplication_address = deduplication_address(deduplication_key.clone());
    let ratchet_after_accept = bob_snapshot
        .get(&ratchet_address)
        .unwrap()
        .as_bytes()
        .to_vec();
    let dedup_after_accept = bob_snapshot
        .get(&deduplication_address)
        .unwrap()
        .as_bytes()
        .to_vec();

    for seed in 0x3d..0x45 {
        let duplicate = engine
            .decrypt_message_with_transport_bindings(
                &mut ChaCha20Rng::from_seed([seed; 32]),
                &bob_snapshot,
                inbound(
                    key.clone(),
                    deduplication_key.clone(),
                    &encrypted,
                    &acknowledgment_sender_identity,
                ),
                &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
                &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            )
            .unwrap();
        assert!(matches!(duplicate, InboundMessageOutcome::Duplicate));
        assert_eq!(
            bob_snapshot.get(&ratchet_address).unwrap().as_bytes(),
            ratchet_after_accept
        );
        assert_eq!(
            bob_snapshot.get(&deduplication_address).unwrap().as_bytes(),
            dedup_after_accept
        );
    }
}

#[test]
fn skipped_key_total_overflow_rejects_without_marking_session_unrecoverable() {
    let mut setup = setup();
    let mut rng = ChaCha20Rng::from_seed([0xf0; 32]);
    // Fill the Crypto cache directly; Core only needs to translate one overflow and its retry.
    let associated_data = b"skipped-key fixture";
    for _ in 0..5 {
        let messages: Vec<_> = (0..=100)
            .map(|_| {
                setup
                    .alice_state
                    .ratchet_encrypt(b"fill", associated_data)
                    .unwrap()
            })
            .collect();
        let (header, ciphertext) = messages.last().unwrap();
        setup
            .bob_state
            .ratchet_decrypt(&mut rng, ciphertext, header, associated_data)
            .unwrap();
    }
    assert_eq!(setup.bob_state.skipped_key_count(), 500);
    setup
        .alice_state
        .ratchet_encrypt(b"undelivered", associated_data)
        .unwrap();

    let engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let sender = validated_sender();
    let domain_keys = [sender.domain_signing_key()];
    let revoked = [];
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender.sender_identity,
        deduplication_key.clone(),
    );
    let binding = roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap();
    let terminal = engine
        .encrypt_message_with_transport_binding(
            &alice_snapshot,
            key.clone(),
            outbound(1, b"overflow", &sender.sender_identity),
            &binding,
        )
        .unwrap()
        .message;

    let overflow = engine.decrypt_message_with_transport_bindings(
        &mut ChaCha20Rng::from_seed([0xf0; 32]),
        &bob_snapshot,
        inbound_with_certificate_validation(
            key.clone(),
            deduplication_key.clone(),
            &terminal,
            &acknowledgment_sender_identity,
            &domain_keys,
            &revoked,
        ),
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
    );
    assert!(matches!(
        overflow,
        Err(ProtocolStateError::Ratchet(
            RatchetError::MaxSkippedKeysExceeded
        ))
    ));

    let repeated = engine.decrypt_message_with_transport_bindings(
        &mut ChaCha20Rng::from_seed([0xf1; 32]),
        &bob_snapshot,
        inbound_with_certificate_validation(
            key.clone(),
            deduplication_key.clone(),
            &terminal,
            &acknowledgment_sender_identity,
            &domain_keys,
            &revoked,
        ),
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
    );
    assert!(matches!(
        repeated,
        Err(ProtocolStateError::Ratchet(
            RatchetError::MaxSkippedKeysExceeded
        ))
    ));
}

#[test]
fn dead_session_marker_reports_once_without_reset() {
    let initial_setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let sender = validated_sender();
    let domain_keys = [sender.domain_signing_key()];
    let revoked = [];
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let alice_snapshot = snapshot_with_state(&engine, key.clone(), &initial_setup.alice_state);
    let mut bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        key.clone(),
        &initial_setup.bob_state,
        &sender.sender_identity,
        deduplication_key.clone(),
    );
    let address = ratchet_address(key.clone());
    let dead_message = engine
        .encrypt_message_with_transport_binding(
            &alice_snapshot,
            key.clone(),
            sequenced_outbound(0x80, b"dead marker probe", &sender.sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap()
        .message;
    bob_snapshot
        .set(
            address.clone(),
            dead_session_blob(false, sender.sender_identity.identity_key),
        )
        .unwrap();

    let unrecoverable = engine
        .decrypt_message_with_transport_bindings(
            &mut ChaCha20Rng::from_seed([0xe0; 32]),
            &bob_snapshot,
            inbound_with_certificate_validation(
                key.clone(),
                deduplication_key.clone(),
                &dead_message,
                &acknowledgment_sender_identity,
                &domain_keys,
                &revoked,
            ),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .map(session_unrecoverable)
        .unwrap();
    assert_eq!(unrecoverable.session_key, key);
    assert_eq!(
        unrecoverable.reason,
        SessionUnrecoverableReason::SkippedKeyLimitExceeded
    );
    assert_eq!(unrecoverable.state_updates.len(), 1);
    assert_eq!(unrecoverable.state_updates[0].address(), &address);
    assert!(matches!(
        unrecoverable.event,
        Some(SessionEvent::Unrecoverable {
            reason: SessionUnrecoverableReason::SkippedKeyLimitExceeded,
            ..
        })
    ));
    bob_snapshot.apply_all(unrecoverable.state_updates).unwrap();

    let repeated = engine
        .decrypt_message_with_transport_bindings(
            &mut ChaCha20Rng::from_seed([0xe1; 32]),
            &bob_snapshot,
            inbound_with_certificate_validation(
                key.clone(),
                deduplication_key.clone(),
                &dead_message,
                &acknowledgment_sender_identity,
                &domain_keys,
                &revoked,
            ),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .map(session_unrecoverable)
        .unwrap();
    assert!(repeated.event.is_none());
    assert!(repeated.state_updates.is_empty());
}

#[test]
fn transient_aead_failure_does_not_mark_session_unrecoverable() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let sender = validated_sender();
    let domain_keys = [sender.domain_signing_key()];
    let revoked = [];
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender.sender_identity,
        deduplication_key.clone(),
    );
    let encrypted = engine
        .encrypt_message_with_transport_binding(
            &alice_snapshot,
            key.clone(),
            sequenced_outbound(0x70, b"valid after tamper", &sender.sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap()
        .message;
    let mut tampered = copy_message(&encrypted);
    *tampered.ciphertext.last_mut().unwrap() ^= 0x01;

    assert!(matches!(
        engine.decrypt_message_with_transport_bindings(
            &mut ChaCha20Rng::from_seed([0x70; 32]),
            &bob_snapshot,
            inbound_with_certificate_validation(
                key.clone(),
                deduplication_key.clone(),
                &tampered,
                &acknowledgment_sender_identity,
                &domain_keys,
                &revoked,
            ),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        ),
        Err(ProtocolStateError::SealedFrame(SealedFrameError::Aead))
    ));

    let decrypted = engine
        .decrypt_message_with_transport_bindings(
            &mut ChaCha20Rng::from_seed([0x71; 32]),
            &bob_snapshot,
            inbound_with_certificate_validation(
                key,
                deduplication_key,
                &encrypted,
                &acknowledgment_sender_identity,
                &domain_keys,
                &revoked,
            ),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .map(accepted)
        .unwrap();

    assert_eq!(decrypted.plaintext.as_slice(), b"valid after tamper");
}

#[test]
fn receive_without_certificate_validation_rejects_before_plaintext_is_surfaced() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let sender = validated_sender();
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender.sender_identity,
        deduplication_key.clone(),
    );
    let encrypted = engine
        .encrypt_message_with_transport_binding(
            &alice_snapshot,
            key.clone(),
            outbound(0x4f, b"must validate", &sender.sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap()
        .message;

    let result = engine.decrypt_message_with_transport_bindings(
        &mut ChaCha20Rng::from_seed([0x4f; 32]),
        &bob_snapshot,
        inbound(
            key,
            deduplication_key,
            &encrypted,
            &acknowledgment_sender_identity,
        ),
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
    );

    assert!(matches!(
        result,
        Err(ProtocolStateError::MissingSenderCertificateValidation)
    ));
}

#[test]
fn validated_receive_persists_contact_identity_key_into_session_update() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let sender = validated_sender();
    let domain_keys = [sender.domain_signing_key()];
    let revoked = [];
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let other_contact = alternate_contact_identity();
    let alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let mut bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender.sender_identity,
        deduplication_key.clone(),
    );
    install_accepted_contact_identity(&engine, &mut bob_snapshot, other_contact);
    let encrypted = engine
        .encrypt_message_with_transport_binding(
            &alice_snapshot,
            key.clone(),
            outbound(0x50, b"bind contact", &sender.sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap()
        .message;
    let decrypted = engine
        .decrypt_message_with_transport_bindings(
            &mut ChaCha20Rng::from_seed([0x50; 32]),
            &bob_snapshot,
            inbound_with_certificate_validation(
                key.clone(),
                deduplication_key,
                &encrypted,
                &acknowledgment_sender_identity,
                &domain_keys,
                &revoked,
            ),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .map(accepted)
        .unwrap();
    bob_snapshot.apply_all(decrypted.state_updates).unwrap();

    let result = engine.encrypt_message_with_transport_binding(
        &bob_snapshot,
        key.clone(),
        OutboundPlaintext {
            id: MessageId::from_bytes([0x50; 16]),
            sender_identity: &acknowledgment_sender_identity,
            sender_identity_signing_key: sender_identity_signing_key(
                &acknowledgment_sender_identity,
            ),
            contact_identity_key: other_contact.identity_key,
            recipient_public_key: other_contact.discovery_key.prekey_bundle_lookup_key(),
            sent_at_millis: 1_700_000_000_500,
            plaintext: b"wrong contact",
        },
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
    );

    assert!(matches!(
        result,
        Err(ProtocolStateError::InvalidStateBinding { address, .. })
            if address == ratchet_address(key)
    ));
}

#[test]
fn duplicate_received_message_does_not_load_or_advance_ratchet_state() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let sender = validated_sender();
    let domain_keys = [sender.domain_signing_key()];
    let revoked = [];
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let mut bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender.sender_identity,
        deduplication_key.clone(),
    );
    let encrypted = engine
        .encrypt_message_with_transport_binding(
            &alice_snapshot,
            key.clone(),
            outbound(11, b"no duplicate effect", &sender.sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap()
        .message;
    let decrypted = engine
        .decrypt_message_with_transport_bindings(
            &mut ChaCha20Rng::from_seed([21u8; 32]),
            &bob_snapshot,
            inbound_with_certificate_validation(
                key.clone(),
                deduplication_key.clone(),
                &encrypted,
                &acknowledgment_sender_identity,
                &domain_keys,
                &revoked,
            ),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .map(accepted)
        .unwrap();
    bob_snapshot.apply_all(decrypted.state_updates).unwrap();
    let ratchet_address = ratchet_address(key.clone());
    bob_snapshot
        .set(
            ratchet_address,
            ProtocolStateBlob::from_bytes(vec![1, 0, 0xaa]),
        )
        .unwrap();

    let duplicate = engine
        .decrypt_message_with_transport_bindings(
            &mut ChaCha20Rng::from_seed([22u8; 32]),
            &bob_snapshot,
            inbound(
                key,
                deduplication_key,
                &encrypted,
                &acknowledgment_sender_identity,
            ),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap();

    assert!(matches!(duplicate, InboundMessageOutcome::Duplicate));
}

#[test]
fn blocked_inbound_message_under_unreachable_policy_suppresses_acknowledgment_without_plaintext() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let sender = validated_sender();
    let domain_keys = [sender.domain_signing_key()];
    let revoked = [];
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let mut bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender.sender_identity,
        deduplication_key.clone(),
    );
    block_contact(&engine, &mut bob_snapshot);
    let ratchet_address = ratchet_address(key.clone());
    let deduplication_address = deduplication_address(deduplication_key.clone());
    let prior_ratchet = bob_snapshot
        .get(&ratchet_address)
        .unwrap()
        .as_bytes()
        .to_vec();
    let prior_deduplication = bob_snapshot
        .get(&deduplication_address)
        .unwrap()
        .as_bytes()
        .to_vec();
    let encrypted = engine
        .encrypt_message_with_transport_binding(
            &alice_snapshot,
            key.clone(),
            outbound(0x51, b"blocked text", &sender.sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap()
        .message;

    let blocked = engine
        .decrypt_message_with_transport_bindings(
            &mut ChaCha20Rng::from_seed([0x51; 32]),
            &bob_snapshot,
            inbound_with_certificate_validation(
                key,
                deduplication_key,
                &encrypted,
                &acknowledgment_sender_identity,
                &domain_keys,
                &revoked,
            ),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .map(blocked)
        .unwrap();

    assert!(blocked.acknowledgment.is_none());
    assert_eq!(blocked.state_updates.len(), 2);
    assert_eq!(blocked.state_updates[0].address(), &ratchet_address);
    assert_eq!(blocked.state_updates[1].address(), &deduplication_address);
    assert_ne!(
        blocked.state_updates[0].blob().unwrap().as_bytes(),
        prior_ratchet
    );
    assert_ne!(
        blocked.state_updates[1].blob().unwrap().as_bytes(),
        prior_deduplication
    );
}

#[test]
fn blocked_inbound_message_under_silent_receipt_policy_returns_acknowledgment_without_plaintext() {
    let setup = setup();
    let engine = ProtocolStateEngine::new().with_blocked_contact_acknowledgment_policy(
        BlockedContactAcknowledgmentPolicy::SilentReceipt,
    );
    let key = key();
    let deduplication_key = deduplication_key();
    let sender = validated_sender();
    let domain_keys = [sender.domain_signing_key()];
    let revoked = [];
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let mut bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender.sender_identity,
        deduplication_key.clone(),
    );
    block_contact(&engine, &mut bob_snapshot);
    let ratchet_address = ratchet_address(key.clone());
    let deduplication_address = deduplication_address(deduplication_key.clone());
    let encrypted = engine
        .encrypt_message_with_transport_binding(
            &alice_snapshot,
            key.clone(),
            outbound(0x54, b"blocked but receipted", &sender.sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap()
        .message;

    let blocked = engine
        .decrypt_message_with_transport_bindings(
            &mut ChaCha20Rng::from_seed([0x54; 32]),
            &bob_snapshot,
            inbound_with_certificate_validation(
                key,
                deduplication_key,
                &encrypted,
                &acknowledgment_sender_identity,
                &domain_keys,
                &revoked,
            ),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .map(blocked)
        .unwrap();

    let acknowledgment = blocked
        .acknowledgment
        .expect("silent-receipt returns an acknowledgment");
    assert!(acknowledgment.prekey_reference.is_none());
    assert_eq!(blocked.state_updates.len(), 2);
    assert_eq!(blocked.state_updates[0].address(), &ratchet_address);
    assert_eq!(blocked.state_updates[1].address(), &deduplication_address);
}

#[test]
fn blocked_acknowledgment_policy_controls_sending_chain_advance() {
    let setup = setup();
    let unreachable = ProtocolStateEngine::new();
    let silent_receipt = ProtocolStateEngine::new().with_blocked_contact_acknowledgment_policy(
        BlockedContactAcknowledgmentPolicy::SilentReceipt,
    );
    let key = key();
    let deduplication_key = deduplication_key();
    let sender = validated_sender();
    let domain_keys = [sender.domain_signing_key()];
    let revoked = [];
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let alice_snapshot = snapshot_with_state(&unreachable, key.clone(), &setup.alice_state);
    let mut bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &unreachable,
        key.clone(),
        &setup.bob_state,
        &sender.sender_identity,
        deduplication_key.clone(),
    );
    block_contact(&unreachable, &mut bob_snapshot);
    let ratchet_address = ratchet_address(key.clone());
    let encrypted = unreachable
        .encrypt_message_with_transport_binding(
            &alice_snapshot,
            key.clone(),
            outbound(0x55, b"chain advance", &sender.sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap()
        .message;

    let suppressed = unreachable
        .decrypt_message_with_transport_bindings(
            &mut ChaCha20Rng::from_seed([0x55; 32]),
            &bob_snapshot,
            inbound_with_certificate_validation(
                key.clone(),
                deduplication_key.clone(),
                &encrypted,
                &acknowledgment_sender_identity,
                &domain_keys,
                &revoked,
            ),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .map(blocked)
        .unwrap();
    let receipted = silent_receipt
        .decrypt_message_with_transport_bindings(
            &mut ChaCha20Rng::from_seed([0x55; 32]),
            &bob_snapshot,
            inbound_with_certificate_validation(
                key,
                deduplication_key,
                &encrypted,
                &acknowledgment_sender_identity,
                &domain_keys,
                &revoked,
            ),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .map(blocked)
        .unwrap();

    assert!(suppressed.acknowledgment.is_none());
    assert!(receipted.acknowledgment.is_some());
    assert_eq!(suppressed.state_updates[0].address(), &ratchet_address);
    assert_eq!(receipted.state_updates[0].address(), &ratchet_address);
    // The acknowledgment advances the sending chain, so only silent-receipt mutates it further.
    assert_ne!(
        suppressed.state_updates[0].blob().unwrap().as_bytes(),
        receipted.state_updates[0].blob().unwrap().as_bytes(),
    );
}

#[test]
fn duplicate_blocked_inbound_message_does_not_load_or_advance_ratchet_state() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let sender = validated_sender();
    let domain_keys = [sender.domain_signing_key()];
    let revoked = [];
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let mut bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender.sender_identity,
        deduplication_key.clone(),
    );
    block_contact(&engine, &mut bob_snapshot);
    let encrypted = engine
        .encrypt_message_with_transport_binding(
            &alice_snapshot,
            key.clone(),
            outbound(0x52, b"blocked once", &sender.sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap()
        .message;
    let first = engine
        .decrypt_message_with_transport_bindings(
            &mut ChaCha20Rng::from_seed([0x52; 32]),
            &bob_snapshot,
            inbound_with_certificate_validation(
                key.clone(),
                deduplication_key.clone(),
                &encrypted,
                &acknowledgment_sender_identity,
                &domain_keys,
                &revoked,
            ),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .map(blocked)
        .unwrap();
    bob_snapshot.apply_all(first.state_updates).unwrap();
    bob_snapshot
        .set(
            ratchet_address(key.clone()),
            ProtocolStateBlob::from_bytes(vec![1, 0, 0xaa]),
        )
        .unwrap();

    let duplicate = engine
        .decrypt_message_with_transport_bindings(
            &mut ChaCha20Rng::from_seed([0x53; 32]),
            &bob_snapshot,
            inbound_with_certificate_validation(
                key,
                deduplication_key,
                &encrypted,
                &acknowledgment_sender_identity,
                &domain_keys,
                &revoked,
            ),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap();

    assert!(matches!(duplicate, InboundMessageOutcome::Duplicate));
}

#[test]
fn discovery_key_rotation_does_not_bypass_blocked_inbound_message() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let sender = validated_sender();
    let domain_keys = [sender.domain_signing_key()];
    let revoked = [];
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let mut bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender.sender_identity,
        deduplication_key.clone(),
    );
    block_contact(&engine, &mut bob_snapshot);
    rotate_blocked_contact(&engine, &mut bob_snapshot);
    let encrypted = engine
        .encrypt_message_with_transport_binding(
            &alice_snapshot,
            key.clone(),
            outbound(0x54, b"rotated blocked", &sender.sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap()
        .message;

    let outcome = engine
        .decrypt_message_with_transport_bindings(
            &mut ChaCha20Rng::from_seed([0x54; 32]),
            &bob_snapshot,
            inbound_with_certificate_validation(
                key,
                deduplication_key,
                &encrypted,
                &acknowledgment_sender_identity,
                &domain_keys,
                &revoked,
            ),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap();

    assert!(matches!(outcome, InboundMessageOutcome::Blocked(_)));
}

#[test]
fn revoked_certificate_rejects_before_local_block_handling() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let sender = validated_sender();
    let domain_keys = [sender.domain_signing_key()];
    let revoked = [sender.revoked_identity_key()];
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let mut bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender.sender_identity,
        deduplication_key.clone(),
    );
    block_contact(&engine, &mut bob_snapshot);
    let encrypted = engine
        .encrypt_message_with_transport_binding(
            &alice_snapshot,
            key.clone(),
            outbound(0x55, b"revoked blocked", &sender.sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap()
        .message;

    let result = engine.decrypt_message_with_transport_bindings(
        &mut ChaCha20Rng::from_seed([0x55; 32]),
        &bob_snapshot,
        inbound_with_certificate_validation(
            key,
            deduplication_key,
            &encrypted,
            &acknowledgment_sender_identity,
            &domain_keys,
            &revoked,
        ),
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
    );

    assert!(matches!(
        result,
        Err(ProtocolStateError::SenderCertificateValidation(
            SenderCertificateValidationError::RevokedIdentityKey
        ))
    ));
}

#[test]
fn validated_once_then_missing_validation_rejects_for_blocked_sender() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let sender = validated_sender();
    let domain_keys = [sender.domain_signing_key()];
    let revoked = [];
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let mut alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let mut bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender.sender_identity,
        deduplication_key.clone(),
    );
    let first = engine
        .encrypt_message_with_transport_binding(
            &alice_snapshot,
            key.clone(),
            outbound(0x5b, b"validated first", &sender.sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap();
    alice_snapshot.apply_all(first.state_updates).unwrap();
    let accepted = engine
        .decrypt_message_with_transport_bindings(
            &mut ChaCha20Rng::from_seed([0x5b; 32]),
            &bob_snapshot,
            inbound_with_certificate_validation(
                key.clone(),
                deduplication_key.clone(),
                &first.message,
                &acknowledgment_sender_identity,
                &domain_keys,
                &revoked,
            ),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .map(accepted)
        .unwrap();
    bob_snapshot.apply_all(accepted.state_updates).unwrap();
    block_contact(&engine, &mut bob_snapshot);
    let second = engine
        .encrypt_message_with_transport_binding(
            &alice_snapshot,
            key.clone(),
            outbound(0x5c, b"missing validation", &sender.sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap();

    let result = engine.decrypt_message_with_transport_bindings(
        &mut ChaCha20Rng::from_seed([0x5c; 32]),
        &bob_snapshot,
        inbound(
            key,
            deduplication_key,
            &second.message,
            &acknowledgment_sender_identity,
        ),
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
    );

    assert!(matches!(
        result,
        Err(ProtocolStateError::MissingSenderCertificateValidation)
    ));
}

#[test]
fn unavailable_revocation_state_rejects_before_plaintext_is_surfaced() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let sender = validated_sender();
    let domain_keys = [sender.domain_signing_key()];
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender.sender_identity,
        deduplication_key.clone(),
    );
    let encrypted = engine
        .encrypt_message_with_transport_binding(
            &alice_snapshot,
            key.clone(),
            outbound(0x56, b"revocation unavailable", &sender.sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap()
        .message;

    let result = engine.decrypt_message_with_transport_bindings(
        &mut ChaCha20Rng::from_seed([0x56; 32]),
        &bob_snapshot,
        InboundEncryptedMessage {
            session_key: key,
            deduplication_key,
            message: &encrypted,
            recipient_discovery_key: accepted_contact_discovery_key_ref(),
            recipient_identity_verifying_key: accepted_contact_identity()
                .identity_key
                .ed25519_verifying_key,
            acknowledgment: acknowledgment(0xee, &acknowledgment_sender_identity),
            sender_certificate_validation: Some(sender_certificate_validation(
                &domain_keys,
                RevocationState::Unavailable,
            )),
        },
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
    );

    assert!(matches!(
        result,
        Err(ProtocolStateError::SenderCertificateValidation(
            SenderCertificateValidationError::RevocationStateUnavailable
        ))
    ));
}

#[test]
fn untrusted_signing_key_rejects_before_plaintext_is_surfaced() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let sender = validated_sender();
    let domain_keys = [sender.domain_signing_key_with_status(DomainSigningKeyStatus::Untrusted)];
    let revoked = [];
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender.sender_identity,
        deduplication_key.clone(),
    );
    let encrypted = engine
        .encrypt_message_with_transport_binding(
            &alice_snapshot,
            key.clone(),
            outbound(0x59, b"untrusted domain", &sender.sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap()
        .message;

    let result = engine.decrypt_message_with_transport_bindings(
        &mut ChaCha20Rng::from_seed([0x59; 32]),
        &bob_snapshot,
        inbound_with_certificate_validation(
            key,
            deduplication_key,
            &encrypted,
            &acknowledgment_sender_identity,
            &domain_keys,
            &revoked,
        ),
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
    );

    assert!(matches!(
        result,
        Err(ProtocolStateError::SenderCertificateValidation(
            SenderCertificateValidationError::UntrustedSigningKeyId
        ))
    ));
}

#[test]
fn engine_rejects_certificate_grace_above_the_maximum() {
    let grace = MAX_CERTIFICATE_GRACE_WINDOW + Duration::from_millis(1);
    assert!(matches!(
        ProtocolStateEngine::new().with_certificate_grace(grace),
        Err(ProtocolStateError::SenderCertificateValidation(
            SenderCertificateValidationError::GraceWindowTooLarge { grace_window, max }
        )) if grace_window == grace && max == MAX_CERTIFICATE_GRACE_WINDOW
    ));
}

#[test]
fn expired_certificate_rejects_before_plaintext_is_surfaced() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let sender = validated_sender_for_contact_expires_at(
        accepted_contact_identity(),
        CERTIFICATE_REFERENCE_TIME_SECS - 1,
    );
    let domain_keys = [sender.domain_signing_key()];
    let revoked = [];
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender.sender_identity,
        deduplication_key.clone(),
    );
    let encrypted = engine
        .encrypt_message_with_transport_binding(
            &alice_snapshot,
            key.clone(),
            outbound(0x5a, b"expired domain", &sender.sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap()
        .message;

    let result = engine.decrypt_message_with_transport_bindings(
        &mut ChaCha20Rng::from_seed([0x5a; 32]),
        &bob_snapshot,
        inbound_with_certificate_validation(
            key,
            deduplication_key,
            &encrypted,
            &acknowledgment_sender_identity,
            &domain_keys,
            &revoked,
        ),
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
    );

    assert!(matches!(
        result,
        Err(ProtocolStateError::SenderCertificateValidation(
            SenderCertificateValidationError::ExpiredCertificate
        ))
    ));
}

#[test]
fn message_at_the_configured_grace_boundary_is_accepted() {
    let setup = setup();
    let engine = ProtocolStateEngine::new()
        .with_certificate_grace(MAX_CERTIFICATE_GRACE_WINDOW)
        .unwrap();
    let key = key();
    let deduplication_key = deduplication_key();
    let sender = validated_sender_for_contact_expires_at(
        accepted_contact_identity(),
        CERTIFICATE_REFERENCE_TIME_SECS - MAX_CERTIFICATE_GRACE_WINDOW.as_secs(),
    );
    let domain_keys = [sender.domain_signing_key()];
    let revoked = [];
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender.sender_identity,
        deduplication_key.clone(),
    );
    let encrypted = engine
        .encrypt_message_with_transport_binding(
            &alice_snapshot,
            key.clone(),
            outbound(
                0x5e,
                b"at the grace window boundary",
                &sender.sender_identity,
            ),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap()
        .message;
    let inbound = inbound_with_certificate_validation(
        key,
        deduplication_key,
        &encrypted,
        &acknowledgment_sender_identity,
        &domain_keys,
        &revoked,
    );
    let accepted = engine
        .decrypt_message_with_transport_bindings(
            &mut ChaCha20Rng::from_seed([0x5e; 32]),
            &bob_snapshot,
            inbound,
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .map(accepted)
        .unwrap();

    assert_eq!(
        accepted.plaintext.as_slice(),
        b"at the grace window boundary"
    );
}

#[test]
fn certificate_identity_key_must_match_bound_session_contact() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let sender =
        validated_sender_for_contact(contact_with_unrelated_identity_key_and_sender_discovery());
    let domain_keys = [sender.domain_signing_key()];
    let revoked = [];
    let alice = validated_sender();
    let alice_domain_keys = [alice.domain_signing_key()];
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let mut alice_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        key.clone(),
        &setup.alice_state,
        &sender.sender_identity,
        deduplication_key.clone(),
    );
    let mut bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        key.clone(),
        &setup.bob_state,
        &alice.sender_identity,
        deduplication_key.clone(),
    );
    let first = engine
        .encrypt_message_with_transport_binding(
            &alice_snapshot,
            key.clone(),
            outbound(0x57, b"bind alice contact session", &alice.sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap();
    alice_snapshot.apply_all(first.state_updates).unwrap();
    let decrypted = engine
        .decrypt_message_with_transport_bindings(
            &mut ChaCha20Rng::from_seed([0x57; 32]),
            &bob_snapshot,
            inbound_with_certificate_validation(
                key.clone(),
                deduplication_key.clone(),
                &first.message,
                &acknowledgment_sender_identity,
                &alice_domain_keys,
                &revoked,
            ),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .map(accepted)
        .unwrap();
    bob_snapshot.apply_all(decrypted.state_updates).unwrap();
    let reply = engine
        .encrypt_message_with_transport_binding(
            &bob_snapshot,
            key.clone(),
            outbound(0x58, b"mismatched certificate", &sender.sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap();
    bob_snapshot.apply_all(reply.state_updates).unwrap();

    assert!(matches!(
            engine.decrypt_message_with_transport_bindings(
                &mut ChaCha20Rng::from_seed([0x58; 32]),
                &alice_snapshot,
                inbound_with_certificate_validation(
                    key,
                    deduplication_key,
                    &reply.message,
                    &acknowledgment_sender_identity,
                    &domain_keys,
                    &revoked,
                ), &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(), &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
    ),
            Err(ProtocolStateError::InvalidMessage { reason })
                if reason == "sender certificate identity key does not match session contact"
        ));
}

#[test]
fn unblocked_contact_resumes_existing_session_without_new_handshake() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let sender = validated_sender();
    let domain_keys = [sender.domain_signing_key()];
    let revoked = [];
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let mut alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let mut bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender.sender_identity,
        deduplication_key.clone(),
    );
    block_contact(&engine, &mut bob_snapshot);
    let first = engine
        .encrypt_message_with_transport_binding(
            &alice_snapshot,
            key.clone(),
            outbound(0x56, b"blocked before unblock", &sender.sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap();
    alice_snapshot.apply_all(first.state_updates).unwrap();
    let blocked = engine
        .decrypt_message_with_transport_bindings(
            &mut ChaCha20Rng::from_seed([0x56; 32]),
            &bob_snapshot,
            inbound_with_certificate_validation(
                key.clone(),
                deduplication_key.clone(),
                &first.message,
                &acknowledgment_sender_identity,
                &domain_keys,
                &revoked,
            ),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .map(blocked)
        .unwrap();
    bob_snapshot.apply_all(blocked.state_updates).unwrap();
    let unblocked = engine
        .unblock_contact(&bob_snapshot, sender.contact.identity_key)
        .unwrap();
    bob_snapshot.apply_all(unblocked.state_updates).unwrap();
    let second = engine
        .encrypt_message_with_transport_binding(
            &alice_snapshot,
            key.clone(),
            outbound(0x57, b"after unblock", &sender.sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap();

    let accepted = engine
        .decrypt_message_with_transport_bindings(
            &mut ChaCha20Rng::from_seed([0x57; 32]),
            &bob_snapshot,
            inbound_with_certificate_validation(
                key,
                deduplication_key,
                &second.message,
                &acknowledgment_sender_identity,
                &domain_keys,
                &revoked,
            ),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .map(accepted)
        .unwrap();

    assert_eq!(accepted.plaintext.as_slice(), b"after unblock");
}

#[test]
fn in_band_messages_and_acknowledgments_do_not_verify_contact() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let sender = validated_sender();
    let domain_keys = [sender.domain_signing_key()];
    let revoked = [];
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let contact = accepted_contact_identity();
    let mut alice_snapshot = snapshot_with_state_and_peer_identity(
        &engine,
        key.clone(),
        &setup.alice_state,
        &acknowledgment_sender_identity,
    );
    let mut bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender.sender_identity,
        deduplication_key.clone(),
    );

    assert_eq!(
        engine
            .contact_state(&alice_snapshot, contact.identity_key)
            .unwrap()
            .unwrap()
            .trust_state,
        ContactTrustState::Unverified
    );

    let encrypted = engine
        .encrypt_message_with_transport_binding(
            &alice_snapshot,
            key.clone(),
            outbound(12, b"in band is not verification", &sender.sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap();
    alice_snapshot.apply_all(encrypted.state_updates).unwrap();
    let decrypted = engine
        .decrypt_message_with_transport_bindings(
            &mut ChaCha20Rng::from_seed([23u8; 32]),
            &bob_snapshot,
            inbound_with_certificate_validation(
                key.clone(),
                deduplication_key,
                &encrypted.message,
                &acknowledgment_sender_identity,
                &domain_keys,
                &revoked,
            ),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .map(accepted)
        .unwrap();
    bob_snapshot.apply_all(decrypted.state_updates).unwrap();

    assert_eq!(
        engine
            .contact_state(&bob_snapshot, contact.identity_key)
            .unwrap()
            .unwrap()
            .trust_state,
        ContactTrustState::Unverified
    );

    let cleared = engine
        .process_acknowledgment_with_transport_binding(
            &mut ChaCha20Rng::from_seed([24u8; 32]),
            &alice_snapshot,
            inbound_acknowledgment(key, &decrypted.acknowledgment),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap();
    let AcknowledgmentOutcome::Cleared(cleared) = cleared else {
        panic!("acknowledgment did not clear pending state");
    };
    alice_snapshot.apply_all(cleared.state_updates).unwrap();

    assert_eq!(
        engine
            .contact_state(&alice_snapshot, contact.identity_key)
            .unwrap()
            .unwrap()
            .trust_state,
        ContactTrustState::Unverified
    );
}

#[test]
fn deduplication_receive_rejects_bad_state_and_capacity() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let deduplication_address = deduplication_address(deduplication_key.clone());
    let sender_identity = sender_identity(0xa1);
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let encrypted = engine
        .encrypt_message_with_transport_binding(
            &alice_snapshot,
            key.clone(),
            outbound(12, b"bad dedup state", &sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap()
        .message;

    let missing_snapshot = snapshot_with_state_and_peer_identity(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender_identity,
    );
    assert!(matches!(
            engine.decrypt_message_with_transport_bindings(
                &mut ChaCha20Rng::from_seed([23u8; 32]),
                &missing_snapshot,
                inbound(
                    key.clone(),
                    deduplication_key.clone(),
                    &encrypted,
                    &acknowledgment_sender_identity,
                ), &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(), &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
    ),
            Err(ProtocolStateError::MissingRequiredState { address }) if address == deduplication_address
        ));

    let mut corrupt_snapshot = snapshot_with_state_and_peer_identity(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender_identity,
    );
    corrupt_snapshot
        .set(
            deduplication_address.clone(),
            ProtocolStateBlob::from_bytes(vec![1, 0, 0xaa]),
        )
        .unwrap();
    assert!(matches!(
            engine.decrypt_message_with_transport_bindings(
                &mut ChaCha20Rng::from_seed([24u8; 32]),
                &corrupt_snapshot,
                inbound(
                    key.clone(),
                    deduplication_key.clone(),
                    &encrypted,
                    &acknowledgment_sender_identity,
                ), &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(), &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
    ),
            Err(ProtocolStateError::BlobDecode { address, .. }) if address == deduplication_address
        ));

    let mut unsupported_snapshot = snapshot_with_state_and_peer_identity(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender_identity,
    );
    unsupported_snapshot
        .set(
            deduplication_address.clone(),
            ProtocolStateBlob::from_bytes(vec![2, 0, 0xaa]),
        )
        .unwrap();
    assert!(matches!(
            engine.decrypt_message_with_transport_bindings(
                &mut ChaCha20Rng::from_seed([25u8; 32]),
                &unsupported_snapshot,
                inbound(key, deduplication_key, &encrypted, &acknowledgment_sender_identity), &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(), &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
    ),
            Err(ProtocolStateError::UnsupportedBlobVersion {
                address,
                major: 2,
                minor: 0
            }) if address == deduplication_address
        ));

    assert!(matches!(
        ProtocolStateEngine::with_deduplication_capacity(MIN_DEDUPLICATION_CAPACITY - 1),
        Err(ProtocolStateError::InvalidDeduplicationCapacity { capacity, .. })
            if capacity == MIN_DEDUPLICATION_CAPACITY - 1
    ));
    assert!(matches!(
        ProtocolStateEngine::with_deduplication_capacity(MAX_DEDUPLICATION_CAPACITY + 1),
        Err(ProtocolStateError::InvalidDeduplicationCapacity { capacity, .. })
            if capacity == MAX_DEDUPLICATION_CAPACITY + 1
    ));
}

#[test]
fn deduplication_capacity_evicts_oldest_digest_first() {
    let setup = setup();
    let engine =
        ProtocolStateEngine::with_deduplication_capacity(MIN_DEDUPLICATION_CAPACITY).unwrap();
    let key = key();
    let deduplication_key = deduplication_key();
    let sender = validated_sender();
    let domain_keys = [sender.domain_signing_key()];
    let revoked = [];
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let mut alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let mut bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender.sender_identity,
        deduplication_key.clone(),
    );
    let mut first_message = None;

    for index in 0..=MIN_DEDUPLICATION_CAPACITY {
        let encrypted = engine
            .encrypt_message_with_transport_binding(
                &alice_snapshot,
                key.clone(),
                outbound(index as u8, b"fills window", &sender.sender_identity),
                &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            )
            .unwrap();
        let message = encrypted.message;
        alice_snapshot.apply_all(encrypted.state_updates).unwrap();
        if index == 0 {
            first_message = Some(copy_message(&message));
        }
        let decrypted = engine
            .decrypt_message_with_transport_bindings(
                &mut ChaCha20Rng::from_seed([26u8; 32]),
                &bob_snapshot,
                inbound_with_certificate_validation(
                    key.clone(),
                    deduplication_key.clone(),
                    &message,
                    &acknowledgment_sender_identity,
                    &domain_keys,
                    &revoked,
                ),
                &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
                &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            )
            .map(accepted)
            .unwrap();
        bob_snapshot.apply_all(decrypted.state_updates).unwrap();
    }

    let result = engine.decrypt_message_with_transport_bindings(
        &mut ChaCha20Rng::from_seed([27u8; 32]),
        &bob_snapshot,
        inbound(
            key,
            deduplication_key,
            &first_message.unwrap(),
            &acknowledgment_sender_identity,
        ),
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
    );

    assert!(matches!(result, Err(ProtocolStateError::Ratchet(_))));
}

#[test]
fn set_session_state_with_peer_identity_key_allows_key_only_install() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let sender = validated_sender();
    let domain_keys = [sender.domain_signing_key()];
    let revoked = [];
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let mut bob_snapshot = ProtocolStateSnapshot::new();
    bob_snapshot
        .apply(
            engine
                .set_session_state_with_peer_identity_key(
                    key.clone(),
                    &setup.bob_state,
                    sender.sender_identity.identity_key,
                )
                .unwrap(),
        )
        .unwrap();
    install_deduplication_set(&engine, &mut bob_snapshot, deduplication_key.clone(), 0x44);

    let encrypted = engine
        .encrypt_message_with_transport_binding(
            &alice_snapshot,
            key.clone(),
            outbound(7, b"key-only install", &sender.sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap()
        .message;

    let decrypted = engine
        .decrypt_message_with_transport_bindings(
            &mut ChaCha20Rng::from_seed([18u8; 32]),
            &bob_snapshot,
            inbound_with_certificate_validation(
                key,
                deduplication_key,
                &encrypted,
                &acknowledgment_sender_identity,
                &domain_keys,
                &revoked,
            ),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .map(accepted)
        .unwrap();

    assert_eq!(decrypted.plaintext.as_slice(), b"key-only install");
    assert_eq!(
        decrypted.sender_identity.identity_key,
        sender.sender_identity.identity_key
    );
}

#[test]
fn bind_session_state_peer_identity_key_allows_existing_blob_to_decrypt() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let sender = validated_sender();
    let domain_keys = [sender.domain_signing_key()];
    let revoked = [];
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let mut bob_snapshot = snapshot_with_state(&engine, key.clone(), &setup.bob_state);
    let address = ratchet_address(key.clone());
    let unbound_blob = bob_snapshot.get(&address).unwrap().as_bytes().to_vec();

    let bind_update = engine
        .bind_session_state_peer_identity_key(
            &bob_snapshot,
            key.clone(),
            sender.sender_identity.identity_key,
        )
        .unwrap();
    assert_eq!(bind_update.address(), &address);
    assert_ne!(bind_update.blob().unwrap().as_bytes(), unbound_blob);
    bob_snapshot.apply(bind_update).unwrap();
    install_deduplication_set(&engine, &mut bob_snapshot, deduplication_key.clone(), 0x44);

    let encrypted = engine
        .encrypt_message_with_transport_binding(
            &alice_snapshot,
            key.clone(),
            outbound(2, b"bound by key", &sender.sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap()
        .message;

    let decrypted = engine
        .decrypt_message_with_transport_bindings(
            &mut ChaCha20Rng::from_seed([17u8; 32]),
            &bob_snapshot,
            inbound_with_certificate_validation(
                key,
                deduplication_key,
                &encrypted,
                &acknowledgment_sender_identity,
                &domain_keys,
                &revoked,
            ),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .map(accepted)
        .unwrap();

    assert_eq!(decrypted.plaintext.as_slice(), b"bound by key");
    assert_eq!(
        decrypted.sender_identity.identity_key,
        sender.sender_identity.identity_key
    );
    assert_eq!(
        decrypted.sender_identity.certificate,
        sender.sender_identity.certificate
    );
    assert_eq!(
        decrypted.sender_identity.signature,
        sender.sender_identity.signature
    );
}

#[test]
fn bind_session_state_peer_identity_key_rejects_mismatched_rebind() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let bound_sender_identity = sender_identity(0xa1);
    let other_sender_identity = sender_identity(0xb1);
    let snapshot = snapshot_with_state_and_peer_identity(
        &engine,
        key.clone(),
        &setup.bob_state,
        &bound_sender_identity,
    );
    let address = ratchet_address(key.clone());

    let result = engine.bind_session_state_peer_identity_key(
        &snapshot,
        key,
        other_sender_identity.identity_key,
    );

    assert!(matches!(
        result,
        Err(ProtocolStateError::InvalidStateBinding { address: actual, .. }) if actual == address
    ));
}

#[test]
fn decrypt_rejects_sender_identity_that_is_not_bound_to_session() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let expected_sender_identity = sender_identity(0xa1);
    let actual_sender_identity = sender_identity(0xb1);
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let mut bob_snapshot = ProtocolStateSnapshot::new();
    bob_snapshot
        .apply(
            engine
                .set_session_state_with_peer_identity(
                    key.clone(),
                    &setup.bob_state,
                    &expected_sender_identity,
                )
                .unwrap(),
        )
        .unwrap();
    install_deduplication_set(&engine, &mut bob_snapshot, deduplication_key.clone(), 0x44);

    let encrypted = engine
        .encrypt_message_with_transport_binding(
            &alice_snapshot,
            key.clone(),
            {
                let contact = accepted_contact_identity();
                OutboundPlaintext {
                    id: MessageId::from_bytes([9; 16]),
                    sender_identity: &actual_sender_identity,
                    sender_identity_signing_key: sender_identity_signing_key(
                        &actual_sender_identity,
                    ),
                    contact_identity_key: contact.identity_key,
                    recipient_public_key: contact.discovery_key.prekey_bundle_lookup_key(),
                    sent_at_millis: 1_700_000_000_999,
                    plaintext: b"wrong sender",
                }
            },
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap();

    let result = engine.decrypt_message_with_transport_bindings(
        &mut ChaCha20Rng::from_seed([15u8; 32]),
        &bob_snapshot,
        inbound(
            key,
            deduplication_key,
            &encrypted.message,
            &acknowledgment_sender_identity,
        ),
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
    );

    assert!(matches!(
        result,
        Err(ProtocolStateError::InvalidMessage { .. })
    ));
}

#[test]
fn tampered_ciphertext_exposes_no_sender_identity() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let sender_identity = sender_identity(1);
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender_identity,
        deduplication_key.clone(),
    );
    let mut encrypted = engine
        .encrypt_message_with_transport_binding(
            &alice_snapshot,
            key.clone(),
            outbound(3, b"secret", &sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap()
        .message;
    let last = encrypted.ciphertext.last_mut().unwrap();
    *last ^= 0x01;

    let result = engine.decrypt_message_with_transport_bindings(
        &mut ChaCha20Rng::from_seed([13u8; 32]),
        &bob_snapshot,
        inbound(
            key,
            deduplication_key,
            &encrypted,
            &acknowledgment_sender_identity,
        ),
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
    );

    assert!(matches!(result, Err(ProtocolStateError::SealedFrame(_))));
}

#[test]
fn tampered_transport_metadata_exposes_no_sender_identity() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let sender_identity = sender_identity(1);
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender_identity,
        deduplication_key.clone(),
    );
    let encrypted = engine
        .encrypt_message_with_transport_binding(
            &alice_snapshot,
            key.clone(),
            outbound(5, b"metadata-bound", &sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap()
        .message;

    let mut wrong_recipient = copy_message(&encrypted);
    wrong_recipient.recipient_public_key = *acknowledgment_recipient_discovery_key()
        .public_key()
        .as_bytes();
    let mut wrong_ephemeral = copy_message(&encrypted);
    wrong_ephemeral.ephemeral_public_key =
        *KeyPair::from_secret_bytes([0x55; 32]).public.as_bytes();
    for message in [wrong_recipient, wrong_ephemeral] {
        let result = engine.decrypt_message_with_transport_bindings(
            &mut ChaCha20Rng::from_seed([16u8; 32]),
            &bob_snapshot,
            inbound(
                key.clone(),
                deduplication_key.clone(),
                &message,
                &acknowledgment_sender_identity,
            ),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        );
        assert!(matches!(result, Err(ProtocolStateError::SealedFrame(_))));
    }
}

#[test]
fn message_transcript_signature_rejects_session_key_transplant() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let other_key = ProtocolStateKey::session(SessionId::from_bytes([0x19; 16]));
    let deduplication_key = deduplication_key();
    let sender_identity = sender_identity(1);
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        other_key.clone(),
        &setup.bob_state,
        &sender_identity,
        deduplication_key.clone(),
    );

    let encrypted = engine
        .encrypt_message_with_transport_binding(
            &alice_snapshot,
            key,
            outbound(0x19, b"wrong session key", &sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap()
        .message;

    let result = engine.decrypt_message_with_transport_bindings(
        &mut ChaCha20Rng::from_seed([0x19; 32]),
        &bob_snapshot,
        inbound(
            other_key,
            deduplication_key,
            &encrypted,
            &acknowledgment_sender_identity,
        ),
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
    );

    assert!(matches!(result, Err(ProtocolStateError::Ratchet(_))));
}

#[test]
fn decrypt_message_rejects_recipient_identity_discovery_mismatch() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let sender_identity = sender_identity(1);
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender_identity,
        deduplication_key.clone(),
    );
    let encrypted = engine
        .encrypt_message_with_transport_binding(
            &alice_snapshot,
            key.clone(),
            outbound(0x1a, b"wrong recipient identity", &sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap()
        .message;
    let mut inbound = inbound(
        key,
        deduplication_key,
        &encrypted,
        &acknowledgment_sender_identity,
    );
    inbound.recipient_identity_verifying_key = SigningKeyPair::from_signing_bytes([0x44; 32])
        .verifying
        .to_bytes();

    let result = engine.decrypt_message_with_transport_bindings(
        &mut ChaCha20Rng::from_seed([0x1a; 32]),
        &bob_snapshot,
        inbound,
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
    );

    assert!(matches!(
        result,
        Err(ProtocolStateError::InvalidMessage { reason })
            if reason == "recipient discovery key does not match recipient identity key"
    ));
}

#[test]
fn decrypt_message_rejects_noncanonical_recipient_identity_key() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let sender_identity = sender_identity(1);
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender_identity,
        deduplication_key.clone(),
    );
    let encrypted = engine
        .encrypt_message_with_transport_binding(
            &alice_snapshot,
            key.clone(),
            outbound(0x1b, b"invalid recipient identity", &sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap()
        .message;
    let mut inbound = inbound(
        key,
        deduplication_key,
        &encrypted,
        &acknowledgment_sender_identity,
    );
    inbound.recipient_identity_verifying_key = [0xff; 32];

    let result = engine.decrypt_message_with_transport_bindings(
        &mut ChaCha20Rng::from_seed([0x1b; 32]),
        &bob_snapshot,
        inbound,
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
    );

    assert!(matches!(
        result,
        Err(ProtocolStateError::InvalidMessage { reason })
            if reason == "recipient identity verifying key is not canonical"
    ));
}

#[test]
fn acknowledgment_transcript_signature_rejects_session_key_transplant() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let other_key = ProtocolStateKey::session(SessionId::from_bytes([0x1a; 16]));
    let deduplication_key = deduplication_key();
    let sender = validated_sender_for_contact(accepted_contact_identity());
    let domain_keys = [sender.domain_signing_key()];
    let revoked = [];
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let mut alice_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender.sender_identity,
        deduplication_key.clone(),
    );

    let encrypted = engine
        .encrypt_message_with_transport_binding(
            &alice_snapshot,
            key.clone(),
            outbound(0x1a, b"ack wrong session key", &sender.sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap();
    for update in encrypted.state_updates {
        alice_snapshot
            .set(
                ProtocolStateAddress::new(update.address().kind(), other_key.clone()),
                ProtocolStateBlob::from_bytes(update.blob().unwrap().as_bytes().to_vec()),
            )
            .unwrap();
    }
    let decrypted = engine
        .decrypt_message_with_transport_bindings(
            &mut ChaCha20Rng::from_seed([0x1a; 32]),
            &bob_snapshot,
            inbound_with_certificate_validation(
                key,
                deduplication_key,
                &encrypted.message,
                &acknowledgment_sender_identity,
                &domain_keys,
                &revoked,
            ),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .map(accepted)
        .unwrap();
    let bound = engine
        .bind_session_state_peer_identity_key(
            &alice_snapshot,
            other_key.clone(),
            acknowledgment_sender_identity.identity_key,
        )
        .unwrap();
    alice_snapshot.apply(bound).unwrap();

    let result = engine.process_acknowledgment_with_transport_binding(
        &mut ChaCha20Rng::from_seed([0x1b; 32]),
        &alice_snapshot,
        InboundAcknowledgmentMessage {
            session_key: other_key,
            message: &decrypted.acknowledgment,
            recipient_discovery_key: acknowledgment_recipient_discovery_key_ref(),
            recipient_identity_verifying_key: accepted_contact_identity()
                .identity_key
                .ed25519_verifying_key,
        },
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
    );

    assert!(matches!(result, Err(ProtocolStateError::Ratchet(_))));
}

#[test]
fn process_acknowledgment_rejects_recipient_identity_discovery_mismatch() {
    let (engine, key, snapshot, acknowledgment) = acknowledgment_processing_setup(0x1c);
    let mut inbound = inbound_acknowledgment(key, &acknowledgment);
    inbound.recipient_identity_verifying_key = SigningKeyPair::from_signing_bytes([0x44; 32])
        .verifying
        .to_bytes();

    let result = engine.process_acknowledgment_with_transport_binding(
        &mut ChaCha20Rng::from_seed([0x1c; 32]),
        &snapshot,
        inbound,
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
    );

    assert!(matches!(
        result,
        Err(ProtocolStateError::InvalidMessage { reason })
            if reason == "recipient discovery key does not match recipient identity key"
    ));
}

#[test]
fn process_acknowledgment_rejects_noncanonical_recipient_identity_key() {
    let (engine, key, snapshot, acknowledgment) = acknowledgment_processing_setup(0x1d);
    let mut inbound = inbound_acknowledgment(key, &acknowledgment);
    inbound.recipient_identity_verifying_key = [0xff; 32];

    let result = engine.process_acknowledgment_with_transport_binding(
        &mut ChaCha20Rng::from_seed([0x1d; 32]),
        &snapshot,
        inbound,
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
    );

    assert!(matches!(
        result,
        Err(ProtocolStateError::InvalidMessage { reason })
            if reason == "recipient identity verifying key is not canonical"
    ));
}

#[test]
fn malformed_sealed_sender_envelope_is_rejected() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let mut alice_state = setup.alice_state;
    let sender_identity = sender_identity(1);
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender_identity,
        deduplication_key.clone(),
    );
    let recipient_public_key = accepted_contact_identity()
        .discovery_key
        .prekey_bundle_lookup_key();
    let associated_data = ratchet_associated_data(&key, &recipient_public_key);
    let (header, ciphertext) = alice_state
        .ratchet_encrypt(b"not a sealed-sender envelope", &associated_data)
        .unwrap();
    let ratcheted_payload = ratcheted_payload(&header, &ciphertext);
    let frame_plaintext = message_frame_plaintext(
        MessageId::from_bytes([4; 16]),
        1_700_000_000_444,
        PayloadKind::EncryptedText,
        &ratcheted_payload,
    );
    let mut rng = ChaCha20Rng::from_seed([0x14; 32]);
    let frame = seal_frame_with_associated_data(
        &mut rng,
        &PublicKey::from(recipient_public_key),
        None,
        &frame_plaintext,
        b"test-route",
    )
    .unwrap();
    let message = Message {
        version: frame.version,
        recipient_public_key: frame.recipient_public_key,
        prekey_reference: frame.prekey_reference,
        ephemeral_public_key: frame.ephemeral_public_key,
        ciphertext: frame.ciphertext,
    };

    let result = engine.decrypt_message_with_transport_bindings(
        &mut ChaCha20Rng::from_seed([14u8; 32]),
        &bob_snapshot,
        inbound(
            key,
            deduplication_key,
            &message,
            &acknowledgment_sender_identity,
        ),
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
    );

    assert!(matches!(
        result,
        Err(ProtocolStateError::InvalidMessage { .. })
    ));
}

#[test]
fn large_valid_outbound_message_persists_pending_acknowledgment() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let mut snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let sender_identity = sender_identity(1);
    let large_plaintext = vec![0u8; 65_180];

    let result = engine
        .encrypt_message_with_transport_binding(
            &snapshot,
            key.clone(),
            outbound(1, &large_plaintext, &sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap();
    assert!(result.message.to_bytes().unwrap().len() > 64 * 1024);
    let message_id = result.message_id;
    snapshot.apply_all(result.state_updates).unwrap();

    let pending = engine.pending_acknowledgments(&snapshot, key).unwrap();

    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].message_id, message_id);
}

#[test]
fn oversized_outbound_message_does_not_return_advanced_state() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let address = ratchet_address(key.clone());
    let prior_blob = snapshot.get(&address).unwrap().as_bytes().to_vec();
    let oversized_plaintext = vec![0u8; 64 * 1024];
    let sender_identity = sender_identity(1);

    let result = engine.encrypt_message_with_transport_binding(
        &snapshot,
        key,
        outbound(1, &oversized_plaintext, &sender_identity),
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
    );

    assert!(matches!(
        result,
        Err(ProtocolStateError::InvalidMessage { .. })
    ));
    assert_eq!(snapshot.get(&address).unwrap().as_bytes(), prior_blob);
}

#[test]
fn wipe_removes_all_state_kinds_for_key() {
    let engine = ProtocolStateEngine::new();
    let key = key();
    let mut snapshot = ProtocolStateSnapshot::new();
    let active_kinds = [
        ProtocolStateKind::RatchetSession,
        ProtocolStateKind::DeduplicationSet,
        ProtocolStateKind::PendingAcknowledgments,
        ProtocolStateKind::ContactState,
        // Wiping must clear a peer's delivery capability too: leaving one behind after session
        // replacement would keep a stale bearer secret on disk with nothing left that uses it.
        ProtocolStateKind::PeerInboxAuthorization,
        ProtocolStateKind::LocalInboxAuthorization,
    ];
    assert_eq!(ProtocolStateKind::all(), active_kinds.as_slice());

    for kind in active_kinds {
        snapshot
            .set(
                ProtocolStateAddress::new(kind, key.clone()),
                ProtocolStateBlob::from_bytes(vec![kind as u8, 7]),
            )
            .unwrap();
    }

    let updates = engine.wipe(&snapshot, key.clone());
    assert_eq!(
        updates
            .iter()
            .map(|update| update.address().kind())
            .collect::<Vec<_>>(),
        active_kinds
    );
    snapshot.apply_all(updates).unwrap();

    for kind in active_kinds {
        assert!(
            snapshot
                .get(&ProtocolStateAddress::new(kind, key.clone()))
                .is_none()
        );
    }
}

#[test]
fn oversized_ratchet_blob_is_a_decode_fault_before_restore() {
    let engine = ProtocolStateEngine::new();
    let key = key();
    let address = ratchet_address(key.clone());
    let sender_identity = sender_identity(1);
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot
        .set(
            address.clone(),
            ProtocolStateBlob::from_bytes(vec![1; 128 * 1024]),
        )
        .unwrap();
    install_accepted_contact(&engine, &mut snapshot);

    assert!(matches!(
            engine.encrypt_message_with_transport_binding(&snapshot, key, outbound(1, b"lost", &sender_identity), &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
    ),
            Err(ProtocolStateError::BlobDecode { address: actual, .. }) if actual == address
        ));
}

#[test]
fn corrupt_ratchet_blob_does_not_silently_reinitialize_state() {
    let engine = ProtocolStateEngine::new();
    let key = key();
    let address = ratchet_address(key.clone());
    let sender_identity = sender_identity(1);
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot
        .set(
            address.clone(),
            ProtocolStateBlob::from_bytes(vec![1, 0, 0xaa]),
        )
        .unwrap();
    install_accepted_contact(&engine, &mut snapshot);

    let result = engine.encrypt_message_with_transport_binding(
        &snapshot,
        key,
        outbound(1, b"lost", &sender_identity),
        &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
    );

    assert!(matches!(result, Err(ProtocolStateError::BlobDecode { .. })));
    assert_eq!(snapshot.get(&address).unwrap().as_bytes(), &[1, 0, 0xaa]);
}

#[test]
fn missing_required_state_is_an_explicit_failure() {
    let engine = ProtocolStateEngine::new();
    let key = key();
    let address = ratchet_address(key.clone());
    let sender_identity = sender_identity(1);
    let mut snapshot = ProtocolStateSnapshot::new();
    install_accepted_contact(&engine, &mut snapshot);

    assert!(matches!(
            engine.encrypt_message_with_transport_binding(&snapshot, key, outbound(1, b"lost", &sender_identity), &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
    ),
            Err(ProtocolStateError::MissingRequiredState { address: actual }) if actual == address
        ));
}

#[test]
fn after_wipe_session_operation_requires_explicit_restore() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let mut snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    let sender_identity = sender_identity(1);
    snapshot
        .apply_all(engine.wipe(&snapshot, key.clone()))
        .unwrap();

    assert!(matches!(
        engine.encrypt_message_with_transport_binding(
            &snapshot,
            key.clone(),
            outbound(1, b"after wipe", &sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        ),
        Err(ProtocolStateError::MissingRequiredState { .. })
    ));

    snapshot
        .apply(
            engine
                .set_session_state(key.clone(), &setup.alice_state)
                .unwrap(),
        )
        .unwrap();
    install_pending_acknowledgments(&engine, &mut snapshot, key.clone());
    let result = engine
        .encrypt_message_with_transport_binding(
            &snapshot,
            key,
            outbound(2, b"restored", &sender_identity),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap();
    assert_eq!(result.payload_kind, PayloadKind::EncryptedText);
}
