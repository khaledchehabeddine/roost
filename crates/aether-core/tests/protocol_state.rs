//! Exercises the public protocol-state API over consumer-held opaque blobs.

use aether_core::{
    AcknowledgmentOutcome, ContactDiscoveryKey, ContactIdentity, ContactIdentityKey,
    ContactTrustState, DomainSigningKey, DomainSigningKeyStatus, InboundAcknowledgmentMessage,
    InboundEncryptedMessage, InboundMessageOutcome, InboundSenderCertificateValidation,
    MAX_DEDUPLICATION_CAPACITY, MIN_DEDUPLICATION_CAPACITY, Message, MessageId,
    OutboundAcknowledgment, OutboundPlaintext, PayloadKind, ProtocolStateAddress,
    ProtocolStateBlob, ProtocolStateEngine, ProtocolStateError, ProtocolStateKey,
    ProtocolStateKind, ProtocolStateSnapshot, RevocationState, SenderCertificateIdentityKey,
    SenderCertificateValidationError, SenderIdentityMaterial, SessionEvent, SessionId,
    SessionUnrecoverableReason, SessionUnrecoverableResult,
};
use aether_crypto::{
    CryptoError, DiscoveryKey, Header, IdentityKeyBundle, InitialPlaintext, KeyPair, PreKeyBundle,
    PublicKey, RatchetState, SealedFramePreKeyReference, SigningKeyPair, accept,
    generate_discovery_key, generate_key_pair, generate_one_time_prekey,
    generate_signed_prekey_for_discovery_key, generate_signing_key_pair, initiate, seal_frame,
    sign_identity_key_binding,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};

const CREATED_AT: u64 = 1_700_000_000;
const CERTIFICATE_DOMAIN_TAG: &[u8] = b"AetherSenderCertificate-v1:";
const CERTIFICATE_VERSION: u8 = 1;
const CERTIFICATE_EXPIRES_AT: u64 = 1_700_100_000;
const CERTIFICATE_REFERENCE_TIME: u64 = 1_700_000_000;

struct Setup {
    alice_state: RatchetState,
    bob_state: RatchetState,
}

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
    first_sent_millis: u64,
    last_retry_millis: Option<u64>,
}

fn setup() -> Setup {
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
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
        &alice_identity_key,
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
    let discovery_key = generate_discovery_key(&mut rng, identity, 0, CREATED_AT);
    let rotated_discovery_key = generate_discovery_key(&mut rng, identity, 1, CREATED_AT + 60);
    let identity_key = ContactIdentityKey {
        x25519_public_key: *identity_key_pair.public.as_bytes(),
        ed25519_verifying_key: identity.verifying.to_bytes(),
    };
    (
        ContactIdentity {
            identity_key,
            discovery_key: ContactDiscoveryKey::from(&discovery_key.bundle()),
        },
        ContactIdentity {
            identity_key,
            discovery_key: ContactDiscoveryKey::from(&rotated_discovery_key.bundle()),
        },
    )
}

fn accepted_contact_identity() -> ContactIdentity {
    contact_identities().0
}

fn accepted_contact_discovery_key() -> DiscoveryKey {
    let identity = test_sender_identity_signing_key(0xa1);
    let mut rng = ChaCha20Rng::from_seed([0x71; 32]);
    generate_discovery_key(&mut rng, identity, 0, CREATED_AT)
}

fn accepted_contact_discovery_key_ref() -> &'static DiscoveryKey {
    Box::leak(Box::new(accepted_contact_discovery_key()))
}

fn rotated_contact_identity() -> ContactIdentity {
    contact_identities().1
}

fn acknowledgment_recipient_discovery_key() -> DiscoveryKey {
    DiscoveryKey::from_secret_bytes([0xc2; 32], [0xc3; 32], 0, CREATED_AT, [0u8; 64])
}

fn acknowledgment_recipient_discovery_key_ref() -> &'static DiscoveryKey {
    Box::leak(Box::new(acknowledgment_recipient_discovery_key()))
}

struct ValidatedSender {
    contact: ContactIdentity,
    sender_identity: SenderIdentityMaterial,
    domain_identifier: Vec<u8>,
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
            identifier: &self.domain_identifier,
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
    let domain_identifier = b"test-domain".to_vec();
    let certificate = sender_certificate_bytes(&domain_identifier, contact, expires_at_secs);
    let signature = domain_signing_key.sign(&certificate).to_bytes().to_vec();
    ValidatedSender {
        contact,
        sender_identity: sender_identity_for_contact(
            contact,
            certificate.clone(),
            signature.clone(),
        ),
        domain_identifier,
        domain_verifying_key: domain_signing_key.verifying.to_bytes().to_vec(),
    }
}

fn alternate_contact_identity() -> ContactIdentity {
    let identity = test_sender_identity_signing_key(0x77);
    let identity_key_pair = test_identity_key_pair(0x77);
    let mut rng = ChaCha20Rng::from_seed([0x73; 32]);
    let discovery_key = generate_discovery_key(&mut rng, identity, 0, CREATED_AT);
    ContactIdentity {
        identity_key: ContactIdentityKey {
            x25519_public_key: *identity_key_pair.public.as_bytes(),
            ed25519_verifying_key: identity.verifying.to_bytes(),
        },
        discovery_key: ContactDiscoveryKey::from(&discovery_key.bundle()),
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
    signing_key_identifier: &[u8],
    contact: ContactIdentity,
    expires_at_secs: u64,
) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(CERTIFICATE_DOMAIN_TAG);
    bytes.push(CERTIFICATE_VERSION);
    bytes.push(signing_key_identifier.len() as u8);
    bytes.extend_from_slice(signing_key_identifier);
    bytes.extend_from_slice(&contact.identity_key.x25519_public_key);
    bytes.extend_from_slice(&contact.identity_key.ed25519_verifying_key);
    bytes.extend_from_slice(&contact.discovery_key.x25519_public_key);
    bytes.extend_from_slice(&contact.discovery_key.ed25519_verifying_key);
    bytes.extend_from_slice(&contact.discovery_key.epoch.to_be_bytes());
    bytes.extend_from_slice(&expires_at_secs.to_be_bytes());
    bytes
}

fn sender_certificate_validation<'a>(
    domain_signing_keys: &'a [DomainSigningKey<'a>],
    revocation_state: RevocationState<'a>,
) -> InboundSenderCertificateValidation<'a> {
    InboundSenderCertificateValidation {
        domain_signing_keys,
        revocation_state,
        reference_timestamp_secs: CERTIFICATE_REFERENCE_TIME,
        grace_window_secs: 0,
    }
}

fn inbound_with_certificate_validation<'a>(
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

fn block_contact(engine: &ProtocolStateEngine, snapshot: &mut ProtocolStateSnapshot) {
    let contact = accepted_contact_identity();
    let blocked = engine
        .block_contact(snapshot, contact.identity_key)
        .unwrap();
    snapshot.apply_all(blocked.state_updates);
}

fn rotate_blocked_contact(engine: &ProtocolStateEngine, snapshot: &mut ProtocolStateSnapshot) {
    let rotated = engine
        .record_contact(snapshot, rotated_contact_identity())
        .unwrap();
    snapshot.apply_all(rotated.state_updates);
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
    snapshot.apply_all(created.state_updates);
    let accepted = engine
        .accept_contact(snapshot, contact.identity_key)
        .unwrap();
    snapshot.apply_all(accepted.state_updates);
}

fn snapshot_with_state(
    engine: &ProtocolStateEngine,
    key: ProtocolStateKey,
    state: &RatchetState,
) -> ProtocolStateSnapshot {
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot.apply(engine.set_session_state(key.clone(), state).unwrap());
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
    snapshot.apply(
        engine
            .initialize_deduplication_set(&mut ChaCha20Rng::from_seed([seed; 32]), key)
            .unwrap(),
    );
}

fn install_pending_acknowledgments(
    engine: &ProtocolStateEngine,
    snapshot: &mut ProtocolStateSnapshot,
    key: ProtocolStateKey,
) {
    snapshot.apply(engine.initialize_pending_acknowledgments(key).unwrap());
}

fn snapshot_with_state_and_peer_identity(
    engine: &ProtocolStateEngine,
    key: ProtocolStateKey,
    state: &RatchetState,
    peer_sender_identity: &SenderIdentityMaterial,
) -> ProtocolStateSnapshot {
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot.apply(
        engine
            .set_session_state_with_peer_identity(key.clone(), state, peer_sender_identity)
            .unwrap(),
    );
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

fn outbound<'a>(
    id: u8,
    plaintext: &'a [u8],
    sender_identity: &'a SenderIdentityMaterial,
) -> OutboundPlaintext<'a> {
    let contact = accepted_contact_identity();
    OutboundPlaintext {
        id: MessageId::from_bytes([id; 16]),
        sender_identity,
        sender_identity_signing_key: sender_identity_signing_key(sender_identity),
        contact_identity_key: contact.identity_key,
        recipient_public_key: contact.discovery_key.prekey_bundle_lookup_key(),
        timestamp_millis: 1_700_000_000_123 + u64::from(id),
        plaintext,
    }
}

fn sequenced_outbound<'a>(
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

fn acknowledgment_sender_identity() -> SenderIdentityMaterial {
    sender_identity(0xb1)
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

fn inbound<'a>(
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

fn remap_session_updates(
    updates: Vec<aether_core::ProtocolStateUpdate>,
    key: ProtocolStateKey,
) -> Vec<aether_core::ProtocolStateUpdate> {
    updates
        .into_iter()
        .map(|update| {
            let kind = update.address().kind();
            let address = match kind {
                ProtocolStateKind::RatchetSession | ProtocolStateKind::PendingAcknowledgments => {
                    ProtocolStateAddress::new(kind, key.clone())
                }
                _ => update.address().clone(),
            };
            match update.blob() {
                Some(blob) => aether_core::ProtocolStateUpdate::set(
                    address,
                    ProtocolStateBlob::from_bytes(blob.as_bytes().to_vec()),
                ),
                None => aether_core::ProtocolStateUpdate::delete(address),
            }
        })
        .collect()
}

fn inbound_acknowledgment<'a>(
    session_key: ProtocolStateKey,
    message: &'a Message,
) -> InboundAcknowledgmentMessage<'a> {
    InboundAcknowledgmentMessage {
        session_key,
        message,
        recipient_discovery_key: acknowledgment_recipient_discovery_key_ref(),
    }
}

fn accepted(outcome: InboundMessageOutcome) -> aether_core::InboundMessageResult {
    match outcome {
        InboundMessageOutcome::Accepted(result) => *result,
        InboundMessageOutcome::Blocked(_) => panic!("message was unexpectedly blocked"),
        InboundMessageOutcome::Duplicate => panic!("message was unexpectedly duplicate"),
        InboundMessageOutcome::SessionUnrecoverable(_) => {
            panic!("message was unexpectedly unrecoverable")
        }
    }
}

fn blocked(outcome: InboundMessageOutcome) -> aether_core::BlockedInboundMessageResult {
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

#[derive(Serialize)]
struct DeadSessionWire {
    version: u8,
    reason: SessionUnrecoverableReason,
    event_emitted: bool,
    peer_sender_identity_key: Option<[u8; 32]>,
    contact_identity_key: Option<()>,
}

fn dead_session_blob(event_emitted: bool, peer_sender_identity_key: [u8; 32]) -> ProtocolStateBlob {
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
    timestamp_millis: u64,
    payload_kind: PayloadKind,
    ratcheted_payload: &[u8],
) -> Vec<u8> {
    use serde::Serialize;

    #[derive(Serialize)]
    struct Wire<'a> {
        version: u8,
        id: [u8; 16],
        timestamp_millis: u64,
        payload_kind: u8,
        ratcheted_payload: &'a [u8],
    }

    let payload_kind = match payload_kind {
        PayloadKind::EncryptedText => 0,
        PayloadKind::Acknowledgment => 1,
        PayloadKind::KeyExchange => 2,
        PayloadKind::RatchetHeader => 3,
        _ => panic!("unsupported test payload kind"),
    };
    postcard::to_stdvec(&Wire {
        version: 1,
        id: *id.as_bytes(),
        timestamp_millis,
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
        .encrypt_message(
            &snapshot,
            key.clone(),
            outbound(1, b"second", &sender_identity),
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
fn sealed_sender_round_trip_exposes_sender_identity_after_decrypt() {
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
        .encrypt_message(&alice_snapshot, key.clone(), {
            let contact = accepted_contact_identity();
            OutboundPlaintext {
                id: MessageId::from_bytes([8; 16]),
                sender_identity: &sender.sender_identity,
                sender_identity_signing_key: sender_identity_signing_key(&sender.sender_identity),
                contact_identity_key: contact.identity_key,
                recipient_public_key: contact.discovery_key.prekey_bundle_lookup_key(),
                timestamp_millis: 1_700_000_000_888,
                plaintext: b"sealed sender",
            }
        })
        .unwrap();
    alice_snapshot.apply_all(encrypted.state_updates);

    let encoded = encrypted.message.to_bytes().unwrap();
    assert!(
        !encoded
            .windows(sender.sender_identity.identity_key.len())
            .any(|window| window == sender.sender_identity.identity_key)
    );

    let decrypted = engine
        .decrypt_message(
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
        )
        .map(accepted)
        .unwrap();
    bob_snapshot.apply_all(decrypted.state_updates);

    assert_eq!(decrypted.plaintext.as_slice(), b"sealed sender");
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
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            outbound(0x42, b"hidden metadata", &sender.sender_identity),
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
        .decrypt_message(
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
        )
        .map(accepted)
        .unwrap();

    assert_eq!(decrypted.message_id, MessageId::from_bytes([0x42; 16]));
    assert_eq!(decrypted.timestamp_millis, 1_700_000_000_123 + 0x42);
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
    let bob_sender = sender_identity(0xb1);
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
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            outbound(0x31, b"ack me", &alice.sender_identity),
        )
        .unwrap();
    alice_snapshot.apply_all(encrypted.state_updates);
    let pending = engine
        .pending_acknowledgments(&alice_snapshot, key.clone())
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].message_id, encrypted.message_id);

    let decrypted = engine
        .decrypt_message(
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
        )
        .map(accepted)
        .unwrap();
    bob_snapshot.apply_all(decrypted.state_updates);

    assert_eq!(decrypted.plaintext.as_slice(), b"ack me");
    assert!(decrypted.acknowledgment.prekey_reference.is_none());
    let encoded_ack = decrypted.acknowledgment.to_bytes().unwrap();
    assert!(
        !encoded_ack
            .windows(encrypted.message_id.as_bytes().len())
            .any(|window| window == encrypted.message_id.as_bytes())
    );

    let cleared = engine
        .process_acknowledgment(
            &mut ChaCha20Rng::from_seed([0x41; 32]),
            &alice_snapshot,
            inbound_acknowledgment(key.clone(), &decrypted.acknowledgment),
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
    alice_snapshot.apply_all(cleared.state_updates);

    assert!(
        engine
            .pending_acknowledgments(&alice_snapshot, key.clone())
            .unwrap()
            .is_empty()
    );
    let duplicate = engine
        .process_acknowledgment(
            &mut ChaCha20Rng::from_seed([0x42; 32]),
            &alice_snapshot,
            inbound_acknowledgment(key, &decrypted.acknowledgment),
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
    let bob_sender = sender_identity(0xb1);
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
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            outbound(0x32, b"ack missing pending", &alice.sender_identity),
        )
        .unwrap();
    for update in encrypted.state_updates {
        if update.address().kind() == ProtocolStateKind::RatchetSession {
            alice_snapshot.apply(update);
        }
    }
    let decrypted = engine
        .decrypt_message(
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
        )
        .map(accepted)
        .unwrap();

    let miss = engine
        .process_acknowledgment(
            &mut ChaCha20Rng::from_seed([0x43; 32]),
            &alice_snapshot,
            inbound_acknowledgment(key, &decrypted.acknowledgment),
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
        .encrypt_message(&snapshot, key.clone(), {
            let contact = accepted_contact_identity();
            OutboundPlaintext {
                id: MessageId::from_bytes([0x33; 16]),
                sender_identity: &sender_identity,
                sender_identity_signing_key: sender_identity_signing_key(&sender_identity),
                contact_identity_key: contact.identity_key,
                recipient_public_key: contact.discovery_key.prekey_bundle_lookup_key(),
                timestamp_millis: sent_at,
                plaintext: b"retry later",
            }
        })
        .unwrap();
    snapshot.apply_all(encrypted.state_updates);

    let early = engine
        .retry_instructions(&snapshot, key.clone(), sent_at + 999, 1_000)
        .unwrap();
    assert!(early.instructions.is_empty());
    assert!(early.state_updates.is_empty());

    let due = engine
        .retry_instructions(&snapshot, key.clone(), sent_at + 1_000, 1_000)
        .unwrap();
    assert_eq!(due.instructions.len(), 1);
    assert_eq!(due.instructions[0].message_id, encrypted.message_id);
    snapshot.apply_all(due.state_updates);

    let repeated = ProtocolStateEngine::new()
        .retry_instructions(&snapshot, key.clone(), sent_at + 1_000, 1_000)
        .unwrap();
    assert!(repeated.instructions.is_empty());
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
    corrupt_snapshot.set(
        address.clone(),
        ProtocolStateBlob::from_bytes(vec![1, 0, 0xaa]),
    );
    assert!(matches!(
        engine.encrypt_message(
            &corrupt_snapshot,
            key.clone(),
            outbound(0x34, b"corrupt pending", &sender_identity),
        ),
        Err(ProtocolStateError::BlobDecode { address: actual, .. }) if actual == address
    ));

    let mut unsupported_snapshot = snapshot_with_state(&engine, key.clone(), &setup.alice_state);
    unsupported_snapshot.set(
        address.clone(),
        ProtocolStateBlob::from_bytes(vec![2, 0, 0xaa]),
    );
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
        .encrypt_message(
            &snapshot,
            key.clone(),
            outbound(0x35, b"retry wrong frame", &sender_identity),
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
    corrupt_snapshot.set(address.clone(), ProtocolStateBlob::from_bytes(corrupt_blob));

    assert!(matches!(
        engine.pending_acknowledgments(&corrupt_snapshot, key),
        Err(ProtocolStateError::BlobDecode { address: actual, .. }) if actual == address
    ));
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
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            outbound(10, b"accept once", &sender.sender_identity),
        )
        .unwrap()
        .message;

    let decrypted = engine
        .decrypt_message(
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
    bob_snapshot.apply_all(decrypted.state_updates);

    let duplicate = ProtocolStateEngine::new()
        .decrypt_message(
            &mut ChaCha20Rng::from_seed([20u8; 32]),
            &bob_snapshot,
            inbound(
                key,
                deduplication_key,
                &encrypted,
                &acknowledgment_sender_identity,
            ),
        )
        .unwrap();
    assert!(matches!(duplicate, InboundMessageOutcome::Duplicate));
}

#[test]
fn skipped_key_total_overflow_rejects_without_marking_session_unrecoverable() {
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
    let mut sequence = 0u16;

    for batch in 0..5 {
        let mut last = None;
        for _ in 0..=100 {
            let encrypted = engine
                .encrypt_message(
                    &alice_snapshot,
                    key.clone(),
                    sequenced_outbound(sequence, b"skipped fill", &sender.sender_identity),
                )
                .unwrap();
            alice_snapshot.apply_all(encrypted.state_updates);
            last = Some(encrypted.message);
            sequence += 1;
        }
        let decrypted = engine
            .decrypt_message(
                &mut ChaCha20Rng::from_seed([batch as u8; 32]),
                &bob_snapshot,
                inbound_with_certificate_validation(
                    key.clone(),
                    deduplication_key.clone(),
                    last.as_ref().unwrap(),
                    &acknowledgment_sender_identity,
                    &domain_keys,
                    &revoked,
                ),
            )
            .map(accepted)
            .unwrap();
        bob_snapshot.apply_all(decrypted.state_updates);
    }

    let mut terminal = None;
    for _ in 0..=100 {
        let encrypted = engine
            .encrypt_message(
                &alice_snapshot,
                key.clone(),
                sequenced_outbound(sequence, b"terminal overflow", &sender.sender_identity),
            )
            .unwrap();
        alice_snapshot.apply_all(encrypted.state_updates);
        terminal = Some(encrypted.message);
        sequence += 1;
    }
    let terminal = terminal.unwrap();

    let overflow = engine.decrypt_message(
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
    );
    assert!(matches!(
        overflow,
        Err(ProtocolStateError::Crypto(
            CryptoError::MaxSkippedKeysExceeded
        ))
    ));

    let repeated = engine.decrypt_message(
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
    );
    assert!(matches!(
        repeated,
        Err(ProtocolStateError::Crypto(
            CryptoError::MaxSkippedKeysExceeded
        ))
    ));
}

#[test]
fn dead_session_marker_reports_once_and_replacement_allows_messages() {
    let initial_setup = setup();
    let replacement = setup();
    let engine = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let sender = validated_sender();
    let domain_keys = [sender.domain_signing_key()];
    let revoked = [];
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let mut alice_snapshot = snapshot_with_state(&engine, key.clone(), &initial_setup.alice_state);
    let mut bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &engine,
        key.clone(),
        &initial_setup.bob_state,
        &sender.sender_identity,
        deduplication_key.clone(),
    );
    let address = ratchet_address(key.clone());
    let dead_message = engine
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            sequenced_outbound(0x80, b"dead marker probe", &sender.sender_identity),
        )
        .unwrap()
        .message;
    bob_snapshot.apply(aether_core::ProtocolStateUpdate::set(
        address.clone(),
        dead_session_blob(false, sender.sender_identity.identity_key),
    ));

    let unrecoverable = engine
        .decrypt_message(
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
    bob_snapshot.apply_all(unrecoverable.state_updates);

    let repeated = engine
        .decrypt_message(
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
        )
        .map(session_unrecoverable)
        .unwrap();
    assert!(repeated.event.is_none());
    assert!(repeated.state_updates.is_empty());

    bob_snapshot.apply(
        engine
            .set_session_state_with_peer_identity(
                key.clone(),
                &replacement.bob_state,
                &sender.sender_identity,
            )
            .unwrap(),
    );
    alice_snapshot = snapshot_with_state(&engine, key.clone(), &replacement.alice_state);

    let encrypted = engine
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            sequenced_outbound(9_000, b"after replacement", &sender.sender_identity),
        )
        .unwrap();
    let decrypted = engine
        .decrypt_message(
            &mut ChaCha20Rng::from_seed([0xf2; 32]),
            &bob_snapshot,
            inbound_with_certificate_validation(
                key,
                deduplication_key,
                &encrypted.message,
                &acknowledgment_sender_identity,
                &domain_keys,
                &revoked,
            ),
        )
        .map(accepted)
        .unwrap();

    assert_eq!(decrypted.plaintext.as_slice(), b"after replacement");
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
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            sequenced_outbound(0x70, b"valid after tamper", &sender.sender_identity),
        )
        .unwrap()
        .message;
    let mut tampered = copy_message(&encrypted);
    *tampered.ciphertext.last_mut().unwrap() ^= 0x01;

    assert!(matches!(
        engine.decrypt_message(
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
        ),
        Err(ProtocolStateError::Crypto(aether_crypto::CryptoError::Aead))
    ));

    let decrypted = engine
        .decrypt_message(
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
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            outbound(0x4f, b"must validate", &sender.sender_identity),
        )
        .unwrap()
        .message;

    let result = engine.decrypt_message(
        &mut ChaCha20Rng::from_seed([0x4f; 32]),
        &bob_snapshot,
        inbound(
            key,
            deduplication_key,
            &encrypted,
            &acknowledgment_sender_identity,
        ),
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
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            outbound(0x50, b"bind contact", &sender.sender_identity),
        )
        .unwrap()
        .message;
    let decrypted = engine
        .decrypt_message(
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
        )
        .map(accepted)
        .unwrap();
    bob_snapshot.apply_all(decrypted.state_updates);

    let result = engine.encrypt_message(
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
            timestamp_millis: 1_700_000_000_500,
            plaintext: b"wrong contact",
        },
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
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            outbound(11, b"no duplicate effect", &sender.sender_identity),
        )
        .unwrap()
        .message;
    let decrypted = engine
        .decrypt_message(
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
        )
        .map(accepted)
        .unwrap();
    bob_snapshot.apply_all(decrypted.state_updates);
    let ratchet_address = ratchet_address(key.clone());
    bob_snapshot.set(
        ratchet_address,
        ProtocolStateBlob::from_bytes(vec![1, 0, 0xaa]),
    );

    let duplicate = engine
        .decrypt_message(
            &mut ChaCha20Rng::from_seed([22u8; 32]),
            &bob_snapshot,
            inbound(
                key,
                deduplication_key,
                &encrypted,
                &acknowledgment_sender_identity,
            ),
        )
        .unwrap();

    assert!(matches!(duplicate, InboundMessageOutcome::Duplicate));
}

#[test]
fn blocked_inbound_message_advances_state_and_returns_acknowledgment_without_plaintext() {
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
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            outbound(0x51, b"blocked text", &sender.sender_identity),
        )
        .unwrap()
        .message;

    let blocked = engine
        .decrypt_message(
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
        )
        .map(blocked)
        .unwrap();

    assert!(blocked.acknowledgment.prekey_reference.is_none());
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
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            outbound(0x52, b"blocked once", &sender.sender_identity),
        )
        .unwrap()
        .message;
    let first = engine
        .decrypt_message(
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
        )
        .map(blocked)
        .unwrap();
    bob_snapshot.apply_all(first.state_updates);
    bob_snapshot.set(
        ratchet_address(key.clone()),
        ProtocolStateBlob::from_bytes(vec![1, 0, 0xaa]),
    );

    let duplicate = engine
        .decrypt_message(
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
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            outbound(0x54, b"rotated blocked", &sender.sender_identity),
        )
        .unwrap()
        .message;

    let outcome = engine
        .decrypt_message(
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
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            outbound(0x55, b"revoked blocked", &sender.sender_identity),
        )
        .unwrap()
        .message;

    let result = engine.decrypt_message(
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
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            outbound(0x5b, b"validated first", &sender.sender_identity),
        )
        .unwrap();
    alice_snapshot.apply_all(first.state_updates);
    let accepted = engine
        .decrypt_message(
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
        )
        .map(accepted)
        .unwrap();
    bob_snapshot.apply_all(accepted.state_updates);
    block_contact(&engine, &mut bob_snapshot);
    let second = engine
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            outbound(0x5c, b"missing validation", &sender.sender_identity),
        )
        .unwrap();

    let result = engine.decrypt_message(
        &mut ChaCha20Rng::from_seed([0x5c; 32]),
        &bob_snapshot,
        inbound(
            key,
            deduplication_key,
            &second.message,
            &acknowledgment_sender_identity,
        ),
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
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            outbound(0x56, b"revocation unavailable", &sender.sender_identity),
        )
        .unwrap()
        .message;

    let result = engine.decrypt_message(
        &mut ChaCha20Rng::from_seed([0x56; 32]),
        &bob_snapshot,
        InboundEncryptedMessage {
            session_key: key,
            deduplication_key,
            message: &encrypted,
            recipient_discovery_key: accepted_contact_discovery_key_ref(),
            acknowledgment: acknowledgment(0xee, &acknowledgment_sender_identity),
            sender_certificate_validation: Some(sender_certificate_validation(
                &domain_keys,
                RevocationState::Unavailable,
            )),
        },
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
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            outbound(0x59, b"untrusted domain", &sender.sender_identity),
        )
        .unwrap()
        .message;

    let result = engine.decrypt_message(
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
    );

    assert!(matches!(
        result,
        Err(ProtocolStateError::SenderCertificateValidation(
            SenderCertificateValidationError::UntrustedSigningKeyIdentifier
        ))
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
        CERTIFICATE_REFERENCE_TIME - 1,
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
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            outbound(0x5a, b"expired domain", &sender.sender_identity),
        )
        .unwrap()
        .message;

    let result = engine.decrypt_message(
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
    );

    assert!(matches!(
        result,
        Err(ProtocolStateError::SenderCertificateValidation(
            SenderCertificateValidationError::ExpiredCertificate
        ))
    ));
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
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            outbound(0x57, b"bind alice contact session", &alice.sender_identity),
        )
        .unwrap();
    alice_snapshot.apply_all(first.state_updates);
    let decrypted = engine
        .decrypt_message(
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
        )
        .map(accepted)
        .unwrap();
    bob_snapshot.apply_all(decrypted.state_updates);
    let reply = engine
        .encrypt_message(
            &bob_snapshot,
            key.clone(),
            outbound(0x58, b"mismatched certificate", &sender.sender_identity),
        )
        .unwrap();
    bob_snapshot.apply_all(reply.state_updates);

    assert!(matches!(
        engine.decrypt_message(
            &mut ChaCha20Rng::from_seed([0x58; 32]),
            &alice_snapshot,
            inbound_with_certificate_validation(
                key,
                deduplication_key,
                &reply.message,
                &acknowledgment_sender_identity,
                &domain_keys,
                &revoked,
            ),
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
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            outbound(0x56, b"blocked before unblock", &sender.sender_identity),
        )
        .unwrap();
    alice_snapshot.apply_all(first.state_updates);
    let blocked = engine
        .decrypt_message(
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
        )
        .map(blocked)
        .unwrap();
    bob_snapshot.apply_all(blocked.state_updates);
    let unblocked = engine
        .unblock_contact(&bob_snapshot, sender.contact.identity_key)
        .unwrap();
    bob_snapshot.apply_all(unblocked.state_updates);
    let second = engine
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            outbound(0x57, b"after unblock", &sender.sender_identity),
        )
        .unwrap();

    let accepted = engine
        .decrypt_message(
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
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            outbound(12, b"in band is not verification", &sender.sender_identity),
        )
        .unwrap();
    alice_snapshot.apply_all(encrypted.state_updates);
    let decrypted = engine
        .decrypt_message(
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
        )
        .map(accepted)
        .unwrap();
    bob_snapshot.apply_all(decrypted.state_updates);

    assert_eq!(
        engine
            .contact_state(&bob_snapshot, contact.identity_key)
            .unwrap()
            .unwrap()
            .trust_state,
        ContactTrustState::Unverified
    );

    let cleared = engine
        .process_acknowledgment(
            &mut ChaCha20Rng::from_seed([24u8; 32]),
            &alice_snapshot,
            inbound_acknowledgment(key, &decrypted.acknowledgment),
        )
        .unwrap();
    let AcknowledgmentOutcome::Cleared(cleared) = cleared else {
        panic!("acknowledgment did not clear pending state");
    };
    alice_snapshot.apply_all(cleared.state_updates);

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
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            outbound(12, b"bad dedup state", &sender_identity),
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
        engine.decrypt_message(
            &mut ChaCha20Rng::from_seed([23u8; 32]),
            &missing_snapshot,
            inbound(
                key.clone(),
                deduplication_key.clone(),
                &encrypted,
                &acknowledgment_sender_identity,
            ),
        ),
        Err(ProtocolStateError::MissingRequiredState { address }) if address == deduplication_address
    ));

    let mut corrupt_snapshot = snapshot_with_state_and_peer_identity(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender_identity,
    );
    corrupt_snapshot.set(
        deduplication_address.clone(),
        ProtocolStateBlob::from_bytes(vec![1, 0, 0xaa]),
    );
    assert!(matches!(
        engine.decrypt_message(
            &mut ChaCha20Rng::from_seed([24u8; 32]),
            &corrupt_snapshot,
            inbound(
                key.clone(),
                deduplication_key.clone(),
                &encrypted,
                &acknowledgment_sender_identity,
            ),
        ),
        Err(ProtocolStateError::BlobDecode { address, .. }) if address == deduplication_address
    ));

    let mut unsupported_snapshot = snapshot_with_state_and_peer_identity(
        &engine,
        key.clone(),
        &setup.bob_state,
        &sender_identity,
    );
    unsupported_snapshot.set(
        deduplication_address.clone(),
        ProtocolStateBlob::from_bytes(vec![2, 0, 0xaa]),
    );
    assert!(matches!(
        engine.decrypt_message(
            &mut ChaCha20Rng::from_seed([25u8; 32]),
            &unsupported_snapshot,
            inbound(key, deduplication_key, &encrypted, &acknowledgment_sender_identity),
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
            .encrypt_message(
                &alice_snapshot,
                key.clone(),
                outbound(index as u8, b"fills window", &sender.sender_identity),
            )
            .unwrap();
        let message = encrypted.message;
        alice_snapshot.apply_all(encrypted.state_updates);
        if index == 0 {
            first_message = Some(copy_message(&message));
        }
        let decrypted = engine
            .decrypt_message(
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
            )
            .map(accepted)
            .unwrap();
        bob_snapshot.apply_all(decrypted.state_updates);
    }

    let result = engine.decrypt_message(
        &mut ChaCha20Rng::from_seed([27u8; 32]),
        &bob_snapshot,
        inbound(
            key,
            deduplication_key,
            &first_message.unwrap(),
            &acknowledgment_sender_identity,
        ),
    );

    assert!(matches!(result, Err(ProtocolStateError::Crypto(_))));
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
    bob_snapshot.apply(
        engine
            .set_session_state_with_peer_identity_key(
                key.clone(),
                &setup.bob_state,
                sender.sender_identity.identity_key,
            )
            .unwrap(),
    );
    install_deduplication_set(&engine, &mut bob_snapshot, deduplication_key.clone(), 0x44);

    let encrypted = engine
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            outbound(7, b"key-only install", &sender.sender_identity),
        )
        .unwrap()
        .message;

    let decrypted = engine
        .decrypt_message(
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
    bob_snapshot.apply(bind_update);
    install_deduplication_set(&engine, &mut bob_snapshot, deduplication_key.clone(), 0x44);

    let encrypted = engine
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            outbound(2, b"bound by key", &sender.sender_identity),
        )
        .unwrap()
        .message;

    let decrypted = engine
        .decrypt_message(
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
    bob_snapshot.apply(
        engine
            .set_session_state_with_peer_identity(
                key.clone(),
                &setup.bob_state,
                &expected_sender_identity,
            )
            .unwrap(),
    );
    install_deduplication_set(&engine, &mut bob_snapshot, deduplication_key.clone(), 0x44);

    let encrypted = engine
        .encrypt_message(&alice_snapshot, key.clone(), {
            let contact = accepted_contact_identity();
            OutboundPlaintext {
                id: MessageId::from_bytes([9; 16]),
                sender_identity: &actual_sender_identity,
                sender_identity_signing_key: sender_identity_signing_key(&actual_sender_identity),
                contact_identity_key: contact.identity_key,
                recipient_public_key: contact.discovery_key.prekey_bundle_lookup_key(),
                timestamp_millis: 1_700_000_000_999,
                plaintext: b"wrong sender",
            }
        })
        .unwrap();

    let result = engine.decrypt_message(
        &mut ChaCha20Rng::from_seed([15u8; 32]),
        &bob_snapshot,
        inbound(
            key,
            deduplication_key,
            &encrypted.message,
            &acknowledgment_sender_identity,
        ),
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
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            outbound(3, b"secret", &sender_identity),
        )
        .unwrap()
        .message;
    let last = encrypted.ciphertext.last_mut().unwrap();
    *last ^= 0x01;

    let result = engine.decrypt_message(
        &mut ChaCha20Rng::from_seed([13u8; 32]),
        &bob_snapshot,
        inbound(
            key,
            deduplication_key,
            &encrypted,
            &acknowledgment_sender_identity,
        ),
    );

    assert!(matches!(result, Err(ProtocolStateError::Crypto(_))));
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
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            outbound(5, b"metadata-bound", &sender_identity),
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
        let result = engine.decrypt_message(
            &mut ChaCha20Rng::from_seed([16u8; 32]),
            &bob_snapshot,
            inbound(
                key.clone(),
                deduplication_key.clone(),
                &message,
                &acknowledgment_sender_identity,
            ),
        );
        assert!(matches!(result, Err(ProtocolStateError::Crypto(_))));
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
        .encrypt_message(
            &alice_snapshot,
            key,
            outbound(0x19, b"wrong session key", &sender_identity),
        )
        .unwrap()
        .message;

    let result = engine.decrypt_message(
        &mut ChaCha20Rng::from_seed([0x19; 32]),
        &bob_snapshot,
        inbound(
            other_key,
            deduplication_key,
            &encrypted,
            &acknowledgment_sender_identity,
        ),
    );

    assert!(matches!(result, Err(ProtocolStateError::Crypto(_))));
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
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            outbound(0x1a, b"ack wrong session key", &sender.sender_identity),
        )
        .unwrap();
    alice_snapshot.apply_all(remap_session_updates(
        encrypted.state_updates,
        other_key.clone(),
    ));
    let decrypted = engine
        .decrypt_message(
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
    alice_snapshot.apply(bound);

    let result = engine.process_acknowledgment(
        &mut ChaCha20Rng::from_seed([0x1b; 32]),
        &alice_snapshot,
        InboundAcknowledgmentMessage {
            session_key: other_key,
            message: &decrypted.acknowledgment,
            recipient_discovery_key: acknowledgment_recipient_discovery_key_ref(),
        },
    );

    assert!(matches!(result, Err(ProtocolStateError::Crypto(_))));
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
    let frame = seal_frame(
        &mut rng,
        &PublicKey::from(recipient_public_key),
        None,
        &frame_plaintext,
    )
    .unwrap();
    let message = Message {
        version: frame.version,
        recipient_public_key: frame.recipient_public_key,
        prekey_reference: frame.prekey_reference,
        ephemeral_public_key: frame.ephemeral_public_key,
        ciphertext: frame.ciphertext,
    };

    let result = engine.decrypt_message(
        &mut ChaCha20Rng::from_seed([14u8; 32]),
        &bob_snapshot,
        inbound(
            key,
            deduplication_key,
            &message,
            &acknowledgment_sender_identity,
        ),
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
        .encrypt_message(
            &snapshot,
            key.clone(),
            outbound(1, &large_plaintext, &sender_identity),
        )
        .unwrap();
    assert!(result.message.to_bytes().unwrap().len() > 64 * 1024);
    let message_id = result.message_id;
    snapshot.apply_all(result.state_updates);

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

    let result = engine.encrypt_message(
        &snapshot,
        key,
        outbound(1, &oversized_plaintext, &sender_identity),
    );

    assert!(matches!(
        result,
        Err(ProtocolStateError::InvalidMessage { .. })
    ));
    assert_eq!(snapshot.get(&address).unwrap().as_bytes(), prior_blob);
}

#[test]
fn two_instances_alternate_against_latest_consumer_blobs() {
    let setup = setup();
    let first_instance = ProtocolStateEngine::new();
    let second_instance = ProtocolStateEngine::new();
    let key = key();
    let deduplication_key = deduplication_key();
    let sender = validated_sender();
    let domain_keys = [sender.domain_signing_key()];
    let revoked = [];
    let acknowledgment_sender_identity = acknowledgment_sender_identity();
    let mut alice_snapshot = snapshot_with_state(&first_instance, key.clone(), &setup.alice_state);
    let mut bob_snapshot = snapshot_with_state_peer_identity_and_deduplication(
        &first_instance,
        key.clone(),
        &setup.bob_state,
        &sender.sender_identity,
        deduplication_key.clone(),
    );

    let first = first_instance
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            outbound(1, b"from first", &sender.sender_identity),
        )
        .unwrap();
    let first_message = first.message;
    alice_snapshot.apply_all(first.state_updates);

    let second = second_instance
        .encrypt_message(
            &alice_snapshot,
            key.clone(),
            outbound(2, b"from second", &sender.sender_identity),
        )
        .unwrap();
    let second_message = second.message;
    alice_snapshot.apply_all(second.state_updates);

    let first_decrypt = first_instance
        .decrypt_message(
            &mut ChaCha20Rng::from_seed([10u8; 32]),
            &bob_snapshot,
            inbound_with_certificate_validation(
                key.clone(),
                deduplication_key.clone(),
                &first_message,
                &acknowledgment_sender_identity,
                &domain_keys,
                &revoked,
            ),
        )
        .map(accepted)
        .unwrap();
    let first_plaintext = first_decrypt.plaintext.to_vec();
    bob_snapshot.apply_all(first_decrypt.state_updates);
    let second_decrypt = second_instance
        .decrypt_message(
            &mut ChaCha20Rng::from_seed([11u8; 32]),
            &bob_snapshot,
            inbound_with_certificate_validation(
                key,
                deduplication_key,
                &second_message,
                &acknowledgment_sender_identity,
                &domain_keys,
                &revoked,
            ),
        )
        .map(accepted)
        .unwrap();
    let second_plaintext = second_decrypt.plaintext.to_vec();
    bob_snapshot.apply_all(second_decrypt.state_updates);

    assert_eq!(first_plaintext, b"from first");
    assert_eq!(second_plaintext, b"from second");
}

#[test]
fn wipe_removes_all_state_kinds_for_key() {
    let engine = ProtocolStateEngine::new();
    let key = key();
    let mut snapshot = ProtocolStateSnapshot::new();
    for kind in ProtocolStateKind::all() {
        snapshot.set(
            ProtocolStateAddress::new(*kind, key.clone()),
            ProtocolStateBlob::from_bytes(vec![*kind as u8, 7]),
        );
    }

    snapshot.apply_all(engine.wipe(key.clone()));

    for kind in ProtocolStateKind::all() {
        assert!(
            snapshot
                .get(&ProtocolStateAddress::new(*kind, key.clone()))
                .is_none()
        );
    }
}

#[test]
fn corrupt_ratchet_blob_is_a_decode_fault() {
    let engine = ProtocolStateEngine::new();
    let key = key();
    let address = ratchet_address(key.clone());
    let sender_identity = sender_identity(1);
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot.set(
        address.clone(),
        ProtocolStateBlob::from_bytes(vec![1, 0, 0xaa]),
    );
    install_accepted_contact(&engine, &mut snapshot);

    assert!(matches!(
        engine.encrypt_message(&snapshot, key, outbound(1, b"lost", &sender_identity)),
        Err(ProtocolStateError::BlobDecode { address: actual, .. }) if actual == address
    ));
}

#[test]
fn oversized_ratchet_blob_is_a_decode_fault_before_restore() {
    let engine = ProtocolStateEngine::new();
    let key = key();
    let address = ratchet_address(key.clone());
    let sender_identity = sender_identity(1);
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot.set(
        address.clone(),
        ProtocolStateBlob::from_bytes(vec![1; 128 * 1024]),
    );
    install_accepted_contact(&engine, &mut snapshot);

    assert!(matches!(
        engine.encrypt_message(&snapshot, key, outbound(1, b"lost", &sender_identity)),
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
    snapshot.set(
        address.clone(),
        ProtocolStateBlob::from_bytes(vec![1, 0, 0xaa]),
    );
    install_accepted_contact(&engine, &mut snapshot);

    let result = engine.encrypt_message(&snapshot, key, outbound(1, b"lost", &sender_identity));

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
        engine.encrypt_message(&snapshot, key, outbound(1, b"lost", &sender_identity)),
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
    snapshot.apply_all(engine.wipe(key.clone()));

    assert!(matches!(
        engine.encrypt_message(
            &snapshot,
            key.clone(),
            outbound(1, b"after wipe", &sender_identity),
        ),
        Err(ProtocolStateError::MissingRequiredState { .. })
    ));

    snapshot.apply(
        engine
            .set_session_state(key.clone(), &setup.alice_state)
            .unwrap(),
    );
    install_pending_acknowledgments(&engine, &mut snapshot, key.clone());
    let result = engine
        .encrypt_message(&snapshot, key, outbound(2, b"restored", &sender_identity))
        .unwrap();
    assert_eq!(result.payload_kind, PayloadKind::EncryptedText);
}
