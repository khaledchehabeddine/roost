//! Exercises the v0.6.0 public Core API across two library instances and consumer-held blobs.

use std::collections::BTreeMap;

use aether_core::{
    AcknowledgmentOutcome, BlockedContactAcknowledgmentPolicy, ContactDiscoveryKey,
    ContactEventStream, ContactIdentity, ContactIdentityKey, ContactTrustState, DomainSigningKey,
    DomainSigningKeyStatus, EventStream, EventStreamItem, InboundAcknowledgmentMessage,
    InboundEncryptedMessage, InboundMessageOutcome, InboundSenderCertificateValidation, Message,
    MessageId, OutboundAcknowledgment, OutboundPlaintext, ProtocolStateAddress, ProtocolStateBlob,
    ProtocolStateEngine, ProtocolStateError, ProtocolStateKey, ProtocolStateKind,
    ProtocolStateSnapshot, RelayRoute, RelayRouteError, RevocationState,
    SenderCertificateIdentityKey, SenderIdentityMaterial, SessionId,
};
use aether_crypto::{
    DiscoveryKey, IdentityKeyBundle, InitialPlaintext, KeyPair, PreKeyBundle, PublicKey,
    RatchetState, SigningKeyPair, accept, generate_discovery_key, generate_key_pair,
    generate_one_time_prekey, generate_signed_prekey_for_discovery_key, generate_signing_key_pair,
    initiate, sign_identity_key_binding,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use zeroize::Zeroizing;

const CREATED_AT: u64 = 1_700_000_000;
const RETRY_WINDOW_MILLIS: u64 = 1_000;
const CERTIFICATE_DOMAIN_TAG: &[u8] = b"AetherSenderCertificate-v2:";
const TEST_RELAY_DOMAIN: &[u8] = b"relay.test";
const CERTIFICATE_VERSION: u8 = 2;
const CERTIFICATE_EXPIRES_AT: u64 = 1_700_100_000;
const CERTIFICATE_REFERENCE_TIME: u64 = 1_700_000_000;

#[derive(Clone, Debug, Eq, PartialEq)]
enum InstanceEvent {
    Accepted { plaintext: Vec<u8> },
    AcknowledgmentCleared { id: MessageId },
}

type InstanceEventStream = EventStream<InstanceEvent, Vec<InstanceEvent>>;

struct Setup {
    alice_state: RatchetState,
    bob_state: RatchetState,
}

#[derive(Clone, Default)]
struct ConsumerStore {
    blobs: BTreeMap<ProtocolStateAddress, Zeroizing<Vec<u8>>>,
}

impl ConsumerStore {
    fn snapshot(&self) -> ProtocolStateSnapshot {
        let mut snapshot = ProtocolStateSnapshot::new();
        for (address, blob) in &self.blobs {
            snapshot.set(
                address.clone(),
                ProtocolStateBlob::from_bytes(blob.as_slice().to_vec()),
            );
        }
        snapshot
    }

    fn apply(&mut self, update: aether_core::ProtocolStateUpdate) {
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
        I: IntoIterator<Item = aether_core::ProtocolStateUpdate>,
    {
        for update in updates {
            self.apply(update);
        }
    }

    fn set_raw(&mut self, address: ProtocolStateAddress, blob: Vec<u8>) {
        self.blobs.insert(address, Zeroizing::new(blob));
    }
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
        generate_signed_prekey_for_discovery_key(&mut rng, &bob_discovery, 0, CREATED_AT);
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

fn sender_identity_signing_key(tag: u8) -> &'static SigningKeyPair {
    Box::leak(Box::new(SigningKeyPair::from_signing_bytes([tag; 32])))
}

fn sender_identity_signing_key_for_material(
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

fn session_key() -> ProtocolStateKey {
    ProtocolStateKey::session(SessionId::from_bytes([9u8; 16]))
}

fn deduplication_key() -> ProtocolStateKey {
    ProtocolStateKey::from_bytes(vec![0xdd; 16]).unwrap()
}

fn ratchet_address(key: ProtocolStateKey) -> ProtocolStateAddress {
    ProtocolStateAddress::new(ProtocolStateKind::RatchetSession, key)
}

fn recipient_sender_identity() -> SenderIdentityMaterial {
    sender_identity_for_contact(
        accepted_contact_identity(),
        vec![0xb2, 0xb3, 0xb4],
        vec![0xb5; 64],
    )
}

fn accepted_contact_identity() -> ContactIdentity {
    contact_identity(0xa1, 0x71)
}

fn acknowledgment_recipient_identity() -> ContactIdentity {
    contact_identity(0xa2, 0x72)
}

fn contact_identity(identity_tag: u8, discovery_seed: u8) -> ContactIdentity {
    let identity = sender_identity_signing_key(identity_tag);
    let identity_key_pair = test_identity_key_pair(identity_tag);
    let mut rng = ChaCha20Rng::from_seed([discovery_seed; 32]);
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
    let identity = sender_identity_signing_key(0xa1);
    let mut rng = ChaCha20Rng::from_seed([0x71; 32]);
    generate_discovery_key(&mut rng, identity, 0, CREATED_AT)
}

fn accepted_contact_discovery_key_ref() -> &'static DiscoveryKey {
    Box::leak(Box::new(accepted_contact_discovery_key()))
}

fn acknowledgment_recipient_discovery_key() -> DiscoveryKey {
    let mut rng = ChaCha20Rng::from_seed([0xc2; 32]);
    generate_discovery_key(&mut rng, sender_identity_signing_key(0xa1), 0, CREATED_AT)
}

fn route_acknowledgment_recipient_discovery_key() -> DiscoveryKey {
    let mut rng = ChaCha20Rng::from_seed([0x72; 32]);
    generate_discovery_key(&mut rng, sender_identity_signing_key(0xa2), 0, CREATED_AT)
}

fn acknowledgment_recipient_discovery_key_ref() -> &'static DiscoveryKey {
    Box::leak(Box::new(acknowledgment_recipient_discovery_key()))
}

struct ValidatedSender {
    sender_identity: SenderIdentityMaterial,
    domain_identifier: Vec<u8>,
    domain_verifying_key: Vec<u8>,
}

impl ValidatedSender {
    fn domain_signing_key(&self) -> DomainSigningKey<'_> {
        DomainSigningKey {
            identifier: &self.domain_identifier,
            verifying_key: &self.domain_verifying_key,
            status: DomainSigningKeyStatus::Trusted,
        }
    }
}

fn validated_sender() -> ValidatedSender {
    validated_sender_for_contact(accepted_contact_identity(), 0x90)
}

fn validated_sender_for_contact(contact: ContactIdentity, domain_seed: u8) -> ValidatedSender {
    let mut rng = ChaCha20Rng::from_seed([domain_seed; 32]);
    let domain_signing_key = generate_signing_key_pair(&mut rng);
    let domain_identifier = b"test-domain".to_vec();
    let certificate = sender_certificate_bytes(&domain_identifier, contact, CERTIFICATE_EXPIRES_AT);
    let signature = domain_signing_key.sign(&certificate).to_bytes().to_vec();
    ValidatedSender {
        sender_identity: sender_identity_for_contact(
            contact,
            certificate.clone(),
            signature.clone(),
        ),
        domain_identifier,
        domain_verifying_key: domain_signing_key.verifying.to_bytes().to_vec(),
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
    bytes.push(TEST_RELAY_DOMAIN.len() as u8);
    bytes.extend_from_slice(TEST_RELAY_DOMAIN);
    bytes.extend_from_slice(&contact.identity_key.x25519_public_key);
    bytes.extend_from_slice(&contact.identity_key.ed25519_verifying_key);
    bytes.extend_from_slice(&expires_at_secs.to_be_bytes());
    bytes
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
        sender_identity_signing_key: sender_identity_signing_key_for_material(sender_identity),
        contact_identity_key: contact.identity_key,
        recipient_public_key: contact.discovery_key.prekey_bundle_lookup_key(),
        timestamp_millis: 1_700_000_000_000 + u64::from(id),
        plaintext,
    }
}

fn acknowledgment<'a>(
    id: u8,
    sender_identity: &'a SenderIdentityMaterial,
) -> OutboundAcknowledgment<'a> {
    OutboundAcknowledgment {
        id: MessageId::from_bytes([id; 16]),
        sender_identity,
        sender_identity_signing_key: sender_identity_signing_key_for_material(sender_identity),
        recipient_public_key: *acknowledgment_recipient_discovery_key()
            .public_key()
            .as_bytes(),
        timestamp_millis: 1_700_000_100_000 + u64::from(id),
    }
}

fn inbound<'a>(
    session_key: ProtocolStateKey,
    deduplication_key: ProtocolStateKey,
    message: &'a Message,
    acknowledgment_sender_identity: &'a SenderIdentityMaterial,
    acknowledgment_id: u8,
) -> InboundEncryptedMessage<'a> {
    InboundEncryptedMessage {
        session_key,
        deduplication_key,
        message,
        recipient_discovery_key: accepted_contact_discovery_key_ref(),
        recipient_identity_verifying_key: accepted_contact_identity()
            .identity_key
            .ed25519_verifying_key,
        acknowledgment: acknowledgment(acknowledgment_id, acknowledgment_sender_identity),
        sender_certificate_validation: None,
    }
}

fn inbound_with_certificate_validation<'a>(
    session_key: ProtocolStateKey,
    deduplication_key: ProtocolStateKey,
    message: &'a Message,
    acknowledgment_sender_identity: &'a SenderIdentityMaterial,
    acknowledgment_id: u8,
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
        acknowledgment: acknowledgment(acknowledgment_id, acknowledgment_sender_identity),
        sender_certificate_validation: Some(InboundSenderCertificateValidation {
            expected_relay_domain: TEST_RELAY_DOMAIN,
            domain_signing_keys,
            revocation_state: RevocationState::Available(revoked_identity_keys),
            reference_timestamp_secs: CERTIFICATE_REFERENCE_TIME,
            grace_window_secs: 0,
        }),
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

fn emit_event(stream: &InstanceEventStream, event: InstanceEvent) {
    let mut state = stream.current_state().unwrap().state().clone();
    state.push(event.clone());
    stream.emit(event, state).unwrap();
}

fn install_accepted_contact_identity(
    engine: &ProtocolStateEngine,
    store: &mut ConsumerStore,
    contact: ContactIdentity,
) {
    let created = engine.record_contact(&store.snapshot(), contact).unwrap();
    store.apply_all(created.state_updates);
    let accepted = engine
        .accept_contact(&store.snapshot(), contact.identity_key)
        .unwrap();
    store.apply_all(accepted.state_updates);
}

fn block_accepted_contact(engine: &ProtocolStateEngine, store: &mut ConsumerStore) {
    let contact = accepted_contact_identity();
    let blocked = engine
        .block_contact(&store.snapshot(), contact.identity_key)
        .unwrap();
    store.apply_all(blocked.state_updates);
}

fn initialize_stores(
    engine: &ProtocolStateEngine,
    session_key: ProtocolStateKey,
    deduplication_key: ProtocolStateKey,
    alice_sender: &SenderIdentityMaterial,
    bob_sender: &SenderIdentityMaterial,
) -> (ConsumerStore, ConsumerStore) {
    initialize_stores_with_contacts(
        engine,
        session_key,
        deduplication_key,
        alice_sender,
        bob_sender,
        accepted_contact_identity(),
        accepted_contact_identity(),
    )
}

fn initialize_stores_with_contacts(
    engine: &ProtocolStateEngine,
    session_key: ProtocolStateKey,
    deduplication_key: ProtocolStateKey,
    alice_sender: &SenderIdentityMaterial,
    bob_sender: &SenderIdentityMaterial,
    alice_contact: ContactIdentity,
    bob_contact: ContactIdentity,
) -> (ConsumerStore, ConsumerStore) {
    let setup = setup();
    let mut alice = ConsumerStore::default();
    let mut bob = ConsumerStore::default();

    alice.apply(
        engine
            .set_session_state_with_peer_identity(
                session_key.clone(),
                &setup.alice_state,
                bob_sender,
            )
            .unwrap(),
    );
    alice.apply(
        engine
            .initialize_pending_acknowledgments(session_key.clone())
            .unwrap(),
    );
    install_accepted_contact_identity(engine, &mut alice, bob_contact);
    bob.apply(
        engine
            .set_session_state_with_peer_identity(
                session_key.clone(),
                &setup.bob_state,
                alice_sender,
            )
            .unwrap(),
    );
    bob.apply(
        engine
            .initialize_deduplication_set(
                &mut ChaCha20Rng::from_seed([0x44; 32]),
                deduplication_key,
            )
            .unwrap(),
    );
    install_accepted_contact_identity(engine, &mut bob, alice_contact);
    (alice, bob)
}

#[test]
fn app_instance_rebuilds_current_state_after_extension_commits_without_importing_event_ids() {
    let app_instance = ProtocolStateEngine::new();
    let extension_instance = ProtocolStateEngine::new();
    let first_contact = accepted_contact_identity();
    let second_contact = acknowledgment_recipient_identity();
    let mut store = ConsumerStore::default();
    let events = ContactEventStream::with_observer_capacity(Vec::new(), 1).unwrap();
    let observer = events.subscribe().unwrap();

    let created = app_instance
        .record_contact(&store.snapshot(), first_contact)
        .unwrap();
    let created_event = created.event.unwrap();
    store.apply_all(created.state_updates);
    let app_state = app_instance.contact_states(&store.snapshot()).unwrap();
    let local_event = events.emit(created_event, app_state).unwrap();
    assert_eq!(local_event.id().as_u64(), 1);

    let accepted = extension_instance
        .accept_contact(&store.snapshot(), first_contact.identity_key)
        .unwrap();
    store.apply_all(accepted.state_updates);
    let created_by_extension = extension_instance
        .record_contact(&store.snapshot(), second_contact)
        .unwrap();
    store.apply_all(created_by_extension.state_updates);

    let stale = events.current_state().unwrap();
    assert_eq!(stale.event_id().as_u64(), 1);
    assert_eq!(stale.state().len(), 1);
    assert_eq!(stale.state()[0].trust_state, ContactTrustState::Pending);

    let rebuilt = app_instance.contact_states(&store.snapshot()).unwrap();
    assert_eq!(rebuilt.len(), 2);
    assert_eq!(
        rebuilt
            .iter()
            .find(|contact| contact.identity.identity_key == first_contact.identity_key)
            .unwrap()
            .trust_state,
        ContactTrustState::Unverified
    );
    let imported = events.import_current_state(rebuilt).unwrap();
    assert_eq!(imported.event_id().as_u64(), 1);
    assert_eq!(imported.state_revision(), 1);
    assert_eq!(observer.poll_next().unwrap(), Some(EventStreamItem::Stale));

    let accepted = app_instance
        .accept_contact(&store.snapshot(), second_contact.identity_key)
        .unwrap();
    let accepted_event = accepted.event.unwrap();
    store.apply_all(accepted.state_updates);
    events
        .emit(
            accepted_event,
            app_instance.contact_states(&store.snapshot()).unwrap(),
        )
        .unwrap();
    let blocked = app_instance
        .block_contact(&store.snapshot(), second_contact.identity_key)
        .unwrap();
    let blocked_event = blocked.event.unwrap();
    store.apply_all(blocked.state_updates);
    events
        .emit(
            blocked_event,
            app_instance.contact_states(&store.snapshot()).unwrap(),
        )
        .unwrap();

    observer.resume_after(&imported).unwrap();
    assert_eq!(
        observer.poll_next().unwrap(),
        Some(EventStreamItem::Lagged { missed: 1 })
    );
    let recovered = events.current_state().unwrap();
    assert_eq!(recovered.event_id().as_u64(), 3);
    assert_eq!(recovered.state_revision(), 1);
    observer.resume_after(&recovered).unwrap();
    assert_eq!(observer.poll_next().unwrap(), None);

    let reconstructed = ProtocolStateEngine::new()
        .contact_states(&store.snapshot())
        .unwrap();
    assert_eq!(reconstructed, *recovered.state());
    let restarted = ContactEventStream::new(reconstructed);
    let restart_snapshot = restarted.current_state().unwrap();
    assert_eq!(restart_snapshot.event_id().as_u64(), 0);
    assert_eq!(restart_snapshot.state_revision(), 0);
    assert_eq!(restart_snapshot.state(), recovered.state());
}

#[test]
fn established_relay_route_is_authenticated_for_messages_and_acknowledgments() {
    let engine = ProtocolStateEngine::new();
    let session_key = session_key();
    let deduplication_key = deduplication_key();
    let alice_contact = acknowledgment_recipient_identity();
    let alice = validated_sender_for_contact(alice_contact, 0x91);
    let alice_domain_keys = [alice.domain_signing_key()];
    let revoked = [];
    let bob_contact = accepted_contact_identity();
    let bob_sender = recipient_sender_identity();
    let (mut alice_store, bob_store) = initialize_stores_with_contacts(
        &engine,
        session_key.clone(),
        deduplication_key.clone(),
        &alice.sender_identity,
        &bob_sender,
        alice_contact,
        bob_contact,
    );
    let message_route = RelayRoute::established(1, bob_contact.identity_key.ed25519_verifying_key);
    let acknowledgment_route =
        RelayRoute::established(1, alice_contact.identity_key.ed25519_verifying_key);
    let wrong_message_version =
        RelayRoute::established(2, bob_contact.identity_key.ed25519_verifying_key);
    let wrong_acknowledgment_version =
        RelayRoute::established(2, alice_contact.identity_key.ed25519_verifying_key);
    let wrong_recipient = RelayRoute::established(1, [0x99; 32]);

    let outbound = engine
        .encrypt_message_with_relay_route(
            &alice_store.snapshot(),
            session_key.clone(),
            outbound(0x41, b"route bound", &alice.sender_identity),
            &message_route,
        )
        .unwrap();
    let outbound_message_id = outbound.message_id;
    alice_store.apply_all(outbound.state_updates);

    let alice_discovery_key = route_acknowledgment_recipient_discovery_key();
    let receive = |route: &RelayRoute, acknowledgment_route: &RelayRoute| {
        engine.decrypt_message_with_relay_routes(
            &mut ChaCha20Rng::from_seed([0x42; 32]),
            &bob_store.snapshot(),
            InboundEncryptedMessage {
                session_key: session_key.clone(),
                deduplication_key: deduplication_key.clone(),
                message: &outbound.message,
                recipient_discovery_key: accepted_contact_discovery_key_ref(),
                recipient_identity_verifying_key: bob_contact.identity_key.ed25519_verifying_key,
                acknowledgment: OutboundAcknowledgment {
                    id: MessageId::from_bytes([0x42; 16]),
                    sender_identity: &bob_sender,
                    sender_identity_signing_key: sender_identity_signing_key_for_material(
                        &bob_sender,
                    ),
                    recipient_public_key: *alice_discovery_key.public_key().as_bytes(),
                    timestamp_millis: 1_700_000_100_042,
                },
                sender_certificate_validation: Some(InboundSenderCertificateValidation {
                    expected_relay_domain: TEST_RELAY_DOMAIN,
                    domain_signing_keys: &alice_domain_keys,
                    revocation_state: RevocationState::Available(&revoked),
                    reference_timestamp_secs: CERTIFICATE_REFERENCE_TIME,
                    grace_window_secs: 0,
                }),
            },
            route,
            acknowledgment_route,
        )
    };
    assert!(matches!(
        receive(&wrong_recipient, &acknowledgment_route),
        Err(ProtocolStateError::RelayRoute(
            RelayRouteError::RecipientMismatch
        ))
    ));
    assert!(matches!(
        receive(&wrong_message_version, &acknowledgment_route),
        Err(ProtocolStateError::Crypto(aether_crypto::CryptoError::Aead))
    ));
    assert!(matches!(
        receive(&message_route, &message_route),
        Err(ProtocolStateError::RelayRoute(
            RelayRouteError::RecipientMismatch
        ))
    ));

    let received = accepted(receive(&message_route, &acknowledgment_route).unwrap());
    assert_eq!(received.plaintext.as_slice(), b"route bound");
    let acknowledgment = received.acknowledgment;

    assert!(matches!(
        engine.process_acknowledgment_with_relay_route(
            &mut ChaCha20Rng::from_seed([0x43; 32]),
            &alice_store.snapshot(),
            InboundAcknowledgmentMessage {
                session_key: session_key.clone(),
                message: &acknowledgment,
                recipient_discovery_key: &alice_discovery_key,
                recipient_identity_verifying_key: alice_contact.identity_key.ed25519_verifying_key,
            },
            &wrong_acknowledgment_version,
        ),
        Err(ProtocolStateError::Crypto(aether_crypto::CryptoError::Aead))
    ));
    assert!(matches!(
        engine.process_acknowledgment_with_relay_route(
            &mut ChaCha20Rng::from_seed([0x44; 32]),
            &alice_store.snapshot(),
            InboundAcknowledgmentMessage {
                session_key: session_key.clone(),
                message: &acknowledgment,
                recipient_discovery_key: &alice_discovery_key,
                recipient_identity_verifying_key: alice_contact.identity_key.ed25519_verifying_key,
            },
            &message_route,
        ),
        Err(ProtocolStateError::RelayRoute(
            RelayRouteError::RecipientMismatch
        ))
    ));
    let outcome = engine
        .process_acknowledgment_with_relay_route(
            &mut ChaCha20Rng::from_seed([0x44; 32]),
            &alice_store.snapshot(),
            InboundAcknowledgmentMessage {
                session_key,
                message: &acknowledgment,
                recipient_discovery_key: &alice_discovery_key,
                recipient_identity_verifying_key: alice_contact.identity_key.ed25519_verifying_key,
            },
            &acknowledgment_route,
        )
        .unwrap();
    assert!(matches!(
        outcome,
        AcknowledgmentOutcome::Cleared(ref cleared)
            if cleared.acknowledged_message_id == outbound_message_id
    ));
}

#[test]
fn two_instances_commit_out_of_order_messages_acks_retries_and_resync_in_total_order() {
    let first_instance = ProtocolStateEngine::new();
    let second_instance = ProtocolStateEngine::new();
    let session_key = session_key();
    let deduplication_key = deduplication_key();
    let alice = validated_sender();
    let alice_domain_keys = [alice.domain_signing_key()];
    let revoked = [];
    let bob_sender = recipient_sender_identity();
    let (mut alice_store, mut bob_store) = initialize_stores(
        &first_instance,
        session_key.clone(),
        deduplication_key.clone(),
        &alice.sender_identity,
        &bob_sender,
    );
    let events = InstanceEventStream::with_observer_capacity(Vec::new(), 1).unwrap();
    let ordered_observer = events.subscribe().unwrap();
    let lagged_observer = events.subscribe().unwrap();

    let first = first_instance
        .encrypt_message(
            &alice_store.snapshot(),
            session_key.clone(),
            outbound(0x01, b"first", &alice.sender_identity),
        )
        .unwrap();
    let first_message_id = first.message_id;
    let first_message = first.message;
    alice_store.apply_all(first.state_updates);
    let second = second_instance
        .encrypt_message(
            &alice_store.snapshot(),
            session_key.clone(),
            outbound(0x02, b"second", &alice.sender_identity),
        )
        .unwrap();
    let second_message_id = second.message_id;
    let second_message = second.message;
    alice_store.apply_all(second.state_updates);

    let pending = second_instance
        .pending_acknowledgments(&alice_store.snapshot(), session_key.clone())
        .unwrap();
    assert_eq!(pending.len(), 2);
    assert_eq!(pending[0].message_id, first_message_id);
    assert_eq!(pending[1].message_id, second_message_id);

    let early_retry = first_instance
        .retry_instructions(
            &alice_store.snapshot(),
            session_key.clone(),
            1_700_000_000_001 + RETRY_WINDOW_MILLIS - 1,
            RETRY_WINDOW_MILLIS,
        )
        .unwrap();
    assert!(early_retry.instructions.is_empty());
    assert!(early_retry.state_updates.is_empty());
    let due_retry = second_instance
        .retry_instructions(
            &alice_store.snapshot(),
            session_key.clone(),
            1_700_000_000_002 + RETRY_WINDOW_MILLIS,
            RETRY_WINDOW_MILLIS,
        )
        .unwrap();
    assert_eq!(due_retry.instructions.len(), 2);
    assert_eq!(due_retry.instructions[0].message_id, first_message_id);
    assert_eq!(due_retry.instructions[1].message_id, second_message_id);
    alice_store.apply_all(due_retry.state_updates);

    let second_received = first_instance
        .decrypt_message(
            &mut ChaCha20Rng::from_seed([0x12; 32]),
            &bob_store.snapshot(),
            inbound_with_certificate_validation(
                session_key.clone(),
                deduplication_key.clone(),
                &second_message,
                &bob_sender,
                0x12,
                &alice_domain_keys,
                &revoked,
            ),
        )
        .map(accepted)
        .unwrap();
    assert_eq!(second_received.plaintext.as_slice(), b"second");
    let second_ack = second_received.acknowledgment;
    bob_store.apply_all(second_received.state_updates);
    emit_event(
        &events,
        InstanceEvent::Accepted {
            plaintext: b"second".to_vec(),
        },
    );
    let Some(EventStreamItem::Event(second_event)) = ordered_observer.poll_next().unwrap() else {
        panic!("expected second receive event")
    };
    assert_eq!(second_event.id().as_u64(), 1);
    assert_eq!(
        second_event.event(),
        &InstanceEvent::Accepted {
            plaintext: b"second".to_vec()
        }
    );

    let first_received = second_instance
        .decrypt_message(
            &mut ChaCha20Rng::from_seed([0x13; 32]),
            &bob_store.snapshot(),
            inbound_with_certificate_validation(
                session_key.clone(),
                deduplication_key.clone(),
                &first_message,
                &bob_sender,
                0x13,
                &alice_domain_keys,
                &revoked,
            ),
        )
        .map(accepted)
        .unwrap();
    assert_eq!(first_received.plaintext.as_slice(), b"first");
    bob_store.apply_all(first_received.state_updates);
    emit_event(
        &events,
        InstanceEvent::Accepted {
            plaintext: b"first".to_vec(),
        },
    );
    let Some(EventStreamItem::Event(first_event)) = ordered_observer.poll_next().unwrap() else {
        panic!("expected first receive event")
    };
    assert_eq!(first_event.id().as_u64(), 2);
    assert_eq!(
        first_event.event(),
        &InstanceEvent::Accepted {
            plaintext: b"first".to_vec()
        }
    );

    assert_eq!(
        lagged_observer.poll_next().unwrap(),
        Some(EventStreamItem::Lagged { missed: 1 })
    );
    let resync = events.current_state().unwrap();
    assert_eq!(resync.event_id().as_u64(), 2);
    assert_eq!(resync.state().len(), 2);

    let cleared = first_instance
        .process_acknowledgment(
            &mut ChaCha20Rng::from_seed([0x14; 32]),
            &alice_store.snapshot(),
            inbound_acknowledgment(session_key.clone(), &second_ack),
        )
        .unwrap();
    let AcknowledgmentOutcome::Cleared(cleared) = cleared else {
        panic!("acknowledgment did not clear pending state")
    };
    assert_eq!(cleared.acknowledged_message_id, second_message_id);
    alice_store.apply_all(cleared.state_updates);
    emit_event(
        &events,
        InstanceEvent::AcknowledgmentCleared {
            id: second_message_id,
        },
    );
    let Some(EventStreamItem::Event(cleared_event)) = ordered_observer.poll_next().unwrap() else {
        panic!("expected acknowledgment-cleared event")
    };
    assert_eq!(cleared_event.id().as_u64(), 3);

    lagged_observer.resume_after(&resync).unwrap();
    let Some(EventStreamItem::Event(resumed_event)) = lagged_observer.poll_next().unwrap() else {
        panic!("expected post-resync event")
    };
    assert_eq!(resumed_event.id().as_u64(), 3);
    assert_eq!(
        resumed_event.event(),
        &InstanceEvent::AcknowledgmentCleared {
            id: second_message_id
        }
    );
    assert_eq!(lagged_observer.poll_next().unwrap(), None);

    let remaining = first_instance
        .pending_acknowledgments(&alice_store.snapshot(), session_key)
        .unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].message_id, first_message_id);
    assert_eq!(remaining[0].last_retry_millis, Some(1_700_000_001_002));
}

#[test]
fn blocked_out_of_order_and_duplicate_messages_ack_without_visible_events() {
    let first_instance = ProtocolStateEngine::new().with_blocked_contact_acknowledgment_policy(
        BlockedContactAcknowledgmentPolicy::SilentReceipt,
    );
    let second_instance = ProtocolStateEngine::new().with_blocked_contact_acknowledgment_policy(
        BlockedContactAcknowledgmentPolicy::SilentReceipt,
    );
    let session_key = session_key();
    let deduplication_key = deduplication_key();
    let alice = validated_sender();
    let alice_domain_keys = [alice.domain_signing_key()];
    let revoked = [];
    let bob_sender = recipient_sender_identity();
    let (mut alice_store, mut bob_store) = initialize_stores(
        &first_instance,
        session_key.clone(),
        deduplication_key.clone(),
        &alice.sender_identity,
        &bob_sender,
    );
    block_accepted_contact(&first_instance, &mut bob_store);
    let events = InstanceEventStream::new(Vec::new());

    let first = first_instance
        .encrypt_message(
            &alice_store.snapshot(),
            session_key.clone(),
            outbound(0x61, b"blocked first", &alice.sender_identity),
        )
        .unwrap();
    let first_message_id = first.message_id;
    let first_message = first.message;
    alice_store.apply_all(first.state_updates);
    let second = second_instance
        .encrypt_message(
            &alice_store.snapshot(),
            session_key.clone(),
            outbound(0x62, b"blocked second", &alice.sender_identity),
        )
        .unwrap();
    let second_message_id = second.message_id;
    let second_message = second.message;
    alice_store.apply_all(second.state_updates);

    let second_blocked = first_instance
        .decrypt_message(
            &mut ChaCha20Rng::from_seed([0x61; 32]),
            &bob_store.snapshot(),
            inbound_with_certificate_validation(
                session_key.clone(),
                deduplication_key.clone(),
                &second_message,
                &bob_sender,
                0x71,
                &alice_domain_keys,
                &revoked,
            ),
        )
        .map(blocked)
        .unwrap();
    let second_ack = second_blocked
        .acknowledgment
        .expect("silent-receipt returns an acknowledgment");
    bob_store.apply_all(second_blocked.state_updates);
    assert!(events.current_state().unwrap().state().is_empty());

    let first_blocked = second_instance
        .decrypt_message(
            &mut ChaCha20Rng::from_seed([0x62; 32]),
            &bob_store.snapshot(),
            inbound_with_certificate_validation(
                session_key.clone(),
                deduplication_key.clone(),
                &first_message,
                &bob_sender,
                0x72,
                &alice_domain_keys,
                &revoked,
            ),
        )
        .map(blocked)
        .unwrap();
    bob_store.apply_all(first_blocked.state_updates);
    assert!(events.current_state().unwrap().state().is_empty());

    let duplicate = first_instance
        .decrypt_message(
            &mut ChaCha20Rng::from_seed([0x63; 32]),
            &bob_store.snapshot(),
            inbound_with_certificate_validation(
                session_key.clone(),
                deduplication_key.clone(),
                &second_message,
                &bob_sender,
                0x73,
                &alice_domain_keys,
                &revoked,
            ),
        )
        .unwrap();
    assert!(matches!(duplicate, InboundMessageOutcome::Duplicate));
    assert!(events.current_state().unwrap().state().is_empty());

    let cleared = second_instance
        .process_acknowledgment(
            &mut ChaCha20Rng::from_seed([0x64; 32]),
            &alice_store.snapshot(),
            inbound_acknowledgment(session_key.clone(), &second_ack),
        )
        .unwrap();
    let AcknowledgmentOutcome::Cleared(cleared) = cleared else {
        panic!("acknowledgment did not clear pending state")
    };
    assert_eq!(cleared.acknowledged_message_id, second_message_id);
    alice_store.apply_all(cleared.state_updates);

    let pending = first_instance
        .pending_acknowledgments(&alice_store.snapshot(), session_key)
        .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].message_id, first_message_id);
}

#[test]
fn duplicate_messages_and_ack_replays_are_idempotent_across_instance_recreation() {
    let first_instance = ProtocolStateEngine::new();
    let second_instance = ProtocolStateEngine::new();
    let session_key = session_key();
    let deduplication_key = deduplication_key();
    let alice = validated_sender();
    let alice_domain_keys = [alice.domain_signing_key()];
    let revoked = [];
    let bob_sender = recipient_sender_identity();
    let (mut alice_store, mut bob_store) = initialize_stores(
        &first_instance,
        session_key.clone(),
        deduplication_key.clone(),
        &alice.sender_identity,
        &bob_sender,
    );
    let events = InstanceEventStream::new(Vec::new());

    let encrypted = first_instance
        .encrypt_message(
            &alice_store.snapshot(),
            session_key.clone(),
            outbound(0x31, b"deliver once", &alice.sender_identity),
        )
        .unwrap();
    let message = encrypted.message;
    alice_store.apply_all(encrypted.state_updates);
    let received = second_instance
        .decrypt_message(
            &mut ChaCha20Rng::from_seed([0x31; 32]),
            &bob_store.snapshot(),
            inbound_with_certificate_validation(
                session_key.clone(),
                deduplication_key.clone(),
                &message,
                &bob_sender,
                0x41,
                &alice_domain_keys,
                &revoked,
            ),
        )
        .map(accepted)
        .unwrap();
    let acknowledgment = received.acknowledgment;
    bob_store.apply_all(received.state_updates);
    emit_event(
        &events,
        InstanceEvent::Accepted {
            plaintext: b"deliver once".to_vec(),
        },
    );
    assert_eq!(events.current_state().unwrap().event_id().as_u64(), 1);

    let mut corrupt_duplicate_store = bob_store.clone();
    corrupt_duplicate_store.set_raw(ratchet_address(session_key.clone()), vec![1, 0, 0xaa]);
    let duplicate = first_instance
        .decrypt_message(
            &mut ChaCha20Rng::from_seed([0x32; 32]),
            &corrupt_duplicate_store.snapshot(),
            inbound(
                session_key.clone(),
                deduplication_key.clone(),
                &message,
                &bob_sender,
                0x42,
            ),
        )
        .unwrap();
    assert!(matches!(duplicate, InboundMessageOutcome::Duplicate));
    assert_eq!(events.current_state().unwrap().event_id().as_u64(), 1);

    let restarted_instance = ProtocolStateEngine::new();
    let duplicate_after_restart = restarted_instance
        .decrypt_message(
            &mut ChaCha20Rng::from_seed([0x33; 32]),
            &bob_store.snapshot(),
            inbound(
                session_key.clone(),
                deduplication_key,
                &message,
                &bob_sender,
                0x43,
            ),
        )
        .unwrap();
    assert!(matches!(
        duplicate_after_restart,
        InboundMessageOutcome::Duplicate
    ));

    let cleared = second_instance
        .process_acknowledgment(
            &mut ChaCha20Rng::from_seed([0x34; 32]),
            &alice_store.snapshot(),
            inbound_acknowledgment(session_key.clone(), &acknowledgment),
        )
        .unwrap();
    let AcknowledgmentOutcome::Cleared(cleared) = cleared else {
        panic!("acknowledgment did not clear pending state")
    };
    alice_store.apply_all(cleared.state_updates);

    let mut corrupt_ack_store = alice_store.clone();
    corrupt_ack_store.set_raw(ratchet_address(session_key.clone()), vec![1, 0, 0xaa]);
    let replay = ProtocolStateEngine::new()
        .process_acknowledgment(
            &mut ChaCha20Rng::from_seed([0x35; 32]),
            &corrupt_ack_store.snapshot(),
            inbound_acknowledgment(session_key, &acknowledgment),
        )
        .unwrap();
    assert!(matches!(replay, AcknowledgmentOutcome::Duplicate));
}
