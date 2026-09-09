//! Verifies checked-in Protocol State Blob fixtures across the public Core API.

use rand::RngCore;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use roost_core::{
    AcknowledgmentOutcome, ContactDiscoveryKey, ContactIdentity, ContactIdentityKey,
    ContactSafetyNumberConfirmation, ContactTrustState, DEFAULT_DEDUPLICATION_CAPACITY,
    IdentityKey, InboundAcknowledgmentMessage, InboundEncryptedMessage, InboundMessageOutcome,
    Message, OutboundAcknowledgment, OutboundPlaintext, ProtocolStateAddress, ProtocolStateBlob,
    ProtocolStateEngine, ProtocolStateError, ProtocolStateKey, ProtocolStateKind,
    ProtocolStateSnapshot, SenderIdentityMaterial, SessionId, derive_safety_number,
};
use roost_crypto::{
    DiscoveryKey, IdentityKeyBundle, InitialPlaintext, KeyPair, PreKeyBundle, RatchetState,
    SigningKeyPair, accept, generate_discovery_key, generate_key_pair, generate_one_time_prekey,
    generate_signed_prekey_for_discovery_key, generate_signing_key_pair, initiate,
    sign_identity_key_binding,
};
use roost_protocol::MessageId;
use serde::{Deserialize, Serialize};

const CREATED_AT: u64 = 1_700_000_000;

#[derive(Deserialize)]
struct FixtureFile {
    provenance: String,
    current_version: Version,
    fixtures: Vec<Fixture>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
struct Version {
    major: u8,
    minor: u8,
}

#[derive(Deserialize)]
struct Fixture {
    name: String,
    kind: String,
    key_hex: String,
    current_encoded_hex: String,
    decoded: DecodedFixture,
    replay: Option<ReplayFixture>,
}

#[derive(Deserialize)]
struct DecodedFixture {
    skipped_key_count: Option<usize>,
    digest_count: Option<usize>,
    pending_count: Option<usize>,
    acknowledgment_digest_count: Option<usize>,
    capacity: Option<usize>,
    trust_state: Option<String>,
    blocked: Option<bool>,
    discovery_epoch: Option<u32>,
    discovery_created_at: Option<u64>,
}

#[derive(Deserialize)]
struct ReplayFixture {
    encoded_message_hex: String,
    digest_hex: String,
}

#[derive(Serialize)]
struct TestSessionStateWire<'a> {
    version: u8,
    status: u8,
    ratchet_state: &'a [u8],
    peer_sender_identity_key: Option<[u8; 32]>,
}

struct Setup {
    alice_state: RatchetState,
    bob_state: RatchetState,
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
        version: roost_crypto::PREKEY_BUNDLE_VERSION,
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

fn fixture_file() -> FixtureFile {
    serde_json::from_str(include_str!("fixtures/protocol_state_blobs_v1.json")).unwrap()
}

fn session_key() -> ProtocolStateKey {
    ProtocolStateKey::session(SessionId::from_bytes([9u8; 16]))
}

fn session_address(key: ProtocolStateKey) -> ProtocolStateAddress {
    ProtocolStateAddress::new(ProtocolStateKind::RatchetSession, key)
}

fn deduplication_key() -> ProtocolStateKey {
    ProtocolStateKey::from_bytes(vec![0xdd; 16]).unwrap()
}

fn deduplication_address(key: ProtocolStateKey) -> ProtocolStateAddress {
    ProtocolStateAddress::new(ProtocolStateKind::DeduplicationSet, key)
}

fn pending_acknowledgment_address(key: ProtocolStateKey) -> ProtocolStateAddress {
    ProtocolStateAddress::new(ProtocolStateKind::PendingAcknowledgments, key)
}

fn accepted_contact_identity() -> ContactIdentity {
    contact_fixture_identities().0
}

fn accepted_contact_discovery_key() -> DiscoveryKey {
    let mut rng = ChaCha20Rng::from_seed([0x71; 32]);
    let identity = generate_signing_key_pair(&mut rng);
    let _identity_key_pair = generate_key_pair(&mut rng);
    generate_discovery_key(&mut rng, &identity, 0, CREATED_AT)
}

fn local_identity_key() -> IdentityKey {
    let mut rng = ChaCha20Rng::from_seed([0x72; 32]);
    let identity = generate_signing_key_pair(&mut rng);
    let identity_key_pair = generate_key_pair(&mut rng);
    IdentityKey {
        x25519_public_key: *identity_key_pair.public.as_bytes(),
        ed25519_verifying_key: identity.verifying.to_bytes(),
    }
}

fn contact_fixture_identities() -> (ContactIdentity, ContactIdentity) {
    let mut rng = ChaCha20Rng::from_seed([0x71; 32]);
    let identity = generate_signing_key_pair(&mut rng);
    let identity_key_pair = generate_key_pair(&mut rng);
    let discovery_key = generate_discovery_key(&mut rng, &identity, 0, CREATED_AT);
    let rotated_discovery_key = generate_discovery_key(&mut rng, &identity, 1, CREATED_AT + 60);
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

fn contact_key_hex() -> String {
    hex::encode(
        accepted_contact_identity()
            .identity_key
            .canonical_encoding(),
    )
}

fn expected_contact_fixture(
    engine: &ProtocolStateEngine,
    name: &str,
) -> roost_core::ProtocolStateUpdate {
    let (contact, rotated_contact) = contact_fixture_identities();
    let mut snapshot = ProtocolStateSnapshot::new();
    let pending = engine.record_contact(&snapshot, contact).unwrap();
    if name == "contact_pending" {
        return pending.state_updates.into_iter().next().unwrap();
    }
    snapshot.apply_all(pending.state_updates).unwrap();
    if name == "contact_blocked_pending" {
        return engine
            .block_contact(&snapshot, contact.identity_key)
            .unwrap()
            .state_updates
            .into_iter()
            .next()
            .unwrap();
    }

    let unverified = engine
        .accept_contact(&snapshot, contact.identity_key)
        .unwrap();
    if name == "contact_unverified" {
        return unverified.state_updates.into_iter().next().unwrap();
    }
    snapshot.apply_all(unverified.state_updates).unwrap();
    if name == "contact_blocked_unverified" {
        return engine
            .block_contact(&snapshot, contact.identity_key)
            .unwrap()
            .state_updates
            .into_iter()
            .next()
            .unwrap();
    }

    if name == "contact_dk_rotated_unverified" {
        return engine
            .record_contact(&snapshot, rotated_contact)
            .unwrap()
            .state_updates
            .into_iter()
            .next()
            .unwrap();
    }
    if name == "contact_dk_rotated_blocked" {
        let blocked = engine
            .block_contact(&snapshot, contact.identity_key)
            .unwrap();
        snapshot.apply_all(blocked.state_updates).unwrap();
        return engine
            .record_contact(&snapshot, rotated_contact)
            .unwrap()
            .state_updates
            .into_iter()
            .next()
            .unwrap();
    }

    let local_identity_key = local_identity_key();
    let safety_number = derive_safety_number(local_identity_key, contact.identity_key).unwrap();
    let verified = engine
        .confirm_contact_safety_number(
            &snapshot,
            local_identity_key,
            contact.identity_key,
            &safety_number.grouped_decimal,
        )
        .unwrap();
    let ContactSafetyNumberConfirmation::Matched(verified) = verified else {
        panic!("fixture safety number did not match");
    };
    if name == "contact_verified" {
        return verified.state_updates.into_iter().next().unwrap();
    }
    snapshot.apply_all(verified.state_updates).unwrap();
    if name == "contact_blocked_verified" {
        return engine
            .block_contact(&snapshot, contact.identity_key)
            .unwrap()
            .state_updates
            .into_iter()
            .next()
            .unwrap();
    }
    if name == "contact_unblocked_restored_state" {
        let blocked = engine
            .block_contact(&snapshot, contact.identity_key)
            .unwrap();
        snapshot.apply_all(blocked.state_updates).unwrap();
        return engine
            .unblock_contact(&snapshot, contact.identity_key)
            .unwrap()
            .state_updates
            .into_iter()
            .next()
            .unwrap();
    }

    engine
        .record_contact(&snapshot, rotated_contact)
        .unwrap()
        .state_updates
        .into_iter()
        .next()
        .unwrap()
}

fn expected_contact_trust_state(fixture: &Fixture) -> ContactTrustState {
    match fixture.name.as_str() {
        "contact_pending" | "contact_blocked_pending" => ContactTrustState::Pending,
        "contact_unverified"
        | "contact_blocked_unverified"
        | "contact_dk_rotated_unverified"
        | "contact_dk_rotated_blocked" => ContactTrustState::Unverified,
        "contact_verified"
        | "contact_blocked_verified"
        | "contact_dk_rotated_verified"
        | "contact_unblocked_restored_state" => ContactTrustState::Verified,
        _ => panic!("not a contact fixture: {}", fixture.name),
    }
}

fn expected_contact_epoch(fixture: &Fixture) -> u32 {
    match fixture.name.as_str() {
        "contact_dk_rotated_unverified"
        | "contact_dk_rotated_verified"
        | "contact_dk_rotated_blocked" => 1,
        _ => 0,
    }
}

fn expected_contact_created_at(fixture: &Fixture) -> u64 {
    match fixture.name.as_str() {
        "contact_dk_rotated_unverified"
        | "contact_dk_rotated_verified"
        | "contact_dk_rotated_blocked" => CREATED_AT + 60,
        _ => CREATED_AT,
    }
}

fn expected_contact_blocked(fixture: &Fixture) -> bool {
    matches!(
        fixture.name.as_str(),
        "contact_blocked_pending"
            | "contact_blocked_unverified"
            | "contact_blocked_verified"
            | "contact_dk_rotated_blocked"
    )
}

fn contact_state_name(state: ContactTrustState) -> &'static str {
    match state {
        ContactTrustState::Pending => "pending",
        ContactTrustState::Unverified => "unverified",
        ContactTrustState::Verified => "verified",
    }
}

fn contact_fixture<'a>(fixture_file: &'a FixtureFile, name: &str) -> &'a Fixture {
    fixture_named(fixture_file, name)
}

fn fixture_named<'a>(fixture_file: &'a FixtureFile, name: &str) -> &'a Fixture {
    fixture_file
        .fixtures
        .iter()
        .find(|fixture| fixture.name == name)
        .unwrap()
}

fn contact_fixture_names() -> &'static [&'static str] {
    &[
        "contact_pending",
        "contact_unverified",
        "contact_verified",
        "contact_dk_rotated_unverified",
        "contact_dk_rotated_verified",
        "contact_blocked_pending",
        "contact_blocked_unverified",
        "contact_blocked_verified",
        "contact_dk_rotated_blocked",
        "contact_unblocked_restored_state",
    ]
}

fn install_accepted_contact(engine: &ProtocolStateEngine, snapshot: &mut ProtocolStateSnapshot) {
    let contact = accepted_contact_identity();
    let created = engine.record_contact(snapshot, contact).unwrap();
    snapshot.apply_all(created.state_updates).unwrap();
    let accepted = engine
        .accept_contact(snapshot, contact.identity_key)
        .unwrap();
    snapshot.apply_all(accepted.state_updates).unwrap();
}

fn outbound<'a>(
    plaintext: &'a [u8],
    sender_identity: &'a SenderIdentityMaterial,
    signing_key: &'a SigningKeyPair,
) -> OutboundPlaintext<'a> {
    let contact = accepted_contact_identity();
    OutboundPlaintext {
        id: MessageId::from_bytes([1u8; 16]),
        sender_identity,
        sender_identity_signing_key: signing_key,
        contact_identity_key: contact.identity_key,
        recipient_public_key: contact.discovery_key.prekey_bundle_lookup_key(),
        timestamp_millis: 1_700_000_000_123,
        plaintext,
    }
}

fn sender_identity() -> SenderIdentityMaterial {
    let signing_key = sender_identity_signing_key();
    let identity_key_pair = KeyPair::from_secret_bytes([0x34; 32]);
    let binding_signature =
        sign_identity_key_binding(&signing_key, &identity_key_pair.public).unwrap();
    SenderIdentityMaterial {
        identity_key: *identity_key_pair.public.as_bytes(),
        identity_verifying_key: signing_key.verifying.to_bytes(),
        identity_binding_signature: binding_signature.to_bytes().to_vec(),
        certificate: vec![2, 3, 4],
        signature: vec![5; 64],
    }
}

fn sender_identity_signing_key() -> SigningKeyPair {
    SigningKeyPair::from_signing_bytes([1u8; 32])
}

fn acknowledgment<'a>(
    sender_identity: &'a SenderIdentityMaterial,
    signing_key: &'a SigningKeyPair,
) -> OutboundAcknowledgment<'a> {
    OutboundAcknowledgment {
        id: MessageId::from_bytes([0xee; 16]),
        sender_identity,
        sender_identity_signing_key: signing_key,
        recipient_public_key: [0xb6; 32],
        timestamp_millis: 1_700_000_100_000,
    }
}

#[test]
fn current_version_fixture_matches_decoded_state_expectations() {
    let fixture_file = fixture_file();
    let fixture = &fixture_file.fixtures[0];
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = session_key();
    let address = session_address(key.clone());
    let current = hex::decode(&fixture.current_encoded_hex).unwrap();

    assert!(fixture_file.provenance.contains("test-only"));
    assert_eq!(fixture_file.current_version.major, 1);
    assert_eq!(fixture_file.current_version.minor, 0);
    assert_eq!(fixture.name, "ratchet_session_alice");
    assert_eq!(fixture.kind, "ratchet_session");
    assert_eq!(hex::decode(&fixture.key_hex).unwrap(), key.as_bytes());
    assert_eq!(current[..2], [1, 0]);
    assert_eq!(fixture.decoded.skipped_key_count, Some(0));

    let expected = engine
        .set_session_state(key.clone(), &setup.alice_state)
        .unwrap();
    assert_eq!(
        expected.blob().unwrap().as_bytes(),
        current.as_slice(),
        "fixture pins the canonical encoded bytes for the decoded state"
    );

    let mut fixture_snapshot = ProtocolStateSnapshot::new();
    fixture_snapshot
        .set(address.clone(), ProtocolStateBlob::from_bytes(current))
        .unwrap();
    insert_pending_acknowledgment_fixture(&mut fixture_snapshot, &fixture_file, key.clone());
    install_accepted_contact(&engine, &mut fixture_snapshot);

    let mut expected_snapshot = ProtocolStateSnapshot::new();
    expected_snapshot.apply(expected).unwrap();
    expected_snapshot
        .apply(
            engine
                .initialize_pending_acknowledgments(key.clone())
                .unwrap(),
        )
        .unwrap();
    install_accepted_contact(&engine, &mut expected_snapshot);
    let sender_identity = sender_identity();
    let fixture_result = engine
        .encrypt_message_with_transport_binding(
            &fixture_snapshot,
            key.clone(),
            outbound(b"fixture", &sender_identity, &sender_identity_signing_key()),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap();
    let expected_result = engine
        .encrypt_message_with_transport_binding(
            &expected_snapshot,
            key,
            outbound(b"fixture", &sender_identity, &sender_identity_signing_key()),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap();
    assert_eq!(fixture_result.message_id, expected_result.message_id);
    assert_eq!(
        fixture_result.timestamp_millis,
        expected_result.timestamp_millis
    );
    assert_eq!(fixture_result.payload_kind, expected_result.payload_kind);
    assert_eq!(
        fixture_result.message.recipient_public_key,
        expected_result.message.recipient_public_key
    );
    assert_eq!(
        fixture_result.state_updates[0].blob().unwrap().as_bytes(),
        expected_result.state_updates[0].blob().unwrap().as_bytes()
    );
}

#[test]
fn bound_peer_identity_fixture_matches_decoded_state_expectations() {
    let fixture_file = fixture_file();
    let fixture = &fixture_file.fixtures[1];
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = session_key();
    let address = session_address(key.clone());
    let current = hex::decode(&fixture.current_encoded_hex).unwrap();
    let sender_identity = sender_identity();

    assert_eq!(fixture.name, "ratchet_session_bob_bound");
    assert_eq!(fixture.kind, "ratchet_session");
    assert_eq!(hex::decode(&fixture.key_hex).unwrap(), key.as_bytes());
    assert_eq!(current[..2], [1, 0]);
    assert_eq!(fixture.decoded.skipped_key_count, Some(0));

    let expected = engine
        .set_session_state_with_peer_identity(key.clone(), &setup.bob_state, &sender_identity)
        .unwrap();
    assert_eq!(
        expected.blob().unwrap().as_bytes(),
        current.as_slice(),
        "fixture pins the canonical encoded bytes for a peer-bound session"
    );

    let mut fixture_snapshot = ProtocolStateSnapshot::new();
    fixture_snapshot
        .set(address, ProtocolStateBlob::from_bytes(current))
        .unwrap();
    let update = engine
        .bind_session_state_peer_identity_key(&fixture_snapshot, key, sender_identity.identity_key)
        .unwrap();
    assert_eq!(
        update.blob().unwrap().as_bytes(),
        expected.blob().unwrap().as_bytes()
    );
}

#[test]
fn deduplication_set_fixture_matches_decoded_state_expectations() {
    let fixture_file = fixture_file();
    let fixture = fixture_named(&fixture_file, "deduplication_set_identity");
    let engine = ProtocolStateEngine::new();
    let key = deduplication_key();
    let address = deduplication_address(key.clone());
    let current = hex::decode(&fixture.current_encoded_hex).unwrap();

    assert_eq!(fixture.name, "deduplication_set_identity");
    assert_eq!(fixture.kind, "deduplication_set");
    assert_eq!(hex::decode(&fixture.key_hex).unwrap(), key.as_bytes());
    assert_eq!(current[..2], [1, 0]);
    assert_eq!(fixture.decoded.digest_count, Some(0));
    assert_eq!(
        fixture.decoded.capacity,
        Some(DEFAULT_DEDUPLICATION_CAPACITY)
    );

    let expected = engine
        .initialize_deduplication_set(&mut ChaCha20Rng::from_seed([0x44; 32]), key.clone())
        .unwrap();
    assert_eq!(
        hex::encode(expected.blob().unwrap().as_bytes()),
        fixture.current_encoded_hex,
        "fixture pins the canonical encoded bytes for an empty deduplication set"
    );

    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot
        .set(address.clone(), ProtocolStateBlob::from_bytes(current))
        .unwrap();
    assert!(snapshot.get(&address).is_some());
}

#[test]
fn pending_acknowledgments_fixture_matches_decoded_state_expectations() {
    let fixture_file = fixture_file();
    let fixture = fixture_named(&fixture_file, "pending_acknowledgments_session");
    let engine = ProtocolStateEngine::new();
    let key = session_key();
    let address = pending_acknowledgment_address(key.clone());
    let current = hex::decode(&fixture.current_encoded_hex).unwrap();

    assert_eq!(fixture.name, "pending_acknowledgments_session");
    assert_eq!(fixture.kind, "pending_acknowledgments");
    assert_eq!(hex::decode(&fixture.key_hex).unwrap(), key.as_bytes());
    assert_eq!(current[..2], [1, 0]);
    assert_eq!(fixture.decoded.pending_count, Some(0));
    assert_eq!(fixture.decoded.acknowledgment_digest_count, Some(0));

    let expected = engine
        .initialize_pending_acknowledgments(key.clone())
        .unwrap();
    assert_eq!(
        hex::encode(expected.blob().unwrap().as_bytes()),
        fixture.current_encoded_hex,
        "fixture pins the canonical encoded bytes for empty pending acknowledgments"
    );

    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot
        .set(address.clone(), ProtocolStateBlob::from_bytes(current))
        .unwrap();
    assert!(snapshot.get(&address).is_some());
}

#[test]
fn deduplication_replay_fixture_rejects_duplicate_message() {
    let fixture_file = fixture_file();
    let fixture = fixture_named(
        &fixture_file,
        "deduplication_set_identity_with_duplicate_message",
    );
    let engine = ProtocolStateEngine::new();
    let key = deduplication_key();
    let address = deduplication_address(key.clone());
    let current = hex::decode(&fixture.current_encoded_hex).unwrap();

    assert_eq!(fixture.kind, "deduplication_set");
    assert_eq!(hex::decode(&fixture.key_hex).unwrap(), key.as_bytes());
    assert_eq!(current[..2], [1, 0]);
    assert_eq!(fixture.decoded.digest_count, Some(1));
    assert_eq!(
        fixture.decoded.capacity,
        Some(DEFAULT_DEDUPLICATION_CAPACITY)
    );

    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot
        .set(address, ProtocolStateBlob::from_bytes(current))
        .unwrap();
    assert_duplicate_inbound_replay(&engine, &snapshot, fixture);
}

#[test]
fn pending_acknowledgment_replay_fixture_rejects_duplicate_acknowledgment() {
    let fixture_file = fixture_file();
    let fixture = fixture_named(
        &fixture_file,
        "pending_acknowledgments_session_with_duplicate_ack",
    );
    let engine = ProtocolStateEngine::new();
    let key = session_key();
    let address = pending_acknowledgment_address(key.clone());
    let current = hex::decode(&fixture.current_encoded_hex).unwrap();

    assert_eq!(fixture.kind, "pending_acknowledgments");
    assert_eq!(hex::decode(&fixture.key_hex).unwrap(), key.as_bytes());
    assert_eq!(current[..2], [1, 0]);
    assert_eq!(fixture.decoded.pending_count, Some(0));
    assert_eq!(fixture.decoded.acknowledgment_digest_count, Some(1));

    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot
        .set(address, ProtocolStateBlob::from_bytes(current))
        .unwrap();
    assert_duplicate_acknowledgment_replay(&engine, &snapshot, fixture);
}

fn assert_duplicate_inbound_replay(
    engine: &ProtocolStateEngine,
    snapshot: &ProtocolStateSnapshot,
    fixture: &Fixture,
) {
    let replay = fixture.replay.as_ref().unwrap();
    let encoded = hex::decode(&replay.encoded_message_hex).unwrap();
    let message = Message::from_bytes(&encoded).unwrap();
    assert_eq!(message.version, 1);
    assert!(message.prekey_reference.is_none());
    let mut digest_key = [0u8; 32];
    ChaCha20Rng::from_seed([0x44; 32]).fill_bytes(&mut digest_key);
    assert_eq!(
        keyed_digest_hex(&digest_key, &encoded),
        replay.digest_hex,
        "{} replay digest",
        fixture.name
    );

    let acknowledgment_sender = sender_identity();
    let outcome = engine
        .decrypt_message_with_transport_bindings(
            &mut ChaCha20Rng::from_seed([0x55; 32]),
            snapshot,
            InboundEncryptedMessage {
                session_key: session_key(),
                deduplication_key: deduplication_key(),
                message: &message,
                recipient_discovery_key: &accepted_contact_discovery_key(),
                recipient_identity_verifying_key: accepted_contact_identity()
                    .identity_key
                    .ed25519_verifying_key,
                acknowledgment: acknowledgment(
                    &acknowledgment_sender,
                    &sender_identity_signing_key(),
                ),
                sender_certificate_validation: None,
            },
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap();
    assert!(matches!(outcome, InboundMessageOutcome::Duplicate));
}

fn assert_duplicate_acknowledgment_replay(
    engine: &ProtocolStateEngine,
    snapshot: &ProtocolStateSnapshot,
    fixture: &Fixture,
) {
    let replay = fixture.replay.as_ref().unwrap();
    let encoded = hex::decode(&replay.encoded_message_hex).unwrap();
    let message = Message::from_bytes(&encoded).unwrap();
    assert_eq!(message.version, 1);
    assert!(message.prekey_reference.is_none());
    assert_eq!(
        digest_hex(&encoded),
        replay.digest_hex,
        "{} replay digest",
        fixture.name
    );

    let outcome = engine
        .process_acknowledgment_with_transport_binding(
            &mut ChaCha20Rng::from_seed([0x56; 32]),
            snapshot,
            InboundAcknowledgmentMessage {
                session_key: session_key(),
                message: &message,
                recipient_discovery_key: &accepted_contact_discovery_key(),
                recipient_identity_verifying_key: accepted_contact_identity()
                    .identity_key
                    .ed25519_verifying_key,
            },
            &roost_core::TransportBinding::new(b"test-route".to_vec()).unwrap(),
        )
        .unwrap();
    assert!(matches!(outcome, AcknowledgmentOutcome::Duplicate));
}

fn framed_replay_message(encoded: &[u8]) -> Vec<u8> {
    let binding = b"test-route";
    let mut framed = (binding.len() as u32).to_be_bytes().to_vec();
    framed.extend_from_slice(binding);
    framed.extend_from_slice(encoded);
    framed
}

fn keyed_digest_hex(key: &[u8; 32], encoded: &[u8]) -> String {
    let input = framed_replay_message(encoded);
    let hash = blake3::keyed_hash(key, &input);
    hex::encode(&hash.as_bytes()[..16])
}

fn digest_hex(encoded: &[u8]) -> String {
    let input = framed_replay_message(encoded);
    let hash = blake3::hash(&input);
    hex::encode(&hash.as_bytes()[..16])
}

#[test]
fn contact_state_fixtures_match_decoded_state_expectations() {
    let fixture_file = fixture_file();
    let engine = ProtocolStateEngine::new();
    let contact_key = ProtocolStateKey::from_bytes(
        accepted_contact_identity()
            .identity_key
            .canonical_encoding()
            .to_vec(),
    )
    .unwrap();
    let address = ProtocolStateAddress::new(ProtocolStateKind::ContactState, contact_key);

    for name in contact_fixture_names() {
        let fixture = contact_fixture(&fixture_file, name);
        let current = hex::decode(&fixture.current_encoded_hex).unwrap();
        let expected = expected_contact_fixture(&engine, name);
        let expected_trust = expected_contact_trust_state(fixture);

        assert_eq!(fixture.kind, "contact_state");
        assert_eq!(fixture.key_hex, contact_key_hex());
        assert_eq!(current[..2], [1, 0]);
        assert_eq!(
            fixture.decoded.trust_state.as_deref(),
            Some(contact_state_name(expected_trust))
        );
        assert_eq!(
            fixture.decoded.blocked,
            Some(expected_contact_blocked(fixture))
        );
        assert_eq!(
            fixture.decoded.discovery_epoch,
            Some(expected_contact_epoch(fixture))
        );
        assert_eq!(
            fixture.decoded.discovery_created_at,
            Some(expected_contact_created_at(fixture))
        );
        assert_eq!(
            hex::encode(expected.blob().unwrap().as_bytes()),
            fixture.current_encoded_hex,
            "fixture pins the canonical encoded bytes for {name}"
        );

        let mut snapshot = ProtocolStateSnapshot::new();
        snapshot
            .set(address.clone(), ProtocolStateBlob::from_bytes(current))
            .unwrap();
        let contact = engine
            .contact_state(&snapshot, accepted_contact_identity().identity_key)
            .unwrap()
            .unwrap();
        assert_eq!(contact.trust_state, expected_trust);
        assert_eq!(contact.blocked, expected_contact_blocked(fixture));
        assert_eq!(
            contact.identity.discovery_key.epoch,
            expected_contact_epoch(fixture)
        );
        assert_eq!(
            contact.identity.discovery_key.created_at,
            expected_contact_created_at(fixture)
        );
    }
}

fn insert_pending_acknowledgment_fixture(
    snapshot: &mut ProtocolStateSnapshot,
    fixture_file: &FixtureFile,
    key: ProtocolStateKey,
) {
    let fixture = fixture_file
        .fixtures
        .iter()
        .find(|fixture| fixture.name == "pending_acknowledgments_session")
        .unwrap();
    snapshot
        .set(
            pending_acknowledgment_address(key),
            ProtocolStateBlob::from_bytes(hex::decode(&fixture.current_encoded_hex).unwrap()),
        )
        .unwrap();
}

#[test]
fn flat_ratchet_state_blob_is_rejected_as_malformed_current_blob() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let key = session_key();
    let address = session_address(key.clone());
    let mut flat_blob = vec![1, 0];
    flat_blob.extend_from_slice(&setup.alice_state.to_bytes().unwrap());
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot
        .set(address.clone(), ProtocolStateBlob::from_bytes(flat_blob))
        .unwrap();

    assert!(matches!(
        engine.bind_session_state_peer_identity_key(&snapshot, key, [1u8; 32]),
        Err(ProtocolStateError::BlobDecode { address: actual, .. }) if actual == address
    ));
}

#[test]
fn non_current_envelope_versions_are_faults() {
    let engine = ProtocolStateEngine::new();
    for (major, minor) in [(2, 0), (0, 1), (1, 1)] {
        let key = session_key();
        let address = session_address(key.clone());
        let mut snapshot = ProtocolStateSnapshot::new();
        snapshot
            .set(
                address.clone(),
                ProtocolStateBlob::from_bytes(vec![major, minor, 0xaa]),
            )
            .unwrap();
        assert!(matches!(
            engine.bind_session_state_peer_identity_key(&snapshot, key, [1; 32]),
            Err(ProtocolStateError::UnsupportedBlobVersion { address: actual, major: actual_major, minor: actual_minor })
                if actual == address && actual_major == major && actual_minor == minor
        ));
    }
}

#[test]
fn malformed_current_blob_is_a_fault() {
    let engine = ProtocolStateEngine::new();
    let key = session_key();
    let address = session_address(key.clone());
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot
        .set(
            address.clone(),
            ProtocolStateBlob::from_bytes(vec![1, 0, 0xaa]),
        )
        .unwrap();

    assert!(matches!(
        engine.bind_session_state_peer_identity_key(&snapshot, key, [1u8; 32]),
        Err(ProtocolStateError::BlobDecode { address: actual, .. }) if actual == address
    ));
}

#[test]
fn nested_ratchet_decode_failure_does_not_echo_state_bytes() {
    const SECRET_DERIVED_BYTE: u8 = 0x42;

    let engine = ProtocolStateEngine::new();
    let key = session_key();
    let address = session_address(key.clone());
    let payload = postcard::to_stdvec(&TestSessionStateWire {
        version: 4,
        status: 0,
        ratchet_state: &[SECRET_DERIVED_BYTE],
        peer_sender_identity_key: None,
    })
    .unwrap();
    let mut blob = vec![1, 0];
    blob.extend_from_slice(&payload);
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot
        .set(address.clone(), ProtocolStateBlob::from_bytes(blob))
        .unwrap();

    let err = match engine.bind_session_state_peer_identity_key(&snapshot, key, [1u8; 32]) {
        Ok(_) => panic!("malformed nested ratchet state decoded"),
        Err(err) => err,
    };
    let rendered = err.to_string();
    match err {
        ProtocolStateError::BlobDecode {
            address: actual,
            reason,
        } => {
            assert_eq!(actual, address);
            assert_eq!(reason, "ratchet/session state failed to decode");
        }
        other => panic!("unexpected error: {other}"),
    }
    assert!(!rendered.contains("66"));
    assert!(!rendered.contains("0x42"));
}
