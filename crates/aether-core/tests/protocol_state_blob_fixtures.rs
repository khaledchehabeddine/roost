//! Verifies checked-in Protocol State Blob fixtures across the public Core API.

use aether_core::{
    DEFAULT_DEDUPLICATION_CAPACITY, MessageId, OutboundPlaintext, ProtocolStateAddress,
    ProtocolStateBlob, ProtocolStateEngine, ProtocolStateError, ProtocolStateKey,
    ProtocolStateKind, ProtocolStateSnapshot, SenderIdentityMaterial, SessionId,
};
use aether_crypto::{
    InitialPlaintext, PreKeyBundle, RatchetState, accept, generate_discovery_key,
    generate_one_time_prekey, generate_signed_prekey_for_discovery_key, generate_signing_key_pair,
    initiate,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
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
}

#[derive(Deserialize)]
struct DecodedFixture {
    skipped_key_count: Option<usize>,
    digest_count: Option<usize>,
    capacity: Option<usize>,
}

#[derive(Serialize)]
struct TestSessionStateWire<'a> {
    version: u8,
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
    let alice_discovery = generate_discovery_key(&mut rng, &alice_identity, 0, CREATED_AT);
    let bob_discovery = generate_discovery_key(&mut rng, &bob_identity, 0, CREATED_AT);
    let bob_signed_prekey =
        generate_signed_prekey_for_discovery_key(&mut rng, &bob_discovery, CREATED_AT);
    let bob_one_time_prekey =
        generate_one_time_prekey(&mut rng, 9, bob_discovery.epoch(), CREATED_AT);
    let prekey_bundle = PreKeyBundle {
        discovery_key: bob_discovery.bundle(),
        signed_prekey: bob_signed_prekey.bundle(),
        one_time_prekey: Some(bob_one_time_prekey.bundle()),
    };
    let (alice_state, envelope) = initiate(
        &mut rng,
        &alice_discovery,
        &bob_identity.verifying,
        &prekey_bundle,
        initial_plaintext(b"initial"),
    )
    .unwrap();
    let (bob_state, plaintext) = accept(
        &mut rng,
        &envelope,
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

fn outbound<'a>(
    plaintext: &'a [u8],
    sender_identity: &'a SenderIdentityMaterial,
) -> OutboundPlaintext<'a> {
    OutboundPlaintext {
        id: MessageId::from_bytes([1u8; 16]),
        sender_identity,
        recipient_public_key: [2u8; 32],
        timestamp_millis: 1_700_000_000_123,
        plaintext,
    }
}

fn sender_identity() -> SenderIdentityMaterial {
    SenderIdentityMaterial {
        identity_key: [1u8; 32],
        certificate: vec![2, 3, 4],
        signature: vec![5; 64],
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
    fixture_snapshot.set(address.clone(), ProtocolStateBlob::from_bytes(current));

    let mut expected_snapshot = ProtocolStateSnapshot::new();
    expected_snapshot.apply(expected);
    let sender_identity = sender_identity();
    let fixture_message = engine
        .encrypt_message(
            &fixture_snapshot,
            key.clone(),
            outbound(b"fixture", &sender_identity),
        )
        .unwrap()
        .message;
    let expected_message = engine
        .encrypt_message(
            &expected_snapshot,
            key,
            outbound(b"fixture", &sender_identity),
        )
        .unwrap()
        .message;
    assert_eq!(fixture_message.payload, expected_message.payload);
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
    fixture_snapshot.set(address, ProtocolStateBlob::from_bytes(current));
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
    let fixture = &fixture_file.fixtures[2];
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
    snapshot.set(address.clone(), ProtocolStateBlob::from_bytes(current));
    assert!(snapshot.get(&address).is_some());
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
    snapshot.set(address.clone(), ProtocolStateBlob::from_bytes(flat_blob));

    assert!(matches!(
        engine.bind_session_state_peer_identity_key(&snapshot, key, [1u8; 32]),
        Err(ProtocolStateError::BlobDecode { address: actual, .. }) if actual == address
    ));
}

#[test]
fn unsupported_major_version_is_a_fault() {
    let engine = ProtocolStateEngine::new();
    let key = session_key();
    let address = session_address(key.clone());
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot.set(
        address.clone(),
        ProtocolStateBlob::from_bytes(vec![2, 0, 0xaa]),
    );

    assert!(matches!(
        engine.bind_session_state_peer_identity_key(&snapshot, key, [1u8; 32]),
        Err(ProtocolStateError::UnsupportedBlobVersion {
            address: actual,
            major: 2,
            minor: 0
        }) if actual == address
    ));
}

#[test]
fn lower_pre_release_version_is_a_fault() {
    let engine = ProtocolStateEngine::new();
    let key = session_key();
    let address = session_address(key.clone());
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot.set(
        address.clone(),
        ProtocolStateBlob::from_bytes(vec![0, 1, 0xaa]),
    );

    assert!(matches!(
        engine.bind_session_state_peer_identity_key(&snapshot, key, [1u8; 32]),
        Err(ProtocolStateError::UnsupportedBlobVersion {
            address: actual,
            major: 0,
            minor: 1
        }) if actual == address
    ));
}

#[test]
fn unsupported_minor_version_is_a_fault() {
    let engine = ProtocolStateEngine::new();
    let key = session_key();
    let address = session_address(key.clone());
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot.set(
        address.clone(),
        ProtocolStateBlob::from_bytes(vec![1, 1, 0xaa]),
    );

    assert!(matches!(
        engine.bind_session_state_peer_identity_key(&snapshot, key, [1u8; 32]),
        Err(ProtocolStateError::UnsupportedBlobVersion {
            address: actual,
            major: 1,
            minor: 1
        }) if actual == address
    ));
}

#[test]
fn malformed_current_blob_is_a_fault() {
    let engine = ProtocolStateEngine::new();
    let key = session_key();
    let address = session_address(key.clone());
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot.set(
        address.clone(),
        ProtocolStateBlob::from_bytes(vec![1, 0, 0xaa]),
    );

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
        version: 1,
        ratchet_state: &[SECRET_DERIVED_BYTE],
        peer_sender_identity_key: None,
    })
    .unwrap();
    let mut blob = vec![1, 0];
    blob.extend_from_slice(&payload);
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot.set(address.clone(), ProtocolStateBlob::from_bytes(blob));

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
