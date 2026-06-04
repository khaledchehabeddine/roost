//! Verifies checked-in Protocol State Blob fixtures across Core migration boundaries.

use aether_core::{
    MessageId, OutboundPlaintext, ProtocolStateAddress, ProtocolStateBlob, ProtocolStateEngine,
    ProtocolStateError, ProtocolStateKey, ProtocolStateKind, ProtocolStateSnapshot, SessionId,
};
use aether_crypto::{
    PreKeyBundle, RatchetState, accept, generate_discovery_key, generate_one_time_prekey,
    generate_signed_prekey_for_discovery_key, generate_signing_key_pair, initial_associated_data,
    initiate,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const CREATED_AT: u64 = 1_700_000_000;

#[derive(Deserialize)]
struct FixtureFile {
    provenance: String,
    current_version: Version,
    supported_migration_versions: Vec<Version>,
    fixtures: Vec<Fixture>,
    unsupported_pre_release_blobs: Vec<UnsupportedFixture>,
}

#[derive(Clone, Copy, Deserialize)]
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
    migrations: Vec<MigrationFixture>,
}

#[derive(Deserialize)]
struct DecodedFixture {
    skipped_key_count: usize,
}

#[derive(Deserialize)]
struct MigrationFixture {
    from_version: Version,
    encoded_hex: String,
    migrated_encoded_hex: String,
}

#[derive(Deserialize)]
struct UnsupportedFixture {
    name: String,
    kind: String,
    key_hex: String,
    encoded_hex: String,
    expected_error: String,
}

struct Setup {
    associated_data: Vec<u8>,
    alice_state: RatchetState,
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
    let associated_data = initial_associated_data(
        alice_discovery.public_key(),
        bob_discovery.public_key(),
        bob_discovery.epoch(),
    );
    let (alice_state, envelope) = initiate(
        &mut rng,
        &alice_discovery,
        &bob_identity.verifying,
        &prekey_bundle,
        b"initial",
    )
    .unwrap();
    let (_, plaintext) = accept(
        &mut rng,
        &envelope,
        &alice_identity.verifying,
        &alice_discovery.bundle(),
        &bob_discovery,
        &bob_signed_prekey,
        Some(bob_one_time_prekey),
    )
    .unwrap();
    assert_eq!(plaintext.as_slice(), b"initial");
    Setup {
        associated_data: associated_data.to_vec(),
        alice_state,
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

fn outbound<'a>(plaintext: &'a [u8], associated_data: &'a [u8]) -> OutboundPlaintext<'a> {
    OutboundPlaintext {
        id: MessageId::from_bytes([1u8; 16]),
        sender_public_key: [1u8; 32],
        recipient_public_key: [2u8; 32],
        timestamp_millis: 1_700_000_000_123,
        plaintext,
        associated_data,
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
    assert_eq!(fixture.decoded.skipped_key_count, 0);

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
    assert!(
        engine
            .migrate_session_state(&fixture_snapshot, key.clone())
            .unwrap()
            .is_none()
    );

    let mut expected_snapshot = ProtocolStateSnapshot::new();
    expected_snapshot.apply(expected);
    let fixture_message = engine
        .encrypt_message(
            &fixture_snapshot,
            key.clone(),
            outbound(b"fixture", &setup.associated_data),
        )
        .unwrap()
        .message;
    let expected_message = engine
        .encrypt_message(
            &expected_snapshot,
            key,
            outbound(b"fixture", &setup.associated_data),
        )
        .unwrap()
        .message;
    assert_eq!(fixture_message.payload, expected_message.payload);
}

#[test]
fn supported_old_fixture_migrates_to_current_bytes() {
    let fixture_file = fixture_file();
    let fixture = &fixture_file.fixtures[0];
    let migration = &fixture.migrations[0];
    let engine = ProtocolStateEngine::new();
    let key = session_key();
    let address = session_address(key.clone());
    let old_bytes = hex::decode(&migration.encoded_hex).unwrap();
    let expected_current = hex::decode(&migration.migrated_encoded_hex).unwrap();
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot.set(address.clone(), ProtocolStateBlob::from_bytes(old_bytes));

    assert_eq!(fixture_file.supported_migration_versions.len(), 1);
    assert_eq!(migration.from_version.major, 0);
    assert_eq!(migration.from_version.minor, 1);

    let update = engine
        .migrate_session_state(&snapshot, key)
        .unwrap()
        .expect("old fixture should produce a migration update");

    assert_eq!(update.address(), &address);
    assert_eq!(update.blob().unwrap().as_bytes(), expected_current);
}

#[test]
fn old_pre_release_blob_is_not_implicitly_supported() {
    let fixture_file = fixture_file();
    let fixture = &fixture_file.unsupported_pre_release_blobs[0];
    let engine = ProtocolStateEngine::new();
    let key = session_key();
    let address = session_address(key.clone());
    let old_bytes = hex::decode(&fixture.encoded_hex).unwrap();
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot.set(address.clone(), ProtocolStateBlob::from_bytes(old_bytes));

    assert_eq!(fixture.name, "flat_v1_ratchet_session");
    assert_eq!(fixture.kind, "ratchet_session");
    assert_eq!(hex::decode(&fixture.key_hex).unwrap(), key.as_bytes());
    assert_eq!(fixture.expected_error, "unsupported_blob_version");
    assert!(matches!(
        engine.migrate_session_state(&snapshot, key),
        Err(ProtocolStateError::UnsupportedBlobVersion {
            address: actual,
            major: 1,
            minor: 1
        }) if actual == address
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
        engine.migrate_session_state(&snapshot, key),
        Err(ProtocolStateError::UnsupportedBlobVersion {
            address: actual,
            major: 2,
            minor: 0
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
        engine.migrate_session_state(&snapshot, key),
        Err(ProtocolStateError::BlobDecode { address: actual, .. }) if actual == address
    ));
}

#[test]
fn migration_invariant_violation_is_a_fault_without_resetting_state() {
    let engine = ProtocolStateEngine::new();
    let key = session_key();
    let address = session_address(key.clone());
    let bad_blob = invalid_legacy_blob();
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot.set(
        address.clone(),
        ProtocolStateBlob::from_bytes(bad_blob.clone()),
    );

    let result = engine.migrate_session_state(&snapshot, key);

    assert!(matches!(
        result,
        Err(ProtocolStateError::MigrationFailed { address: actual, .. }) if actual == address
    ));
    assert_eq!(snapshot.get(&address).unwrap().as_bytes(), bad_blob);
}

fn invalid_legacy_blob() -> Vec<u8> {
    let wire = RatchetStateWire {
        version: 1,
        dhs_secret: [0; 32],
        dhr: None,
        rk: [0; 32],
        cks: None,
        ckr: None,
        ns: 0,
        nr: 0,
        pn: 0,
        mk_skipped: [(
            ([0; 32], 0),
            SkippedMessageKeyWire {
                message_key: [0; 32],
                sequence: 0,
            },
        )]
        .into(),
        next_skipped_key_sequence: 0,
    };
    let mut blob = vec![0, 1];
    blob.extend_from_slice(&postcard::to_stdvec(&wire).unwrap());
    blob
}

#[derive(Serialize)]
struct RatchetStateWire {
    version: u8,
    dhs_secret: [u8; 32],
    dhr: Option<[u8; 32]>,
    rk: [u8; 32],
    cks: Option<[u8; 32]>,
    ckr: Option<[u8; 32]>,
    ns: u32,
    nr: u32,
    pn: u32,
    mk_skipped: BTreeMap<([u8; 32], u32), SkippedMessageKeyWire>,
    next_skipped_key_sequence: u64,
}

#[derive(Serialize)]
struct SkippedMessageKeyWire {
    message_key: [u8; 32],
    sequence: u64,
}
