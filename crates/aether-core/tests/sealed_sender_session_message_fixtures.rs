//! Verifies checked-in sealed-sender session Message fixtures across the public Core API.

use aether_core::{
    Message, PayloadKind, ProtocolStateAddress, ProtocolStateBlob, ProtocolStateEngine,
    ProtocolStateKey, ProtocolStateKind, ProtocolStateSnapshot, SenderIdentityMaterial,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::Deserialize;

const SESSION_REPLAY_RNG_SEED: [u8; 32] = [11u8; 32];

#[derive(Deserialize)]
struct FixtureFile {
    session_key_hex: String,
    fixtures: Vec<Fixture>,
}

#[derive(Deserialize)]
struct Fixture {
    name: String,
    recipient_state_fixture: String,
    encoded_hex: String,
    transport_visible: TransportFixture,
    plaintext_hex: String,
    post_decryption: SenderIdentityFixture,
}

#[derive(Deserialize)]
struct TransportFixture {
    id_hex: String,
    recipient_public_key_hex: String,
    timestamp_millis: u64,
    payload_kind: String,
    payload_hex: String,
}

#[derive(Deserialize)]
struct SenderIdentityFixture {
    sender_identity_key_hex: String,
    sender_certificate_hex: String,
    sender_signature_hex: String,
}

#[derive(Deserialize)]
struct BlobFixtureFile {
    fixtures: Vec<BlobFixture>,
}

#[derive(Deserialize)]
struct BlobFixture {
    name: String,
    kind: String,
    current_encoded_hex: String,
}

#[test]
fn checked_in_session_message_fixtures_decrypt_after_transport_replay() {
    let fixture_file: FixtureFile = serde_json::from_str(include_str!(
        "fixtures/sealed_sender_session_messages_v1.json"
    ))
    .unwrap();
    let blob_file: BlobFixtureFile =
        serde_json::from_str(include_str!("fixtures/protocol_state_blobs_v1.json")).unwrap();
    let key =
        ProtocolStateKey::from_bytes(hex::decode(&fixture_file.session_key_hex).unwrap()).unwrap();

    assert_eq!(fixture_file.fixtures.len(), 1);
    for fixture in fixture_file.fixtures {
        let encoded = hex::decode(&fixture.encoded_hex).unwrap();
        let message = Message::from_bytes(&encoded).unwrap();
        let sender_identity = sender_identity(&fixture.post_decryption);

        assert_transport(&message, &fixture.transport_visible, &fixture.name);
        assert_eq!(
            hex::encode(message.to_bytes().unwrap()),
            fixture.encoded_hex,
            "{} re-encoded bytes",
            fixture.name
        );
        assert_sender_material_hidden(&encoded, &sender_identity);

        let snapshot = snapshot(&blob_file, &fixture.recipient_state_fixture, key.clone());
        let decrypted = ProtocolStateEngine::new()
            .decrypt_message(
                &mut ChaCha20Rng::from_seed(SESSION_REPLAY_RNG_SEED),
                &snapshot,
                key.clone(),
                &message,
            )
            .unwrap();
        assert_eq!(
            decrypted.plaintext.as_slice(),
            hex::decode(&fixture.plaintext_hex).unwrap().as_slice(),
            "{} plaintext",
            fixture.name
        );
        assert_sender_identity(&decrypted.sender_identity, &sender_identity);

        let mut tampered = copy_message(&message);
        *tampered.payload.last_mut().unwrap() ^= 0x01;
        assert!(
            ProtocolStateEngine::new()
                .decrypt_message(
                    &mut ChaCha20Rng::from_seed(SESSION_REPLAY_RNG_SEED),
                    &snapshot,
                    key.clone(),
                    &tampered,
                )
                .is_err(),
            "{} tampered ciphertext",
            fixture.name
        );
    }
}

fn snapshot(
    blob_file: &BlobFixtureFile,
    fixture_name: &str,
    key: ProtocolStateKey,
) -> ProtocolStateSnapshot {
    let fixture = blob_file
        .fixtures
        .iter()
        .find(|fixture| fixture.name == fixture_name)
        .unwrap();
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot.set(
        ProtocolStateAddress::new(protocol_state_kind(&fixture.kind), key),
        ProtocolStateBlob::from_bytes(hex::decode(&fixture.current_encoded_hex).unwrap()),
    );
    snapshot
}

fn assert_transport(message: &Message, expected: &TransportFixture, name: &str) {
    assert_eq!(
        message.id.as_bytes(),
        &hex_array::<16>(&expected.id_hex),
        "{name} id"
    );
    assert_eq!(
        message.recipient_public_key,
        hex_array::<32>(&expected.recipient_public_key_hex),
        "{name} recipient public key"
    );
    assert_eq!(
        message.timestamp_millis, expected.timestamp_millis,
        "{name} timestamp"
    );
    assert_eq!(
        message.payload_kind,
        payload_kind(&expected.payload_kind),
        "{name} payload kind"
    );
    assert_eq!(
        message.payload,
        hex::decode(&expected.payload_hex).unwrap(),
        "{name} payload"
    );
}

fn assert_sender_material_hidden(encoded: &[u8], sender_identity: &SenderIdentityMaterial) {
    assert!(!contains_bytes(encoded, &sender_identity.identity_key));
    assert!(!contains_bytes(encoded, &sender_identity.certificate));
    assert!(!contains_bytes(encoded, &sender_identity.signature));
}

fn assert_sender_identity(actual: &SenderIdentityMaterial, expected: &SenderIdentityMaterial) {
    assert_eq!(actual.identity_key, expected.identity_key);
    assert_eq!(actual.certificate, expected.certificate);
    assert_eq!(actual.signature, expected.signature);
}

fn sender_identity(fixture: &SenderIdentityFixture) -> SenderIdentityMaterial {
    SenderIdentityMaterial {
        identity_key: hex_array(&fixture.sender_identity_key_hex),
        certificate: hex::decode(&fixture.sender_certificate_hex).unwrap(),
        signature: hex::decode(&fixture.sender_signature_hex).unwrap(),
    }
}

fn copy_message(message: &Message) -> Message {
    Message {
        id: message.id,
        recipient_public_key: message.recipient_public_key,
        timestamp_millis: message.timestamp_millis,
        payload_kind: message.payload_kind,
        payload: message.payload.clone(),
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn hex_array<const N: usize>(hex: &str) -> [u8; N] {
    hex::decode(hex).unwrap().try_into().unwrap()
}

fn protocol_state_kind(kind: &str) -> ProtocolStateKind {
    match kind {
        "ratchet_session" => ProtocolStateKind::RatchetSession,
        _ => panic!("unknown protocol-state kind in fixture: {kind}"),
    }
}

fn payload_kind(kind: &str) -> PayloadKind {
    match kind {
        "text" => PayloadKind::EncryptedText,
        _ => panic!("unknown payload kind in fixture: {kind}"),
    }
}
