//! Verifies checked-in sealed-sender session Message fixtures across the public Core API.

use aether_core::{
    DomainSigningKey, DomainSigningKeyStatus, InboundEncryptedMessage, InboundMessageOutcome,
    InboundSenderCertificateValidation, Message, MessageId, OutboundAcknowledgment, PayloadKind,
    ProtocolStateAddress, ProtocolStateBlob, ProtocolStateEngine, ProtocolStateError,
    ProtocolStateKey, ProtocolStateKind, ProtocolStateSnapshot, RevocationState,
    SenderCertificateIdentityKey, SenderIdentityMaterial,
};
use aether_crypto::{KeyPair, SigningKeyPair, sign_identity_key_binding};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::Deserialize;

const SESSION_REPLAY_RNG_SEED: [u8; 32] = [11u8; 32];

#[derive(Deserialize)]
struct FixtureFile {
    session_key_hex: String,
    sender_certificate_validation: CertificateValidationFixture,
    fixtures: Vec<Fixture>,
}

#[derive(Deserialize)]
struct CertificateValidationFixture {
    domain_signing_keys: Vec<DomainSigningKeyFixture>,
    revoked_identity_keys: Vec<IdentityKeyFixture>,
    reference_timestamp_secs: u64,
    grace_window_secs: u64,
}

#[derive(Deserialize)]
struct DomainSigningKeyFixture {
    identifier_hex: String,
    verifying_key_hex: String,
    status: String,
}

#[derive(Deserialize)]
struct IdentityKeyFixture {
    x25519_public_key_hex: String,
    ed25519_verifying_key_hex: String,
}

struct OwnedCertificateValidation {
    domain_signing_keys: Vec<OwnedDomainSigningKey>,
    revoked_identity_keys: Vec<SenderCertificateIdentityKey>,
    reference_timestamp_secs: u64,
    grace_window_secs: u64,
}

struct OwnedDomainSigningKey {
    identifier: Vec<u8>,
    verifying_key: Vec<u8>,
    status: DomainSigningKeyStatus,
}

impl OwnedCertificateValidation {
    fn domain_signing_keys(&self) -> Vec<DomainSigningKey<'_>> {
        self.domain_signing_keys
            .iter()
            .map(|key| DomainSigningKey {
                identifier: &key.identifier,
                verifying_key: &key.verifying_key,
                status: key.status,
            })
            .collect()
    }
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
    sender_identity_verifying_key_hex: String,
    sender_identity_binding_signature_hex: String,
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
    let deduplication_key = deduplication_key();
    let validation = certificate_validation(&fixture_file.sender_certificate_validation);
    let domain_signing_keys = validation.domain_signing_keys();

    assert_eq!(fixture_file.fixtures.len(), 1);
    for fixture in fixture_file.fixtures {
        let encoded = hex::decode(&fixture.encoded_hex).unwrap();
        let message = Message::from_bytes(&encoded).unwrap();
        let sender_identity = sender_identity(&fixture.post_decryption);
        let acknowledgment_sender_identity = acknowledgment_sender_identity();

        assert_transport(&message, &fixture.transport_visible, &fixture.name);
        assert_eq!(
            hex::encode(message.to_bytes().unwrap()),
            fixture.encoded_hex,
            "{} re-encoded bytes",
            fixture.name
        );
        assert_sender_material_hidden(&encoded, &sender_identity);

        let snapshot = snapshot(
            &blob_file,
            &fixture.recipient_state_fixture,
            key.clone(),
            deduplication_key.clone(),
        );
        let decrypted = ProtocolStateEngine::new()
            .decrypt_message(
                &mut ChaCha20Rng::from_seed(SESSION_REPLAY_RNG_SEED),
                &snapshot,
                inbound(
                    key.clone(),
                    deduplication_key.clone(),
                    &message,
                    &acknowledgment_sender_identity,
                    &domain_signing_keys,
                    &validation.revoked_identity_keys,
                    validation.reference_timestamp_secs,
                    validation.grace_window_secs,
                ),
            )
            .map(accepted)
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
        let tampered_result = ProtocolStateEngine::new().decrypt_message(
            &mut ChaCha20Rng::from_seed(SESSION_REPLAY_RNG_SEED),
            &snapshot,
            inbound(
                key.clone(),
                deduplication_key.clone(),
                &tampered,
                &acknowledgment_sender_identity,
                &domain_signing_keys,
                &validation.revoked_identity_keys,
                validation.reference_timestamp_secs,
                validation.grace_window_secs,
            ),
        );
        assert!(
            matches!(tampered_result, Err(ProtocolStateError::Crypto(_))),
            "{} tampered ciphertext",
            fixture.name
        );
    }
}

fn snapshot(
    blob_file: &BlobFixtureFile,
    fixture_name: &str,
    key: ProtocolStateKey,
    deduplication_key: ProtocolStateKey,
) -> ProtocolStateSnapshot {
    let mut snapshot = ProtocolStateSnapshot::new();
    insert_blob(&mut snapshot, blob_file, fixture_name, key);
    insert_blob(
        &mut snapshot,
        blob_file,
        "deduplication_set_identity",
        deduplication_key,
    );
    snapshot
}

fn insert_blob(
    snapshot: &mut ProtocolStateSnapshot,
    blob_file: &BlobFixtureFile,
    fixture_name: &str,
    key: ProtocolStateKey,
) {
    let fixture = blob_file
        .fixtures
        .iter()
        .find(|fixture| fixture.name == fixture_name)
        .unwrap();
    snapshot.set(
        ProtocolStateAddress::new(protocol_state_kind(&fixture.kind), key),
        ProtocolStateBlob::from_bytes(hex::decode(&fixture.current_encoded_hex).unwrap()),
    );
}

fn deduplication_key() -> ProtocolStateKey {
    ProtocolStateKey::from_bytes(vec![0xdd; 16]).unwrap()
}

#[allow(clippy::too_many_arguments)]
fn inbound<'a>(
    session_key: ProtocolStateKey,
    deduplication_key: ProtocolStateKey,
    message: &'a Message,
    acknowledgment_sender_identity: &'a SenderIdentityMaterial,
    domain_signing_keys: &'a [DomainSigningKey<'a>],
    revoked_identity_keys: &'a [SenderCertificateIdentityKey],
    reference_timestamp_secs: u64,
    grace_window_secs: u64,
) -> InboundEncryptedMessage<'a> {
    InboundEncryptedMessage {
        session_key,
        deduplication_key,
        message,
        acknowledgment: acknowledgment(acknowledgment_sender_identity),
        sender_certificate_validation: Some(InboundSenderCertificateValidation {
            domain_signing_keys,
            revocation_state: RevocationState::Available(revoked_identity_keys),
            reference_timestamp_secs,
            grace_window_secs,
        }),
    }
}

fn acknowledgment_sender_identity() -> SenderIdentityMaterial {
    sender_identity_with_material(0xb1, vec![0xb2, 0xb3, 0xb4], vec![0xb5; 64])
}

fn acknowledgment<'a>(sender_identity: &'a SenderIdentityMaterial) -> OutboundAcknowledgment<'a> {
    OutboundAcknowledgment {
        id: MessageId::from_bytes([0xee; 16]),
        sender_identity,
        sender_identity_signing_key: sender_identity_signing_key(sender_identity),
        recipient_public_key: [0xb6; 32],
        timestamp_millis: 1_700_000_100_000,
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
    assert!(!contains_bytes(
        encoded,
        &sender_identity.identity_verifying_key
    ));
    assert!(!contains_bytes(
        encoded,
        &sender_identity.identity_binding_signature
    ));
    assert!(!contains_bytes(encoded, &sender_identity.certificate));
    assert!(!contains_bytes(encoded, &sender_identity.signature));
}

fn assert_sender_identity(actual: &SenderIdentityMaterial, expected: &SenderIdentityMaterial) {
    assert_eq!(actual.identity_key, expected.identity_key);
    assert_eq!(
        actual.identity_verifying_key,
        expected.identity_verifying_key
    );
    assert_eq!(
        actual.identity_binding_signature,
        expected.identity_binding_signature
    );
    assert_eq!(actual.certificate, expected.certificate);
    assert_eq!(actual.signature, expected.signature);
}

fn sender_identity(fixture: &SenderIdentityFixture) -> SenderIdentityMaterial {
    SenderIdentityMaterial {
        identity_key: hex_array::<32>(&fixture.sender_identity_key_hex),
        identity_verifying_key: hex_array::<32>(&fixture.sender_identity_verifying_key_hex),
        identity_binding_signature: hex::decode(&fixture.sender_identity_binding_signature_hex)
            .unwrap(),
        certificate: hex::decode(&fixture.sender_certificate_hex).unwrap(),
        signature: hex::decode(&fixture.sender_signature_hex).unwrap(),
    }
}

fn certificate_validation(fixture: &CertificateValidationFixture) -> OwnedCertificateValidation {
    OwnedCertificateValidation {
        domain_signing_keys: fixture
            .domain_signing_keys
            .iter()
            .map(domain_signing_key)
            .collect(),
        revoked_identity_keys: fixture
            .revoked_identity_keys
            .iter()
            .map(identity_key)
            .collect(),
        reference_timestamp_secs: fixture.reference_timestamp_secs,
        grace_window_secs: fixture.grace_window_secs,
    }
}

fn domain_signing_key(fixture: &DomainSigningKeyFixture) -> OwnedDomainSigningKey {
    OwnedDomainSigningKey {
        identifier: hex::decode(&fixture.identifier_hex).unwrap(),
        verifying_key: hex::decode(&fixture.verifying_key_hex).unwrap(),
        status: domain_signing_key_status(&fixture.status),
    }
}

fn identity_key(fixture: &IdentityKeyFixture) -> SenderCertificateIdentityKey {
    SenderCertificateIdentityKey {
        x25519_public_key: hex_array(&fixture.x25519_public_key_hex),
        ed25519_verifying_key: hex_array(&fixture.ed25519_verifying_key_hex),
    }
}

fn sender_identity_with_material(
    tag: u8,
    certificate: Vec<u8>,
    signature: Vec<u8>,
) -> SenderIdentityMaterial {
    let signing_key = SigningKeyPair::from_signing_bytes([tag; 32]);
    let identity_key_pair = KeyPair::from_secret_bytes([tag.wrapping_add(0x33); 32]);
    let binding_signature =
        sign_identity_key_binding(&signing_key, &identity_key_pair.public).unwrap();
    SenderIdentityMaterial {
        identity_key: *identity_key_pair.public.as_bytes(),
        identity_verifying_key: signing_key.verifying.to_bytes(),
        identity_binding_signature: binding_signature.to_bytes().to_vec(),
        certificate,
        signature,
    }
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
        "deduplication_set" => ProtocolStateKind::DeduplicationSet,
        "pending_acknowledgments" => ProtocolStateKind::PendingAcknowledgments,
        _ => panic!("unknown protocol-state kind in fixture: {kind}"),
    }
}

fn payload_kind(kind: &str) -> PayloadKind {
    match kind {
        "text" => PayloadKind::EncryptedText,
        _ => panic!("unknown payload kind in fixture: {kind}"),
    }
}

fn domain_signing_key_status(status: &str) -> DomainSigningKeyStatus {
    match status {
        "trusted" => DomainSigningKeyStatus::Trusted,
        "untrusted" => DomainSigningKeyStatus::Untrusted,
        _ => panic!("unknown domain-signing-key status in fixture: {status}"),
    }
}
