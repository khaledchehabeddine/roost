//! Verifies checked-in sealed-sender session Message fixtures across the public Core API.

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use roost_core::{
    ContactDiscoveryKey, ContactIdentity, ContactIdentityKey, InboundEncryptedMessage,
    InboundMessageOutcome, InboundSenderCertificateValidation, Message, OutboundAcknowledgment,
    OutboundPlaintext, ProtocolStateAddress, ProtocolStateBlob, ProtocolStateEngine,
    ProtocolStateError, ProtocolStateKey, ProtocolStateKind, ProtocolStateSnapshot,
    SenderIdentityMaterial,
};
use roost_crypto::{
    DiscoveryKey, KeyPair, SealedFramePreKeyReference, SigningKeyPair, generate_discovery_key,
    generate_key_pair, generate_signing_key_pair, sign_identity_key_binding,
};
use roost_protocol::{
    DomainSigningKey, DomainSigningKeyStatus, MessageId, PayloadKind, RevocationState,
    SenderCertificateIdentityKey,
};
use serde::Deserialize;

const TEST_RELAY_DOMAIN: &[u8] = b"relay.test";

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
    relay_domain: String,
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
    relay_domain: Vec<u8>,
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
    decrypted_metadata: DecryptedMetadataFixture,
    plaintext_hex: String,
    post_decryption: SenderIdentityFixture,
}

#[derive(Deserialize)]
struct TransportFixture {
    version: u8,
    recipient_public_key_hex: String,
    prekey_reference: Option<PreKeyReferenceFixture>,
    ephemeral_public_key_hex: String,
    ciphertext_hex: String,
}

#[derive(Deserialize)]
struct PreKeyReferenceFixture {
    discovery_epoch: u32,
    signed_prekey_public_key_hex: String,
    one_time_prekey_id: Option<u64>,
    one_time_prekey_public_key_hex: Option<String>,
}

#[derive(Deserialize)]
struct DecryptedMetadataFixture {
    id_hex: String,
    timestamp_millis: u64,
    payload_kind: String,
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
                    &validation.relay_domain,
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
        assert_decrypted_metadata(&decrypted, &fixture.decrypted_metadata, &fixture.name);
        assert_sender_identity(&decrypted.sender_identity, &sender_identity);

        let mut tampered = copy_message(&message);
        *tampered.ciphertext.last_mut().unwrap() ^= 0x01;
        let tampered_result = ProtocolStateEngine::new().decrypt_message(
            &mut ChaCha20Rng::from_seed(SESSION_REPLAY_RNG_SEED),
            &snapshot,
            inbound(
                key.clone(),
                deduplication_key.clone(),
                &tampered,
                &acknowledgment_sender_identity,
                &domain_signing_keys,
                &validation.relay_domain,
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

fn accepted_contact_discovery_key() -> DiscoveryKey {
    let mut rng = ChaCha20Rng::from_seed([0x71; 32]);
    let identity = generate_signing_key_pair(&mut rng);
    let _identity_key_pair = generate_key_pair(&mut rng);
    generate_discovery_key(&mut rng, &identity, 0, 1_700_000_000)
}

fn accepted_contact_discovery_key_ref() -> &'static DiscoveryKey {
    Box::leak(Box::new(accepted_contact_discovery_key()))
}

fn acknowledgment_recipient_discovery_key() -> DiscoveryKey {
    let mut rng = ChaCha20Rng::from_seed([0xc2; 32]);
    generate_discovery_key(
        &mut rng,
        fixture_recipient_identity_signing_key(),
        0,
        1_700_000_000,
    )
}

#[allow(clippy::too_many_arguments)]
fn inbound<'a>(
    session_key: ProtocolStateKey,
    deduplication_key: ProtocolStateKey,
    message: &'a Message,
    acknowledgment_sender_identity: &'a SenderIdentityMaterial,
    domain_signing_keys: &'a [DomainSigningKey<'a>],
    expected_relay_domain: &'a [u8],
    revoked_identity_keys: &'a [SenderCertificateIdentityKey],
    reference_timestamp_secs: u64,
    grace_window_secs: u64,
) -> InboundEncryptedMessage<'a> {
    InboundEncryptedMessage {
        session_key,
        deduplication_key,
        message,
        recipient_discovery_key: accepted_contact_discovery_key_ref(),
        recipient_identity_verifying_key: fixture_contact_identity()
            .identity_key
            .ed25519_verifying_key,
        acknowledgment: acknowledgment(acknowledgment_sender_identity),
        sender_certificate_validation: Some(InboundSenderCertificateValidation {
            domain_signing_keys,
            expected_relay_domain,
            revocation_state: RevocationState::Available(revoked_identity_keys),
            reference_timestamp_secs,
            grace_window_secs,
        }),
    }
}

fn acknowledgment_sender_identity() -> SenderIdentityMaterial {
    let contact = fixture_contact_identity();
    let signing_key = fixture_recipient_identity_signing_key();
    let public_key = roost_crypto::PublicKey::from(contact.identity_key.x25519_public_key);
    let binding_signature = sign_identity_key_binding(signing_key, &public_key).unwrap();
    SenderIdentityMaterial {
        identity_key: contact.identity_key.x25519_public_key,
        identity_verifying_key: contact.identity_key.ed25519_verifying_key,
        identity_binding_signature: binding_signature.to_bytes().to_vec(),
        certificate: vec![0xb2, 0xb3, 0xb4],
        signature: vec![0xb5; 64],
    }
}

fn acknowledgment<'a>(sender_identity: &'a SenderIdentityMaterial) -> OutboundAcknowledgment<'a> {
    let recipient = acknowledgment_recipient_discovery_key();
    OutboundAcknowledgment {
        id: MessageId::from_bytes([0xee; 16]),
        sender_identity,
        sender_identity_signing_key: fixture_recipient_identity_signing_key(),
        recipient_public_key: *recipient.public_key().as_bytes(),
        timestamp_millis: 1_700_000_100_000,
    }
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

fn assert_transport(message: &Message, expected: &TransportFixture, name: &str) {
    assert_eq!(message.version, expected.version, "{name} version");
    assert_eq!(
        message.recipient_public_key,
        hex_array::<32>(&expected.recipient_public_key_hex),
        "{name} recipient public key"
    );
    assert_prekey_reference(
        message.prekey_reference,
        expected.prekey_reference.as_ref(),
        name,
    );
    assert_eq!(
        message.ephemeral_public_key,
        hex_array::<32>(&expected.ephemeral_public_key_hex),
        "{name} ephemeral public key"
    );
    assert_eq!(
        message.ciphertext,
        hex::decode(&expected.ciphertext_hex).unwrap(),
        "{name} ciphertext"
    );
}

fn assert_prekey_reference(
    actual: Option<SealedFramePreKeyReference>,
    expected: Option<&PreKeyReferenceFixture>,
    name: &str,
) {
    match (actual, expected) {
        (None, None) => {}
        (Some(actual), Some(expected)) => {
            assert_eq!(
                actual.discovery_epoch, expected.discovery_epoch,
                "{name} discovery epoch"
            );
            assert_eq!(
                actual.signed_prekey_public_key,
                hex_array::<32>(&expected.signed_prekey_public_key_hex),
                "{name} signed prekey"
            );
            assert_eq!(
                actual.one_time_prekey_id, expected.one_time_prekey_id,
                "{name} one-time prekey id"
            );
            assert_eq!(
                actual.one_time_prekey_public_key,
                expected
                    .one_time_prekey_public_key_hex
                    .as_deref()
                    .map(hex_array::<32>),
                "{name} one-time prekey public key"
            );
        }
        _ => panic!("{name} prekey reference mismatch"),
    }
}

fn assert_decrypted_metadata(
    actual: &roost_core::InboundMessageResult,
    expected: &DecryptedMetadataFixture,
    name: &str,
) {
    assert_eq!(
        actual.message_id.as_bytes(),
        &hex_array::<16>(&expected.id_hex),
        "{name} decrypted id"
    );
    assert_eq!(
        actual.timestamp_millis, expected.timestamp_millis,
        "{name} decrypted timestamp"
    );
    assert_eq!(
        actual.payload_kind,
        payload_kind(&expected.payload_kind),
        "{name} decrypted payload kind"
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
        relay_domain: fixture.relay_domain.clone().into_bytes(),
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
        version: message.version,
        recipient_public_key: message.recipient_public_key,
        prekey_reference: message.prekey_reference,
        ephemeral_public_key: message.ephemeral_public_key,
        ciphertext: message.ciphertext.clone(),
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

/// Rebuilds `sealed_sender_session_messages_v1.json` after a sealed-payload format change.
///
/// The sender certificate sits inside the encrypted payload, so the message must be
/// re-encrypted rather than edited. Every identity here is derived deterministically, but
/// `encrypt_message` draws its sealed-frame ephemeral from `OsRng` and takes no RNG argument,
/// so the emitted bytes are pinned from one run rather than reproducible. That is deliberate:
/// making the ephemeral injectable would put a nonce-reuse footgun on the public API to save
/// a manual step on a file that changes once per wire format. Re-run and re-pin instead.
#[test]
#[ignore = "regenerates sealed_sender_session_messages_v1.json; run explicitly"]
fn regenerate_sealed_sender_session_message_fixtures() {
    const DOMAIN_IDENTIFIER: &[u8] = b"fixture-domain";
    const SENDER_TAG: u8 = 0x01;
    const EXPIRES_AT_SECS: u64 = 1_700_100_000;
    const REFERENCE_TIMESTAMP_SECS: u64 = 1_700_000_000;
    const TIMESTAMP_MILLIS: u64 = 1_700_000_000_321;
    const PLAINTEXT: &[u8] = b"fixture sealed session";
    const SENDER_STATE_FIXTURE: &str = "ratchet_session_alice";
    const RECIPIENT_STATE_FIXTURE: &str = "ratchet_session_bob_bound";

    let blob_file: BlobFixtureFile =
        serde_json::from_str(include_str!("fixtures/protocol_state_blobs_v1.json")).unwrap();
    let engine = ProtocolStateEngine::new();
    let session_key = ProtocolStateKey::from_bytes(vec![0x09; 16]).unwrap();

    let mut snapshot = ProtocolStateSnapshot::new();
    insert_blob(
        &mut snapshot,
        &blob_file,
        SENDER_STATE_FIXTURE,
        session_key.clone(),
    );
    snapshot.apply(
        engine
            .initialize_pending_acknowledgments(session_key.clone())
            .unwrap(),
    );
    let contact = fixture_contact_identity();
    let recorded = engine.record_contact(&snapshot, contact).unwrap();
    snapshot.apply_all(recorded.state_updates);
    let accepted = engine
        .accept_contact(&snapshot, contact.identity_key)
        .unwrap();
    snapshot.apply_all(accepted.state_updates);

    let domain_signing_key = fixture_domain_signing_key();
    let certificate = fixture_sender_certificate(DOMAIN_IDENTIFIER, SENDER_TAG, EXPIRES_AT_SECS);
    let signature = domain_signing_key.sign(&certificate).to_bytes().to_vec();
    let sender_identity = sender_identity_with_material(SENDER_TAG, certificate, signature);

    let encrypted = engine
        .encrypt_message(
            &snapshot,
            session_key,
            OutboundPlaintext {
                id: MessageId::from_bytes([0x31; 16]),
                sender_identity: &sender_identity,
                sender_identity_signing_key: sender_identity_signing_key(&sender_identity),
                contact_identity_key: contact.identity_key,
                recipient_public_key: contact.discovery_key.prekey_bundle_lookup_key(),
                timestamp_millis: TIMESTAMP_MILLIS,
                plaintext: PLAINTEXT,
            },
        )
        .unwrap();
    let message = &encrypted.message;

    assert!(
        message.prekey_reference.is_none(),
        "fixture pins a session message, which carries no prekey reference"
    );

    // Emitted field-by-field rather than through `serde_json::json!`, which orders keys
    // alphabetically and would rewrite every line of the file on each regeneration.
    let emitted = format!(
        r#"{{
  "provenance": "test-only bytes generated from deterministic protocol-state blob fixtures; the sealed-frame ephemeral key is pinned from one local fixture generation",
  "session_key_hex": "09090909090909090909090909090909",
  "sender_certificate_validation": {{
    "domain_signing_keys": [
      {{
        "identifier_hex": "{domain_identifier}",
        "verifying_key_hex": "{domain_verifying_key}",
        "status": "trusted"
      }}
    ],
    "relay_domain": "{relay_domain}",
    "revoked_identity_keys": [],
    "reference_timestamp_secs": {REFERENCE_TIMESTAMP_SECS},
    "grace_window_secs": 0
  }},
  "fixtures": [
    {{
      "name": "sealed_text",
      "sender_state_fixture": "{SENDER_STATE_FIXTURE}",
      "recipient_state_fixture": "{RECIPIENT_STATE_FIXTURE}",
      "encoded_hex": "{encoded}",
      "transport_visible": {{
        "version": {version},
        "recipient_public_key_hex": "{recipient_public_key}",
        "prekey_reference": null,
        "ephemeral_public_key_hex": "{ephemeral_public_key}",
        "ciphertext_hex": "{ciphertext}"
      }},
      "decrypted_metadata": {{
        "id_hex": "{message_id}",
        "timestamp_millis": {timestamp_millis},
        "payload_kind": "text"
      }},
      "plaintext_hex": "{plaintext}",
      "post_decryption": {{
        "sender_identity_key_hex": "{identity_key}",
        "sender_identity_verifying_key_hex": "{identity_verifying_key}",
        "sender_identity_binding_signature_hex": "{identity_binding_signature}",
        "sender_certificate_hex": "{certificate}",
        "sender_signature_hex": "{certificate_signature}"
      }}
    }}
  ]
}}"#,
        domain_identifier = hex::encode(DOMAIN_IDENTIFIER),
        domain_verifying_key = hex::encode(domain_signing_key.verifying.to_bytes()),
        relay_domain = std::str::from_utf8(TEST_RELAY_DOMAIN).unwrap(),
        encoded = hex::encode(message.to_bytes().unwrap()),
        version = message.version,
        recipient_public_key = hex::encode(message.recipient_public_key),
        ephemeral_public_key = hex::encode(message.ephemeral_public_key),
        ciphertext = hex::encode(&message.ciphertext),
        message_id = hex::encode(encrypted.message_id.as_bytes()),
        timestamp_millis = encrypted.timestamp_millis,
        plaintext = hex::encode(PLAINTEXT),
        identity_key = hex::encode(sender_identity.identity_key),
        identity_verifying_key = hex::encode(sender_identity.identity_verifying_key),
        identity_binding_signature = hex::encode(&sender_identity.identity_binding_signature),
        certificate = hex::encode(&sender_identity.certificate),
        certificate_signature = hex::encode(&sender_identity.signature),
    );

    // Proves the emitted document still satisfies the schema this file replays, so a
    // regeneration cannot hand back JSON the harness would reject on load.
    let parsed: FixtureFile = serde_json::from_str(&emitted).unwrap();
    assert_eq!(parsed.fixtures.len(), 1);
    assert_eq!(
        parsed.sender_certificate_validation.relay_domain,
        "relay.test"
    );

    println!("FIXTURE_START");
    println!("{emitted}");
    println!("FIXTURE_END");
}

/// Domain signing key the fixture's certificate is signed under.
///
/// Shares the seed with the sender-certificate fixtures so one trusted domain key covers both.
fn fixture_domain_signing_key() -> SigningKeyPair {
    generate_signing_key_pair(&mut ChaCha20Rng::from_seed([0x90; 32]))
}

/// Recipient contact the fixture message is addressed to.
///
/// The three draws from seed `0x71` must stay in this order — they are what
/// [`accepted_contact_discovery_key`] reproduces, and the discovery key is the third.
fn fixture_contact_identity() -> ContactIdentity {
    let mut rng = ChaCha20Rng::from_seed([0x71; 32]);
    let identity = generate_signing_key_pair(&mut rng);
    let identity_key_pair = generate_key_pair(&mut rng);
    let discovery_key = generate_discovery_key(&mut rng, &identity, 0, 1_700_000_000);
    ContactIdentity {
        identity_key: ContactIdentityKey {
            x25519_public_key: *identity_key_pair.public.as_bytes(),
            ed25519_verifying_key: identity.verifying.to_bytes(),
        },
        discovery_key: ContactDiscoveryKey::from(&discovery_key.bundle()),
    }
}

fn fixture_recipient_identity_signing_key() -> &'static SigningKeyPair {
    let mut rng = ChaCha20Rng::from_seed([0x71; 32]);
    Box::leak(Box::new(generate_signing_key_pair(&mut rng)))
}

/// Builds the v2 sender certificate binding the sender Identity Key to the relay domain.
///
/// Mirrors the layout `parse_certificate` accepts; the discovery-key pair and epoch that v1
/// carried are deliberately absent (AE-CRT-01, AE-IDN-05).
fn fixture_sender_certificate(
    signing_key_identifier: &[u8],
    sender_tag: u8,
    expires_at_secs: u64,
) -> Vec<u8> {
    let signing_key = SigningKeyPair::from_signing_bytes([sender_tag; 32]);
    let identity_key_pair = KeyPair::from_secret_bytes([sender_tag.wrapping_add(0x33); 32]);
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"AetherSenderCertificate-v2:");
    bytes.push(2);
    bytes.push(signing_key_identifier.len() as u8);
    bytes.extend_from_slice(signing_key_identifier);
    bytes.push(TEST_RELAY_DOMAIN.len() as u8);
    bytes.extend_from_slice(TEST_RELAY_DOMAIN);
    bytes.extend_from_slice(identity_key_pair.public.as_bytes());
    bytes.extend_from_slice(&signing_key.verifying.to_bytes());
    bytes.extend_from_slice(&expires_at_secs.to_be_bytes());
    bytes
}
