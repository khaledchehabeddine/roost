//! Feature-gated fixture replay exports for generated Swift and Kotlin bindings.

use crate::error::AetherError;
use aether_core::{
    AcknowledgmentOutcome, ContactDiscoveryKey, ContactIdentity, ContactIdentityKey,
    ContactSafetyNumberConfirmation, ContactStateChange, DomainSigningKey, DomainSigningKeyStatus,
    IdentityKey, InboundAcknowledgmentMessage, InboundEncryptedMessage, InboundMessageOutcome,
    InboundSenderCertificateValidation, Message, MessageId, OutboundAcknowledgment, PayloadKind,
    ProtocolStateAddress, ProtocolStateBlob, ProtocolStateEngine, ProtocolStateError,
    ProtocolStateKey, ProtocolStateKind, ProtocolStateSnapshot, ProtocolStateUpdate,
    RevocationState, SenderCertificateIdentityKey, SenderIdentityMaterial, SessionId,
    derive_safety_number,
};
use aether_crypto::{
    DiscoveryKey, HandshakeEnvelope, IdentityKeyBundle, InitialPlaintext, KeyPair, PreKeyBundle,
    RatchetState, SealedFramePreKeyReference, SigningKeyPair, accept, generate_discovery_key,
    generate_key_pair, generate_one_time_prekey, generate_signed_prekey_for_discovery_key,
    generate_signing_key_pair, initiate, sign_identity_key_binding,
};
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::Deserialize;

const CREATED_AT: u64 = 1_700_000_000;
const SESSION_REPLAY_RNG_SEED: [u8; 32] = [11u8; 32];
const DEDUPLICATION_REPLAY_RNG_SEED: [u8; 32] = [0x44; 32];
const OLD_SENDER_VISIBLE_MESSAGE_HEX: &str = "010000000000000000000000000000000120121212121212121212121212121212121212121212121212121212121212121220525252525252525252525252525252525252525252525252525252525252525281d095ffbc3100059091929394";

/// Transport-visible fields decoded from a Message fixture.
#[derive(uniffi::Record)]
pub struct MessageTransportFields {
    /// Sealed-frame wire version.
    pub version: u8,
    /// Recipient public key as lowercase hex.
    pub recipient_public_key_hex: String,
    /// Optional X3DH prekey reference.
    pub prekey_reference: Option<FramePreKeyReferenceReplay>,
    /// Per-frame ephemeral public key as lowercase hex.
    pub ephemeral_public_key_hex: String,
    /// Opaque frame ciphertext bytes as lowercase hex.
    pub ciphertext_hex: String,
}

/// Transport-visible X3DH prekey reference.
#[derive(uniffi::Record)]
pub struct FramePreKeyReferenceReplay {
    /// Recipient Discovery Key epoch.
    pub discovery_epoch: u32,
    /// Signed pre-key public key as lowercase hex.
    pub signed_prekey_public_key_hex: String,
    /// Optional one-time pre-key ID.
    pub one_time_prekey_id: Option<u64>,
    /// Optional one-time pre-key public key as lowercase hex.
    pub one_time_prekey_public_key_hex: Option<String>,
}

/// Sender identity material that is visible only after decrypt.
#[derive(uniffi::Record)]
pub struct SenderIdentityReplay {
    /// Sender identity key as lowercase hex.
    pub sender_identity_key_hex: String,
    /// Sender identity Ed25519 verifying key as lowercase hex.
    pub sender_identity_verifying_key_hex: String,
    /// Sender identity binding signature as lowercase hex.
    pub sender_identity_binding_signature_hex: String,
    /// Sender certificate bytes as lowercase hex.
    pub sender_certificate_hex: String,
    /// Sender signature bytes as lowercase hex.
    pub sender_signature_hex: String,
}

/// Replay result for a canonical Message wire fixture.
#[derive(uniffi::Record)]
pub struct MessageWireReplayCase {
    /// Fixture name.
    pub name: String,
    /// Transport-visible decoded fields.
    pub transport_visible: MessageTransportFields,
    /// Canonical re-encoded Message bytes as lowercase hex.
    pub reencoded_hex: String,
}

/// Replay result for a sealed-sender session Message fixture.
#[derive(uniffi::Record)]
pub struct SealedSenderReplayCase {
    /// Fixture name.
    pub name: String,
    /// Transport-visible decoded fields.
    pub transport_visible: MessageTransportFields,
    /// Decrypted plaintext bytes as lowercase hex.
    pub plaintext_hex: String,
    /// Sender identity material returned after decrypt.
    pub post_decryption: SenderIdentityReplay,
    /// Canonical re-encoded Message bytes as lowercase hex.
    pub reencoded_hex: String,
    /// True when sender identity key bytes are absent before decrypt.
    pub sender_identity_hidden_before_decrypt: bool,
    /// True when sender identity verifying-key bytes are absent before decrypt.
    pub sender_identity_verifying_key_hidden_before_decrypt: bool,
    /// True when sender identity binding signature bytes are absent before decrypt.
    pub sender_identity_binding_signature_hidden_before_decrypt: bool,
    /// True when sender certificate bytes are absent before decrypt.
    pub sender_certificate_hidden_before_decrypt: bool,
    /// True when sender signature bytes are absent before decrypt.
    pub sender_signature_hidden_before_decrypt: bool,
    /// True when tampered ciphertext returns an error and no sender material.
    pub tampered_ciphertext_rejected: bool,
}

/// Transport-visible fields decoded from an initial handshake fixture.
#[derive(uniffi::Record)]
pub struct InitialHandshakeTransportFields {
    /// Sealed-frame wire version.
    pub version: u8,
    /// Recipient Discovery Key public key as lowercase hex.
    pub recipient_public_key_hex: String,
    /// X3DH prekey reference.
    pub prekey_reference: Option<FramePreKeyReferenceReplay>,
    /// Initiator/frame ephemeral public key as lowercase hex.
    pub ephemeral_public_key_hex: String,
    /// Opaque frame ciphertext bytes as lowercase hex.
    pub ciphertext_hex: String,
}

/// Replay result for the sealed-sender initial handshake fixture.
#[derive(uniffi::Record)]
pub struct InitialHandshakeReplayCase {
    /// Fixture name.
    pub name: String,
    /// Transport-visible decoded fields.
    pub transport_visible: InitialHandshakeTransportFields,
    /// Decrypted first-message plaintext bytes as lowercase hex.
    pub plaintext_hex: String,
    /// Sender identity material returned after decrypt.
    pub post_decryption: SenderIdentityReplay,
    /// Canonical re-encoded initial handshake bytes as lowercase hex.
    pub reencoded_hex: String,
    /// True when sender identity key bytes are absent before decrypt.
    pub sender_identity_hidden_before_decrypt: bool,
    /// True when sender identity verifying-key bytes are absent before decrypt.
    pub sender_identity_verifying_key_hidden_before_decrypt: bool,
    /// True when sender identity binding signature bytes are absent before decrypt.
    pub sender_identity_binding_signature_hidden_before_decrypt: bool,
    /// True when sender certificate bytes are absent before decrypt.
    pub sender_certificate_hidden_before_decrypt: bool,
    /// True when sender signature bytes are absent before decrypt.
    pub sender_signature_hidden_before_decrypt: bool,
    /// True when tampered ciphertext returns an error and no sender material.
    pub tampered_ciphertext_rejected: bool,
}

/// Replay result for a Protocol State Blob fixture.
#[derive(uniffi::Record)]
pub struct BlobReplayCase {
    /// Fixture name.
    pub name: String,
    /// Protocol State Kind using fixture spelling.
    pub kind: String,
    /// Protocol State Key as lowercase hex.
    pub key_hex: String,
    /// Blob major version.
    pub major: u8,
    /// Blob minor version.
    pub minor: u8,
    /// Canonical re-encoded Blob bytes as lowercase hex.
    pub reencoded_hex: String,
}

/// Full binding fixture replay report.
#[derive(uniffi::Record)]
pub struct FixtureReplayReport {
    /// Message wire replay cases.
    pub message_wire_cases: Vec<MessageWireReplayCase>,
    /// Sealed-sender session Message replay cases.
    pub sealed_sender_session_cases: Vec<SealedSenderReplayCase>,
    /// Initial handshake replay cases.
    pub initial_handshake_cases: Vec<InitialHandshakeReplayCase>,
    /// Protocol State Blob replay cases.
    pub protocol_state_blob_cases: Vec<BlobReplayCase>,
    /// True when unsupported Message versions reject.
    pub unsupported_message_version_rejected: bool,
    /// True when malformed Message bytes reject.
    pub malformed_message_rejected: bool,
    /// True when old sender-visible Message bytes reject.
    pub old_sender_visible_message_rejected: bool,
    /// True when unsupported initial handshake versions reject.
    pub unsupported_initial_handshake_version_rejected: bool,
    /// True when malformed initial handshake bytes reject.
    pub malformed_initial_handshake_rejected: bool,
    /// True when unsupported Protocol State Blob major versions reject.
    pub unsupported_blob_major_rejected: bool,
    /// True when malformed Protocol State Blob bytes reject.
    pub malformed_blob_rejected: bool,
}

#[derive(Deserialize)]
struct MessageFixtureFile {
    version: u8,
    fixtures: Vec<MessageFixture>,
}

#[derive(Deserialize)]
struct MessageFixture {
    name: String,
    encoded_hex: String,
    decoded: MessageDecodedFixture,
}

#[derive(Deserialize)]
struct MessageDecodedFixture {
    version: u8,
    recipient_public_key_hex: String,
    prekey_reference: Option<PreKeyReferenceFixture>,
    ephemeral_public_key_hex: String,
    ciphertext_hex: String,
}

#[derive(Clone, Deserialize)]
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
struct SessionMessageFixtureFile {
    session_key_hex: String,
    sender_certificate_validation: CertificateValidationFixture,
    fixtures: Vec<SessionMessageFixture>,
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
struct SessionMessageFixture {
    name: String,
    sender_state_fixture: String,
    recipient_state_fixture: String,
    encoded_hex: String,
    transport_visible: MessageDecodedFixture,
    decrypted_metadata: DecryptedMetadataFixture,
    plaintext_hex: String,
    post_decryption: SenderIdentityFixture,
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
    current_version: BlobVersionFixture,
    fixtures: Vec<BlobFixture>,
}

#[derive(Deserialize)]
struct BlobVersionFixture {
    major: u8,
    minor: u8,
}

#[derive(Deserialize)]
struct BlobFixture {
    name: String,
    kind: String,
    key_hex: String,
    current_encoded_hex: String,
    replay: Option<BlobReplayFixture>,
}

#[derive(Deserialize)]
struct BlobReplayFixture {
    encoded_message_hex: String,
    digest_hex: String,
}

#[derive(Deserialize)]
struct TranscriptFixture {
    rng_seed: [u8; 32],
    created_at: u64,
    alice_discovery_epoch: u32,
    bob_discovery_epoch: u32,
    bob_one_time_prekey_id: u64,
    handshake_plaintext: String,
    handshake_envelope: TranscriptEnvelopeFixture,
    handshake_envelope_encoded_hex: String,
}

#[derive(Deserialize)]
struct TranscriptEnvelopeFixture {
    version: u8,
    recipient_public_key: [u8; 32],
    prekey_reference: Option<TranscriptPreKeyReferenceFixture>,
    ephemeral_public_key: [u8; 32],
    ciphertext_hex: String,
}

#[derive(Clone, Copy, Deserialize)]
struct TranscriptPreKeyReferenceFixture {
    discovery_epoch: u32,
    signed_prekey_public_key: [u8; 32],
    one_time_prekey_id: Option<u64>,
    one_time_prekey_public_key: Option<[u8; 32]>,
}

struct SessionSetup {
    alice_state: RatchetState,
    bob_state: RatchetState,
}

struct PreparedInitialHandshake {
    rng: ChaCha20Rng,
    generated_envelope: HandshakeEnvelope,
    initiator_identity_key: IdentityKeyBundle,
    responder_identity_key: IdentityKeyBundle,
    bob_discovery_key: aether_crypto::DiscoveryKey,
    bob_signed_prekey: aether_crypto::SignedPreKey,
    bob_one_time_prekey: aether_crypto::OneTimePreKey,
    sender_identity: SenderIdentityMaterial,
}

/// Replays every canonical fixture category exposed to binding maintainers.
///
/// This test-only API is available only with the `fixture-replay` feature.
///
/// # Errors
/// - [`AetherError::InvalidData`] when a checked-in fixture is malformed.
/// - [`AetherError::InternalError`] when replay detects a fixture mismatch.
#[uniffi::export]
pub fn replay_fixture_harness() -> Result<FixtureReplayReport, AetherError> {
    Ok(FixtureReplayReport {
        message_wire_cases: replay_message_wire_fixtures()?,
        sealed_sender_session_cases: replay_sealed_sender_session_fixtures()?,
        initial_handshake_cases: replay_initial_handshake_fixtures()?,
        protocol_state_blob_cases: replay_protocol_state_blob_fixtures()?,
        unsupported_message_version_rejected: unsupported_message_version_rejected(),
        malformed_message_rejected: malformed_message_rejected(),
        old_sender_visible_message_rejected: old_sender_visible_message_rejected()?,
        unsupported_initial_handshake_version_rejected:
            unsupported_initial_handshake_version_rejected(),
        malformed_initial_handshake_rejected: malformed_initial_handshake_rejected(),
        unsupported_blob_major_rejected: unsupported_blob_major_rejected()?,
        malformed_blob_rejected: malformed_blob_rejected()?,
    })
}

/// Replays canonical Message wire fixtures through generated bindings.
///
/// # Errors
/// - [`AetherError::InvalidData`] when fixture JSON or hex is malformed.
/// - [`AetherError::InternalError`] when Message decode, encode, or field replay fails.
#[uniffi::export]
pub fn replay_message_wire_fixtures() -> Result<Vec<MessageWireReplayCase>, AetherError> {
    let fixture_file: MessageFixtureFile = fixture_json(include_str!(
        "../../aether-core/tests/fixtures/message_wire_v1.json"
    ))?;
    ensure(
        fixture_file.version == 1,
        "message fixture version must be 1",
    )?;

    fixture_file
        .fixtures
        .iter()
        .map(replay_message_wire_fixture)
        .collect()
}

/// Replays canonical sealed-sender session Message fixtures through generated bindings.
///
/// # Errors
/// - [`AetherError::InvalidData`] when fixture JSON, hex, or referenced state is malformed.
/// - [`AetherError::InternalError`] when decode, re-encode, decrypt, or tamper replay fails.
#[uniffi::export]
pub fn replay_sealed_sender_session_fixtures() -> Result<Vec<SealedSenderReplayCase>, AetherError> {
    let session_file: SessionMessageFixtureFile = fixture_json(include_str!(
        "../../aether-core/tests/fixtures/sealed_sender_session_messages_v1.json"
    ))?;
    let blob_file: BlobFixtureFile = fixture_json(include_str!(
        "../../aether-core/tests/fixtures/protocol_state_blobs_v1.json"
    ))?;
    let key = ProtocolStateKey::from_bytes(decode_hex(
        &session_file.session_key_hex,
        "session message fixture key",
    )?)
    .map_err(|e| invalid_fixture(format!("invalid session fixture key: {e}")))?;
    let deduplication_key = deduplication_key()?;
    let validation = certificate_validation(&session_file.sender_certificate_validation)?;
    let domain_signing_keys = validation.domain_signing_keys();

    session_file
        .fixtures
        .iter()
        .map(|fixture| {
            replay_sealed_sender_session_fixture(
                fixture,
                &blob_file,
                &key,
                &deduplication_key,
                &domain_signing_keys,
                &validation,
            )
        })
        .collect()
}

/// Replays the canonical sealed-sender initial handshake fixture through generated bindings.
///
/// # Errors
/// - [`AetherError::InvalidData`] when fixture JSON or hex is malformed.
/// - [`AetherError::InternalError`] when decode, re-encode, decrypt, or tamper replay fails.
#[uniffi::export]
pub fn replay_initial_handshake_fixtures() -> Result<Vec<InitialHandshakeReplayCase>, AetherError> {
    let transcript: TranscriptFixture = fixture_json(include_str!(
        "../../aether-crypto/tests/fixtures/session_transcript_v1.json"
    ))?;
    Ok(vec![replay_initial_handshake_fixture(&transcript)?])
}

/// Replays canonical Protocol State Blob fixtures through generated bindings.
///
/// # Errors
/// - [`AetherError::InvalidData`] when fixture JSON, hex, kind, or key data is malformed.
/// - [`AetherError::InternalError`] when blob re-encoding or version replay fails.
#[uniffi::export]
pub fn replay_protocol_state_blob_fixtures() -> Result<Vec<BlobReplayCase>, AetherError> {
    let fixture_file: BlobFixtureFile = fixture_json(include_str!(
        "../../aether-core/tests/fixtures/protocol_state_blobs_v1.json"
    ))?;
    let setup = session_setup()?;
    let sender_identity = session_sender_identity()?;
    ensure(
        fixture_file.current_version.major == 1 && fixture_file.current_version.minor == 0,
        "protocol-state blob fixture version must be 1.0",
    )?;

    fixture_file
        .fixtures
        .iter()
        .map(|fixture| replay_protocol_state_blob_fixture(fixture, &setup, &sender_identity))
        .collect()
}

fn replay_message_wire_fixture(
    fixture: &MessageFixture,
) -> Result<MessageWireReplayCase, AetherError> {
    let encoded = decode_hex(&fixture.encoded_hex, &fixture.name)?;
    let message = Message::from_bytes(&encoded).map_err(|e| {
        replay_failure(format!(
            "message fixture {} failed to decode: {e}",
            fixture.name
        ))
    })?;
    let transport_visible = message_transport_fields(&message);
    assert_message_transport(&transport_visible, &fixture.decoded, &fixture.name)?;
    let reencoded = message.to_bytes().map_err(|e| {
        replay_failure(format!(
            "message fixture {} failed to re-encode: {e}",
            fixture.name
        ))
    })?;
    ensure(
        reencoded == encoded,
        format!(
            "message fixture {} did not re-encode canonically",
            fixture.name
        ),
    )?;

    Ok(MessageWireReplayCase {
        name: fixture.name.clone(),
        transport_visible,
        reencoded_hex: hex::encode(reencoded),
    })
}

fn replay_sealed_sender_session_fixture(
    fixture: &SessionMessageFixture,
    blob_file: &BlobFixtureFile,
    key: &ProtocolStateKey,
    deduplication_key: &ProtocolStateKey,
    domain_signing_keys: &[DomainSigningKey<'_>],
    validation: &OwnedCertificateValidation,
) -> Result<SealedSenderReplayCase, AetherError> {
    let encoded = decode_hex(&fixture.encoded_hex, &fixture.name)?;
    let message = Message::from_bytes(&encoded).map_err(|e| {
        replay_failure(format!(
            "sealed session fixture {} failed to decode: {e}",
            fixture.name
        ))
    })?;
    let transport_visible = message_transport_fields(&message);
    assert_message_transport(
        &transport_visible,
        &fixture.transport_visible,
        &fixture.name,
    )?;
    let reencoded = message.to_bytes().map_err(|e| {
        replay_failure(format!(
            "sealed session fixture {} failed to re-encode: {e}",
            fixture.name
        ))
    })?;
    ensure(
        reencoded == encoded,
        format!(
            "sealed session fixture {} did not re-encode canonically",
            fixture.name
        ),
    )?;

    let sender_identity = sender_identity_from_fixture(&fixture.post_decryption)?;
    let acknowledgment_sender_identity = acknowledgment_sender_identity()?;
    let acknowledgment_sender_signing_key =
        sender_identity_signing_key(&acknowledgment_sender_identity)?;
    let pre_auth_hidden = pre_auth_sender_material_hidden(&encoded, &sender_identity);
    let mut recipient_snapshot =
        snapshot_from_blob_fixture(blob_file, &fixture.recipient_state_fixture, key)?;
    insert_blob_fixture(
        &mut recipient_snapshot,
        blob_file,
        "deduplication_set_identity",
        deduplication_key,
    )?;
    let decrypted = accepted(
        ProtocolStateEngine::new()
            .decrypt_message(
                &mut ChaCha20Rng::from_seed(SESSION_REPLAY_RNG_SEED),
                &recipient_snapshot,
                inbound(
                    key.clone(),
                    deduplication_key.clone(),
                    &message,
                    &acknowledgment_sender_identity,
                    &acknowledgment_sender_signing_key,
                    domain_signing_keys,
                    &validation.relay_domain,
                    &validation.revoked_identity_keys,
                    validation.reference_timestamp_secs,
                    validation.grace_window_secs,
                ),
            )
            .map_err(|e| {
                replay_failure(format!(
                    "sealed session fixture {} failed to decrypt: {e}",
                    fixture.name
                ))
            })?,
    )?;
    assert_decrypted_metadata(&decrypted, &fixture.decrypted_metadata, &fixture.name)?;
    assert_decrypted_sender(
        decrypted.plaintext.as_slice(),
        &decrypted.sender_identity,
        &fixture.plaintext_hex,
        &fixture.post_decryption,
        &fixture.name,
    )?;
    assert_acknowledgment_artifact(
        &decrypted.acknowledgment,
        decrypted.message_id,
        &acknowledgment_sender_identity,
        &fixture.name,
    )?;
    recipient_snapshot.apply_all(decrypted.state_updates);
    assert_sender_state_fixture_matches(blob_file, &fixture.sender_state_fixture)?;
    let tampered_ciphertext_rejected = session_tamper_rejects_without_sender(
        blob_file,
        &fixture.recipient_state_fixture,
        key,
        deduplication_key,
        &message,
        domain_signing_keys,
        validation,
    )?;

    Ok(SealedSenderReplayCase {
        name: fixture.name.clone(),
        transport_visible,
        plaintext_hex: fixture.plaintext_hex.clone(),
        post_decryption: sender_identity_report(&decrypted.sender_identity),
        reencoded_hex: hex::encode(reencoded),
        sender_identity_hidden_before_decrypt: pre_auth_hidden.identity_key,
        sender_identity_verifying_key_hidden_before_decrypt: pre_auth_hidden.verifying_key,
        sender_identity_binding_signature_hidden_before_decrypt: pre_auth_hidden.binding_signature,
        sender_certificate_hidden_before_decrypt: pre_auth_hidden.certificate,
        sender_signature_hidden_before_decrypt: pre_auth_hidden.signature,
        tampered_ciphertext_rejected,
    })
}

fn replay_initial_handshake_fixture(
    transcript: &TranscriptFixture,
) -> Result<InitialHandshakeReplayCase, AetherError> {
    let mut prepared = prepare_initial_handshake(transcript)?;
    let encoded = decode_hex(
        &transcript.handshake_envelope_encoded_hex,
        "initial handshake encoded fixture",
    )?;
    let decoded = HandshakeEnvelope::from_bytes(&encoded)
        .map_err(|e| replay_failure(format!("initial handshake fixture failed to decode: {e}")))?;
    assert_envelope_eq(&prepared.generated_envelope, &decoded, "initial handshake")?;
    assert_transcript_envelope(&decoded, &transcript.handshake_envelope)?;
    let reencoded = decoded.to_bytes().map_err(|e| {
        replay_failure(format!(
            "initial handshake fixture failed to re-encode: {e}"
        ))
    })?;
    ensure(
        reencoded == encoded,
        "initial handshake fixture did not re-encode canonically",
    )?;

    let expected_sender = &prepared.sender_identity;
    let pre_auth_hidden = pre_auth_sender_material_hidden(&encoded, expected_sender);
    let (_, accepted) = accept(
        &mut prepared.rng,
        &decoded,
        Some(&prepared.initiator_identity_key),
        &prepared.responder_identity_key,
        &prepared.bob_discovery_key,
        &prepared.bob_signed_prekey,
        Some(prepared.bob_one_time_prekey),
    )
    .map_err(|e| replay_failure(format!("initial handshake fixture failed to decrypt: {e}")))?;
    assert_sender_identity(
        &accepted.sender_identity,
        expected_sender,
        "initial handshake sender",
    )?;
    ensure(
        accepted.plaintext.as_slice() == transcript.handshake_plaintext.as_bytes(),
        "initial handshake plaintext did not match fixture",
    )?;

    Ok(InitialHandshakeReplayCase {
        name: "initial_handshake".into(),
        transport_visible: initial_handshake_transport_fields(&decoded),
        plaintext_hex: hex::encode(accepted.plaintext.as_slice()),
        post_decryption: sender_identity_report(&accepted.sender_identity),
        reencoded_hex: hex::encode(reencoded),
        sender_identity_hidden_before_decrypt: pre_auth_hidden.identity_key,
        sender_identity_verifying_key_hidden_before_decrypt: pre_auth_hidden.verifying_key,
        sender_identity_binding_signature_hidden_before_decrypt: pre_auth_hidden.binding_signature,
        sender_certificate_hidden_before_decrypt: pre_auth_hidden.certificate,
        sender_signature_hidden_before_decrypt: pre_auth_hidden.signature,
        tampered_ciphertext_rejected: initial_handshake_tamper_rejects_without_sender(transcript)?,
    })
}

fn replay_protocol_state_blob_fixture(
    fixture: &BlobFixture,
    setup: &SessionSetup,
    sender_identity: &SenderIdentityMaterial,
) -> Result<BlobReplayCase, AetherError> {
    let key = ProtocolStateKey::from_bytes(decode_hex(&fixture.key_hex, &fixture.name)?)
        .map_err(|e| invalid_fixture(format!("invalid blob fixture key: {e}")))?;
    let kind = protocol_state_kind(&fixture.kind)?;
    let encoded = decode_hex(&fixture.current_encoded_hex, &fixture.name)?;
    let major = *encoded
        .first()
        .ok_or_else(|| invalid_fixture(format!("blob fixture {} is empty", fixture.name)))?;
    let minor = *encoded.get(1).ok_or_else(|| {
        invalid_fixture(format!(
            "blob fixture {} has no minor version",
            fixture.name
        ))
    })?;
    let update = match fixture.name.as_str() {
        "ratchet_session_alice" => {
            ensure(
                kind == ProtocolStateKind::RatchetSession,
                "ratchet fixture kind mismatch",
            )?;
            ProtocolStateEngine::new().set_session_state(key, &setup.alice_state)
        }
        "ratchet_session_bob_bound" => {
            ensure(
                kind == ProtocolStateKind::RatchetSession,
                "ratchet fixture kind mismatch",
            )?;
            ProtocolStateEngine::new().set_session_state_with_peer_identity(
                key,
                &setup.bob_state,
                sender_identity,
            )
        }
        "deduplication_set_identity" => {
            ensure(
                kind == ProtocolStateKind::DeduplicationSet,
                "deduplication fixture kind mismatch",
            )?;
            ProtocolStateEngine::new().initialize_deduplication_set(
                &mut ChaCha20Rng::from_seed(DEDUPLICATION_REPLAY_RNG_SEED),
                key,
            )
        }
        "deduplication_set_identity_with_duplicate_message" => {
            ensure(
                kind == ProtocolStateKind::DeduplicationSet,
                "deduplication fixture kind mismatch",
            )?;
            assert_duplicate_inbound_blob_replay(fixture, &encoded, key.clone())?;
            Ok(ProtocolStateUpdate::set(
                ProtocolStateAddress::new(kind, key),
                ProtocolStateBlob::from_bytes(encoded.clone()),
            ))
        }
        "pending_acknowledgments_session" => {
            ensure(
                kind == ProtocolStateKind::PendingAcknowledgments,
                "pending acknowledgment fixture kind mismatch",
            )?;
            ProtocolStateEngine::new().initialize_pending_acknowledgments(key)
        }
        "pending_acknowledgments_session_with_duplicate_ack" => {
            ensure(
                kind == ProtocolStateKind::PendingAcknowledgments,
                "pending acknowledgment fixture kind mismatch",
            )?;
            assert_duplicate_acknowledgment_blob_replay(fixture, &encoded, key.clone())?;
            Ok(ProtocolStateUpdate::set(
                ProtocolStateAddress::new(kind, key),
                ProtocolStateBlob::from_bytes(encoded.clone()),
            ))
        }
        "contact_pending"
        | "contact_unverified"
        | "contact_verified"
        | "contact_dk_rotated_unverified"
        | "contact_dk_rotated_verified"
        | "contact_blocked_pending"
        | "contact_blocked_unverified"
        | "contact_blocked_verified"
        | "contact_dk_rotated_blocked"
        | "contact_unblocked_restored_state" => {
            ensure(
                kind == ProtocolStateKind::ContactState,
                "contact fixture kind mismatch",
            )?;
            ensure(
                key.as_bytes() == contact_fixture_identity().identity_key.canonical_encoding(),
                "contact fixture key mismatch",
            )?;
            contact_fixture_update(&fixture.name)
        }
        _ => {
            return Err(invalid_fixture(format!(
                "unknown blob fixture: {}",
                fixture.name
            )));
        }
    }
    .map_err(|e| {
        replay_failure(format!(
            "blob fixture {} failed to re-encode: {e}",
            fixture.name
        ))
    })?;
    let reencoded = update
        .blob()
        .ok_or_else(|| replay_failure(format!("blob fixture {} produced no blob", fixture.name)))?
        .as_bytes()
        .to_vec();
    ensure(
        reencoded == encoded,
        format!(
            "blob fixture {} did not re-encode canonically",
            fixture.name
        ),
    )?;

    Ok(BlobReplayCase {
        name: fixture.name.clone(),
        kind: fixture.kind.clone(),
        key_hex: fixture.key_hex.clone(),
        major,
        minor,
        reencoded_hex: hex::encode(reencoded),
    })
}

fn required_blob_replay(fixture: &BlobFixture) -> Result<&BlobReplayFixture, AetherError> {
    fixture
        .replay
        .as_ref()
        .ok_or_else(|| invalid_fixture(format!("blob fixture {} has no replay", fixture.name)))
}

fn assert_duplicate_inbound_blob_replay(
    fixture: &BlobFixture,
    encoded_blob: &[u8],
    deduplication_key: ProtocolStateKey,
) -> Result<(), AetherError> {
    let replay = required_blob_replay(fixture)?;
    let encoded_message = decode_hex(&replay.encoded_message_hex, &fixture.name)?;
    let message = Message::from_bytes(&encoded_message).map_err(|e| {
        invalid_fixture(format!(
            "blob fixture {} replay message failed to decode: {e}",
            fixture.name
        ))
    })?;
    ensure(
        message.version == 1 && message.prekey_reference.is_none(),
        format!(
            "blob fixture {} replay message is not a session frame",
            fixture.name
        ),
    )?;
    let mut digest_key = [0u8; 32];
    ChaCha20Rng::from_seed(DEDUPLICATION_REPLAY_RNG_SEED).fill_bytes(&mut digest_key);
    let digest = blake3::keyed_hash(&digest_key, &encoded_message);
    ensure(
        hex::encode(&digest.as_bytes()[..16]) == replay.digest_hex,
        format!("blob fixture {} replay digest mismatch", fixture.name),
    )?;

    let address = ProtocolStateAddress::new(
        ProtocolStateKind::DeduplicationSet,
        deduplication_key.clone(),
    );
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot.set(
        address,
        ProtocolStateBlob::from_bytes(encoded_blob.to_vec()),
    );
    let acknowledgment_sender_identity = acknowledgment_sender_identity()?;
    let acknowledgment_sender_signing_key =
        sender_identity_signing_key(&acknowledgment_sender_identity)?;
    let outcome = ProtocolStateEngine::new()
        .decrypt_message(
            &mut ChaCha20Rng::from_seed(SESSION_REPLAY_RNG_SEED),
            &snapshot,
            InboundEncryptedMessage {
                session_key: ProtocolStateKey::session(SessionId::from_bytes([9u8; 16])),
                deduplication_key,
                message: &message,
                recipient_discovery_key: Box::leak(Box::new(contact_fixture_discovery_key())),
                acknowledgment: acknowledgment(
                    &acknowledgment_sender_identity,
                    &acknowledgment_sender_signing_key,
                ),
                sender_certificate_validation: None,
            },
        )
        .map_err(|e| replay_failure(format!("blob fixture {} replay failed: {e}", fixture.name)))?;
    ensure(
        matches!(outcome, InboundMessageOutcome::Duplicate),
        format!(
            "blob fixture {} did not replay as duplicate message",
            fixture.name
        ),
    )
}

fn assert_duplicate_acknowledgment_blob_replay(
    fixture: &BlobFixture,
    encoded_blob: &[u8],
    session_key: ProtocolStateKey,
) -> Result<(), AetherError> {
    let replay = required_blob_replay(fixture)?;
    let encoded_message = decode_hex(&replay.encoded_message_hex, &fixture.name)?;
    let message = Message::from_bytes(&encoded_message).map_err(|e| {
        invalid_fixture(format!(
            "blob fixture {} replay acknowledgment failed to decode: {e}",
            fixture.name
        ))
    })?;
    ensure(
        message.version == 1 && message.prekey_reference.is_none(),
        format!(
            "blob fixture {} replay message is not a session frame",
            fixture.name
        ),
    )?;
    let digest = blake3::hash(&encoded_message);
    ensure(
        hex::encode(&digest.as_bytes()[..16]) == replay.digest_hex,
        format!("blob fixture {} replay digest mismatch", fixture.name),
    )?;

    let address = ProtocolStateAddress::new(
        ProtocolStateKind::PendingAcknowledgments,
        session_key.clone(),
    );
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot.set(
        address,
        ProtocolStateBlob::from_bytes(encoded_blob.to_vec()),
    );
    let outcome = ProtocolStateEngine::new()
        .process_acknowledgment(
            &mut ChaCha20Rng::from_seed(SESSION_REPLAY_RNG_SEED),
            &snapshot,
            InboundAcknowledgmentMessage {
                session_key,
                message: &message,
                recipient_discovery_key: Box::leak(Box::new(contact_fixture_discovery_key())),
            },
        )
        .map_err(|e| replay_failure(format!("blob fixture {} replay failed: {e}", fixture.name)))?;
    ensure(
        matches!(outcome, AcknowledgmentOutcome::Duplicate),
        format!(
            "blob fixture {} did not replay as duplicate acknowledgment",
            fixture.name
        ),
    )
}

fn contact_fixture_identity() -> ContactIdentity {
    contact_fixture_identities().0
}

fn contact_fixture_local_identity() -> IdentityKey {
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

fn contact_fixture_discovery_key() -> DiscoveryKey {
    let mut rng = ChaCha20Rng::from_seed([0x71; 32]);
    let identity = generate_signing_key_pair(&mut rng);
    let _identity_key_pair = generate_key_pair(&mut rng);
    generate_discovery_key(&mut rng, &identity, 0, CREATED_AT)
}

fn acknowledgment_recipient_discovery_key() -> DiscoveryKey {
    DiscoveryKey::from_secret_bytes([0xc2; 32], [0xc3; 32], 0, CREATED_AT, [0u8; 64])
}

fn contact_fixture_update(name: &str) -> Result<ProtocolStateUpdate, ProtocolStateError> {
    let engine = ProtocolStateEngine::new();
    let (contact, rotated_contact) = contact_fixture_identities();
    let mut snapshot = ProtocolStateSnapshot::new();
    let pending = engine.record_contact(&snapshot, contact)?;
    if name == "contact_pending" {
        return contact_fixture_state_update(pending, contact.identity_key);
    }
    snapshot.apply_all(pending.state_updates);
    if name == "contact_blocked_pending" {
        let blocked = engine.block_contact(&snapshot, contact.identity_key)?;
        return contact_fixture_state_update(blocked, contact.identity_key);
    }

    let unverified = engine.accept_contact(&snapshot, contact.identity_key)?;
    if name == "contact_unverified" {
        return contact_fixture_state_update(unverified, contact.identity_key);
    }
    snapshot.apply_all(unverified.state_updates);
    if name == "contact_blocked_unverified" {
        let blocked = engine.block_contact(&snapshot, contact.identity_key)?;
        return contact_fixture_state_update(blocked, contact.identity_key);
    }

    if name == "contact_dk_rotated_unverified" {
        let update = engine.record_contact(&snapshot, rotated_contact)?;
        return contact_fixture_state_update(update, contact.identity_key);
    }
    if name == "contact_dk_rotated_blocked" {
        let blocked = engine.block_contact(&snapshot, contact.identity_key)?;
        snapshot.apply_all(blocked.state_updates);
        let update = engine.record_contact(&snapshot, rotated_contact)?;
        return contact_fixture_state_update(update, contact.identity_key);
    }

    let local_identity_key = contact_fixture_local_identity();
    let safety_number =
        derive_safety_number(local_identity_key, contact.identity_key).map_err(|_| {
            ProtocolStateError::InvalidStateBinding {
                address: ProtocolStateAddress::new(
                    ProtocolStateKind::ContactState,
                    ProtocolStateKey::from(contact.identity_key),
                ),
                reason: "contact fixture safety number failed".into(),
            }
        })?;
    let verified = engine.confirm_contact_safety_number(
        &snapshot,
        local_identity_key,
        contact.identity_key,
        &safety_number.grouped_decimal,
    )?;
    let ContactSafetyNumberConfirmation::Matched(verified) = verified else {
        return Err(ProtocolStateError::InvalidStateBinding {
            address: ProtocolStateAddress::new(
                ProtocolStateKind::ContactState,
                ProtocolStateKey::from(contact.identity_key),
            ),
            reason: "contact fixture safety number mismatched".into(),
        });
    };
    if name == "contact_verified" {
        return contact_fixture_state_update(verified, contact.identity_key);
    }
    snapshot.apply_all(verified.state_updates);
    if name == "contact_blocked_verified" {
        let blocked = engine.block_contact(&snapshot, contact.identity_key)?;
        return contact_fixture_state_update(blocked, contact.identity_key);
    }
    if name == "contact_unblocked_restored_state" {
        let blocked = engine.block_contact(&snapshot, contact.identity_key)?;
        snapshot.apply_all(blocked.state_updates);
        let unblocked = engine.unblock_contact(&snapshot, contact.identity_key)?;
        return contact_fixture_state_update(unblocked, contact.identity_key);
    }

    let update = engine.record_contact(&snapshot, rotated_contact)?;
    contact_fixture_state_update(update, contact.identity_key)
}

fn contact_fixture_state_update(
    change: ContactStateChange,
    identity_key: ContactIdentityKey,
) -> Result<ProtocolStateUpdate, ProtocolStateError> {
    let address = ProtocolStateAddress::new(
        ProtocolStateKind::ContactState,
        ProtocolStateKey::from(identity_key),
    );
    let mut updates = change.state_updates.into_iter();
    let update = updates
        .next()
        .ok_or_else(|| ProtocolStateError::InvalidStateBinding {
            address: address.clone(),
            reason: "contact fixture produced no state update".into(),
        })?;
    if updates.next().is_some() {
        return Err(ProtocolStateError::InvalidStateBinding {
            address,
            reason: "contact fixture produced multiple state updates".into(),
        });
    }
    Ok(update)
}

fn session_setup() -> Result<SessionSetup, AetherError> {
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let alice_identity = generate_signing_key_pair(&mut rng);
    let bob_identity = generate_signing_key_pair(&mut rng);
    let alice_identity_key = identity_key_bundle(&mut rng, &alice_identity)?;
    let bob_identity_key = identity_key_bundle(&mut rng, &bob_identity)?;
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
    .map_err(|e| replay_failure(format!("failed to create deterministic session: {e}")))?;
    let (bob_state, accepted) = accept(
        &mut rng,
        &envelope,
        Some(&alice_identity_key),
        &bob_identity_key,
        &bob_discovery,
        &bob_signed_prekey,
        Some(bob_one_time_prekey),
    )
    .map_err(|e| replay_failure(format!("failed to accept deterministic session: {e}")))?;
    ensure(
        accepted.plaintext.as_slice() == b"initial",
        "deterministic session plaintext mismatch",
    )?;
    Ok(SessionSetup {
        alice_state,
        bob_state,
    })
}

fn prepare_initial_handshake(
    transcript: &TranscriptFixture,
) -> Result<PreparedInitialHandshake, AetherError> {
    let mut rng = ChaCha20Rng::from_seed(transcript.rng_seed);
    let alice_identity = generate_signing_key_pair(&mut rng);
    let alice_identity_key = identity_key_bundle(&mut rng, &alice_identity)?;
    let alice_discovery_key = generate_discovery_key(
        &mut rng,
        &alice_identity,
        transcript.alice_discovery_epoch,
        transcript.created_at,
    );
    let bob_identity = generate_signing_key_pair(&mut rng);
    let bob_identity_key = identity_key_bundle(&mut rng, &bob_identity)?;
    let bob_discovery_key = generate_discovery_key(
        &mut rng,
        &bob_identity,
        transcript.bob_discovery_epoch,
        transcript.created_at,
    );
    let bob_signed_prekey = generate_signed_prekey_for_discovery_key(
        &mut rng,
        &bob_discovery_key,
        transcript.created_at,
    );
    let bob_one_time_prekey = generate_one_time_prekey(
        &mut rng,
        transcript.bob_one_time_prekey_id,
        bob_discovery_key.epoch(),
        transcript.created_at,
    );
    let prekey_bundle = PreKeyBundle {
        version: aether_crypto::PREKEY_BUNDLE_VERSION,
        discovery_key: bob_discovery_key.bundle(),
        signed_prekey: bob_signed_prekey.bundle(),
        one_time_prekey: Some(bob_one_time_prekey.bundle()),
    };
    let (_, generated_envelope) = initiate(
        &mut rng,
        &alice_discovery_key,
        &alice_identity_key,
        &bob_identity_key,
        &prekey_bundle,
        initial_plaintext(transcript.handshake_plaintext.as_bytes()),
    )
    .map_err(|e| {
        replay_failure(format!(
            "failed to create deterministic initial handshake: {e}"
        ))
    })?;
    Ok(PreparedInitialHandshake {
        rng,
        generated_envelope,
        sender_identity: SenderIdentityMaterial {
            identity_key: *alice_identity_key.public_key.as_bytes(),
            identity_verifying_key: alice_identity_key.verifying_key.to_bytes(),
            identity_binding_signature: alice_identity_key.binding_signature.to_bytes().to_vec(),
            certificate: b"sender certificate".to_vec(),
            signature: b"sender signature".to_vec(),
        },
        initiator_identity_key: alice_identity_key,
        responder_identity_key: bob_identity_key,
        bob_discovery_key,
        bob_signed_prekey,
        bob_one_time_prekey,
    })
}

fn identity_key_bundle(
    rng: &mut ChaCha20Rng,
    signing_key: &SigningKeyPair,
) -> Result<IdentityKeyBundle, AetherError> {
    let agreement_key = generate_key_pair(rng);
    let binding_signature = sign_identity_key_binding(signing_key, &agreement_key.public)
        .map_err(|e| replay_failure(format!("failed to sign identity key binding: {e}")))?;
    Ok(IdentityKeyBundle {
        public_key: agreement_key.public,
        verifying_key: signing_key.verifying,
        binding_signature,
    })
}

fn initial_plaintext(plaintext: &[u8]) -> InitialPlaintext<'_> {
    InitialPlaintext {
        sender_certificate: b"sender certificate",
        sender_signature: b"sender signature",
        plaintext,
    }
}

fn session_sender_identity() -> Result<SenderIdentityMaterial, AetherError> {
    sender_identity_with_material(1, vec![2, 3, 4], vec![5; 64])
}

fn sender_identity_from_fixture(
    fixture: &SenderIdentityFixture,
) -> Result<SenderIdentityMaterial, AetherError> {
    Ok(SenderIdentityMaterial {
        identity_key: hex_array(
            &fixture.sender_identity_key_hex,
            "sender identity key fixture",
        )?,
        identity_verifying_key: hex_array(
            &fixture.sender_identity_verifying_key_hex,
            "sender identity verifying key fixture",
        )?,
        identity_binding_signature: hex_array::<64>(
            &fixture.sender_identity_binding_signature_hex,
            "sender identity binding signature fixture",
        )?
        .to_vec(),
        certificate: decode_hex(
            &fixture.sender_certificate_hex,
            "sender certificate fixture",
        )?,
        signature: decode_hex(&fixture.sender_signature_hex, "sender signature fixture")?,
    })
}

fn certificate_validation(
    fixture: &CertificateValidationFixture,
) -> Result<OwnedCertificateValidation, AetherError> {
    Ok(OwnedCertificateValidation {
        domain_signing_keys: fixture
            .domain_signing_keys
            .iter()
            .map(domain_signing_key)
            .collect::<Result<Vec<_>, _>>()?,
        relay_domain: fixture.relay_domain.clone().into_bytes(),
        revoked_identity_keys: fixture
            .revoked_identity_keys
            .iter()
            .map(identity_key)
            .collect::<Result<Vec<_>, _>>()?,
        reference_timestamp_secs: fixture.reference_timestamp_secs,
        grace_window_secs: fixture.grace_window_secs,
    })
}

fn domain_signing_key(
    fixture: &DomainSigningKeyFixture,
) -> Result<OwnedDomainSigningKey, AetherError> {
    Ok(OwnedDomainSigningKey {
        identifier: decode_hex(
            &fixture.identifier_hex,
            "sender certificate domain key identifier",
        )?,
        verifying_key: decode_hex(
            &fixture.verifying_key_hex,
            "sender certificate domain verifying key",
        )?,
        status: domain_signing_key_status(&fixture.status)?,
    })
}

fn identity_key(fixture: &IdentityKeyFixture) -> Result<SenderCertificateIdentityKey, AetherError> {
    Ok(SenderCertificateIdentityKey {
        x25519_public_key: hex_array(
            &fixture.x25519_public_key_hex,
            "sender certificate revoked identity x25519 key",
        )?,
        ed25519_verifying_key: hex_array(
            &fixture.ed25519_verifying_key_hex,
            "sender certificate revoked identity ed25519 key",
        )?,
    })
}

fn snapshot_from_blob_fixture(
    blob_file: &BlobFixtureFile,
    name: &str,
    key: &ProtocolStateKey,
) -> Result<ProtocolStateSnapshot, AetherError> {
    let mut snapshot = ProtocolStateSnapshot::new();
    insert_blob_fixture(&mut snapshot, blob_file, name, key)?;
    Ok(snapshot)
}

fn insert_blob_fixture(
    snapshot: &mut ProtocolStateSnapshot,
    blob_file: &BlobFixtureFile,
    name: &str,
    key: &ProtocolStateKey,
) -> Result<(), AetherError> {
    let fixture = blob_file
        .fixtures
        .iter()
        .find(|fixture| fixture.name == name)
        .ok_or_else(|| invalid_fixture(format!("missing blob fixture: {name}")))?;
    snapshot.set(
        ProtocolStateAddress::new(protocol_state_kind(&fixture.kind)?, key.clone()),
        ProtocolStateBlob::from_bytes(decode_hex(&fixture.current_encoded_hex, name)?),
    );
    Ok(())
}

fn deduplication_key() -> Result<ProtocolStateKey, AetherError> {
    ProtocolStateKey::from_bytes(vec![0xdd; 16])
        .map_err(|e| invalid_fixture(format!("invalid deduplication fixture key: {e}")))
}

// Fixture wiring mirrors the InboundEncryptedMessage fields one-for-one; bundling them into a
// struct here would add a type that exists only to satisfy the lint.
#[allow(clippy::too_many_arguments)]
fn inbound<'a>(
    session_key: ProtocolStateKey,
    deduplication_key: ProtocolStateKey,
    message: &'a Message,
    acknowledgment_sender_identity: &'a SenderIdentityMaterial,
    acknowledgment_sender_signing_key: &'a SigningKeyPair,
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
        recipient_discovery_key: Box::leak(Box::new(contact_fixture_discovery_key())),
        acknowledgment: acknowledgment(
            acknowledgment_sender_identity,
            acknowledgment_sender_signing_key,
        ),
        sender_certificate_validation: Some(InboundSenderCertificateValidation {
            domain_signing_keys,
            expected_relay_domain,
            revocation_state: RevocationState::Available(revoked_identity_keys),
            reference_timestamp_secs,
            grace_window_secs,
        }),
    }
}

fn acknowledgment_sender_identity() -> Result<SenderIdentityMaterial, AetherError> {
    sender_identity_with_material(0xb1, vec![0xb2, 0xb3, 0xb4], vec![0xb5; 64])
}

fn acknowledgment<'a>(
    sender_identity: &'a SenderIdentityMaterial,
    sender_identity_signing_key: &'a SigningKeyPair,
) -> OutboundAcknowledgment<'a> {
    let recipient = acknowledgment_recipient_discovery_key();
    OutboundAcknowledgment {
        id: MessageId::from_bytes([0xee; 16]),
        sender_identity,
        sender_identity_signing_key,
        recipient_public_key: *recipient.public_key().as_bytes(),
        timestamp_millis: 1_700_000_100_000,
    }
}

fn sender_identity_with_material(
    tag: u8,
    certificate: Vec<u8>,
    signature: Vec<u8>,
) -> Result<SenderIdentityMaterial, AetherError> {
    let signing_key = SigningKeyPair::from_signing_bytes([tag; 32]);
    let identity_key_pair = KeyPair::from_secret_bytes([tag.wrapping_add(0x33); 32]);
    let binding_signature = sign_identity_key_binding(&signing_key, &identity_key_pair.public)
        .map_err(|e| replay_failure(format!("failed to sign sender identity binding: {e}")))?;
    Ok(SenderIdentityMaterial {
        identity_key: *identity_key_pair.public.as_bytes(),
        identity_verifying_key: signing_key.verifying.to_bytes(),
        identity_binding_signature: binding_signature.to_bytes().to_vec(),
        certificate,
        signature,
    })
}

fn sender_identity_signing_key(
    sender_identity: &SenderIdentityMaterial,
) -> Result<SigningKeyPair, AetherError> {
    for tag in 0..=u8::MAX {
        let signing_key = SigningKeyPair::from_signing_bytes([tag; 32]);
        if signing_key.verifying.to_bytes() == sender_identity.identity_verifying_key {
            return Ok(signing_key);
        }
    }
    Err(replay_failure(
        "fixture sender identity uses an unknown signing key",
    ))
}

fn accepted(
    outcome: InboundMessageOutcome,
) -> Result<aether_core::InboundMessageResult, AetherError> {
    match outcome {
        InboundMessageOutcome::Accepted(result) => Ok(*result),
        InboundMessageOutcome::Blocked(_) => {
            Err(replay_failure("sealed session fixture was blocked"))
        }
        InboundMessageOutcome::Duplicate => {
            Err(replay_failure("sealed session fixture was duplicate"))
        }
        InboundMessageOutcome::SessionUnrecoverable(_) => Err(replay_failure(
            "sealed session fixture was unexpectedly unrecoverable",
        )),
    }
}

fn assert_sender_state_fixture_matches(
    blob_file: &BlobFixtureFile,
    name: &str,
) -> Result<(), AetherError> {
    blob_file
        .fixtures
        .iter()
        .find(|fixture| fixture.name == name)
        .map(|_| ())
        .ok_or_else(|| invalid_fixture(format!("missing sender state fixture: {name}")))
}

fn message_transport_fields(message: &Message) -> MessageTransportFields {
    MessageTransportFields {
        version: message.version,
        recipient_public_key_hex: hex::encode(message.recipient_public_key),
        prekey_reference: message.prekey_reference.map(frame_prekey_reference_report),
        ephemeral_public_key_hex: hex::encode(message.ephemeral_public_key),
        ciphertext_hex: hex::encode(&message.ciphertext),
    }
}

fn initial_handshake_transport_fields(
    envelope: &HandshakeEnvelope,
) -> InitialHandshakeTransportFields {
    InitialHandshakeTransportFields {
        version: envelope.version,
        recipient_public_key_hex: hex::encode(envelope.recipient_public_key),
        prekey_reference: envelope.prekey_reference.map(frame_prekey_reference_report),
        ephemeral_public_key_hex: hex::encode(envelope.ephemeral_public_key),
        ciphertext_hex: hex::encode(&envelope.ciphertext),
    }
}

fn frame_prekey_reference_report(
    reference: SealedFramePreKeyReference,
) -> FramePreKeyReferenceReplay {
    FramePreKeyReferenceReplay {
        discovery_epoch: reference.discovery_epoch,
        signed_prekey_public_key_hex: hex::encode(reference.signed_prekey_public_key),
        one_time_prekey_id: reference.one_time_prekey_id,
        one_time_prekey_public_key_hex: reference.one_time_prekey_public_key.map(hex::encode),
    }
}

fn sender_identity_report(identity: &SenderIdentityMaterial) -> SenderIdentityReplay {
    SenderIdentityReplay {
        sender_identity_key_hex: hex::encode(identity.identity_key),
        sender_identity_verifying_key_hex: hex::encode(identity.identity_verifying_key),
        sender_identity_binding_signature_hex: hex::encode(&identity.identity_binding_signature),
        sender_certificate_hex: hex::encode(&identity.certificate),
        sender_signature_hex: hex::encode(&identity.signature),
    }
}

struct PreAuthHidden {
    identity_key: bool,
    verifying_key: bool,
    binding_signature: bool,
    certificate: bool,
    signature: bool,
}

fn pre_auth_sender_material_hidden(
    encoded: &[u8],
    sender_identity: &SenderIdentityMaterial,
) -> PreAuthHidden {
    PreAuthHidden {
        identity_key: !contains_bytes(encoded, &sender_identity.identity_key),
        verifying_key: !contains_bytes(encoded, &sender_identity.identity_verifying_key),
        binding_signature: !contains_bytes(encoded, &sender_identity.identity_binding_signature),
        certificate: !contains_bytes(encoded, &sender_identity.certificate),
        signature: !contains_bytes(encoded, &sender_identity.signature),
    }
}

fn assert_acknowledgment_artifact(
    acknowledgment: &Message,
    acknowledged_message_id: MessageId,
    sender_identity: &SenderIdentityMaterial,
    name: &str,
) -> Result<(), AetherError> {
    ensure(
        acknowledgment.prekey_reference.is_none(),
        format!("sealed session fixture {name} acknowledgment carried prekey reference"),
    )?;
    let encoded = acknowledgment.to_bytes().map_err(|e| {
        replay_failure(format!(
            "sealed session fixture {name} acknowledgment failed to encode: {e}"
        ))
    })?;
    ensure(
        !contains_bytes(&encoded, acknowledged_message_id.as_bytes()),
        format!("sealed session fixture {name} exposed acknowledged message id"),
    )?;
    ensure(
        !contains_bytes(&encoded, &sender_identity.identity_key),
        format!("sealed session fixture {name} exposed acknowledgment sender identity"),
    )?;
    ensure(
        !contains_bytes(&encoded, &sender_identity.identity_verifying_key),
        format!("sealed session fixture {name} exposed acknowledgment sender verifying key"),
    )?;
    ensure(
        !contains_bytes(&encoded, &sender_identity.identity_binding_signature),
        format!("sealed session fixture {name} exposed acknowledgment sender binding signature"),
    )?;
    ensure(
        !contains_bytes(&encoded, &sender_identity.certificate),
        format!("sealed session fixture {name} exposed acknowledgment sender certificate"),
    )?;
    ensure(
        !contains_bytes(&encoded, &sender_identity.signature),
        format!("sealed session fixture {name} exposed acknowledgment sender signature"),
    )
}

fn assert_decrypted_metadata(
    actual: &aether_core::InboundMessageResult,
    expected: &DecryptedMetadataFixture,
    name: &str,
) -> Result<(), AetherError> {
    ensure(
        hex::encode(actual.message_id.as_bytes()) == expected.id_hex,
        format!("sealed sender fixture {name} decrypted id mismatch"),
    )?;
    ensure(
        actual.timestamp_millis == expected.timestamp_millis,
        format!("sealed sender fixture {name} decrypted timestamp mismatch"),
    )?;
    ensure(
        payload_kind_name(actual.payload_kind) == expected.payload_kind,
        format!("sealed sender fixture {name} decrypted kind mismatch"),
    )
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn assert_message_transport(
    actual: &MessageTransportFields,
    expected: &MessageDecodedFixture,
    name: &str,
) -> Result<(), AetherError> {
    ensure(
        actual.version == expected.version,
        format!("message fixture {name} version mismatch"),
    )?;
    ensure(
        actual.recipient_public_key_hex == expected.recipient_public_key_hex,
        format!("message fixture {name} recipient mismatch"),
    )?;
    assert_frame_prekey_reference(
        actual.prekey_reference.as_ref(),
        expected.prekey_reference.as_ref(),
        name,
    )?;
    ensure(
        actual.ephemeral_public_key_hex == expected.ephemeral_public_key_hex,
        format!("message fixture {name} ephemeral key mismatch"),
    )?;
    ensure(
        actual.ciphertext_hex == expected.ciphertext_hex,
        format!("message fixture {name} ciphertext mismatch"),
    )
}

fn assert_frame_prekey_reference(
    actual: Option<&FramePreKeyReferenceReplay>,
    expected: Option<&PreKeyReferenceFixture>,
    name: &str,
) -> Result<(), AetherError> {
    match (actual, expected) {
        (None, None) => Ok(()),
        (Some(actual), Some(expected)) => {
            ensure(
                actual.discovery_epoch == expected.discovery_epoch,
                format!("message fixture {name} prekey epoch mismatch"),
            )?;
            ensure(
                actual.signed_prekey_public_key_hex == expected.signed_prekey_public_key_hex,
                format!("message fixture {name} signed prekey mismatch"),
            )?;
            ensure(
                actual.one_time_prekey_id == expected.one_time_prekey_id,
                format!("message fixture {name} one-time prekey id mismatch"),
            )?;
            ensure(
                actual.one_time_prekey_public_key_hex == expected.one_time_prekey_public_key_hex,
                format!("message fixture {name} one-time prekey public mismatch"),
            )
        }
        _ => Err(replay_failure(format!(
            "message fixture {name} prekey reference mismatch"
        ))),
    }
}

fn assert_decrypted_sender(
    plaintext: &[u8],
    sender_identity: &SenderIdentityMaterial,
    expected_plaintext_hex: &str,
    expected_sender: &SenderIdentityFixture,
    name: &str,
) -> Result<(), AetherError> {
    ensure(
        hex::encode(plaintext) == expected_plaintext_hex,
        format!("sealed sender fixture {name} plaintext mismatch"),
    )?;
    assert_sender_identity(
        sender_identity,
        &sender_identity_from_fixture(expected_sender)?,
        name,
    )
}

fn assert_sender_identity(
    actual: &SenderIdentityMaterial,
    expected: &SenderIdentityMaterial,
    name: &str,
) -> Result<(), AetherError> {
    ensure(
        actual.identity_key == expected.identity_key,
        format!("sender identity key mismatch for {name}"),
    )?;
    ensure(
        actual.identity_verifying_key == expected.identity_verifying_key,
        format!("sender identity verifying key mismatch for {name}"),
    )?;
    ensure(
        actual.identity_binding_signature == expected.identity_binding_signature,
        format!("sender identity binding signature mismatch for {name}"),
    )?;
    ensure(
        actual.certificate == expected.certificate,
        format!("sender certificate mismatch for {name}"),
    )?;
    ensure(
        actual.signature == expected.signature,
        format!("sender signature mismatch for {name}"),
    )
}

fn assert_transcript_envelope(
    actual: &HandshakeEnvelope,
    expected: &TranscriptEnvelopeFixture,
) -> Result<(), AetherError> {
    ensure(
        actual.version == expected.version,
        "initial handshake version mismatch",
    )?;
    ensure(
        actual.recipient_public_key == expected.recipient_public_key,
        "initial handshake recipient key mismatch",
    )?;
    assert_transcript_prekey_reference(
        actual.prekey_reference,
        expected.prekey_reference,
        "initial handshake",
    )?;
    ensure(
        actual.ephemeral_public_key == expected.ephemeral_public_key,
        "initial handshake ephemeral key mismatch",
    )?;
    ensure(
        actual.ciphertext
            == decode_hex(
                &expected.ciphertext_hex,
                "initial handshake ciphertext fixture",
            )?,
        "initial handshake ciphertext mismatch",
    )
}

fn assert_envelope_eq(
    actual: &HandshakeEnvelope,
    expected: &HandshakeEnvelope,
    name: &str,
) -> Result<(), AetherError> {
    ensure(
        actual.version == expected.version,
        format!("{name} generated version mismatch"),
    )?;
    ensure(
        actual.recipient_public_key == expected.recipient_public_key,
        format!("{name} generated recipient key mismatch"),
    )?;
    assert_generated_prekey_reference(actual.prekey_reference, expected.prekey_reference, name)?;
    ensure(
        actual.ephemeral_public_key == expected.ephemeral_public_key,
        format!("{name} generated ephemeral key mismatch"),
    )?;
    ensure(
        actual.ciphertext == expected.ciphertext,
        format!("{name} generated ciphertext mismatch"),
    )
}

fn assert_transcript_prekey_reference(
    actual: Option<SealedFramePreKeyReference>,
    expected: Option<TranscriptPreKeyReferenceFixture>,
    name: &str,
) -> Result<(), AetherError> {
    match (actual, expected) {
        (None, None) => Ok(()),
        (Some(actual), Some(expected)) => {
            ensure(
                actual.discovery_epoch == expected.discovery_epoch,
                format!("{name} prekey epoch mismatch"),
            )?;
            ensure(
                actual.signed_prekey_public_key == expected.signed_prekey_public_key,
                format!("{name} signed prekey mismatch"),
            )?;
            ensure(
                actual.one_time_prekey_id == expected.one_time_prekey_id,
                format!("{name} one-time prekey id mismatch"),
            )?;
            ensure(
                actual.one_time_prekey_public_key == expected.one_time_prekey_public_key,
                format!("{name} one-time prekey public mismatch"),
            )
        }
        _ => Err(replay_failure(format!("{name} prekey reference mismatch"))),
    }
}

fn assert_generated_prekey_reference(
    actual: Option<SealedFramePreKeyReference>,
    expected: Option<SealedFramePreKeyReference>,
    name: &str,
) -> Result<(), AetherError> {
    ensure(
        actual == expected,
        format!("{name} generated prekey reference mismatch"),
    )
}

fn session_tamper_rejects_without_sender(
    blob_file: &BlobFixtureFile,
    recipient_state_fixture: &str,
    key: &ProtocolStateKey,
    deduplication_key: &ProtocolStateKey,
    message: &Message,
    domain_signing_keys: &[DomainSigningKey<'_>],
    validation: &OwnedCertificateValidation,
) -> Result<bool, AetherError> {
    let mut tampered = copy_message(message);
    let last = tampered
        .ciphertext
        .last_mut()
        .ok_or_else(|| replay_failure("sealed session fixture ciphertext is empty"))?;
    *last ^= 0x01;
    let mut snapshot = snapshot_from_blob_fixture(blob_file, recipient_state_fixture, key)?;
    insert_blob_fixture(
        &mut snapshot,
        blob_file,
        "deduplication_set_identity",
        deduplication_key,
    )?;
    let acknowledgment_sender_identity = acknowledgment_sender_identity()?;
    let acknowledgment_sender_signing_key =
        sender_identity_signing_key(&acknowledgment_sender_identity)?;
    Ok(ProtocolStateEngine::new()
        .decrypt_message(
            &mut ChaCha20Rng::from_seed(SESSION_REPLAY_RNG_SEED),
            &snapshot,
            inbound(
                key.clone(),
                deduplication_key.clone(),
                &tampered,
                &acknowledgment_sender_identity,
                &acknowledgment_sender_signing_key,
                domain_signing_keys,
                &validation.relay_domain,
                &validation.revoked_identity_keys,
                validation.reference_timestamp_secs,
                validation.grace_window_secs,
            ),
        )
        .is_err())
}

fn initial_handshake_tamper_rejects_without_sender(
    transcript: &TranscriptFixture,
) -> Result<bool, AetherError> {
    let mut prepared = prepare_initial_handshake(transcript)?;
    let mut tampered = HandshakeEnvelope::from_bytes(&decode_hex(
        &transcript.handshake_envelope_encoded_hex,
        "initial handshake tamper fixture",
    )?)
    .map_err(|e| {
        replay_failure(format!(
            "initial handshake tamper fixture failed to decode: {e}"
        ))
    })?;
    let last = tampered
        .ciphertext
        .last_mut()
        .ok_or_else(|| replay_failure("initial handshake ciphertext is empty"))?;
    *last ^= 0x01;
    Ok(accept(
        &mut prepared.rng,
        &tampered,
        Some(&prepared.initiator_identity_key),
        &prepared.responder_identity_key,
        &prepared.bob_discovery_key,
        &prepared.bob_signed_prekey,
        Some(prepared.bob_one_time_prekey),
    )
    .is_err())
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

fn unsupported_message_version_rejected() -> bool {
    Message::from_bytes(&[2]).is_err()
}

fn malformed_message_rejected() -> bool {
    Message::from_bytes(&[1, 0xff]).is_err()
}

fn old_sender_visible_message_rejected() -> Result<bool, AetherError> {
    Ok(Message::from_bytes(&decode_hex(
        OLD_SENDER_VISIBLE_MESSAGE_HEX,
        "old sender-visible message",
    )?)
    .is_err())
}

fn unsupported_initial_handshake_version_rejected() -> bool {
    HandshakeEnvelope::from_bytes(&[2]).is_err()
}

fn malformed_initial_handshake_rejected() -> bool {
    HandshakeEnvelope::from_bytes(b"not a postcard envelope").is_err()
}

fn unsupported_blob_major_rejected() -> Result<bool, AetherError> {
    let engine = ProtocolStateEngine::new();
    let key = ProtocolStateKey::session(SessionId::from_bytes([9u8; 16]));
    let address = ProtocolStateAddress::new(ProtocolStateKind::RatchetSession, key.clone());
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot.set(
        address.clone(),
        ProtocolStateBlob::from_bytes(vec![2, 0, 0xaa]),
    );
    Ok(matches!(
        engine.bind_session_state_peer_identity_key(&snapshot, key, [1u8; 32]),
        Err(ProtocolStateError::UnsupportedBlobVersion {
            address: actual,
            major: 2,
            minor: 0
        }) if actual == address
    ))
}

fn malformed_blob_rejected() -> Result<bool, AetherError> {
    let engine = ProtocolStateEngine::new();
    let key = ProtocolStateKey::session(SessionId::from_bytes([9u8; 16]));
    let address = ProtocolStateAddress::new(ProtocolStateKind::RatchetSession, key.clone());
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot.set(
        address.clone(),
        ProtocolStateBlob::from_bytes(vec![1, 0, 0xaa]),
    );
    Ok(matches!(
        engine.bind_session_state_peer_identity_key(&snapshot, key, [1u8; 32]),
        Err(ProtocolStateError::BlobDecode { address: actual, .. }) if actual == address
    ))
}

fn protocol_state_kind(kind: &str) -> Result<ProtocolStateKind, AetherError> {
    match kind {
        "ratchet_session" => Ok(ProtocolStateKind::RatchetSession),
        "deduplication_set" => Ok(ProtocolStateKind::DeduplicationSet),
        "pending_acknowledgments" => Ok(ProtocolStateKind::PendingAcknowledgments),
        "contact_state" => Ok(ProtocolStateKind::ContactState),
        _ => Err(invalid_fixture(format!(
            "unknown protocol-state kind: {kind}"
        ))),
    }
}

fn payload_kind_name(kind: PayloadKind) -> &'static str {
    match kind {
        PayloadKind::EncryptedText => "text",
        PayloadKind::Acknowledgment => "acknowledgment",
        PayloadKind::KeyExchange => "key_exchange",
        PayloadKind::RatchetHeader => "ratchet_header",
        _ => "unknown",
    }
}

fn domain_signing_key_status(status: &str) -> Result<DomainSigningKeyStatus, AetherError> {
    match status {
        "trusted" => Ok(DomainSigningKeyStatus::Trusted),
        "untrusted" => Ok(DomainSigningKeyStatus::Untrusted),
        _ => Err(invalid_fixture(format!(
            "unknown domain-signing-key status: {status}"
        ))),
    }
}

fn fixture_json<T: for<'de> Deserialize<'de>>(json: &str) -> Result<T, AetherError> {
    serde_json::from_str(json).map_err(|e| invalid_fixture(format!("fixture JSON failed: {e}")))
}

fn decode_hex(value: &str, context: &str) -> Result<Vec<u8>, AetherError> {
    hex::decode(value).map_err(|e| invalid_fixture(format!("{context} hex failed: {e}")))
}

fn hex_array<const N: usize>(value: &str, context: &str) -> Result<[u8; N], AetherError> {
    let bytes = decode_hex(value, context)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid_fixture(format!("{context} must be {N} bytes")))
}

fn ensure(condition: bool, reason: impl Into<String>) -> Result<(), AetherError> {
    if condition {
        Ok(())
    } else {
        Err(replay_failure(reason))
    }
}

fn invalid_fixture(reason: impl Into<String>) -> AetherError {
    AetherError::InvalidData {
        reason: reason.into(),
    }
}

fn replay_failure(reason: impl Into<String>) -> AetherError {
    AetherError::InternalError {
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::replay_fixture_harness;

    #[test]
    fn fixture_harness_replays_all_categories() {
        let report = replay_fixture_harness().unwrap();

        assert_eq!(report.message_wire_cases.len(), 4);
        assert_eq!(report.sealed_sender_session_cases.len(), 1);
        assert_eq!(report.initial_handshake_cases.len(), 1);
        assert_eq!(report.protocol_state_blob_cases.len(), 16);
        assert!(report.unsupported_message_version_rejected);
        assert!(report.malformed_message_rejected);
        assert!(report.old_sender_visible_message_rejected);
        assert!(report.unsupported_initial_handshake_version_rejected);
        assert!(report.malformed_initial_handshake_rejected);
        assert!(report.unsupported_blob_major_rejected);
        assert!(report.malformed_blob_rejected);
        assert!(report.sealed_sender_session_cases[0].sender_identity_hidden_before_decrypt);
        assert!(
            report.sealed_sender_session_cases[0]
                .sender_identity_verifying_key_hidden_before_decrypt
        );
        assert!(
            report.sealed_sender_session_cases[0]
                .sender_identity_binding_signature_hidden_before_decrypt
        );
        assert!(report.sealed_sender_session_cases[0].sender_certificate_hidden_before_decrypt);
        assert!(report.sealed_sender_session_cases[0].sender_signature_hidden_before_decrypt);
        assert!(report.sealed_sender_session_cases[0].tampered_ciphertext_rejected);
        assert!(report.initial_handshake_cases[0].sender_identity_hidden_before_decrypt);
        assert!(
            report.initial_handshake_cases[0].sender_identity_verifying_key_hidden_before_decrypt
        );
        assert!(
            report.initial_handshake_cases[0]
                .sender_identity_binding_signature_hidden_before_decrypt
        );
        assert!(report.initial_handshake_cases[0].sender_certificate_hidden_before_decrypt);
        assert!(report.initial_handshake_cases[0].sender_signature_hidden_before_decrypt);
        assert!(report.initial_handshake_cases[0].tampered_ciphertext_rejected);
    }
}
