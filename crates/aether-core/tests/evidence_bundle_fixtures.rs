//! Replays the version-one Evidence Bundle vector through the standalone Core verifier.

use aether_core::{
    DomainSigningKey, DomainSigningKeyStatus, EvidenceProfile, EvidenceVerificationError,
    EvidenceVerificationInput, PayloadKind, SenderCertificateValidationError,
    VerifiedEvidenceBundle, verify_evidence_bundle,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct FixtureFile {
    version: u8,
    profile: String,
    accepted_timestamp_secs: u64,
    grace_window_secs: u64,
    expected_relay_domain_hex: String,
    replay_relay_domain_hex: String,
    domain_signing_key: DomainSigningKeyFixture,
    valid: ValidFixture,
    rejections: RejectionFixtures,
}

#[derive(Deserialize)]
struct DomainSigningKeyFixture {
    identifier_hex: String,
    verifying_key_hex: String,
    status: String,
}

#[derive(Deserialize)]
struct ValidFixture {
    name: String,
    bundle_hex: String,
    decoded: DecodedFixture,
}

#[derive(Deserialize)]
struct DecodedFixture {
    session_key_hex: String,
    recipient_identity_verifying_key_hex: String,
    message_id_hex: String,
    timestamp_millis: u64,
    payload_kind: String,
    plaintext_hex: String,
    sender_identity_x25519_public_key_hex: String,
    sender_identity_ed25519_verifying_key_hex: String,
    relay_domain_hex: String,
    certificate_expires_at_secs: u64,
}

#[derive(Deserialize)]
struct RejectionFixtures {
    malformed_bundle_hex: String,
    wrong_profile_bundle_hex: String,
    unsupported_version_bundle_hex: String,
    tampered_signature_bundle_hex: String,
}

#[test]
fn checked_in_evidence_bundle_vector_replays() {
    let fixture: FixtureFile =
        serde_json::from_str(include_str!("fixtures/evidence_bundles_v1.json")).unwrap();
    assert_eq!(fixture.version, 1);
    assert_eq!(fixture.profile, "message_transcript_v1");
    assert_eq!(fixture.valid.name, "accepted_text_message");
    assert_eq!(fixture.domain_signing_key.status, "trusted");

    let identifier = hex::decode(&fixture.domain_signing_key.identifier_hex).unwrap();
    let verifying_key = hex::decode(&fixture.domain_signing_key.verifying_key_hex).unwrap();
    let domain_signing_keys = [DomainSigningKey {
        identifier: &identifier,
        verifying_key: &verifying_key,
        status: DomainSigningKeyStatus::Trusted,
    }];
    let relay_domain = hex::decode(&fixture.expected_relay_domain_hex).unwrap();
    let bundle = hex::decode(&fixture.valid.bundle_hex).unwrap();
    let verified = verify_evidence_bundle(EvidenceVerificationInput {
        bundle: &bundle,
        expected_profile: EvidenceProfile::MessageTranscriptV1,
        domain_signing_keys: &domain_signing_keys,
        expected_relay_domain: &relay_domain,
        accepted_timestamp_secs: fixture.accepted_timestamp_secs,
        grace_window_secs: fixture.grace_window_secs,
    })
    .unwrap();
    assert_verified(&verified, &fixture.valid.decoded);

    assert_rejected(
        &hex::decode(&fixture.rejections.malformed_bundle_hex).unwrap(),
        &domain_signing_keys,
        &relay_domain,
        fixture.accepted_timestamp_secs,
        fixture.grace_window_secs,
        EvidenceVerificationError::MalformedBundle,
    );
    assert_rejected(
        &hex::decode(&fixture.rejections.wrong_profile_bundle_hex).unwrap(),
        &domain_signing_keys,
        &relay_domain,
        fixture.accepted_timestamp_secs,
        fixture.grace_window_secs,
        EvidenceVerificationError::WrongProfile {
            expected: EvidenceProfile::MessageTranscriptV1,
            actual: 2,
        },
    );
    assert_rejected(
        &hex::decode(&fixture.rejections.unsupported_version_bundle_hex).unwrap(),
        &domain_signing_keys,
        &relay_domain,
        fixture.accepted_timestamp_secs,
        fixture.grace_window_secs,
        EvidenceVerificationError::UnsupportedVersion(2),
    );
    assert_rejected(
        &hex::decode(&fixture.rejections.tampered_signature_bundle_hex).unwrap(),
        &domain_signing_keys,
        &relay_domain,
        fixture.accepted_timestamp_secs,
        fixture.grace_window_secs,
        EvidenceVerificationError::SignatureFailure,
    );
    let replay_domain = hex::decode(&fixture.replay_relay_domain_hex).unwrap();
    assert_rejected(
        &bundle,
        &domain_signing_keys,
        &replay_domain,
        fixture.accepted_timestamp_secs,
        fixture.grace_window_secs,
        EvidenceVerificationError::SenderCertificate(
            SenderCertificateValidationError::RelayDomainMismatch,
        ),
    );
}

fn assert_verified(actual: &VerifiedEvidenceBundle, expected: &DecodedFixture) {
    assert_eq!(actual.profile, EvidenceProfile::MessageTranscriptV1);
    assert_eq!(hex::encode(&actual.session_key), expected.session_key_hex);
    assert_eq!(
        hex::encode(actual.recipient_identity_verifying_key),
        expected.recipient_identity_verifying_key_hex
    );
    assert_eq!(
        hex::encode(actual.message_id.as_bytes()),
        expected.message_id_hex
    );
    assert_eq!(actual.timestamp_millis, expected.timestamp_millis);
    assert_eq!(expected.payload_kind, "encrypted_text");
    assert_eq!(actual.payload_kind, PayloadKind::EncryptedText);
    assert_eq!(hex::encode(&actual.plaintext), expected.plaintext_hex);
    assert_eq!(
        hex::encode(actual.sender_identity_key.x25519_public_key),
        expected.sender_identity_x25519_public_key_hex
    );
    assert_eq!(
        hex::encode(actual.sender_identity_key.ed25519_verifying_key),
        expected.sender_identity_ed25519_verifying_key_hex
    );
    assert_eq!(hex::encode(&actual.relay_domain), expected.relay_domain_hex);
    assert_eq!(
        actual.certificate_expires_at_secs,
        expected.certificate_expires_at_secs
    );
}

fn assert_rejected(
    bundle: &[u8],
    domain_signing_keys: &[DomainSigningKey<'_>],
    relay_domain: &[u8],
    accepted_timestamp_secs: u64,
    grace_window_secs: u64,
    expected: EvidenceVerificationError,
) {
    let actual = match verify_evidence_bundle(EvidenceVerificationInput {
        bundle,
        expected_profile: EvidenceProfile::MessageTranscriptV1,
        domain_signing_keys,
        expected_relay_domain: relay_domain,
        accepted_timestamp_secs,
        grace_window_secs,
    }) {
        Ok(_) => panic!("evidence fixture verified unexpectedly"),
        Err(error) => error,
    };
    assert_eq!(actual, expected);
}
