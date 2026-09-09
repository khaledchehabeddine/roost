//! Generates abuse evidence at the accepted-Message boundary and verifies it without Session state.

mod support;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use roost_core::ProtocolStateEngine;
use roost_crypto::generate_signing_key_pair;
use roost_protocol::{
    EvidenceProfile, EvidenceVerificationError, EvidenceVerificationInput,
    MAX_EVIDENCE_GRACE_WINDOW_SECS, PayloadKind, SenderCertificateValidationError,
    verify_evidence_bundle,
};
use support::{ProtocolFixture, TEST_RELAY_DOMAIN, accepted_contact_identity};

const ACCEPTED_TIMESTAMP_SECS: u64 = 1_700_000_000;

fn verification_error(
    result: Result<roost_protocol::VerifiedEvidenceBundle, EvidenceVerificationError>,
) -> EvidenceVerificationError {
    match result {
        Ok(_) => panic!("evidence bundle verified unexpectedly"),
        Err(error) => error,
    }
}

fn accepted_evidence(
    sequence: u16,
) -> (
    ProtocolFixture,
    support::StoredMessage,
    roost_core::InboundMessageResult,
) {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0xe1; 32]);
    let sent = fixture.encrypt_from_alice(&engine, sequence, b"context for an abuse report");
    let accepted = fixture.decrypt_for_bob(&engine, &sent, 0xe2);
    (fixture, sent, accepted)
}

fn verified_evidence(
    fixture: &ProtocolFixture,
    accepted: &roost_core::InboundMessageResult,
) -> roost_protocol::VerifiedEvidenceBundle {
    let domain_signing_keys = [fixture.alice_sender.domain_signing_key()];
    verify_evidence_bundle(EvidenceVerificationInput {
        bundle: accepted.evidence_bundle.as_bytes(),
        expected_profile: EvidenceProfile::MessageTranscriptV1,
        domain_signing_keys: &domain_signing_keys,
        expected_relay_domain: TEST_RELAY_DOMAIN,
        accepted_timestamp_secs: ACCEPTED_TIMESTAMP_SECS,
        grace_window_secs: 0,
    })
    .unwrap()
}

#[test]
fn accepted_message_returns_verifiable_evidence_bundle() {
    let (fixture, sent, accepted) = accepted_evidence(1);
    let verified = verified_evidence(&fixture, &accepted);

    assert_eq!(verified.profile, EvidenceProfile::MessageTranscriptV1);
    assert_ne!(verified.evidence_identity, [0; 32]);
    assert_eq!(verified.session_key, fixture.session_key.as_bytes());
    assert_eq!(
        verified.recipient_identity_verifying_key,
        accepted_contact_identity()
            .identity_key
            .ed25519_verifying_key
    );
    assert_eq!(verified.message_id, sent.message_id);
    assert_eq!(verified.timestamp_millis, 1_700_000_300_001);
    assert_eq!(verified.payload_kind, PayloadKind::EncryptedText);
    assert_eq!(verified.plaintext.as_slice(), sent.plaintext);
    assert_eq!(
        verified.sender_identity_key.x25519_public_key,
        accepted.sender_identity.identity_key
    );
    assert_eq!(
        verified.sender_identity_key.ed25519_verifying_key,
        accepted.sender_identity.identity_verifying_key
    );
    assert_ne!(
        verified.recipient_identity_verifying_key,
        verified.sender_identity_key.ed25519_verifying_key
    );
}

#[test]
fn reused_message_id_with_distinct_transcript_has_distinct_evidence_identity() {
    let engine = ProtocolStateEngine::new();
    let mut first_fixture = ProtocolFixture::new([0xe3; 32]);
    let first_sent = first_fixture.encrypt_from_alice(&engine, 10, b"first authenticated report");
    let first_accepted = first_fixture.decrypt_for_bob(&engine, &first_sent, 0xe4);
    let mut second_fixture = ProtocolFixture::new([0xe3; 32]);
    let second_sent =
        second_fixture.encrypt_from_alice(&engine, 10, b"second authenticated report");
    let second_accepted = second_fixture.decrypt_for_bob(&engine, &second_sent, 0xe4);

    assert_eq!(first_sent.message_id, second_sent.message_id);
    assert_ne!(
        verified_evidence(&first_fixture, &first_accepted).evidence_identity,
        verified_evidence(&second_fixture, &second_accepted).evidence_identity
    );
}

#[test]
fn malformed_evidence_bundle_is_rejected() {
    let domain_signing_keys = [];

    let actual = verification_error(verify_evidence_bundle(EvidenceVerificationInput {
        bundle: &[1, 1, 0xff],
        expected_profile: EvidenceProfile::MessageTranscriptV1,
        domain_signing_keys: &domain_signing_keys,
        expected_relay_domain: TEST_RELAY_DOMAIN,
        accepted_timestamp_secs: ACCEPTED_TIMESTAMP_SECS,
        grace_window_secs: 0,
    }));

    assert_eq!(actual, EvidenceVerificationError::MalformedBundle);
}

#[test]
fn evidence_bundle_above_size_cap_is_rejected_before_decode() {
    let oversized = vec![0; 160 * 1024 + 1];
    let domain_signing_keys = [];

    let actual = verification_error(verify_evidence_bundle(EvidenceVerificationInput {
        bundle: &oversized,
        expected_profile: EvidenceProfile::MessageTranscriptV1,
        domain_signing_keys: &domain_signing_keys,
        expected_relay_domain: TEST_RELAY_DOMAIN,
        accepted_timestamp_secs: ACCEPTED_TIMESTAMP_SECS,
        grace_window_secs: 0,
    }));

    assert_eq!(actual, EvidenceVerificationError::BundleTooLarge);
}

#[test]
fn evidence_bundle_with_trailing_bytes_is_rejected() {
    let (fixture, _, accepted) = accepted_evidence(2);
    let domain_signing_keys = [fixture.alice_sender.domain_signing_key()];
    let mut trailing = accepted.evidence_bundle.as_bytes().to_vec();
    trailing.push(0);

    let actual = verification_error(verify_evidence_bundle(EvidenceVerificationInput {
        bundle: &trailing,
        expected_profile: EvidenceProfile::MessageTranscriptV1,
        domain_signing_keys: &domain_signing_keys,
        expected_relay_domain: TEST_RELAY_DOMAIN,
        accepted_timestamp_secs: ACCEPTED_TIMESTAMP_SECS,
        grace_window_secs: 0,
    }));

    assert_eq!(actual, EvidenceVerificationError::MalformedBundle);
}

#[test]
fn evidence_bundle_with_wrong_profile_is_rejected_before_verification() {
    let (fixture, _, accepted) = accepted_evidence(3);
    let domain_signing_keys = [fixture.alice_sender.domain_signing_key()];
    let mut wrong_profile = accepted.evidence_bundle.as_bytes().to_vec();
    wrong_profile[1] = 2;

    let actual = verification_error(verify_evidence_bundle(EvidenceVerificationInput {
        bundle: &wrong_profile,
        expected_profile: EvidenceProfile::MessageTranscriptV1,
        domain_signing_keys: &domain_signing_keys,
        expected_relay_domain: TEST_RELAY_DOMAIN,
        accepted_timestamp_secs: ACCEPTED_TIMESTAMP_SECS,
        grace_window_secs: 0,
    }));

    assert_eq!(
        actual,
        EvidenceVerificationError::WrongProfile {
            expected: EvidenceProfile::MessageTranscriptV1,
            actual: 2,
        }
    );
}

#[test]
fn evidence_bundle_replayed_at_another_relay_is_rejected() {
    let (fixture, _, accepted) = accepted_evidence(4);
    let domain_signing_keys = [fixture.alice_sender.domain_signing_key()];

    let actual = verification_error(verify_evidence_bundle(EvidenceVerificationInput {
        bundle: accepted.evidence_bundle.as_bytes(),
        expected_profile: EvidenceProfile::MessageTranscriptV1,
        domain_signing_keys: &domain_signing_keys,
        expected_relay_domain: b"other-relay.test",
        accepted_timestamp_secs: ACCEPTED_TIMESTAMP_SECS,
        grace_window_secs: 0,
    }));

    assert_eq!(
        actual,
        EvidenceVerificationError::SenderCertificate(
            SenderCertificateValidationError::RelayDomainMismatch
        )
    );
}

#[test]
fn evidence_bundle_with_substituted_valid_relay_certificate_is_rejected() {
    const OTHER_RELAY_DOMAIN: &[u8] = b"other.test";

    let (fixture, _, accepted) = accepted_evidence(5);
    let mut substituted_certificate = accepted.sender_identity.certificate.clone();
    let relay_offset = substituted_certificate
        .windows(TEST_RELAY_DOMAIN.len())
        .position(|window| window == TEST_RELAY_DOMAIN)
        .unwrap();
    substituted_certificate[relay_offset..relay_offset + TEST_RELAY_DOMAIN.len()]
        .copy_from_slice(OTHER_RELAY_DOMAIN);
    let domain_signing_key = generate_signing_key_pair(&mut ChaCha20Rng::from_seed([0x90; 32]));
    let substituted_certificate_signature =
        domain_signing_key.sign(&substituted_certificate).to_bytes();

    let mut substituted = accepted.evidence_bundle.as_bytes().to_vec();
    let certificate_offset = substituted
        .windows(accepted.sender_identity.certificate.len())
        .position(|window| window == accepted.sender_identity.certificate)
        .unwrap();
    substituted[certificate_offset..certificate_offset + substituted_certificate.len()]
        .copy_from_slice(&substituted_certificate);
    let certificate_signature_offset = substituted
        .windows(accepted.sender_identity.signature.len())
        .position(|window| window == accepted.sender_identity.signature)
        .unwrap();
    substituted[certificate_signature_offset
        ..certificate_signature_offset + substituted_certificate_signature.len()]
        .copy_from_slice(&substituted_certificate_signature);

    let domain_signing_keys = [fixture.alice_sender.domain_signing_key()];
    let actual = verification_error(verify_evidence_bundle(EvidenceVerificationInput {
        bundle: &substituted,
        expected_profile: EvidenceProfile::MessageTranscriptV1,
        domain_signing_keys: &domain_signing_keys,
        expected_relay_domain: OTHER_RELAY_DOMAIN,
        accepted_timestamp_secs: ACCEPTED_TIMESTAMP_SECS,
        grace_window_secs: 0,
    }));

    assert_eq!(actual, EvidenceVerificationError::SignatureFailure);
}

#[test]
fn evidence_bundle_with_tampered_message_signature_is_rejected() {
    let (fixture, _, accepted) = accepted_evidence(5);
    let domain_signing_keys = [fixture.alice_sender.domain_signing_key()];
    let mut tampered = accepted.evidence_bundle.as_bytes().to_vec();
    let last = tampered.last_mut().unwrap();
    *last ^= 0x01;

    let actual = verification_error(verify_evidence_bundle(EvidenceVerificationInput {
        bundle: &tampered,
        expected_profile: EvidenceProfile::MessageTranscriptV1,
        domain_signing_keys: &domain_signing_keys,
        expected_relay_domain: TEST_RELAY_DOMAIN,
        accepted_timestamp_secs: ACCEPTED_TIMESTAMP_SECS,
        grace_window_secs: 0,
    }));

    assert_eq!(actual, EvidenceVerificationError::SignatureFailure);
}

#[test]
fn unsupported_evidence_bundle_version_is_rejected_before_body_decode() {
    let (fixture, _, accepted) = accepted_evidence(6);
    let domain_signing_keys = [fixture.alice_sender.domain_signing_key()];
    let mut unsupported = accepted.evidence_bundle.as_bytes().to_vec();
    unsupported[0] = 2;

    let actual = verification_error(verify_evidence_bundle(EvidenceVerificationInput {
        bundle: &unsupported,
        expected_profile: EvidenceProfile::MessageTranscriptV1,
        domain_signing_keys: &domain_signing_keys,
        expected_relay_domain: TEST_RELAY_DOMAIN,
        accepted_timestamp_secs: ACCEPTED_TIMESTAMP_SECS,
        grace_window_secs: 0,
    }));

    assert_eq!(actual, EvidenceVerificationError::UnsupportedVersion(2));
}

#[test]
fn evidence_verifier_caps_caller_supplied_domain_signing_keys() {
    let (fixture, _, accepted) = accepted_evidence(7);
    let domain_signing_keys = vec![fixture.alice_sender.domain_signing_key(); 33];

    let actual = verification_error(verify_evidence_bundle(EvidenceVerificationInput {
        bundle: accepted.evidence_bundle.as_bytes(),
        expected_profile: EvidenceProfile::MessageTranscriptV1,
        domain_signing_keys: &domain_signing_keys,
        expected_relay_domain: TEST_RELAY_DOMAIN,
        accepted_timestamp_secs: ACCEPTED_TIMESTAMP_SECS,
        grace_window_secs: 0,
    }));

    assert_eq!(
        actual,
        EvidenceVerificationError::TooManyDomainSigningKeys {
            count: 33,
            maximum: 32,
        }
    );
}

#[test]
fn evidence_grace_window_above_profile_maximum_is_rejected() {
    let (fixture, _, accepted) = accepted_evidence(8);
    let domain_signing_keys = [fixture.alice_sender.domain_signing_key()];

    let actual = verification_error(verify_evidence_bundle(EvidenceVerificationInput {
        bundle: accepted.evidence_bundle.as_bytes(),
        expected_profile: EvidenceProfile::MessageTranscriptV1,
        domain_signing_keys: &domain_signing_keys,
        expected_relay_domain: TEST_RELAY_DOMAIN,
        accepted_timestamp_secs: ACCEPTED_TIMESTAMP_SECS,
        grace_window_secs: MAX_EVIDENCE_GRACE_WINDOW_SECS + 1,
    }));

    assert_eq!(
        actual,
        EvidenceVerificationError::GraceWindowTooLarge {
            actual: 301,
            maximum: 300,
        }
    );
}

#[test]
fn evidence_bundle_with_noncanonical_recipient_identity_key_is_rejected() {
    let (fixture, _, accepted) = accepted_evidence(9);
    let domain_signing_keys = [fixture.alice_sender.domain_signing_key()];
    let recipient_key = accepted_contact_identity()
        .identity_key
        .ed25519_verifying_key;
    let mut malformed = accepted.evidence_bundle.as_bytes().to_vec();
    let key_offset = malformed
        .windows(recipient_key.len())
        .position(|window| window == recipient_key)
        .unwrap();
    malformed[key_offset..key_offset + recipient_key.len()].fill(0xff);

    let actual = verification_error(verify_evidence_bundle(EvidenceVerificationInput {
        bundle: &malformed,
        expected_profile: EvidenceProfile::MessageTranscriptV1,
        domain_signing_keys: &domain_signing_keys,
        expected_relay_domain: TEST_RELAY_DOMAIN,
        accepted_timestamp_secs: ACCEPTED_TIMESTAMP_SECS,
        grace_window_secs: 0,
    }));

    assert_eq!(actual, EvidenceVerificationError::MalformedBundle);
}

#[test]
fn accepted_message_matches_canonical_evidence_bundle() {
    let (_, _, accepted) = accepted_evidence(0x0221);
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../roost-protocol/tests/fixtures/evidence_bundles_v1.json"
    ))
    .unwrap();
    assert_eq!(
        hex::encode(accepted.evidence_bundle.as_bytes()),
        fixture["valid"]["bundle_hex"].as_str().unwrap()
    );
}
