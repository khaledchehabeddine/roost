//! Generates abuse evidence at the accepted-Message boundary and verifies it without Session state.

mod support;

use aether_core::{
    EvidenceProfile, EvidenceVerificationError, EvidenceVerificationInput,
    MAX_EVIDENCE_GRACE_WINDOW_SECS, PayloadKind, ProtocolStateEngine,
    SenderCertificateValidationError, verify_evidence_bundle,
};
use support::{ProtocolFixture, TEST_RELAY_DOMAIN, accepted_contact_identity};

const ACCEPTED_TIMESTAMP_SECS: u64 = 1_700_000_000;

fn verification_error(
    result: Result<aether_core::VerifiedEvidenceBundle, EvidenceVerificationError>,
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
    aether_core::InboundMessageResult,
) {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0xe1; 32]);
    let sent = fixture.encrypt_from_alice(&engine, sequence, b"context for an abuse report");
    let accepted = fixture.decrypt_for_bob(&engine, &sent, 0xe2);
    (fixture, sent, accepted)
}

#[test]
fn accepted_message_returns_verifiable_evidence_bundle() {
    let (fixture, sent, accepted) = accepted_evidence(1);
    let domain_signing_keys = [fixture.alice_sender.domain_signing_key()];

    let verified = verify_evidence_bundle(EvidenceVerificationInput {
        bundle: accepted.evidence_bundle.as_bytes(),
        expected_profile: EvidenceProfile::MessageTranscriptV1,
        domain_signing_keys: &domain_signing_keys,
        expected_relay_domain: TEST_RELAY_DOMAIN,
        accepted_timestamp_secs: ACCEPTED_TIMESTAMP_SECS,
        grace_window_secs: 0,
    })
    .unwrap();

    assert_eq!(verified.profile, EvidenceProfile::MessageTranscriptV1);
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
#[ignore = "prints the evidence_bundles_v1.json vector; run explicitly"]
fn print_evidence_bundle_fixture() {
    let (fixture, sent, accepted) = accepted_evidence(0x0221);
    let domain_key = fixture.alice_sender.domain_signing_key();
    let domain_signing_keys = [domain_key];
    let verified = verify_evidence_bundle(EvidenceVerificationInput {
        bundle: accepted.evidence_bundle.as_bytes(),
        expected_profile: EvidenceProfile::MessageTranscriptV1,
        domain_signing_keys: &domain_signing_keys,
        expected_relay_domain: TEST_RELAY_DOMAIN,
        accepted_timestamp_secs: ACCEPTED_TIMESTAMP_SECS,
        grace_window_secs: 0,
    })
    .unwrap();
    let mut wrong_profile = accepted.evidence_bundle.as_bytes().to_vec();
    wrong_profile[1] = 2;
    let mut unsupported_version = accepted.evidence_bundle.as_bytes().to_vec();
    unsupported_version[0] = 2;
    let mut tampered_signature = accepted.evidence_bundle.as_bytes().to_vec();
    *tampered_signature.last_mut().unwrap() ^= 0x01;
    let mut invalid_recipient_identity_key = accepted.evidence_bundle.as_bytes().to_vec();
    let recipient_key_offset = invalid_recipient_identity_key
        .windows(verified.recipient_identity_verifying_key.len())
        .position(|window| window == verified.recipient_identity_verifying_key)
        .unwrap();
    invalid_recipient_identity_key[recipient_key_offset
        ..recipient_key_offset + verified.recipient_identity_verifying_key.len()]
        .fill(0xff);
    let output = serde_json::json!({
        "version": 1,
        "profile": "message_transcript_v1",
        "accepted_timestamp_secs": ACCEPTED_TIMESTAMP_SECS,
        "grace_window_secs": 0,
        "expected_relay_domain_hex": hex::encode(TEST_RELAY_DOMAIN),
        "replay_relay_domain_hex": hex::encode(b"other-relay.test"),
        "domain_signing_key": {
            "identifier_hex": hex::encode(domain_key.identifier),
            "verifying_key_hex": hex::encode(domain_key.verifying_key),
            "status": "trusted"
        },
        "valid": {
            "name": "accepted_text_message",
            "bundle_hex": hex::encode(accepted.evidence_bundle.as_bytes()),
            "verification_material": {
                "sender_certificate_hex": hex::encode(&accepted.sender_identity.certificate),
                "sender_certificate_signature_hex": hex::encode(&accepted.sender_identity.signature),
                "message_transcript_signature_hex": hex::encode(
                    &accepted.evidence_bundle.as_bytes()[accepted.evidence_bundle.as_bytes().len() - 64..]
                )
            },
            "decoded": {
                "session_key_hex": hex::encode(&verified.session_key),
                "recipient_identity_verifying_key_hex": hex::encode(
                    verified.recipient_identity_verifying_key
                ),
                "message_id_hex": hex::encode(verified.message_id.as_bytes()),
                "timestamp_millis": verified.timestamp_millis,
                "payload_kind": "encrypted_text",
                "plaintext_hex": hex::encode(&verified.plaintext),
                "sender_identity_x25519_public_key_hex": hex::encode(
                    verified.sender_identity_key.x25519_public_key
                ),
                "sender_identity_ed25519_verifying_key_hex": hex::encode(
                    verified.sender_identity_key.ed25519_verifying_key
                ),
                "relay_domain_hex": hex::encode(&verified.relay_domain),
                "certificate_expires_at_secs": verified.certificate_expires_at_secs
            },
            "outbound_message_id_hex": hex::encode(sent.message_id.as_bytes())
        },
        "rejections": {
            "malformed_bundle_hex": "0101ff",
            "wrong_profile_bundle_hex": hex::encode(wrong_profile),
            "unsupported_version_bundle_hex": hex::encode(unsupported_version),
            "tampered_signature_bundle_hex": hex::encode(tampered_signature),
            "invalid_recipient_identity_key_bundle_hex": hex::encode(
                invalid_recipient_identity_key
            )
        }
    });
    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}
