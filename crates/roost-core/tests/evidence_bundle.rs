//! Generates abuse evidence at the accepted-Message boundary and verifies it without Session state.

mod support;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use roost_core::ProtocolStateEngine;
use roost_crypto::generate_signing_key_pair;
use roost_protocol::{
    DomainSigningKey, DomainSigningKeyStatus, EvidenceProfile, EvidenceVerificationError,
    EvidenceVerificationInput, PayloadKind, verify_evidence_bundle,
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
fn evidence_bundle_with_substituted_valid_relay_certificate_is_rejected() {
    const OTHER_RELAY_DOMAIN: &[u8] = b"other.test";

    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../roost-protocol/tests/fixtures/evidence_bundles_v1.json"
    ))
    .unwrap();
    let material = &fixture["valid"]["verification_material"];
    let certificate = hex::decode(material["sender_certificate_hex"].as_str().unwrap()).unwrap();
    let signature = hex::decode(
        material["sender_certificate_signature_hex"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let mut substituted_certificate = certificate.clone();
    let relay_offset = substituted_certificate
        .windows(TEST_RELAY_DOMAIN.len())
        .position(|window| window == TEST_RELAY_DOMAIN)
        .unwrap();
    substituted_certificate[relay_offset..relay_offset + TEST_RELAY_DOMAIN.len()]
        .copy_from_slice(OTHER_RELAY_DOMAIN);
    let domain_signing_key = generate_signing_key_pair(&mut ChaCha20Rng::from_seed([0x90; 32]));
    let substituted_certificate_signature =
        domain_signing_key.sign(&substituted_certificate).to_bytes();

    let mut substituted = hex::decode(fixture["valid"]["bundle_hex"].as_str().unwrap()).unwrap();
    let certificate_offset = substituted
        .windows(certificate.len())
        .position(|window| window == certificate)
        .unwrap();
    substituted[certificate_offset..certificate_offset + substituted_certificate.len()]
        .copy_from_slice(&substituted_certificate);
    let certificate_signature_offset = substituted
        .windows(signature.len())
        .position(|window| window == signature)
        .unwrap();
    substituted[certificate_signature_offset
        ..certificate_signature_offset + substituted_certificate_signature.len()]
        .copy_from_slice(&substituted_certificate_signature);

    let identifier = hex::decode(
        fixture["domain_signing_key"]["identifier_hex"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let verifying_key = domain_signing_key.verifying.to_bytes();
    let domain_signing_keys = [DomainSigningKey {
        identifier: &identifier,
        verifying_key: &verifying_key,
        status: DomainSigningKeyStatus::Trusted,
    }];
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
