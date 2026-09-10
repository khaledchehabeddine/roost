//! Checks signed reports and rejection errors through the public Server API without device state.

use roost_server::{
    DomainSigningKey, DomainSigningKeyStatus, EvidenceProfile, EvidenceVerificationError,
    EvidenceVerificationInput, PayloadKind, SenderCertificateValidationError,
    VerifiedEvidenceBundle, verify_evidence_bundle,
};
#[test]
fn verifies_a_signed_report_and_rejects_invalid_inputs() {
    let identifier = b"test-domain".to_vec();
    let verifying_key =
        hex::decode("6556ea860463d074ae046736e1f20f6c78f7a26e31518d1fe7f645150aaa6ad1").unwrap();
    let domain_signing_keys = [DomainSigningKey {
        identifier: &identifier,
        verifying_key: &verifying_key,
        status: DomainSigningKeyStatus::Trusted,
    }];
    let relay_domain = b"relay.test".to_vec();
    let bundle = hex::decode("01011009090909090909090909090909090909bc7cbcb5636375fa1d82434d466724d92377f53b980695dd49d26d0ce12205a50221000000004000800000000000000081fca7ffbc3100200000001b636f6e7465787420666f7220616e206162757365207265706f7274007b41657468657253656e64657243657274696669636174652d76323a020b746573742d646f6d61696e0a72656c61792e7465737457f24707f390532aa6598f61c43f3bc2dae984525359cb43fc13db947e93f63e65e8f9b0bc6eae124169f0576f97362d295a8cf5f770b45e14357ce647d33eec00000000655577a0409ed439e636de0aabb9ec5e6c0562d1c2892d1a1679897b3f4d1583bcc4abfc014821307b3bb6e35ec85fe66bca2c2e46ffd56f0bd533e43469659c01f985450640340624ac228577b9d3823baec5f873a09708c2e88d4f83ce4f2660911f7606b89a1b0b0f82399c1137947e6fc1c1bec30553cfdc435559c1d76007741143e40f").unwrap();
    let verified = verify_evidence_bundle(EvidenceVerificationInput {
        bundle: &bundle,
        expected_profile: EvidenceProfile::MessageTranscriptV1,
        domain_signing_keys: &domain_signing_keys,
        expected_relay_domain: &relay_domain,
        accepted_timestamp_secs: 1_700_000_000,
        grace_window_secs: 0,
    })
    .unwrap();
    assert_verified(&verified);

    let mut tampered = bundle.clone();
    *tampered.last_mut().unwrap() ^= 1;
    let mut invalid_recipient = bundle.clone();
    let offset = invalid_recipient
        .windows(32)
        .position(|part| part == verified.recipient_identity_verifying_key)
        .unwrap();
    invalid_recipient[offset..offset + 32].fill(0xff);
    for (bytes, expected) in [
        (vec![1, 1], EvidenceVerificationError::MalformedBundle),
        (
            vec![1, 2],
            EvidenceVerificationError::WrongProfile {
                expected: EvidenceProfile::MessageTranscriptV1,
                actual: 2,
            },
        ),
        (vec![2, 1], EvidenceVerificationError::UnsupportedVersion(2)),
        (tampered, EvidenceVerificationError::SignatureFailure),
        (
            invalid_recipient,
            EvidenceVerificationError::MalformedBundle,
        ),
    ] {
        assert_rejected(
            &bytes,
            &domain_signing_keys,
            &relay_domain,
            1_700_000_000,
            0,
            expected,
        );
    }
    let mut trailing = bundle.clone();
    trailing.push(0);
    for (bytes, keys, grace, expected) in [
        (
            vec![0; 160 * 1024 + 1],
            domain_signing_keys.to_vec(),
            0,
            EvidenceVerificationError::BundleTooLarge,
        ),
        (
            trailing,
            domain_signing_keys.to_vec(),
            0,
            EvidenceVerificationError::MalformedBundle,
        ),
        (
            bundle.clone(),
            vec![domain_signing_keys[0]; 33],
            0,
            EvidenceVerificationError::TooManyDomainSigningKeys {
                count: 33,
                maximum: 32,
            },
        ),
        (
            bundle.clone(),
            domain_signing_keys.to_vec(),
            301,
            EvidenceVerificationError::GraceWindowTooLarge {
                actual: 301,
                maximum: 300,
            },
        ),
    ] {
        assert_rejected(&bytes, &keys, &relay_domain, 1_700_000_000, grace, expected);
    }
    let replay_domain = b"other.relay.test".to_vec();
    assert_rejected(
        &bundle,
        &domain_signing_keys,
        &replay_domain,
        1_700_000_000,
        0,
        EvidenceVerificationError::SenderCertificate(
            SenderCertificateValidationError::RelayDomainMismatch,
        ),
    );
}

fn assert_verified(actual: &VerifiedEvidenceBundle) {
    assert_eq!(actual.profile, EvidenceProfile::MessageTranscriptV1);
    assert_eq!(
        hex::encode(actual.evidence_identity),
        "a7af7974cb7c5c3c770baf1b946f8d7d69a295068d99b78425b1df538a6aa489"
    );
    assert_eq!(
        hex::encode(&actual.session_key),
        "09090909090909090909090909090909"
    );
    assert_eq!(
        hex::encode(actual.recipient_identity_verifying_key),
        "bc7cbcb5636375fa1d82434d466724d92377f53b980695dd49d26d0ce12205a5"
    );
    assert_eq!(
        hex::encode(actual.message_id.as_bytes()),
        "02210000000040008000000000000000"
    );
    assert_eq!(actual.timestamp_millis, 1700000300545);
    assert_eq!(actual.payload_kind, PayloadKind::EncryptedText);
    assert_eq!(
        hex::encode(&actual.plaintext),
        "636f6e7465787420666f7220616e206162757365207265706f7274"
    );
    assert_eq!(
        hex::encode(actual.sender_identity_key.x25519_public_key),
        "57f24707f390532aa6598f61c43f3bc2dae984525359cb43fc13db947e93f63e"
    );
    assert_eq!(
        hex::encode(actual.sender_identity_key.ed25519_verifying_key),
        "65e8f9b0bc6eae124169f0576f97362d295a8cf5f770b45e14357ce647d33eec"
    );
    assert_eq!(hex::encode(&actual.relay_domain), "72656c61792e74657374");
    assert_eq!(actual.certificate_expires_at_secs, 1700100000);
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
        Ok(_) => panic!("invalid evidence verified unexpectedly"),
        Err(error) => error,
    };
    assert_eq!(actual, expected);
}
