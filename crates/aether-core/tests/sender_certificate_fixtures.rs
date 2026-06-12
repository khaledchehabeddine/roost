//! Replays checked-in sender certificate fixtures across the public Core validation API.

use aether_core::{
    DomainSigningKey, DomainSigningKeyStatus, RevocationState, SenderCertificateDiscoveryKey,
    SenderCertificateIdentityKey, SenderCertificateValidationError,
    SenderCertificateValidationInput, validate_sender_certificate,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct FixtureFile {
    version: u8,
    reference_timestamp_secs: u64,
    grace_window_secs: u64,
    fixtures: Vec<Fixture>,
}

#[derive(Deserialize)]
struct Fixture {
    name: String,
    certificate_hex: String,
    signature_hex: String,
    domain_signing_keys: Vec<DomainSigningKeyFixture>,
    revoked_identity_keys: Vec<IdentityKeyFixture>,
    decoded: DecodedFixture,
    expected: String,
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

#[derive(Deserialize)]
struct DecodedFixture {
    signing_key_identifier_hex: String,
    identity_x25519_public_key_hex: String,
    identity_ed25519_verifying_key_hex: String,
    discovery_x25519_public_key_hex: String,
    discovery_ed25519_verifying_key_hex: String,
    discovery_epoch: u32,
    expires_at_secs: u64,
}

#[test]
fn checked_in_sender_certificate_fixtures_replay() {
    let fixture_file: FixtureFile =
        serde_json::from_str(include_str!("fixtures/sender_certificates_v1.json")).unwrap();

    assert_eq!(fixture_file.version, 1);
    assert_eq!(fixture_file.fixtures.len(), 7);
    for fixture in &fixture_file.fixtures {
        replay_fixture(&fixture_file, fixture);
    }
}

fn replay_fixture(fixture_file: &FixtureFile, fixture: &Fixture) {
    let certificate = hex::decode(&fixture.certificate_hex).unwrap();
    let signature = hex::decode(&fixture.signature_hex).unwrap();
    let domain_identifiers: Vec<Vec<u8>> = fixture
        .domain_signing_keys
        .iter()
        .map(|key| hex::decode(&key.identifier_hex).unwrap())
        .collect();
    let domain_verifying_keys: Vec<Vec<u8>> = fixture
        .domain_signing_keys
        .iter()
        .map(|key| hex::decode(&key.verifying_key_hex).unwrap())
        .collect();
    let domain_signing_keys: Vec<DomainSigningKey<'_>> = fixture
        .domain_signing_keys
        .iter()
        .enumerate()
        .map(|(index, key)| DomainSigningKey {
            identifier: &domain_identifiers[index],
            verifying_key: &domain_verifying_keys[index],
            status: domain_signing_key_status(&key.status),
        })
        .collect();
    let revoked_identity_keys: Vec<SenderCertificateIdentityKey> = fixture
        .revoked_identity_keys
        .iter()
        .map(identity_key)
        .collect();
    let input = SenderCertificateValidationInput {
        certificate: &certificate,
        signature: &signature,
        domain_signing_keys: &domain_signing_keys,
        revocation_state: RevocationState::Available(&revoked_identity_keys),
        reference_timestamp_secs: fixture_file.reference_timestamp_secs,
        grace_window_secs: fixture_file.grace_window_secs,
    };

    match expected_error(&fixture.expected) {
        None => {
            let validated = validate_sender_certificate(input).unwrap();
            assert_eq!(
                hex::encode(validated.signing_key_identifier),
                fixture.decoded.signing_key_identifier_hex,
                "{} signing-key identifier",
                fixture.name
            );
            assert_eq!(
                validated.identity_key,
                decoded_identity_key(&fixture.decoded),
                "{} identity key",
                fixture.name
            );
            assert_eq!(
                validated.discovery_key,
                decoded_discovery_key(&fixture.decoded),
                "{} discovery key",
                fixture.name
            );
            assert_eq!(
                validated.expires_at_secs, fixture.decoded.expires_at_secs,
                "{} expiry",
                fixture.name
            );
        }
        Some(expected) => {
            let actual = validate_sender_certificate(input).unwrap_err();
            assert_eq!(actual, expected, "{} expected error", fixture.name);
        }
    }
}

fn domain_signing_key_status(status: &str) -> DomainSigningKeyStatus {
    match status {
        "trusted" => DomainSigningKeyStatus::Trusted,
        "untrusted" => DomainSigningKeyStatus::Untrusted,
        _ => panic!("unknown domain-signing-key status in fixture: {status}"),
    }
}

fn expected_error(expected: &str) -> Option<SenderCertificateValidationError> {
    match expected {
        "valid" => None,
        "malformed_certificate" => Some(SenderCertificateValidationError::MalformedCertificate),
        "invalid_key_encoding" => Some(SenderCertificateValidationError::InvalidKeyEncoding),
        "unknown_signing_key_identifier" => {
            Some(SenderCertificateValidationError::UnknownSigningKeyIdentifier)
        }
        "untrusted_signing_key_identifier" => {
            Some(SenderCertificateValidationError::UntrustedSigningKeyIdentifier)
        }
        "signature_failure" => Some(SenderCertificateValidationError::SignatureFailure),
        "revoked_identity_key" => Some(SenderCertificateValidationError::RevokedIdentityKey),
        "expired_certificate" => Some(SenderCertificateValidationError::ExpiredCertificate),
        _ => panic!("unknown expected sender-certificate verdict in fixture: {expected}"),
    }
}

fn identity_key(fixture: &IdentityKeyFixture) -> SenderCertificateIdentityKey {
    SenderCertificateIdentityKey {
        x25519_public_key: hex_array(&fixture.x25519_public_key_hex),
        ed25519_verifying_key: hex_array(&fixture.ed25519_verifying_key_hex),
    }
}

fn decoded_identity_key(decoded: &DecodedFixture) -> SenderCertificateIdentityKey {
    SenderCertificateIdentityKey {
        x25519_public_key: hex_array(&decoded.identity_x25519_public_key_hex),
        ed25519_verifying_key: hex_array(&decoded.identity_ed25519_verifying_key_hex),
    }
}

fn decoded_discovery_key(decoded: &DecodedFixture) -> SenderCertificateDiscoveryKey {
    SenderCertificateDiscoveryKey {
        x25519_public_key: hex_array(&decoded.discovery_x25519_public_key_hex),
        ed25519_verifying_key: hex_array(&decoded.discovery_ed25519_verifying_key_hex),
        epoch: decoded.discovery_epoch,
    }
}

fn hex_array<const N: usize>(hex: &str) -> [u8; N] {
    hex::decode(hex).unwrap().try_into().unwrap()
}
