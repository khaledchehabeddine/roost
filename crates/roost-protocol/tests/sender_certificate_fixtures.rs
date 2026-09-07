//! Replays checked-in sender certificate fixtures across the public Core validation API.

use roost_protocol::{
    DomainSigningKey, DomainSigningKeyStatus, RevocationState, SenderCertificateIdentityKey,
    SenderCertificateValidationError, SenderCertificateValidationInput,
    validate_sender_certificate,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct FixtureFile {
    version: u8,
    relay_domain: String,
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
        expected_relay_domain: fixture_file.relay_domain.as_bytes(),
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
                validated.relay_domain,
                fixture_file.relay_domain.as_bytes().to_vec(),
                "{} relay domain",
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

fn hex_array<const N: usize>(hex: &str) -> [u8; N] {
    hex::decode(hex).unwrap().try_into().unwrap()
}

#[test]
#[ignore = "regenerates sender_certificates_v1.json; run explicitly"]
fn regenerate_sender_certificate_fixtures() {
    use ed25519_dalek::{Signer, SigningKey};

    const TAG: &[u8] = b"AetherSenderCertificate-v2:";
    const VERSION: u8 = 2;
    const RELAY_DOMAIN: &[u8] = b"relay.example";
    const REF: u64 = 1_700_000_000;
    const GRACE: u64 = 300;
    const PRIMARY: &[u8] = b"primary-key";
    const SECONDARY: &[u8] = b"secondary-key";
    const UNTRUSTED: &[u8] = b"untrusted-key";

    fn cert(identifier: &[u8], ik_x: [u8; 32], ik_ed: [u8; 32], expires: u64) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(TAG);
        b.push(VERSION);
        b.push(identifier.len() as u8);
        b.extend_from_slice(identifier);
        b.push(RELAY_DOMAIN.len() as u8);
        b.extend_from_slice(RELAY_DOMAIN);
        b.extend_from_slice(&ik_x);
        b.extend_from_slice(&ik_ed);
        b.extend_from_slice(&expires.to_be_bytes());
        b
    }

    let primary = SigningKey::from_bytes(&[0x01; 32]);
    let secondary = SigningKey::from_bytes(&[0x02; 32]);
    let untrusted = SigningKey::from_bytes(&[0x03; 32]);
    let ik_signing = SigningKey::from_bytes(&[0x11; 32]);
    let ik_ed = ik_signing.verifying_key().to_bytes();
    let ik_x = [0x22u8; 32];
    // 2^255 - 19 little-endian: a valid field element but not a canonical X25519 key.
    let mut modulus = [0xffu8; 32];
    modulus[0] = 0xed;
    modulus[31] = 0x7f;

    let mut out = String::new();
    let emit = |out: &mut String, name: &str, c: &[u8], sig: Vec<u8>, expected: &str| {
        out.push_str(&format!(
            "{}|{}|{}|{}\n",
            name,
            hex::encode(c),
            hex::encode(sig),
            expected
        ));
    };

    let valid = cert(PRIMARY, ik_x, ik_ed, REF + 300);
    emit(
        &mut out,
        "valid-primary",
        &valid,
        primary.sign(&valid).to_bytes().to_vec(),
        "valid",
    );

    let rot = cert(SECONDARY, ik_x, ik_ed, REF + 300);
    emit(
        &mut out,
        "rotation-overlap-secondary",
        &rot,
        secondary.sign(&rot).to_bytes().to_vec(),
        "valid",
    );

    let unt = cert(UNTRUSTED, ik_x, ik_ed, REF + 300);
    emit(
        &mut out,
        "untrusted-key",
        &unt,
        untrusted.sign(&unt).to_bytes().to_vec(),
        "untrusted_signing_key_identifier",
    );

    emit(
        &mut out,
        "revoked-identity-key",
        &valid,
        primary.sign(&valid).to_bytes().to_vec(),
        "revoked_identity_key",
    );

    let exp = cert(PRIMARY, ik_x, ik_ed, REF - GRACE - 1);
    emit(
        &mut out,
        "expired-outside-grace",
        &exp,
        primary.sign(&exp).to_bytes().to_vec(),
        "expired_certificate",
    );

    let trunc = valid[..valid.len() - 4].to_vec();
    emit(
        &mut out,
        "malformed-truncated",
        &trunc,
        primary.sign(&trunc).to_bytes().to_vec(),
        "malformed_certificate",
    );

    let nc = cert(PRIMARY, modulus, ik_ed, REF + 300);
    emit(
        &mut out,
        "non-canonical-identity-x25519",
        &nc,
        primary.sign(&nc).to_bytes().to_vec(),
        "invalid_key_encoding",
    );

    println!("FIXTURE_START");
    print!("{out}");
    println!(
        "KEYS|{}|{}|{}",
        hex::encode(primary.verifying_key().to_bytes()),
        hex::encode(secondary.verifying_key().to_bytes()),
        hex::encode(untrusted.verifying_key().to_bytes())
    );
    println!("IK|{}|{}", hex::encode(ik_x), hex::encode(ik_ed));
    println!("FIXTURE_END");
}
