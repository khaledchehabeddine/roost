#![no_main]

use aether_core::{
    DomainSigningKey, DomainSigningKeyStatus, RevocationState, SenderCertificateIdentityKey,
    SenderCertificateValidationInput, validate_sender_certificate,
};
use libfuzzer_sys::fuzz_target;

mod support;

fuzz_target!(|data: &[u8]| {
    if let Some(text) = support::text(data)
        && let Some(input) = text_case(text)
    {
        validate(input);
        return;
    }
    validate(binary_case(data));
});

struct CertificateCase {
    certificate: Vec<u8>,
    signature: Vec<u8>,
    domain_identifier: Vec<u8>,
    domain_verifying_key: Vec<u8>,
    domain_status: DomainSigningKeyStatus,
    expected_relay_domain: Vec<u8>,
    revoked_identity_keys: Vec<SenderCertificateIdentityKey>,
    reference_timestamp_secs: u64,
    grace_window_secs: u64,
}

fn validate(case: CertificateCase) {
    let domain_key = DomainSigningKey {
        identifier: &case.domain_identifier,
        verifying_key: &case.domain_verifying_key,
        status: case.domain_status,
    };
    let domain_signing_keys = [domain_key];
    let input = SenderCertificateValidationInput {
        certificate: &case.certificate,
        signature: &case.signature,
        domain_signing_keys: &domain_signing_keys,
        expected_relay_domain: &case.expected_relay_domain,
        revocation_state: RevocationState::Available(&case.revoked_identity_keys),
        reference_timestamp_secs: case.reference_timestamp_secs,
        grace_window_secs: case.grace_window_secs,
    };
    let _ = validate_sender_certificate(input);
}

fn text_case(text: &str) -> Option<CertificateCase> {
    let revoked_identity_keys = match (
        support::hex_field(text, "revoked_x25519"),
        support::hex_field(text, "revoked_ed25519"),
    ) {
        (Some(x25519), Some(ed25519)) => vec![SenderCertificateIdentityKey {
            x25519_public_key: support::array_32(&x25519),
            ed25519_verifying_key: support::array_32(&ed25519),
        }],
        _ => Vec::new(),
    };
    Some(CertificateCase {
        certificate: support::hex_field(text, "certificate")?,
        signature: support::hex_field(text, "signature")?,
        domain_identifier: support::hex_field(text, "domain_id")?,
        domain_verifying_key: support::hex_field(text, "domain_key")?,
        domain_status: match support::field(text, "domain_status") {
            Some("untrusted") => DomainSigningKeyStatus::Untrusted,
            _ => DomainSigningKeyStatus::Trusted,
        },
        expected_relay_domain: support::hex_field(text, "expected_relay_domain")?,
        revoked_identity_keys,
        reference_timestamp_secs: support::u64_field(text, "reference", 1_700_000_000),
        grace_window_secs: support::u64_field(text, "grace", 60),
    })
}

fn binary_case(data: &[u8]) -> CertificateCase {
    let Some((&cert_len, rest)) = data.split_first() else {
        return empty_case();
    };
    let (certificate, rest) = take_len(rest, usize::from(cert_len));
    let Some((&signature_len, rest)) = rest.split_first() else {
        return empty_case();
    };
    let (signature, rest) = take_len(rest, usize::from(signature_len));
    let Some((&identifier_len, rest)) = rest.split_first() else {
        return empty_case();
    };
    let (domain_identifier, rest) = take_len(rest, usize::from(identifier_len % 65));
    let (domain_verifying_key, rest) = take_len(rest, 32);
    let Some((&relay_domain_len, rest)) = rest.split_first() else {
        return empty_case();
    };
    let (expected_relay_domain, rest) = take_len(rest, usize::from(relay_domain_len));
    let revoked_identity_keys = (rest.len() >= 64)
        .then(|| SenderCertificateIdentityKey {
            x25519_public_key: support::array_32(&rest[..32]),
            ed25519_verifying_key: support::array_32(&rest[32..64]),
        })
        .into_iter()
        .collect();
    CertificateCase {
        certificate: certificate.to_vec(),
        signature: signature.to_vec(),
        domain_identifier: domain_identifier.to_vec(),
        domain_verifying_key: domain_verifying_key.to_vec(),
        expected_relay_domain: expected_relay_domain.to_vec(),
        domain_status: rest
            .first()
            .is_some_and(|byte| byte % 2 == 0)
            .then_some(DomainSigningKeyStatus::Trusted)
            .unwrap_or(DomainSigningKeyStatus::Untrusted),
        revoked_identity_keys,
        reference_timestamp_secs: be_u64(rest.get(64..72).unwrap_or_default()),
        grace_window_secs: be_u64(rest.get(72..80).unwrap_or_default()),
    }
}

fn empty_case() -> CertificateCase {
    CertificateCase {
        certificate: Vec::new(),
        signature: Vec::new(),
        domain_identifier: Vec::new(),
        domain_verifying_key: Vec::new(),
        domain_status: DomainSigningKeyStatus::Trusted,
        expected_relay_domain: Vec::new(),
        revoked_identity_keys: Vec::new(),
        reference_timestamp_secs: 0,
        grace_window_secs: 0,
    }
}

fn take_len(bytes: &[u8], len: usize) -> (&[u8], &[u8]) {
    bytes.split_at(len.min(bytes.len()))
}

fn be_u64(bytes: &[u8]) -> u64 {
    let mut out = [0u8; 8];
    let len = bytes.len().min(out.len());
    out[..len].copy_from_slice(&bytes[..len]);
    u64::from_be_bytes(out)
}
