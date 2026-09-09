#![no_main]

use libfuzzer_sys::fuzz_target;
use roost_protocol::{
    DomainSigningKey, DomainSigningKeyStatus, RevocationState, SenderCertificateValidationInput,
    validate_sender_certificate,
};

// Public verification key from the canonical primary certificate fixture.
const DOMAIN_KEY: [u8; 32] = [
    0x8a, 0x88, 0xe3, 0xdd, 0x74, 0x09, 0xf1, 0x95, 0xfd, 0x52, 0xdb, 0x2d, 0x3c, 0xba, 0x5d, 0x72,
    0xca, 0x67, 0x09, 0xbf, 0x1d, 0x94, 0x12, 0x1b, 0xf3, 0x74, 0x88, 0x01, 0xb4, 0x0f, 0x6f, 0x5c,
];

fuzz_target!(|data: &[u8]| {
    let (signature, certificate) = data.split_at(data.len().min(64));
    let keys = [DomainSigningKey {
        identifier: b"primary-key",
        verifying_key: &DOMAIN_KEY,
        status: DomainSigningKeyStatus::Trusted,
    }];
    let _ = validate_sender_certificate(SenderCertificateValidationInput {
        certificate,
        signature,
        domain_signing_keys: &keys,
        expected_relay_domain: b"relay.example",
        revocation_state: RevocationState::Available(&[]),
        reference_timestamp_secs: 1_700_000_000,
        grace_window_secs: 30,
    });
});
