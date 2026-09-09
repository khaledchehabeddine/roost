//! Fixed certificate bytes across Protocol's public validation boundary.

use roost_protocol::{
    DomainSigningKey, DomainSigningKeyStatus, RevocationState, SenderCertificateIdentityKey,
    SenderCertificateValidationInput, validate_sender_certificate,
};

#[test]
fn sender_certificate_known_answer() {
    // Source: the original project-derived sender_certificates_v1 fixture.
    // Inputs: test-only signing seed 0x01, identity signing seed 0x11, X25519 bytes 0x22.
    // Derivation: Ed25519 over the version-2 certificate including relay.example and expiry.
    // Output: fixed certificate, signature, and decoded identity below.
    let certificate = hex::decode("41657468657253656e64657243657274696669636174652d76323a020b7072696d6172792d6b65790d72656c61792e6578616d706c652222222222222222222222222222222222222222222222222222222222222222d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737000000006553f22c").unwrap();
    let signature = hex::decode("305f9d131e2f9f41bd050cd112e1f7fe1e7f452de16e748bad11096587dfc7db2822057a8a27f21f78099ac8a708d7a7f57efe3fe8515d21fb399d32cbd7c70e").unwrap();
    let verifying_key =
        hex::decode("8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c").unwrap();
    let keys = [DomainSigningKey {
        identifier: b"primary-key",
        verifying_key: &verifying_key,
        status: DomainSigningKeyStatus::Trusted,
    }];
    let decoded = validate_sender_certificate(SenderCertificateValidationInput {
        certificate: &certificate,
        signature: &signature,
        domain_signing_keys: &keys,
        expected_relay_domain: b"relay.example",
        revocation_state: RevocationState::Available(&[]),
        reference_timestamp_secs: 1_700_000_000,
        grace_window_secs: 300,
    })
    .unwrap();
    assert_eq!(decoded.signing_key_identifier, b"primary-key");
    assert_eq!(decoded.relay_domain, b"relay.example");
    assert_eq!(decoded.expires_at_secs, 1_700_000_300);
    assert_eq!(
        decoded.identity_key,
        SenderCertificateIdentityKey {
            x25519_public_key: [0x22; 32],
            ed25519_verifying_key: hex::decode(
                "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737"
            )
            .unwrap()
            .try_into()
            .unwrap(),
        }
    );
}
