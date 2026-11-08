//! A host drives identity creation, backup, prekeys, and deletion through one IdentityContext.

use crate::support::{
    DOMAIN_SIGNING_KEY_ID, MemoryStorage, RELAY_DOMAIN, complete, domain_signing_key,
    issue_certificate,
};
use roost_client::{
    DomainSigningKey, IdentityContext, IdentityKey, OperationId, OperationStatus, RevocationState,
    RoostError, SenderCertificateValidation, SignedSenderCertificate, ValidatedSenderCertificate,
};
use roost_crypto::{KeyPair, SigningKeyPair};
use roost_protocol::SenderCertificateValidationError;
use std::sync::Arc;

const PASSPHRASE: &str = "correct horse battery staple";
const CERTIFICATE_EXPIRES_AT_SECS: u64 = 1_800_000_000;
const CERTIFICATE_EXPIRES_AT_MILLIS: u64 = CERTIFICATE_EXPIRES_AT_SECS * 1_000;

#[test]
fn identity_is_absent_until_its_creation_finalizes() {
    let context = IdentityContext::new(Arc::new(MemoryStorage::default()));
    assert_eq!(context.identity().unwrap(), None);

    let prepared = context.prepare_identity_creation().unwrap();
    assert_eq!(context.identity().unwrap(), None);
    context
        .reserve_operation(prepared.operation_id.clone())
        .unwrap();
    assert!(matches!(
        context.identity(),
        Err(RoostError::UnfinishedReservation { operation_id, .. })
            if operation_id == prepared.operation_id
    ));

    context.finalize_operation(prepared.operation_id).unwrap();
    assert_eq!(context.identity().unwrap(), Some(prepared.identity));
}

#[test]
fn identity_reports_a_storage_failure_instead_of_absence() {
    let storage = Arc::new(MemoryStorage::default());
    let context = IdentityContext::new(storage.clone());

    storage.fail_next_load();
    match context.identity() {
        Err(RoostError::Storage { reason }) => assert_eq!(
            reason,
            "prepared-operation storage failed: keychain unavailable"
        ),
        other => panic!("expected a storage error, got {other:?}"),
    }
    assert_eq!(context.identity().unwrap(), None);
}

#[test]
fn restored_backup_publishes_only_after_inbox_rotation() {
    let source = IdentityContext::new(Arc::new(MemoryStorage::default()));
    let created = source.prepare_identity_creation().unwrap();
    complete(&source, created.operation_id);
    let signed_prekey = source
        .prepare_signed_prekey_rotation_and_discovery_key_cleanup()
        .unwrap();
    complete(&source, signed_prekey.operation_id);
    let source_epoch = source.current_publication().unwrap().discovery_key.epoch;
    let backup = source.export_encrypted_backup(PASSPHRASE.into()).unwrap();

    let restored = IdentityContext::new(Arc::new(MemoryStorage::default()));
    let import = restored
        .prepare_backup_import(backup, PASSPHRASE.into())
        .unwrap();
    // The host replaces its protocol state in the same commit that records the import.
    complete(&restored, import);
    assert_eq!(restored.identity().unwrap(), Some(created.identity));
    assert!(matches!(
        restored.current_publication(),
        Err(RoostError::InboxRotationRequired)
    ));
    assert!(matches!(
        restored.encode_contact_publication(),
        Err(RoostError::InboxRotationRequired)
    ));
    assert!(matches!(
        restored.prepare_one_time_prekeys(4),
        Err(RoostError::InboxRotationRequired)
    ));

    let rotation = restored.prepare_inbox_rotation().unwrap();
    complete(&restored, rotation.operation_id);
    let publication = restored.current_publication().unwrap();
    assert_eq!(publication.discovery_key.epoch, source_epoch + 1);
    assert_eq!(publication, rotation.publication);
    let one_time_prekeys = restored.prepare_one_time_prekeys(4).unwrap();
    assert_eq!(one_time_prekeys.one_time_prekeys.len(), 4);
    complete(&restored, one_time_prekeys.operation_id);
}

#[test]
fn deletion_removes_the_identity() {
    let context = IdentityContext::new(Arc::new(MemoryStorage::default()));
    let created = context.prepare_identity_creation().unwrap();
    complete(&context, created.operation_id);

    let deletion = context.prepare_identity_deletion().unwrap();
    complete(&context, deletion);
    assert_eq!(context.identity().unwrap(), None);
}

#[test]
fn operation_ids_must_be_canonical() {
    let context = IdentityContext::new(Arc::new(MemoryStorage::default()));
    let prepared = context.prepare_identity_creation().unwrap();
    assert_eq!(
        context
            .operation_status(prepared.operation_id.clone())
            .unwrap(),
        OperationStatus::Prepared
    );

    let uppercase = OperationId {
        value: prepared.operation_id.value.to_uppercase(),
    };
    let truncated = OperationId {
        value: prepared.operation_id.value[1..].into(),
    };
    for id in [uppercase, truncated] {
        assert!(matches!(
            context.operation_status(id),
            Err(RoostError::InvalidData { .. })
        ));
    }
    let unknown = OperationId {
        value: "0".repeat(32),
    };
    assert!(matches!(
        context.operation_status(unknown),
        Err(RoostError::NotFound)
    ));
}

/// A sender certificate signed by a relay's domain key, with the keys a host checks it against.
struct IssuedCertificate {
    identity_key: IdentityKey,
    certificate: Vec<u8>,
    signature: Vec<u8>,
    domain_verifying_key: Vec<u8>,
}

impl IssuedCertificate {
    fn new() -> Self {
        let identity_key = IdentityKey {
            agreement_key: KeyPair::from_secret_bytes(&[0x31; 32])
                .public
                .as_bytes()
                .to_vec(),
            signing_key: SigningKeyPair::from_signing_bytes(&[0x21; 32])
                .verifying
                .to_bytes()
                .to_vec(),
        };
        let (certificate, signature) =
            issue_certificate(&identity_key, CERTIFICATE_EXPIRES_AT_SECS);
        Self {
            identity_key,
            signature,
            certificate,
            domain_verifying_key: domain_signing_key().verifying.to_bytes().to_vec(),
        }
    }

    /// Returns validation input that trusts the domain key and revokes nothing.
    fn validation(&self, reference_time_millis: u64) -> SenderCertificateValidation {
        SenderCertificateValidation {
            domain_signing_keys: vec![DomainSigningKey {
                id: DOMAIN_SIGNING_KEY_ID.to_vec(),
                verifying_key: self.domain_verifying_key.clone(),
            }],
            expected_relay_domain: RELAY_DOMAIN.to_vec(),
            revocation_state: RevocationState {
                available: true,
                revoked_identity_keys: Vec::new(),
            },
            reference_time_millis,
        }
    }

    fn signed(&self) -> SignedSenderCertificate {
        SignedSenderCertificate {
            certificate: self.certificate.clone(),
            signature: self.signature.clone(),
        }
    }

    fn validate_at(
        &self,
        context: &IdentityContext,
        reference_time_millis: u64,
        certificate_grace_millis: u64,
    ) -> Result<ValidatedSenderCertificate, RoostError> {
        context.validate_sender_certificate(
            self.signed(),
            self.validation(reference_time_millis),
            certificate_grace_millis,
        )
    }
}

#[track_caller]
fn assert_rejected_for(
    result: Result<ValidatedSenderCertificate, RoostError>,
    expected: SenderCertificateValidationError,
) {
    match result {
        Err(RoostError::CertificateRejected { reason }) => assert_eq!(reason, expected.to_string()),
        Err(error) => panic!("expected CertificateRejected, got {error:?}"),
        Ok(_) => panic!("expected CertificateRejected, got a validated certificate"),
    }
}

#[test]
fn expired_sender_certificate_validates_only_within_the_passed_grace() {
    let signed = IssuedCertificate::new();
    let context = IdentityContext::new(Arc::new(MemoryStorage::default()));
    let grace_millis = 300_000;

    let validated = signed
        .validate_at(&context, CERTIFICATE_EXPIRES_AT_MILLIS, 0)
        .unwrap();
    assert_eq!(validated.identity_key, signed.identity_key);
    assert_eq!(validated.expires_at_millis, CERTIFICATE_EXPIRES_AT_MILLIS);
    assert_rejected_for(
        signed.validate_at(&context, CERTIFICATE_EXPIRES_AT_MILLIS + 1, 0),
        SenderCertificateValidationError::ExpiredCertificate,
    );
    signed
        .validate_at(
            &context,
            CERTIFICATE_EXPIRES_AT_MILLIS + grace_millis,
            grace_millis,
        )
        .unwrap();
    assert_rejected_for(
        signed.validate_at(
            &context,
            CERTIFICATE_EXPIRES_AT_MILLIS + grace_millis + 1,
            grace_millis,
        ),
        SenderCertificateValidationError::ExpiredCertificate,
    );
}

#[test]
fn certificate_grace_above_five_minutes_is_refused() {
    let signed = IssuedCertificate::new();
    let context = IdentityContext::new(Arc::new(MemoryStorage::default()));

    assert!(matches!(
        signed.validate_at(&context, CERTIFICATE_EXPIRES_AT_MILLIS, 300_001),
        Err(RoostError::InvalidData { .. })
    ));
}

#[test]
fn sender_certificate_is_rejected_when_revocation_is_unavailable() {
    let signed = IssuedCertificate::new();
    let context = IdentityContext::new(Arc::new(MemoryStorage::default()));
    let validation = SenderCertificateValidation {
        revocation_state: RevocationState {
            available: false,
            revoked_identity_keys: Vec::new(),
        },
        ..signed.validation(CERTIFICATE_EXPIRES_AT_MILLIS)
    };

    assert_rejected_for(
        context.validate_sender_certificate(signed.signed(), validation, 0),
        SenderCertificateValidationError::RevocationStateUnavailable,
    );
}

#[test]
fn validation_input_errors_are_invalid_data() {
    let signed = IssuedCertificate::new();
    let context = IdentityContext::new(Arc::new(MemoryStorage::default()));
    let valid = || signed.validation(CERTIFICATE_EXPIRES_AT_MILLIS);
    let trusted = || DomainSigningKey {
        id: DOMAIN_SIGNING_KEY_ID.to_vec(),
        verifying_key: signed.domain_verifying_key.clone(),
    };
    let with_keys = |domain_signing_keys| SenderCertificateValidation {
        domain_signing_keys,
        ..valid()
    };
    let low_order_key = IdentityKey {
        agreement_key: vec![0; 32],
        ..signed.identity_key.clone()
    };
    let cases = [
        (
            with_keys(vec![
                trusted(),
                DomainSigningKey {
                    id: b"other".to_vec(),
                    verifying_key: vec![0xff; 32],
                },
            ]),
            SenderCertificateValidationError::InvalidDomainSigningKey { index: 1 },
        ),
        (
            with_keys(vec![
                trusted(),
                DomainSigningKey {
                    id: Vec::new(),
                    ..trusted()
                },
            ]),
            SenderCertificateValidationError::EmptySigningKeyId { index: 1 },
        ),
        (
            with_keys(vec![trusted(), trusted()]),
            SenderCertificateValidationError::DuplicateSigningKeyId { index: 1 },
        ),
        (
            SenderCertificateValidation {
                expected_relay_domain: Vec::new(),
                ..valid()
            },
            SenderCertificateValidationError::EmptyRelayDomain,
        ),
        (
            SenderCertificateValidation {
                revocation_state: RevocationState {
                    available: true,
                    revoked_identity_keys: vec![signed.identity_key.clone(), low_order_key],
                },
                ..valid()
            },
            SenderCertificateValidationError::InvalidRevokedIdentityKey { index: 1 },
        ),
    ];

    for (validation, expected) in cases {
        match context.validate_sender_certificate(signed.signed(), validation, 0) {
            Err(RoostError::InvalidData { reason }) => assert_eq!(reason, expected.to_string()),
            Err(error) => panic!("expected InvalidData, got {error:?}"),
            Ok(_) => panic!("expected InvalidData, got a validated certificate"),
        }
    }
}
