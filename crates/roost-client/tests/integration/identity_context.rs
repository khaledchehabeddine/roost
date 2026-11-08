//! An app drives identity creation, backup, prekeys, signing, and deletion through one
//! IdentityContext.

use crate::support::{
    DOMAIN_SIGNING_KEY_ID, MemoryStorage, RELAY_DOMAIN, complete, domain_signing_key,
    issue_certificate, published_identity,
};
use roost_client::{
    DomainSigningKey, Identity, IdentityContext, IdentityKey, OperationId, OperationStatus,
    PublicDiscoveryKey, PublicOneTimePreKey, PublicSignedPreKey, PublicationBundle,
    RevocationState, RoostError, SenderCertificateValidation, SignedSenderCertificate,
    ValidatedSenderCertificate,
};
use roost_crypto::{
    KeyPair, PublicDiscoveryKey as CryptoPublicDiscoveryKey,
    PublicIdentityKey as CryptoPublicIdentityKey, PublicKey,
    PublicSignedPreKey as CryptoPublicSignedPreKey, Signature, SigningKeyPair, VerifyingKey,
    verify_discovery_to_identity_binding, verify_public_discovery_key, verify_public_signed_prekey,
};
use roost_protocol::{SenderCertificateValidationError, SignatureError, verify_with_context};
use std::sync::Arc;

const PASSPHRASE: &str = "correct horse battery staple";
const CERTIFICATE_EXPIRES_AT_SECS: u64 = 1_800_000_000;
const CERTIFICATE_EXPIRES_AT_MILLIS: u64 = CERTIFICATE_EXPIRES_AT_SECS * 1_000;

const RELAY_HTTP_AUTH_CONTEXT: &[u8] = b"Relay-HTTP-Auth-v1";
const RELAY_PROTOCOL_VERSION: u16 = 1;
const RELAY_CHALLENGE_NONCE: [u8; 32] = [0x22; 32];
const RELAY_METHOD: &[u8] = b"POST";
const RELAY_REQUEST_TARGET: &[u8] = b"/v1/prekeys?count=10";
const RELAY_BODY_DIGEST: [u8; 32] = [0x33; 32];

// Returns a context whose identity is created and finalized, and the identity.
fn created_identity() -> (Arc<IdentityContext>, Identity) {
    let context = IdentityContext::new(Arc::new(MemoryStorage::default()));
    let created = context.prepare_identity_creation().unwrap();
    complete(&context, created.operation_id);
    (context, created.identity)
}

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
fn startup_resolves_unfinished_operations_and_an_unrecorded_finalization() {
    let storage = Arc::new(MemoryStorage::default());
    let context = IdentityContext::new(storage.clone());
    // The app commits the identity and finalizes it, but crashes before recording the finalization.
    let created = context.prepare_identity_creation().unwrap();
    complete(&context, created.operation_id.clone());
    // The app commits these prekeys, but crashes before finalizing them.
    let committed = context.prepare_one_time_prekeys(1).unwrap();
    // The app never commits this rotation.
    let abandoned = context.prepare_inbox_rotation().unwrap();
    context
        .reserve_operation(committed.operation_id.clone())
        .unwrap();
    let app_committed = [created.operation_id, committed.operation_id];

    let restarted = IdentityContext::new(storage);
    let unfinished = restarted.unfinished_operations().unwrap();
    assert_eq!(unfinished.len(), 2);
    for operation in unfinished {
        match (operation.status, app_committed.contains(&operation.id)) {
            (OperationStatus::Reserved | OperationStatus::Finalizing, true) => {
                restarted.finalize_operation(operation.id).unwrap();
            }
            (OperationStatus::Prepared | OperationStatus::Reserved, false) => {
                restarted.abort_operation(operation.id).unwrap();
            }
            other => panic!("unexpected unfinished operation {other:?}"),
        }
    }

    assert!(restarted.unfinished_operations().unwrap().is_empty());
    for id in app_committed {
        assert_eq!(
            restarted.operation_status(id).unwrap(),
            OperationStatus::Finalized
        );
    }
    assert_eq!(
        restarted.operation_status(abandoned.operation_id).unwrap(),
        OperationStatus::Aborted
    );
    assert_eq!(restarted.identity().unwrap(), Some(created.identity));
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
    // The app replaces its protocol state in the same commit that records the import.
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
    let (context, _) = created_identity();
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

fn push_length_prefixed(transcript: &mut Vec<u8>, field: &[u8]) {
    transcript.extend_from_slice(&(field.len() as u16).to_be_bytes());
    transcript.extend_from_slice(field);
}

// The relay's authentication transcript: its context, protocol version, challenge nonce, and
// identity signing key, then the relay domain, method, and request target, each after a big-endian
// `u16` length, then the request body's SHA-256 digest. Nothing separates the context from what
// follows it.
fn relay_http_transcript(identity_signing_key: &[u8], body_digest: &[u8; 32]) -> Vec<u8> {
    let mut transcript = RELAY_HTTP_AUTH_CONTEXT.to_vec();
    transcript.extend_from_slice(&RELAY_PROTOCOL_VERSION.to_be_bytes());
    transcript.extend_from_slice(&RELAY_CHALLENGE_NONCE);
    transcript.extend_from_slice(identity_signing_key);
    push_length_prefixed(&mut transcript, RELAY_DOMAIN);
    push_length_prefixed(&mut transcript, RELAY_METHOD);
    push_length_prefixed(&mut transcript, RELAY_REQUEST_TARGET);
    transcript.extend_from_slice(body_digest);
    transcript
}

/// The signature must cover the transcript bytes and nothing else.
///
/// The relay rebuilds the transcript alone and calls bare Ed25519 verify, so a context added on
/// this side, as `sign_with_context` would add it, makes a preimage the relay never rebuilds. That
/// signature would verify nowhere, and nothing at the boundary would say why.
#[test]
fn signed_authentication_transcript_verifies_bare_and_is_not_context_prefixed() {
    let (context, identity) = created_identity();
    let transcript = relay_http_transcript(&identity.key.signing_key, &RELAY_BODY_DIGEST);

    let signature_bytes = context
        .sign_authentication_transcript(transcript.clone())
        .unwrap();

    assert_eq!(signature_bytes.len(), 64);
    let signature = signature_from(&signature_bytes);
    let verifying = verifying_key(&identity);
    verifying.verify_strict(&transcript, &signature).unwrap();
    // The transcript's own context added again is the shape a contextual signature would have.
    assert!(matches!(
        verify_with_context(&verifying, RELAY_HTTP_AUTH_CONTEXT, &transcript, &signature),
        Err(SignatureError::SignatureInvalid)
    ));
    // Ed25519 is deterministic, so an app that retries a challenge sends the same proof.
    assert_eq!(
        context.sign_authentication_transcript(transcript).unwrap(),
        signature_bytes
    );
}

/// The identity key signs identity bindings, discovery key bindings, and message transcripts, so
/// signing any bytes the app passes would sign those preimages too. Each starts with `Roost`, which
/// the export refuses in any letter case.
#[test]
fn sign_authentication_transcript_refuses_the_reserved_prefix_in_any_case() {
    let (context, _) = created_identity();
    for prefix in ["Roost", "roost", "ROOST"] {
        let transcript = [prefix.as_bytes(), &[0x41; 32]].concat();
        assert!(
            matches!(
                context.sign_authentication_transcript(transcript),
                Err(RoostError::InvalidData { .. })
            ),
            "expected InvalidData for a transcript starting {prefix}"
        );
    }
}

#[test]
fn sign_authentication_transcript_requires_a_stored_identity() {
    let context = IdentityContext::new(Arc::new(MemoryStorage::default()));
    match context.sign_authentication_transcript(RELAY_HTTP_AUTH_CONTEXT.to_vec()) {
        Err(RoostError::NotFound) => {}
        other => panic!("expected NotFound without an identity, got {other:?}"),
    }
}

#[test]
fn current_publication_bundle_returns_verifiable_records() {
    let context = published_identity();
    let identity = context.identity().unwrap().unwrap();
    let publication = context.current_publication().unwrap();
    assert_publication_verifies(&identity, &publication);
}

#[test]
fn replenish_one_time_prekeys_returns_public_records() {
    let context = published_identity();
    let epoch = context.current_publication().unwrap().discovery_key.epoch;
    let replenished = context.prepare_one_time_prekey_replenishment().unwrap();
    complete(&context, replenished.operation_id);

    assert_eq!(replenished.one_time_prekeys.len(), 100);
    for one_time_prekey in &replenished.one_time_prekeys {
        assert_one_time_prekey_record(one_time_prekey, epoch);
    }
    let again = context.prepare_one_time_prekey_replenishment().unwrap();
    complete(&context, again.operation_id);
    assert!(again.one_time_prekeys.is_empty());
}

fn signature_from(bytes: &[u8]) -> Signature {
    Signature::from_bytes(&<[u8; 64]>::try_from(bytes).unwrap())
}

fn verifying_key(identity: &Identity) -> VerifyingKey {
    VerifyingKey::from_bytes(&<[u8; 32]>::try_from(identity.key.signing_key.as_slice()).unwrap())
        .unwrap()
}

fn public_identity_key(identity: &Identity) -> CryptoPublicIdentityKey {
    CryptoPublicIdentityKey::from_bytes(
        &identity.key.agreement_key,
        &identity.key.signing_key,
        &identity.binding_signature,
    )
    .unwrap()
}

fn public_discovery_key(discovery_key: &PublicDiscoveryKey) -> CryptoPublicDiscoveryKey {
    CryptoPublicDiscoveryKey::from_bytes(
        &discovery_key.public_key,
        &discovery_key.verifying_key,
        discovery_key.epoch,
        discovery_key.created_at_millis / 1_000,
        &discovery_key.signature,
    )
    .unwrap()
}

fn public_signed_prekey(signed_prekey: &PublicSignedPreKey) -> CryptoPublicSignedPreKey {
    CryptoPublicSignedPreKey {
        id: signed_prekey.id,
        public_key: PublicKey::from(
            <[u8; 32]>::try_from(signed_prekey.public_key.as_slice()).unwrap(),
        ),
        signature: signature_from(&signed_prekey.signature),
        epoch: signed_prekey.epoch,
        created_at_secs: signed_prekey.created_at_millis / 1_000,
    }
}

fn assert_publication_verifies(identity: &Identity, publication: &PublicationBundle) {
    let discovery_key = public_discovery_key(&publication.discovery_key);
    verify_public_discovery_key(&discovery_key, &verifying_key(identity)).unwrap();
    verify_public_signed_prekey(
        &public_signed_prekey(&publication.signed_prekey),
        &discovery_key.verifying_key,
    )
    .unwrap();
    let identity_key = public_identity_key(identity);
    verify_discovery_to_identity_binding(
        &identity_key.public_key,
        &identity_key.verifying_key,
        &discovery_key.verifying_key,
        &signature_from(&publication.discovery_to_identity),
    )
    .unwrap();
}

fn assert_one_time_prekey_record(one_time_prekey: &PublicOneTimePreKey, epoch: u32) {
    assert_eq!(one_time_prekey.public_key.len(), 32);
    assert_eq!(one_time_prekey.epoch, epoch);
}

/// A sender certificate signed by a relay's domain key, with the keys an app checks it against.
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
