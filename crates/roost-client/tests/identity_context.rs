//! A host drives identity creation, backup, prekeys, and deletion through one IdentityContext.

mod support;

use roost_client::{
    BlockedContactAcknowledgmentPolicy, ContactDiscoveryKey, ContactIdentity,
    ContactSafetyNumberConfirmationKind, ContactTrustState, ContextConfiguration, IdentityContext,
    OperationId, OperationStatus, ProtocolStateEntry, ProtocolStateUpdate, RoostError,
    derive_safety_number,
};
use std::sync::Arc;
use support::MemoryStorage;

const PASSPHRASE: &str = "correct horse battery staple";

/// Reserves and finalizes an operation, as a host does around its own commit.
fn complete(context: &IdentityContext, id: OperationId) {
    context.reserve_operation(id.clone()).unwrap();
    context.finalize_operation(id).unwrap();
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
        Err(RoostError::OperationRecoveryRequired { operation_id, .. })
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
    assert!(matches!(
        context.identity(),
        Err(RoostError::Storage { .. })
    ));
    assert_eq!(context.identity().unwrap(), None);
}

#[test]
fn restored_backup_publishes_only_after_inbox_rotation() {
    let source = IdentityContext::new(Arc::new(MemoryStorage::default()));
    let created = source.prepare_identity_creation().unwrap();
    complete(&source, created.operation_id);
    let signed_prekey = source.prepare_signed_prekey_rotation_if_stale().unwrap();
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
        restored.prepare_one_time_prekeys(4),
        Err(RoostError::InboxRotationRequired)
    ));

    let rotation = restored.prepare_inbox_rotation().unwrap();
    complete(&restored, rotation.operation_id);
    let publication = restored.current_publication().unwrap();
    assert_eq!(publication.discovery_key.epoch, source_epoch + 1);
    assert_eq!(publication, rotation.rotation.publication);
    assert_eq!(
        restored.current_delivery_capability().unwrap(),
        rotation.rotation.capability
    );
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

/// A configuration a host might choose: smaller deduplication, receipts for blocked senders,
/// the largest certificate grace, and its own revision number.
fn configuration() -> ContextConfiguration {
    ContextConfiguration {
        deduplication_capacity: 64,
        blocked_contact_acknowledgment_policy: BlockedContactAcknowledgmentPolicy::SilentReceipt,
        certificate_grace_millis: 300_000,
        revision: 7,
    }
}

#[test]
fn context_reports_the_configuration_it_was_created_with() {
    let default = IdentityContext::new(Arc::new(MemoryStorage::default())).configuration();
    assert_eq!(default.certificate_grace_millis, 0);
    assert_eq!(default.revision, 0);

    let context =
        IdentityContext::with_configuration(Arc::new(MemoryStorage::default()), configuration())
            .unwrap();
    assert_eq!(context.configuration(), configuration());
    assert_eq!(
        context
            .messaging()
            .hardening_limits()
            .deduplication_capacity,
        64
    );
}

#[test]
fn configuration_rejects_certificate_grace_above_five_minutes() {
    let result = IdentityContext::with_configuration(
        Arc::new(MemoryStorage::default()),
        ContextConfiguration {
            certificate_grace_millis: 300_001,
            ..configuration()
        },
    );
    assert!(matches!(result, Err(RoostError::InvalidData { .. })));
}

#[test]
fn safety_number_confirmation_uses_the_contexts_local_identity() {
    let alice = IdentityContext::new(Arc::new(MemoryStorage::default()));
    let bob = IdentityContext::new(Arc::new(MemoryStorage::default()));
    let charlie = IdentityContext::new(Arc::new(MemoryStorage::default()));
    for context in [&alice, &bob, &charlie] {
        let created = context.prepare_identity_creation().unwrap();
        complete(context, created.operation_id);
        let signed_prekey = context.prepare_signed_prekey_rotation().unwrap();
        complete(context, signed_prekey.operation_id);
    }
    let identity_key = |context: &IdentityContext| context.identity().unwrap().unwrap().key;
    let key = bob.current_publication().unwrap().discovery_key;
    let change = alice
        .contacts()
        .record_contact(
            Vec::new(),
            ContactIdentity {
                identity_key: identity_key(&bob),
                discovery_key: ContactDiscoveryKey {
                    x25519_public_key: key.public_key,
                    ed25519_verifying_key: key.verifying_key,
                    epoch: key.epoch,
                    created_at_millis: key.created_at_millis,
                    identity_signature: key.signature,
                },
            },
        )
        .unwrap();
    let entries = |updates: &[ProtocolStateUpdate]| {
        updates
            .iter()
            .map(|update| ProtocolStateEntry {
                kind: update.kind,
                key: update.key.clone(),
                blob: update.blob.clone().expect("contact changes write a blob"),
            })
            .collect::<Vec<_>>()
    };
    let accepted = alice
        .contacts()
        .accept_contact(entries(&change.state_updates), identity_key(&bob))
        .unwrap();
    let foreign = derive_safety_number(identity_key(&charlie), identity_key(&bob)).unwrap();
    let rejected = alice
        .contacts()
        .confirm_contact_safety_number(
            entries(&accepted.state_updates),
            identity_key(&bob),
            foreign.grouped_decimal,
        )
        .unwrap();
    assert!(matches!(
        rejected.kind,
        ContactSafetyNumberConfirmationKind::Mismatched
    ));
    assert!(!matches!(
        rejected.change.contact.trust_state,
        ContactTrustState::Verified
    ));
    let correct = derive_safety_number(identity_key(&alice), identity_key(&bob)).unwrap();
    let confirmed = alice
        .contacts()
        .confirm_contact_safety_number(
            entries(&accepted.state_updates),
            identity_key(&bob),
            correct.grouped_decimal,
        )
        .unwrap();
    assert!(matches!(
        confirmed.kind,
        ContactSafetyNumberConfirmationKind::Matched
    ));
    assert!(matches!(
        confirmed.change.contact.trust_state,
        ContactTrustState::Verified
    ));
}
