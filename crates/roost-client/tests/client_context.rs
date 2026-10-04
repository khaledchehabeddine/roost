//! One generated Client shares identity storage, configuration, and prepared-operation recovery.

use roost_client::{
    BlockedContactAcknowledgmentPolicy, Client, ClientConfiguration, ClientError,
    ContactDiscoveryKey, ContactIdentity, ContactSafetyNumberConfirmationKind, ContactTrustState,
    IdentityKey, InMemorySecureStorage, KeyStoreOperationStatus, ProtocolStateEntry,
    ProtocolStateUpdate, derive_safety_number,
};
use std::sync::Arc;

#[test]
fn focused_interfaces_share_the_configured_identity_context() {
    let storage = Arc::new(InMemorySecureStorage::new());
    let client = Client::with_configuration(
        storage.clone(),
        ClientConfiguration {
            deduplication_capacity: 64,
            blocked_contact_acknowledgment_policy:
                BlockedContactAcknowledgmentPolicy::SilentReceipt,
        },
    )
    .unwrap();
    assert_eq!(
        client.messaging().hardening_limits().deduplication_capacity,
        64
    );
    assert!(!client.identity().has_identity().unwrap());
    let prepared = client.identity().prepare_generate_identity().unwrap();
    let id = prepared.operation.id;
    client.commit_operation(id.clone()).unwrap();
    assert!(matches!(
        client.identity().load_identity(),
        Err(ClientError::OperationRecoveryRequired { .. })
    ));
    client.finalize_operation(id.clone()).unwrap();
    assert!(matches!(
        client.finalize_operation(id).unwrap(),
        KeyStoreOperationStatus::Finalized
    ));
    let reopened = Client::new(storage);
    assert_eq!(
        reopened
            .identity()
            .load_identity()
            .unwrap()
            .x25519_public_key,
        prepared.identity.x25519_public_key
    );
    assert!(
        client
            .contacts()
            .contact_states(Vec::new())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn safety_number_confirmation_uses_the_clients_local_identity() {
    let alice = Client::new(Arc::new(InMemorySecureStorage::new()));
    let bob = Client::new(Arc::new(InMemorySecureStorage::new()));
    let charlie = Client::new(Arc::new(InMemorySecureStorage::new()));
    for client in [&alice, &bob, &charlie] {
        let prepared = client.identity().prepare_generate_identity().unwrap();
        client
            .commit_operation(prepared.operation.id.clone())
            .unwrap();
        client.finalize_operation(prepared.operation.id).unwrap();
    }
    let identity_key = |client: &Client| {
        let identity = client.identity().load_identity().unwrap();
        IdentityKey {
            x25519_public_key: identity.x25519_public_key,
            ed25519_verifying_key: identity.ed25519_verifying_key,
        }
    };
    let key = bob.identity().current_discovery_key_bundle().unwrap();
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
