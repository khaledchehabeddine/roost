//! Public contact queries reconstruct app state after another instance commits opaque host blobs.

mod support;

use roost_core::ProtocolStateEngine;
use support::{HostStore, accepted_contact_identity};

#[test]
fn app_queries_observe_extension_changes_only_after_host_commit() {
    let app = ProtocolStateEngine::new();
    let extension = ProtocolStateEngine::new();
    let mut host = HostStore::default();
    let contact = accepted_contact_identity();
    host.commit(
        app.record_contact(&host.snapshot(), contact)
            .unwrap()
            .state_updates,
    )
    .unwrap();
    host.commit(
        app.accept_contact(&host.snapshot(), contact.identity_key)
            .unwrap()
            .state_updates,
    )
    .unwrap();
    let read = host.snapshot();
    let contact = app.contact_states(&read).unwrap().remove(0);
    assert!(!contact.blocked);

    let change = extension
        .block_contact(&read, contact.identity.identity_key)
        .unwrap();
    assert!(change.contact.blocked);
    assert!(change.event.is_some());
    assert!(
        !app.contact_state(&host.snapshot(), contact.identity.identity_key)
            .unwrap()
            .unwrap()
            .blocked
    );

    host.commit(change.state_updates).unwrap();
    let restarted_app = ProtocolStateEngine::new();
    assert!(
        restarted_app
            .contact_state(&host.snapshot(), contact.identity.identity_key)
            .unwrap()
            .unwrap()
            .blocked
    );
}
