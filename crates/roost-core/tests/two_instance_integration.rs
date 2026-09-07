//! Public contact queries reconstruct app state after another instance commits opaque host blobs.

mod support;

use roost_core::ProtocolStateEngine;
use support::ProtocolFixture;

#[test]
fn app_queries_observe_extension_changes_only_after_host_commit() {
    let app = ProtocolStateEngine::new();
    let extension = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0x51; 32]);
    let read = fixture.alice_store.read();
    let contact = app.contact_states(&read.snapshot).unwrap().remove(0);
    assert!(!contact.blocked);

    let change = extension
        .block_contact(&read.snapshot, contact.identity.identity_key)
        .unwrap();
    assert!(change.contact.blocked);
    assert!(change.event.is_some());
    assert!(
        !app.contact_state(
            &fixture.alice_store.snapshot(),
            contact.identity.identity_key
        )
        .unwrap()
        .unwrap()
        .blocked
    );

    fixture
        .alice_store
        .commit(read.token, change.state_updates)
        .unwrap();
    let restarted_app = ProtocolStateEngine::new();
    assert!(
        restarted_app
            .contact_state(
                &fixture.alice_store.snapshot(),
                contact.identity.identity_key
            )
            .unwrap()
            .unwrap()
            .blocked
    );
}
