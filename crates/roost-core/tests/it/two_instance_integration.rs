//! Public contact decoders reconstruct app state after another instance commits opaque host blobs.

use crate::support::device::{Device, Relay};

#[test]
fn app_queries_observe_extension_changes_only_after_host_commit() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    let request = alice.request(&bob, b"hi bob");
    bob.receive(&request.message);
    assert!(!bob.contact(&alice).unwrap().blocked);

    let extension = bob.second_instance();
    let record = bob.contact_record(alice.identity_key());
    let block = extension
        .prepare_block_contact(alice.identity_key(), record.as_ref())
        .unwrap();
    assert!(!bob.contact(&alice).unwrap().blocked);

    let operation = block.changes.operation().unwrap();
    extension.reserve_operation(operation).unwrap();
    bob.host.commit(block.changes).unwrap();
    extension.finalize_operation(operation).unwrap();
    bob.restart();
    assert!(bob.contact(&alice).unwrap().blocked);
}
