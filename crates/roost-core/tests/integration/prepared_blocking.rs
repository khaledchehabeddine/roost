use crate::support::device::{Device, Relay};
use rand::rngs::OsRng;
use roost_core::{IdentityKey, ProtocolStateBlob};

// Bob holds Alice's contact request.
fn setup() -> (Device, IdentityKey, ProtocolStateBlob) {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    let request = alice.request(&bob, b"hi bob");
    bob.receive(&request.message);
    let record = bob.contact_record(alice.identity_key()).unwrap();
    (bob, alice.identity_key(), record)
}

fn epoch(device: &Device) -> u32 {
    device
        .store
        .current_publication()
        .unwrap()
        .discovery_key
        .epoch
}

fn blocked(device: &Device, address: &roost_core::ProtocolStateAddress, blob: &[u8]) -> bool {
    device
        .store
        .protocol_engine()
        .decode_contact(address, &ProtocolStateBlob::from_bytes(blob.to_vec()))
        .unwrap()
        .blocked
}

#[test]
fn prepared_block_commits_contact_and_rotation_without_a_cross_store_partial_state() {
    let (mut bob, alice, record) = setup();
    let before = epoch(&bob);

    let block = bob
        .store
        .prepare_block_contact(&mut OsRng, alice, Some(&record))
        .unwrap();

    assert_eq!(block.publication.unwrap().discovery_key.epoch, before + 1);
    assert_eq!(epoch(&bob), before);
    let operation = block.changes.operation().unwrap();
    bob.store.reserve_operation(operation).unwrap();
    bob.database.commit(block.changes).unwrap();
    bob.store.finalize_operation(operation).unwrap();

    assert_eq!(epoch(&bob), before + 1);
    let address = bob.contact_address(alice);
    assert!(blocked(
        &bob,
        &address,
        &bob.database.blob_bytes(&address).unwrap()
    ));
}
