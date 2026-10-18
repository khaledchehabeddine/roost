//! Prepared blocking across Protocol State and SecureStorage.
//!
//! The scenario commits the contact update and inbox rotation through their separate host-owned
//! stores while one stable prepared-operation identifier coordinates recovery.

use crate::support::device::{Device, Relay};
use roost_core::{
    ContactIdentityKey, KeyStoreOperationStatus, ProtocolStateBlob, commit_conditions_match,
};
use zeroize::Zeroizing;

// Bob holds Alice's Contact Request, and returns her Identity Key and her record's bytes.
fn setup() -> (Device, ContactIdentityKey, ProtocolStateBlob) {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let mut bob = Device::new(&relay, 0xb0);
    let request = alice.request(&bob, b"hi bob");
    bob.receive(&request.message);
    let record = bob.contact_record(alice.identity_key()).unwrap();
    (bob, alice.identity_key(), record)
}

fn epoch(device: &Device) -> u32 {
    device.store.current_public_discovery_key().unwrap().epoch
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
        .prepare_block_contact(alice, Some(&record))
        .unwrap();

    assert_eq!(block.publication.unwrap().discovery_key.epoch, before + 1);
    assert_eq!(epoch(&bob), before);
    let operation = block.changes.operation().unwrap();
    bob.store.reserve_operation(operation).unwrap();
    bob.host.commit(block.changes).unwrap();
    bob.store.finalize_operation(operation).unwrap();

    assert_eq!(epoch(&bob), before + 1);
    let address = bob.contact_address(alice);
    assert!(blocked(
        &bob,
        &address,
        &bob.host.blob_bytes(&address).unwrap()
    ));
}

#[test]
fn failed_host_block_commit_aborts_without_rotating_the_inbox() {
    let (bob, alice, record) = setup();
    let before = epoch(&bob);
    let block = bob
        .store
        .prepare_block_contact(alice, Some(&record))
        .unwrap();
    let operation = block.changes.operation().unwrap();

    bob.store.reserve_operation(operation).unwrap();
    bob.store.abort_operation(operation).unwrap();

    assert_eq!(epoch(&bob), before);
}

#[test]
fn uncertain_host_block_commit_recovers_both_decisions_from_durable_operation_record() {
    for applied_before_response_loss in [false, true] {
        let (bob, alice, record) = setup();
        let before = epoch(&bob);
        let block = bob
            .store
            .prepare_block_contact(alice, Some(&record))
            .unwrap();
        let id = block.changes.operation().unwrap();
        let addresses: Vec<_> = block
            .changes
            .conditions()
            .iter()
            .map(|(address, _)| address.clone())
            .collect();
        let current = bob.host.read(&addresses);
        let conditions = block.changes.conditions().to_vec();
        let updates = block.changes.into_updates();
        assert_eq!(updates.len(), 1);
        let address = updates[0].address().clone();
        let directory =
            std::env::temp_dir().join(format!("roost-host-commit-{}", hex::encode(id.as_bytes()),));
        std::fs::create_dir(&directory).unwrap();
        let committed_path = directory.join("committed");
        let staged_path = directory.join("staged");
        // This one host record holds both the opaque contact blob and the commit decision.
        let initial =
            Zeroizing::new(postcard::to_allocvec(&(None::<[u8; 16]>, record.as_bytes())).unwrap());
        std::fs::write(&committed_path, &initial).unwrap();
        std::fs::File::open(&committed_path)
            .unwrap()
            .sync_all()
            .unwrap();

        bob.store.reserve_operation(id).unwrap();
        assert!(commit_conditions_match(&conditions, &current).unwrap());
        let staged = Zeroizing::new(
            postcard::to_allocvec(&(Some(*id.as_bytes()), updates[0].blob().unwrap().as_bytes()))
                .unwrap(),
        );
        std::fs::write(&staged_path, &staged).unwrap();
        std::fs::File::open(&staged_path)
            .unwrap()
            .sync_all()
            .unwrap();
        if applied_before_response_loss {
            std::fs::rename(&staged_path, &committed_path).unwrap();
        }
        std::fs::File::open(&directory).unwrap().sync_all().unwrap();
        // No transaction response reaches the caller. Do not finalize or abort from that absence.
        assert!(
            bob.store
                .unfinished_operations()
                .unwrap()
                .iter()
                .any(|operation| operation.status == KeyStoreOperationStatus::Reserved)
        );
        drop(updates);

        let recovered = bob.second_instance();
        let unfinished = recovered.unfinished_operations().unwrap();
        assert_eq!(unfinished.len(), 1);
        let operation = &unfinished[0];
        assert_eq!(operation.status, KeyStoreOperationStatus::Reserved);
        let durable = Zeroizing::new(std::fs::read(&committed_path).unwrap());
        let (host_id, blob): (Option<[u8; 16]>, &[u8]) = postcard::from_bytes(&durable).unwrap();
        let expected_status = if host_id == Some(*operation.operation.id.as_bytes()) {
            recovered
                .finalize_operation(operation.operation.id)
                .unwrap();
            assert_eq!(
                recovered
                    .finalize_operation(operation.operation.id)
                    .unwrap(),
                KeyStoreOperationStatus::Finalized
            );
            KeyStoreOperationStatus::Finalized
        } else {
            recovered.abort_operation(operation.operation.id).unwrap();
            KeyStoreOperationStatus::Aborted
        };
        assert_eq!(
            recovered.operation_status(operation.operation.id).unwrap(),
            expected_status
        );
        assert_eq!(blocked(&bob, &address, blob), applied_before_response_loss);
        assert_eq!(
            recovered.current_public_discovery_key().unwrap().epoch,
            before + u32::from(applied_before_response_loss)
        );
        std::fs::remove_dir_all(directory).unwrap();
    }
}
