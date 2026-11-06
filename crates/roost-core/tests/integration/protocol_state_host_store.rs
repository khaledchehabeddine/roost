//! A commit condition that a record is absent fails once another commit writes the record.

use crate::support::HostCommitError;
use crate::support::device::{Device, Relay};
use roost_core::ProtocolStateCommitCondition;

#[test]
fn a_stale_absence_condition_rejects_the_commit_before_host_effects() {
    let relay = Relay::new();
    let mut bob = Device::new(&relay, 0xb0);
    let stranger = Device::new(&relay, 0xc0).identity_key();
    let first = bob.store.prepare_block_contact(stranger, None).unwrap();
    let stale = bob.store.prepare_block_contact(stranger, None).unwrap();
    assert!(matches!(
        stale.changes.conditions()[0].1,
        ProtocolStateCommitCondition::Absent
    ));
    let stale_operation = stale.changes.operation().unwrap();
    bob.commit_changes(first.changes).unwrap();
    let address = bob.contact_address(stranger);
    let before = bob.host.blob_bytes(&address);
    assert_eq!(
        bob.host.commit(stale.changes).err(),
        Some(HostCommitError::StaleCondition)
    );
    assert_eq!(bob.host.blob_bytes(&address), before);
    bob.store.abort_operation(stale_operation).unwrap();
}
