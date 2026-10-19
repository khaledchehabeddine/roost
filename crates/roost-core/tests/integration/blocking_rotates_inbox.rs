//! Blocking a contact rotates the local inbox.
//!
//! Crosses the keystore boundary into protocol state: the contact flag lives in protocol state
//! while the inbox lives in secure storage, and blocking must move both.

use crate::support::device::{Relay, requested};

#[test]
fn blocking_a_contact_rotates_the_inbox() {
    let relay = Relay::new();
    let (alice, mut bob) = requested(&relay);
    let before = bob.publication();

    let publication = bob
        .block(alice.identity_key())
        .expect("blocking must rotate the inbox so the blocked contact loses delivery");

    assert!(bob.contact(&alice).unwrap().blocked);
    assert_eq!(
        publication.discovery_key.epoch,
        before.discovery_key.epoch + 1
    );
    // The capability the blocked contact could have held no longer matches the registered verifier.
    assert_ne!(
        publication.recipient_delivery_verifier,
        before.recipient_delivery_verifier
    );
    assert_eq!(
        bob.publication().discovery_key.epoch,
        publication.discovery_key.epoch
    );
}

/// Blocking someone already blocked must not churn every other contact's delivery capability for
/// no reason, since each rotation sends every remaining contact a new Inbox Grant.
#[test]
fn blocking_an_already_blocked_contact_does_not_rotate_again() {
    let relay = Relay::new();
    let (alice, mut bob) = requested(&relay);
    bob.block(alice.identity_key()).unwrap();
    let epoch_after_first = bob.publication().discovery_key.epoch;
    let record = bob.contact_record(alice.identity_key());

    let second = bob
        .store
        .prepare_block_contact(alice.identity_key(), record.as_ref())
        .unwrap();

    assert!(second.publication.is_none());
    assert!(second.changes.operation().is_none());
    assert!(second.changes.into_updates().is_empty());
    assert_eq!(bob.publication().discovery_key.epoch, epoch_after_first);
}
