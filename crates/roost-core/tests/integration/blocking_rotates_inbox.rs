use crate::support::device::{Relay, requested};
use rand::rngs::OsRng;

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
        publication.recipient_delivery_verifier.as_bytes(),
        before.recipient_delivery_verifier.as_bytes()
    );
    assert_eq!(
        bob.publication().discovery_key.epoch,
        publication.discovery_key.epoch
    );
}

/// Another rotation would make every other contact need a new inbox grant.
#[test]
fn blocking_an_already_blocked_contact_does_not_rotate_again() {
    let relay = Relay::new();
    let (alice, mut bob) = requested(&relay);
    bob.block(alice.identity_key()).unwrap();
    let epoch_after_first = bob.publication().discovery_key.epoch;
    let record = bob.contact_record(alice.identity_key());

    let second = bob
        .store
        .prepare_block_contact(&mut OsRng, alice.identity_key(), record.as_ref())
        .unwrap();

    assert!(second.publication.is_none());
    assert!(second.changes.operation().is_none());
    assert!(second.changes.into_updates().is_empty());
    assert_eq!(bob.publication().discovery_key.epoch, epoch_after_first);
}
