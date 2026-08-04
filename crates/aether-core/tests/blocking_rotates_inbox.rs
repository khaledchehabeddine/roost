//! Blocking a contact rotates the local inbox (AE-BLK-08).
//!
//! Crosses the keystore boundary into protocol state: the contact flag lives in protocol state
//! while the inbox lives in secure storage, and blocking must move both.

use aether_core::{
    ContactDiscoveryKey, ContactIdentity, ContactIdentityKey, InMemorySecureStorage, KeyStore,
    ProtocolStateEngine, ProtocolStateSnapshot,
};
use aether_crypto::{
    generate_discovery_key, generate_key_pair, generate_signing_key_pair, sign_identity_key_binding,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

const CREATED_AT: u64 = 1_700_000_000;

fn peer_contact() -> ContactIdentity {
    let mut rng = ChaCha20Rng::from_seed([21u8; 32]);
    let signing = generate_signing_key_pair(&mut rng);
    let agreement = generate_key_pair(&mut rng);
    let _binding = sign_identity_key_binding(&signing, &agreement.public).unwrap();
    let discovery = generate_discovery_key(&mut rng, &signing, 1, CREATED_AT);
    ContactIdentity {
        identity_key: ContactIdentityKey {
            x25519_public_key: *agreement.public.as_bytes(),
            ed25519_verifying_key: signing.verifying.to_bytes(),
        },
        discovery_key: ContactDiscoveryKey::from(&discovery.bundle()),
    }
}

fn store_with_contact() -> (KeyStore, ProtocolStateSnapshot, ContactIdentityKey) {
    let key_store = KeyStore::new(Box::new(InMemorySecureStorage::new()));
    key_store.generate_identity().unwrap();
    let engine = ProtocolStateEngine::new();
    let contact = peer_contact();
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot.apply_all(
        engine
            .record_contact(&snapshot, contact)
            .unwrap()
            .state_updates,
    );
    (key_store, snapshot, contact.identity_key)
}

#[test]
fn blocking_a_contact_rotates_the_inbox() {
    let (key_store, snapshot, identity_key) = store_with_contact();
    let before = key_store.current_discovery_key_bundle().unwrap().epoch;
    let previous_capability = *key_store.current_delivery_capability().unwrap().to_bytes();

    let block = key_store.block_contact(&snapshot, identity_key).unwrap();

    assert!(block.contact.contact.blocked);
    let rotation = block
        .rotation
        .expect("blocking must rotate the inbox so the blocked contact loses delivery");
    assert_eq!(rotation.publication.discovery_key.epoch, before + 1);
    // The blocked contact's copy of the capability is now worthless at the relay.
    assert_ne!(*rotation.capability.to_bytes(), previous_capability);
}

/// Blocking someone already blocked must not churn every other contact's delivery capability for
/// no reason. Each rotation costs an encrypted re-key message to every remaining contact.
#[test]
fn blocking_an_already_blocked_contact_does_not_rotate_again() {
    let (key_store, mut snapshot, identity_key) = store_with_contact();
    let first = key_store.block_contact(&snapshot, identity_key).unwrap();
    snapshot.apply_all(first.contact.state_updates);
    let generation_after_first = key_store.current_discovery_key_bundle().unwrap().epoch;

    let second = key_store.block_contact(&snapshot, identity_key).unwrap();

    assert!(second.rotation.is_none());
    assert_eq!(
        key_store.current_discovery_key_bundle().unwrap().epoch,
        generation_after_first
    );
}
