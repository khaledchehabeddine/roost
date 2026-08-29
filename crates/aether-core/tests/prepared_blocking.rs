//! Prepared blocking across Protocol State and SecureStorage.
//!
//! The scenario commits the contact update and inbox rotation through their separate host-owned
//! stores while one stable prepared-operation identifier coordinates recovery.

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

fn setup() -> (
    KeyStore,
    ProtocolStateEngine,
    ProtocolStateSnapshot,
    ContactIdentityKey,
) {
    let store = KeyStore::new(Box::new(InMemorySecureStorage::new()));
    let identity = store.prepare_generate_identity().unwrap();
    store
        .commit_operation(identity.operation.identifier)
        .unwrap();
    store
        .finalize_operation(identity.operation.identifier)
        .unwrap();
    let engine = ProtocolStateEngine::new();
    let contact = peer_contact();
    let identity_key = contact.identity_key;
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot.apply_all(
        engine
            .record_contact(&snapshot, contact)
            .unwrap()
            .state_updates,
    );
    (store, engine, snapshot, identity_key)
}

#[test]
fn prepared_block_commits_contact_and_rotation_without_a_cross_store_partial_state() {
    let (store, engine, mut snapshot, identity_key) = setup();
    let before = store.current_discovery_key_bundle().unwrap().epoch;

    let prepared = store
        .prepare_block_contact(&snapshot, identity_key)
        .unwrap();

    assert!(prepared.output.contact.contact.blocked);
    assert_eq!(
        prepared
            .output
            .rotation
            .as_ref()
            .unwrap()
            .publication
            .discovery_key
            .epoch,
        before + 1
    );
    assert_eq!(store.current_discovery_key_bundle().unwrap().epoch, before);

    store
        .commit_operation(prepared.operation.identifier)
        .unwrap();
    snapshot.apply_all(prepared.output.contact.state_updates);
    store
        .finalize_operation(prepared.operation.identifier)
        .unwrap();

    assert_eq!(
        store.current_discovery_key_bundle().unwrap().epoch,
        before + 1
    );
    assert!(
        engine
            .contact_state(&snapshot, identity_key)
            .unwrap()
            .unwrap()
            .blocked
    );
}

#[test]
fn failed_host_block_commit_aborts_without_rotating_the_inbox() {
    let (store, _engine, snapshot, identity_key) = setup();
    let before = store.current_discovery_key_bundle().unwrap().epoch;
    let prepared = store
        .prepare_block_contact(&snapshot, identity_key)
        .unwrap();

    store
        .commit_operation(prepared.operation.identifier)
        .unwrap();
    store
        .abort_operation(prepared.operation.identifier)
        .unwrap();

    assert_eq!(store.current_discovery_key_bundle().unwrap().epoch, before);
}
