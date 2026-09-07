//! Prepared blocking across Protocol State and SecureStorage.
//!
//! The scenario commits the contact update and inbox rotation through their separate host-owned
//! stores while one stable prepared-operation identifier coordinates recovery.

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use roost_core::{
    ContactDiscoveryKey, ContactIdentity, ContactIdentityKey, InMemorySecureStorage, KeyStore,
    KeyStoreOperationStatus, ProtocolStateEngine, ProtocolStateSnapshot, SecureStorage,
    StorageError,
};
use roost_crypto::{
    generate_discovery_key, generate_key_pair, generate_signing_key_pair, sign_identity_key_binding,
};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

const CREATED_AT: u64 = 1_700_000_000;

#[derive(Clone)]
struct SharedSecureStorage(Arc<Mutex<InMemorySecureStorage>>);

impl SharedSecureStorage {
    fn new() -> Self {
        Self(Arc::new(Mutex::new(InMemorySecureStorage::new())))
    }

    fn key_store(&self) -> KeyStore {
        KeyStore::new(Box::new(self.clone()))
    }
}

impl SecureStorage for SharedSecureStorage {
    fn store(&mut self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        self.0.lock().unwrap().store(key, value)
    }

    fn load(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, StorageError> {
        self.0.lock().unwrap().load(key)
    }

    fn delete(&mut self, key: &str) -> Result<(), StorageError> {
        self.0.lock().unwrap().delete(key)
    }
}

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
    SharedSecureStorage,
    KeyStore,
    ProtocolStateEngine,
    ProtocolStateSnapshot,
    ContactIdentityKey,
) {
    let storage = SharedSecureStorage::new();
    let store = storage.key_store();
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
    (storage, store, engine, snapshot, identity_key)
}

#[test]
fn prepared_block_commits_contact_and_rotation_without_a_cross_store_partial_state() {
    let (_storage, store, engine, mut snapshot, identity_key) = setup();
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
    let (_storage, store, _engine, snapshot, identity_key) = setup();
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

#[test]
fn committed_block_reconciles_host_operation_identifier_and_finalizes_after_restart() {
    let (storage, store, engine, mut snapshot, identity_key) = setup();
    let before = store.current_discovery_key_bundle().unwrap().epoch;
    let prepared = store
        .prepare_block_contact(&snapshot, identity_key)
        .unwrap();
    let host_operation_identifier = prepared.operation.identifier;

    store.commit_operation(host_operation_identifier).unwrap();
    // The host transaction applies both the contact update and this identifier atomically.
    snapshot.apply_all(prepared.output.contact.state_updates);
    drop(store);

    let recovered = storage.key_store();
    let unfinished = recovered.unfinished_operations().unwrap();
    let operation = unfinished
        .iter()
        .find(|operation| operation.operation.identifier == host_operation_identifier)
        .unwrap();
    assert_eq!(operation.status, KeyStoreOperationStatus::Committed);
    recovered
        .finalize_operation(host_operation_identifier)
        .unwrap();

    assert_eq!(
        recovered.current_discovery_key_bundle().unwrap().epoch,
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
