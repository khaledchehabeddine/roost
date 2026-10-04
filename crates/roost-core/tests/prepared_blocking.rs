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

const CREATED_AT_SECS: u64 = 1_700_000_000;

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
    let discovery = generate_discovery_key(&mut rng, &signing, 1, CREATED_AT_SECS);
    ContactIdentity {
        identity_key: ContactIdentityKey {
            x25519_public_key: *agreement.public.as_bytes(),
            ed25519_verifying_key: signing.verifying.to_bytes(),
        },
        discovery_key: ContactDiscoveryKey::from(&discovery.public()),
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
    let identity = store.prepare_identity_creation().unwrap();
    store.reserve_operation(identity.operation.id).unwrap();
    store.finalize_operation(identity.operation.id).unwrap();
    let engine = ProtocolStateEngine::new();
    let contact = peer_contact();
    let identity_key = contact.identity_key;
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot
        .apply_all(
            engine
                .record_contact(&snapshot, contact)
                .unwrap()
                .state_updates,
        )
        .unwrap();
    (storage, store, engine, snapshot, identity_key)
}

#[test]
fn prepared_block_commits_contact_and_rotation_without_a_cross_store_partial_state() {
    let (_storage, store, engine, mut snapshot, identity_key) = setup();
    let before = store.current_public_discovery_key().unwrap().epoch;

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
    assert_eq!(store.current_public_discovery_key().unwrap().epoch, before);

    store.reserve_operation(prepared.operation.id).unwrap();
    snapshot
        .apply_all(prepared.output.contact.state_updates)
        .unwrap();
    store.finalize_operation(prepared.operation.id).unwrap();

    assert_eq!(
        store.current_public_discovery_key().unwrap().epoch,
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
    let before = store.current_public_discovery_key().unwrap().epoch;
    let prepared = store
        .prepare_block_contact(&snapshot, identity_key)
        .unwrap();

    store.reserve_operation(prepared.operation.id).unwrap();
    store.abort_operation(prepared.operation.id).unwrap();

    assert_eq!(store.current_public_discovery_key().unwrap().epoch, before);
}

#[test]
fn uncertain_host_block_commit_recovers_both_decisions_from_durable_operation_record() {
    for applied_before_response_loss in [false, true] {
        let (storage, store, engine, mut snapshot, identity_key) = setup();
        let before = store.current_public_discovery_key().unwrap().epoch;
        let prepared = store
            .prepare_block_contact(&snapshot, identity_key)
            .unwrap();
        let id = prepared.operation.id;
        let updates = prepared.output.contact.state_updates;
        assert_eq!(updates.len(), 1);
        let address = updates[0].address().clone();
        let directory =
            std::env::temp_dir().join(format!("roost-host-commit-{}", hex::encode(id.as_bytes()),));
        std::fs::create_dir(&directory).unwrap();
        let committed_path = directory.join("committed");
        let staged_path = directory.join("staged");
        // This one host record holds both the opaque contact blob and the commit decision.
        let initial = Zeroizing::new(
            postcard::to_allocvec(&(None::<[u8; 16]>, snapshot.get(&address).unwrap().as_bytes()))
                .unwrap(),
        );
        std::fs::write(&committed_path, &initial).unwrap();
        std::fs::File::open(&committed_path)
            .unwrap()
            .sync_all()
            .unwrap();

        store.reserve_operation(id).unwrap();
        assert!(updates.iter().all(|update| {
            update
                .commit_condition()
                .is_satisfied_by(snapshot.get(update.address()))
        }));
        snapshot.apply_all(updates).unwrap();
        let staged = Zeroizing::new(
            postcard::to_allocvec(&(
                Some(*id.as_bytes()),
                snapshot.get(&address).unwrap().as_bytes(),
            ))
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
            store
                .unfinished_operations()
                .unwrap()
                .iter()
                .any(|operation| operation.status == KeyStoreOperationStatus::Reserved)
        );
        drop(snapshot);
        drop(store);

        let recovered = storage.key_store();
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
        let mut snapshot = ProtocolStateSnapshot::new();
        snapshot
            .set(
                address,
                roost_core::ProtocolStateBlob::from_bytes(blob.to_vec()),
            )
            .unwrap();
        assert_eq!(
            engine
                .contact_state(&snapshot, identity_key)
                .unwrap()
                .unwrap()
                .blocked,
            applied_before_response_loss
        );
        assert_eq!(
            recovered.current_public_discovery_key().unwrap().epoch,
            before + u32::from(applied_before_response_loss)
        );
        std::fs::remove_dir_all(directory).unwrap();
    }
}
