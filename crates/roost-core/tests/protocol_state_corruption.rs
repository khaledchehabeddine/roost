//! Corrupt host blobs fault at the Core receive boundary without replacing committed state.

mod support;

use roost_core::{ProtocolStateEngine, ProtocolStateError};
use support::{ProtocolFixture, deduplication_address, session_address};

#[test]
fn corrupt_committed_blobs_surface_faults_without_reinitialization() {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0x56; 32]);
    let message = fixture.encrypt_from_alice(&engine, 1, b"corruption probe");
    for address in [
        session_address(fixture.session_id),
        deduplication_address(fixture.deduplication_key.clone()),
    ] {
        let mut store = fixture.bob_store.clone();
        let corrupt = vec![1, 0, 0xaa];
        store.set_raw(address.clone(), corrupt.clone());
        let result = fixture.receive(&engine, &store.snapshot(), &message.message, 0x57);
        assert!(
            matches!(result, Err(ProtocolStateError::BlobDecode { address: actual, .. }) if actual == address)
        );
        assert_eq!(store.blob_bytes(&address).unwrap(), corrupt);
    }
}
