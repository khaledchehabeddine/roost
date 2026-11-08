use crate::support::ProtocolFixture;
use roost_core::{MessageOperationError, ProtocolStateError, ProtocolStateKind};

#[test]
fn corrupt_committed_blobs_surface_faults_without_reinitialization() {
    let mut fixture = ProtocolFixture::new();
    let message = fixture.encrypt_from_alice(1, b"corruption probe");
    for kind in [
        ProtocolStateKind::RatchetSession,
        ProtocolStateKind::DeduplicationSet,
    ] {
        let mut store = fixture.bob.database.clone();
        let address = store.only(kind);
        let corrupt = store.corrupt(&address);
        let result = fixture.receive(&store, &message.message, 0x57);
        assert!(
            matches!(result, Err(MessageOperationError::ProtocolState(ProtocolStateError::BlobDecode { address: actual, .. })) if actual == address)
        );
        assert_eq!(store.blob_bytes(&address).unwrap(), corrupt);
    }
}
