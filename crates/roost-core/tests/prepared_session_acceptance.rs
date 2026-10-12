//! Prepared X3DH acceptance across Protocol State and SecureStorage.
//!
//! The scenario proves that an authenticated first Message stages one-time-prekey consumption,
//! and that two preparations from the same prekey state cannot both commit.

mod support;

use roost_core::{
    HandshakeError, KeyStoreError, KeyStoreOperationError, OneTimePreKeyError, PreKeySelection,
    ProtocolStateError, SealedFrameError, SessionAcceptanceOutcome, SessionEstablishmentError,
    SignedPreKeyError, TransportBinding,
};
use support::device::{Device, Relay};

#[test]
fn prepared_session_acceptance_consumes_one_time_prekey_only_after_finalize() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let bob = Device::new(&relay, 0xb0);
    let bob_bundle = bob.bundle();
    let prekey_selection = bob_bundle.selection;
    let initial = alice.initiate(&bob_bundle, b"hello bob");
    let replacement_signed_prekey = bob.store.prepare_signed_prekey_rotation().unwrap();
    assert_eq!(
        replacement_signed_prekey.output.id,
        prekey_selection.signed_prekey_id + 1
    );
    bob.store
        .reserve_operation(replacement_signed_prekey.operation.id)
        .unwrap();
    bob.store
        .finalize_operation(replacement_signed_prekey.operation.id)
        .unwrap();

    let accepted = bob
        .prepare_accept(&initial.message, prekey_selection)
        .unwrap();
    let stale = bob
        .prepare_accept(&initial.message, prekey_selection)
        .unwrap();
    let SessionAcceptanceOutcome::Accepted(result) = &accepted.output else {
        panic!("expected an accepted Session");
    };
    assert_eq!(&*result.plaintext, b"hello bob");

    let changed_transport_binding =
        TransportBinding::new(b"consumer-owned changed binding".to_vec()).unwrap();
    assert!(matches!(
        bob.prepare_accept_with_binding(
            &initial.message,
            &changed_transport_binding,
            prekey_selection
        ),
        Err(SessionEstablishmentError::ProtocolState(
            ProtocolStateError::SealedFrame(SealedFrameError::Aead)
        ))
    ));
    let wrong_signed_prekey = PreKeySelection {
        signed_prekey_id: prekey_selection.signed_prekey_id + 1,
        ..prekey_selection
    };
    assert!(matches!(
        bob.prepare_accept(&initial.message, wrong_signed_prekey),
        Err(SessionEstablishmentError::SignedPreKey(
            SignedPreKeyError::NotFound
        ))
    ));
    let wrong_one_time_prekey = PreKeySelection {
        one_time_prekey_id: prekey_selection.one_time_prekey_id.map(|id| id + 1),
        ..prekey_selection
    };
    assert!(matches!(
        bob.prepare_accept(&initial.message, wrong_one_time_prekey),
        Err(SessionEstablishmentError::Handshake(
            HandshakeError::OneTimePreKeyMismatch
        ))
    ));

    bob.store.reserve_operation(accepted.operation.id).unwrap();
    bob.store.finalize_operation(accepted.operation.id).unwrap();
    assert!(matches!(
        bob.store.reserve_operation(stale.operation.id),
        Err(KeyStoreError::Operation(
            KeyStoreOperationError::PreconditionChanged { .. }
        ))
    ));
    bob.store.abort_operation(stale.operation.id).unwrap();
    assert!(matches!(
        bob.prepare_accept(&initial.message, prekey_selection),
        Err(SessionEstablishmentError::OneTimePreKey(
            OneTimePreKeyError::NotFound
        ))
    ));
}
