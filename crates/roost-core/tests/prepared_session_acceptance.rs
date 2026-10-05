//! Prepared X3DH acceptance across Protocol State and SecureStorage.
//!
//! The scenario proves that an authenticated first Message stages one-time-prekey consumption,
//! and that two preparations from the same prekey state cannot both commit.

use roost_core::{
    InMemorySecureStorage, KeyStore, KeyStoreError, KeyStoreOperationError, PreKeySelection,
    ProtocolStateKey, SessionAcceptance, SessionEstablishmentError, SessionId, SessionInitiation,
    SignedPreKeyError, TransportBinding,
};

fn finalize<T>(store: &KeyStore, prepared: &roost_core::PreparedKeyStoreOperation<T>) {
    store.reserve_operation(prepared.operation.id).unwrap();
    store.finalize_operation(prepared.operation.id).unwrap();
}

#[test]
fn prepared_session_acceptance_consumes_one_time_prekey_only_after_finalize() {
    let alice = KeyStore::new(Box::new(InMemorySecureStorage::new()));
    let bob = KeyStore::new(Box::new(InMemorySecureStorage::new()));
    let alice_identity = alice.prepare_identity_creation().unwrap();
    finalize(&alice, &alice_identity);
    let bob_identity = bob.prepare_identity_creation().unwrap();
    finalize(&bob, &bob_identity);
    let signed_prekey = bob.prepare_signed_prekey_rotation().unwrap();
    finalize(&bob, &signed_prekey);
    let one_time_prekeys = bob.prepare_one_time_prekeys(1).unwrap();
    finalize(&bob, &one_time_prekeys);
    let bob_publication = bob.current_publication().unwrap();
    let bob_one_time_prekey = one_time_prekeys.output[0].clone();
    let transport_binding =
        TransportBinding::new(b"consumer-owned initial binding".to_vec()).unwrap();
    let prekey_selection = PreKeySelection {
        signed_prekey_id: bob_publication.signed_prekey.id,
        one_time_prekey_id: Some(bob_one_time_prekey.id),
    };

    let session_key = ProtocolStateKey::session(SessionId::from_bytes([0x22; 16]));
    let initial = alice
        .initiate_session_with_transport_binding(
            SessionInitiation {
                session_key: session_key.clone(),
                responder_identity_key: bob_identity.output.public().unwrap(),
                responder_discovery_to_identity: bob_publication.discovery_to_identity,
                responder_prekey_bundle: roost_crypto::PreKeyBundle {
                    version: bob_publication.version,
                    discovery_key: bob_publication.discovery_key,
                    signed_prekey: bob_publication.signed_prekey,
                    one_time_prekey: Some(bob_one_time_prekey),
                },
                sender_certificate: b"alice certificate",
                sender_signature: b"alice signature",
                plaintext: b"hello bob",
            },
            &transport_binding,
        )
        .unwrap();
    let replacement_signed_prekey = bob.prepare_signed_prekey_rotation().unwrap();
    assert_eq!(
        replacement_signed_prekey.output.id,
        prekey_selection.signed_prekey_id + 1
    );
    finalize(&bob, &replacement_signed_prekey);
    let input = || SessionAcceptance {
        session_key: session_key.clone(),
        initiator_identity_key: Some(alice_identity.output.public().unwrap()),
        message: &initial.message,
    };

    let accepted = bob
        .prepare_accept_session_with_transport_binding(
            input(),
            &transport_binding,
            prekey_selection,
        )
        .unwrap();
    let stale = bob
        .prepare_accept_session_with_transport_binding(
            input(),
            &transport_binding,
            prekey_selection,
        )
        .unwrap();
    assert_eq!(&*accepted.output.plaintext, b"hello bob");

    let changed_transport_binding =
        TransportBinding::new(b"consumer-owned changed binding".to_vec()).unwrap();
    assert!(
        bob.prepare_accept_session_with_transport_binding(
            SessionAcceptance {
                session_key: session_key.clone(),
                initiator_identity_key: Some(alice_identity.output.public().unwrap()),
                message: &initial.message,
            },
            &changed_transport_binding,
            prekey_selection,
        )
        .is_err()
    );
    let wrong_signed_prekey = PreKeySelection {
        signed_prekey_id: prekey_selection.signed_prekey_id + 1,
        ..prekey_selection
    };
    assert!(matches!(
        bob.prepare_accept_session_with_transport_binding(
            input(),
            &transport_binding,
            wrong_signed_prekey,
        ),
        Err(SessionEstablishmentError::SignedPreKey(
            SignedPreKeyError::NotFound
        ))
    ));
    let wrong_one_time_prekey = PreKeySelection {
        one_time_prekey_id: prekey_selection.one_time_prekey_id.map(|id| id + 1),
        ..prekey_selection
    };
    assert!(matches!(
        bob.prepare_accept_session_with_transport_binding(
            input(),
            &transport_binding,
            wrong_one_time_prekey,
        ),
        Err(SessionEstablishmentError::Handshake(
            roost_crypto::HandshakeError::OneTimePreKeyMismatch
        ))
    ));

    finalize(&bob, &accepted);
    assert!(matches!(
        bob.reserve_operation(stale.operation.id),
        Err(KeyStoreError::Operation(
            KeyStoreOperationError::PreconditionChanged { .. }
        ))
    ));
    bob.abort_operation(stale.operation.id).unwrap();
    assert!(
        bob.prepare_accept_session_with_transport_binding(
            input(),
            &transport_binding,
            prekey_selection,
        )
        .is_err()
    );
}
