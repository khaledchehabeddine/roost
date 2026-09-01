//! Prepared X3DH acceptance across Protocol State and SecureStorage.
//!
//! The scenario proves that an authenticated first Message stages one-time-prekey consumption,
//! and that two preparations from the same prekey state cannot both commit.

use aether_core::{
    InMemorySecureStorage, KeyStore, KeyStoreError, KeyStoreOperationError, ProtocolStateKey,
    RelayPreKeyReference, RelayRoute, RelayRouteError, SessionAcceptance,
    SessionEstablishmentError, SessionId, SessionInitiation, SignedPreKeyError,
};

fn finalize<T>(store: &KeyStore, prepared: &aether_core::PreparedKeyStoreOperation<T>) {
    store
        .commit_operation(prepared.operation.identifier)
        .unwrap();
    store
        .finalize_operation(prepared.operation.identifier)
        .unwrap();
}

#[test]
fn prepared_session_acceptance_consumes_one_time_prekey_only_after_finalize() {
    let alice = KeyStore::new(Box::new(InMemorySecureStorage::new()));
    let bob = KeyStore::new(Box::new(InMemorySecureStorage::new()));
    let alice_identity = alice.prepare_generate_identity().unwrap();
    finalize(&alice, &alice_identity);
    let bob_identity = bob.prepare_generate_identity().unwrap();
    finalize(&bob, &bob_identity);
    let signed_prekey = bob.prepare_rotate_signed_prekey_now().unwrap();
    finalize(&bob, &signed_prekey);
    let one_time_prekeys = bob.prepare_generate_one_time_prekeys(1).unwrap();
    finalize(&bob, &one_time_prekeys);
    let bob_publication = bob.current_publication_bundle().unwrap();
    let bob_one_time_prekey = one_time_prekeys.output[0].clone();
    let route = RelayRoute::initial(
        1,
        bob_publication.discovery_key.verifying_key.to_bytes(),
        RelayPreKeyReference {
            signed_prekey_id: bob_publication.signed_prekey.id,
            one_time_prekey_id: Some(bob_one_time_prekey.id),
        },
    );

    let session_key = ProtocolStateKey::session(SessionId::from_bytes([0x22; 16]));
    let initial = alice
        .initiate_session_with_relay_route(
            SessionInitiation {
                session_key: session_key.clone(),
                responder_identity_key: bob_identity.output.identity_key_bundle().unwrap(),
                responder_discovery_to_identity: bob_publication.discovery_to_identity,
                responder_prekey_bundle: aether_crypto::PreKeyBundle {
                    version: bob_publication.version,
                    discovery_key: bob_publication.discovery_key,
                    signed_prekey: bob_publication.signed_prekey,
                    one_time_prekey: Some(bob_one_time_prekey),
                },
                sender_certificate: b"alice certificate",
                sender_signature: b"alice signature",
                plaintext: b"hello bob",
            },
            &route,
        )
        .unwrap();
    let replacement_signed_prekey = bob.prepare_rotate_signed_prekey_now().unwrap();
    assert_eq!(
        replacement_signed_prekey.output.id,
        route.prekey_reference().unwrap().signed_prekey_id + 1
    );
    finalize(&bob, &replacement_signed_prekey);
    let input = || SessionAcceptance {
        session_key: session_key.clone(),
        initiator_identity_key: Some(alice_identity.output.identity_key_bundle().unwrap()),
        message: &initial.message,
    };

    assert!(matches!(
        bob.prepare_accept_session(input()),
        Err(SessionEstablishmentError::SignedPreKey(
            SignedPreKeyError::NotFound
        ))
    ));
    let accepted = bob
        .prepare_accept_session_with_relay_route(input(), &route)
        .unwrap();
    let stale = bob
        .prepare_accept_session_with_relay_route(input(), &route)
        .unwrap();
    assert_eq!(&*accepted.output.plaintext, b"hello bob");

    let rerouted = RelayRoute::initial(
        2,
        *route.recipient_signing_key(),
        route.prekey_reference().unwrap(),
    );
    assert!(
        bob.prepare_accept_session_with_relay_route(
            SessionAcceptance {
                session_key: session_key.clone(),
                initiator_identity_key: Some(alice_identity.output.identity_key_bundle().unwrap()),
                message: &initial.message,
            },
            &rerouted
        )
        .is_err()
    );
    let selected_prekeys = route.prekey_reference().unwrap();
    let wrong_signed_prekey = RelayRoute::initial(
        1,
        *route.recipient_signing_key(),
        RelayPreKeyReference {
            signed_prekey_id: selected_prekeys.signed_prekey_id + 1,
            one_time_prekey_id: selected_prekeys.one_time_prekey_id,
        },
    );
    assert!(matches!(
        bob.prepare_accept_session_with_relay_route(input(), &wrong_signed_prekey),
        Err(SessionEstablishmentError::SignedPreKey(
            SignedPreKeyError::NotFound
        ))
    ));
    let wrong_one_time_prekey = RelayRoute::initial(
        1,
        *route.recipient_signing_key(),
        RelayPreKeyReference {
            signed_prekey_id: selected_prekeys.signed_prekey_id,
            one_time_prekey_id: selected_prekeys.one_time_prekey_id.map(|id| id + 1),
        },
    );
    assert!(matches!(
        bob.prepare_accept_session_with_relay_route(input(), &wrong_one_time_prekey),
        Err(SessionEstablishmentError::RelayRoute(
            RelayRouteError::PreKeyReferenceMismatch
        ))
    ));

    finalize(&bob, &accepted);
    assert!(matches!(
        bob.commit_operation(stale.operation.identifier),
        Err(KeyStoreError::Operation(
            KeyStoreOperationError::PreconditionChanged { .. }
        ))
    ));
    bob.abort_operation(stale.operation.identifier).unwrap();
    assert!(
        bob.prepare_accept_session_with_relay_route(input(), &route)
            .is_err()
    );
}
