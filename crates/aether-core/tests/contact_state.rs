//! Exercises IK-keyed Contact State protocol blobs and trust transitions.

use aether_core::{
    ContactDiscoveryKey, ContactEvent, ContactIdentity, ContactIdentityKey, ContactTrustState,
    IdentityKey, MessageId, OutboundPlaintext, ProtocolStateAddress, ProtocolStateBlob,
    ProtocolStateEngine, ProtocolStateError, ProtocolStateKey, ProtocolStateKind,
    ProtocolStateSnapshot, SenderIdentityMaterial, SessionId, derive_safety_number,
};
use aether_crypto::{
    IdentityKeyBundle, InitialPlaintext, KeyPair, PreKeyBundle, RatchetState,
    RecipientDeliveryCapability, SigningKeyPair, accept, generate_discovery_key, generate_key_pair,
    generate_one_time_prekey, generate_signed_prekey_for_discovery_key, generate_signing_key_pair,
    initiate, sign_identity_key_binding,
};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

const CREATED_AT: u64 = 1_700_000_000;

struct Setup {
    alice_state: RatchetState,
    alice_identity: IdentityKey,
    bob_identity: ContactIdentityKey,
    bob_discovery: ContactDiscoveryKey,
    bob_rotated_discovery: ContactDiscoveryKey,
    bob_restored_discovery: ContactDiscoveryKey,
}

fn setup() -> Setup {
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let alice_identity = generate_signing_key_pair(&mut rng);
    let bob_identity = generate_signing_key_pair(&mut rng);
    let bob_identity_key_pair = generate_key_pair(&mut rng);
    let alice_identity_key = identity_key_bundle(&mut rng, &alice_identity);
    let bob_identity_key = identity_key_bundle(&mut rng, &bob_identity);
    let alice_discovery = generate_discovery_key(&mut rng, &alice_identity, 0, CREATED_AT);
    let bob_discovery = generate_discovery_key(&mut rng, &bob_identity, 0, CREATED_AT);
    let bob_signed_prekey =
        generate_signed_prekey_for_discovery_key(&mut rng, &bob_discovery, 0, CREATED_AT);
    let bob_one_time_prekey =
        generate_one_time_prekey(&mut rng, 9, bob_discovery.epoch(), CREATED_AT);
    let prekey_bundle = PreKeyBundle {
        version: aether_crypto::PREKEY_BUNDLE_VERSION,
        discovery_key: bob_discovery.bundle(),
        signed_prekey: bob_signed_prekey.bundle(),
        one_time_prekey: Some(bob_one_time_prekey.bundle()),
    };
    let (alice_state, envelope) = initiate(
        &mut rng,
        &alice_discovery,
        &alice_identity_key,
        &bob_identity_key,
        &prekey_bundle,
        InitialPlaintext {
            sender_certificate: b"sender certificate",
            sender_signature: b"sender signature",
            plaintext: b"initial",
        },
    )
    .unwrap();
    let _ = accept(
        &mut rng,
        &envelope,
        Some(&alice_identity_key),
        &bob_identity_key,
        &bob_discovery,
        &bob_signed_prekey,
        Some(bob_one_time_prekey),
    )
    .unwrap();
    let bob_rotated_discovery = generate_discovery_key(&mut rng, &bob_identity, 1, CREATED_AT + 60);
    let bob_restored_discovery =
        generate_discovery_key(&mut rng, &bob_identity, 0, CREATED_AT + 120);
    let alice_identity_key_pair = generate_key_pair(&mut rng);

    Setup {
        alice_state,
        alice_identity: IdentityKey {
            x25519_public_key: *alice_identity_key_pair.public.as_bytes(),
            ed25519_verifying_key: alice_identity.verifying.to_bytes(),
        },
        bob_identity: ContactIdentityKey {
            x25519_public_key: *bob_identity_key_pair.public.as_bytes(),
            ed25519_verifying_key: bob_identity.verifying.to_bytes(),
        },
        bob_discovery: ContactDiscoveryKey::from(&bob_discovery.bundle()),
        bob_rotated_discovery: ContactDiscoveryKey::from(&bob_rotated_discovery.bundle()),
        bob_restored_discovery: ContactDiscoveryKey::from(&bob_restored_discovery.bundle()),
    }
}

fn session_key() -> ProtocolStateKey {
    ProtocolStateKey::session(SessionId::from_bytes([9u8; 16]))
}

fn sender_identity() -> SenderIdentityMaterial {
    let signing_key = sender_identity_signing_key();
    let identity_key_pair = KeyPair::from_secret_bytes([0x34; 32]);
    let binding_signature =
        sign_identity_key_binding(signing_key, &identity_key_pair.public).unwrap();
    SenderIdentityMaterial {
        identity_key: *identity_key_pair.public.as_bytes(),
        identity_verifying_key: signing_key.verifying.to_bytes(),
        identity_binding_signature: binding_signature.to_bytes().to_vec(),
        certificate: vec![2, 3, 4],
        signature: vec![5; 64],
    }
}

fn sender_identity_signing_key() -> &'static SigningKeyPair {
    Box::leak(Box::new(SigningKeyPair::from_signing_bytes([1u8; 32])))
}

fn identity_key_bundle(rng: &mut ChaCha20Rng, signing_key: &SigningKeyPair) -> IdentityKeyBundle {
    let agreement_key = generate_key_pair(rng);
    let binding_signature = sign_identity_key_binding(signing_key, &agreement_key.public).unwrap();
    IdentityKeyBundle {
        public_key: agreement_key.public,
        verifying_key: signing_key.verifying,
        binding_signature,
    }
}

fn contact_identity(setup: &Setup) -> ContactIdentity {
    ContactIdentity {
        identity_key: setup.bob_identity,
        discovery_key: setup.bob_discovery,
    }
}

fn alternate_contact_identity() -> ContactIdentity {
    let mut rng = ChaCha20Rng::from_seed([0x31; 32]);
    let identity = generate_signing_key_pair(&mut rng);
    let identity_key_pair = generate_key_pair(&mut rng);
    let discovery_key = generate_discovery_key(&mut rng, &identity, 0, CREATED_AT);
    ContactIdentity {
        identity_key: ContactIdentityKey {
            x25519_public_key: *identity_key_pair.public.as_bytes(),
            ed25519_verifying_key: identity.verifying.to_bytes(),
        },
        discovery_key: ContactDiscoveryKey::from(&discovery_key.bundle()),
    }
}

fn snapshot_with_session(engine: &ProtocolStateEngine, setup: &Setup) -> ProtocolStateSnapshot {
    let key = session_key();
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot.apply(
        engine
            .set_session_state(key.clone(), &setup.alice_state)
            .unwrap(),
    );
    snapshot.apply(engine.initialize_pending_acknowledgments(key).unwrap());
    snapshot
}

fn outbound<'a>(
    setup: &Setup,
    sender_identity: &'a SenderIdentityMaterial,
) -> OutboundPlaintext<'a> {
    OutboundPlaintext {
        id: MessageId::from_bytes([1u8; 16]),
        sender_identity,
        sender_identity_signing_key: sender_identity_signing_key(),
        contact_identity_key: setup.bob_identity,
        recipient_public_key: setup.bob_discovery.prekey_bundle_lookup_key(),
        timestamp_millis: 1_700_000_000_123,
        plaintext: b"hello contact",
    }
}

#[test]
fn new_contact_starts_pending_and_is_exposed_in_current_state() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let mut snapshot = ProtocolStateSnapshot::new();

    let change = engine
        .record_contact(&snapshot, contact_identity(&setup))
        .unwrap();
    snapshot.apply_all(change.state_updates);

    let contact = engine
        .contact_state(&snapshot, setup.bob_identity)
        .unwrap()
        .unwrap();
    assert_eq!(contact.trust_state, ContactTrustState::Pending);
    assert_eq!(contact.identity.identity_key, setup.bob_identity);
    assert_eq!(contact.identity.discovery_key, setup.bob_discovery);
    assert_eq!(
        engine.contact_states(&snapshot).unwrap(),
        vec![contact.clone()]
    );
    assert_eq!(
        change.event,
        Some(ContactEvent::Changed {
            contact: change.contact
        })
    );
}

#[test]
fn pending_contact_refuses_outgoing_user_message_until_accepted() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let sender = sender_identity();
    let mut snapshot = snapshot_with_session(&engine, &setup);
    let change = engine
        .record_contact(&snapshot, contact_identity(&setup))
        .unwrap();
    snapshot.apply_all(change.state_updates);

    assert!(matches!(
        engine.encrypt_message(&snapshot, session_key(), outbound(&setup, &sender)),
        Err(ProtocolStateError::InvalidStateBinding { .. })
    ));

    let accepted = engine
        .accept_contact(&snapshot, setup.bob_identity)
        .unwrap();
    snapshot.apply_all(accepted.state_updates);

    assert!(
        engine
            .encrypt_message(&snapshot, session_key(), outbound(&setup, &sender))
            .is_ok()
    );
}

#[test]
fn contact_can_be_blocked_and_unblocked_without_changing_pending_trust() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot.apply_all(
        engine
            .record_contact(&snapshot, contact_identity(&setup))
            .unwrap()
            .state_updates,
    );

    let blocked = engine.block_contact(&snapshot, setup.bob_identity).unwrap();
    snapshot.apply_all(blocked.state_updates);
    let contact = engine
        .contact_state(&snapshot, setup.bob_identity)
        .unwrap()
        .unwrap();
    assert_eq!(contact.trust_state, ContactTrustState::Pending);
    assert!(contact.blocked);

    let unblocked = engine
        .unblock_contact(&snapshot, setup.bob_identity)
        .unwrap();
    snapshot.apply_all(unblocked.state_updates);
    let contact = engine
        .contact_state(&snapshot, setup.bob_identity)
        .unwrap()
        .unwrap();
    assert_eq!(contact.trust_state, ContactTrustState::Pending);
    assert!(!contact.blocked);
}

#[test]
fn contact_can_be_blocked_and_unblocked_without_changing_unverified_trust() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot.apply_all(
        engine
            .record_contact(&snapshot, contact_identity(&setup))
            .unwrap()
            .state_updates,
    );
    snapshot.apply_all(
        engine
            .accept_contact(&snapshot, setup.bob_identity)
            .unwrap()
            .state_updates,
    );

    let blocked = engine.block_contact(&snapshot, setup.bob_identity).unwrap();
    snapshot.apply_all(blocked.state_updates);
    let contact = engine
        .contact_state(&snapshot, setup.bob_identity)
        .unwrap()
        .unwrap();
    assert_eq!(contact.trust_state, ContactTrustState::Unverified);
    assert!(contact.blocked);

    let unblocked = engine
        .unblock_contact(&snapshot, setup.bob_identity)
        .unwrap();
    snapshot.apply_all(unblocked.state_updates);
    let contact = engine
        .contact_state(&snapshot, setup.bob_identity)
        .unwrap()
        .unwrap();
    assert_eq!(contact.trust_state, ContactTrustState::Unverified);
    assert!(!contact.blocked);
}

#[test]
fn contact_can_be_blocked_and_unblocked_without_changing_verified_trust() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot.apply_all(
        engine
            .record_contact(&snapshot, contact_identity(&setup))
            .unwrap()
            .state_updates,
    );
    snapshot.apply_all(
        engine
            .accept_contact(&snapshot, setup.bob_identity)
            .unwrap()
            .state_updates,
    );
    snapshot.apply_all(
        confirm_safety_number(&engine, &snapshot, &setup)
            .unwrap()
            .state_updates,
    );

    let blocked = engine.block_contact(&snapshot, setup.bob_identity).unwrap();
    snapshot.apply_all(blocked.state_updates);
    let contact = engine
        .contact_state(&snapshot, setup.bob_identity)
        .unwrap()
        .unwrap();
    assert_eq!(contact.trust_state, ContactTrustState::Verified);
    assert!(contact.blocked);

    let unblocked = engine
        .unblock_contact(&snapshot, setup.bob_identity)
        .unwrap();
    snapshot.apply_all(unblocked.state_updates);
    let contact = engine
        .contact_state(&snapshot, setup.bob_identity)
        .unwrap()
        .unwrap();
    assert_eq!(contact.trust_state, ContactTrustState::Verified);
    assert!(!contact.blocked);
}

#[test]
fn blocked_accepted_contact_refuses_outgoing_user_message() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let sender = sender_identity();
    let mut snapshot = snapshot_with_session(&engine, &setup);
    snapshot.apply_all(
        engine
            .record_contact(&snapshot, contact_identity(&setup))
            .unwrap()
            .state_updates,
    );
    snapshot.apply_all(
        engine
            .accept_contact(&snapshot, setup.bob_identity)
            .unwrap()
            .state_updates,
    );
    snapshot.apply_all(
        engine
            .block_contact(&snapshot, setup.bob_identity)
            .unwrap()
            .state_updates,
    );

    assert!(matches!(
        engine.encrypt_message(&snapshot, session_key(), outbound(&setup, &sender)),
        Err(ProtocolStateError::InvalidStateBinding { .. })
    ));

    snapshot.apply_all(
        engine
            .unblock_contact(&snapshot, setup.bob_identity)
            .unwrap()
            .state_updates,
    );
    assert!(
        engine
            .encrypt_message(&snapshot, session_key(), outbound(&setup, &sender))
            .is_ok()
    );
}

#[test]
fn accepted_contact_refuses_outgoing_message_for_stale_recipient_key() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let sender = sender_identity();
    let mut snapshot = snapshot_with_session(&engine, &setup);
    snapshot.apply_all(
        engine
            .record_contact(&snapshot, contact_identity(&setup))
            .unwrap()
            .state_updates,
    );
    snapshot.apply_all(
        engine
            .accept_contact(&snapshot, setup.bob_identity)
            .unwrap()
            .state_updates,
    );
    let mut plaintext = outbound(&setup, &sender);
    plaintext.recipient_public_key = setup.bob_rotated_discovery.prekey_bundle_lookup_key();

    assert!(matches!(
        engine.encrypt_message(&snapshot, session_key(), plaintext),
        Err(ProtocolStateError::InvalidStateBinding { .. })
    ));
}

#[test]
fn outbound_message_binds_session_to_one_contact_identity() {
    let setup = setup();
    let other_contact = alternate_contact_identity();
    let engine = ProtocolStateEngine::new();
    let sender = sender_identity();
    let mut snapshot = snapshot_with_session(&engine, &setup);
    snapshot.apply_all(
        engine
            .record_contact(&snapshot, contact_identity(&setup))
            .unwrap()
            .state_updates,
    );
    snapshot.apply_all(
        engine
            .accept_contact(&snapshot, setup.bob_identity)
            .unwrap()
            .state_updates,
    );
    let first_send = engine
        .encrypt_message(&snapshot, session_key(), outbound(&setup, &sender))
        .unwrap();
    snapshot.apply_all(first_send.state_updates);
    snapshot.apply_all(
        engine
            .record_contact(&snapshot, other_contact)
            .unwrap()
            .state_updates,
    );
    snapshot.apply_all(
        engine
            .accept_contact(&snapshot, other_contact.identity_key)
            .unwrap()
            .state_updates,
    );
    let mut plaintext = outbound(&setup, &sender);
    plaintext.contact_identity_key = other_contact.identity_key;
    plaintext.recipient_public_key = other_contact.discovery_key.prekey_bundle_lookup_key();

    assert!(matches!(
        engine.encrypt_message(&snapshot, session_key(), plaintext),
        Err(ProtocolStateError::InvalidStateBinding { .. })
    ));
}

#[test]
fn acceptance_transitions_pending_to_unverified() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot.apply_all(
        engine
            .record_contact(&snapshot, contact_identity(&setup))
            .unwrap()
            .state_updates,
    );

    let change = engine
        .accept_contact(&snapshot, setup.bob_identity)
        .unwrap();
    snapshot.apply_all(change.state_updates);

    assert_eq!(change.contact.trust_state, ContactTrustState::Unverified);
    assert_eq!(
        engine
            .contact_state(&snapshot, setup.bob_identity)
            .unwrap()
            .unwrap()
            .trust_state,
        ContactTrustState::Unverified
    );
}

#[test]
fn pending_contact_cannot_be_verified_by_safety_number() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot.apply_all(
        engine
            .record_contact(&snapshot, contact_identity(&setup))
            .unwrap()
            .state_updates,
    );
    let safety_number = derive_safety_number(setup.alice_identity, setup.bob_identity).unwrap();

    assert!(matches!(
        engine.confirm_contact_safety_number(
            &snapshot,
            setup.alice_identity,
            setup.bob_identity,
            &safety_number.grouped_decimal,
        ),
        Err(ProtocolStateError::InvalidStateBinding { .. })
    ));
}

#[test]
fn discovery_key_update_preserves_unverified_state() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot.apply_all(
        engine
            .record_contact(&snapshot, contact_identity(&setup))
            .unwrap()
            .state_updates,
    );
    snapshot.apply_all(
        engine
            .accept_contact(&snapshot, setup.bob_identity)
            .unwrap()
            .state_updates,
    );

    let change = engine
        .record_contact(
            &snapshot,
            ContactIdentity {
                identity_key: setup.bob_identity,
                discovery_key: setup.bob_rotated_discovery,
            },
        )
        .unwrap();
    snapshot.apply_all(change.state_updates);

    let contact = engine
        .contact_state(&snapshot, setup.bob_identity)
        .unwrap()
        .unwrap();
    assert_eq!(contact.trust_state, ContactTrustState::Unverified);
    assert_eq!(contact.identity.discovery_key, setup.bob_rotated_discovery);
}

#[test]
fn discovery_key_update_preserves_blocking_state() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot.apply_all(
        engine
            .record_contact(&snapshot, contact_identity(&setup))
            .unwrap()
            .state_updates,
    );
    snapshot.apply_all(
        engine
            .accept_contact(&snapshot, setup.bob_identity)
            .unwrap()
            .state_updates,
    );
    snapshot.apply_all(
        engine
            .block_contact(&snapshot, setup.bob_identity)
            .unwrap()
            .state_updates,
    );

    let change = engine
        .record_contact(
            &snapshot,
            ContactIdentity {
                identity_key: setup.bob_identity,
                discovery_key: setup.bob_rotated_discovery,
            },
        )
        .unwrap();
    snapshot.apply_all(change.state_updates);

    let contact = engine
        .contact_state(&snapshot, setup.bob_identity)
        .unwrap()
        .unwrap();
    assert_eq!(contact.trust_state, ContactTrustState::Unverified);
    assert_eq!(contact.identity.discovery_key, setup.bob_rotated_discovery);
    assert!(contact.blocked);
}

#[test]
fn discovery_key_update_preserves_verified_state() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot.apply_all(
        engine
            .record_contact(&snapshot, contact_identity(&setup))
            .unwrap()
            .state_updates,
    );
    snapshot.apply_all(
        engine
            .accept_contact(&snapshot, setup.bob_identity)
            .unwrap()
            .state_updates,
    );
    snapshot.apply_all(
        confirm_safety_number(&engine, &snapshot, &setup)
            .unwrap()
            .state_updates,
    );

    let change = engine
        .record_contact(
            &snapshot,
            ContactIdentity {
                identity_key: setup.bob_identity,
                discovery_key: setup.bob_rotated_discovery,
            },
        )
        .unwrap();
    snapshot.apply_all(change.state_updates);

    let contact = engine
        .contact_state(&snapshot, setup.bob_identity)
        .unwrap()
        .unwrap();
    assert_eq!(contact.trust_state, ContactTrustState::Verified);
    assert_eq!(contact.identity.discovery_key, setup.bob_rotated_discovery);
}

fn confirm_safety_number(
    engine: &ProtocolStateEngine,
    snapshot: &ProtocolStateSnapshot,
    setup: &Setup,
) -> Result<aether_core::ContactStateChange, ProtocolStateError> {
    let safety_number = derive_safety_number(setup.alice_identity, setup.bob_identity).unwrap();
    let confirmation = engine.confirm_contact_safety_number(
        snapshot,
        setup.alice_identity,
        setup.bob_identity,
        &safety_number.grouped_decimal,
    )?;
    match confirmation {
        aether_core::ContactSafetyNumberConfirmation::Matched(change) => Ok(change),
        aether_core::ContactSafetyNumberConfirmation::Mismatched(_) => {
            panic!("safety number did not match")
        }
    }
}

#[test]
fn later_discovery_key_creation_time_updates_even_with_lower_epoch() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot.apply_all(
        engine
            .record_contact(&snapshot, contact_identity(&setup))
            .unwrap()
            .state_updates,
    );
    snapshot.apply_all(
        engine
            .accept_contact(&snapshot, setup.bob_identity)
            .unwrap()
            .state_updates,
    );
    snapshot.apply_all(
        engine
            .record_contact(
                &snapshot,
                ContactIdentity {
                    identity_key: setup.bob_identity,
                    discovery_key: setup.bob_rotated_discovery,
                },
            )
            .unwrap()
            .state_updates,
    );

    let change = engine
        .record_contact(
            &snapshot,
            ContactIdentity {
                identity_key: setup.bob_identity,
                discovery_key: setup.bob_restored_discovery,
            },
        )
        .unwrap();
    assert_eq!(change.state_updates.len(), 1);
    snapshot.apply_all(change.state_updates);

    let contact = engine
        .contact_state(&snapshot, setup.bob_identity)
        .unwrap()
        .unwrap();
    assert_eq!(contact.trust_state, ContactTrustState::Unverified);
    assert_eq!(contact.identity.discovery_key, setup.bob_restored_discovery);
}

#[test]
fn older_discovery_key_is_not_restored_by_higher_epoch_replay() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot.apply_all(
        engine
            .record_contact(&snapshot, contact_identity(&setup))
            .unwrap()
            .state_updates,
    );
    snapshot.apply_all(
        engine
            .accept_contact(&snapshot, setup.bob_identity)
            .unwrap()
            .state_updates,
    );
    snapshot.apply_all(
        engine
            .record_contact(
                &snapshot,
                ContactIdentity {
                    identity_key: setup.bob_identity,
                    discovery_key: setup.bob_rotated_discovery,
                },
            )
            .unwrap()
            .state_updates,
    );
    snapshot.apply_all(
        engine
            .record_contact(
                &snapshot,
                ContactIdentity {
                    identity_key: setup.bob_identity,
                    discovery_key: setup.bob_restored_discovery,
                },
            )
            .unwrap()
            .state_updates,
    );

    let replay = engine
        .record_contact(
            &snapshot,
            ContactIdentity {
                identity_key: setup.bob_identity,
                discovery_key: setup.bob_rotated_discovery,
            },
        )
        .unwrap();
    assert!(replay.state_updates.is_empty());

    let contact = engine
        .contact_state(&snapshot, setup.bob_identity)
        .unwrap()
        .unwrap();
    assert_eq!(contact.identity.discovery_key, setup.bob_restored_discovery);
}

#[test]
fn contact_lookup_rejects_blob_whose_identity_key_mismatches_address() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let mut snapshot = ProtocolStateSnapshot::new();
    let change = engine
        .record_contact(&snapshot, contact_identity(&setup))
        .unwrap();
    let blob = change.state_updates.into_iter().next().unwrap();
    let mut wrong_identity = setup.bob_identity;
    wrong_identity.x25519_public_key[0] ^= 0x01;
    snapshot.set(
        ProtocolStateAddress::new(ProtocolStateKind::ContactState, wrong_identity.into()),
        ProtocolStateBlob::from_bytes(blob.blob().unwrap().as_bytes().to_vec()),
    );

    assert!(matches!(
        engine.contact_state(&snapshot, wrong_identity),
        Err(ProtocolStateError::BlobDecode { .. })
    ));
}

#[test]
fn contact_inputs_reject_non_canonical_identity_and_discovery_keys() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let mut bad_identity = contact_identity(&setup);
    bad_identity.identity_key.x25519_public_key = [0xff; 32];
    assert!(matches!(
        engine.record_contact(&ProtocolStateSnapshot::new(), bad_identity),
        Err(ProtocolStateError::InvalidStateBinding { .. })
    ));

    let mut bad_discovery = contact_identity(&setup);
    bad_discovery.discovery_key.x25519_public_key = [0xff; 32];
    assert!(matches!(
        engine.record_contact(&ProtocolStateSnapshot::new(), bad_discovery),
        Err(ProtocolStateError::InvalidStateBinding { .. })
    ));
}

#[test]
fn contact_input_rejects_invalid_discovery_key_signature() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let mut identity = contact_identity(&setup);
    identity.discovery_key.identity_signature[0] ^= 0x01;

    assert!(matches!(
        engine.record_contact(&ProtocolStateSnapshot::new(), identity),
        Err(ProtocolStateError::InvalidStateBinding { .. })
    ));
}

/// A peer's delivery capability is a bearer secret they handed us for submission (AE-CON-05).
/// It must survive a commit and read back exactly, since a wrong byte means the relay rejects
/// every submission to that contact.
#[test]
fn peer_inbox_authorization_round_trips_through_protocol_state() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot.apply_all(
        engine
            .record_contact(&snapshot, contact_identity(&setup))
            .unwrap()
            .state_updates,
    );
    let capability = RecipientDeliveryCapability::from_bytes([0x5Au8; 32]);

    snapshot.apply_all(
        engine
            .record_peer_inbox_authorization(&snapshot, setup.bob_identity, 4, &capability)
            .unwrap(),
    );

    let stored = engine
        .peer_inbox_authorization(&snapshot, setup.bob_identity)
        .unwrap()
        .unwrap();
    assert_eq!(stored.generation, 4);
    assert_eq!(*stored.capability.to_bytes(), *capability.to_bytes());
}

#[test]
fn peer_inbox_authorization_is_absent_until_recorded() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot.apply_all(
        engine
            .record_contact(&snapshot, contact_identity(&setup))
            .unwrap()
            .state_updates,
    );

    assert!(
        engine
            .peer_inbox_authorization(&snapshot, setup.bob_identity)
            .unwrap()
            .is_none()
    );
}

/// Replaying an older inbox-authorization update must not roll a contact back to a capability
/// they have already rotated away from — which is exactly what a blocked sender would want
/// (AE-BLK-08).
#[test]
fn peer_inbox_authorization_refuses_to_go_backwards() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot.apply_all(
        engine
            .record_contact(&snapshot, contact_identity(&setup))
            .unwrap()
            .state_updates,
    );
    let current = RecipientDeliveryCapability::from_bytes([0x11u8; 32]);
    let superseded = RecipientDeliveryCapability::from_bytes([0x22u8; 32]);
    snapshot.apply_all(
        engine
            .record_peer_inbox_authorization(&snapshot, setup.bob_identity, 7, &current)
            .unwrap(),
    );

    let updates = engine
        .record_peer_inbox_authorization(&snapshot, setup.bob_identity, 6, &superseded)
        .unwrap();

    assert!(
        updates.is_empty(),
        "a lower generation must produce no update"
    );
    let stored = engine
        .peer_inbox_authorization(&snapshot, setup.bob_identity)
        .unwrap()
        .unwrap();
    assert_eq!(stored.generation, 7);
    assert_eq!(*stored.capability.to_bytes(), *current.to_bytes());
}

#[test]
fn peer_inbox_authorization_advances_on_a_higher_generation() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot.apply_all(
        engine
            .record_contact(&snapshot, contact_identity(&setup))
            .unwrap()
            .state_updates,
    );
    let first = RecipientDeliveryCapability::from_bytes([0x11u8; 32]);
    let rotated = RecipientDeliveryCapability::from_bytes([0x22u8; 32]);
    snapshot.apply_all(
        engine
            .record_peer_inbox_authorization(&snapshot, setup.bob_identity, 1, &first)
            .unwrap(),
    );

    snapshot.apply_all(
        engine
            .record_peer_inbox_authorization(&snapshot, setup.bob_identity, 2, &rotated)
            .unwrap(),
    );

    let stored = engine
        .peer_inbox_authorization(&snapshot, setup.bob_identity)
        .unwrap()
        .unwrap();
    assert_eq!(stored.generation, 2);
    assert_eq!(*stored.capability.to_bytes(), *rotated.to_bytes());
}
