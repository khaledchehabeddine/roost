//! Exercises IK-keyed Contact State protocol blobs and trust transitions.

mod support;

use roost_core::MessageOperationError;
use support::device::{Device, Relay};
use support::{ProtocolFixture, accepted_contact_identity};

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use roost_core::{
    ContactDiscoveryKey, ContactEvent, ContactIdentity, ContactIdentityKey, ContactTrustState,
    IdentityKey, ProtocolStateAddress, ProtocolStateBlob, ProtocolStateEngine, ProtocolStateError,
    ProtocolStateKind, ProtocolStateSnapshot, derive_safety_number,
};
use roost_crypto::{
    RecipientDeliveryCapability, generate_discovery_key, generate_key_pair,
    generate_signing_key_pair,
};

const CREATED_AT_SECS: u64 = 1_700_000_000;

struct Setup {
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
    let bob_discovery =
        generate_discovery_key(&mut rng, &bob_identity, 0, CREATED_AT_SECS).unwrap();
    let bob_rotated_discovery =
        generate_discovery_key(&mut rng, &bob_identity, 1, CREATED_AT_SECS + 60).unwrap();
    let bob_restored_discovery =
        generate_discovery_key(&mut rng, &bob_identity, 0, CREATED_AT_SECS + 120).unwrap();
    let alice_identity_key_pair = generate_key_pair(&mut rng);

    Setup {
        alice_identity: IdentityKey {
            x25519_public_key: *alice_identity_key_pair.public.as_bytes(),
            ed25519_verifying_key: alice_identity.verifying.to_bytes(),
        },
        bob_identity: ContactIdentityKey {
            x25519_public_key: *bob_identity_key_pair.public.as_bytes(),
            ed25519_verifying_key: bob_identity.verifying.to_bytes(),
        },
        bob_discovery: ContactDiscoveryKey::from(&bob_discovery.public()),
        bob_rotated_discovery: ContactDiscoveryKey::from(&bob_rotated_discovery.public()),
        bob_restored_discovery: ContactDiscoveryKey::from(&bob_restored_discovery.public()),
    }
}

fn contact_identity(setup: &Setup) -> ContactIdentity {
    ContactIdentity {
        identity_key: setup.bob_identity,
        discovery_key: setup.bob_discovery,
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
    snapshot.apply_all(change.state_updates).unwrap();

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
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let bob = Device::new(&relay, 0xb0);
    alice.initiate(&bob.bundle(), b"hello bob");
    let engine = *alice.store.protocol_engine();
    let recorded = engine
        .record_contact(&alice.host.snapshot(), bob.contact_identity())
        .unwrap();
    alice.host.commit(recorded.state_updates).unwrap();

    assert!(matches!(
        alice.encrypt(&bob, b"too early"),
        Err(MessageOperationError::ProtocolState(
            ProtocolStateError::ContactNotAccepted
        ))
    ));

    let accepted = engine
        .accept_contact(&alice.host.snapshot(), bob.identity_key())
        .unwrap();
    alice.host.commit(accepted.state_updates).unwrap();
    alice.send(&bob, b"accepted");
}

#[test]
fn accepted_contact_without_a_session_needs_a_handshake() {
    let relay = Relay::new();
    let mut alice = Device::new(&relay, 0xa1);
    let bob = Device::new(&relay, 0xb0);
    alice.accept_contact(&bob);
    let before = alice.host.clone();

    assert!(matches!(
        alice.encrypt(&bob, b"no session"),
        Err(MessageOperationError::ProtocolState(
            ProtocolStateError::NoSession
        ))
    ));
    assert_eq!(alice.host.snapshot_bytes(), before.snapshot_bytes());
}

#[test]
fn contact_can_be_blocked_and_unblocked_without_changing_pending_trust() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot
        .apply_all(
            engine
                .record_contact(&snapshot, contact_identity(&setup))
                .unwrap()
                .state_updates,
        )
        .unwrap();

    let blocked = engine.block_contact(&snapshot, setup.bob_identity).unwrap();
    snapshot.apply_all(blocked.state_updates).unwrap();
    let contact = engine
        .contact_state(&snapshot, setup.bob_identity)
        .unwrap()
        .unwrap();
    assert_eq!(contact.trust_state, ContactTrustState::Pending);
    assert!(contact.blocked);

    let unblocked = engine
        .unblock_contact(&snapshot, setup.bob_identity)
        .unwrap();
    snapshot.apply_all(unblocked.state_updates).unwrap();
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
    snapshot
        .apply_all(
            engine
                .record_contact(&snapshot, contact_identity(&setup))
                .unwrap()
                .state_updates,
        )
        .unwrap();
    snapshot
        .apply_all(
            engine
                .accept_contact(&snapshot, setup.bob_identity)
                .unwrap()
                .state_updates,
        )
        .unwrap();

    let blocked = engine.block_contact(&snapshot, setup.bob_identity).unwrap();
    snapshot.apply_all(blocked.state_updates).unwrap();
    let contact = engine
        .contact_state(&snapshot, setup.bob_identity)
        .unwrap()
        .unwrap();
    assert_eq!(contact.trust_state, ContactTrustState::Unverified);
    assert!(contact.blocked);

    let unblocked = engine
        .unblock_contact(&snapshot, setup.bob_identity)
        .unwrap();
    snapshot.apply_all(unblocked.state_updates).unwrap();
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
    snapshot
        .apply_all(
            engine
                .record_contact(&snapshot, contact_identity(&setup))
                .unwrap()
                .state_updates,
        )
        .unwrap();
    snapshot
        .apply_all(
            engine
                .accept_contact(&snapshot, setup.bob_identity)
                .unwrap()
                .state_updates,
        )
        .unwrap();
    snapshot
        .apply_all(
            confirm_safety_number(&engine, &snapshot, &setup)
                .unwrap()
                .state_updates,
        )
        .unwrap();

    let blocked = engine.block_contact(&snapshot, setup.bob_identity).unwrap();
    snapshot.apply_all(blocked.state_updates).unwrap();
    let contact = engine
        .contact_state(&snapshot, setup.bob_identity)
        .unwrap()
        .unwrap();
    assert_eq!(contact.trust_state, ContactTrustState::Verified);
    assert!(contact.blocked);

    let unblocked = engine
        .unblock_contact(&snapshot, setup.bob_identity)
        .unwrap();
    snapshot.apply_all(unblocked.state_updates).unwrap();
    let contact = engine
        .contact_state(&snapshot, setup.bob_identity)
        .unwrap()
        .unwrap();
    assert_eq!(contact.trust_state, ContactTrustState::Verified);
    assert!(!contact.blocked);
}

#[test]
fn blocked_accepted_contact_refuses_outgoing_user_message() {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0x71; 32]);
    let bob = accepted_contact_identity().identity_key;
    let blocked = engine
        .block_contact(&fixture.alice_store.snapshot(), bob)
        .unwrap();
    fixture.alice_store.commit(blocked.state_updates).unwrap();

    assert!(matches!(
        engine.encrypt_message_with_transport_binding(
            &mut ChaCha20Rng::from_seed([0x72; 32]),
            &fixture.alice_store.snapshot(),
            fixture.outbound(1, b"blocked"),
            &fixture.binding,
        ),
        Err(ProtocolStateError::BlockedContact)
    ));

    let unblocked = engine
        .unblock_contact(&fixture.alice_store.snapshot(), bob)
        .unwrap();
    fixture.alice_store.commit(unblocked.state_updates).unwrap();
    let sent = fixture.encrypt_from_alice(&engine, 2, b"unblocked");
    let received = fixture.decrypt_for_bob(&engine, &sent, 0x73);
    assert_eq!(received.plaintext.as_slice(), b"unblocked");
}

#[test]
fn acceptance_transitions_pending_to_unverified() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot
        .apply_all(
            engine
                .record_contact(&snapshot, contact_identity(&setup))
                .unwrap()
                .state_updates,
        )
        .unwrap();

    let change = engine
        .accept_contact(&snapshot, setup.bob_identity)
        .unwrap();
    snapshot.apply_all(change.state_updates).unwrap();

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
    snapshot
        .apply_all(
            engine
                .record_contact(&snapshot, contact_identity(&setup))
                .unwrap()
                .state_updates,
        )
        .unwrap();
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
    snapshot
        .apply_all(
            engine
                .record_contact(&snapshot, contact_identity(&setup))
                .unwrap()
                .state_updates,
        )
        .unwrap();
    snapshot
        .apply_all(
            engine
                .accept_contact(&snapshot, setup.bob_identity)
                .unwrap()
                .state_updates,
        )
        .unwrap();

    let change = engine
        .record_contact(
            &snapshot,
            ContactIdentity {
                identity_key: setup.bob_identity,
                discovery_key: setup.bob_rotated_discovery,
            },
        )
        .unwrap();
    snapshot.apply_all(change.state_updates).unwrap();

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
    snapshot
        .apply_all(
            engine
                .record_contact(&snapshot, contact_identity(&setup))
                .unwrap()
                .state_updates,
        )
        .unwrap();
    snapshot
        .apply_all(
            engine
                .accept_contact(&snapshot, setup.bob_identity)
                .unwrap()
                .state_updates,
        )
        .unwrap();
    snapshot
        .apply_all(
            engine
                .block_contact(&snapshot, setup.bob_identity)
                .unwrap()
                .state_updates,
        )
        .unwrap();

    let change = engine
        .record_contact(
            &snapshot,
            ContactIdentity {
                identity_key: setup.bob_identity,
                discovery_key: setup.bob_rotated_discovery,
            },
        )
        .unwrap();
    snapshot.apply_all(change.state_updates).unwrap();

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
    snapshot
        .apply_all(
            engine
                .record_contact(&snapshot, contact_identity(&setup))
                .unwrap()
                .state_updates,
        )
        .unwrap();
    snapshot
        .apply_all(
            engine
                .accept_contact(&snapshot, setup.bob_identity)
                .unwrap()
                .state_updates,
        )
        .unwrap();
    snapshot
        .apply_all(
            confirm_safety_number(&engine, &snapshot, &setup)
                .unwrap()
                .state_updates,
        )
        .unwrap();

    let change = engine
        .record_contact(
            &snapshot,
            ContactIdentity {
                identity_key: setup.bob_identity,
                discovery_key: setup.bob_rotated_discovery,
            },
        )
        .unwrap();
    snapshot.apply_all(change.state_updates).unwrap();

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
) -> Result<roost_core::ContactStateChange, ProtocolStateError> {
    let safety_number = derive_safety_number(setup.alice_identity, setup.bob_identity).unwrap();
    let confirmation = engine.confirm_contact_safety_number(
        snapshot,
        setup.alice_identity,
        setup.bob_identity,
        &safety_number.grouped_decimal,
    )?;
    match confirmation {
        roost_core::ContactSafetyNumberConfirmation::Matched(change) => Ok(change),
        roost_core::ContactSafetyNumberConfirmation::Mismatched(_) => {
            panic!("safety number did not match")
        }
    }
}

#[test]
fn later_discovery_key_creation_time_updates_even_with_lower_epoch() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot
        .apply_all(
            engine
                .record_contact(&snapshot, contact_identity(&setup))
                .unwrap()
                .state_updates,
        )
        .unwrap();
    snapshot
        .apply_all(
            engine
                .accept_contact(&snapshot, setup.bob_identity)
                .unwrap()
                .state_updates,
        )
        .unwrap();
    snapshot
        .apply_all(
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
        )
        .unwrap();

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
    snapshot.apply_all(change.state_updates).unwrap();

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
    snapshot
        .apply_all(
            engine
                .record_contact(&snapshot, contact_identity(&setup))
                .unwrap()
                .state_updates,
        )
        .unwrap();
    snapshot
        .apply_all(
            engine
                .accept_contact(&snapshot, setup.bob_identity)
                .unwrap()
                .state_updates,
        )
        .unwrap();
    snapshot
        .apply_all(
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
        )
        .unwrap();
    snapshot
        .apply_all(
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
        )
        .unwrap();

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
    snapshot
        .set(
            ProtocolStateAddress::new(ProtocolStateKind::ContactState, wrong_identity.into()),
            ProtocolStateBlob::from_bytes(blob.blob().unwrap().as_bytes().to_vec()),
        )
        .unwrap();

    assert!(matches!(
        engine.contact_state(&snapshot, wrong_identity),
        Err(ProtocolStateError::BlobDecode { .. })
    ));
}

#[test]
fn contact_lookup_rejects_corrupt_blobs_without_replacing_stored_state() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let mut snapshot = ProtocolStateSnapshot::new();
    let change = engine
        .record_contact(&snapshot, contact_identity(&setup))
        .unwrap();
    snapshot.apply_all(change.state_updates).unwrap();
    assert!(
        engine
            .contact_state(&snapshot, setup.bob_identity)
            .unwrap()
            .is_some()
    );

    let address =
        ProtocolStateAddress::new(ProtocolStateKind::ContactState, setup.bob_identity.into());
    let valid = snapshot.get(&address).unwrap().as_bytes().to_vec();
    let mut trailing = valid.clone();
    trailing.push(0xaa);
    let truncated = valid[..valid.len() / 2].to_vec();
    for corrupt in [trailing, truncated] {
        snapshot
            .set(
                address.clone(),
                ProtocolStateBlob::from_bytes(corrupt.clone()),
            )
            .unwrap();
        assert!(matches!(
            engine.contact_state(&snapshot, setup.bob_identity),
            Err(ProtocolStateError::BlobDecode { address: actual, .. }) if actual == address
        ));
        assert_eq!(snapshot.get(&address).unwrap().as_bytes(), corrupt);
    }
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

/// A peer's delivery capability is a bearer secret they handed us for submission.
/// It must survive a commit and read back exactly, since a wrong byte means the relay rejects
/// every submission to that contact.
#[test]
fn peer_inbox_authorization_round_trips_through_protocol_state() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot
        .apply_all(
            engine
                .record_contact(&snapshot, contact_identity(&setup))
                .unwrap()
                .state_updates,
        )
        .unwrap();
    let capability = RecipientDeliveryCapability::from_bytes([0x5Au8; 32]);

    snapshot
        .apply_all(
            engine
                .record_peer_inbox_authorization(&snapshot, setup.bob_identity, 4, &capability)
                .unwrap(),
        )
        .unwrap();

    let stored = engine
        .peer_inbox_authorization(&snapshot, setup.bob_identity)
        .unwrap()
        .unwrap();
    assert_eq!(stored.epoch, 4);
    assert_eq!(*stored.capability.to_bytes(), *capability.to_bytes());
}

#[test]
fn peer_inbox_authorization_is_absent_until_recorded() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot
        .apply_all(
            engine
                .record_contact(&snapshot, contact_identity(&setup))
                .unwrap()
                .state_updates,
        )
        .unwrap();

    assert!(
        engine
            .peer_inbox_authorization(&snapshot, setup.bob_identity)
            .unwrap()
            .is_none()
    );
}

/// Replaying an older inbox-authorization update must not roll a contact back to a capability
/// they have already rotated away from — which is exactly what a blocked sender would want.
#[test]
fn peer_inbox_authorization_refuses_to_go_backwards() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot
        .apply_all(
            engine
                .record_contact(&snapshot, contact_identity(&setup))
                .unwrap()
                .state_updates,
        )
        .unwrap();
    let current = RecipientDeliveryCapability::from_bytes([0x11u8; 32]);
    let superseded = RecipientDeliveryCapability::from_bytes([0x22u8; 32]);
    snapshot
        .apply_all(
            engine
                .record_peer_inbox_authorization(&snapshot, setup.bob_identity, 7, &current)
                .unwrap(),
        )
        .unwrap();

    let updates = engine
        .record_peer_inbox_authorization(&snapshot, setup.bob_identity, 6, &superseded)
        .unwrap();

    assert!(updates.is_empty(), "a lower epoch must produce no update");
    let stored = engine
        .peer_inbox_authorization(&snapshot, setup.bob_identity)
        .unwrap()
        .unwrap();
    assert_eq!(stored.epoch, 7);
    assert_eq!(*stored.capability.to_bytes(), *current.to_bytes());
}

#[test]
fn peer_inbox_authorization_advances_on_a_higher_epoch() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let mut snapshot = ProtocolStateSnapshot::new();
    snapshot
        .apply_all(
            engine
                .record_contact(&snapshot, contact_identity(&setup))
                .unwrap()
                .state_updates,
        )
        .unwrap();
    let first = RecipientDeliveryCapability::from_bytes([0x11u8; 32]);
    let rotated = RecipientDeliveryCapability::from_bytes([0x22u8; 32]);
    snapshot
        .apply_all(
            engine
                .record_peer_inbox_authorization(&snapshot, setup.bob_identity, 1, &first)
                .unwrap(),
        )
        .unwrap();

    snapshot
        .apply_all(
            engine
                .record_peer_inbox_authorization(&snapshot, setup.bob_identity, 2, &rotated)
                .unwrap(),
        )
        .unwrap();

    let stored = engine
        .peer_inbox_authorization(&snapshot, setup.bob_identity)
        .unwrap()
        .unwrap();
    assert_eq!(stored.epoch, 2);
    assert_eq!(*stored.capability.to_bytes(), *rotated.to_bytes());
}
