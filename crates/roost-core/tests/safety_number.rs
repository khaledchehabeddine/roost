//! Exercises Safety Number derivation and out-of-band contact verification.

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use roost_core::{
    ContactDiscoveryKey, ContactIdentity, ContactSafetyNumberConfirmation, ContactStateChange,
    ContactTrustState, IdentityKey, ProtocolStateEngine, ProtocolStateError, ProtocolStateSnapshot,
    SafetyNumberError, derive_safety_number,
};
use roost_crypto::{generate_discovery_key, generate_key_pair, generate_signing_key_pair};

const CREATED_AT: u64 = 1_700_000_000;

struct Setup {
    local_identity: IdentityKey,
    local_discovery: ContactDiscoveryKey,
    local_rotated_discovery: ContactDiscoveryKey,
    contact_identity: IdentityKey,
    contact_discovery: ContactDiscoveryKey,
    contact_rotated_discovery: ContactDiscoveryKey,
}

fn setup() -> Setup {
    let mut rng = ChaCha20Rng::from_seed([0x19; 32]);
    let local_signing = generate_signing_key_pair(&mut rng);
    let local_key_pair = generate_key_pair(&mut rng);
    let contact_signing = generate_signing_key_pair(&mut rng);
    let contact_key_pair = generate_key_pair(&mut rng);
    let contact_discovery = generate_discovery_key(&mut rng, &contact_signing, 0, CREATED_AT);
    let contact_rotated_discovery =
        generate_discovery_key(&mut rng, &contact_signing, 1, CREATED_AT + 60);
    let local_discovery = generate_discovery_key(&mut rng, &local_signing, 0, CREATED_AT);
    let local_rotated_discovery =
        generate_discovery_key(&mut rng, &local_signing, 1, CREATED_AT + 60);

    Setup {
        local_identity: IdentityKey {
            x25519_public_key: *local_key_pair.public.as_bytes(),
            ed25519_verifying_key: local_signing.verifying.to_bytes(),
        },
        local_discovery: ContactDiscoveryKey::from(&local_discovery.bundle()),
        local_rotated_discovery: ContactDiscoveryKey::from(&local_rotated_discovery.bundle()),
        contact_identity: IdentityKey {
            x25519_public_key: *contact_key_pair.public.as_bytes(),
            ed25519_verifying_key: contact_signing.verifying.to_bytes(),
        },
        contact_discovery: ContactDiscoveryKey::from(&contact_discovery.bundle()),
        contact_rotated_discovery: ContactDiscoveryKey::from(&contact_rotated_discovery.bundle()),
    }
}

fn contact_identity(setup: &Setup) -> ContactIdentity {
    ContactIdentity {
        identity_key: setup.contact_identity,
        discovery_key: setup.contact_discovery,
    }
}

fn display_groups(value: &str) -> Vec<&str> {
    value.split(' ').collect()
}

fn matched_confirmation(confirmation: ContactSafetyNumberConfirmation) -> ContactStateChange {
    match confirmation {
        ContactSafetyNumberConfirmation::Matched(change) => change,
        ContactSafetyNumberConfirmation::Mismatched(_) => panic!("safety number did not match"),
    }
}

#[test]
fn safety_number_derivation_is_deterministic_and_order_independent() {
    let setup = setup();

    let first = derive_safety_number(setup.local_identity, setup.contact_identity).unwrap();
    let repeated = derive_safety_number(setup.local_identity, setup.contact_identity).unwrap();
    let reversed = derive_safety_number(setup.contact_identity, setup.local_identity).unwrap();

    assert_eq!(first, repeated);
    assert_eq!(first, reversed);
    assert_eq!(first.raw_bytes.len(), 32);
    assert_eq!(display_groups(&first.grouped_decimal).len(), 12);
    assert!(
        display_groups(&first.grouped_decimal)
            .iter()
            .all(|group| group.len() == 5 && group.chars().all(|ch| ch.is_ascii_digit()))
    );
}

#[test]
fn safety_number_derivation_agrees_across_independent_caller_views() {
    let setup = setup();
    let local_view = (setup.local_identity, setup.contact_identity);
    let contact_view = (setup.contact_identity, setup.local_identity);

    let local_number = derive_safety_number(local_view.0, local_view.1).unwrap();
    let contact_number = derive_safety_number(contact_view.0, contact_view.1).unwrap();

    assert_eq!(local_number, contact_number);
}

#[test]
fn safety_number_derivation_rejects_non_canonical_identity_key() {
    let setup = setup();
    let mut invalid = setup.contact_identity;
    invalid.x25519_public_key = [0xff; 32];

    assert_eq!(
        derive_safety_number(setup.local_identity, invalid),
        Err(SafetyNumberError::InvalidIdentityKey)
    );
}

#[test]
fn discovery_key_rotation_does_not_change_safety_number() {
    let setup = setup();
    let engine = ProtocolStateEngine::new();
    let mut snapshot = ProtocolStateSnapshot::new();
    let initial_number =
        derive_safety_number(setup.local_identity, setup.contact_identity).unwrap();
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
                .accept_contact(&snapshot, setup.contact_identity)
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
                        identity_key: setup.contact_identity,
                        discovery_key: setup.contact_rotated_discovery,
                    },
                )
                .unwrap()
                .state_updates,
        )
        .unwrap();

    let rotated_number =
        derive_safety_number(setup.local_identity, setup.contact_identity).unwrap();
    let contact = engine
        .contact_state(&snapshot, setup.contact_identity)
        .unwrap()
        .unwrap();
    assert_eq!(rotated_number, initial_number);
    assert_eq!(
        contact.identity.discovery_key,
        setup.contact_rotated_discovery
    );
    assert_eq!(contact.trust_state, ContactTrustState::Unverified);
}

#[test]
fn local_discovery_key_rotation_does_not_change_safety_number() {
    let setup = setup();
    let initial_number =
        derive_safety_number(setup.local_identity, setup.contact_identity).unwrap();

    assert_ne!(
        setup.local_discovery.prekey_bundle_lookup_key(),
        setup.local_rotated_discovery.prekey_bundle_lookup_key()
    );
    assert_eq!(
        derive_safety_number(setup.local_identity, setup.contact_identity).unwrap(),
        initial_number
    );
}

#[test]
fn out_of_band_confirmation_transitions_unverified_contact_to_verified() {
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
                .accept_contact(&snapshot, setup.contact_identity)
                .unwrap()
                .state_updates,
        )
        .unwrap();
    let safety_number = derive_safety_number(setup.local_identity, setup.contact_identity).unwrap();

    let change = matched_confirmation(
        engine
            .confirm_contact_safety_number(
                &snapshot,
                setup.local_identity,
                setup.contact_identity,
                &safety_number.grouped_decimal,
            )
            .unwrap(),
    );
    snapshot.apply_all(change.state_updates).unwrap();

    assert_eq!(change.contact.trust_state, ContactTrustState::Verified);
    assert_eq!(
        engine
            .contact_state(&snapshot, setup.contact_identity)
            .unwrap()
            .unwrap()
            .trust_state,
        ContactTrustState::Verified
    );
}

#[test]
fn pending_contact_cannot_be_raised_to_verified_by_safety_number() {
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
    let safety_number = derive_safety_number(setup.local_identity, setup.contact_identity).unwrap();

    assert!(matches!(
        engine.confirm_contact_safety_number(
            &snapshot,
            setup.local_identity,
            setup.contact_identity,
            &safety_number.grouped_decimal,
        ),
        Err(ProtocolStateError::InvalidStateBinding { .. })
    ));
}

#[test]
fn safety_number_mismatch_leaves_trust_state_unchanged() {
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
                .accept_contact(&snapshot, setup.contact_identity)
                .unwrap()
                .state_updates,
        )
        .unwrap();

    let confirmation = engine
        .confirm_contact_safety_number(
            &snapshot,
            setup.local_identity,
            setup.contact_identity,
            "00000 00000 00000 00000 00000 00000 00000 00000 00000 00000 00000 00000",
        )
        .unwrap();
    let ContactSafetyNumberConfirmation::Mismatched(change) = confirmation else {
        panic!("safety number mismatch was not explicit");
    };

    assert_eq!(change.contact.trust_state, ContactTrustState::Unverified);
    assert!(change.state_updates.is_empty());
    assert!(change.event.is_none());
    assert_eq!(
        engine
            .contact_state(&snapshot, setup.contact_identity)
            .unwrap()
            .unwrap()
            .trust_state,
        ContactTrustState::Unverified
    );
}

#[test]
fn safety_number_mismatch_on_verified_contact_is_explicit() {
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
                .accept_contact(&snapshot, setup.contact_identity)
                .unwrap()
                .state_updates,
        )
        .unwrap();
    let safety_number = derive_safety_number(setup.local_identity, setup.contact_identity).unwrap();
    let matched = matched_confirmation(
        engine
            .confirm_contact_safety_number(
                &snapshot,
                setup.local_identity,
                setup.contact_identity,
                &safety_number.grouped_decimal,
            )
            .unwrap(),
    );
    snapshot.apply_all(matched.state_updates).unwrap();

    let confirmation = engine
        .confirm_contact_safety_number(
            &snapshot,
            setup.local_identity,
            setup.contact_identity,
            "00000 00000 00000 00000 00000 00000 00000 00000 00000 00000 00000 00000",
        )
        .unwrap();
    let ContactSafetyNumberConfirmation::Mismatched(change) = confirmation else {
        panic!("verified contact mismatch was not explicit");
    };

    assert_eq!(change.contact.trust_state, ContactTrustState::Verified);
    assert!(change.state_updates.is_empty());
    assert!(change.event.is_none());
}
