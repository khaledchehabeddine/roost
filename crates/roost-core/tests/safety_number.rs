//! Exercises Safety Number derivation and out-of-band contact verification.

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use roost_core::{
    ContactDiscoveryKey, ContactIdentity, ContactSafetyNumberConfirmation, ContactStateChange,
    ContactTrustState, IdentityKey, ProtocolStateEngine, ProtocolStateError, ProtocolStateSnapshot,
    SafetyNumberError, derive_safety_number,
};
use roost_crypto::{generate_discovery_key, generate_key_pair, generate_signing_key_pair};

const CREATED_AT_SECS: u64 = 1_700_000_000;

struct Setup {
    local_identity: IdentityKey,
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
    let contact_discovery =
        generate_discovery_key(&mut rng, &contact_signing, 0, CREATED_AT_SECS).unwrap();
    let contact_rotated_discovery =
        generate_discovery_key(&mut rng, &contact_signing, 1, CREATED_AT_SECS + 60).unwrap();

    Setup {
        local_identity: IdentityKey {
            x25519_public_key: *local_key_pair.public.as_bytes(),
            ed25519_verifying_key: local_signing.verifying.to_bytes(),
        },
        contact_identity: IdentityKey {
            x25519_public_key: *contact_key_pair.public.as_bytes(),
            ed25519_verifying_key: contact_signing.verifying.to_bytes(),
        },
        contact_discovery: ContactDiscoveryKey::from(&contact_discovery.public()),
        contact_rotated_discovery: ContactDiscoveryKey::from(&contact_rotated_discovery.public()),
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

/// Pinned on purpose, unlike Roost's other derivations: people compare Safety Numbers across app
/// versions, so a change to the derivation or the display must fail here before it ships.
#[test]
fn safety_number_matches_expected_hash_and_display() {
    let bytes = |hex: &str| -> [u8; 32] { hex::decode(hex).unwrap().try_into().unwrap() };
    let first = IdentityKey {
        x25519_public_key: bytes(
            "cea8522b478dd6836e54235f6e425a69fd8a07e0113a6393390235298aa76207",
        ),
        ed25519_verifying_key: bytes(
            "734cce51a84fbd45336303ce2a3cb6d7cdcb6703d5eb80f1eacf42613487a8f0",
        ),
    };
    let second = IdentityKey {
        x25519_public_key: bytes(
            "3d4dafeef11bf354d5038ed7987cfcaa441845be52f1b8d14c4b4a4e2389f56b",
        ),
        ed25519_verifying_key: bytes(
            "b12661824d74f494a38a1dda9d0594e1f4cdd049af4f283d42145c82d9819142",
        ),
    };
    let number = derive_safety_number(first, second).unwrap();
    assert_eq!(
        number.raw_bytes,
        bytes("349f7fdde676ae10533bd755edcfebb10a8513ff988597e9c4979ddd9fad1cdd")
    );
    assert_eq!(
        number.grouped_decimal,
        "32361 23425 39384 52205 48501 64357 11666 54322 91485 22401 21720 41437"
    );
    assert_eq!(
        derive_safety_number(second, first).unwrap().raw_bytes,
        number.raw_bytes
    );
}

#[test]
fn safety_number_changes_with_each_identity_key_half() {
    let setup = setup();
    let mut rng = ChaCha20Rng::from_seed([0x5A; 32]);
    let other_x25519 = *generate_key_pair(&mut rng).public.as_bytes();
    let other_ed25519 = generate_signing_key_pair(&mut rng).verifying.to_bytes();
    let local = setup.local_identity;
    let contact = setup.contact_identity;
    let expected = derive_safety_number(local, contact).unwrap();

    for (first, second) in [
        (
            IdentityKey {
                x25519_public_key: other_x25519,
                ..local
            },
            contact,
        ),
        (
            IdentityKey {
                ed25519_verifying_key: other_ed25519,
                ..local
            },
            contact,
        ),
        (
            local,
            IdentityKey {
                x25519_public_key: other_x25519,
                ..contact
            },
        ),
        (
            local,
            IdentityKey {
                ed25519_verifying_key: other_ed25519,
                ..contact
            },
        ),
    ] {
        assert_ne!(derive_safety_number(first, second).unwrap(), expected);
    }
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
