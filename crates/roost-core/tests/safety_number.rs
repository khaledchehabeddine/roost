//! Exercises Safety Number derivation.

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use roost_core::{IdentityKey, SafetyNumberError, derive_safety_number};
use roost_crypto::{generate_key_pair, generate_signing_key_pair};

struct Setup {
    local_identity: IdentityKey,
    contact_identity: IdentityKey,
}

fn setup() -> Setup {
    let mut rng = ChaCha20Rng::from_seed([0x19; 32]);
    let local_signing = generate_signing_key_pair(&mut rng).unwrap();
    let local_key_pair = generate_key_pair(&mut rng).unwrap();
    let contact_signing = generate_signing_key_pair(&mut rng).unwrap();
    let contact_key_pair = generate_key_pair(&mut rng).unwrap();

    Setup {
        local_identity: IdentityKey {
            x25519_public_key: *local_key_pair.public.as_bytes(),
            ed25519_verifying_key: local_signing.verifying.to_bytes(),
        },
        contact_identity: IdentityKey {
            x25519_public_key: *contact_key_pair.public.as_bytes(),
            ed25519_verifying_key: contact_signing.verifying.to_bytes(),
        },
    }
}

fn display_groups(value: &str) -> Vec<&str> {
    value.split(' ').collect()
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
        bytes("11ec6a72d8289a704f13391812abedf2d580658ddb0a045f6e255ab29b584c0e")
    );
    assert_eq!(
        number.grouped_decimal,
        "37847 72638 08075 94309 68303 47906 65306 81346 83769 30836 34772 40846"
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
    let other_x25519 = *generate_key_pair(&mut rng).unwrap().public.as_bytes();
    let other_ed25519 = generate_signing_key_pair(&mut rng)
        .unwrap()
        .verifying
        .to_bytes();
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
