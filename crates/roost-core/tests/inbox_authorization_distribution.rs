//! Tracks which contacts still hold a superseded inbox generation.
//!
//! After an inbox rotation every contact holds a stale delivery capability and must be re-supplied
//! in band — except a blocked one, who must never be. This exercises that bookkeeping through the
//! protocol-state engine.

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use roost_core::{
    ContactDiscoveryKey, ContactIdentity, ContactIdentityKey, ProtocolStateEngine,
    ProtocolStateSnapshot,
};
use roost_crypto::{generate_discovery_key, generate_key_pair, generate_signing_key_pair};

const CREATED_AT_SECS: u64 = 1_700_000_000;

fn peer_contact(seed: u8) -> ContactIdentity {
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let signing = generate_signing_key_pair(&mut rng);
    let agreement = generate_key_pair(&mut rng);
    let discovery = generate_discovery_key(&mut rng, &signing, 1, CREATED_AT_SECS);
    ContactIdentity {
        identity_key: ContactIdentityKey {
            x25519_public_key: *agreement.public.as_bytes(),
            ed25519_verifying_key: signing.verifying.to_bytes(),
        },
        discovery_key: ContactDiscoveryKey::from(&discovery.public()),
    }
}

struct Setup {
    engine: ProtocolStateEngine,
    snapshot: ProtocolStateSnapshot,
    alice: ContactIdentityKey,
    bob: ContactIdentityKey,
}

fn setup() -> Setup {
    let engine = ProtocolStateEngine::new();
    let mut snapshot = ProtocolStateSnapshot::new();
    let alice = peer_contact(31);
    let bob = peer_contact(32);
    for contact in [alice, bob] {
        snapshot
            .apply_all(
                engine
                    .record_contact(&snapshot, contact)
                    .unwrap()
                    .state_updates,
            )
            .unwrap();
    }
    Setup {
        engine,
        snapshot,
        alice: alice.identity_key,
        bob: bob.identity_key,
    }
}

#[test]
fn a_contact_needs_authorization_until_the_current_generation_is_delivered() {
    let mut setup = setup();

    let stale = setup
        .engine
        .contacts_needing_inbox_authorization(&setup.snapshot, 5, &[setup.alice])
        .unwrap();
    assert_eq!(stale, vec![setup.alice], "never delivered means stale");

    setup
        .snapshot
        .apply_all(
            setup
                .engine
                .record_inbox_authorization_delivered(&setup.snapshot, setup.alice, 5)
                .unwrap(),
        )
        .unwrap();

    assert!(
        setup
            .engine
            .contacts_needing_inbox_authorization(&setup.snapshot, 5, &[setup.alice])
            .unwrap()
            .is_empty()
    );
    // A later rotation makes them stale again.
    assert_eq!(
        setup
            .engine
            .contacts_needing_inbox_authorization(&setup.snapshot, 6, &[setup.alice])
            .unwrap(),
        vec![setup.alice]
    );
}

/// The whole point of rotating on a block is that the blocked contact does not receive the
/// replacement capability. Listing them for re-key would silently undo the block.
#[test]
fn a_blocked_contact_is_never_listed_for_re_key() {
    let mut setup = setup();
    setup
        .snapshot
        .apply_all(
            setup
                .engine
                .block_contact(&setup.snapshot, setup.bob)
                .unwrap()
                .state_updates,
        )
        .unwrap();

    let stale = setup
        .engine
        .contacts_needing_inbox_authorization(&setup.snapshot, 9, &[setup.alice, setup.bob])
        .unwrap();

    assert_eq!(stale, vec![setup.alice]);
    assert!(
        !stale.contains(&setup.bob),
        "a blocked contact must be skipped"
    );
}

#[test]
fn delivering_an_older_generation_does_not_move_the_record_backwards() {
    let mut setup = setup();
    setup
        .snapshot
        .apply_all(
            setup
                .engine
                .record_inbox_authorization_delivered(&setup.snapshot, setup.alice, 7)
                .unwrap(),
        )
        .unwrap();

    let updates = setup
        .engine
        .record_inbox_authorization_delivered(&setup.snapshot, setup.alice, 4)
        .unwrap();

    assert!(updates.is_empty());
    assert_eq!(
        setup
            .engine
            .delivered_inbox_authorization(&setup.snapshot, setup.alice)
            .unwrap(),
        Some(7)
    );
}
