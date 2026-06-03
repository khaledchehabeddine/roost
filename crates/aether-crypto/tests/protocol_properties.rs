//! Property tests for handshake and Double Ratchet protocol invariants.

use aether_crypto::{
    DiscoveryKey, HandshakeEnvelope, OneTimePreKey, PreKeyBundle, RatchetState, SignedPreKey,
    SigningKeyPair, accept, generate_discovery_key, generate_one_time_prekey,
    generate_signed_prekey_for_discovery_key, generate_signing_key_pair, initial_associated_data,
    initiate,
};
use proptest::prelude::*;
use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

const CREATED_AT: u64 = 1_700_000_000;
const SKIPPED_KEY_CAP: usize = 500;

struct Setup {
    alice_identity: SigningKeyPair,
    alice_discovery_key: DiscoveryKey,
    bob_identity: SigningKeyPair,
    bob_discovery_key: DiscoveryKey,
    bob_signed_prekey: SignedPreKey,
    bob_one_time_prekey: Option<OneTimePreKey>,
}

fn setup(seed: [u8; 32]) -> (Setup, ChaCha20Rng) {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let alice_identity = generate_signing_key_pair(&mut rng);
    let alice_discovery_key = generate_discovery_key(&mut rng, &alice_identity, 1, CREATED_AT);
    let bob_identity = generate_signing_key_pair(&mut rng);
    let bob_discovery_key = generate_discovery_key(&mut rng, &bob_identity, 2, CREATED_AT);
    let bob_signed_prekey =
        generate_signed_prekey_for_discovery_key(&mut rng, &bob_discovery_key, CREATED_AT);
    let bob_one_time_prekey =
        generate_one_time_prekey(&mut rng, 7, bob_discovery_key.epoch(), CREATED_AT);
    (
        Setup {
            alice_identity,
            alice_discovery_key,
            bob_identity,
            bob_discovery_key,
            bob_signed_prekey,
            bob_one_time_prekey: Some(bob_one_time_prekey),
        },
        rng,
    )
}

fn bootstrap(
    setup: &mut Setup,
    rng: &mut ChaCha20Rng,
    include_one_time_prekey: bool,
    plaintext: &[u8],
) -> (RatchetState, RatchetState, HandshakeEnvelope) {
    let one_time_prekey_bundle =
        include_one_time_prekey.then(|| setup.bob_one_time_prekey.as_ref().unwrap().bundle());
    let prekey_bundle = PreKeyBundle {
        discovery_key: setup.bob_discovery_key.bundle(),
        signed_prekey: setup.bob_signed_prekey.bundle(),
        one_time_prekey: one_time_prekey_bundle,
    };
    let (alice, envelope) = initiate(
        rng,
        &setup.alice_discovery_key,
        &setup.bob_identity.verifying,
        &prekey_bundle,
        plaintext,
    )
    .unwrap();
    let bob_one_time_prekey =
        include_one_time_prekey.then(|| setup.bob_one_time_prekey.take().unwrap());
    let (bob, decrypted) = accept(
        rng,
        &envelope,
        &setup.alice_identity.verifying,
        &setup.alice_discovery_key.bundle(),
        &setup.bob_discovery_key,
        &setup.bob_signed_prekey,
        bob_one_time_prekey,
    )
    .unwrap();
    assert_eq!(decrypted.as_slice(), plaintext);
    (alice, bob, envelope)
}

fn associated_data(setup: &Setup) -> [u8; 68] {
    initial_associated_data(
        setup.alice_discovery_key.public_key(),
        setup.bob_discovery_key.public_key(),
        setup.bob_discovery_key.epoch(),
    )
}

fn runner(seed: [u8; 32], cases: u32) -> TestRunner {
    let config = Config {
        cases,
        failure_persistence: None,
        ..Config::default()
    };
    TestRunner::new_with_rng(config, TestRng::from_seed(RngAlgorithm::ChaCha, &seed))
}

#[test]
fn handshake_commutativity_property() {
    let strategy = (
        any::<[u8; 32]>(),
        any::<bool>(),
        proptest::collection::vec(any::<u8>(), 0..64),
    );
    runner([0xA1u8; 32], 32)
        .run(&strategy, |(seed, include_one_time_prekey, plaintext)| {
            let (mut setup, mut rng) = setup(seed);
            let associated_data = associated_data(&setup);
            let (mut alice, mut bob, _) =
                bootstrap(&mut setup, &mut rng, include_one_time_prekey, &plaintext);

            let (bob_header, bob_ciphertext) = bob
                .ratchet_encrypt(b"bob proves root", &associated_data)
                .unwrap();
            let alice_plaintext = alice
                .ratchet_decrypt(&mut rng, &bob_ciphertext, &bob_header, &associated_data)
                .unwrap();
            prop_assert_eq!(alice_plaintext.as_slice(), b"bob proves root");

            let (alice_header, alice_ciphertext) = alice
                .ratchet_encrypt(b"alice proves root", &associated_data)
                .unwrap();
            let bob_plaintext = bob
                .ratchet_decrypt(&mut rng, &alice_ciphertext, &alice_header, &associated_data)
                .unwrap();
            prop_assert_eq!(bob_plaintext.as_slice(), b"alice proves root");
            Ok(())
        })
        .unwrap();
}

#[test]
fn ratchet_progression_under_reordering_property() {
    let strategy = (any::<[u8; 32]>(), 1usize..=8, 0usize..8, any::<bool>());
    runner([0xA2u8; 32], 32)
        .run(&strategy, |(seed, message_count, offset, reverse)| {
            let (mut setup, mut rng) = setup(seed);
            let associated_data = associated_data(&setup);
            let (mut alice, mut bob, _) = bootstrap(&mut setup, &mut rng, true, b"start");

            let mut messages = Vec::with_capacity(message_count);
            for i in 0..message_count {
                let plaintext = format!("alice msg {i}");
                let (header, ciphertext) = alice
                    .ratchet_encrypt(plaintext.as_bytes(), &associated_data)
                    .unwrap();
                messages.push((plaintext, header, ciphertext));
            }

            let mut order: Vec<usize> = (0..message_count).collect();
            order.rotate_left(offset % message_count);
            if reverse {
                order.reverse();
            }

            for index in order {
                let (plaintext, header, ciphertext) = &messages[index];
                let decrypted = bob
                    .ratchet_decrypt(&mut rng, ciphertext, header, &associated_data)
                    .unwrap();
                prop_assert_eq!(decrypted.as_slice(), plaintext.as_bytes());
                prop_assert!(bob.skipped_key_count() < message_count);
            }
            prop_assert_eq!(bob.skipped_key_count(), 0);
            Ok(())
        })
        .unwrap();
}

#[test]
fn skipped_key_bound_enforcement_property() {
    let strategy = (any::<[u8; 32]>(), 6usize..=8, 90usize..=100);
    runner([0xA3u8; 32], 16)
        .run(&strategy, |(seed, batches, gap)| {
            let (mut setup, mut rng) = setup(seed);
            let associated_data = associated_data(&setup);
            let (mut alice, mut bob, _) = bootstrap(&mut setup, &mut rng, true, b"start");

            for batch in 0..batches {
                let messages: Vec<_> = (0..=gap)
                    .map(|message| {
                        alice
                            .ratchet_encrypt(
                                format!("batch {batch} msg {message}").as_bytes(),
                                &associated_data,
                            )
                            .unwrap()
                    })
                    .collect();
                let (header, ciphertext) = messages.last().unwrap();
                bob.ratchet_decrypt(&mut rng, ciphertext, header, &associated_data)
                    .unwrap();
                prop_assert!(bob.skipped_key_count() <= SKIPPED_KEY_CAP);
            }
            prop_assert_eq!(bob.skipped_key_count(), SKIPPED_KEY_CAP);
            Ok(())
        })
        .unwrap();
}
