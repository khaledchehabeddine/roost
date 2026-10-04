//! Property tests for handshake and Double Ratchet protocol invariants.

use proptest::prelude::*;
use proptest::test_runner::{Config, RngAlgorithm, TestCaseError, TestRng, TestRunner};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use roost_crypto::{
    DiscoveryKey, HandshakeEnvelope, Header, IdentityKeyBundle, InitialPlaintext, OneTimePreKey,
    PreKeyBundle, RatchetError, RatchetState, SignedPreKey, SigningKeyPair, accept,
    generate_discovery_key, generate_key_pair, generate_one_time_prekey,
    generate_signed_prekey_for_discovery_key, generate_signing_key_pair, initial_associated_data,
    initiate, sign_identity_key_binding,
};

const CREATED_AT: u64 = 1_700_000_000;
const MAX_SKIP: u32 = 100;
const SKIPPED_KEY_CAP: usize = 500;

struct Setup {
    alice_identity_key: IdentityKeyBundle,
    alice_discovery_key: DiscoveryKey,
    bob_identity_key: IdentityKeyBundle,
    bob_discovery_key: DiscoveryKey,
    bob_signed_prekey: SignedPreKey,
    bob_one_time_prekey: Option<OneTimePreKey>,
}

#[derive(Clone, Debug)]
struct TraceBatch {
    from_alice: bool,
    message_count: usize,
    offset: usize,
    reverse: bool,
}

fn setup(seed: [u8; 32]) -> (Setup, ChaCha20Rng) {
    let mut rng = ChaCha20Rng::from_seed(seed);
    let alice_identity = generate_signing_key_pair(&mut rng);
    let alice_identity_key = identity_key_bundle(&mut rng, &alice_identity);
    let alice_discovery_key = generate_discovery_key(&mut rng, &alice_identity, 1, CREATED_AT);
    let bob_identity = generate_signing_key_pair(&mut rng);
    let bob_identity_key = identity_key_bundle(&mut rng, &bob_identity);
    let bob_discovery_key = generate_discovery_key(&mut rng, &bob_identity, 2, CREATED_AT);
    let bob_signed_prekey =
        generate_signed_prekey_for_discovery_key(&mut rng, &bob_discovery_key, 0, CREATED_AT);
    let bob_one_time_prekey =
        generate_one_time_prekey(&mut rng, 7, bob_discovery_key.epoch(), CREATED_AT);
    (
        Setup {
            alice_identity_key,
            alice_discovery_key,
            bob_identity_key,
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
        version: roost_crypto::PREKEY_BUNDLE_VERSION,
        discovery_key: setup.bob_discovery_key.bundle(),
        signed_prekey: setup.bob_signed_prekey.bundle(),
        one_time_prekey: one_time_prekey_bundle,
    };
    let (alice, envelope) = initiate(
        rng,
        &setup.alice_discovery_key,
        &setup.alice_identity_key,
        &setup.bob_identity_key,
        &prekey_bundle,
        initial_plaintext(plaintext),
    )
    .unwrap();
    let bob_one_time_prekey =
        include_one_time_prekey.then(|| setup.bob_one_time_prekey.take().unwrap());
    let (bob, decrypted) = accept(
        rng,
        &envelope,
        Some(&setup.alice_identity_key),
        &setup.bob_identity_key,
        &setup.bob_discovery_key,
        &setup.bob_signed_prekey,
        bob_one_time_prekey,
    )
    .unwrap();
    assert_eq!(decrypted.plaintext.as_slice(), plaintext);
    (alice, bob, envelope)
}

fn associated_data(setup: &Setup) -> [u8; 36] {
    initial_associated_data(
        setup.bob_discovery_key.public_key(),
        setup.bob_discovery_key.epoch(),
    )
}

fn initial_plaintext(plaintext: &[u8]) -> InitialPlaintext<'_> {
    InitialPlaintext {
        sender_certificate: b"sender certificate",
        sender_signature: b"sender signature",
        plaintext,
    }
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

fn runner(seed: [u8; 32], cases: u32) -> TestRunner {
    let config = Config {
        cases,
        failure_persistence: None,
        ..Config::default()
    };
    TestRunner::new_with_rng(config, TestRng::from_seed(RngAlgorithm::ChaCha, &seed))
}

fn trace_batch_strategy() -> impl Strategy<Value = TraceBatch> {
    (any::<bool>(), 1usize..=6, 0usize..6, any::<bool>()).prop_map(
        |(from_alice, message_count, offset, reverse)| TraceBatch {
            from_alice,
            message_count,
            offset,
            reverse,
        },
    )
}

fn encrypted_batch(
    state: &mut RatchetState,
    associated_data: &[u8],
    batch: usize,
    from_alice: bool,
    count: usize,
) -> Vec<(Vec<u8>, Header, Vec<u8>)> {
    let sender = if from_alice { "alice" } else { "bob" };
    (0..count)
        .map(|message| {
            let plaintext = format!("{sender} batch {batch} msg {message}").into_bytes();
            let (header, ciphertext) = state.ratchet_encrypt(&plaintext, associated_data).unwrap();
            (plaintext, header, ciphertext)
        })
        .collect()
}

fn delivery_order(count: usize, offset: usize, reverse: bool) -> Vec<usize> {
    let mut order: Vec<usize> = (0..count).collect();
    order.rotate_left(offset % count);
    if reverse {
        order.reverse();
    }
    order
}

fn decrypt_batch_once(
    state: &mut RatchetState,
    rng: &mut ChaCha20Rng,
    messages: &[(Vec<u8>, Header, Vec<u8>)],
    order: Vec<usize>,
    associated_data: &[u8],
) -> Result<(), TestCaseError> {
    let mut seen = vec![false; messages.len()];
    for index in order {
        let (plaintext, header, ciphertext) = &messages[index];
        prop_assert!(!seen[index]);
        let decrypted = state
            .ratchet_decrypt(rng, ciphertext, header, associated_data)
            .unwrap();
        prop_assert_eq!(decrypted.as_slice(), plaintext.as_slice());
        seen[index] = true;

        let replay = state.ratchet_decrypt(rng, ciphertext, header, associated_data);
        prop_assert!(matches!(replay, Err(RatchetError::Aead)));
    }
    prop_assert!(seen.iter().all(|delivered| *delivered));
    prop_assert_eq!(state.skipped_key_count(), 0);
    Ok(())
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
fn generated_bidirectional_traces_decrypt_once_and_remain_live_property() {
    let strategy = (
        any::<[u8; 32]>(),
        proptest::collection::vec(trace_batch_strategy(), 1..=8),
    );
    runner([0xA4u8; 32], 24)
        .run(&strategy, |(seed, batches)| {
            let (mut setup, mut rng) = setup(seed);
            let associated_data = associated_data(&setup);
            let (mut alice, mut bob, _) = bootstrap(&mut setup, &mut rng, true, b"start");

            for (batch_index, batch) in batches.iter().enumerate() {
                if batch.from_alice {
                    let messages = encrypted_batch(
                        &mut alice,
                        &associated_data,
                        batch_index,
                        true,
                        batch.message_count,
                    );
                    decrypt_batch_once(
                        &mut bob,
                        &mut rng,
                        &messages,
                        delivery_order(batch.message_count, batch.offset, batch.reverse),
                        &associated_data,
                    )?;
                } else {
                    let messages = encrypted_batch(
                        &mut bob,
                        &associated_data,
                        batch_index,
                        false,
                        batch.message_count,
                    );
                    decrypt_batch_once(
                        &mut alice,
                        &mut rng,
                        &messages,
                        delivery_order(batch.message_count, batch.offset, batch.reverse),
                        &associated_data,
                    )?;
                }
            }

            let (alice_header, alice_ciphertext) = alice
                .ratchet_encrypt(b"final alice", &associated_data)
                .unwrap();
            let bob_plaintext = bob
                .ratchet_decrypt(&mut rng, &alice_ciphertext, &alice_header, &associated_data)
                .unwrap();
            prop_assert_eq!(bob_plaintext.as_slice(), b"final alice");

            let (bob_header, bob_ciphertext) =
                bob.ratchet_encrypt(b"final bob", &associated_data).unwrap();
            let alice_plaintext = alice
                .ratchet_decrypt(&mut rng, &bob_ciphertext, &bob_header, &associated_data)
                .unwrap();
            prop_assert_eq!(alice_plaintext.as_slice(), b"final bob");
            Ok(())
        })
        .unwrap();
}

#[test]
fn per_chain_skip_overflow_rejects_without_advancing_state() {
    let (mut setup, mut rng) = setup([0xA5u8; 32]);
    let associated_data = associated_data(&setup);
    let (mut alice, mut bob, _) = bootstrap(&mut setup, &mut rng, true, b"start");
    let messages: Vec<_> = (0..=MAX_SKIP + 1)
        .map(|message| {
            alice
                .ratchet_encrypt(format!("gap msg {message}").as_bytes(), &associated_data)
                .unwrap()
        })
        .collect();
    let (overflow_header, overflow_ciphertext) = messages.last().unwrap();

    let overflow = bob.ratchet_decrypt(
        &mut rng,
        overflow_ciphertext,
        overflow_header,
        &associated_data,
    );

    assert!(matches!(overflow, Err(RatchetError::MaxSkipExceeded)));
    assert_eq!(bob.skipped_key_count(), 0);
    let (first_header, first_ciphertext) = &messages[0];
    let first = bob
        .ratchet_decrypt(&mut rng, first_ciphertext, first_header, &associated_data)
        .unwrap();
    assert_eq!(first.as_slice(), b"gap msg 0");
}

#[test]
fn skipped_key_bound_enforcement_property() {
    let strategy = (any::<[u8; 32]>(), 6usize..=8, 90usize..=100);
    runner([0xA3u8; 32], 16)
        .run(&strategy, |(seed, batches, gap)| {
            let (mut setup, mut rng) = setup(seed);
            let associated_data = associated_data(&setup);
            let (mut alice, mut bob, _) = bootstrap(&mut setup, &mut rng, true, b"start");
            let mut rejected = false;
            let mut retained = None;

            for batch in 0..batches {
                let mut messages: Vec<_> = (0..=gap)
                    .map(|message| {
                        let plaintext = format!("batch {batch} msg {message}");
                        alice
                            .ratchet_encrypt(plaintext.as_bytes(), &associated_data)
                            .map(|(header, ciphertext)| (plaintext, header, ciphertext))
                            .unwrap()
                    })
                    .collect();
                if batch == 0 {
                    retained = Some(messages.remove(0));
                }
                let (_, header, ciphertext) = messages.last().unwrap();
                let before = bob.skipped_key_count();
                let result = bob.ratchet_decrypt(&mut rng, ciphertext, header, &associated_data);
                if before + gap > SKIPPED_KEY_CAP {
                    prop_assert!(matches!(result, Err(RatchetError::MaxSkippedKeysExceeded)));
                    prop_assert_eq!(bob.skipped_key_count(), before);
                    let (plaintext, header, ciphertext) = retained.take().unwrap();
                    let decrypted = bob
                        .ratchet_decrypt(&mut rng, &ciphertext, &header, &associated_data)
                        .unwrap();
                    prop_assert_eq!(decrypted.as_slice(), plaintext.as_bytes());
                    rejected = true;
                    break;
                }
                result.unwrap();
                prop_assert_eq!(bob.skipped_key_count(), before + gap);
                prop_assert!(bob.skipped_key_count() <= SKIPPED_KEY_CAP);
            }
            prop_assert!(rejected);
            Ok(())
        })
        .unwrap();
}
