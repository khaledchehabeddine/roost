use crate::support::{ASSOCIATED_DATA, bootstrap, setup};
use proptest::prelude::*;
use proptest::test_runner::{Config, RngAlgorithm, TestCaseError, TestRng, TestRunner};
use rand_chacha::ChaCha20Rng;
use roost_crypto::{Header, RatchetError, RatchetState};

const MAX_SKIP: u32 = 100;
const SKIPPED_KEY_CAP: usize = 500;

#[derive(Clone, Debug)]
struct TraceBatch {
    from_alice: bool,
    message_count: usize,
    offset: usize,
    reverse: bool,
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
            let associated_data = ASSOCIATED_DATA;
            let (mut alice, mut bob) =
                bootstrap(&mut setup, &mut rng, include_one_time_prekey, &plaintext);

            let (bob_header, bob_ciphertext) = bob
                .ratchet_encrypt(b"bob proves root", associated_data)
                .unwrap();
            let alice_plaintext = alice
                .ratchet_decrypt(&mut rng, &bob_ciphertext, &bob_header, associated_data)
                .unwrap();
            prop_assert_eq!(alice_plaintext.as_slice(), b"bob proves root");

            let (alice_header, alice_ciphertext) = alice
                .ratchet_encrypt(b"alice proves root", associated_data)
                .unwrap();
            let bob_plaintext = bob
                .ratchet_decrypt(&mut rng, &alice_ciphertext, &alice_header, associated_data)
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
            let associated_data = ASSOCIATED_DATA;
            let (mut alice, mut bob) = bootstrap(&mut setup, &mut rng, true, b"start");

            for (batch_index, batch) in batches.iter().enumerate() {
                if batch.from_alice {
                    let messages = encrypted_batch(
                        &mut alice,
                        associated_data,
                        batch_index,
                        true,
                        batch.message_count,
                    );
                    decrypt_batch_once(
                        &mut bob,
                        &mut rng,
                        &messages,
                        delivery_order(batch.message_count, batch.offset, batch.reverse),
                        associated_data,
                    )?;
                } else {
                    let messages = encrypted_batch(
                        &mut bob,
                        associated_data,
                        batch_index,
                        false,
                        batch.message_count,
                    );
                    decrypt_batch_once(
                        &mut alice,
                        &mut rng,
                        &messages,
                        delivery_order(batch.message_count, batch.offset, batch.reverse),
                        associated_data,
                    )?;
                }
            }

            let (alice_header, alice_ciphertext) = alice
                .ratchet_encrypt(b"final alice", associated_data)
                .unwrap();
            let bob_plaintext = bob
                .ratchet_decrypt(&mut rng, &alice_ciphertext, &alice_header, associated_data)
                .unwrap();
            prop_assert_eq!(bob_plaintext.as_slice(), b"final alice");

            let (bob_header, bob_ciphertext) =
                bob.ratchet_encrypt(b"final bob", associated_data).unwrap();
            let alice_plaintext = alice
                .ratchet_decrypt(&mut rng, &bob_ciphertext, &bob_header, associated_data)
                .unwrap();
            prop_assert_eq!(alice_plaintext.as_slice(), b"final bob");
            Ok(())
        })
        .unwrap();
}

#[test]
fn per_chain_skip_overflow_rejects_without_advancing_state() {
    let (mut setup, mut rng) = setup([0xA5u8; 32]);
    let associated_data = ASSOCIATED_DATA;
    let (mut alice, mut bob) = bootstrap(&mut setup, &mut rng, true, b"start");
    let messages: Vec<_> = (0..=MAX_SKIP + 1)
        .map(|message| {
            alice
                .ratchet_encrypt(format!("gap msg {message}").as_bytes(), associated_data)
                .unwrap()
        })
        .collect();
    let (overflow_header, overflow_ciphertext) = messages.last().unwrap();
    let before = bob.to_bytes().unwrap();

    let overflow = bob.ratchet_decrypt(
        &mut rng,
        overflow_ciphertext,
        overflow_header,
        associated_data,
    );

    assert!(matches!(
        overflow,
        Err(RatchetError::MaxSkipExceeded { count, max: MAX_SKIP }) if count == MAX_SKIP + 1
    ));
    assert_eq!(*bob.to_bytes().unwrap(), *before);
    let (first_header, first_ciphertext) = &messages[0];
    let first = bob
        .ratchet_decrypt(&mut rng, first_ciphertext, first_header, associated_data)
        .unwrap();
    assert_eq!(first.as_slice(), b"gap msg 0");
}

#[test]
fn skipped_key_bound_enforcement_property() {
    let strategy = (any::<[u8; 32]>(), 6usize..=8, 90usize..=100);
    runner([0xA3u8; 32], 16)
        .run(&strategy, |(seed, batches, gap)| {
            let (mut setup, mut rng) = setup(seed);
            let associated_data = ASSOCIATED_DATA;
            let (mut alice, mut bob) = bootstrap(&mut setup, &mut rng, true, b"start");
            let mut rejected = false;
            let mut retained = None;
            let mut cached = 0;

            for batch in 0..batches {
                let mut messages: Vec<_> = (0..=gap)
                    .map(|message| {
                        let plaintext = format!("batch {batch} msg {message}");
                        alice
                            .ratchet_encrypt(plaintext.as_bytes(), associated_data)
                            .map(|(header, ciphertext)| (plaintext, header, ciphertext))
                            .unwrap()
                    })
                    .collect();
                if batch == 0 {
                    retained = Some(messages.remove(0));
                }
                let (_, header, ciphertext) = messages.last().unwrap();
                let before = bob.to_bytes().unwrap();
                let result = bob.ratchet_decrypt(&mut rng, ciphertext, header, associated_data);
                if cached + gap > SKIPPED_KEY_CAP {
                    let rejected_at_cap = matches!(
                        result,
                        Err(RatchetError::MaxSkippedKeysExceeded {
                            max: SKIPPED_KEY_CAP
                        })
                    );
                    prop_assert!(rejected_at_cap);
                    prop_assert_eq!(&*bob.to_bytes().unwrap(), &*before);
                    let (plaintext, header, ciphertext) = retained.take().unwrap();
                    let decrypted = bob
                        .ratchet_decrypt(&mut rng, &ciphertext, &header, associated_data)
                        .unwrap();
                    prop_assert_eq!(decrypted.as_slice(), plaintext.as_bytes());
                    rejected = true;
                    break;
                }
                result.unwrap();
                cached += gap;
            }
            prop_assert!(rejected);
            Ok(())
        })
        .unwrap();
}
