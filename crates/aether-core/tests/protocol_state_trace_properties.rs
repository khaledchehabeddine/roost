//! Generated protocol-state traces across Core's public Message and Protocol State Blob boundary.

mod support;

use aether_core::{InboundMessageOutcome, ProtocolStateEngine};
use proptest::prelude::*;
use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use support::{ProtocolFixture, StoredMessage, inbound_duplicate, ratchet_address};

#[derive(Clone, Debug)]
struct TraceBatch {
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
    (1usize..=6, 0usize..6, any::<bool>()).prop_map(|(message_count, offset, reverse)| TraceBatch {
        message_count,
        offset,
        reverse,
    })
}

fn delivery_order(count: usize, offset: usize, reverse: bool) -> Vec<usize> {
    let mut order: Vec<usize> = (0..count).collect();
    order.rotate_left(offset % count);
    if reverse {
        order.reverse();
    }
    order
}

#[test]
fn generated_receive_traces_accept_once_and_deduplicate_before_ratchet_property() {
    let strategy = (
        any::<[u8; 32]>(),
        proptest::collection::vec(trace_batch_strategy(), 1..=8),
    );
    runner([0xB1; 32], 16)
        .run(&strategy, |(seed, batches)| {
            let engine = ProtocolStateEngine::new();
            let mut fixture = ProtocolFixture::new(seed);
            let mut sequence = 1u16;

            for (batch_index, batch) in batches.iter().enumerate() {
                let mut messages = Vec::new();
                for message_index in 0..batch.message_count {
                    let plaintext =
                        format!("batch {batch_index} message {message_index}").into_bytes();
                    messages.push(fixture.encrypt_from_alice(&engine, sequence, &plaintext));
                    sequence = sequence.wrapping_add(1);
                }

                for index in delivery_order(batch.message_count, batch.offset, batch.reverse) {
                    let message: &StoredMessage = &messages[index];
                    let decrypted = fixture.decrypt_for_bob(
                        &engine,
                        message,
                        0x40u8.wrapping_add(sequence as u8),
                    );
                    prop_assert_eq!(decrypted.message_id, message.message_id);
                    prop_assert_eq!(decrypted.plaintext.as_slice(), message.plaintext.as_slice());

                    let mut corrupt_store = fixture.bob_store.clone();
                    corrupt_store.set_raw(
                        ratchet_address(fixture.session_key.clone()),
                        vec![1, 0, 0xaa],
                    );
                    let duplicate = engine
                        .decrypt_message(
                            &mut ChaCha20Rng::from_seed([0x90; 32]),
                            &corrupt_store.read().snapshot,
                            inbound_duplicate(
                                fixture.session_key.clone(),
                                fixture.deduplication_key.clone(),
                                &message.message,
                                &fixture.bob_sender,
                            ),
                        )
                        .unwrap();
                    prop_assert!(matches!(duplicate, InboundMessageOutcome::Duplicate));
                }
            }

            let final_message =
                fixture.encrypt_from_alice(&engine, sequence, b"final trace liveness");
            let final_decrypted = fixture.decrypt_for_bob(&engine, &final_message, 0xf1);
            prop_assert_eq!(
                final_decrypted.plaintext.as_slice(),
                b"final trace liveness"
            );
            Ok(())
        })
        .unwrap();
}
