//! Generated protocol-state traces across Core's public message and protocol state blob boundary.

use crate::support::{ProtocolFixture, StoredMessage, validation};
use proptest::prelude::*;
use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};
use roost_core::{InboundMessageOutcome, ProtocolStateKind, ReceiveSettings};

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
    let strategy = proptest::collection::vec(trace_batch_strategy(), 1..=8);
    runner([0xB1; 32], 16)
        .run(&strategy, |batches| {
            let mut fixture = ProtocolFixture::new();
            let mut sequence = 1u16;

            for (batch_index, batch) in batches.iter().enumerate() {
                let mut messages = Vec::new();
                for message_index in 0..batch.message_count {
                    let plaintext =
                        format!("batch {batch_index} message {message_index}").into_bytes();
                    messages.push(fixture.encrypt_from_alice(sequence, &plaintext));
                    sequence = sequence.wrapping_add(1);
                }

                for index in delivery_order(batch.message_count, batch.offset, batch.reverse) {
                    let message: &StoredMessage = &messages[index];
                    let decrypted =
                        fixture.decrypt_for_bob(message, 0x40u8.wrapping_add(sequence as u8));
                    prop_assert_eq!(decrypted.message_id, message.message_id);
                    prop_assert_eq!(decrypted.plaintext.as_slice(), message.plaintext.as_slice());

                    let mut corrupt_store = fixture.bob.host.clone();
                    let session = corrupt_store.only(ProtocolStateKind::RatchetSession);
                    corrupt_store.corrupt(&session);
                    let duplicate = fixture
                        .decrypt(
                            &corrupt_store,
                            fixture.incoming(
                                &message.message,
                                ReceiveSettings::default(),
                                validation(Vec::new(), Vec::new()),
                            ),
                            0x90,
                        )
                        .unwrap()
                        .outcome;
                    prop_assert!(matches!(duplicate, InboundMessageOutcome::Duplicate));
                }
            }

            let final_message = fixture.encrypt_from_alice(sequence, b"final trace liveness");
            let final_decrypted = fixture.decrypt_for_bob(&final_message, 0xf1);
            prop_assert_eq!(
                final_decrypted.plaintext.as_slice(),
                b"final trace liveness"
            );
            Ok(())
        })
        .unwrap();
}
