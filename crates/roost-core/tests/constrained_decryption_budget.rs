//! Constrained-environment budget gate for the real encrypted Message receive path.

mod support;

use std::alloc::System;
use std::fmt;
use std::time::{Duration, Instant};

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use roost_core::{
    MessageError, ProtocolHardeningLimits, ProtocolStateAddress, ProtocolStateEngine,
    ProtocolStateError, ProtocolStateSnapshot, ProtocolStateUpdate,
};
use roost_protocol::PayloadKind;
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};
use support::{
    ProtocolFixture, StoredMessage, accepted, deduplication_address,
    inbound_with_certificate_validation, ratchet_address,
};

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

const MEMORY_BUDGET_BYTES: usize = 24 * 1024 * 1024;
const RELEASE_WALL_CLOCK_BUDGET: Duration = Duration::from_millis(250);
const DEBUG_WALL_CLOCK_BUDGET: Duration = Duration::from_secs(30);
const MAX_SEALED_PAYLOAD_PLAINTEXT_LEN: usize = 65_536 - 4;

#[derive(Clone, Copy)]
struct Budget {
    max_allocated_bytes: usize,
    max_elapsed: Duration,
}

#[derive(Clone, Copy, Debug)]
struct Measurement {
    allocated_bytes: usize,
    elapsed: Duration,
}

struct Measured<T> {
    value: T,
    measurement: Measurement,
}

#[derive(Debug)]
enum BudgetFailure {
    Memory {
        label: &'static str,
        allocated_bytes: usize,
        max_allocated_bytes: usize,
    },
    WallClock {
        label: &'static str,
        elapsed: Duration,
        max_elapsed: Duration,
    },
}

impl fmt::Display for BudgetFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Memory {
                label,
                allocated_bytes,
                max_allocated_bytes,
            } => write!(
                f,
                "{label} allocated {allocated_bytes} bytes, above {max_allocated_bytes}"
            ),
            Self::WallClock {
                label,
                elapsed,
                max_elapsed,
            } => write!(f, "{label} took {elapsed:?}, above {max_elapsed:?}"),
        }
    }
}

struct PlaintextCase {
    label: &'static str,
    len: usize,
    fill: u8,
}

const PLAINTEXT_CASES: &[PlaintextCase] = &[
    PlaintextCase {
        label: "first-empty-payload",
        len: 0,
        fill: 0x10,
    },
    PlaintextCase {
        label: "bucket-32-boundary",
        len: 28,
        fill: 0x20,
    },
    PlaintextCase {
        label: "bucket-256-boundary",
        len: 252,
        fill: 0x30,
    },
    PlaintextCase {
        label: "bucket-4096-boundary",
        len: 4092,
        fill: 0x40,
    },
    PlaintextCase {
        label: "bucket-65536-boundary",
        len: MAX_SEALED_PAYLOAD_PLAINTEXT_LEN,
        fill: 0x50,
    },
];

#[test]
fn constrained_decryption_budget_gate() {
    representative_decrypts_stay_within_budget();
    skipped_key_decrypts_stay_within_budget();
    maximum_size_precheck_rejects_before_state_access();
    budget_harness_reports_too_small_memory_budget();
    budget_harness_reports_too_small_wall_clock_budget();
}

fn representative_decrypts_stay_within_budget() {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0x11; 32]);

    for (index, case) in PLAINTEXT_CASES.iter().enumerate() {
        let plaintext = vec![case.fill; case.len];
        let message = fixture.encrypt_from_alice(&engine, index as u16, &plaintext);
        decrypt_and_commit(
            &engine,
            &mut fixture,
            &message,
            0x30 + index as u8,
            case.label,
            constrained_budget(),
        );
    }
}

fn skipped_key_decrypts_stay_within_budget() {
    if cfg!(debug_assertions) && std::env::var_os("AETHER_RUN_CONSTRAINED_DEBUG").is_none() {
        return;
    }

    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0x22; 32]);
    let mut retained = None;
    let mut sequence = 0u16;

    for batch in 0..5 {
        let mut last = None;
        for offset in 0..=100 {
            let message =
                fixture.encrypt_from_alice(&engine, sequence, b"retained skipped-key fill");
            if batch == 0 && offset == 0 {
                retained = Some(message);
            } else {
                last = Some(message);
            }
            sequence += 1;
        }
        let last = last.unwrap();
        decrypt_and_commit(
            &engine,
            &mut fixture,
            &last,
            0x60 + batch as u8,
            "skipped-gap-100",
            constrained_budget(),
        );
    }

    let retained = retained.unwrap();
    decrypt_and_commit(
        &engine,
        &mut fixture,
        &retained,
        0x70,
        "skipped-key-retained-at-cap",
        constrained_budget(),
    );
}

fn maximum_size_precheck_rejects_before_state_access() {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0x33; 32]);
    let message = fixture.encrypt_from_alice(&engine, 0x80, b"oversized precheck");
    let encoded_len = message.message.to_bytes().unwrap().len();
    let limits = ProtocolHardeningLimits {
        max_encoded_message_len: encoded_len - 1,
        ..Default::default()
    };
    let tight_engine = ProtocolStateEngine::with_hardening_limits(limits).unwrap();
    let domain_keys = [fixture.alice_sender.domain_signing_key()];
    let revoked = [];

    let measured = assert_within_budget("maximum-size-precheck", constrained_budget(), || {
        tight_engine.decrypt_message(
            &mut ChaCha20Rng::from_seed([0x80; 32]),
            &ProtocolStateSnapshot::new(),
            inbound_with_certificate_validation(
                fixture.session_key.clone(),
                fixture.deduplication_key.clone(),
                &message.message,
                &fixture.bob_sender,
                &domain_keys,
                &revoked,
            ),
        )
    });
    let result = measured.value;

    assert!(matches!(
        result,
        Err(ProtocolStateError::MessageEncode(
            MessageError::EncodedTooLarge
        ))
    ));
}

fn budget_harness_reports_too_small_memory_budget() {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0x44; 32]);
    let message = fixture.encrypt_from_alice(&engine, 0x90, b"memory negative");
    let read = fixture.bob_store.read();
    let domain_keys = [fixture.alice_sender.domain_signing_key()];
    let revoked = [];
    let budget = Budget {
        max_allocated_bytes: 0,
        max_elapsed: Duration::from_secs(30),
    };

    let result = measure_budget("too-small-memory-budget", budget, || {
        engine
            .decrypt_message(
                &mut ChaCha20Rng::from_seed([0x90; 32]),
                &read.snapshot,
                inbound_with_certificate_validation(
                    fixture.session_key.clone(),
                    fixture.deduplication_key.clone(),
                    &message.message,
                    &fixture.bob_sender,
                    &domain_keys,
                    &revoked,
                ),
            )
            .unwrap()
    });

    assert!(matches!(result, Err(BudgetFailure::Memory { .. })));
}

fn budget_harness_reports_too_small_wall_clock_budget() {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0x55; 32]);
    let message = fixture.encrypt_from_alice(&engine, 0xa0, b"wall-clock negative");
    let read = fixture.bob_store.read();
    let domain_keys = [fixture.alice_sender.domain_signing_key()];
    let revoked = [];
    let budget = Budget {
        max_allocated_bytes: usize::MAX,
        max_elapsed: Duration::from_nanos(1),
    };

    let result = measure_budget("too-small-wall-clock-budget", budget, || {
        engine
            .decrypt_message(
                &mut ChaCha20Rng::from_seed([0xa0; 32]),
                &read.snapshot,
                inbound_with_certificate_validation(
                    fixture.session_key.clone(),
                    fixture.deduplication_key.clone(),
                    &message.message,
                    &fixture.bob_sender,
                    &domain_keys,
                    &revoked,
                ),
            )
            .unwrap()
    });

    assert!(matches!(result, Err(BudgetFailure::WallClock { .. })));
}

fn decrypt_and_commit(
    engine: &ProtocolStateEngine,
    fixture: &mut ProtocolFixture,
    message: &StoredMessage,
    rng_seed: u8,
    label: &'static str,
    budget: Budget,
) -> Measurement {
    let read = fixture.bob_store.read();
    let ratchet_address = ratchet_address(fixture.session_key.clone());
    let deduplication_address = deduplication_address(fixture.deduplication_key.clone());
    let prior_ratchet = fixture.bob_store.blob_bytes(&ratchet_address).unwrap();
    let prior_deduplication = fixture
        .bob_store
        .blob_bytes(&deduplication_address)
        .unwrap();
    let domain_keys = [fixture.alice_sender.domain_signing_key()];
    let revoked = [];
    let measured = assert_within_budget(label, budget, || {
        engine
            .decrypt_message(
                &mut ChaCha20Rng::from_seed([rng_seed; 32]),
                &read.snapshot,
                inbound_with_certificate_validation(
                    fixture.session_key.clone(),
                    fixture.deduplication_key.clone(),
                    &message.message,
                    &fixture.bob_sender,
                    &domain_keys,
                    &revoked,
                ),
            )
            .unwrap()
    });
    let Measured { value, measurement } = measured;
    let mut decrypted = accepted(value);

    assert_eq!(decrypted.message_id, message.message_id);
    let sequence = u16::from_be_bytes([
        message.message_id.as_bytes()[0],
        message.message_id.as_bytes()[1],
    ]);
    assert_eq!(
        decrypted.timestamp_millis,
        1_700_000_300_000 + u64::from(sequence)
    );
    assert_eq!(decrypted.payload_kind, PayloadKind::EncryptedText);
    assert_eq!(decrypted.plaintext.as_slice(), message.plaintext.as_slice());
    assert_eq!(
        decrypted.sender_identity.identity_key,
        fixture.alice_sender.sender_identity.identity_key
    );
    assert_eq!(
        decrypted.sender_identity.identity_verifying_key,
        fixture.alice_sender.sender_identity.identity_verifying_key
    );
    assert_eq!(
        decrypted.sender_identity.certificate,
        fixture.alice_sender.sender_identity.certificate
    );
    assert_eq!(
        decrypted.sender_identity.signature,
        fixture.alice_sender.sender_identity.signature
    );
    assert!(!decrypted.acknowledgment.ciphertext.is_empty());

    let updates = std::mem::take(&mut decrypted.state_updates);
    assert_receive_updates(
        &updates,
        &ratchet_address,
        &deduplication_address,
        &prior_ratchet,
        &prior_deduplication,
    );
    fixture.bob_store.commit(read.token, updates).unwrap();
    measurement
}

fn assert_receive_updates(
    updates: &[ProtocolStateUpdate],
    ratchet_address: &ProtocolStateAddress,
    deduplication_address: &ProtocolStateAddress,
    prior_ratchet: &[u8],
    prior_deduplication: &[u8],
) {
    assert_eq!(updates.len(), 2);
    assert_eq!(updates[0].address(), ratchet_address);
    assert_eq!(updates[1].address(), deduplication_address);
    assert_ne!(updates[0].blob().unwrap().as_bytes(), prior_ratchet);
    assert_ne!(updates[1].blob().unwrap().as_bytes(), prior_deduplication);
}

fn constrained_budget() -> Budget {
    Budget {
        max_allocated_bytes: MEMORY_BUDGET_BYTES,
        max_elapsed: if cfg!(debug_assertions) {
            DEBUG_WALL_CLOCK_BUDGET
        } else {
            RELEASE_WALL_CLOCK_BUDGET
        },
    }
}

fn assert_within_budget<T>(
    label: &'static str,
    budget: Budget,
    operation: impl FnOnce() -> T,
) -> Measured<T> {
    match measure_budget(label, budget, operation) {
        Ok(measured) => {
            println!(
                "{label}: allocated={} elapsed_ms={:.3}",
                measured.measurement.allocated_bytes,
                measured.measurement.elapsed.as_secs_f64() * 1000.0
            );
            measured
        }
        Err(failure) => panic!("budget failure: {failure}"),
    }
}

fn measure_budget<T>(
    label: &'static str,
    budget: Budget,
    operation: impl FnOnce() -> T,
) -> Result<Measured<T>, BudgetFailure> {
    let region = Region::new(GLOBAL);
    let started = Instant::now();
    let value = operation();
    let elapsed = started.elapsed();
    let stats = region.change();
    let allocated_bytes = stats.bytes_allocated;

    if allocated_bytes > budget.max_allocated_bytes {
        return Err(BudgetFailure::Memory {
            label,
            allocated_bytes,
            max_allocated_bytes: budget.max_allocated_bytes,
        });
    }
    if elapsed > budget.max_elapsed {
        return Err(BudgetFailure::WallClock {
            label,
            elapsed,
            max_elapsed: budget.max_elapsed,
        });
    }

    Ok(Measured {
        value,
        measurement: Measurement {
            allocated_bytes,
            elapsed,
        },
    })
}
