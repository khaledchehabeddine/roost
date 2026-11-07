//! Exercises app-owned binding bytes across Core's message and acknowledgment APIs.

use crate::support::device::{Sealed, run_encryption};
use crate::support::{ProtocolFixture, accepted, run_decryption, trusted_validation};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use roost_core::{
    InboundMessageOutcome, IncomingMessage, MessageOperationError, ProtocolStateError,
    ReceiveSettings, TransportBinding,
};
use roost_crypto::SealedFrameError;

#[test]
fn messages_and_acknowledgments_authenticate_their_distinct_exact_bindings() {
    let mut fixture = ProtocolFixture::new();
    let message_binding = TransportBinding::new(b"message\0\xff".to_vec()).unwrap();
    let acknowledgment_binding = TransportBinding::new(b"acknowledgment\0\xff".to_vec()).unwrap();
    let changed_binding = TransportBinding::new(b"message\0\xfe".to_vec()).unwrap();
    let outbound = run_encryption(
        fixture
            .alice
            .store
            .start_encryption(fixture.outgoing(1, b"transport bound"))
            .unwrap(),
        &fixture.alice.host,
        &mut ChaCha20Rng::from_seed([0x42; 32]),
        &message_binding,
    )
    .unwrap()
    .ready();
    let Sealed {
        result: outbound,
        changes,
        ..
    } = outbound;
    let message_id = outbound.message_id;
    let message = outbound.message.clone();
    fixture.alice.host.commit_sent(&outbound, changes).unwrap();

    let receive = |binding: &TransportBinding| {
        let mut incoming =
            fixture.incoming(&message, ReceiveSettings::default(), trusted_validation());
        incoming.transport_binding = binding.clone();
        run_decryption(
            fixture.bob.store.start_decryption(incoming).unwrap(),
            &fixture.bob.host,
            &mut ChaCha20Rng::from_seed([0x43; 32]),
            &acknowledgment_binding,
        )
    };
    assert!(matches!(
        receive(&changed_binding),
        Err(MessageOperationError::ProtocolState(
            ProtocolStateError::SealedFrame(SealedFrameError::Aead)
        ))
    ));
    let decrypted = receive(&message_binding).unwrap();
    fixture.bob.host.commit(decrypted.changes).unwrap();
    let received = accepted(decrypted.outcome);
    let acknowledgment = received.acknowledgment.as_ref().unwrap().clone();
    assert_eq!(received.plaintext.as_slice(), b"transport bound");

    let process = |binding: &TransportBinding| {
        run_decryption(
            fixture
                .alice
                .store
                .start_decryption(IncomingMessage {
                    message: acknowledgment.clone(),
                    transport_binding: binding.clone(),
                    settings: ReceiveSettings::default(),
                    sender_certificate_validation: trusted_validation(),
                    acknowledgment_sent_at_millis: 0,
                    acknowledgment_sender_certificate: fixture.alice.certificate(),
                })
                .unwrap(),
            &fixture.alice.host,
            &mut ChaCha20Rng::from_seed([0x44; 32]),
            binding,
        )
    };
    // Even the valid inbound binding must not authenticate the generated acknowledgment.
    for binding in [&message_binding, &changed_binding] {
        assert!(matches!(
            process(binding),
            Err(MessageOperationError::ProtocolState(
                ProtocolStateError::SealedFrame(SealedFrameError::Aead)
            ))
        ));
    }
    let processed = process(&acknowledgment_binding).unwrap();
    let InboundMessageOutcome::AcknowledgmentMatched(matched) = processed.outcome else {
        panic!("expected the pending Message to be acknowledged");
    };
    assert_eq!(matched.acknowledged_message_id, message_id);
    fixture.alice.host.commit(processed.changes).unwrap();
}
