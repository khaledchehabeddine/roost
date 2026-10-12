//! Exercises caller-owned binding bytes across Core construction, Message, and acknowledgment APIs.

mod support;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use roost_core::{
    AcknowledgmentOutcome, InboundAcknowledgmentMessage, ProtocolStateEngine, ProtocolStateError,
    TransportBinding, TransportBindingError,
};
use roost_crypto::SealedFrameError;
use support::{ProtocolFixture, accepted, acknowledgment_recipient_discovery_key};

#[test]
fn transport_binding_preserves_exact_caller_bytes() {
    let bytes = vec![0x41, 0x00, 0xff, 0x7f];
    let binding = TransportBinding::new(bytes.clone()).expect("binding should be valid");

    assert_eq!(binding.as_bytes(), bytes);
}

#[test]
fn transport_binding_rejects_empty_bytes() {
    assert_eq!(
        TransportBinding::new(Vec::new()),
        Err(TransportBindingError::Empty)
    );
}

#[test]
fn transport_binding_enforces_the_external_associated_data_limit() {
    const MAX_LEN: usize = 1024;

    assert!(TransportBinding::new(vec![0x41; MAX_LEN]).is_ok());
    assert_eq!(
        TransportBinding::new(vec![0x41; MAX_LEN + 1]),
        Err(TransportBindingError::TooLong {
            length: MAX_LEN + 1,
            maximum: MAX_LEN,
        })
    );
}

#[test]
fn messages_and_acknowledgments_authenticate_their_distinct_exact_bindings() {
    let engine = ProtocolStateEngine::new();
    let mut fixture = ProtocolFixture::new([0x42; 32]);
    let message_binding = TransportBinding::new(b"message\0\xff".to_vec()).unwrap();
    let acknowledgment_binding = TransportBinding::new(b"acknowledgment\0\xff".to_vec()).unwrap();
    let changed_binding = TransportBinding::new(b"message\0\xfe".to_vec()).unwrap();
    let read = fixture.alice_store.snapshot();
    let outbound = engine
        .encrypt_message_with_transport_binding(
            &mut ChaCha20Rng::from_seed([0x42; 32]),
            &read,
            fixture.outbound(1, b"transport bound"),
            &message_binding,
        )
        .unwrap();
    fixture
        .alice_store
        .commit_outbound(
            outbound.state_updates,
            outbound.message_id,
            &outbound.message,
        )
        .unwrap();

    let read = fixture.bob_store.snapshot();
    let domain_keys = [fixture.alice_sender.domain_signing_key()];
    let receive = |binding: &TransportBinding| {
        engine.decrypt_message_with_transport_bindings(
            &mut ChaCha20Rng::from_seed([0x43; 32]),
            &read,
            fixture.inbound(&outbound.message, &domain_keys, &[]),
            binding,
            &acknowledgment_binding,
        )
    };
    assert!(matches!(
        receive(&changed_binding),
        Err(ProtocolStateError::SealedFrame(SealedFrameError::Aead))
    ));
    let received = accepted(receive(&message_binding).unwrap());
    fixture.bob_store.commit(received.state_updates).unwrap();
    assert_eq!(received.plaintext.as_slice(), b"transport bound");

    let read = fixture.alice_store.snapshot();
    let recipient = acknowledgment_recipient_discovery_key();
    let process = |binding: &TransportBinding| {
        engine.process_acknowledgment_with_transport_binding(
            &mut ChaCha20Rng::from_seed([0x44; 32]),
            &read,
            InboundAcknowledgmentMessage {
                message: &received.acknowledgment,
                recipient_discovery_key: &recipient,
                recipient_identity_verifying_key: fixture
                    .alice_sender
                    .sender_identity
                    .identity_verifying_key,
            },
            binding,
        )
    };
    // Even the valid inbound binding must not authenticate the generated acknowledgment.
    assert!(matches!(
        process(&message_binding),
        Err(ProtocolStateError::SealedFrame(SealedFrameError::Aead))
    ));
    assert!(matches!(
        process(&changed_binding),
        Err(ProtocolStateError::SealedFrame(SealedFrameError::Aead))
    ));
    let AcknowledgmentOutcome::Cleared(cleared) = process(&acknowledgment_binding).unwrap() else {
        panic!("expected the pending Message to be acknowledged");
    };
    fixture.alice_store.commit(cleared.state_updates).unwrap();
    assert_eq!(cleared.acknowledged_message_id, outbound.message_id);
}
