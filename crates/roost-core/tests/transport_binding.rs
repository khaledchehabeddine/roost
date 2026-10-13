//! Exercises caller-owned binding bytes across Core construction, Message, and acknowledgment APIs.

mod support;

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use roost_core::{
    InboundMessageOutcome, IncomingMessage, MessageOperationError, ProtocolStateError,
    ReceiveSettings, TransportBinding, TransportBindingError,
};
use roost_crypto::SealedFrameError;
use support::{
    ProtocolFixture, accepted, copy, run_decryption, run_encryption, trusted_validation,
};

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
    .unwrap();
    let message_id = outbound.message_id;
    let message = copy(&outbound.message);
    fixture.alice.host.commit_sent(outbound).unwrap();

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
    let received = accepted(receive(&message_binding).unwrap());
    let acknowledgment = copy(received.acknowledgment.as_ref().unwrap());
    assert_eq!(received.plaintext.as_slice(), b"transport bound");
    fixture.bob.host.commit_changes(received.changes).unwrap();

    let process = |binding: &TransportBinding| {
        run_decryption(
            fixture
                .alice
                .store
                .start_decryption(IncomingMessage {
                    message: copy(&acknowledgment),
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
    let InboundMessageOutcome::AcknowledgmentMatched(matched) =
        process(&acknowledgment_binding).unwrap()
    else {
        panic!("expected the pending Message to be acknowledged");
    };
    assert_eq!(matched.acknowledged_message_id, message_id);
    fixture.alice.host.commit_changes(matched.changes).unwrap();
}
