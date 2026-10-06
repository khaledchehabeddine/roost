//! Verifies the shared sealed-sender frame used by session, acknowledgment, and X3DH wires.

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use roost_crypto::{
    KeyPair, SealedFrame, SealedFrameError, SealedFramePreKeyReference, generate_discovery_key,
    generate_signing_key_pair, open_frame, open_frame_for_discovery_key_with_associated_data,
    seal_frame, seal_frame_with_associated_data,
};

fn recipient_key() -> KeyPair {
    KeyPair::from_secret_bytes([0x42; 32])
}

#[test]
fn sealed_frame_authenticates_external_associated_data() {
    let mut rng = ChaCha20Rng::from_seed([0x10; 32]);
    let signing_key = generate_signing_key_pair(&mut rng);
    let recipient = generate_discovery_key(&mut rng, &signing_key, 1, 1_700_000_000).unwrap();
    let frame = seal_frame_with_associated_data(
        &mut rng,
        recipient.public_key(),
        None,
        b"transport-bound payload",
        b"consumer-binding:expected",
    )
    .unwrap();

    assert_eq!(
        open_frame_for_discovery_key_with_associated_data(
            &recipient,
            &frame,
            b"consumer-binding:expected",
        )
        .unwrap()
        .as_slice(),
        b"transport-bound payload"
    );
    assert!(matches!(
        open_frame_for_discovery_key_with_associated_data(
            &recipient,
            &frame,
            b"consumer-binding:changed",
        ),
        Err(SealedFrameError::Aead)
    ));
    assert!(matches!(
        open_frame_for_discovery_key_with_associated_data(&recipient, &frame, &[]),
        Err(SealedFrameError::Aead)
    ));
}

fn prekey_reference() -> SealedFramePreKeyReference {
    SealedFramePreKeyReference {
        discovery_epoch: 7,
        signed_prekey_public_key: [0x51; 32],
        one_time_prekey_id: Some(9),
        one_time_prekey_public_key: Some([0x61; 32]),
    }
}

#[test]
fn sealed_frame_round_trip_with_prekey_reference() {
    let mut rng = ChaCha20Rng::from_seed([0x11; 32]);
    let recipient = recipient_key();
    let frame = seal_frame(
        &mut rng,
        &recipient.public,
        Some(prekey_reference()),
        b"sealed payload",
    )
    .unwrap();
    let encoded = frame.to_bytes().unwrap();
    let decoded = SealedFrame::from_bytes(&encoded).unwrap();

    assert_eq!(decoded.recipient_public_key, *recipient.public.as_bytes());
    assert_eq!(decoded.prekey_reference, Some(prekey_reference()));
    assert_ne!(decoded.ephemeral_public_key, [0u8; 32]);
    assert_eq!(
        open_frame(&recipient, &decoded).unwrap().as_slice(),
        b"sealed payload"
    );
}

#[test]
fn sealed_frame_aad_binds_transport_visible_fields() {
    let mut rng = ChaCha20Rng::from_seed([0x12; 32]);
    let recipient = recipient_key();
    let other_recipient = KeyPair::from_secret_bytes([0x44; 32]);
    let frame = seal_frame(&mut rng, &recipient.public, None, b"metadata-bound").unwrap();

    let mut wrong_version = frame.clone();
    wrong_version.version = wrong_version.version.wrapping_add(1);
    let mut wrong_recipient = frame.clone();
    wrong_recipient.recipient_public_key = *other_recipient.public.as_bytes();
    let mut wrong_ephemeral = frame.clone();
    wrong_ephemeral.ephemeral_public_key =
        *KeyPair::from_secret_bytes([0x45; 32]).public.as_bytes();
    let mut wrong_prekey = frame.clone();
    wrong_prekey.prekey_reference = Some(prekey_reference());

    assert!(open_frame(&recipient, &wrong_version).is_err());
    assert!(matches!(
        open_frame(&other_recipient, &wrong_recipient),
        Err(SealedFrameError::Aead)
    ));
    for tampered in [wrong_ephemeral, wrong_prekey] {
        assert!(matches!(
            open_frame(&recipient, &tampered),
            Err(SealedFrameError::Aead)
        ));
    }
}

#[test]
fn sealed_frame_from_bytes_rejects_oversized_before_decode() {
    let bytes = vec![0u8; SealedFrame::MAX_ENCODED_LEN + 1];

    assert!(matches!(
        SealedFrame::from_bytes(&bytes),
        Err(SealedFrameError::Decode)
    ));
}

#[test]
fn sealed_frame_rejects_invalid_public_keys() {
    let mut frame = SealedFrame {
        version: SealedFrame::VERSION,
        recipient_public_key: [0u8; 32],
        prekey_reference: None,
        ephemeral_public_key: [0x42; 32],
        ciphertext: vec![0x51; 16],
    };

    assert!(matches!(frame.to_bytes(), Err(SealedFrameError::Encode)));

    frame.recipient_public_key = *recipient_key().public.as_bytes();
    frame.ephemeral_public_key = [0u8; 32];
    assert!(matches!(frame.to_bytes(), Err(SealedFrameError::Encode)));
}

#[test]
fn sealed_frame_rejects_mismatched_one_time_prekey_reference_halves() {
    let mut reference = prekey_reference();
    reference.one_time_prekey_public_key = None;

    let frame = SealedFrame {
        version: SealedFrame::VERSION,
        recipient_public_key: *recipient_key().public.as_bytes(),
        prekey_reference: Some(reference),
        ephemeral_public_key: *KeyPair::from_secret_bytes([0x52; 32]).public.as_bytes(),
        ciphertext: vec![0x61; 16],
    };

    assert!(matches!(frame.to_bytes(), Err(SealedFrameError::Encode)));
}

#[test]
fn sealed_frame_open_rejects_recipient_key_mismatch() {
    let mut rng = ChaCha20Rng::from_seed([0x13; 32]);
    let recipient = recipient_key();
    let other_recipient = KeyPair::from_secret_bytes([0x43; 32]);
    let frame = seal_frame(&mut rng, &recipient.public, None, b"payload").unwrap();

    assert!(matches!(
        open_frame(&other_recipient, &frame),
        Err(SealedFrameError::Decode)
    ));
}
