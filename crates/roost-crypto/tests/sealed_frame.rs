//! Verifies the shared sealed-sender frame used by session, acknowledgment, and X3DH wires.

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use roost_crypto::{
    DiscoveryKey, KeyPair, OneTimePreKeyReference, SealedFrame, SealedFrameError,
    SealedFramePreKeyReference, generate_discovery_key, generate_signing_key_pair,
    open_frame_for_discovery_key_with_associated_data, seal_frame_with_associated_data,
};
use serde::Serialize;

fn recipient_discovery_key(seed: u8) -> DiscoveryKey {
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    let signing_key = generate_signing_key_pair(&mut rng);
    generate_discovery_key(&mut rng, &signing_key, 1, 1_700_000_000).unwrap()
}

// Reads the version a real sealed frame carries, so a version bump doesn't leave these tests
// building frames that fail for the wrong reason.
fn current_frame_version() -> u8 {
    let mut rng = ChaCha20Rng::from_seed([0x14; 32]);
    let recipient = recipient_discovery_key(0x42);
    seal_frame_with_associated_data(&mut rng, recipient.public_key(), None, b"", &[])
        .unwrap()
        .version
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
        one_time_prekey: Some(OneTimePreKeyReference {
            id: 9,
            public_key: [0x61; 32],
        }),
    }
}

#[test]
fn sealed_frame_round_trip_with_prekey_reference() {
    let mut rng = ChaCha20Rng::from_seed([0x11; 32]);
    let recipient = recipient_discovery_key(0x42);
    let frame = seal_frame_with_associated_data(
        &mut rng,
        recipient.public_key(),
        Some(prekey_reference()),
        b"sealed payload",
        &[],
    )
    .unwrap();
    let encoded = frame.to_bytes().unwrap();
    let decoded = SealedFrame::from_bytes(&encoded).unwrap();

    assert_eq!(
        decoded.recipient_public_key,
        *recipient.public_key().as_bytes()
    );
    assert_eq!(decoded.prekey_reference, Some(prekey_reference()));
    assert_ne!(decoded.ephemeral_public_key, [0u8; 32]);
    assert_eq!(
        open_frame_for_discovery_key_with_associated_data(&recipient, &decoded, &[])
            .unwrap()
            .as_slice(),
        b"sealed payload"
    );
}

#[test]
fn sealed_frame_aad_binds_transport_visible_fields() {
    let mut rng = ChaCha20Rng::from_seed([0x12; 32]);
    let recipient = recipient_discovery_key(0x42);
    let other_recipient = recipient_discovery_key(0x44);
    let frame = seal_frame_with_associated_data(
        &mut rng,
        recipient.public_key(),
        None,
        b"metadata-bound",
        &[],
    )
    .unwrap();

    let mut wrong_version = frame.clone();
    wrong_version.version = wrong_version.version.wrapping_add(1);
    let mut wrong_recipient = frame.clone();
    wrong_recipient.recipient_public_key = *other_recipient.public_key().as_bytes();
    let mut wrong_ephemeral = frame.clone();
    wrong_ephemeral.ephemeral_public_key =
        *KeyPair::from_secret_bytes([0x45; 32]).public.as_bytes();
    let mut wrong_prekey = frame.clone();
    wrong_prekey.prekey_reference = Some(prekey_reference());

    assert!(matches!(
        open_frame_for_discovery_key_with_associated_data(&recipient, &wrong_version, &[]),
        Err(SealedFrameError::UnsupportedVersion(version)) if version == wrong_version.version
    ));
    assert!(matches!(
        open_frame_for_discovery_key_with_associated_data(&other_recipient, &wrong_recipient, &[]),
        Err(SealedFrameError::Aead)
    ));
    for tampered in [wrong_ephemeral, wrong_prekey] {
        assert!(matches!(
            open_frame_for_discovery_key_with_associated_data(&recipient, &tampered, &[]),
            Err(SealedFrameError::Aead)
        ));
    }
}

#[test]
fn sealed_frame_from_bytes_rejects_oversized_before_decode() {
    let bytes = vec![0u8; SealedFrame::MAX_ENCODED_LEN + 1];

    assert!(matches!(
        SealedFrame::from_bytes(&bytes),
        Err(SealedFrameError::FrameTooLong { len, max: SealedFrame::MAX_ENCODED_LEN })
            if len == bytes.len()
    ));
}

#[test]
fn sealed_frame_from_bytes_rejects_an_unknown_version_before_decoding() {
    let unknown = current_frame_version() + 1;

    assert!(matches!(
        SealedFrame::from_bytes(&[unknown]),
        Err(SealedFrameError::UnsupportedVersion(version)) if version == unknown
    ));
}

#[test]
fn sealed_frame_from_bytes_rejects_trailing_bytes() {
    let mut rng = ChaCha20Rng::from_seed([0x15; 32]);
    let recipient = recipient_discovery_key(0x42);
    let frame =
        seal_frame_with_associated_data(&mut rng, recipient.public_key(), None, b"payload", &[])
            .unwrap();
    let mut bytes = frame.to_bytes().unwrap();
    bytes.push(0);

    assert!(matches!(
        SealedFrame::from_bytes(&bytes),
        Err(SealedFrameError::TrailingBytes { len: 1 })
    ));
}

#[test]
fn sealed_frame_rejects_invalid_public_keys() {
    let mut frame = SealedFrame {
        version: current_frame_version(),
        recipient_public_key: [0u8; 32],
        prekey_reference: None,
        ephemeral_public_key: [0x42; 32],
        ciphertext: vec![0x51; 16],
    };

    assert!(matches!(
        frame.to_bytes(),
        Err(SealedFrameError::InvalidPublicKey)
    ));

    frame.recipient_public_key = *recipient_discovery_key(0x42).public_key().as_bytes();
    frame.ephemeral_public_key = [0u8; 32];
    assert!(matches!(
        frame.to_bytes(),
        Err(SealedFrameError::InvalidPublicKey)
    ));
}

#[test]
fn sealed_frame_from_bytes_rejects_half_of_a_one_time_prekey() {
    #[derive(Serialize)]
    struct HalfReferenceWire {
        discovery_epoch: u32,
        signed_prekey_public_key: [u8; 32],
        one_time_prekey_id: Option<u64>,
        one_time_prekey_public_key: Option<[u8; 32]>,
    }

    #[derive(Serialize)]
    struct FrameWire {
        version: u8,
        recipient_public_key: [u8; 32],
        prekey_reference: Option<HalfReferenceWire>,
        ephemeral_public_key: [u8; 32],
        ciphertext: Vec<u8>,
    }

    let bytes = postcard::to_stdvec(&FrameWire {
        version: current_frame_version(),
        recipient_public_key: *recipient_discovery_key(0x42).public_key().as_bytes(),
        prekey_reference: Some(HalfReferenceWire {
            discovery_epoch: 7,
            signed_prekey_public_key: [0x51; 32],
            one_time_prekey_id: Some(9),
            one_time_prekey_public_key: None,
        }),
        ephemeral_public_key: *KeyPair::from_secret_bytes([0x52; 32]).public.as_bytes(),
        ciphertext: vec![0x61; 16],
    })
    .unwrap();

    assert!(matches!(
        SealedFrame::from_bytes(&bytes),
        Err(SealedFrameError::IncompleteOneTimePreKey)
    ));
}

#[test]
fn sealed_frame_open_rejects_recipient_key_mismatch() {
    let mut rng = ChaCha20Rng::from_seed([0x13; 32]);
    let recipient = recipient_discovery_key(0x42);
    let other_recipient = recipient_discovery_key(0x43);
    let frame =
        seal_frame_with_associated_data(&mut rng, recipient.public_key(), None, b"payload", &[])
            .unwrap();

    assert!(matches!(
        open_frame_for_discovery_key_with_associated_data(&other_recipient, &frame, &[]),
        Err(SealedFrameError::RecipientMismatch)
    ));
}
