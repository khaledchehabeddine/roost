//! Session-level integration tests for peers bootstrapped through the X3DH handshake.
//!
//! These scenarios cross the handshake, signed pre-key, and Double Ratchet modules through the
//! public API the way a downstream crate would.

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use roost_crypto::{
    DiscoveryKey, HandshakeError, Header, OneTimePreKey, PreKeyBundle, PublicIdentityKey,
    PublicKeyError, RatchetError, RatchetState, Signature, SignedPreKey, SigningKeyPair,
    accept_handshake, generate_discovery_key, generate_key_pair, generate_one_time_prekey,
    generate_signed_prekey_for_discovery_key, generate_signing_key_pair, initiate_handshake,
    sign_identity_key_binding,
};
use roost_protocol::SignatureError;

const FIXED_CREATED_AT_SECS: u64 = 1_700_000_000;
const ASSOCIATED_DATA: &[u8] = b"associated data";

struct Setup {
    bob_identity_key: PublicIdentityKey,
    bob_discovery_key: DiscoveryKey,
    bob_signed_prekey: SignedPreKey,
    bob_one_time_prekey: Option<OneTimePreKey>,
}

fn setup() -> (Setup, ChaCha20Rng) {
    let mut rng = ChaCha20Rng::from_seed([0x33u8; 32]);
    let bob_identity = generate_signing_key_pair(&mut rng).unwrap();
    let bob_identity_key = public_identity_key(&mut rng, &bob_identity);
    let bob_discovery_key =
        generate_discovery_key(&mut rng, &bob_identity, 2, FIXED_CREATED_AT_SECS).unwrap();
    let bob_signed_prekey = generate_signed_prekey_for_discovery_key(
        &mut rng,
        &bob_discovery_key,
        0,
        FIXED_CREATED_AT_SECS,
    )
    .unwrap();
    let bob_one_time_prekey = generate_one_time_prekey(
        &mut rng,
        7,
        bob_discovery_key.epoch(),
        FIXED_CREATED_AT_SECS,
    )
    .unwrap();
    let setup = Setup {
        bob_identity_key,
        bob_discovery_key,
        bob_signed_prekey,
        bob_one_time_prekey: Some(bob_one_time_prekey),
    };
    (setup, rng)
}

fn bootstrap(
    setup: &mut Setup,
    rng: &mut ChaCha20Rng,
    plaintext: &[u8],
) -> (RatchetState, RatchetState) {
    let prekey_bundle = PreKeyBundle {
        version: roost_crypto::PREKEY_BUNDLE_VERSION,
        discovery_key: setup.bob_discovery_key.public(),
        signed_prekey: setup.bob_signed_prekey.public(),
        one_time_prekey: setup
            .bob_one_time_prekey
            .as_ref()
            .map(OneTimePreKey::public),
    };
    let (mut alice, alice_session_id, handshake) =
        initiate_handshake(rng, &setup.bob_identity_key, &prekey_bundle).unwrap();
    let (mut bob, bob_session_id) = accept_handshake(
        &handshake,
        &setup.bob_discovery_key,
        &setup.bob_signed_prekey,
        setup.bob_one_time_prekey.take(),
    )
    .unwrap();
    assert_eq!(bob_session_id, alice_session_id);
    let (header, ciphertext) = alice.ratchet_encrypt(plaintext, ASSOCIATED_DATA).unwrap();
    let decrypted = bob
        .ratchet_decrypt(rng, &ciphertext, &header, ASSOCIATED_DATA)
        .unwrap();
    assert_eq!(decrypted.as_slice(), plaintext);
    (alice, bob)
}

fn public_identity_key(rng: &mut ChaCha20Rng, signing_key: &SigningKeyPair) -> PublicIdentityKey {
    let agreement_key = generate_key_pair(rng).unwrap();
    let binding_signature = sign_identity_key_binding(signing_key, &agreement_key.public).unwrap();
    PublicIdentityKey {
        public_key: agreement_key.public,
        verifying_key: signing_key.verifying,
        binding_signature,
    }
}

#[test]
fn round_trip_advances_diffie_hellman_ratchet() {
    let (mut setup, mut rng) = setup();
    let (mut alice, mut bob) = bootstrap(&mut setup, &mut rng, b"hello");
    let associated_data = ASSOCIATED_DATA;

    let (bob_header, bob_ciphertext) = bob.ratchet_encrypt(b"hi back", associated_data).unwrap();
    let decrypted = alice
        .ratchet_decrypt(&mut rng, &bob_ciphertext, &bob_header, associated_data)
        .unwrap();
    assert_eq!(decrypted.as_slice(), b"hi back");

    let (alice_header, alice_ciphertext) =
        alice.ratchet_encrypt(b"round 2", associated_data).unwrap();
    let decrypted = bob
        .ratchet_decrypt(&mut rng, &alice_ciphertext, &alice_header, associated_data)
        .unwrap();
    assert_eq!(decrypted.as_slice(), b"round 2");
}

#[test]
fn consecutive_sends_use_symmetric_ratchet_only() {
    let (mut setup, mut rng) = setup();
    let (mut alice, mut bob) = bootstrap(&mut setup, &mut rng, b"msg-0");
    let associated_data = ASSOCIATED_DATA;

    let mut messages = Vec::new();
    for i in 1..=5 {
        let plaintext = format!("msg-{i}");
        let (header, ciphertext) = alice
            .ratchet_encrypt(plaintext.as_bytes(), associated_data)
            .unwrap();
        messages.push((plaintext, header, ciphertext));
    }

    let alice_ratchet_public_key = *messages[0].1.public_key.as_bytes();
    for (_, header, _) in &messages {
        assert_eq!(header.public_key.as_bytes(), &alice_ratchet_public_key);
    }

    for (plaintext, header, ciphertext) in &messages {
        let decrypted = bob
            .ratchet_decrypt(&mut rng, ciphertext, header, associated_data)
            .unwrap();
        assert_eq!(decrypted.as_slice(), plaintext.as_bytes());
    }
}

#[test]
fn skipped_keys_are_consumed_after_use() {
    let (mut setup, mut rng) = setup();
    let (mut alice, mut bob) = bootstrap(&mut setup, &mut rng, b"msg-0");
    let associated_data = ASSOCIATED_DATA;

    let mut messages = Vec::new();
    for i in 1..=5 {
        let (header, ciphertext) = alice
            .ratchet_encrypt(format!("msg-{i}").as_bytes(), associated_data)
            .unwrap();
        messages.push((header, ciphertext));
    }

    for index in [0, 2, 4, 1, 3] {
        let (header, ciphertext) = &messages[index];
        bob.ratchet_decrypt(&mut rng, ciphertext, header, associated_data)
            .unwrap();
    }
    let delivered = bob.to_bytes().unwrap();

    for (header, ciphertext) in &messages {
        assert!(matches!(
            bob.ratchet_decrypt(&mut rng, ciphertext, header, associated_data),
            Err(RatchetError::Aead)
        ));
    }
    assert_eq!(*bob.to_bytes().unwrap(), *delivered);
}

#[test]
fn tampered_signed_prekey_signature_rejects_before_any_key_work() {
    let (setup, mut rng) = setup();
    let mut bundle = setup.bob_signed_prekey.public();
    let mut signature_bytes = bundle.signature.to_bytes();
    signature_bytes[0] ^= 0x01;
    bundle.signature = Signature::from_bytes(&signature_bytes);
    let prekey_bundle = PreKeyBundle {
        version: roost_crypto::PREKEY_BUNDLE_VERSION,
        discovery_key: setup.bob_discovery_key.public(),
        signed_prekey: bundle,
        one_time_prekey: setup
            .bob_one_time_prekey
            .as_ref()
            .map(OneTimePreKey::public),
    };
    let result = initiate_handshake(&mut rng, &setup.bob_identity_key, &prekey_bundle);
    assert!(matches!(
        result,
        Err(HandshakeError::PublicKey(PublicKeyError::Signature(
            SignatureError::SignatureInvalid
        )))
    ));
}

#[test]
fn tampered_header_rolls_back_state() {
    let (mut setup, mut rng) = setup();
    let (mut alice, mut bob) = bootstrap(&mut setup, &mut rng, b"msg-0");
    let associated_data = ASSOCIATED_DATA;

    let (header, ciphertext) = alice.ratchet_encrypt(b"legit", associated_data).unwrap();
    let before = bob.to_bytes().unwrap();
    let tampered = Header {
        public_key: header.public_key,
        previous_chain_length: header.previous_chain_length,
        message_number: header.message_number + 10,
    };
    assert!(matches!(
        bob.ratchet_decrypt(&mut rng, &ciphertext, &tampered, associated_data),
        Err(RatchetError::Aead)
    ));
    assert_eq!(*bob.to_bytes().unwrap(), *before);

    let decrypted = bob
        .ratchet_decrypt(&mut rng, &ciphertext, &header, associated_data)
        .unwrap();
    assert_eq!(decrypted.as_slice(), b"legit");
}
