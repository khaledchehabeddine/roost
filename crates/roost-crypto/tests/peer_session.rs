//! Session-level integration tests for peers bootstrapped through the X3DH handshake.
//!
//! These scenarios cross the handshake, signed pre-key, and Double Ratchet modules through the
//! public API the way a downstream crate would.

use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use roost_crypto::{
    CryptoError, DiscoveryKey, HandshakeEnvelope, Header, IdentityKeyBundle, InitialPlaintext,
    OneTimePreKey, PreKeyBundle, RatchetState, Signature, SignedPreKey, SigningKeyPair, accept,
    generate_discovery_key, generate_key_pair, generate_one_time_prekey,
    generate_signed_prekey_for_discovery_key, generate_signing_key_pair, initial_associated_data,
    initiate, sign_identity_key_binding,
};

const FIXED_CREATED_AT: u64 = 1_700_000_000;

struct Setup {
    alice_identity_key: IdentityKeyBundle,
    alice_discovery_key: DiscoveryKey,
    bob_identity_key: IdentityKeyBundle,
    bob_discovery_key: DiscoveryKey,
    bob_signed_prekey: SignedPreKey,
    bob_one_time_prekey: Option<OneTimePreKey>,
}

fn setup() -> (Setup, ChaCha20Rng) {
    let mut rng = ChaCha20Rng::from_seed([0x33u8; 32]);
    let alice_identity = generate_signing_key_pair(&mut rng);
    let alice_identity_key = identity_key_bundle(&mut rng, &alice_identity);
    let alice_discovery_key =
        generate_discovery_key(&mut rng, &alice_identity, 1, FIXED_CREATED_AT);
    let bob_identity = generate_signing_key_pair(&mut rng);
    let bob_identity_key = identity_key_bundle(&mut rng, &bob_identity);
    let bob_discovery_key = generate_discovery_key(&mut rng, &bob_identity, 2, FIXED_CREATED_AT);
    let bob_signed_prekey =
        generate_signed_prekey_for_discovery_key(&mut rng, &bob_discovery_key, 0, FIXED_CREATED_AT);
    let bob_one_time_prekey =
        generate_one_time_prekey(&mut rng, 7, bob_discovery_key.epoch(), FIXED_CREATED_AT);
    let setup = Setup {
        alice_identity_key,
        alice_discovery_key,
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
) -> (RatchetState, RatchetState, HandshakeEnvelope) {
    let prekey_bundle = PreKeyBundle {
        version: roost_crypto::PREKEY_BUNDLE_VERSION,
        discovery_key: setup.bob_discovery_key.bundle(),
        signed_prekey: setup.bob_signed_prekey.bundle(),
        one_time_prekey: setup
            .bob_one_time_prekey
            .as_ref()
            .map(OneTimePreKey::bundle),
    };
    let (alice, envelope) = initiate(
        rng,
        &setup.alice_discovery_key,
        &setup.alice_identity_key,
        &setup.bob_identity_key,
        &prekey_bundle,
        initial_plaintext(plaintext),
    )
    .unwrap();
    let bob_one_time_prekey = setup.bob_one_time_prekey.take();
    let (bob, _) = accept(
        rng,
        &envelope,
        Some(&setup.alice_identity_key),
        &setup.bob_identity_key,
        &setup.bob_discovery_key,
        &setup.bob_signed_prekey,
        bob_one_time_prekey,
    )
    .unwrap();
    (alice, bob, envelope)
}

fn associated_data(setup: &Setup) -> [u8; 36] {
    initial_associated_data(
        setup.bob_discovery_key.public_key(),
        setup.bob_discovery_key.epoch(),
    )
}

fn initial_plaintext(plaintext: &[u8]) -> InitialPlaintext<'_> {
    InitialPlaintext {
        sender_certificate: b"sender certificate",
        sender_signature: b"sender signature",
        plaintext,
    }
}

fn identity_key_bundle(rng: &mut ChaCha20Rng, signing_key: &SigningKeyPair) -> IdentityKeyBundle {
    let agreement_key = generate_key_pair(rng);
    let binding_signature = sign_identity_key_binding(signing_key, &agreement_key.public).unwrap();
    IdentityKeyBundle {
        public_key: agreement_key.public,
        verifying_key: signing_key.verifying,
        binding_signature,
    }
}

#[test]
fn round_trip_advances_diffie_hellman_ratchet() {
    let (mut setup, mut rng) = setup();
    let (mut alice, mut bob, _) = bootstrap(&mut setup, &mut rng, b"hello");
    let associated_data = associated_data(&setup);

    let (bob_header, bob_ciphertext) = bob.ratchet_encrypt(b"hi back", &associated_data).unwrap();
    let decrypted = alice
        .ratchet_decrypt(&mut rng, &bob_ciphertext, &bob_header, &associated_data)
        .unwrap();
    assert_eq!(decrypted.as_slice(), b"hi back");

    let (alice_header, alice_ciphertext) =
        alice.ratchet_encrypt(b"round 2", &associated_data).unwrap();
    let decrypted = bob
        .ratchet_decrypt(&mut rng, &alice_ciphertext, &alice_header, &associated_data)
        .unwrap();
    assert_eq!(decrypted.as_slice(), b"round 2");
}

#[test]
fn serialized_handshake_envelope_establishes_session_and_reply() {
    let (mut setup, mut rng) = setup();
    let prekey_bundle = PreKeyBundle {
        version: roost_crypto::PREKEY_BUNDLE_VERSION,
        discovery_key: setup.bob_discovery_key.bundle(),
        signed_prekey: setup.bob_signed_prekey.bundle(),
        one_time_prekey: setup
            .bob_one_time_prekey
            .as_ref()
            .map(OneTimePreKey::bundle),
    };
    let (mut alice, envelope) = initiate(
        &mut rng,
        &setup.alice_discovery_key,
        &setup.alice_identity_key,
        &setup.bob_identity_key,
        &prekey_bundle,
        initial_plaintext(b"hello serialized Bob"),
    )
    .unwrap();
    let envelope_bytes = envelope.to_bytes().unwrap();
    let decoded_envelope = HandshakeEnvelope::from_bytes(&envelope_bytes).unwrap();
    let bob_one_time_prekey = setup.bob_one_time_prekey.take();
    let (mut bob, decrypted) = accept(
        &mut rng,
        &decoded_envelope,
        Some(&setup.alice_identity_key),
        &setup.bob_identity_key,
        &setup.bob_discovery_key,
        &setup.bob_signed_prekey,
        bob_one_time_prekey,
    )
    .unwrap();
    assert_eq!(decrypted.plaintext.as_slice(), b"hello serialized Bob");

    let associated_data = associated_data(&setup);
    let (reply_header, reply_ciphertext) = bob
        .ratchet_encrypt(b"reply after serialization", &associated_data)
        .unwrap();
    let reply = alice
        .ratchet_decrypt(&mut rng, &reply_ciphertext, &reply_header, &associated_data)
        .unwrap();
    assert_eq!(reply.as_slice(), b"reply after serialization");
}

#[test]
fn consecutive_sends_use_symmetric_ratchet_only() {
    let (mut setup, mut rng) = setup();
    let (mut alice, mut bob, _) = bootstrap(&mut setup, &mut rng, b"msg-0");
    let associated_data = associated_data(&setup);

    let mut messages = Vec::new();
    for i in 1..=5 {
        let plaintext = format!("msg-{i}");
        let (header, ciphertext) = alice
            .ratchet_encrypt(plaintext.as_bytes(), &associated_data)
            .unwrap();
        messages.push((plaintext, header, ciphertext));
    }

    let alice_ratchet_public_key = *messages[0].1.public_key.as_bytes();
    for (_, header, _) in &messages {
        assert_eq!(header.public_key.as_bytes(), &alice_ratchet_public_key);
    }

    for (plaintext, header, ciphertext) in &messages {
        let decrypted = bob
            .ratchet_decrypt(&mut rng, ciphertext, header, &associated_data)
            .unwrap();
        assert_eq!(decrypted.as_slice(), plaintext.as_bytes());
    }
}

#[test]
fn out_of_order_delivery_uses_skipped_keys() {
    let (mut setup, mut rng) = setup();
    let (mut alice, mut bob, _) = bootstrap(&mut setup, &mut rng, b"msg-0");
    let associated_data = associated_data(&setup);

    let mut messages = Vec::new();
    for i in 1..=5 {
        let plaintext = format!("msg-{i}");
        let (header, ciphertext) = alice
            .ratchet_encrypt(plaintext.as_bytes(), &associated_data)
            .unwrap();
        messages.push((plaintext, header, ciphertext));
    }

    for delivery_index in [0usize, 2, 4, 1, 3] {
        let (plaintext, header, ciphertext) = &messages[delivery_index];
        let decrypted = bob
            .ratchet_decrypt(&mut rng, ciphertext, header, &associated_data)
            .unwrap();
        assert_eq!(decrypted.as_slice(), plaintext.as_bytes());
    }
}

#[test]
fn skipped_keys_are_consumed_after_use() {
    let (mut setup, mut rng) = setup();
    let (mut alice, mut bob, _) = bootstrap(&mut setup, &mut rng, b"msg-0");
    let associated_data = associated_data(&setup);

    let mut messages = Vec::new();
    for i in 1..=5 {
        let (header, ciphertext) = alice
            .ratchet_encrypt(format!("msg-{i}").as_bytes(), &associated_data)
            .unwrap();
        messages.push((header, ciphertext));
    }

    assert_eq!(bob.skipped_key_count(), 0);
    bob.ratchet_decrypt(&mut rng, &messages[0].1, &messages[0].0, &associated_data)
        .unwrap();
    assert_eq!(bob.skipped_key_count(), 0);
    bob.ratchet_decrypt(&mut rng, &messages[2].1, &messages[2].0, &associated_data)
        .unwrap();
    assert_eq!(bob.skipped_key_count(), 1);
    bob.ratchet_decrypt(&mut rng, &messages[4].1, &messages[4].0, &associated_data)
        .unwrap();
    assert_eq!(bob.skipped_key_count(), 2);
    bob.ratchet_decrypt(&mut rng, &messages[1].1, &messages[1].0, &associated_data)
        .unwrap();
    assert_eq!(bob.skipped_key_count(), 1);
    bob.ratchet_decrypt(&mut rng, &messages[3].1, &messages[3].0, &associated_data)
        .unwrap();
    assert_eq!(bob.skipped_key_count(), 0);
}

#[test]
fn ratchet_is_self_contained_after_bootstrap() {
    let (mut setup, mut rng) = setup();
    let associated_data = associated_data(&setup);
    let (mut alice, mut bob, _) = bootstrap(&mut setup, &mut rng, b"hello");

    drop(setup);

    let bob_message = b"still here";
    let (bob_header, bob_ciphertext) = bob.ratchet_encrypt(bob_message, &associated_data).unwrap();
    assert_eq!(
        alice
            .ratchet_decrypt(&mut rng, &bob_ciphertext, &bob_header, &associated_data)
            .unwrap()
            .as_slice(),
        bob_message,
    );

    let alice_message = b"acknowledged";
    let (alice_header, alice_ciphertext) = alice
        .ratchet_encrypt(alice_message, &associated_data)
        .unwrap();
    assert_eq!(
        bob.ratchet_decrypt(&mut rng, &alice_ciphertext, &alice_header, &associated_data)
            .unwrap()
            .as_slice(),
        alice_message,
    );
}

#[test]
fn tampered_signed_prekey_signature_rejects_before_any_key_work() {
    let (setup, mut rng) = setup();
    let mut bundle = setup.bob_signed_prekey.bundle();
    let mut signature_bytes = bundle.signature.to_bytes();
    signature_bytes[0] ^= 0x01;
    bundle.signature = Signature::from_bytes(&signature_bytes);
    let prekey_bundle = PreKeyBundle {
        version: roost_crypto::PREKEY_BUNDLE_VERSION,
        discovery_key: setup.bob_discovery_key.bundle(),
        signed_prekey: bundle,
        one_time_prekey: setup
            .bob_one_time_prekey
            .as_ref()
            .map(OneTimePreKey::bundle),
    };
    let result = initiate(
        &mut rng,
        &setup.alice_discovery_key,
        &setup.alice_identity_key,
        &setup.bob_identity_key,
        &prekey_bundle,
        initial_plaintext(b"payload"),
    );
    assert!(matches!(result, Err(CryptoError::SignatureInvalid)));
}

#[test]
fn tampered_header_rolls_back_state() {
    let (mut setup, mut rng) = setup();
    let (mut alice, mut bob, _) = bootstrap(&mut setup, &mut rng, b"msg-0");
    let associated_data = associated_data(&setup);

    let (header, ciphertext) = alice.ratchet_encrypt(b"legit", &associated_data).unwrap();
    let tampered = Header {
        public_key: header.public_key,
        previous_chain_length: header.previous_chain_length,
        message_number: header.message_number + 10,
    };
    assert!(matches!(
        bob.ratchet_decrypt(&mut rng, &ciphertext, &tampered, &associated_data),
        Err(CryptoError::Aead)
    ));
    assert_eq!(
        bob.skipped_key_count(),
        0,
        "failed decrypt must not leak skipped keys from the discarded snapshot",
    );

    let decrypted = bob
        .ratchet_decrypt(&mut rng, &ciphertext, &header, &associated_data)
        .unwrap();
    assert_eq!(decrypted.as_slice(), b"legit");
}
