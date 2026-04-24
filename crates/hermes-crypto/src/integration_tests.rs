//! Integration tests exercising two [`RatchetState`] instances bootstrapped via the X3DH-lite
//! handshake. Covers the scenarios from issue #38 that cross module boundaries and cannot be
//! asserted from within a single module's unit tests.

use crate::double_ratchet::{Header, RatchetState};
use crate::error::CryptoError;
use crate::handshake::{HandshakeEnvelope, accept, initial_ad, initiate};
use crate::keys::{
    KeyPair, Signature, SigningKeyPair, generate_key_pair, generate_signing_key_pair,
};
use crate::signed_prekey::{SignedPreKey, generate_signed_prekey};

const FIXED_TS: u64 = 1_700_000_000;

struct Setup {
    alice_ik: KeyPair,
    bob_ik: KeyPair,
    bob_signing: SigningKeyPair,
    bob_spk: SignedPreKey,
}

fn setup() -> Setup {
    let bob_signing = generate_signing_key_pair();
    let bob_spk = generate_signed_prekey(&bob_signing, FIXED_TS);
    Setup {
        alice_ik: generate_key_pair(),
        bob_ik: generate_key_pair(),
        bob_signing,
        bob_spk,
    }
}

fn bootstrap(s: &Setup, plaintext: &[u8]) -> (RatchetState, RatchetState, HandshakeEnvelope) {
    let (alice, envelope) = initiate(
        &s.alice_ik,
        &s.bob_signing.verifying,
        &s.bob_ik.public,
        &s.bob_spk.bundle(),
        plaintext,
    )
    .unwrap();
    let (bob, _decrypted) = accept(&envelope, &s.bob_ik, &s.bob_spk).unwrap();
    (alice, bob, envelope)
}

#[test]
fn round_trip_advances_dh_ratchet() {
    let s = setup();
    let (mut alice, mut bob, envelope) = bootstrap(&s, b"hello");
    let ad = initial_ad(&s.alice_ik.public, &s.bob_ik.public);
    let initial_alice_dh = envelope.ratchet_pk;

    let (bob_h, bob_ct) = bob.ratchet_encrypt(b"hi back", &ad).unwrap();
    let decrypted = alice.ratchet_decrypt(&bob_ct, &bob_h, &ad).unwrap();
    assert_eq!(decrypted.as_slice(), b"hi back");

    let (alice_h, alice_ct) = alice.ratchet_encrypt(b"round 2", &ad).unwrap();
    assert_ne!(
        alice_h.public_key.as_bytes(),
        &initial_alice_dh,
        "DH ratchet did not advance on Alice after receiving Bob's reply",
    );
    let decrypted = bob.ratchet_decrypt(&alice_ct, &alice_h, &ad).unwrap();
    assert_eq!(decrypted.as_slice(), b"round 2");
}

#[test]
fn consecutive_sends_use_symmetric_ratchet_only() {
    let s = setup();
    let (mut alice, mut bob, envelope) = bootstrap(&s, b"msg-0");
    let ad = initial_ad(&s.alice_ik.public, &s.bob_ik.public);
    let alice_dh = envelope.ratchet_pk;

    let mut items = Vec::new();
    for i in 1..=5 {
        let pt = format!("msg-{i}");
        let (h, ct) = alice.ratchet_encrypt(pt.as_bytes(), &ad).unwrap();
        items.push((pt, h, ct));
    }

    for (_, h, _) in &items {
        assert_eq!(h.public_key.as_bytes(), &alice_dh);
    }

    for (pt, h, ct) in &items {
        let decrypted = bob.ratchet_decrypt(ct, h, &ad).unwrap();
        assert_eq!(decrypted.as_slice(), pt.as_bytes());
    }
}

#[test]
fn out_of_order_delivery_uses_skipped_keys() {
    let s = setup();
    let (mut alice, mut bob, _) = bootstrap(&s, b"msg-0");
    let ad = initial_ad(&s.alice_ik.public, &s.bob_ik.public);

    let mut items = Vec::new();
    for i in 1..=5 {
        let pt = format!("msg-{i}");
        let (h, ct) = alice.ratchet_encrypt(pt.as_bytes(), &ad).unwrap();
        items.push((pt, h, ct));
    }

    for idx in [0usize, 2, 4, 1, 3] {
        let (pt, h, ct) = &items[idx];
        let decrypted = bob.ratchet_decrypt(ct, h, &ad).unwrap();
        assert_eq!(decrypted.as_slice(), pt.as_bytes());
    }
}

#[test]
fn skipped_keys_are_consumed_after_use() {
    let s = setup();
    let (mut alice, mut bob, _) = bootstrap(&s, b"msg-0");
    let ad = initial_ad(&s.alice_ik.public, &s.bob_ik.public);

    let mut items = Vec::new();
    for i in 1..=5 {
        let (h, ct) = alice
            .ratchet_encrypt(format!("msg-{i}").as_bytes(), &ad)
            .unwrap();
        items.push((h, ct));
    }

    assert_eq!(bob.skipped_key_count(), 0);

    bob.ratchet_decrypt(&items[0].1, &items[0].0, &ad).unwrap();
    assert_eq!(bob.skipped_key_count(), 0);

    bob.ratchet_decrypt(&items[2].1, &items[2].0, &ad).unwrap();
    assert_eq!(bob.skipped_key_count(), 1);

    bob.ratchet_decrypt(&items[4].1, &items[4].0, &ad).unwrap();
    assert_eq!(bob.skipped_key_count(), 2);

    bob.ratchet_decrypt(&items[1].1, &items[1].0, &ad).unwrap();
    assert_eq!(bob.skipped_key_count(), 1);

    bob.ratchet_decrypt(&items[3].1, &items[3].0, &ad).unwrap();
    assert_eq!(bob.skipped_key_count(), 0);
}

#[test]
fn tampered_header_rolls_back_state() {
    let s = setup();
    let (mut alice, mut bob, _) = bootstrap(&s, b"msg-0");
    let ad = initial_ad(&s.alice_ik.public, &s.bob_ik.public);

    let (h, ct) = alice.ratchet_encrypt(b"legit", &ad).unwrap();

    let tampered = Header {
        public_key: h.public_key,
        pn: h.pn,
        n: h.n + 10,
    };
    assert!(matches!(
        bob.ratchet_decrypt(&ct, &tampered, &ad),
        Err(CryptoError::Aead)
    ));
    assert_eq!(
        bob.skipped_key_count(),
        0,
        "failed decrypt must not leak skipped keys from the discarded snapshot",
    );

    let decrypted = bob.ratchet_decrypt(&ct, &h, &ad).unwrap();
    assert_eq!(decrypted.as_slice(), b"legit");
}

#[test]
fn tampered_spk_signature_rejects_before_any_key_work() {
    let s = setup();
    let mut bundle = s.bob_spk.bundle();
    let mut sig_bytes = bundle.signature.to_bytes();
    sig_bytes[0] ^= 0x01;
    bundle.signature = Signature::from_bytes(&sig_bytes);

    let result = initiate(
        &s.alice_ik,
        &s.bob_signing.verifying,
        &s.bob_ik.public,
        &bundle,
        b"payload",
    );
    assert!(matches!(result, Err(CryptoError::SignatureInvalid)));
}

#[test]
fn spk_rotation_does_not_invalidate_active_session() {
    let s = setup();
    let (mut alice, mut bob, _) = bootstrap(&s, b"hello");
    let ad = initial_ad(&s.alice_ik.public, &s.bob_ik.public);

    // Ratchet state is independent of the responder's SPK once bootstrapped — rotation must not
    // invalidate an active session. The new SPK is intentionally unused below.
    let _rotated = generate_signed_prekey(&s.bob_signing, FIXED_TS + 86_400);

    let (h, ct) = bob.ratchet_encrypt(b"still here", &ad).unwrap();
    assert_eq!(
        alice.ratchet_decrypt(&ct, &h, &ad).unwrap().as_slice(),
        b"still here",
    );

    let (h, ct) = alice.ratchet_encrypt(b"acknowledged", &ad).unwrap();
    assert_eq!(
        bob.ratchet_decrypt(&ct, &h, &ad).unwrap().as_slice(),
        b"acknowledged",
    );
}
